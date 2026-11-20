package approvecli

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// TokenFunc returns the approver's access token. The token lives only in this process: it is never written to a file.
type TokenFunc func(ctx context.Context) (string, error)

// loopbackLogin is the OIDC authorization-code flow with PKCE (S256) and a loopback redirect (RFC 8252): the CLI listens on 127.0.0.1 on a random
// port, prints the sign-in link, and trades the code it receives for a token. It asks for a fresh sign-in (prompt=login, max_age=0), as the approval
// page does, because the core asks for a recent one at the strongest level before it takes an approval. The client is public: no secret exists.
//
// The device-code flow would suit a machine with no browser, but it cannot ask for a fresh sign-in (the identity provider reuses the session on the
// other device), and the core would answer with a step-up challenge. A machine with no browser can forward the port to one that has.
func loopbackLogin(ctx context.Context, hc *http.Client, issuer, clientID string, out io.Writer) (string, error) {
	if issuer == "" || clientID == "" {
		return "", errors.New("login: -issuer and -client-id are needed (QV_OIDC_ISSUER)")
	}
	var disc struct {
		Issuer string `json:"issuer"`
		Auth   string `json:"authorization_endpoint"`
		Token  string `json:"token_endpoint"`
	}
	if err := getJSON(ctx, hc, strings.TrimRight(issuer, "/")+"/.well-known/openid-configuration", &disc); err != nil {
		return "", fmt.Errorf("login: discovery: %w", err)
	}
	if disc.Issuer != strings.TrimRight(issuer, "/") || disc.Auth == "" || disc.Token == "" {
		return "", errors.New("login: the discovery document is not for this issuer")
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer l.Close()
	redirect := "http://" + l.Addr().String() + "/callback"
	state, verifier := randString(24), randString(48)
	chal := sha256.Sum256([]byte(verifier))
	u, err := url.Parse(disc.Auth)
	if err != nil {
		return "", err
	}
	q := u.Query()
	for k, v := range map[string]string{"response_type": "code", "client_id": clientID, "redirect_uri": redirect, "scope": "openid", "state": state,
		"code_challenge": base64.RawURLEncoding.EncodeToString(chal[:]), "code_challenge_method": "S256", "prompt": "login", "max_age": "0"} {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()

	type result struct {
		code string
		err  error
	}
	got := make(chan result, 1)
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/callback" {
			http.NotFound(w, r)
			return
		}
		p := r.URL.Query()
		var res result
		switch {
		case subtle.ConstantTimeCompare([]byte(p.Get("state")), []byte(state)) != 1:
			res.err = errors.New("login: the answer does not belong to this sign-in (state differs)")
		case p.Get("error") != "":
			res.err = fmt.Errorf("login: the identity provider refused: %s", p.Get("error"))
		case p.Get("code") == "":
			res.err = errors.New("login: no code in the answer")
		default:
			res.code = p.Get("code")
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if res.err != nil {
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, "Sign-in failed. Go back to the terminal.\n")
		} else {
			io.WriteString(w, "Signed in. You can close this tab and go back to the terminal.\n")
		}
		select {
		case got <- res:
		default:
		}
	})}
	go srv.Serve(l)
	defer srv.Close()

	fmt.Fprintf(out, "Sign in: open this link in a browser on this machine and use your login (it asks for a fresh sign-in):\n\n  %s\n\n", u)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	var res result
	select {
	case res = <-got:
	case <-ctx.Done():
		return "", errors.New("login: timed out waiting for the sign-in")
	}
	if res.err != nil {
		return "", res.err
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {res.code}, "redirect_uri": {redirect}, "client_id": {clientID}, "code_verifier": {verifier}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, disc.Token, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("login: token request: %w", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var t struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error_description"`
	}
	_ = json.Unmarshal(b, &t)
	if resp.StatusCode != 200 || t.AccessToken == "" {
		return "", fmt.Errorf("login: the token endpoint answered %d %s", resp.StatusCode, t.Error)
	}
	return t.AccessToken, nil
}

func randString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func getJSON(ctx context.Context, hc *http.Client, u string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("answered %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(v)
}

// subjectOf reads the "sub" claim of a JWT for display and for the approval's actor field. It does not verify the token: the core does, and the actor
// it checks is the token's own sub, so a wrong value here only makes the core refuse.
func subjectOf(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", errors.New("the token is not a JWT")
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", errors.New("the token payload is not base64url")
	}
	var c struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(b, &c); err != nil || c.Sub == "" {
		return "", errors.New("the token has no sub")
	}
	return c.Sub, nil
}
