// Package idp gives the e2e harnesses their identity provider. Call Init from TestMain, before any qv-core is started: it sets the
// environment the spawned processes inherit, then Bearer(actor) returns the Authorization header value of a named test person.
//
// Two modes:
//
//   - Test issuer (the default, no container): a local ES256 key, whose JWKS the spawned qv-core trusts because QV_ENV=test. Fast, and
//     what most groups use. Simulated: nobody logged in, and the token says acr=aal3 and auth_time=now because the harness says so.
//   - Real Keycloak (QV_E2E_KEYCLOAK_URL set, started by `make keycloak-up`): tokens come from the dev realm in deploy/keycloak with a
//     scripted login, and qv-core fetches the real JWKS. Simulated: the test client `qv-e2e` skips the passkey step, and a mapper sets
//     acr=aal3 on its tokens. That client exists only in the dev realm file, and a production core refuses the dev realm's issuer
//     (it is http) and the QV_ENV that goes with it.
package idp

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/auth/authtest"
)

const (
	audience   = "qv-core"
	testIssuer = "https://idp.e2e.test/realms/qv"
	realm      = "quorumvault"
)

var (
	issuer *authtest.Issuer
	kc     string // Keycloak base URL; empty in test-issuer mode

	mu     sync.Mutex
	cached = map[string]cachedTok{}
)

type cachedTok struct {
	tok string
	at  time.Time
}

// Init prepares the identity provider and sets the environment qv-core inherits.
func Init() error {
	os.Setenv("QV_ENV", "test")
	os.Setenv("QV_OIDC_AUDIENCE", audience)
	os.Setenv("QV_OIDC_SERVICE_CLIENTS", "qv-guardian")
	if u := strings.TrimRight(os.Getenv("QV_E2E_KEYCLOAK_URL"), "/"); u != "" {
		kc = u
		os.Setenv("QV_OIDC_ISSUER", u+"/realms/"+realm)
		os.Unsetenv("QV_OIDC_TEST_JWKS")
		return nil
	}
	issuer = authtest.New(testIssuer, audience)
	dir, err := os.MkdirTemp("", "qv-e2e-idp-")
	if err != nil {
		return err
	}
	p := filepath.Join(dir, "jwks.json")
	if err := os.WriteFile(p, issuer.JWKS(), 0o600); err != nil {
		return err
	}
	os.Setenv("QV_OIDC_ISSUER", testIssuer)
	os.Setenv("QV_OIDC_TEST_JWKS", p)
	return nil
}

// Real reports whether tokens come from Keycloak.
func Real() bool { return kc != "" }

// Bearer returns "Bearer <token>" for the named person, freshly authenticated.
func Bearer(actor string) string {
	if issuer != nil {
		return "Bearer " + issuer.Token(authtest.Spec{Sub: actor, Roles: authtest.RolesOf(actor)})
	}
	mu.Lock()
	defer mu.Unlock()
	if c, ok := cached[actor]; ok && time.Since(c.at) < 45*time.Second { // far inside the 5-minute step-up window
		return c.tok
	}
	t, err := passwordGrant(actor)
	if err != nil {
		panic(fmt.Sprintf("idp: token for %s: %v", actor, err))
	}
	cached[actor] = cachedTok{"Bearer " + t, time.Now()}
	return "Bearer " + t
}

// ServiceBearer returns a token for a service identity that calls the core API: a client-credentials token. The test issuer fakes
// one for the client qv-guardian; Keycloak issues the real thing for that client.
func ServiceBearer(client string) string {
	if issuer != nil {
		return "Bearer " + issuer.Token(authtest.Spec{Sub: "service-account-" + client, Client: client, Service: true, Roles: []string{"operator"}})
	}
	secret := os.Getenv("QV_KEYCLOAK_GUARDIAN_SECRET") // written to .env by scripts/keycloak-env.sh
	if secret == "" {
		panic("idp: QV_KEYCLOAK_GUARDIAN_SECRET is unset: run scripts/keycloak-env.sh")
	}
	t, err := post(kc+"/realms/"+realm+"/protocol/openid-connect/token", url.Values{"grant_type": {"client_credentials"}, "client_id": {client}, "client_secret": {secret}})
	if err != nil {
		panic(fmt.Sprintf("idp: service token for %s: %v", client, err))
	}
	return "Bearer " + t
}

// SetHeaders turns an X-Actor entry of hdr into the bearer token of that person, so a test names who acts.
func SetHeaders(h http.Header, hdr map[string]string) {
	for k, v := range hdr {
		if strings.EqualFold(k, "X-Actor") {
			h.Set("Authorization", Bearer(v))
			continue
		}
		h.Set(k, v)
	}
}

// passwordGrant logs the test user in through the realm's login page, the way a browser does, but with the username and password step only: the
// client qv-e2e is bound to the realm's test-only flow, which has no passkey step. A real browser login (authorization code with PKCE,
// username, passkey) is the flow qv-cli uses and is not exercised here: it needs a browser.
func passwordGrant(user string) (string, error) {
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Timeout: 20 * time.Second, Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	redirect := "http://127.0.0.1/cb"
	base := kc + "/realms/" + realm + "/protocol/openid-connect/"
	resp, err := hc.Get(base + "auth?" + url.Values{"client_id": {"qv-e2e"}, "response_type": {"code"}, "scope": {"openid"}, "redirect_uri": {redirect}, "state": {"s"}}.Encode())
	if err != nil {
		return "", err
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := regexp.MustCompile(`<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"`).FindSubmatch(page)
	if m == nil {
		return "", fmt.Errorf("no login form (HTTP %d)", resp.StatusCode)
	}
	action := strings.ReplaceAll(string(m[1]), "&amp;", "&")
	resp, err = hc.PostForm(action, url.Values{"username": {user}, "password": {testPassword(user)}, "credentialId": {""}})
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	loc, err := resp.Location()
	if err != nil || loc.Query().Get("code") == "" {
		return "", fmt.Errorf("login did not redirect with a code (HTTP %d)", resp.StatusCode)
	}
	return post(base+"token", url.Values{"grant_type": {"authorization_code"}, "client_id": {"qv-e2e"}, "code": {loc.Query().Get("code")}, "redirect_uri": {redirect}})
}

// testPassword is the test user's password, written to .env by scripts/keycloak-env.sh. The repo holds none.
func testPassword(user string) string {
	v := os.Getenv("QV_TEST_PASSWORD_" + strings.ToUpper(user))
	if v == "" {
		panic("idp: QV_TEST_PASSWORD_" + strings.ToUpper(user) + " is unset: run scripts/keycloak-env.sh")
	}
	return v
}

func post(u string, form url.Values) (string, error) {
	resp, err := (&http.Client{Timeout: 20 * time.Second}).PostForm(u, form)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, b)
	}
	var t struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(b, &t); err != nil || t.AccessToken == "" {
		return "", fmt.Errorf("no access_token in %s", b)
	}
	return t.AccessToken, nil
}
