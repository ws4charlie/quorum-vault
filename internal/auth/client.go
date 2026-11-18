package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// ServiceToken returns a bearer token for a service that calls the core API. QV_CORE_TOKEN (a ready token) wins; otherwise a
// client-credentials grant against QV_OIDC_TOKEN_URL with QV_OIDC_CLIENT_ID and QV_OIDC_CLIENT_SECRET. The secret comes from the
// environment, never from a flag, so it is not in a process list.
func ServiceToken(ctx context.Context) (string, error) {
	if t := strings.TrimSpace(os.Getenv("QV_CORE_TOKEN")); t != "" {
		return t, nil
	}
	return ClientCredentials(ctx, os.Getenv("QV_OIDC_TOKEN_URL"), os.Getenv("QV_OIDC_CLIENT_ID"), os.Getenv("QV_OIDC_CLIENT_SECRET"), "")
}

// ClientCredentials runs the OAuth 2.0 client-credentials grant and returns the access token.
func ClientCredentials(ctx context.Context, tokenURL, id, secret, scope string) (string, error) {
	if tokenURL == "" || id == "" || secret == "" {
		return "", errors.New("auth: set QV_CORE_TOKEN, or QV_OIDC_TOKEN_URL, QV_OIDC_CLIENT_ID and QV_OIDC_CLIENT_SECRET")
	}
	form := url.Values{"grant_type": {"client_credentials"}}
	if scope != "" {
		form.Set("scope", scope)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(id), url.QueryEscape(secret))
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("auth: token endpoint answered %d", resp.StatusCode)
	}
	var t struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(b, &t); err != nil || t.AccessToken == "" {
		return "", errors.New("auth: token endpoint gave no access_token")
	}
	return t.AccessToken, nil
}
