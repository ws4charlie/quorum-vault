package auth

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// Only asymmetric algorithms. "none" and HMAC are never accepted.
var allowedAlgs = []jose.SignatureAlgorithm{jose.RS256, jose.RS384, jose.RS512, jose.ES256, jose.ES384, jose.ES512, jose.PS256, jose.EdDSA}

type claims struct {
	Issuer    string          `json:"iss"`
	Subject   string          `json:"sub"`
	Audience  json.RawMessage `json:"aud"`
	Exp       *float64        `json:"exp"`
	Nbf       *float64        `json:"nbf"`
	Iat       *float64        `json:"iat"`
	AuthTime  *float64        `json:"auth_time"`
	ACR       string          `json:"acr"`
	JTI       string          `json:"jti"`
	SID       string          `json:"sid"`
	AZP       string          `json:"azp"`
	ClientID  string          `json:"client_id"`
	Name      string          `json:"preferred_username"`
	FullName  string          `json:"name"`
	TokenType string          `json:"typ"`
}

func unixTime(f float64) time.Time { return time.Unix(int64(f), 0) }

func audiences(raw json.RawMessage) []string {
	var one string
	if json.Unmarshal(raw, &one) == nil && one != "" {
		return []string{one}
	}
	var many []string
	_ = json.Unmarshal(raw, &many)
	return many
}

// Verify checks a compact JWT and returns who it names.
func (a *Authenticator) Verify(ctx context.Context, raw string) (*Principal, error) {
	if len(raw) > 16<<10 {
		return nil, errors.New("token too long")
	}
	jws, err := jose.ParseSigned(raw, allowedAlgs)
	if err != nil {
		return nil, errors.New("not a signed JWT with an accepted algorithm")
	}
	if len(jws.Signatures) != 1 {
		return nil, errors.New("exactly one signature is required")
	}
	// The digest covers the whole token (header, payload, signature), so a token with the same claims and another signature is another
	// entry. The lookup is by the full 32-byte digest in a map: nothing compares secret bytes with an early exit, and the digest of a
	// token one does not hold cannot be guessed, so a hit or a miss tells a caller only about the token they sent themselves.
	digest := sha256.Sum256([]byte(raw))
	var payload []byte
	cached := a.sigs.has(digest, a.cfg.Now())
	gen := uint64(0)
	if cached {
		payload = jws.UnsafePayloadWithoutVerification() // the signature was verified when this exact token was stored
	} else {
		gen = a.sigs.generation() // before the key lookup: a refetch after it must stop this token being stored
		kid := jws.Signatures[0].Header.KeyID
		key, err := a.key(ctx, kid, jws.Signatures[0].Header.Algorithm)
		if err != nil {
			return nil, err
		}
		payload, err = jws.Verify(key)
		if err != nil {
			return nil, errors.New("bad signature")
		}
	}
	var c claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, errors.New("claims are not JSON")
	}
	var all map[string]json.RawMessage
	_ = json.Unmarshal(payload, &all)

	now := a.cfg.Now()
	skew := a.cfg.ClockSkew
	if c.Issuer != a.cfg.Issuer {
		return nil, fmt.Errorf("wrong issuer %q", c.Issuer)
	}
	okAud := false
	for _, x := range audiences(c.Audience) {
		okAud = okAud || x == a.cfg.Audience
	}
	if !okAud {
		return nil, errors.New("wrong audience")
	}
	if c.Exp == nil {
		return nil, errors.New("no exp")
	}
	if !now.Before(unixTime(*c.Exp).Add(skew)) {
		return nil, errors.New("expired")
	}
	if c.Nbf != nil && now.Add(skew).Before(unixTime(*c.Nbf)) {
		return nil, errors.New("not valid yet")
	}
	if c.Iat != nil && now.Add(skew).Before(unixTime(*c.Iat)) {
		return nil, errors.New("issued in the future")
	}
	if c.Subject == "" {
		return nil, errors.New("no sub")
	}

	if a.env == Production {
		for _, id := range []string{c.AZP, c.ClientID} {
			if isE2EClient(id) {
				return nil, fmt.Errorf("client %q is a test client of the dev realm and is refused in production", strings.TrimSpace(id))
			}
		}
	}

	p := &Principal{Issuer: c.Issuer, Sub: c.Subject, Client: c.AZP, ACR: c.ACR, TokenID: c.JTI, Session: c.SID, Name: c.Name}
	if p.Client == "" {
		p.Client = c.ClientID
	}
	if p.Name == "" {
		p.Name = c.FullName
	}
	p.Service = a.services[p.Client] && c.AuthTime == nil // a client-credentials token has no login behind it
	if c.AuthTime != nil {
		p.AuthTime = unixTime(*c.AuthTime)
	}
	if !p.Service {
		// A user token must prove when the person authenticated, and the session may not outlive the AAL3 limit.
		if c.AuthTime == nil {
			return nil, errors.New("no auth_time: not a user token of an accepted client")
		}
		if p.AuthTime.After(now.Add(skew)) {
			return nil, errors.New("auth_time is in the future")
		}
		if now.Sub(p.AuthTime) > a.cfg.MaxSession {
			return nil, errors.New("session is older than the overall limit; log in again")
		}
	}
	p.Roles = a.roles(all[a.cfg.RolesClaim])
	if !cached { // only a token that passed every check is remembered; a failure is never stored
		a.sigs.store(digest, unixTime(*c.Exp), now, gen)
	}
	return p, nil
}

func (a *Authenticator) roles(raw json.RawMessage) []Role {
	var list []string
	if json.Unmarshal(raw, &list) != nil {
		var one string
		if json.Unmarshal(raw, &one) == nil && one != "" {
			list = strings.Fields(one) // a space-separated string, as OAuth scope does
		}
	}
	seen := map[Role]bool{}
	var out []Role
	for _, g := range list {
		if r, ok := a.roleMap[strings.TrimPrefix(g, "/")]; ok && !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out
}

// key finds the verification key for kid, refetching the set once if it is unknown or stale.
func (a *Authenticator) key(ctx context.Context, kid, alg string) (*jose.JSONWebKey, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	find := func() *jose.JSONWebKey {
		if a.keys == nil {
			return nil
		}
		ks := a.keys.Key(kid)
		if kid == "" && len(a.keys.Keys) == 1 {
			ks = a.keys.Keys
		}
		for i := range ks {
			k := ks[i]
			if k.Use != "" && k.Use != "sig" {
				continue
			}
			if k.Algorithm != "" && alg != "" && k.Algorithm != alg {
				continue
			}
			return &k
		}
		return nil
	}
	stale := a.keys == nil || a.cfg.Now().Sub(a.fetchedAt) > a.cfg.JWKSMaxAge
	if k := find(); k != nil && !stale {
		return k, nil
	}
	if len(a.cfg.StaticJWKS) == 0 && a.cfg.Now().Sub(a.lastTry) >= a.cfg.JWKSMinRefresh {
		a.lastTry = a.cfg.Now()
		if err := a.fetchLocked(ctx); err != nil {
			if k := find(); k != nil { // IdP unreachable: keys already cached keep working until they are rotated away
				return k, nil
			}
			return nil, fmt.Errorf("cannot load the signing keys: %v", err)
		}
	}
	if k := find(); k != nil {
		return k, nil
	}
	return nil, fmt.Errorf("unknown signing key %q", kid)
}

func (a *Authenticator) fetchLocked(ctx context.Context) error {
	if a.jwksURL == "" {
		var d struct {
			Issuer  string `json:"issuer"`
			JWKSURI string `json:"jwks_uri"`
		}
		if err := a.getJSON(ctx, strings.TrimSuffix(a.cfg.Issuer, "/")+"/.well-known/openid-configuration", &d); err != nil {
			return err
		}
		if d.Issuer != a.cfg.Issuer || d.JWKSURI == "" {
			return errors.New("discovery document does not match the issuer")
		}
		a.jwksURL = d.JWKSURI
	}
	var ks jose.JSONWebKeySet
	if err := a.getJSON(ctx, a.jwksURL, &ks); err != nil {
		return err
	}
	if len(ks.Keys) == 0 {
		return errors.New("empty key set")
	}
	a.keys, a.fetchedAt = &ks, a.cfg.Now()
	a.sigs.clear() // a key the provider removed must stop being honoured
	return nil
}

func (a *Authenticator) getJSON(ctx context.Context, u string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := a.cfg.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("%s: HTTP %d", u, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(v)
}
