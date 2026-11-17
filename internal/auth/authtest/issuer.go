// Package authtest is the test issuer: a local signing key and the matching JWKS, for unit tests and for the e2e groups that do
// not need a real identity provider. The core trusts such a key set only when QV_ENV is dev or test (auth.New refuses it in
// production), so a token from here is worthless anywhere else.
package authtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/ws4charlie/quorum-vault/internal/auth"
)

// Issuer signs tokens with ES256 keys it can rotate.
type Issuer struct {
	URL      string // the `iss` of its tokens
	Audience string

	mu   sync.Mutex
	keys []*key
	n    int
	Now  func() time.Time
}

type key struct {
	kid  string
	priv *ecdsa.PrivateKey
}

// New returns an issuer named issuer, with one key.
func New(issuer, audience string) *Issuer {
	i := &Issuer{URL: issuer, Audience: audience, Now: time.Now}
	i.Rotate(false)
	return i
}

// Rotate adds a new signing key and starts signing with it; keepOld false drops the old keys from the JWKS.
func (i *Issuer) Rotate(keepOld bool) string {
	i.mu.Lock()
	defer i.mu.Unlock()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	i.n++
	k := &key{kid: "test-key-" + string(rune('0'+i.n%10)) + time.Now().Format("150405.000000"), priv: priv}
	if keepOld {
		i.keys = append(i.keys, k)
	} else {
		i.keys = []*key{k}
	}
	return k.kid
}

// JWKS is the public key set, as JSON.
func (i *Issuer) JWKS() []byte {
	i.mu.Lock()
	defer i.mu.Unlock()
	ks := jose.JSONWebKeySet{}
	for _, k := range i.keys {
		ks.Keys = append(ks.Keys, jose.JSONWebKey{Key: &k.priv.PublicKey, KeyID: k.kid, Algorithm: "ES256", Use: "sig"})
	}
	b, _ := json.Marshal(ks)
	return b
}

// Serve serves discovery and the JWKS over HTTP, for a verifier that fetches (the rotation tests).
func (i *Issuer) Serve() *httptest.Server {
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": i.URL, "jwks_uri": srv.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(i.JWKS()) })
	srv = httptest.NewServer(mux)
	return srv
}

// Spec describes one token. Zero values give a valid fresh user token of one hour.
type Spec struct {
	Sub       string
	Roles     []string
	Client    string        // azp; default "qv-test"
	Service   bool          // client-credentials style: no auth_time, no acr
	AuthAge   time.Duration // how long ago the person authenticated
	ACR       string        // default "aal3"; "-" for none
	Lifetime  time.Duration // default 1 h
	Issuer    string        // override, for the wrong-issuer test
	Audience  string        // override
	NotBefore time.Duration
	KID       string // sign with this key id ("" = the newest)
	Claims    map[string]any
}

// Token signs a token.
func (i *Issuer) Token(s Spec) string {
	i.mu.Lock()
	k := i.keys[len(i.keys)-1]
	for _, x := range i.keys {
		if x.kid == s.KID {
			k = x
		}
	}
	i.mu.Unlock()
	return i.sign(k, s)
}

// TokenWithKey signs with a key the JWKS does not contain (the bad-signature and unknown-kid cases).
func (i *Issuer) TokenWithForeignKey(s Spec, kid string) string {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return i.sign(&key{kid: kid, priv: priv}, s)
}

func (i *Issuer) sign(k *key, s Spec) string {
	now := i.Now()
	if s.Client == "" {
		s.Client = "qv-test"
	}
	if s.Lifetime == 0 {
		s.Lifetime = time.Hour
	}
	iss, aud := i.URL, i.Audience
	if s.Issuer != "" {
		iss = s.Issuer
	}
	if s.Audience != "" {
		aud = s.Audience
	}
	c := map[string]any{
		"iss": iss, "sub": s.Sub, "aud": aud, "azp": s.Client,
		"iat": now.Unix(), "exp": now.Add(s.Lifetime).Unix(), "jti": "jti-" + now.Format("150405.000000000"),
		"roles": s.Roles, "preferred_username": s.Sub,
	}
	if s.NotBefore != 0 {
		c["nbf"] = now.Add(s.NotBefore).Unix()
	}
	if !s.Service {
		c["auth_time"] = now.Add(-s.AuthAge).Unix()
		c["sid"] = "sid-" + s.Sub
		acr := s.ACR
		if acr == "" {
			acr = "aal3"
		}
		if acr != "-" {
			c["acr"] = acr
		}
	}
	for n, v := range s.Claims {
		c[n] = v
	}
	sg, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: k.priv, KeyID: k.kid}}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		panic(err)
	}
	raw, err := jwt.Signed(sg).Claims(c).Serialize()
	if err != nil {
		panic(err)
	}
	return raw
}

// Config returns a verifier configuration that trusts this issuer's static key set.
func (i *Issuer) Config() auth.Config {
	return auth.Config{Issuer: i.URL, Audience: i.Audience, StaticJWKS: i.JWKS(), ServiceClients: []string{"qv-svc"}}
}

// RolesOf gives the roles the e2e harnesses use for the people they name: "ops" is an operator and admin, anyone else a requester and
// approver (the core still refuses a self-approval by sub).
func RolesOf(actor string) []string {
	if actor == "ops" {
		return []string{"operator", "admin"}
	}
	return []string{"requester", "approver"}
}
