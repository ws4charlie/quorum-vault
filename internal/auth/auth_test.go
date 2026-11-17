package auth_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/auth"
	"github.com/ws4charlie/quorum-vault/internal/auth/authtest"
)

const iss, aud = "https://idp.example/realms/qv", "qv-core"

func setup(t *testing.T) (*authtest.Issuer, *auth.Authenticator) {
	t.Helper()
	is := authtest.New(iss, aud)
	a, err := auth.New(is.Config(), auth.Test, false)
	if err != nil {
		t.Fatal(err)
	}
	return is, a
}

func bearer(tok string) *http.Request {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	return r
}

func TestValidTokenNamesTheCallerBySub(t *testing.T) {
	is, a := setup(t)
	p, fail := a.Authenticate(bearer(is.Token(authtest.Spec{Sub: "u-1", Roles: []string{"/approver", "ignored"}})))
	if fail != nil {
		t.Fatal(fail)
	}
	if p.Sub != "u-1" || p.Issuer != iss || !p.Has(auth.Approver) || p.Has(auth.Admin) || len(p.Roles) != 1 || p.ACR != "aal3" || p.AuthTime.IsZero() {
		t.Fatalf("%+v", p)
	}
}

func TestTokensThatMustBeRefused(t *testing.T) {
	is, a := setup(t)
	cases := map[string]string{
		"expired":                 is.Token(authtest.Spec{Sub: "u", Lifetime: -2 * time.Minute}),
		"wrong issuer":            is.Token(authtest.Spec{Sub: "u", Issuer: "https://evil.example"}),
		"wrong audience":          is.Token(authtest.Spec{Sub: "u", Audience: "other"}),
		"not yet valid":           is.Token(authtest.Spec{Sub: "u", NotBefore: time.Hour}),
		"bad signature":           is.TokenWithForeignKey(authtest.Spec{Sub: "u"}, is.Rotate(true)),
		"unknown key id":          is.TokenWithForeignKey(authtest.Spec{Sub: "u"}, "nope"),
		"no sub":                  is.Token(authtest.Spec{}),
		"session too old":         is.Token(authtest.Spec{Sub: "u", AuthAge: 13 * time.Hour}),
		"user without login time": is.Token(authtest.Spec{Sub: "u", Service: true, Client: "some-user-client"}),
		"not a JWT":               "abc.def",
	}
	// the bad-signature case rotated the issuer; a verifier made before holds the old static set, which is what a real one would too
	for name, tok := range cases {
		if _, fail := a.Authenticate(bearer(tok)); fail == nil || fail.Status != 401 {
			t.Errorf("%s: accepted (%v)", name, fail)
		}
	}
}

func TestAlgNoneAndHMACAreRefused(t *testing.T) {
	_, a := setup(t)
	for _, tok := range []string{
		"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlL3JlYWxtcy9xdiIsInN1YiI6InUifQ.",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlL3JlYWxtcy9xdiIsInN1YiI6InUifQ.c2ln",
	} {
		if _, fail := a.Authenticate(bearer(tok)); fail == nil {
			t.Fatal("accepted")
		}
	}
}

func TestRotatedJWKSIsFetchedOnAnUnknownKid(t *testing.T) {
	is := authtest.New(iss, aud)
	srv := is.Serve()
	defer srv.Close()
	now := time.Now()
	clock := &now
	cfg := auth.Config{Issuer: iss, Audience: aud, JWKSURL: srv.URL + "/jwks", JWKSMinRefresh: time.Second, Now: func() time.Time { return *clock }}
	a, err := auth.New(cfg, auth.Test, false)
	if err != nil {
		t.Fatal(err)
	}
	is.Now = func() time.Time { return *clock }
	if _, fail := a.Authenticate(bearer(is.Token(authtest.Spec{Sub: "u"}))); fail != nil {
		t.Fatal(fail)
	}
	is.Rotate(false) // the old key leaves the set
	tok := is.Token(authtest.Spec{Sub: "u"})
	if _, fail := a.Authenticate(bearer(tok)); fail == nil {
		t.Fatal("refetch happened inside the minimum interval")
	}
	*clock = clock.Add(2 * time.Second)
	if _, fail := a.Authenticate(bearer(tok)); fail != nil {
		t.Fatalf("a rotated key must be found after a refetch: %v", fail)
	}
}

func TestDiscoveryFindsTheJWKS(t *testing.T) {
	is := authtest.New("", aud)
	srv := is.Serve()
	defer srv.Close()
	is.URL = srv.URL
	a, err := auth.New(auth.Config{Issuer: srv.URL, Audience: aud}, auth.Test, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, fail := a.Authenticate(bearer(is.Token(authtest.Spec{Sub: "u"}))); fail != nil {
		t.Fatal(fail)
	}
}

func TestStepUp(t *testing.T) {
	is, a := setup(t)
	rule := auth.Rule{Roles: []auth.Role{auth.Approver}, StepUp: true}
	check := func(s authtest.Spec) *auth.Failure {
		p, fail := a.Authenticate(bearer(is.Token(s)))
		if fail != nil {
			t.Fatal(fail)
		}
		return a.Authorize(p, rule)
	}
	if f := check(authtest.Spec{Sub: "u", Roles: []string{"approver"}}); f != nil {
		t.Fatal(f)
	}
	f := check(authtest.Spec{Sub: "u", Roles: []string{"approver"}, AuthAge: 10 * time.Minute})
	if f == nil || f.Status != 401 || !strings.Contains(f.Challenge, "insufficient_user_authentication") || !strings.Contains(f.Challenge, `acr_values="aal3"`) {
		t.Fatalf("stale login: %+v", f)
	}
	if f := check(authtest.Spec{Sub: "u", Roles: []string{"approver"}, ACR: "1"}); f == nil || f.Status != 401 {
		t.Fatalf("weak acr: %+v", f)
	}
	if f := check(authtest.Spec{Sub: "u", Roles: []string{"requester"}}); f == nil || f.Status != 403 {
		t.Fatalf("missing role: %+v", f)
	}
}

func TestServiceTokensSkipStepUpButNotHumanOnlyRoutes(t *testing.T) {
	is, a := setup(t)
	p, fail := a.Authenticate(bearer(is.Token(authtest.Spec{Sub: "svc-1", Client: "qv-svc", Service: true, Roles: []string{"operator"}})))
	if fail != nil || !p.Service {
		t.Fatalf("%v %+v", fail, p)
	}
	if f := a.Authorize(p, auth.Rule{Roles: []auth.Role{auth.Operator}, StepUp: true}); f != nil {
		t.Fatal(f)
	}
	if f := a.Authorize(p, auth.Rule{Roles: []auth.Role{auth.Operator}, HumanOnly: true}); f == nil || f.Status != 403 {
		t.Fatalf("%v", f)
	}
}

func TestDevHeader(t *testing.T) {
	is, off := setup(t)
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Actor", "alice")
	if _, f := off.Authenticate(r); f == nil || f.Status != 401 {
		t.Fatal("X-Actor must be refused without the dev flag")
	}
	on, err := auth.New(is.Config(), auth.Dev, true)
	if err != nil {
		t.Fatal(err)
	}
	if p, f := on.Authenticate(r); f != nil || p.Sub != "alice" || !p.Dev {
		t.Fatalf("%v %+v", f, p)
	}
}

func TestProductionRefusesLooseSetups(t *testing.T) {
	is := authtest.New(iss, aud)
	if _, err := auth.New(is.Config(), auth.Production, true); err == nil {
		t.Fatal("dev header in production")
	}
	if _, err := auth.New(is.Config(), auth.Production, false); err == nil {
		t.Fatal("static test keys in production")
	}
	if _, err := auth.New(auth.Config{Issuer: "http://idp.example", Audience: aud}, auth.Production, false); err == nil {
		t.Fatal("http issuer in production")
	}
	if _, err := auth.New(auth.Config{Issuer: iss, Audience: aud}, auth.Production, false); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.New(auth.Config{}, auth.Production, false); err == nil {
		t.Fatal("no issuer")
	}
	t.Setenv("QV_ENV", "prod-typo")
	if auth.EnvironmentFromEnv() != auth.Production {
		t.Fatal("an unknown QV_ENV must mean production")
	}
}
