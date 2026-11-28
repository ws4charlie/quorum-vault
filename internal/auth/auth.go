// Package auth names the caller of the core API from a verified OpenID Connect access token.
//
// Users arrive with a token from an authorization-code login; services arrive with a client-credentials token. Both are checked
// the same way: signature against the issuer's JWKS, issuer, audience, expiry, not-before, and a session age limit. The actor
// of every action is the token's `sub`. Nothing here is specific to one identity provider: roles come from a configurable
// claim, and only the dev realm under deploy/keycloak is Keycloak.
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/ws4charlie/quorum-vault/internal/pki"
)

// Role is what a route asks for. The set is small on purpose: each role is a separate duty that the dual-control rule keeps apart.
type Role string

const (
	// Requester opens customers, deposit addresses and withdrawals.
	Requester Role = "requester"
	// Approver approves and rejects withdrawals. A requester is never an approver of their own withdrawal (the core checks sub).
	Approver Role = "approver"
	// Operator runs the cold ceremonies, refills, batches, reconcile and the books of the cold address.
	Operator Role = "operator"
	// Admin changes what the factory contracts do (destination, guardian, admin, freeze). Admin does not imply any other role.
	Admin Role = "admin"
	// Gate is the AgentGate service: it may ask for the signature of a Gate-governed payment (docs/gate-credential.md, "The signing API") and
	// nothing else. The core refuses a caller that holds it on every other route, whatever other roles it holds.
	Gate Role = "gate"
)

// Roles lists every role, for configuration checks.
var Roles = []Role{Requester, Approver, Operator, Admin, Gate}

// PersonRoles are the roles of people: the X-Actor dev principal holds all of them and never Gate, which is a service's only role.
var PersonRoles = []Role{Requester, Approver, Operator, Admin}

// Environment says how strict start-up is. The default is Production: an unset QV_ENV is production.
type Environment string

const (
	Production Environment = "production"
	Dev        Environment = "dev"
	Test       Environment = "test"
)

// EnvironmentFromEnv reads QV_ENV. Anything but "dev" or "test" is production, so a typo cannot loosen anything.
func EnvironmentFromEnv() Environment {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("QV_ENV"))) {
	case "dev":
		return Dev
	case "test":
		return Test
	}
	return Production
}

// E2EClients are the OAuth client ids of the dev realm's test clients (deploy/keycloak/quorumvault-realm.json, the clients named
// "TEST ONLY"). They skip the passkey and a mapper hard-codes acr=aal3 on their tokens, so a token of one of them proves no step-up.
// Production refuses them twice: New refuses a configuration that names one (audience or service client), and Verify refuses a token
// whose azp or client_id is one (either claim, case and surrounding space ignored), whatever issuer signed it. A test in this package fails when the realm file gains a test
// client that is missing here.
var E2EClients = []string{"qv-e2e", "qv-approve-e2e", "qv-approval-e2e"}

func isE2EClient(id string) bool {
	for _, c := range E2EClients {
		if strings.EqualFold(strings.TrimSpace(id), c) {
			return true
		}
	}
	return false
}

// Config configures the verifier.
type Config struct {
	Issuer   string // exact `iss` of the tokens; its /.well-known/openid-configuration names the JWKS when JWKSURL is empty
	Audience string // the core API's audience: `aud` must contain it
	JWKSURL  string // optional override

	// RolesClaim is the claim that lists the caller's roles or groups (default "roles"). RoleMap turns what the IdP calls a
	// group or role into a core role; values not in the map are ignored. Empty RoleMap means the IdP uses the core names
	// ("requester", "approver", "operator", "admin"). A leading "/" (Keycloak group paths) is dropped.
	RolesClaim string
	RoleMap    map[string]Role

	// ServiceClients are the OAuth client ids (`azp`) allowed to call as a service with a client-credentials token. A token of
	// any other client is a user token and needs `auth_time`.
	ServiceClients []string

	ClockSkew    time.Duration // default 60 s
	MaxSession   time.Duration // overall session limit counted from `auth_time` (NIST AAL3: 12 h, the default)
	StepUpMaxAge time.Duration // how fresh `auth_time` must be on a step-up route (default 5 min)
	StepUpACR    string        // `acr` a step-up route needs (default "aal3")

	// JWKS refresh: a token with an unknown key id causes one refetch, at most once per JWKSMinRefresh (default 10 s); the cached
	// set is also refreshed after JWKSMaxAge (default 10 min). An IdP that is down does not lock out tokens signed with cached keys.
	JWKSMinRefresh time.Duration
	JWKSMaxAge     time.Duration

	// StaticJWKS is a JSON key set used instead of fetching. Only Test and Dev environments accept it (the test issuer).
	StaticJWKS []byte

	HTTP *http.Client
	Now  func() time.Time
}

// Principal is who called, as far as the token proves it.
type Principal struct {
	Issuer   string
	Sub      string // the actor
	Name     string // preferred_username or name, for logs and screens only
	Client   string // azp
	Roles    []Role
	ACR      string
	AuthTime time.Time // zero for a service
	TokenID  string    // jti
	Session  string    // sid
	Service  bool
	Dev      bool // came from the X-Actor dev header: nothing was verified
	// Cert is the name (spiffe://quorumvault/<zone>/<service>) of the TLS client certificate the caller presented and Authenticate checked
	// against the allow-list, person or service; empty when none was shown or no certificate is required.
	Cert string
}

// Has reports whether the principal holds role.
func (p *Principal) Has(r Role) bool {
	for _, x := range p.Roles {
		if x == r {
			return true
		}
	}
	return false
}

// Failure is an authentication or authorization refusal with its HTTP form.
type Failure struct {
	Status    int
	Code      string // a stable code for callers that branch on it (e.g. client_not_authorized); empty for most refusals
	Message   string
	Challenge string // WWW-Authenticate value, if any
}

func (f *Failure) Error() string { return f.Message }

// Write sends the refusal.
func (f *Failure) Write(w http.ResponseWriter) {
	if f.Challenge != "" {
		w.Header().Set("WWW-Authenticate", f.Challenge)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(f.Status)
	body := map[string]string{"error": f.Message}
	if f.Code != "" {
		body["code"], body["message"] = f.Code, f.Message
	}
	_ = json.NewEncoder(w).Encode(body)
}

// Authenticator verifies bearer tokens. The zero value is not usable; use New.
type Authenticator struct {
	cfg Config
	env Environment
	dev bool // accept X-Actor

	svcCert *serviceCert // when set, a service (client-credentials) caller must also present an allow-listed client certificate

	sigs *sigCache // tokens whose signature was verified, for at most sigCacheTTL

	mu        sync.Mutex
	keys      *jose.JSONWebKeySet
	fetchedAt time.Time
	lastTry   time.Time
	jwksURL   string
	services  map[string]bool
	roleMap   map[string]Role
}

// New checks the configuration against the environment and returns an Authenticator.
//
//   - Production (QV_ENV unset or anything but dev/test): the issuer must be an https URL, the dev header and static keys are refused,
//     and so is any E2EClients id as audience or service client.
//   - devActorHeader accepts "X-Actor" with nothing verified. It needs QV_ENV=dev or test.
func New(cfg Config, env Environment, devActorHeader bool) (*Authenticator, error) {
	if env != Dev && env != Test {
		env = Production
	}
	if devActorHeader && env == Production {
		return nil, errors.New("auth: the X-Actor dev header is refused in production (set QV_ENV=dev only on a development machine)")
	}
	if len(cfg.StaticJWKS) > 0 && env == Production {
		return nil, errors.New("auth: static JWKS (the test issuer) is refused in production")
	}
	if cfg.Issuer == "" && !devActorHeader {
		return nil, errors.New("auth: an issuer is required (or the dev header in a dev environment)")
	}
	if cfg.Issuer != "" {
		u, err := url.Parse(cfg.Issuer)
		if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
			return nil, fmt.Errorf("auth: bad issuer %q", cfg.Issuer)
		}
		if env == Production && u.Scheme != "https" {
			return nil, errors.New("auth: the issuer must be https in production")
		}
		if cfg.Audience == "" {
			return nil, errors.New("auth: an audience is required")
		}
	}
	if env == Production {
		for _, id := range append([]string{cfg.Audience}, cfg.ServiceClients...) {
			if isE2EClient(id) {
				return nil, fmt.Errorf("auth: %q is a test client of the dev realm (no passkey, hard-coded acr) and is refused in production", id)
			}
		}
	}
	if cfg.RolesClaim == "" {
		cfg.RolesClaim = "roles"
	}
	if cfg.ClockSkew == 0 {
		cfg.ClockSkew = 60 * time.Second
	}
	if cfg.MaxSession == 0 {
		cfg.MaxSession = 12 * time.Hour
	}
	if cfg.StepUpMaxAge == 0 {
		cfg.StepUpMaxAge = 5 * time.Minute
	}
	if cfg.StepUpACR == "" {
		cfg.StepUpACR = "aal3"
	}
	if cfg.JWKSMinRefresh == 0 {
		cfg.JWKSMinRefresh = 10 * time.Second
	}
	if cfg.JWKSMaxAge == 0 {
		cfg.JWKSMaxAge = 10 * time.Minute
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	a := &Authenticator{cfg: cfg, env: env, dev: devActorHeader, jwksURL: cfg.JWKSURL, sigs: newSigCache(), services: map[string]bool{}, roleMap: map[string]Role{}}
	for _, c := range cfg.ServiceClients {
		a.services[c] = true
	}
	if len(cfg.RoleMap) == 0 {
		for _, r := range Roles {
			a.roleMap[string(r)] = r
		}
	} else {
		for k, v := range cfg.RoleMap {
			ok := false
			for _, r := range Roles {
				ok = ok || r == v
			}
			if !ok {
				return nil, fmt.Errorf("auth: role map sends %q to unknown role %q", k, v)
			}
			a.roleMap[k] = v
		}
	}
	if len(cfg.StaticJWKS) > 0 {
		var ks jose.JSONWebKeySet
		if err := json.Unmarshal(cfg.StaticJWKS, &ks); err != nil {
			return nil, fmt.Errorf("auth: static JWKS: %w", err)
		}
		a.keys = &ks
		a.fetchedAt = cfg.Now().Add(1000 * 24 * time.Hour) // never stale; never refetched
	}
	return a, nil
}

type serviceCert struct {
	zone  string
	allow pki.Allow
}

// RequireServiceCert makes every service caller (a client-credentials token) present a TLS client certificate of the zone whose name is on
// allow. People keep coming with a bearer token alone. A stolen service token is then useless without the certificate's key.
func (a *Authenticator) RequireServiceCert(zone string, allow pki.Allow) {
	a.svcCert = &serviceCert{zone: zone, allow: allow}
}

// DevHeader reports whether X-Actor is accepted.
func (a *Authenticator) DevHeader() bool { return a != nil && a.dev }

// Authenticate names the caller of r. A bearer token is verified. Without one, X-Actor is accepted only when the dev header is on.
func (a *Authenticator) Authenticate(r *http.Request) (*Principal, *Failure) {
	if a == nil {
		return nil, &Failure{Status: http.StatusUnauthorized, Message: "authentication is not configured"}
	}
	h := r.Header.Get("Authorization")
	if h == "" {
		if actor := r.Header.Get("X-Actor"); actor != "" {
			if !a.dev {
				return nil, &Failure{Status: http.StatusUnauthorized, Message: "X-Actor is not accepted; send a bearer token", Challenge: `Bearer realm="qv-core"`}
			}
			return &Principal{Issuer: "dev:x-actor", Sub: actor, Name: actor, Roles: append([]Role(nil), PersonRoles...), Dev: true, ACR: a.cfg.StepUpACR, AuthTime: a.cfg.Now()}, nil
		}
		return nil, &Failure{Status: http.StatusUnauthorized, Message: "a bearer token is required", Challenge: `Bearer realm="qv-core"`}
	}
	scheme, tok, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(tok) == "" {
		return nil, &Failure{Status: http.StatusUnauthorized, Message: "Authorization must be a Bearer token", Challenge: `Bearer realm="qv-core"`}
	}
	p, err := a.Verify(r.Context(), strings.TrimSpace(tok))
	if err != nil {
		return nil, &Failure{Status: http.StatusUnauthorized, Message: "invalid token: " + err.Error(), Challenge: `Bearer realm="qv-core", error="invalid_token"`}
	}
	if a.svcCert != nil {
		hasCert := r.TLS != nil && len(r.TLS.PeerCertificates) > 0
		if p.Service && !hasCert {
			return nil, &Failure{Status: http.StatusForbidden, Message: "a service must present its TLS client certificate"}
		}
		if hasCert {
			// The certificate's name is recorded for every caller that shows one, person or service, so a route can confine a certificate (AgentGate's)
			// whatever token comes with it. A service's certificate must pass; a person's that does not pass names nobody (the TLS handshake already
			// checked the chain and the allow-list).
			id, err := pki.CheckPeer(r.TLS.PeerCertificates[0], a.svcCert.zone, a.svcCert.allow)
			if err != nil && p.Service {
				return nil, &Failure{Status: http.StatusForbidden, Message: "service certificate refused: " + err.Error()}
			}
			if err == nil {
				p.Cert = id
			}
		}
	}
	return p, nil
}

// Authorize applies a route's rule to an authenticated principal.
func (a *Authenticator) Authorize(p *Principal, rule Rule) *Failure {
	if rule.HumanOnly && p.Service {
		return &Failure{Status: http.StatusForbidden, Message: "this route is for people, not services"}
	}
	if len(rule.Roles) > 0 {
		ok := false
		for _, r := range rule.Roles {
			ok = ok || p.Has(r)
		}
		if !ok {
			return &Failure{Status: http.StatusForbidden, Message: fmt.Sprintf("needs one of the roles %v", rule.Roles)}
		}
	}
	if rule.StepUp && !p.Service && !p.Dev {
		fresh := a.cfg.Now().Sub(p.AuthTime) <= a.cfg.StepUpMaxAge
		if !fresh || p.ACR != a.cfg.StepUpACR {
			return &Failure{Status: http.StatusUnauthorized, Message: "step-up authentication required",
				Challenge: fmt.Sprintf(`Bearer realm="qv-core", error="insufficient_user_authentication", error_description="a fresh authentication is required", acr_values="%s", max_age="%d"`,
					a.cfg.StepUpACR, int(a.cfg.StepUpMaxAge.Seconds()))}
		}
	}
	return nil
}

// Rule is what one route asks for.
type Rule struct {
	Roles     []Role // any one of them; empty means any authenticated caller
	StepUp    bool   // users need a fresh `auth_time` and the required `acr`; services (no interactive login) are exempt
	HumanOnly bool   // refuse service tokens
}

type ctxKey struct{}

// WithPrincipal stores p in ctx.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// FromContext returns the principal the route guard stored.
func FromContext(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(ctxKey{}).(*Principal)
	return p, ok
}
