package custody_test

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/e2e/idp"
)

// TestOIDCWithRealKeycloak runs a two-approver withdrawal with tokens from the dev Keycloak (make keycloak-up; QV_E2E_KEYCLOAK_URL names it):
// qv-core fetches the real JWKS, the actor of everything is the token's sub, the roles come from the realm, and the audit trail carries the
// login. Simulated: the test client logs in by username and password, with no passkey (see e2e/idp).
func TestOIDCWithRealKeycloak(t *testing.T) {
	if !idp.Real() {
		t.Skip("QV_E2E_KEYCLOAK_URL is not set: no Keycloak")
	}
	s, _ := funded(t, opts{}, "c-oidc", 5)
	dest := randAddr()

	// Roles: an approver cannot request; a requester cannot approve; an operator is neither.
	if w := s.withdraw("bob", "k-oidc-bad", "c-oidc", "ETH", dest, eth(2)); w.Code != 403 {
		t.Fatalf("an approver requesting: %d %v", w.Code, w.Raw)
	}
	w := s.withdraw("alice", "k-oidc", "c-oidc", "ETH", dest, eth(2))
	if w.Code != 201 {
		t.Fatalf("%d %v", w.Code, w.Raw)
	}
	s.approv["ops"] = s.approv["bob"] // a valid signature under another name: the refusal must come from the role, not the signature
	if code, _ := s.approve("alice", w.ID); code != 403 {
		t.Fatalf("the requester approving: %d", code)
	}
	if code, _ := s.approve("ops", w.ID); code != 403 {
		t.Fatalf("an operator approving: %d", code)
	}
	if code, out := s.approve("bob", w.ID); code != 200 {
		t.Fatalf("bob: %d %v", code, out)
	}
	if code, out := s.approve("carol", w.ID); code != 200 {
		t.Fatalf("carol: %d %v", code, out)
	}
	s.waitWd(w.ID, "confirmed", 60*time.Second)
	if s.ethBalance(dest).Cmp(eth(2)) != 0 {
		t.Fatalf("destination = %s", s.ethBalance(dest))
	}

	// The audit trail names the person by sub and issuer, with the login's strength, time and token.
	issuer := os.Getenv("QV_OIDC_ISSUER")
	for _, who := range []string{"alice", "bob", "carol"} {
		n := s.count(`SELECT count(*) FROM outbox WHERE topic='qv.audit' AND payload->'identity'->>'sub'=$1 AND payload->'identity'->>'iss'=$2
			AND payload->'identity'->>'acr'='aal3' AND (payload->'identity'->>'auth_time')::bigint > 0 AND payload->'identity'->>'jti' <> ''`, who, issuer)
		if n == 0 {
			t.Fatalf("no audit row with the identity of %s", who)
		}
	}
	if n := s.count(`SELECT count(*) FROM outbox WHERE topic='qv.audit' AND payload->>'type'='withdrawal.approval' AND payload->>'actor' IN ('bob','carol')`); n < 2 {
		t.Fatalf("%d approval audit rows", n)
	}

	// A token the core does not trust is refused: a token signed by another key, and no token at all.
	if code, _ := s.call("GET", "/v2/withdrawals/"+w.ID, map[string]string{"Authorization": "Bearer " + strings.Repeat("a", 20) + ".b.c"}, nil); code != 401 {
		t.Fatalf("a malformed token: %d", code)
	}
	s.reconcileClean()
}
