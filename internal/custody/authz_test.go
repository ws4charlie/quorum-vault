package custody

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/auth"
	"github.com/ws4charlie/quorum-vault/internal/auth/authtest"
)

const tIss, tAud = "https://idp.test/realms/qv", "qv-core"

func apiWith(t *testing.T, s *Service, dev bool) (*authtest.Issuer, http.Handler) {
	t.Helper()
	is := authtest.New(tIss, tAud)
	a, err := auth.New(is.Config(), auth.Test, dev)
	if err != nil {
		t.Fatal(err)
	}
	return is, NewAPI(s, nil, nil, a).Handler()
}

func do(h http.Handler, method, path string, hdr map[string]string, body any) *httptest.ResponseRecorder {
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	r := httptest.NewRequest(method, path, rd)
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func tok(is *authtest.Issuer, s authtest.Spec) map[string]string {
	return map[string]string{"Authorization": "Bearer " + is.Token(s)}
}

// Every route has a rule (Handler panics otherwise), and every rule belongs to a route.
func TestEveryRouteHasARuleAndEveryRuleARoute(t *testing.T) {
	is := authtest.New(tIss, tAud)
	a, _ := auth.New(is.Config(), auth.Test, false)
	NewAPI(nil, nil, nil, a).Handler()
	src := routePatterns(t)
	for p := range routeRules {
		if !src[p] {
			t.Errorf("rule for %q, which is not a route", p)
		}
	}
	for p := range src {
		if _, ok := routeRules[p]; !ok {
			t.Errorf("route %q has no rule", p)
		}
	}
}

func routePatterns(t *testing.T) map[string]bool {
	t.Helper()
	b, err := osReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, l := range strings.Split(string(b), "\n") {
		if i := strings.Index(l, "a.handle(mux, \""); i >= 0 {
			rest := l[i+len("a.handle(mux, \""):]
			out[rest[:strings.Index(rest, "\"")]] = true
		}
	}
	return out
}

func TestRefusalsNeedNoDatabase(t *testing.T) {
	is, h := apiWith(t, nil, false)
	if w := do(h, "POST", "/v2/customers", map[string]string{"X-Actor": "alice"}, map[string]any{"id": "c1"}); w.Code != 401 {
		t.Fatalf("X-Actor without the dev flag: %d", w.Code)
	}
	if w := do(h, "POST", "/v2/customers", nil, map[string]any{"id": "c1"}); w.Code != 401 || w.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("no token: %d", w.Code)
	}
	if w := do(h, "POST", "/v2/withdrawals/w1/approvals", tok(is, authtest.Spec{Sub: "bob", Roles: []string{"requester"}}), map[string]any{}); w.Code != 403 {
		t.Fatalf("missing role: %d", w.Code)
	}
	w := do(h, "POST", "/v2/withdrawals/w1/approvals", tok(is, authtest.Spec{Sub: "bob", Roles: []string{"approver"}, AuthAge: time.Hour}), map[string]any{})
	if w.Code != 401 || !strings.Contains(w.Header().Get("WWW-Authenticate"), "insufficient_user_authentication") {
		t.Fatalf("stale login: %d %q", w.Code, w.Header().Get("WWW-Authenticate"))
	}
	// The CPFP trigger: an operator, freshly logged in, a human. Not a requester, not a stale login, not a service.
	cp := "/v2/withdrawals/w1/cpfp"
	if w := do(h, "POST", cp, tok(is, authtest.Spec{Sub: "bob", Roles: []string{"requester"}}), nil); w.Code != 403 {
		t.Fatalf("CPFP, missing role: %d", w.Code)
	}
	if w := do(h, "POST", cp, tok(is, authtest.Spec{Sub: "bob", Roles: []string{"operator"}, AuthAge: time.Hour}), nil); w.Code != 401 || !strings.Contains(w.Header().Get("WWW-Authenticate"), "insufficient_user_authentication") {
		t.Fatalf("CPFP, stale login: %d %q", w.Code, w.Header().Get("WWW-Authenticate"))
	}
	if w := do(h, "POST", cp, tok(is, authtest.Spec{Sub: "svc", Client: "qv-svc", Service: true, Roles: []string{"operator"}}), nil); w.Code != 403 {
		t.Fatalf("CPFP, a service: %d", w.Code)
	}
	if w := do(h, "POST", "/v2/cold/actions", tok(is, authtest.Spec{Sub: "svc", Client: "qv-svc", Service: true, Roles: []string{"admin"}}), map[string]any{}); w.Code != 403 {
		t.Fatalf("a service on an admin route: %d", w.Code)
	}
}

func TestVerifiedIdentityReachesTheAuditTrailAndSelfApprovalUsesSub(t *testing.T) {
	ctx := context.Background()
	s, _ := newSvc(t)
	is, h := apiWith(t, s, false)

	req := tok(is, authtest.Spec{Sub: "ini", Roles: []string{"requester"}})
	if w := do(h, "POST", "/v2/customers", req, map[string]any{"id": "c1"}); w.Code != 201 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	var n int
	var id Identity
	var raw []byte
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE topic='qv.audit' AND payload->>'type'='api.write' AND payload->'identity'->>'sub'='ini'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("api.write rows %d %v", n, err)
	}
	if err := s.Pool.QueryRow(ctx, `SELECT payload->'identity' FROM outbox WHERE topic='qv.audit' AND payload->>'type'='customer.created'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &id); err != nil {
		t.Fatal(err)
	}
	if id.Issuer != tIss || id.Sub != "ini" || id.ACR != "aal3" || id.AuthTime == 0 || id.TokenID == "" || id.Session == "" {
		t.Fatalf("identity in the audit row: %+v", id)
	}

	// Self-approval: the requester's sub is the actor, so an approver token with the same sub is refused by the core.
	if err := s.transferForTest(ctx, "c1", 1000); err != nil {
		t.Fatal(err)
	}
	to := "0x52908400098527886E0F7030069857D2E4169EE7"
	w1, _, err := s.RequestWithdrawal(WithActorForTest(ctx, "ini"), WithdrawalRequest{Actor: "ini", IdempotencyKey: "k", Customer: "c1", Asset: "ETH", To: to, Amount: big.NewInt(300)})
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"actor": "ini", "signature": strings.Repeat("00", 64)}
	if w := do(h, "POST", "/v2/withdrawals/"+w1.ID+"/approvals", tok(is, authtest.Spec{Sub: "ini", Roles: []string{"approver"}}), body); w.Code != 403 {
		t.Fatalf("self-approval: %d %s", w.Code, w.Body)
	}
	body["actor"] = "alice"
	if w := do(h, "POST", "/v2/withdrawals/"+w1.ID+"/approvals", tok(is, authtest.Spec{Sub: "ini", Roles: []string{"approver"}}), body); w.Code != 400 {
		t.Fatalf("a body actor other than sub: %d", w.Code)
	}
	body["actor"] = "alice"
	if w := do(h, "POST", "/v2/withdrawals/"+w1.ID+"/approvals", tok(is, authtest.Spec{Sub: "alice", Roles: []string{"approver"}, AuthAge: time.Hour}), body); w.Code != 401 {
		t.Fatalf("stale: %d", w.Code)
	}
	if w := do(h, "POST", "/v2/withdrawals/"+w1.ID+"/approvals", tok(is, authtest.Spec{Sub: "alice", Roles: []string{"approver"}}), body); w.Code != 200 {
		t.Fatalf("fresh login: %d %s", w.Code, w.Body)
	}
}

func osReadFile(p string) ([]byte, error) { return os.ReadFile(p) }

func WithActorForTest(ctx context.Context, a string) context.Context { return WithActor(ctx, a) }

func (s *Service) transferForTest(ctx context.Context, cust string, amt int64) error {
	return InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		return s.transfer(ctx, tx, "pre-"+cust, depAcct(testChain, "ETH"), custAcct(cust, testChain, "ETH"), big.NewInt(amt), nil)
	})
}

// The requester in the signed intent is the verified token's sub, never a name the caller supplies.
func TestIntentRequesterIsTheVerifiedSub(t *testing.T) {
	ctx := context.Background()
	s, _ := newSvc(t)
	is, h := apiWith(t, s, false)
	if _, _, err := s.CreateCustomer(ctx, "ops", "c1", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.transferForTest(ctx, "c1", 1000); err != nil {
		t.Fatal(err)
	}
	hdr := tok(is, authtest.Spec{Sub: "sub-of-ini", Roles: []string{"requester"}, Claims: map[string]any{"preferred_username": "Display Name", "name": "Someone Else"}})
	hdr["Idempotency-Key"] = "k-sub"
	hdr["X-Actor"] = "mallory" // ignored: a bearer token wins and the header is not accepted without the dev flag
	w := do(h, "POST", "/v2/withdrawals", hdr, map[string]any{"customer": "c1", "asset": "ETH", "to": "0x52908400098527886E0F7030069857D2E4169EE7", "amount": "300"})
	if w.Code != 201 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	var wd Withdrawal
	if err := json.Unmarshal(w.Body.Bytes(), &wd); err != nil {
		t.Fatal(err)
	}
	if wd.RequestedBy != "sub-of-ini" {
		t.Fatalf("requested_by %q", wd.RequestedBy)
	}
	if got := s.IntentOf(wd).RequestedBy; got != "sub-of-ini" {
		t.Fatalf("intent requester %q", got)
	}
	r := do(h, "GET", "/v2/withdrawals/"+wd.ID+"/intent", tok(is, authtest.Spec{Sub: "ops", Roles: []string{"operator"}}), nil)
	if r.Code != 200 || !strings.Contains(r.Body.String(), `"sub-of-ini"`) {
		t.Fatalf("intent response: %d %s", r.Code, r.Body)
	}
}

// The approvals route takes exactly one of an Ed25519 signature or a WebAuthn assertion, in shape only: the core never judges either.
func TestApprovalsRouteAcceptsEd25519OrWebAuthn(t *testing.T) {
	ctx := context.Background()
	s, _ := newSvc(t)
	is, h := apiWith(t, s, false)
	if _, _, err := s.CreateCustomer(ctx, "ops", "c1", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.transferForTest(ctx, "c1", 1000); err != nil {
		t.Fatal(err)
	}
	to := "0x52908400098527886E0F7030069857D2E4169EE7"
	w1, _, err := s.RequestWithdrawal(WithActorForTest(ctx, "ini"), WithdrawalRequest{Actor: "ini", IdempotencyKey: "k", Customer: "c1", Asset: "ETH", To: to, Amount: big.NewInt(300)})
	if err != nil {
		t.Fatal(err)
	}
	path := "/v2/withdrawals/" + w1.ID + "/approvals"
	b64 := func(n int) string { return base64.RawURLEncoding.EncodeToString(make([]byte, n)) }
	cd := base64.RawURLEncoding.EncodeToString([]byte(`{"type":"webauthn.get"}`))
	wa := func(mod func(m map[string]string)) map[string]string {
		m := map[string]string{"credential_id": b64(16), "authenticator_data": b64(37), "client_data_json": cd, "signature": b64(70)}
		if mod != nil {
			mod(m)
		}
		return m
	}
	post := func(sub string, body map[string]any) int {
		return do(h, "POST", path, tok(is, authtest.Spec{Sub: sub, Roles: []string{"approver"}}), body).Code
	}
	edSig := strings.Repeat("00", 64)
	for name, c := range map[string]struct {
		body map[string]any
		code int
	}{
		"both set":              {map[string]any{"actor": "alice", "signature": edSig, "webauthn": wa(nil)}, 400},
		"neither set":           {map[string]any{"actor": "alice"}, 400},
		"padded base64":         {map[string]any{"actor": "alice", "webauthn": wa(func(m map[string]string) { m["signature"] = base64.URLEncoding.EncodeToString(make([]byte, 70)) })}, 400},
		"not base64url":         {map[string]any{"actor": "alice", "webauthn": wa(func(m map[string]string) { m["credential_id"] = "+/+/" })}, 400},
		"client data not JSON":  {map[string]any{"actor": "alice", "webauthn": wa(func(m map[string]string) { m["client_data_json"] = b64(20) })}, 400},
		"empty credential":      {map[string]any{"actor": "alice", "webauthn": wa(func(m map[string]string) { m["credential_id"] = "" })}, 400},
		"short authenticator":   {map[string]any{"actor": "alice", "webauthn": wa(func(m map[string]string) { m["authenticator_data"] = b64(36) })}, 400},
		"oversized credential":  {map[string]any{"actor": "alice", "webauthn": wa(func(m map[string]string) { m["credential_id"] = b64(maxCredentialID + 1) })}, 400},
		"oversized auth data":   {map[string]any{"actor": "alice", "webauthn": wa(func(m map[string]string) { m["authenticator_data"] = b64(maxAuthenticator + 1) })}, 400},
		"oversized client data": {map[string]any{"actor": "alice", "webauthn": wa(func(m map[string]string) { m["client_data_json"] = b64(maxClientDataJSON + 1) })}, 400},
		"oversized signature":   {map[string]any{"actor": "alice", "webauthn": wa(func(m map[string]string) { m["signature"] = b64(maxAssertionSig + 1) })}, 400},
		"unknown field":         {map[string]any{"actor": "alice", "webauthn": map[string]string{"credential_id": b64(16), "extra": "x"}}, 400},
		"body actor not sub":    {map[string]any{"actor": "bob", "webauthn": wa(nil)}, 400},
	} {
		if got := post("alice", c.body); got != c.code {
			t.Errorf("%s: %d, want %d", name, got, c.code)
		}
	}
	// The requester cannot approve with an assertion either.
	if got := post("ini", map[string]any{"actor": "ini", "webauthn": wa(nil)}); got != 403 {
		t.Errorf("self-approval with an assertion: %d", got)
	}
	// A well-formed assertion is stored as given (the zone judges it) and carried in the job's approval.
	if got := post("alice", map[string]any{"actor": "alice", "webauthn": wa(nil)}); got != 200 {
		t.Fatalf("assertion: %d", got)
	}
	// Ed25519 is unchanged: a second approver by signature counts too.
	if got := post("bob", map[string]any{"actor": "bob", "signature": edSig}); got != 200 {
		t.Fatalf("ed25519: %d", got)
	}
	got, err := s.GetWithdrawal(ctx, w1.ID)
	if err != nil || len(got.Approvals) != 2 {
		t.Fatalf("approvals %+v, %v", got.Approvals, err)
	}
	if a := got.Approvals[0]; a.Actor != "alice" || a.WebAuthn == nil || len(a.Signature) != 0 || len(a.WebAuthn.CredentialID) != 16 || len(a.WebAuthn.Signature) != 70 {
		t.Fatalf("stored webauthn approval %+v", a)
	}
	if a := got.Approvals[1]; a.Actor != "bob" || a.WebAuthn != nil || len(a.Signature) != 64 {
		t.Fatalf("stored ed25519 approval %+v", a)
	}
}
