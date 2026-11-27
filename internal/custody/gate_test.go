package custody

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/ws4charlie/quorum-vault/internal/auth"
	"github.com/ws4charlie/quorum-vault/internal/chain/evm"
	"github.com/ws4charlie/quorum-vault/internal/auth/authtest"
	"github.com/ws4charlie/quorum-vault/internal/gatecred"
	"github.com/ws4charlie/quorum-vault/internal/gatecred/gatecredtest"
	"github.com/ws4charlie/quorum-vault/internal/pki"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

const (
	gateWallet   = "5f0c7a1e-3b2d-4c8e-9a6f-1d2e3f4a5b6c"
	gateAudience = "qv-test"
	gatePayee    = "0x00000000000000000000000000000000000fac01"
)

// gateEnv is the x402 world (one hot USDT shard, x402 enabled) with the signing API on: one Gate-governed wallet paying from shard 0, and the core's
// API behind a test issuer that requires service certificates.
type gateEnv struct {
	*x402Env
	is    *authtest.Issuer
	h     http.Handler
	certs map[string]*tls.ConnectionState
}

func gateWorld(t *testing.T) *gateEnv {
	t.Helper()
	e := x402World(t)
	e.s.Cfg.Gate = &GateConfig{Audience: gateAudience, Skew: 30 * time.Second, Wait: 300 * time.Millisecond,
		Wallets: map[string]GateWallet{gateWallet: {ID: gateWallet, Partition: e.s.Cfg.PartitionKey(x402Asset, 0).String(), Asset: x402Asset}}}
	is := authtest.New(tIss, tAud)
	a, err := auth.New(is.Config(), auth.Test, false)
	if err != nil {
		t.Fatal(err)
	}
	a.RequireServiceCert(pki.ZoneBusiness, pki.Allow{GateClient, pki.ID(pki.ZoneBusiness, "guardian")})
	root := t.TempDir()
	if err := pki.Init(root, time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := pki.IssueAll(root, time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	certs := map[string]*tls.ConnectionState{}
	for _, svc := range []string{"agentgate", "guardian"} {
		d := pki.Dir(root, pki.ZoneBusiness, svc)
		src, err := pki.NewSource(pki.SourceConfig{Name: svc, Zone: pki.ZoneBusiness, CertFile: d + "/tls.crt", KeyFile: d + "/tls.key", CAFile: d + "/ca.crt"})
		if err != nil {
			t.Fatal(err)
		}
		certs[svc] = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{src.Leaf()}}
	}
	return &gateEnv{x402Env: e, is: is, h: NewAPI(e.s, nil, nil, a).Handler(), certs: certs}
}

var gateToken = authtest.Spec{Sub: "agentgate", Client: "qv-svc", Service: true, Roles: []string{"gate"}}

// call sends body to path as the given token and certificate ("" for none).
func (g *gateEnv) call(method, path string, spec authtest.Spec, cert string, body []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+g.is.Token(spec))
	if cert != "" {
		r.TLS = g.certs[cert]
	}
	w := httptest.NewRecorder()
	g.h.ServeHTTP(w, r)
	return w
}

// cred is a credential of the test minter for the wallet, paying amount to the payee in USDT, valid from 990 to 1300 (the core's clock reads 1000).
func (g *gateEnv) cred(id string, amount int64, mod func(c *gatecred.Credential)) gatecred.Credential {
	c := gatecred.Credential{V: 1, KID: "test-only-1", CredentialID: id, ObligationID: "obl-1", Audience: gateAudience, WalletID: gateWallet,
		Chain: "eip155:1", Asset: strings.ToLower(g.s.Cfg.Assets[x402Asset].Address.Hex()), Payee: gatePayee, Amount: big.NewInt(amount).String(),
		IssuedAt: 990, ExpiresAt: 1300, PolicyVersion: "p-1", DecisionReason: "within budget"}
	if mod != nil {
		mod(&c)
	}
	return c
}

// typed is the EIP-712 typed data of an authorization from the wallet's address.
func (g *gateEnv) typed(t *testing.T, amount int64, nonce byte) json.RawMessage {
	t.Helper()
	var n [32]byte
	n[31] = nonce
	b, _, err := g.s.Cfg.EVM.NewPayload3009(x402Asset, g.payer, common.HexToAddress(gatePayee), big.NewInt(amount), 990, 1300, n)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (g *gateEnv) body(t *testing.T, c gatecred.Credential, payload json.RawMessage) []byte {
	t.Helper()
	b, err := json.Marshal(GateRequest{WalletID: gateWallet, Kind: GateKindEIP3009, Payload: payload, Credential: gatecredtest.Mint(gatecredtest.TestKey(1), c)})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (g *gateEnv) post(body []byte) *httptest.ResponseRecorder {
	return g.call("POST", "/v2/gate/signatures", gateToken, "agentgate", body)
}

func code(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var r GateRefusal
	if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
		t.Fatalf("body %s: %v", w.Body, err)
	}
	return r.Code
}

// zoneRejects marks the job rejected the way the gateway does.
func (g *gateEnv) zoneEnds(t *testing.T, id, status, reason string) {
	t.Helper()
	if _, err := g.s.Pool.Exec(context.Background(), `UPDATE sign_jobs SET status=$2, reject_reason=$3 WHERE id=$1`, "x402:"+id, status, reason); err != nil {
		t.Fatal(err)
	}
}

func (g *gateEnv) jobs(t *testing.T) int {
	t.Helper()
	var n int
	if err := g.s.Pool.QueryRow(context.Background(), `SELECT count(*) FROM sign_jobs`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// The signature the API returns is the hot key's over the EIP-712 digest, in r || s || v form, and recovers to the payer.
func (g *gateEnv) checkSigned(t *testing.T, w *httptest.ResponseRecorder, id string) string {
	t.Helper()
	if w.Code != 200 {
		t.Fatalf("want 200, got %d %s", w.Code, w.Body)
	}
	var ok GateSigned
	if err := json.Unmarshal(w.Body.Bytes(), &ok); err != nil {
		t.Fatal(err)
	}
	if ok.CredentialID != id || ok.WalletID != gateWallet || ok.Kind != GateKindEIP3009 {
		t.Fatalf("answer %+v", ok)
	}
	sig, err := hex.DecodeString(strings.TrimPrefix(ok.Signature, "0x"))
	if err != nil || len(sig) != 65 || (sig[64] != 27 && sig[64] != 28) {
		t.Fatalf("signature %q", ok.Signature)
	}
	job, err := signjob.Get(context.Background(), g.s.Pool, "x402:"+id)
	if err != nil {
		t.Fatal(err)
	}
	rs := append(append([]byte(nil), sig[:64]...), sig[64]-27)
	pub, err := crypto.SigToPub(job.Digest, rs)
	if err != nil || crypto.PubkeyToAddress(*pub) != g.payer {
		t.Fatalf("signature does not recover to the payer: %v", err)
	}
	return ok.Signature
}

// AgentGate may call the signing API and nothing else; nobody else may call the signing API.
func TestGateRouteAndAgentGateKeepToEachOther(t *testing.T) {
	g := gateWorld(t)
	operatorSvc := authtest.Spec{Sub: "svc", Client: "qv-svc", Service: true, Roles: []string{"operator"}}
	both := authtest.Spec{Sub: "agentgate", Client: "qv-svc", Service: true, Roles: []string{"gate", "operator"}}
	person := authtest.Spec{Sub: "alice", Roles: []string{"operator"}}
	for name, c := range map[string]struct {
		method, path string
		spec         authtest.Spec
		cert         string
		want         int
	}{
		"AgentGate on reconcile":                    {"GET", "/v2/reconcile", gateToken, "agentgate", 403},
		"AgentGate with operator role on reconcile": {"GET", "/v2/reconcile", both, "agentgate", 403},
		"AgentGate cert, operator token":            {"GET", "/v2/reconcile", operatorSvc, "agentgate", 403},
		"AgentGate on withdrawals":                  {"POST", "/v2/withdrawals", gateToken, "agentgate", 403},
		"gate role, guardian cert":                  {"POST", "/v2/gate/signatures", gateToken, "guardian", 403},
		"gate role, no cert":                        {"POST", "/v2/gate/signatures", gateToken, "", 403},
		"operator service, guardian cert":           {"POST", "/v2/gate/signatures", operatorSvc, "guardian", 403},
		"AgentGate cert, operator token, gate API":  {"POST", "/v2/gate/signatures", operatorSvc, "agentgate", 403},
		"AgentGate cert, a person's token":         {"GET", "/v2/reconcile", person, "agentgate", 403},
		"a person":                                  {"POST", "/v2/gate/signatures", person, "", 403},
	} {
		w := g.call(c.method, c.path, c.spec, c.cert, []byte(`{}`))
		if w.Code != c.want || code(t, w) != "client_not_authorized" {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}
	// The guardian keeps its routes; AgentGate with its certificate reaches the API (an empty body is its own refusal, not an auth one).
	if w := g.call("GET", "/v2/reconcile", authtest.Spec{Sub: "svc", Client: "qv-svc", Service: true, Roles: []string{"operator"}}, "guardian", nil); w.Code != 200 {
		t.Errorf("guardian on reconcile: %d %s", w.Code, w.Body)
	}
	if w := g.post([]byte(`{}`)); w.Code != 400 || code(t, w) != "request_invalid" {
		t.Errorf("AgentGate on its route: %d %s", w.Code, w.Body)
	}
	// No token at all: refused with a code too.
	r := httptest.NewRequest("POST", "/v2/gate/signatures", strings.NewReader(`{}`))
	r.TLS = g.certs["agentgate"]
	w := httptest.NewRecorder()
	g.h.ServeHTTP(w, r)
	if w.Code != 401 || code(t, w) != "client_not_authorized" {
		t.Errorf("no token: %d %s", w.Code, w.Body)
	}
}

// Each status of the spec's table, through the real API with the test minter.
func TestGateStatusCodes(t *testing.T) {
	g := gateWorld(t)
	id := func(n int) string { return "0b6c1d52-8a4f-4e17-b3d9-00000000" + strings.Repeat("0", 4-len(itoa(n))) + itoa(n) }
	good := func(n int, amount int64, mod func(c *gatecred.Credential)) []byte {
		return g.body(t, g.cred(id(n), amount, mod), g.typed(t, amount, byte(n)))
	}
	with := func(b []byte, mod func(m map[string]any)) []byte {
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		mod(m)
		out, _ := json.Marshal(m)
		return out
	}
	other := "aaaaaaaa-0000-4000-8000-000000000001"
	for name, c := range map[string]struct {
		body   []byte
		status int
		code   string
	}{
		"bad wallet id":      {with(good(1, 100, nil), func(m map[string]any) { m["wallet_id"] = "W" }), 400, "request_invalid"},
		"evm_transfer":       {with(good(2, 100, nil), func(m map[string]any) { m["kind"] = "evm_transfer" }), 400, "request_invalid"},
		"unknown field":      {with(good(3, 100, nil), func(m map[string]any) { m["extra"] = 1 }), 400, "request_invalid"},
		"no credential":      {with(good(4, 100, nil), func(m map[string]any) { delete(m, "credential") }), 400, "credential_missing"},
		"malformed":          {with(good(5, 100, nil), func(m map[string]any) { m["credential"].(map[string]any)["v"] = 2 }), 400, "credential_malformed"},
		"not gate-governed":  {with(good(6, 100, func(c *gatecred.Credential) { c.WalletID = other }), func(m map[string]any) { m["wallet_id"] = other }), 403, "wallet_not_gate_governed"},
		"other audience":     {good(7, 100, func(c *gatecred.Credential) { c.Audience = "qv-prod" }), 403, "audience_mismatch"},
		"other wallet":       {good(8, 100, func(c *gatecred.Credential) { c.WalletID = other }), 403, "wallet_mismatch"},
		"expired":            {good(9, 100, func(c *gatecred.Credential) { c.IssuedAt, c.ExpiresAt = 600, 900 }), 403, "expired"},
		"over the limit":     {good(10, 600_000, nil), 403, "fast_lane_cap"},
		"payload not 3009":   {with(good(11, 100, nil), func(m map[string]any) { m["payload"] = map[string]any{"primaryType": "Permit", "message": map[string]any{"nonce": "0x01"}} }), 422, "payload_invalid"},
		"another payer":      {g.body(t, g.cred(id(12), 100, nil), g.typedFrom(t, common.HexToAddress("0x00000000000000000000000000000000000000a2"), 100, 12)), 422, "payload_invalid"},
		"not answered (503)": {good(13, 100, nil), 503, "retry_later"},
	} {
		w := g.post(c.body)
		if w.Code != c.status || code(t, w) != c.code {
			t.Errorf("%s: %d %s, want %d %s", name, w.Code, w.Body, c.status, c.code)
		}
	}
	// Zone refusals: the job's reason maps to the table; an unknown one, or a failed signer, is 503 signing_failed.
	for n, c := range []struct {
		status, reason string
		http           int
		code, field    string
	}{
		{signjob.StatusRejected, "policy_payment_rule: kid_unknown (kid): no key \"x\"", 403, "kid_unknown", "kid"},
		{signjob.StatusRejected, "policy_payment_rule: payment_mismatch (amount): 5 != 6", 403, "payment_mismatch", "amount"},
		{signjob.StatusRejected, "fast_lane_cap: per hour", 403, "fast_lane_cap", ""},
		{signjob.StatusRejected, "credential_malformed: field obligation_id: 129 bytes", 400, "credential_malformed", "obligation_id"},
		{signjob.StatusRejected, "replayed: credential used", 409, "replayed", ""},
		{signjob.StatusRejected, "tx_mismatch: payer", 422, "payload_invalid", ""},
		{signjob.StatusRejected, "keyset_state: lagging", 503, "signing_failed", ""},
		{signjob.StatusFailed, "signer failed: party B", 503, "signing_failed", ""},
	} {
		b := good(20+n, 100, nil)
		if w := g.post(b); w.Code != 503 {
			t.Fatalf("zone case %d: first call %d %s", n, w.Code, w.Body)
		}
		g.zoneEnds(t, id(20+n), c.status, c.reason)
		w := g.post(b)
		var r GateRefusal
		_ = json.Unmarshal(w.Body.Bytes(), &r)
		if w.Code != c.http || r.Code != c.code || r.Field != c.field {
			t.Errorf("zone %q: %d %+v", c.reason, w.Code, r)
		}
		// Final: the same request again gets the stored answer, never a new job.
		if w2 := g.post(b); w2.Code != w.Code || w2.Body.String() != w.Body.String() {
			t.Errorf("zone %q: repeat %d %s", c.reason, w2.Code, w2.Body)
		}
	}
	// 409: the same credential_id with another payload.
	b := good(40, 100, nil)
	_ = g.post(b)
	g.zoneSigns(t, id(40))
	g.checkSigned(t, g.post(b), id(40))
	if w := g.post(g.body(t, g.cred(id(40), 100, nil), g.typed(t, 100, 41))); w.Code != 409 || code(t, w) != "replayed" {
		t.Errorf("other payload: %d %s", w.Code, w.Body)
	}
}

func (g *gateEnv) typedFrom(t *testing.T, from common.Address, amount int64, nonce byte) json.RawMessage {
	t.Helper()
	var n [32]byte
	n[31] = nonce
	b, _, err := g.s.Cfg.EVM.NewPayload3009(x402Asset, from, common.HexToAddress(gatePayee), big.NewInt(amount), 990, 1300, n)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func itoa(n int) string { return big.NewInt(int64(n)).String() }

// The same request twice (one after the other, and many at once) makes one job and gets the same signature; the answer of a signature that was made
// while nobody waited (a lost answer) is returned to the retry. The job carries the credential exactly as Gate sent it, and the hold is booked once.
func TestGateIdempotency(t *testing.T) {
	g := gateWorld(t)
	const id = "0b6c1d52-8a4f-4e17-b3d9-5f2a7c9e1a08"
	c := g.cred(id, 100, nil)
	b := g.body(t, c, g.typed(t, 100, 1))
	// Lost answer: the first call gives up waiting; the zone signs; the retry returns the signature.
	if w := g.post(b); w.Code != 503 || code(t, w) != "retry_later" {
		t.Fatalf("first: %d %s", w.Code, w.Body)
	}
	job, err := signjob.Get(context.Background(), g.s.Pool, "x402:"+id)
	if err != nil {
		t.Fatal(err)
	}
	var in map[string]any
	if err := json.Unmarshal(job.Intent, &in); err != nil {
		t.Fatal(err)
	}
	if in["Credential"] != string(gatecredtest.Mint(gatecredtest.TestKey(1), c)) || in["Kind"] != "eip3009" {
		t.Fatalf("intent %s", job.Intent)
	}
	g.zoneSigns(t, id)
	sig := g.checkSigned(t, g.post(b), id)
	// A re-spaced copy of the same request is the same request.
	var m map[string]json.RawMessage
	_ = json.Unmarshal(b, &m)
	var spaced bytes.Buffer
	_ = json.Indent(&spaced, b, "", "  ")
	if s2 := g.checkSigned(t, g.post(spaced.Bytes()), id); s2 != sig {
		t.Fatalf("re-spaced: %s != %s", s2, sig)
	}
	if n := g.jobs(t); n != 1 {
		t.Fatalf("%d jobs", n)
	}
	// Many at once, on a new credential: one job, one signature for all. The zone signs while they wait.
	const id2 = "0b6c1d52-8a4f-4e17-b3d9-5f2a7c9e1a09"
	g.s.Cfg.Gate.Wait = 5 * time.Second
	b2 := g.body(t, g.cred(id2, 100, nil), g.typed(t, 100, 2))
	var wg sync.WaitGroup
	res := make([]*httptest.ResponseRecorder, 8)
	for i := range res {
		wg.Add(1)
		go func(i int) { defer wg.Done(); res[i] = g.post(b2) }(i)
	}
	deadline := time.Now().Add(4 * time.Second)
	for {
		if _, err := signjob.Get(context.Background(), g.s.Pool, "x402:"+id2); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no job")
		}
		time.Sleep(20 * time.Millisecond)
	}
	g.zoneSigns(t, id2)
	wg.Wait()
	first := ""
	for _, w := range res {
		s := g.checkSigned(t, w, id2)
		if first == "" {
			first = s
		} else if s != first {
			t.Fatalf("two signatures: %s %s", s, first)
		}
	}
	if n := g.jobs(t); n != 2 {
		t.Fatalf("%d jobs after the concurrent requests", n)
	}
	var holds int
	if err := g.s.Pool.QueryRow(context.Background(), `SELECT count(*) FROM ledger_holds WHERE id IN ($1, $2)`, "x402-hold:"+id, "x402-hold:"+id2).Scan(&holds); err != nil || holds != 2 {
		t.Fatalf("holds %d %v", holds, err)
	}
	// One audit event per credential, however often it was asked.
	var audits int
	if err := g.s.Pool.QueryRow(context.Background(), `SELECT count(*) FROM outbox WHERE topic='qv.audit' AND payload->>'type'='gate.request'`).Scan(&audits); err != nil || audits != 2 {
		t.Fatalf("audit events %d %v", audits, err)
	}
}

// Rows are pruned after expires_at + skew + 1 day, not before.
func TestGatePrune(t *testing.T) {
	g := gateWorld(t)
	const id = "0b6c1d52-8a4f-4e17-b3d9-5f2a7c9e1a10"
	_ = g.post(g.body(t, g.cred(id, 100, nil), g.typed(t, 100, 3)))
	ctx := context.Background()
	for _, c := range []struct {
		now  int64
		gone bool
	}{{1300 + 30 + 86400 - 1, false}, {1300 + 30 + 86400 + 1, true}} {
		g.s.Now = func() time.Time { return time.Unix(c.now, 0) }
		if _, err := g.s.PruneGateRequests(ctx); err != nil {
			t.Fatal(err)
		}
		var n int
		_ = g.s.Pool.QueryRow(ctx, `SELECT count(*) FROM gate_requests`).Scan(&n)
		if (n == 0) != c.gone {
			t.Fatalf("at %d: %d rows", c.now, n)
		}
	}
	// A request that comes back after its row was pruned is refused as expired (the core's own clock), not brought back to life.
	if w := g.post(g.body(t, g.cred(id, 100, nil), g.typed(t, 100, 3))); w.Code != 403 || code(t, w) != "expired" {
		t.Fatalf("after pruning: %d %s", w.Code, w.Body)
	}
}

func TestGateZoneRefusalMapping(t *testing.T) {
	for reason, want := range map[string]GateRefusal{
		"payment_mismatch: field amount: 5 != 6": {Code: "payment_mismatch", Field: "amount"},
		"wallet_not_gate_governed: wallet x":       {Code: "wallet_not_gate_governed"},
		"expired: at 5":                                    {Code: "expired"},
		"policy_payment_rule: not_yet_valid (issued_at): x": {Code: "not_yet_valid", Field: "issued_at"},
		"policy_payment_rule: this zone has no payment credential rule: payment authorizations are not signed": {Code: GateSigningFailed},
		"replay_nonce_taken: another intent":           {Code: "replayed"},
		"policy_payment_window: the authorization ended": {Code: "authorization_window"},
		"":                                               {Code: GateSigningFailed},
		"something new":                                  {Code: GateSigningFailed},
	} {
		got := gateZoneRefusal(reason)
		if got.Code != want.Code || got.Field != want.Field {
			t.Errorf("%q: %+v, want %+v", reason, got, want)
		}
		if GateStatus(got.Code) == 200 {
			t.Errorf("%q: a success", reason)
		}
	}
}

func TestGateConfig(t *testing.T) {
	base := func() File {
		return File{
			Chain: ChainFile{Name: testChain, ChainID: 1, Factory: "0x00000000000000000000000000000000000000f1",
				SweepDestination: "0x00000000000000000000000000000000000000a1",
				HotShards:        []string{"0x00000000000000000000000000000000000000a1", "0x00000000000000000000000000000000000000a2"},
				MaxTxFeeWei:      "1000000000000000000",
				Assets: map[string]AssetFile{
					"ETH":  {Decimals: 18, PriceWei: "1"},
					"USDT": {Address: "0x00000000000000000000000000000000000000c1", Decimals: 6, MinDeposit: "1000", PriceWei: "1000"},
				},
				X402: map[string]X402File{"USDT": {Name: "USDC", Version: "2", MaxWindowSeconds: 600, PerPaymentLimit: "500000"}}},
			Withdrawal: WithdrawalFile{Tiers: map[string][]TierFile{"ETH": {{MinAmount: "0", Approvals: 1, Auto: true}}}},
		}
	}
	part := "qv-us/" + testChain + "/USDT/hot/omnibus/1"
	f := base()
	f.Gate = &GateFile{Audience: "qv-staging", Wallets: map[string]GateWalletFile{gateWallet: {Partition: part}}}
	c, err := f.Build()
	if err != nil {
		t.Fatal(err)
	}
	if w := c.Gate.Wallets[gateWallet]; w.Partition != part || w.Asset != "USDT" || c.Gate.Skew != 30*time.Second || c.Gate.Wait != 20*time.Second {
		t.Fatalf("%+v %+v", c.Gate, w)
	}
	for name, g := range map[string]*GateFile{
		"bad audience":   {Audience: "QV", Wallets: map[string]GateWalletFile{gateWallet: {Partition: part}}},
		"no wallets":     {Audience: "qv"},
		"upper-case id":  {Audience: "qv", Wallets: map[string]GateWalletFile{strings.ToUpper(gateWallet): {Partition: part}}},
		"cold partition": {Audience: "qv", Wallets: map[string]GateWalletFile{gateWallet: {Partition: strings.Replace(part, "/hot/", "/cold/", 1)}}},
		"no such shard":  {Audience: "qv", Wallets: map[string]GateWalletFile{gateWallet: {Partition: strings.TrimSuffix(part, "1") + "7"}}},
		"no x402 asset":  {Audience: "qv", Wallets: map[string]GateWalletFile{gateWallet: {Partition: strings.Replace(part, "USDT", "ETH", 1)}}},
		"skew too big":   {Audience: "qv", Skew: "6m", Wallets: map[string]GateWalletFile{gateWallet: {Partition: part}}},
		"shared shard": {Audience: "qv", Wallets: map[string]GateWalletFile{gateWallet: {Partition: part},
			"aaaaaaaa-0000-4000-8000-000000000001": {Partition: part}}},
	} {
		f := base()
		f.Gate = g
		if _, err := f.Build(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Fix 1: the EIP-3009 nonce is Gate's. An all-zero nonce is signed as given (never replaced by a random one); a payload without a nonce is refused.
func TestGateNonceIsTheCallers(t *testing.T) {
	g := gateWorld(t)
	const id = "0b6c1d52-8a4f-4e17-b3d9-5f2a7c9e1a20"
	payload := g.typed(t, 100, 0) // nonce 0x00…00
	if w := g.post(g.body(t, g.cred(id, 100, nil), payload)); w.Code != 503 || code(t, w) != "retry_later" {
		t.Fatalf("first: %d %s", w.Code, w.Body)
	}
	job, err := signjob.Get(context.Background(), g.s.Pool, "x402:"+id)
	if err != nil {
		t.Fatal(err)
	}
	var p evm.Payload3009
	if err := json.Unmarshal(job.Payload, &p); err != nil {
		t.Fatal(err)
	}
	if p.Message.Nonce != "0x"+strings.Repeat("00", 32) {
		t.Fatalf("the job signs nonce %s", p.Message.Nonce)
	}
	want := evm.Digest712("USDC", "2", 1, g.s.Cfg.Assets[x402Asset].Address, g.payer, common.HexToAddress(gatePayee), big.NewInt(100), 990, 1300, [32]byte{})
	if !bytes.Equal(job.Digest, want[:]) {
		t.Fatalf("digest %x, want the digest of the caller's typed data %x", job.Digest, want)
	}
	g.zoneSigns(t, id)
	g.checkSigned(t, g.post(g.body(t, g.cred(id, 100, nil), payload)), id)
	// Without a nonce: refused before anything is recorded.
	var m map[string]any
	_ = json.Unmarshal(g.typed(t, 100, 5), &m)
	delete(m["message"].(map[string]any), "nonce")
	nn, _ := json.Marshal(m)
	if w := g.post(g.body(t, g.cred("0b6c1d52-8a4f-4e17-b3d9-5f2a7c9e1a21", 100, nil), nn)); w.Code != 400 || code(t, w) != "request_invalid" {
		t.Fatalf("no nonce: %d %s", w.Code, w.Body)
	}
}

// Fix 2: the payload's member order and spacing do not make another request.
func TestGatePayloadMemberOrderIsTheSameRequest(t *testing.T) {
	g := gateWorld(t)
	const id = "0b6c1d52-8a4f-4e17-b3d9-5f2a7c9e1a22"
	payload := g.typed(t, 100, 6)
	_ = g.post(g.body(t, g.cred(id, 100, nil), payload))
	g.zoneSigns(t, id)
	sig := g.checkSigned(t, g.post(g.body(t, g.cred(id, 100, nil), payload)), id)
	var m map[string]any // re-encoded: members sorted by name, unlike the struct order of the original
	_ = json.Unmarshal(payload, &m)
	reordered, _ := json.MarshalIndent(m, "", "   ")
	if bytes.Equal(reordered, payload) {
		t.Fatal("the reordered payload is the same bytes")
	}
	if s2 := g.checkSigned(t, g.post(g.body(t, g.cred(id, 100, nil), reordered)), id); s2 != sig {
		t.Fatalf("reordered: %s != %s", s2, sig)
	}
	if n := g.jobs(t); n != 1 {
		t.Fatalf("%d jobs", n)
	}
}

// Fix 3: a request already answered gets its answer whatever the state says now (another hot key, the wallet gone from the config, the clock past the
// credential's expiry); only a new request is checked against the current state.
func TestGateStoredAnswerOutlivesStateChanges(t *testing.T) {
	g := gateWorld(t)
	const id = "0b6c1d52-8a4f-4e17-b3d9-5f2a7c9e1a23"
	b := g.body(t, g.cred(id, 100, nil), g.typed(t, 100, 7))
	_ = g.post(b)
	g.zoneSigns(t, id)
	sig := g.checkSigned(t, g.post(b), id)
	// A placed but unanswered request waits on its job whatever the state too.
	const id2 = "0b6c1d52-8a4f-4e17-b3d9-5f2a7c9e1a24"
	b2 := g.body(t, g.cred(id2, 100, nil), g.typed(t, 100, 8))
	_ = g.post(b2)
	// The hot key is replaced, and then the wallet leaves the config, and the clock passes the expiry.
	part := g.s.Cfg.PartitionKey(x402Asset, 0).String()
	g.s.Cfg.EVM.HotAddresses[part] = common.HexToAddress("0x00000000000000000000000000000000000000a9")
	if s2 := g.checkSigned(t, g.post(b), id); s2 != sig {
		t.Fatalf("after the key change: %s != %s", s2, sig)
	}
	g.s.Cfg.Gate.Wallets = map[string]GateWallet{}
	g.s.Now = func() time.Time { return time.Unix(5000, 0) }
	if s2 := g.checkSigned(t, g.post(b), id); s2 != sig {
		t.Fatalf("after the wallet left the config: %s != %s", s2, sig)
	}
	g.zoneSigns(t, id2)
	g.checkSigned(t, g.post(b2), id2)
	// A new request is judged now: the wallet is no longer Gate-governed here.
	if w := g.post(g.body(t, g.cred("0b6c1d52-8a4f-4e17-b3d9-5f2a7c9e1a25", 100, nil), g.typed(t, 100, 9))); w.Code != 403 || code(t, w) != "wallet_not_gate_governed" {
		t.Fatalf("new request: %d %s", w.Code, w.Body)
	}
}

// Fix 4: when the wallet's address cannot be read, the answer is retry_later and nothing is stored: the same request succeeds once it can.
func TestGateAddressLookupFailureIsRetryLater(t *testing.T) {
	g := gateWorld(t)
	const id = "0b6c1d52-8a4f-4e17-b3d9-5f2a7c9e1a26"
	b := g.body(t, g.cred(id, 100, nil), g.typed(t, 100, 10))
	w0 := g.s.Cfg.Gate.Wallets[gateWallet]
	broken := w0
	broken.Partition = "qv-us/" + testChain + "/" + x402Asset + "/hot/omnibus/9" // a shard the config does not have: the lookup fails
	g.s.Cfg.Gate.Wallets[gateWallet] = broken
	if w := g.post(b); w.Code != 503 || code(t, w) != "retry_later" {
		t.Fatalf("failing lookup: %d %s", w.Code, w.Body)
	}
	var n int
	_ = g.s.Pool.QueryRow(context.Background(), `SELECT count(*) FROM gate_requests`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d rows stored", n)
	}
	g.s.Cfg.Gate.Wallets[gateWallet] = w0
	_ = g.post(b)
	g.zoneSigns(t, id)
	g.checkSigned(t, g.post(b), id)
}

// Fix 6: when the audit trail cannot be written, the signing API answers in its own error shape.
func TestGateAuditFailureAnswersWithACode(t *testing.T) {
	g := gateWorld(t)
	g.s.Pool.Close()
	w := g.post(g.body(t, g.cred("0b6c1d52-8a4f-4e17-b3d9-5f2a7c9e1a27", 100, nil), g.typed(t, 100, 11)))
	if w.Code != 503 || code(t, w) != "retry_later" {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

// GCF2 fix 3: a refusal decided against the current state (the wallet is not Gate-governed, another audience) is stored: the same request gets the
// same answer after the state changes, and never a job.
func TestGateStateRefusalIsStored(t *testing.T) {
	g := gateWorld(t)
	w0 := g.s.Cfg.Gate.Wallets
	const id = "0b6c1d52-8a4f-4e17-b3d9-5f2a7c9e1a30"
	b := g.body(t, g.cred(id, 100, nil), g.typed(t, 100, 30))
	g.s.Cfg.Gate.Wallets = map[string]GateWallet{}
	first := g.post(b)
	if first.Code != 403 || code(t, first) != "wallet_not_gate_governed" {
		t.Fatalf("first: %d %s", first.Code, first.Body)
	}
	g.s.Cfg.Gate.Wallets = w0
	if w := g.post(b); w.Code != first.Code || w.Body.String() != first.Body.String() {
		t.Fatalf("after the wallet was added: %d %s, want the stored %d %s", w.Code, w.Body, first.Code, first.Body)
	}
	const id2 = "0b6c1d52-8a4f-4e17-b3d9-5f2a7c9e1a31"
	b2 := g.body(t, g.cred(id2, 100, nil), g.typed(t, 100, 31))
	g.s.Cfg.Gate.Audience = "qv-other"
	first = g.post(b2)
	if first.Code != 403 || code(t, first) != "audience_mismatch" {
		t.Fatalf("audience: %d %s", first.Code, first.Body)
	}
	g.s.Cfg.Gate.Audience = gateAudience
	if w := g.post(b2); w.Code != first.Code || w.Body.String() != first.Body.String() {
		t.Fatalf("after the audience was fixed: %d %s", w.Code, w.Body)
	}
	if n := g.jobs(t); n != 0 {
		t.Fatalf("%d jobs", n)
	}
	var audits int
	if err := g.s.Pool.QueryRow(context.Background(), `SELECT count(*) FROM outbox WHERE topic='qv.audit' AND payload->>'type'='gate.request'`).Scan(&audits); err != nil || audits != 2 {
		t.Fatalf("audit events %d %v", audits, err)
	}
}

// GCF2 fix 4: the gate section removed (a restart without it) while a request is placed: its retry answers 503 retry_later, never a panic; a stored
// answer is still returned; with the section back the same request gets its signature.
func TestGatePlacedRetryWithoutGateConfig(t *testing.T) {
	g := gateWorld(t)
	const id = "0b6c1d52-8a4f-4e17-b3d9-5f2a7c9e1a32"
	b := g.body(t, g.cred(id, 100, nil), g.typed(t, 100, 32))
	if w := g.post(b); w.Code != 503 || code(t, w) != "retry_later" {
		t.Fatalf("first: %d %s", w.Code, w.Body)
	}
	gc := g.s.Cfg.Gate
	g.s.Cfg.Gate = nil
	if w := g.post(b); w.Code != 503 || code(t, w) != "retry_later" {
		t.Fatalf("without the gate section: %d %s", w.Code, w.Body)
	}
	g.s.Cfg.Gate = gc
	g.zoneSigns(t, id)
	sig := g.checkSigned(t, g.post(b), id)
	g.s.Cfg.Gate = nil
	if s2 := g.checkSigned(t, g.post(b), id); s2 != sig {
		t.Fatalf("stored answer without the gate section: %s != %s", s2, sig)
	}
}

// GCF2 fix 5: an EIP-3009 nonce already used by another credential is refused as nonce_reused (409) and stored: no job, and a repeat gets the same.
func TestGateReusedNonceIsAStoredRefusal(t *testing.T) {
	g := gateWorld(t)
	payload := g.typed(t, 100, 33)
	if w := g.post(g.body(t, g.cred("0b6c1d52-8a4f-4e17-b3d9-5f2a7c9e1a33", 100, nil), payload)); w.Code != 503 || code(t, w) != "retry_later" {
		t.Fatalf("first: %d %s", w.Code, w.Body)
	}
	b := g.body(t, g.cred("0b6c1d52-8a4f-4e17-b3d9-5f2a7c9e1a34", 100, nil), payload)
	first := g.post(b)
	if first.Code != 409 || code(t, first) != "nonce_reused" {
		t.Fatalf("reused nonce: %d %s", first.Code, first.Body)
	}
	if w := g.post(b); w.Code != first.Code || w.Body.String() != first.Body.String() {
		t.Fatalf("repeat: %d %s", w.Code, w.Body)
	}
	if n := g.jobs(t); n != 1 {
		t.Fatalf("%d jobs", n)
	}
}
