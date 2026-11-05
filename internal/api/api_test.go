package api_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"

	"github.com/ws4charlie/quorum-vault/internal/api"
	"github.com/ws4charlie/quorum-vault/internal/approval"
	"github.com/ws4charlie/quorum-vault/internal/audit"
	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
	"github.com/ws4charlie/quorum-vault/internal/domain"
	"github.com/ws4charlie/quorum-vault/internal/keys"
	"github.com/ws4charlie/quorum-vault/internal/policy"
	"github.com/ws4charlie/quorum-vault/internal/signer"
	"github.com/ws4charlie/quorum-vault/internal/signing"
)

// softBackend stands in for the HSM so the API tests need only Postgres:
// software secp256k1 keys registered under backend "hsm".
type softBackend struct {
	mu   sync.Mutex
	priv map[string]*ecdsa.PrivateKey // by key id
}

func (b *softBackend) Backend() domain.Backend { return domain.BackendHSM }

func (b *softBackend) Generate(_ context.Context, walletID string, version int) (domain.Key, error) {
	k, err := crypto.GenerateKey()
	if err != nil {
		return domain.Key{}, err
	}
	id := uuid.NewString()
	b.mu.Lock()
	b.priv[id] = k
	b.mu.Unlock()
	return domain.Key{ID: id, Curve: domain.CurveSecp256k1, HSMLabel: fmt.Sprintf("soft-%s-v%d", walletID, version),
		HSMKeyID: []byte(id[:8]), PublicKey: crypto.FromECDSAPub(&k.PublicKey),
		Address: crypto.PubkeyToAddress(k.PublicKey).Hex()}, nil
}

type softSigner struct {
	key  domain.Key
	priv *ecdsa.PrivateKey
}

func (s softSigner) Backend() domain.Backend     { return domain.BackendHSM }
func (s softSigner) Key() domain.Key             { return s.key }
func (s softSigner) PublicKey() *ecdsa.PublicKey { return &s.priv.PublicKey }
func (s softSigner) SignDigest(_ context.Context, d [32]byte, _ signer.SignOptions) (signer.Result, error) {
	sig, err := crypto.Sign(d[:], s.priv)
	if err != nil {
		return signer.Result{}, err
	}
	return signer.Result{Sig: signer.Signature{R: new(big.Int).SetBytes(sig[:32]), S: new(big.Int).SetBytes(sig[32:64])},
		Participants: []string{"soft"}}, nil
}

type client struct {
	t   *testing.T
	srv *httptest.Server
}

func newClient(t *testing.T) *client {
	pool := dbtest.New(t)
	aud := audit.New(pool)
	be := &softBackend{priv: map[string]*ecdsa.PrivateKey{}}
	reg := keys.New(pool, aud, be)
	pol := policy.New(pool, aud, nil)
	svc := signing.New(signing.Config{Pool: pool, Registry: reg, Policy: pol, Approvals: approval.New(pool, aud), Audit: aud,
		Signers: map[domain.Backend]signing.SignerFunc{domain.BackendHSM: func(k domain.Key) (signer.Signer, error) {
			be.mu.Lock()
			defer be.mu.Unlock()
			return softSigner{k, be.priv[k.ID]}, nil
		}}})
	srv := httptest.NewServer(api.New(api.Config{Registry: reg, Policy: pol, Signing: svc, Audit: aud}))
	t.Cleanup(srv.Close)
	return &client{t: t, srv: srv}
}

// do sends a request; actor "" omits X-Actor. body may be a string (raw) or a value (JSON).
func (c *client) do(method, path, actor string, body any) (int, map[string]any, []byte) {
	c.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	default:
		j, _ := json.Marshal(b)
		rd = bytes.NewReader(j)
	}
	req, _ := http.NewRequest(method, c.srv.URL+path, rd)
	if actor != "" {
		req.Header.Set("X-Actor", actor)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	json.Unmarshal(raw, &m)
	return resp.StatusCode, m, raw
}

func (c *client) must(want int, method, path, actor string, body any) map[string]any {
	c.t.Helper()
	code, m, raw := c.do(method, path, actor, body)
	if code != want {
		c.t.Fatalf("%s %s: status %d want %d: %s", method, path, code, want, raw)
	}
	return m
}

const dest = "0x000000000000000000000000000000000000dEaD"

func (c *client) setupWallet(name string) string {
	m := c.must(201, "POST", "/wallets", "admin", map[string]string{"name": name, "tier": "hot", "backend": "hsm"})
	id := m["wallet"].(map[string]any)["id"].(string)
	c.must(200, "PUT", "/wallets/"+id+"/policy", "admin", map[string]any{
		"daily_limit_wei": "100000000000000000000", "per_tx_limit_wei": "10000000000000000000",
		"approval_threshold_wei": "100000000000000000", "velocity_max_tx": 100, "velocity_window_seconds": 3600})
	c.must(201, "POST", "/wallets/"+id+"/allowlist", "admin", map[string]string{"address": dest, "label": "dead"})
	return id
}

func request(m map[string]any) map[string]any { return m["request"].(map[string]any) }

func TestFlow(t *testing.T) {
	c := newClient(t)
	c.must(200, "GET", "/healthz", "", nil)
	wid := c.setupWallet("hot-1")

	wv := c.must(200, "GET", "/wallets/"+wid, "", nil)
	if len(wv["keys"].([]any)) != 1 || wv["policy"] == nil || len(wv["allowlist"].([]any)) != 1 {
		t.Fatalf("wallet view %v", wv)
	}

	// Small: allowed and signed.
	m := c.must(201, "POST", "/sign-requests", "alice", map[string]any{"wallet_id": wid, "to": dest, "value_wei": "1000", "nonce": 0})
	r := request(m)
	if r["status"] != "signed" || !strings.HasPrefix(r["raw_tx"].(string), "0x02") || r["value_wei"] != "1000" {
		t.Fatalf("small request %v", m)
	}
	if m["from"] != wv["keys"].([]any)[0].(map[string]any)["address"] {
		t.Fatalf("from %v", m["from"])
	}

	// Large: pending; self-approval 403; bob approves -> signed; then 409.
	m = c.must(201, "POST", "/sign-requests", "alice", map[string]any{"wallet_id": wid, "to": dest, "value_wei": "1000000000000000000", "nonce": 1})
	id := request(m)["id"].(string)
	if request(m)["status"] != "pending_approval" {
		t.Fatalf("large request %v", m)
	}
	c.must(403, "POST", "/sign-requests/"+id+"/approve", "alice", nil)
	m = c.must(200, "POST", "/sign-requests/"+id+"/approve", "bob", map[string]string{"comment": "ok"})
	if request(m)["status"] != "signed" || m["tally"] == nil {
		t.Fatalf("approve %v", m)
	}
	c.must(409, "POST", "/sign-requests/"+id+"/reject", "carol", nil)
	if g := c.must(200, "GET", "/sign-requests/"+id, "", nil); g["status"] != "signed" {
		t.Fatalf("get %v", g)
	}

	// Reject path.
	m = c.must(201, "POST", "/sign-requests", "alice", map[string]any{"wallet_id": wid, "to": dest, "value_wei": "2000000000000000000", "nonce": 2})
	rid := request(m)["id"].(string)
	if m = c.must(200, "POST", "/sign-requests/"+rid+"/reject", "bob", map[string]string{"comment": "no"}); request(m)["status"] != "rejected" {
		t.Fatalf("reject %v", m)
	}

	// Denied: not allowlisted.
	m = c.must(201, "POST", "/sign-requests", "alice", map[string]any{"wallet_id": wid, "to": "0x1111111111111111111111111111111111111111", "value_wei": "1", "nonce": 3})
	if request(m)["status"] != "denied" {
		t.Fatalf("denied %v", m)
	}

	_, _, raw := c.do("GET", "/sign-requests?wallet_id="+wid, "", nil)
	var list []map[string]any
	json.Unmarshal(raw, &list)
	if len(list) != 4 {
		t.Fatalf("list: %d requests", len(list))
	}

	_, _, raw = c.do("GET", "/audit?request_id="+id, "", nil)
	var evs []map[string]any
	json.Unmarshal(raw, &evs)
	var types []string
	for _, e := range evs {
		types = append(types, e["type"].(string))
	}
	want := "request.created policy.decision approval.voted request.approved sign.started sign.completed"
	if strings.Join(types, " ") != want {
		t.Fatalf("audit for request: %v", types)
	}
	if v := c.must(200, "GET", "/audit/verify", "", nil); v["ok"] != true {
		t.Fatalf("verify %v", v)
	}
	c.must(200, "GET", "/audit?wallet_id="+wid+"&limit=3", "", nil)

	// Allowlist removal.
	c.must(204, "DELETE", "/wallets/"+wid+"/allowlist/"+dest, "admin", nil)
	c.must(404, "DELETE", "/wallets/"+wid+"/allowlist/"+dest, "admin", nil)
}

func TestKeysEndpoints(t *testing.T) {
	c := newClient(t)
	m := c.must(201, "POST", "/keys", "admin", map[string]string{})
	wid := m["wallet"].(map[string]any)["id"].(string)
	v1 := m["key"].(map[string]any)
	if v1["state"] != "active" || v1["curve"] != "secp256k1" {
		t.Fatalf("key %v", v1)
	}
	m = c.must(201, "POST", "/keys", "admin", map[string]string{"wallet_id": wid})
	if m["key"].(map[string]any)["version"] != 2.0 || m["previous_key"].(map[string]any)["state"] != "sign_only" {
		t.Fatalf("rotate via /keys %v", m)
	}
	m = c.must(201, "POST", "/wallets/"+wid+"/rotate", "admin", nil)
	if m["key"].(map[string]any)["version"] != 3.0 {
		t.Fatalf("rotate %v", m)
	}
	c.must(409, "POST", "/keys/"+m["key"].(map[string]any)["id"].(string)+"/retire", "admin", nil) // active key
	if k := c.must(200, "POST", "/keys/"+v1["id"].(string)+"/retire", "admin", nil); k["state"] != "retired" {
		t.Fatalf("retire %v", k)
	}
	_, _, raw := c.do("GET", "/keys?wallet_id="+wid, "", nil)
	var ks []map[string]any
	json.Unmarshal(raw, &ks)
	if len(ks) != 3 {
		t.Fatalf("keys: %s", raw)
	}
	for _, k := range ks {
		for f := range k {
			if strings.Contains(f, "priv") || f == "d" {
				t.Fatalf("key view leaks field %q", f)
			}
		}
	}
}

func TestErrors(t *testing.T) {
	c := newClient(t)
	wid := c.setupWallet("hot-1")
	zero := "00000000-0000-0000-0000-000000000000"

	// 401 on every mutating route without X-Actor.
	for _, rt := range []struct{ method, path string }{
		{"POST", "/wallets"}, {"POST", "/keys"}, {"POST", "/wallets/" + wid + "/rotate"}, {"POST", "/keys/" + zero + "/retire"},
		{"PUT", "/wallets/" + wid + "/policy"}, {"POST", "/wallets/" + wid + "/allowlist"},
		{"DELETE", "/wallets/" + wid + "/allowlist/" + dest}, {"POST", "/sign-requests"},
		{"POST", "/sign-requests/" + zero + "/approve"}, {"POST", "/sign-requests/" + zero + "/reject"},
	} {
		if code, m, _ := c.do(rt.method, rt.path, "", map[string]string{}); code != 401 || m["error"] == nil {
			t.Errorf("%s %s without actor: %d %v", rt.method, rt.path, code, m)
		}
	}

	cases := []struct {
		code         int
		method, path string
		body         any
	}{
		{404, "GET", "/wallets/" + zero, nil},
		{404, "GET", "/wallets/not-a-uuid", nil},
		{404, "GET", "/sign-requests/" + zero, nil},
		{404, "POST", "/sign-requests/" + zero + "/approve", nil},
		{404, "POST", "/wallets/" + zero + "/rotate", nil},
		{404, "POST", "/keys/" + zero + "/retire", nil},
		{404, "PUT", "/wallets/" + zero + "/policy", map[string]any{}},
		{404, "GET", "/nope", nil},
		{405, "DELETE", "/wallets", nil},
		{400, "POST", "/wallets", "{not json"},
		{400, "POST", "/wallets", map[string]string{"name": "x", "tier": "hot", "backend": "hsm", "extra": "y"}},
		{400, "GET", "/audit?request_id=xyz", nil},
		{422, "POST", "/wallets", map[string]string{"name": "x", "tier": "lukewarm", "backend": "hsm"}},
		{422, "POST", "/wallets", map[string]string{"name": "x", "tier": "hot", "backend": "paper"}},
		{422, "POST", "/wallets", map[string]string{"name": "x", "tier": "hot", "backend": "mpc"}}, // removed: the demo is HSM-only, MPC keys are under /v2
		{422, "POST", "/wallets", map[string]string{"name": "", "tier": "hot", "backend": "hsm"}},
		{409, "POST", "/wallets", map[string]string{"name": "hot-1", "tier": "hot", "backend": "hsm"}},
		{422, "POST", "/wallets/" + wid + "/allowlist", map[string]string{"address": "0x123"}},
		{422, "PUT", "/wallets/" + wid + "/policy", map[string]any{"velocity_max_tx": 1}},
		{404, "POST", "/sign-requests", map[string]any{"wallet_id": zero, "to": dest, "value_wei": "1", "nonce": 0}},
		{422, "POST", "/sign-requests", map[string]any{"wallet_id": wid, "to": dest, "value_wei": "1.5", "nonce": 0}},
		{422, "POST", "/sign-requests", map[string]any{"wallet_id": wid, "to": dest, "value_wei": "-1", "nonce": 0}},
		{422, "POST", "/sign-requests", map[string]any{"wallet_id": wid, "to": "0xabc", "value_wei": "1", "nonce": 0}},
		{422, "POST", "/sign-requests", map[string]any{"wallet_id": wid, "to": dest, "value_wei": "1"}}, // no nonce
		{422, "POST", "/sign-requests", map[string]any{"wallet_id": wid, "to": dest, "value_wei": "1", "nonce": 0, "data": "0xzz"}},
		{400, "POST", "/sign-requests", map[string]any{"wallet_id": wid, "to": dest, "value_wei": 1, "nonce": 0}}, // number, not string
	}
	for _, tc := range cases {
		code, m, raw := c.do(tc.method, tc.path, "admin", tc.body)
		if code != tc.code {
			t.Errorf("%s %s %v: status %d want %d: %s", tc.method, tc.path, tc.body, code, tc.code, raw)
		}
		if code != 405 && m["error"] == nil {
			t.Errorf("%s %s: no error field: %s", tc.method, tc.path, raw)
		}
	}
	if v := c.must(200, "GET", "/audit/verify", "", nil); v["ok"] != true {
		t.Fatalf("verify %v", v)
	}
}
