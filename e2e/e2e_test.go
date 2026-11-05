package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/ws4charlie/quorum-vault/internal/api"
	"github.com/ws4charlie/quorum-vault/internal/approval"
	"github.com/ws4charlie/quorum-vault/internal/audit"
	"github.com/ws4charlie/quorum-vault/internal/chain/eth"
	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
	"github.com/ws4charlie/quorum-vault/internal/domain"
	"github.com/ws4charlie/quorum-vault/internal/hsm"
	"github.com/ws4charlie/quorum-vault/internal/hsm/hsmtest"
	"github.com/ws4charlie/quorum-vault/internal/hsmsigner"
	"github.com/ws4charlie/quorum-vault/internal/keys"
	"github.com/ws4charlie/quorum-vault/internal/policy"
	"github.com/ws4charlie/quorum-vault/internal/signer"
	"github.com/ws4charlie/quorum-vault/internal/signing"
)

var (
	eth1      = new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	fundWei   = new(big.Int).Mul(eth1, big.NewInt(10))
	milliEth1 = new(big.Int).Div(eth1, big.NewInt(1000))
)

// requireChain returns SEPOLIA_RPC_URL after CheckLocalChain accepts it. No
// URL: skip, or fail when QV_REQUIRE_CHAIN=1. A URL that is not a local anvil
// node with chain ID 11155111 always fails: never broadcast to a real network.
func requireChain(t *testing.T) string {
	t.Helper()
	u := os.Getenv("SEPOLIA_RPC_URL")
	if u == "" {
		if os.Getenv("QV_REQUIRE_CHAIN") == "1" {
			t.Fatal("e2e (QV_REQUIRE_CHAIN=1): SEPOLIA_RPC_URL is not set (make chain-up; see .env.example)")
		}
		t.Skip("e2e: SEPOLIA_RPC_URL is not set (make chain-up && make test-demo-v1)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := CheckLocalChain(ctx, u); err != nil {
		t.Fatalf("e2e: refusing to run: %v", err)
	}
	return u
}

func repoDir(t *testing.T) string {
	dir, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

// env is the service wired exactly as cmd/quorumvault does (real HSM token,
// real MPC cluster, broadcast on), served over HTTP by httptest.
type env struct {
	t      *testing.T
	ctx    context.Context
	api    string
	rpcURL string
	node   *eth.Client
	ec     *ethclient.Client
}

func newEnv(t *testing.T) *env {
	t.Helper()
	rpcURL := requireChain(t)
	ctx := context.Background()
	pool := dbtest.New(t)
	tok := hsmtest.Token(t, "quorumvault")
	node, err := eth.Dial(ctx, rpcURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(node.Close)
	ec, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ec.Close)

	aud := audit.New(pool)
	reg := keys.New(pool, aud, hsmsigner.NewGenerator(tok))
	pol := policy.New(pool, aud, nil)
	svc := signing.New(signing.Config{
		Pool: pool, Registry: reg, Policy: pol, Approvals: approval.New(pool, aud), Audit: aud,
		Signers: map[domain.Backend]signing.SignerFunc{
			domain.BackendHSM: func(k domain.Key) (signer.Signer, error) { return hsmsigner.New(tok, k) },
		},
		RPC: node, Broadcast: true,
	})
	srv := httptest.NewServer(api.New(api.Config{Registry: reg, Policy: pol, Signing: svc, Audit: aud}))
	t.Cleanup(srv.Close)

	t.Cleanup(func() { // remove key material this test created
		ks, _ := reg.ListKeys(context.Background(), "")
		for _, k := range ks {
			switch k.Backend {
			case domain.BackendHSM:
				if err := tok.DestroyPrivateKey(context.Background(), k.HSMKeyID); err != nil && !errors.Is(err, hsm.ErrKeyNotFound) {
					t.Logf("cleanup: %v", err)
				}
			}
		}
	})
	return &env{t: t, ctx: ctx, api: srv.URL, rpcURL: rpcURL, node: node, ec: ec}
}

// call sends a JSON request to the API and decodes the JSON response into out.
func (e *env) call(want int, method, path, actor string, body, out any) {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.api+path, rd)
	req.Header.Set("Content-Type", "application/json")
	if actor != "" {
		req.Header.Set("X-Actor", actor)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		e.t.Fatalf("%s %s: HTTP %d want %d: %s", method, path, resp.StatusCode, want, raw)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			e.t.Fatalf("%s %s: decode %s: %v", method, path, raw, err)
		}
	}
}

type result struct {
	Request struct {
		ID     string `json:"id"`
		Status string `json:"status"`
		RawTx  string `json:"raw_tx"`
		TxHash string `json:"tx_hash"`
	} `json:"request"`
	From      string `json:"from"`
	SignError string `json:"sign_error"`
	Broadcast string `json:"broadcast"`
}

type auditEvent struct {
	Type    string         `json:"type"`
	Payload map[string]any `json:"payload"`
}

// wallet creates a wallet over the API with policy: approval over 0.01 ETH,
// per-tx 0.5 ETH, daily 1 ETH, default approvals (hot 1, cold 2); allows to.
func (e *env) wallet(name, tier, backend string, to common.Address) (id string, addr common.Address) {
	e.t.Helper()
	var w struct {
		Wallet struct{ ID string } `json:"wallet"`
		Key    struct{ Address string }
	}
	e.call(201, "POST", "/wallets", "admin", map[string]string{"name": name, "tier": tier, "backend": backend}, &w)
	e.call(200, "PUT", "/wallets/"+w.Wallet.ID+"/policy", "admin", map[string]any{
		"daily_limit_wei": "1000000000000000000", "per_tx_limit_wei": "500000000000000000",
		"approval_threshold_wei": "10000000000000000", "velocity_max_tx": 10, "velocity_window_seconds": 3600}, nil)
	e.call(201, "POST", "/wallets/"+w.Wallet.ID+"/allowlist", "admin", map[string]string{"address": to.Hex(), "label": "dest"}, nil)
	return w.Wallet.ID, common.HexToAddress(w.Key.Address)
}

func (e *env) fund(addr common.Address) {
	e.t.Helper()
	if err := SetBalance(e.ctx, e.rpcURL, addr, fundWei); err != nil {
		e.t.Fatal(err)
	}
}

// submit sends a transfer with nonce and fees left for the node to fill.
func (e *env) submit(walletID string, to common.Address, wei *big.Int) result {
	e.t.Helper()
	var r result
	e.call(201, "POST", "/sign-requests", "alice", map[string]string{"wallet_id": walletID, "to": to.Hex(), "value_wei": wei.String()}, &r)
	return r
}

func (e *env) approve(actor, id string) result {
	e.t.Helper()
	var r result
	e.call(200, "POST", "/sign-requests/"+id+"/approve", actor, map[string]string{"comment": "ok"}, &r)
	return r
}

func (e *env) audit(requestID string) []auditEvent {
	e.t.Helper()
	var evs []auditEvent
	e.call(200, "GET", "/audit?request_id="+requestID, "", nil, &evs)
	return evs
}

func (e *env) event(requestID, typ string) map[string]any {
	e.t.Helper()
	for _, ev := range e.audit(requestID) {
		if ev.Type == typ {
			return ev.Payload
		}
	}
	e.t.Fatalf("request %s has no %s event", requestID, typ)
	return nil
}

func (e *env) verifyAudit() {
	e.t.Helper()
	var v struct{ OK bool }
	e.call(200, "GET", "/audit/verify", "", nil, &v)
	if !v.OK {
		e.t.Fatal("audit chain does not verify")
	}
}

// mined checks that r was signed by from, broadcast, and mined with status 1,
// that the node itself reports from as the sender, and that a tx.broadcast ok
// event was audited. It returns the receipt and the decoded tx.
func (e *env) mined(r result, from common.Address) (*types.Receipt, *types.Transaction) {
	e.t.Helper()
	if r.Request.Status != string(domain.StatusSigned) {
		e.t.Fatalf("status %s, sign error %q", r.Request.Status, r.SignError)
	}
	if r.Broadcast != "ok" {
		e.t.Fatalf("broadcast: %q", r.Broadcast)
	}
	if common.HexToAddress(r.From) != from {
		e.t.Fatalf("server-recovered from %s, want %s", r.From, from)
	}
	tx, err := eth.DecodeRaw(common.FromHex(r.Request.RawTx))
	if err != nil {
		e.t.Fatal(err)
	}
	if tx.ChainId().Int64() != SepoliaChainID || tx.Type() != types.DynamicFeeTxType {
		e.t.Fatalf("tx chain %v type %d", tx.ChainId(), tx.Type())
	}
	ctx, cancel := context.WithTimeout(e.ctx, 30*time.Second)
	defer cancel()
	start := time.Now()
	rc, err := e.node.WaitReceipt(ctx, common.HexToHash(r.Request.TxHash), 50*time.Millisecond)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Logf("tx %s mined in block %d, gasUsed %d, receipt wait %s", rc.TxHash.Hex(), rc.BlockNumber, rc.GasUsed, time.Since(start).Round(time.Millisecond))
	if rc.Status != types.ReceiptStatusSuccessful {
		e.t.Fatalf("receipt status %d", rc.Status)
	}
	if rc.TxHash.Hex() != r.Request.TxHash {
		e.t.Fatalf("receipt hash %s, request tx_hash %s", rc.TxHash.Hex(), r.Request.TxHash)
	}
	var onChain struct {
		From common.Address `json:"from"`
	}
	if err := e.ec.Client().CallContext(ctx, &onChain, "eth_getTransactionByHash", rc.TxHash); err != nil {
		e.t.Fatal(err)
	}
	if onChain.From != from {
		e.t.Fatalf("node reports from %s, want %s", onChain.From.Hex(), from.Hex())
	}
	p := e.event(r.Request.ID, domain.EventTxBroadcast)
	if p["ok"] != true || p["tx_hash"] != r.Request.TxHash {
		e.t.Fatalf("tx.broadcast payload %v", p)
	}
	return rc, tx
}

func (e *env) balanceAt(addr common.Address, block *big.Int) *big.Int {
	e.t.Helper()
	b, err := e.ec.BalanceAt(e.ctx, addr, block)
	if err != nil {
		e.t.Fatal(err)
	}
	return b
}

func (e *env) nonceAt(addr common.Address) uint64 {
	e.t.Helper()
	n, err := e.ec.PendingNonceAt(e.ctx, addr)
	if err != nil {
		e.t.Fatal(err)
	}
	return n
}

// newAddress returns a random address with no history, so its balance is 0.
func newAddress(t *testing.T) common.Address {
	var a common.Address
	if _, err := rand.Read(a[:]); err != nil {
		t.Fatal(err)
	}
	return a
}

// TestLocalChain shares one service (DB, HSM token) across its subtests.
func TestLocalChain(t *testing.T) {
	e := newEnv(t)

	t.Run("HSMHotTransfersMine", func(t *testing.T) {
		e := *e
		e.t = t
		to := newAddress(t)
		wid, from := e.wallet("e2e-hsm-hot", "hot", "hsm", to)
		e.fund(from)

		value := new(big.Int).Mul(milliEth1, big.NewInt(3))
		r := e.submit(wid, to, value)
		rc, tx := e.mined(r, from)
		if tx.Nonce() != 0 {
			t.Fatalf("first nonce %d", tx.Nonce())
		}
		before := new(big.Int).Sub(rc.BlockNumber, big.NewInt(1))
		gotTo := new(big.Int).Sub(e.balanceAt(to, rc.BlockNumber), e.balanceAt(to, before))
		if gotTo.Cmp(value) != 0 {
			t.Fatalf("recipient gained %s, want %s", gotTo, value)
		}
		cost := new(big.Int).Add(value, new(big.Int).Mul(new(big.Int).SetUint64(rc.GasUsed), rc.EffectiveGasPrice))
		spent := new(big.Int).Sub(e.balanceAt(from, before), e.balanceAt(from, rc.BlockNumber))
		if spent.Cmp(cost) != 0 {
			t.Fatalf("sender spent %s, want value + gasUsed*effectiveGasPrice = %s", spent, cost)
		}
		if rc.GasUsed != eth.DefaultGasLimit {
			t.Fatalf("gasUsed %d", rc.GasUsed)
		}

		r2 := e.submit(wid, to, milliEth1)
		_, tx2 := e.mined(r2, from)
		if tx2.Nonce() != 1 {
			t.Fatalf("second nonce %d, want 1", tx2.Nonce())
		}
		if n := e.nonceAt(from); n != 2 {
			t.Fatalf("node nonce %d, want 2", n)
		}
		e.verifyAudit()
	})

	t.Run("HSMOverThresholdApprovedMines", func(t *testing.T) {
		e := *e
		e.t = t
		to := newAddress(t)
		wid, from := e.wallet("e2e-hsm-approve", "hot", "hsm", to)
		e.fund(from)
		value := new(big.Int).Mul(milliEth1, big.NewInt(50)) // over the 0.01 ETH threshold
		r := e.submit(wid, to, value)
		if r.Request.Status != string(domain.StatusPendingApproval) || r.Request.TxHash != "" {
			t.Fatalf("status %s tx %q, want pending_approval and no tx", r.Request.Status, r.Request.TxHash)
		}
		if n := e.nonceAt(from); n != 0 {
			t.Fatalf("pending request reached the node: nonce %d", n)
		}
		e.mined(e.approve("bob", r.Request.ID), from)
		if got := e.balanceAt(to, nil); got.Cmp(value) != 0 {
			t.Fatalf("recipient balance %s, want %s", got, value)
		}
		e.verifyAudit()
	})

	// Regression: a request pending approval got its nonce at Submit; a later
	// allowed request of the same wallet took the same nonce and mined first,
	// so the approved one was refused with "nonce too low". Now the nonce is
	// re-checked against the node at sign time.
	t.Run("ApprovedAfterLaterTransferGetsFreshNonce", func(t *testing.T) {
		e := *e
		e.t = t
		to := newAddress(t)
		wid, from := e.wallet("e2e-hsm-nonce", "hot", "hsm", to)
		e.fund(from)
		big1 := new(big.Int).Mul(milliEth1, big.NewInt(50))
		pending := e.submit(wid, to, big1) // nonce 0 from the node, waits for approval
		if pending.Request.Status != string(domain.StatusPendingApproval) {
			t.Fatalf("status %s", pending.Request.Status)
		}
		_, tx := e.mined(e.submit(wid, to, milliEth1), from) // also nonce 0, mines first
		if tx.Nonce() != 0 {
			t.Fatalf("allowed transfer nonce %d", tx.Nonce())
		}
		_, tx = e.mined(e.approve("bob", pending.Request.ID), from)
		if tx.Nonce() != 1 {
			t.Fatalf("approved transfer nonce %d, want 1", tx.Nonce())
		}
		var stored struct{ Nonce uint64 }
		e.call(200, "GET", "/sign-requests/"+pending.Request.ID, "", nil, &stored)
		if stored.Nonce != 1 {
			t.Fatalf("stored nonce %d, want the signed nonce 1", stored.Nonce)
		}
		p := e.event(pending.Request.ID, domain.EventSignStarted)
		if p["nonce"] != float64(1) || p["nonce_reassigned_from"] != float64(0) {
			t.Fatalf("sign.started payload %v", p)
		}
		e.verifyAudit()
	})

	t.Run("DeniedNeverBroadcasts", func(t *testing.T) {
		e := *e
		e.t = t
		allowed, stranger := newAddress(t), newAddress(t)
		wid, from := e.wallet("e2e-hsm-deny", "hot", "hsm", allowed)
		e.fund(from)
		before := e.nonceAt(from)
		r := e.submit(wid, stranger, milliEth1)
		if r.Request.Status != string(domain.StatusDenied) || r.Request.TxHash != "" || r.Broadcast != "" {
			t.Fatalf("status %s tx %q broadcast %q, want denied with nothing sent", r.Request.Status, r.Request.TxHash, r.Broadcast)
		}
		if n := e.nonceAt(from); n != before {
			t.Fatalf("wallet tx count %d -> %d", before, n)
		}
		if b := e.balanceAt(stranger, nil); b.Sign() != 0 {
			t.Fatalf("stranger balance %s", b)
		}
		for _, ev := range e.audit(r.Request.ID) {
			if ev.Type == domain.EventTxBroadcast || ev.Type == domain.EventSignStarted {
				t.Fatalf("denied request has a %s event", ev.Type)
			}
		}
		e.verifyAudit()
	})

	t.Run("ColdFullQuorumMines", func(t *testing.T) {
		e := *e
		e.t = t
		to := newAddress(t)
		wid, from := e.wallet("e2e-cold", "cold", "hsm", to)
		e.fund(from)
		r := e.submit(wid, to, big.NewInt(1))
		if r.Request.Status != string(domain.StatusPendingApproval) {
			t.Fatalf("status %s, want pending_approval", r.Request.Status)
		}
		if r = e.approve("bob", r.Request.ID); r.Request.Status != string(domain.StatusPendingApproval) {
			t.Fatalf("after 1 of 2 approvals: status %s", r.Request.Status)
		}
		e.mined(e.approve("carol", r.Request.ID), from)
		if got := e.balanceAt(to, nil); got.Cmp(big.NewInt(1)) != 0 {
			t.Fatalf("recipient balance %s, want 1 wei", got)
		}
		e.verifyAudit()
	})
}
