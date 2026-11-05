package signing

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ethereum/go-ethereum/common"

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
)

const (
	dest  = "0x000000000000000000000000000000000000dEaD"
	other = "0x1111111111111111111111111111111111111111"
)

var eth1 = new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)

func milliEth(n int64) *big.Int {
	return new(big.Int).Div(new(big.Int).Mul(eth1, big.NewInt(n)), big.NewInt(1000))
}

type env struct {
	t     *testing.T
	ctx   context.Context
	svc   *Service
	reg   *keys.Registry
	pol   *policy.Engine
	aud   *audit.Log
	calls atomic.Int64 // SignDigest calls across all backends
}

// countingSigner counts SignDigest calls, to prove which paths reach a signer.
type countingSigner struct {
	signer.Signer
	n *atomic.Int64
}

func (c countingSigner) SignDigest(ctx context.Context, d [32]byte, o signer.SignOptions) (signer.Result, error) {
	c.n.Add(1)
	return c.Signer.SignDigest(ctx, d, o)
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

// newEnv wires a Service on a fresh DB and the quorumvault HSM token.
func newEnv(t *testing.T) *env {
	t.Helper()
	pool := dbtest.New(t)
	tok := hsmtest.Token(t, "quorumvault")
	e := &env{t: t, ctx: context.Background(), aud: audit.New(pool)}
	hsmGen := hsmsigner.NewGenerator(tok)
	gens := []domain.KeyGenerator{hsmGen}
	signers := map[domain.Backend]SignerFunc{
		domain.BackendHSM: func(k domain.Key) (signer.Signer, error) {
			s, err := hsmsigner.New(tok, k)
			return countingSigner{s, &e.calls}, err
		},
	}
	e.reg = keys.New(pool, e.aud, gens...)
	e.pol = policy.New(pool, e.aud, nil)
	e.svc = New(Config{Pool: pool, Registry: e.reg, Policy: e.pol, Approvals: approval.New(pool, e.aud),
		Audit: e.aud, Signers: signers})

	t.Cleanup(func() { // remove key material this test created
		ks, _ := e.reg.ListKeys(context.Background(), "")
		for _, k := range ks {
			switch k.Backend {
			case domain.BackendHSM:
				if err := tok.DestroyPrivateKey(context.Background(), k.HSMKeyID); err != nil && !errors.Is(err, hsm.ErrKeyNotFound) {
					t.Logf("cleanup: %v", err)
				}
			}
		}
	})
	return e
}

// wallet creates a wallet with a policy (threshold 0.1 ETH, per-tx 10 ETH,
// daily 100 ETH) and dest allowlisted.
func (e *env) wallet(name string, tier domain.Tier, backend domain.Backend, required int) (domain.Wallet, domain.Key) {
	e.t.Helper()
	w, k, err := e.reg.CreateWallet(e.ctx, "admin", name, tier, backend)
	if err != nil {
		e.t.Fatal(err)
	}
	if err := e.pol.SetPolicy(e.ctx, "admin", domain.Policy{WalletID: w.ID,
		DailyLimitWei: new(big.Int).Mul(eth1, big.NewInt(100)), PerTxLimitWei: new(big.Int).Mul(eth1, big.NewInt(10)),
		ApprovalThresholdWei: milliEth(100), VelocityMaxTx: 100, VelocityWindowSeconds: 3600,
		RequiredApprovals: required}); err != nil {
		e.t.Fatal(err)
	}
	if err := e.pol.AddAllowlist(e.ctx, "admin", w.ID, dest, "dead"); err != nil {
		e.t.Fatal(err)
	}
	return w, k
}

func (e *env) submit(walletID, to string, value *big.Int, nonce uint64) Result {
	e.t.Helper()
	res, err := e.svc.Submit(e.ctx, "alice", Input{WalletID: walletID, To: to, ValueWei: value, Nonce: &nonce})
	if err != nil {
		e.t.Fatal(err)
	}
	return res
}

func (e *env) vote(actor, id string, approve bool) Result {
	e.t.Helper()
	res, err := e.svc.Vote(e.ctx, actor, id, approve, "")
	if err != nil {
		e.t.Fatalf("vote by %s: %v", actor, err)
	}
	return res
}

// events returns the audit event types for one request.
func (e *env) events(requestID string) []string {
	e.t.Helper()
	evs, err := e.aud.List(e.ctx, audit.Filter{RequestID: requestID})
	if err != nil {
		e.t.Fatal(err)
	}
	out := make([]string, len(evs))
	for i, ev := range evs {
		out[i] = ev.Type
	}
	return out
}

func (e *env) payload(requestID, typ string) map[string]any {
	e.t.Helper()
	evs, _ := e.aud.List(e.ctx, audit.Filter{RequestID: requestID})
	for _, ev := range evs {
		if ev.Type == typ {
			var m map[string]any
			json.Unmarshal(ev.Payload, &m)
			return m
		}
	}
	e.t.Fatalf("no %s event for %s", typ, requestID)
	return nil
}

func (e *env) verifyAudit() {
	e.t.Helper()
	ok, bad, err := e.aud.Verify(e.ctx)
	if err != nil || !ok {
		e.t.Fatalf("audit verify: ok=%v firstBad=%d err=%v", ok, bad, err)
	}
}

func eq(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("events\n got %v\nwant %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("events\n got %v\nwant %v", got, want)
		}
	}
}

// checkSigned asserts the request is signed by key and its raw tx decodes to
// a Sepolia EIP-1559 tx whose sender is the key's address.
func checkSigned(t *testing.T, res Result, key domain.Key) {
	t.Helper()
	r := res.Request
	if r.Status != domain.StatusSigned {
		t.Fatalf("status %s (sign error %q)", r.Status, res.SignError)
	}
	if res.From != key.Address {
		t.Fatalf("from %s, key address %s", res.From, key.Address)
	}
	tx, err := eth.DecodeRaw(r.RawTx)
	if err != nil {
		t.Fatal(err)
	}
	if tx.Type() != 2 || tx.ChainId().Int64() != eth.SepoliaChainID || tx.Hash().Hex() != r.TxHash {
		t.Fatalf("tx type %d chain %v hash %s/%s", tx.Type(), tx.ChainId(), tx.Hash().Hex(), r.TxHash)
	}
	if err := eth.VerifySender(tx, common.HexToAddress(key.Address)); err != nil {
		t.Fatal(err)
	}
	if len(r.Signature) != 65 || r.KeyID != key.ID {
		t.Fatalf("signature len %d, key %s want %s", len(r.Signature), r.KeyID, key.ID)
	}
}

var (
	seqAllow    = []string{domain.EventRequestCreated, domain.EventPolicyDecision, domain.EventSignStarted, domain.EventSignCompleted}
	seqApproved = []string{domain.EventRequestCreated, domain.EventPolicyDecision, domain.EventApprovalVoted,
		domain.EventRequestApproved, domain.EventSignStarted, domain.EventSignCompleted}
)

func TestHSMHotAllowSigns(t *testing.T) {
	e := newEnv(t)
	w, k := e.wallet("hot-hsm", domain.TierHot, domain.BackendHSM, 0)
	res := e.submit(w.ID, dest, milliEth(10), 0)
	checkSigned(t, res, k)
	if res.Request.Decision.Outcome != domain.OutcomeAllow {
		t.Fatalf("decision %+v", res.Request.Decision)
	}
	eq(t, e.events(res.Request.ID), seqAllow)
	p := e.payload(res.Request.ID, domain.EventSignCompleted)
	if p["backend"] != "hsm" || p["tx_hash"] != res.Request.TxHash {
		t.Fatalf("sign.completed payload %v", p)
	}
	got, err := e.svc.Get(e.ctx, res.Request.ID)
	if err != nil || got.TxHash != res.Request.TxHash || got.Status != domain.StatusSigned {
		t.Fatalf("Get: %+v %v", got, err)
	}
	e.verifyAudit()
}

func TestOverThresholdNeedsSecondApprover(t *testing.T) {
	e := newEnv(t)
	w, k := e.wallet("hot-hsm", domain.TierHot, domain.BackendHSM, 0)
	res := e.submit(w.ID, dest, eth1, 0)
	if res.Request.Status != domain.StatusPendingApproval {
		t.Fatalf("status %s", res.Request.Status)
	}
	if _, err := e.svc.Vote(e.ctx, "alice", res.Request.ID, true, ""); !errors.Is(err, approval.ErrSelfApproval) {
		t.Fatalf("self approval: %v", err)
	}
	if e.calls.Load() != 0 {
		t.Fatal("signer called before approval")
	}
	out := e.vote("bob", res.Request.ID, true)
	checkSigned(t, out, k)
	if out.Tally == nil || out.Tally.Approvals != 1 || !out.Tally.Done {
		t.Fatalf("tally %+v", out.Tally)
	}
	if _, err := e.svc.Vote(e.ctx, "carol", res.Request.ID, true, ""); !errors.Is(err, approval.ErrNotPending) {
		t.Fatalf("vote after signed: %v", err)
	}
	eq(t, e.events(res.Request.ID), seqApproved)
	e.verifyAudit()
}

func TestRejectPath(t *testing.T) {
	e := newEnv(t)
	w, _ := e.wallet("hot-hsm", domain.TierHot, domain.BackendHSM, 2)
	res := e.submit(w.ID, dest, eth1, 0)
	out := e.vote("bob", res.Request.ID, true)
	if out.Request.Status != domain.StatusPendingApproval || out.Tally.Done {
		t.Fatalf("after 1 of 2: %s %+v", out.Request.Status, out.Tally)
	}
	out = e.vote("carol", res.Request.ID, false)
	if out.Request.Status != domain.StatusRejected {
		t.Fatalf("status %s", out.Request.Status)
	}
	if _, err := e.svc.Vote(e.ctx, "dave", res.Request.ID, true, ""); !errors.Is(err, approval.ErrNotPending) {
		t.Fatalf("vote after reject: %v", err)
	}
	if e.calls.Load() != 0 || len(out.Request.Signature) != 0 {
		t.Fatal("rejected request reached a signer")
	}
	eq(t, e.events(res.Request.ID), []string{domain.EventRequestCreated, domain.EventPolicyDecision,
		domain.EventApprovalVoted, domain.EventApprovalVoted, domain.EventRequestRejected})
	e.verifyAudit()
}

func TestDeniedNeverReachesSigner(t *testing.T) {
	e := newEnv(t)
	w, _ := e.wallet("hot-hsm", domain.TierHot, domain.BackendHSM, 0)
	res := e.submit(w.ID, other, milliEth(1), 0)
	if res.Request.Status != domain.StatusDenied || res.Request.Decision.Reasons[0] != policy.ReasonNotAllowlisted {
		t.Fatalf("status %s decision %+v", res.Request.Status, res.Request.Decision)
	}
	if _, err := e.svc.Vote(e.ctx, "bob", res.Request.ID, true, ""); !errors.Is(err, approval.ErrNotPending) {
		t.Fatalf("vote on denied: %v", err)
	}
	// A wallet without a policy is denied too.
	w2, _, err := e.reg.CreateWallet(e.ctx, "admin", "no-policy", domain.TierHot, domain.BackendHSM)
	if err != nil {
		t.Fatal(err)
	}
	res2 := e.submit(w2.ID, dest, big.NewInt(1), 0)
	if res2.Request.Status != domain.StatusDenied || res2.Request.Decision.Reasons[0] != policy.ReasonNoPolicy {
		t.Fatalf("no policy: %s %+v", res2.Request.Status, res2.Request.Decision)
	}
	if e.calls.Load() != 0 {
		t.Fatalf("signer called %d times for denied requests", e.calls.Load())
	}
	eq(t, e.events(res.Request.ID), []string{domain.EventRequestCreated, domain.EventPolicyDecision})
	e.verifyAudit()
}

func TestSubmitValidation(t *testing.T) {
	e := newEnv(t)
	w, _ := e.wallet("hot-hsm", domain.TierHot, domain.BackendHSM, 0)
	n := uint64(0)
	bad := []Input{
		{WalletID: w.ID, To: "0x1234", ValueWei: big.NewInt(1), Nonce: &n},
		{WalletID: w.ID, To: dest, ValueWei: big.NewInt(-1), Nonce: &n},
		{WalletID: w.ID, To: dest, ValueWei: nil, Nonce: &n},
		{WalletID: w.ID, To: dest, ValueWei: big.NewInt(1)}, // no nonce, no RPC
		{WalletID: w.ID, To: dest, ValueWei: big.NewInt(1), Nonce: &n, MaxFeePerGas: big.NewInt(1), MaxPriorityFeePerGas: big.NewInt(2)},
	}
	for i, in := range bad {
		if _, err := e.svc.Submit(e.ctx, "alice", in); !errors.Is(err, ErrInvalid) {
			t.Errorf("case %d: want ErrInvalid, got %v", i, err)
		}
	}
	if _, err := e.svc.Submit(e.ctx, "", Input{WalletID: w.ID, To: dest, ValueWei: big.NewInt(1), Nonce: &n}); !errors.Is(err, ErrInvalid) {
		t.Errorf("empty actor: %v", err)
	}
	if _, err := e.svc.Submit(e.ctx, "alice", Input{WalletID: "00000000-0000-0000-0000-000000000000", To: dest, ValueWei: big.NewInt(1), Nonce: &n}); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown wallet: %v", err)
	}
	if _, err := e.svc.Get(e.ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("get bad id: %v", err)
	}
}

func TestRotatedKeyStillSignsOldRequest(t *testing.T) {
	e := newEnv(t)
	w, v1 := e.wallet("hot-hsm", domain.TierHot, domain.BackendHSM, 0)
	pending := e.submit(w.ID, dest, eth1, 0)
	v2, _, err := e.reg.Rotate(e.ctx, "admin", w.ID)
	if err != nil {
		t.Fatal(err)
	}
	out := e.vote("bob", pending.Request.ID, true)
	checkSigned(t, out, v1) // bound to v1 (now sign_only), created before the rotation
	fresh := e.submit(w.ID, dest, milliEth(1), 1)
	checkSigned(t, fresh, v2)
	e.verifyAudit()
}

func TestRetiredKeyFails(t *testing.T) {
	e := newEnv(t)
	w, v1 := e.wallet("hot-hsm", domain.TierHot, domain.BackendHSM, 0)
	pending := e.submit(w.ID, dest, eth1, 0)
	if _, _, err := e.reg.Rotate(e.ctx, "admin", w.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.reg.Retire(e.ctx, "admin", v1.ID); err != nil {
		t.Fatal(err)
	}
	out := e.vote("bob", pending.Request.ID, true)
	if out.Request.Status != domain.StatusFailed || out.SignError == "" || len(out.Request.Signature) != 0 {
		t.Fatalf("status %s err %q", out.Request.Status, out.SignError)
	}
	if e.calls.Load() != 0 {
		t.Fatal("retired key reached a signer")
	}
	if p := e.payload(pending.Request.ID, domain.EventSignFailed); p["stage"] != "authorize" {
		t.Fatalf("sign.failed payload %v", p)
	}
	eq(t, e.events(pending.Request.ID), []string{domain.EventRequestCreated, domain.EventPolicyDecision,
		domain.EventApprovalVoted, domain.EventRequestApproved, domain.EventSignFailed})
	e.verifyAudit()
}

func TestConcurrentApprovalsSignOnce(t *testing.T) {
	e := newEnv(t)
	w, k := e.wallet("hot-hsm", domain.TierHot, domain.BackendHSM, 1)
	res := e.submit(w.ID, dest, eth1, 0)
	approvers := []string{"bob", "carol", "dave", "erin", "frank", "grace"}
	var wg sync.WaitGroup
	for _, a := range approvers {
		wg.Add(1)
		go func(a string) {
			defer wg.Done()
			e.svc.Vote(e.ctx, a, res.Request.ID, true, "") // late votes may get ErrNotPending
		}(a)
	}
	wg.Wait()
	if n := e.calls.Load(); n != 1 {
		t.Fatalf("signer called %d times, want 1", n)
	}
	got, _ := e.svc.Get(e.ctx, res.Request.ID)
	checkSigned(t, Result{Request: got, From: k.Address}, k)
	n := 0
	for _, typ := range e.events(res.Request.ID) {
		if typ == domain.EventSignStarted || typ == domain.EventRequestApproved {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("want exactly one request.approved and one sign.started, events %v", e.events(res.Request.ID))
	}
	e.verifyAudit()
}

func TestConcurrentSignCallsSignOnce(t *testing.T) {
	e := newEnv(t)
	w, _ := e.wallet("hot-hsm", domain.TierHot, domain.BackendHSM, 1)
	res := e.submit(w.ID, dest, eth1, 0)
	approved, ok, err := e.svc.transition(e.ctx, res.Request.ID, domain.StatusApproved, domain.StatusPendingApproval)
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	var wg sync.WaitGroup
	var signed atomic.Int64
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r := e.svc.sign(e.ctx, "system", approved); r.Request.Status == domain.StatusSigned && r.SignError == "" {
				signed.Add(1)
			}
		}()
	}
	wg.Wait()
	if e.calls.Load() != 1 || signed.Load() != 1 {
		t.Fatalf("signer calls %d, successful sign() %d; want 1 and 1", e.calls.Load(), signed.Load())
	}
}

// A cold wallet always needs approval, here two.
func TestColdWalletNeedsTwoApprovals(t *testing.T) {
	e := newEnv(t)
	w, k := e.wallet("cold-hsm", domain.TierCold, domain.BackendHSM, 0)
	res := e.submit(w.ID, dest, big.NewInt(1), 0) // 1 wei: cold always needs approval
	if res.Request.Status != domain.StatusPendingApproval || res.Request.Decision.RequiredApprovals != 2 {
		t.Fatalf("status %s decision %+v", res.Request.Status, res.Request.Decision)
	}
	if out := e.vote("bob", res.Request.ID, true); out.Request.Status != domain.StatusPendingApproval {
		t.Fatalf("after 1 of 2: %s", out.Request.Status)
	}
	out := e.vote("carol", res.Request.ID, true)
	checkSigned(t, out, k)
	eq(t, e.events(res.Request.ID), []string{domain.EventRequestCreated, domain.EventPolicyDecision,
		domain.EventApprovalVoted, domain.EventApprovalVoted, domain.EventRequestApproved,
		domain.EventSignStarted, domain.EventSignCompleted})
	e.verifyAudit()
}
