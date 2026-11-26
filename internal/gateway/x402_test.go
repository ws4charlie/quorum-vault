package gateway

import (
	"context"
	"encoding/json"
	"math/big"
	"os"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/ws4charlie/quorum-vault/internal/chain/evm"
	"github.com/ws4charlie/quorum-vault/internal/signer"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// x402 payment authorizations (kind eip3009): the zone decodes the typed data itself, checks it against its own config, holds the token nonce as a
// claim in its guard, and signs only when a payment rule is installed (GC2's credential check). These tests use the software harness.

var addrPayee = common.HexToAddress("0x00000000000000000000000000000000000FAc01")

// testRule stands in for the credential rule, in test code only: it records what the zone decoded and allows or refuses.
type testRule struct {
	mu    sync.Mutex
	seen  []PaymentFacts
	allow bool
}

// Scope treats every authorization as one of a Gate-governed wallet, and nothing else.
func (r *testRule) Scope(_ context.Context, _ *ChainConfig, _ *KeysetView, _ signjob.Job, i signjob.Intent, _ TxInfo) (*PaymentScope, error) {
	if i.Kind == evm.KindEIP3009 {
		return &PaymentScope{WalletID: "00000000-0000-4000-8000-000000000001"}, nil
	}
	return &PaymentScope{}, nil
}

func (r *testRule) CheckPayment(_ context.Context, _ *GuardTx, _ signjob.Job, _ signjob.Intent, p PaymentFacts, _ *PaymentScope) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = append(r.seen, p)
	if !r.allow {
		return reject(ReasonPaymentRule, "the test rule refuses")
	}
	return nil
}

// x402Harness is the software harness with USDT enabled for x402, and (when rule is not nil) the rule installed.
func x402Harness(t *testing.T, rule PaymentRule) *harness {
	t.Helper()
	h := newHarnessSoft(t)
	h.cfg.Chains[testChain].EVM.X402 = map[string]evm.X402Token{"USDT": {Name: "USDC", Version: "2", MaxWindowSeconds: 600, PerPaymentLimit: big.NewInt(1_000_000)}}
	gw, err := New(h.cfg, nil, map[string]signer.Signer{testPartition: h.signer, testColdPartition: h.signer}, h.guard, h.biz,
		Options{WorkerID: "w-x402", Lease: 60e9, Now: h.clock, PaymentRule: rule})
	if err != nil {
		t.Fatal(err)
	}
	h.gw = gw
	t.Cleanup(func() { gw.Wait(10e9) })
	return h
}

type x402Spec struct {
	to          common.Address
	value       int64
	after, ttl  int64 // validAfter is now+after, validBefore is now+ttl (seconds)
	nonce       byte
	intentID    string
	mutatePayer *common.Address
}

func (h *harness) x402Job(id string, s x402Spec) signjob.Job {
	h.t.Helper()
	if s.to == (common.Address{}) {
		s.to = addrPayee
	}
	if s.value == 0 {
		s.value = 250_000
	}
	if s.ttl == 0 {
		s.ttl = 300
	}
	if s.intentID == "" {
		s.intentID = "x-" + id
	}
	payer := h.hot
	if s.mutatePayer != nil {
		payer = *s.mutatePayer
	}
	var nonce [32]byte
	nonce[31] = s.nonce
	now := h.clock().Unix()
	payload, digest, err := h.cfg.Chains[testChain].EVM.NewPayload3009("USDT", payer, s.to, big.NewInt(s.value), uint64(now+s.after), uint64(now+s.ttl), nonce)
	if err != nil {
		h.t.Fatal(err)
	}
	in := signjob.Intent{Kind: evm.KindEIP3009, ID: s.intentID, PartitionID: testPartition, Chain: testChain, Asset: "USDT", To: s.to.Hex(), Amount: big.NewInt(s.value).String()}
	return signjob.Job{ID: id, PartitionID: testPartition, KeyRef: "m/0", Chain: testChain, Intent: mustJSON(in), Digest: digest[:], Payload: payload}
}

// Without a Gate setting no wallet is Gate-governed, so every authorization is refused (check 0), whatever else is right. Every decider has the Gate
// credential rule: NewDecider installs it, and SetPaymentRule(nil) puts it back.
func TestEIP3009RefusedWithoutAGateGovernedWallet(t *testing.T) {
	h := x402Harness(t, nil)
	j := h.x402Job("a1", x402Spec{nonce: 1})
	h.mustReject(j, "wallet_not_gate_governed")
	// Not even with approvals attached: they are ignored for this kind.
	j2 := h.x402Job("a2", x402Spec{nonce: 2})
	j2.Approvals = h.approvals(x402Intent(t, j2), "alice", "bob")
	h.mustReject(j2, "wallet_not_gate_governed")
	if n := h.signer.calls.Load(); n != 0 {
		t.Fatalf("the signer was called %d times", n)
	}
	d := NewDecider(h.cfg, h.gw.codecs, h.guard, ModeGateway, h.clock)
	if _, ok := d.payments.(*GateRule); !ok {
		t.Fatalf("a new decider's payment rule is %T, want the Gate credential rule", d.payments)
	}
	d.SetPaymentRule(&testRule{})
	d.SetPaymentRule(nil)
	if _, ok := d.payments.(*GateRule); !ok {
		t.Fatalf("SetPaymentRule(nil) left %T, want the Gate credential rule", d.payments)
	}
}

func x402Intent(t *testing.T, j signjob.Job) signjob.Intent {
	t.Helper()
	i, err := parseIntent(j)
	if err != nil {
		t.Fatal(err)
	}
	return i
}

func TestEIP3009SignedWithTheRuleAndExposesWhatItDecoded(t *testing.T) {
	rule := &testRule{allow: true}
	h := x402Harness(t, rule)
	j := h.x402Job("b1", x402Spec{nonce: 7, after: -10})
	d := h.mustSign(j) // the signature recovers to the hot address over the EIP-712 digest
	if len(rule.seen) != 1 {
		t.Fatalf("the rule saw %d payments", len(rule.seen))
	}
	p := rule.seen[0]
	now := uint64(h.clock().Unix())
	if p.Chain != "eip155:31337" || p.Asset != addrToken.Hex() || p.Payee != addrPayee.Hex() || p.Amount.Int64() != 250_000 || p.Payer != h.hot.Hex() ||
		p.ValidAfter != now-10 || p.ValidBefore != now+300 || p.ChainName != testChain || p.AssetSymbol != "USDT" ||
		p.Nonce != "0x0000000000000000000000000000000000000000000000000000000000000007" {
		t.Fatalf("decoded payment %+v", p)
	}
	// The signature is in the form x402 expects: r, s low, v 27/28, valid for the token.
	r, s, v, err := evm.SignatureRSV([32]byte(j.Digest), signer.Signature{R: new(big.Int).SetBytes(d.Sig[:32]), S: new(big.Int).SetBytes(d.Sig[32:])}, h.signer.PublicKey())
	if err != nil || (v != 27 && v != 28) || r == ([32]byte{}) || s == ([32]byte{}) {
		t.Fatalf("rsv %x %x %d %v", r, s, v, err)
	}
	// Asking again for the same job returns the stored signature and signs nothing more.
	before := h.signer.calls.Load()
	again := h.x402Job("b1-again", x402Spec{nonce: 7, after: -10, intentID: "x-b1"})
	d2 := h.mustSign(again)
	if string(d2.Sig) != string(d.Sig) || h.signer.calls.Load() != before {
		t.Fatal("the same authorization was signed twice")
	}
}

func TestEIP3009NonceIsNeverSignedTwice(t *testing.T) {
	h := x402Harness(t, &testRule{allow: true})
	h.mustSign(h.x402Job("c1", x402Spec{nonce: 9}))
	// Another intent, same token, same payer, same nonce: even to another payee for another amount.
	h.mustReject(h.x402Job("c2", x402Spec{nonce: 9, to: addrUser, value: 5}), ReasonNonceTaken)
	// The same intent with another window (another digest, same nonce) is no replacement either.
	h.mustReject(h.x402Job("c3", x402Spec{nonce: 9, ttl: 200, intentID: "x-c1"}), ReasonFeeNotHigher)
	// A new nonce is fine.
	h.mustSign(h.x402Job("c4", x402Spec{nonce: 10}))
}

func TestEIP3009RefusalsAtTheZone(t *testing.T) {
	rule := &testRule{allow: true}
	h := x402Harness(t, rule)
	other := addrEvil
	cases := []struct {
		name string
		spec x402Spec
		fix  func(*signjob.Job)
		code string
	}{
		{"value over the per-payment limit", x402Spec{nonce: 20, value: 1_000_001}, nil, ReasonTx},
		{"window already over", x402Spec{nonce: 21, after: -400, ttl: -100}, nil, ReasonPaymentWindow},
		{"valid beyond the zone's window from now", x402Spec{nonce: 22, after: 400, ttl: 700}, nil, ReasonPaymentWindow},
		{"window longer than allowed", x402Spec{nonce: 23, after: -10, ttl: 700}, nil, ReasonTx},
		{"payer is not the hot wallet", x402Spec{nonce: 24, mutatePayer: &other}, nil, ReasonTx},
		{"a payload that is a transaction", x402Spec{nonce: 25}, func(j *signjob.Job) {
			p, d := h.payloadFor(h.tokenTx(addrPayee, 250_000, 5))
			j.Payload, j.Digest = p, d
		}, ReasonTx},
		{"a digest that does not match", x402Spec{nonce: 26}, func(j *signjob.Job) { j.Digest = append([]byte{}, j.Digest...); j.Digest[3] ^= 0xff }, ReasonTx},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			j := h.x402Job("r-"+c.name, c.spec)
			if c.fix != nil {
				c.fix(&j)
			}
			h.mustReject(j, c.code)
		})
	}
	if len(rule.seen) != 0 {
		t.Fatalf("the credential rule was asked about %d payments the zone had already refused", len(rule.seen))
	}
}

// A refusal by the rule leaves no claim behind: the nonce can be used by the retry the rule later allows.
func TestEIP3009RuleRefusalLeavesNoClaim(t *testing.T) {
	rule := &testRule{allow: false}
	h := x402Harness(t, rule)
	h.mustReject(h.x402Job("d1", x402Spec{nonce: 30}), ReasonPaymentRule)
	rule.mu.Lock()
	rule.allow = true
	rule.mu.Unlock()
	h.mustSign(h.x402Job("d2", x402Spec{nonce: 30, intentID: "x-d2"}))
}

func TestEIP3009ForOtherKindsNothingChanged(t *testing.T) {
	h := x402Harness(t, nil)
	h.mustSign(h.withdrawal("w1", addrUser, 100, 0, "alice"))
}

// The x402 block of the zone config: parsed into the verifier's config, and a bad one refuses to start.
func TestX402ConfigParsesAndRefusesBadEntries(t *testing.T) {
	good, _ := os.ReadFile("config.example.json")
	build := func(x402 any) error {
		var m map[string]any
		if err := json.Unmarshal(good, &m); err != nil {
			t.Fatal(err)
		}
		for _, c := range m["chains"].(map[string]any) {
			if e, ok := c.(map[string]any)["evm"].(map[string]any); ok {
				e["x402"] = x402
			}
		}
		b, _ := json.Marshal(m)
		_, err := ParseConfig(b)
		return err
	}
	// The example has a token; find its symbol.
	var f File
	if err := json.Unmarshal(good, &f); err != nil {
		t.Fatal(err)
	}
	sym := ""
	for _, c := range f.Chains {
		if c.EVM == nil {
			continue
		}
		for s := range c.EVM.Tokens {
			sym = s
		}
	}
	if sym == "" {
		t.Skip("the example config has no token")
	}
	ok := map[string]any{sym: map[string]any{"name": "USDC", "version": "2", "max_window_seconds": 600, "per_payment_limit": "500000"}}
	if err := build(ok); err != nil {
		t.Fatalf("a good x402 block was refused: %v", err)
	}
	for name, bad := range map[string]any{
		"unknown token":    map[string]any{"NOPE": ok[sym]},
		"no limit":         map[string]any{sym: map[string]any{"name": "USDC", "version": "2", "max_window_seconds": 600, "per_payment_limit": "0"}},
		"no window":        map[string]any{sym: map[string]any{"name": "USDC", "version": "2", "max_window_seconds": 0, "per_payment_limit": "5"}},
		"no domain name":   map[string]any{sym: map[string]any{"name": "", "version": "2", "max_window_seconds": 600, "per_payment_limit": "5"}},
		"a decimal sign":   map[string]any{sym: map[string]any{"name": "USDC", "version": "2", "max_window_seconds": 600, "per_payment_limit": "-5"}},
		"an unknown field": map[string]any{sym: map[string]any{"name": "USDC", "version": "2", "max_window_seconds": 600, "per_payment_limit": "5", "shard": 1}},
	} {
		if err := build(bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
