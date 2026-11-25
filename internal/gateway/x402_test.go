package gateway

import (
	"context"
	"math/big"
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

func (r *testRule) CheckPayment(_ context.Context, _ *GuardTx, _ signjob.Job, _ signjob.Intent, p PaymentFacts) error {
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

// A build without the credential rule refuses every authorization, whatever else is right: the production state until GC2's rule is installed.
func TestEIP3009RefusedWithoutAPaymentRule(t *testing.T) {
	h := x402Harness(t, nil)
	j := h.x402Job("a1", x402Spec{nonce: 1})
	h.mustReject(j, ReasonPaymentRule)
	// Not even with approvals attached: they are ignored for this kind.
	j2 := h.x402Job("a2", x402Spec{nonce: 2})
	j2.Approvals = h.approvals(x402Intent(t, j2), "alice", "bob")
	h.mustReject(j2, ReasonPaymentRule)
	if n := h.signer.calls.Load(); n != 0 {
		t.Fatalf("the signer was called %d times", n)
	}
	// A plain decider (what qv-gateway and qv-cosigner build today) has no rule either.
	d := NewDecider(h.cfg, h.gw.codecs, h.guard, ModeGateway, h.clock)
	if d.payments != nil {
		t.Fatal("a new decider has a payment rule")
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
