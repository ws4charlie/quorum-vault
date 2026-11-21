package gateway

import (
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// The cancel of a compromised generation (keysets.go, compromisedCancel): the one thing besides its drain that it may sign, so that a transaction refused after
// the mark cannot leave its nonce claimed with no signature (the lane of the old address dead).

func (k *ksRig) cancelJob(id string, nonce uint64) signjob.Job {
	in := signjob.Intent{Kind: "cancel", ID: "c-" + id, PartitionID: testColdPartition, Asset: "ETH", To: k.hot.Hex(), Amount: "0", NotAfter: k.clock().Add(time.Hour).Unix()}
	return k.job("c-"+id, in, k.cancelTx(nonce))
}

// compromised makes generation 1 compromised with generation 2 active, on the guards given (the gateway's when none).
func (k *ksRig) compromised(guards ...*Guard) {
	k.t.Helper()
	k.candidate(testShardID, 2, addrG2, guards...)
	k.step(testShardID, KeysetMarkCompromised, 1, func(c *KeysetChange) { c.Successor = 2; ethCaps("5000", "5000000")(c) }, guards...)
	k.step(testShardID, KeysetActivate, 2, nil, guards...)
}

// A withdrawal signed before the mark claims nonce 0; after it the key may cancel that nonce, and then nothing else can use it.
func TestCompromisedGenerationCancelsAClaimedNonce(t *testing.T) {
	r := newKSRig(t)
	r.mustSign(r.withdrawalShard1("w0", 100, 0))
	r.compromised()
	r.mustSign(r.cancelJob("n0", 0))
	// The cancel took the claim: neither a drain nor the withdrawal again nor another cancel's intent can be signed at nonce 0.
	r.mustReject(r.drain("d0", addrG2, 100, 0, "ETH"), ReasonNonceCancel)
	// the drain goes on at the next nonce
	r.mustSign(r.drain("d1", addrG2, 100, 1, "ETH"))
}

// (The shape is also enforced earlier, by the verifier of the chain: a cancel is a zero-value 21000-gas self-send, else tx_mismatch; the zone rule repeats it from the
// decoded transaction so that it never depends on that layer.)
// What a compromised generation may not do: a cancel is a zero-value transfer to itself with no data, at a nonce the guard claimed, once the drain may start.
func TestCompromisedGenerationCancelShape(t *testing.T) {
	r := newKSRig(t)
	r.mustSign(r.withdrawalShard1("w0", 100, 0))
	r.candidate(testShardID, 2, addrG2)
	r.step(testShardID, KeysetMarkCompromised, 1, func(c *KeysetChange) { c.Successor = 2; ethCaps("5000", "5000000")(c) })
	// the successor is not active yet: a wait, nothing refused
	d := NewDecider(r.cfg, r.gw.codecs, r.guard, ModeGateway, r.clock)
	if _, err := d.Decide(t.Context(), r.cancelJob("early", 0), r.signer.PublicKey()); !errors.Is(err, ErrKeysetLag) {
		t.Fatalf("successor not active: %v", err)
	}
	r.step(testShardID, KeysetActivate, 2, nil)
	mk := func(id string, mod func(*txSpec)) signjob.Job {
		s := r.cancelTx(0)
		mod(&s)
		in := signjob.Intent{Kind: "cancel", ID: "c-" + id, PartitionID: testColdPartition, Asset: "ETH", To: r.hot.Hex(), Amount: "0", NotAfter: r.clock().Add(time.Hour).Unix()}
		return r.job("c-"+id, in, s)
	}
	r.mustReject(mk("value", func(s *txSpec) { s.value = big.NewInt(1) }), ReasonTx)
	r.mustReject(mk("elsewhere", func(s *txSpec) { s.to = addrUser }), ReasonTx)
	r.mustReject(mk("data", func(s *txSpec) { s.data = []byte{1} }), ReasonTx)
	// a label of "cancel" does not make a transfer of value a cancel: the transaction is judged
	r.mustReject(mk("label", func(s *txSpec) { s.to = addrUser; s.value = big.NewInt(50) }), ReasonTx)
	// a nonce the guard never claimed (the hole case: the core fills it with a drain)
	r.mustReject(r.cancelJob("unclaimed", 7), ReasonKeyset)
	// every other kind stays refused
	r.mustReject(r.withdrawalShard1("w9", 100, 1), ReasonKeyset)
	r.mustSign(r.cancelJob("ok", 0))
}

// Without a named successor the generation signs nothing, a cancel included; and a retired generation signs nothing (nothing new becomes signable when the
// state moves on).
func TestCompromisedCancelNeedsASuccessorAndRetiredSignsNothing(t *testing.T) {
	r := newKSRig(t)
	r.mustSign(r.withdrawalShard1("w0", 100, 0))
	r.step(testShardID, KeysetMarkCompromised, 1, nil)
	r.mustReject(r.cancelJob("n", 0), ReasonKeyset)

	r2 := newKSRig(t)
	r2.mustSign(r2.withdrawalShard1("w0", 100, 0))
	r2.replace()
	r2.step(testShardID, KeysetRetire, 1, nil)
	r2.mustReject(r2.cancelJob("n", 0), ReasonKeyset)
}

// The bound: a compromised generation's cancels are counted in all (max_cancels_per_source), the explicit value honoured.
func TestCompromisedCancelCountIsBounded(t *testing.T) {
	r := newKSRig(t)
	r.cfg.Chains[testChain].MaxCancelsPerSource = 2
	for i := uint64(0); i < 3; i++ {
		r.mustSign(r.withdrawalShard1(fmt.Sprintf("w%d", i), 100, i))
	}
	r.compromised()
	r.mustSign(r.cancelJob("a", 0))
	r.mustSign(r.cancelJob("b", 1))
	d := r.mustReject(r.cancelJob("c", 2), ReasonCancelGas)
	if !contains(d.Reason, "max_cancels_per_source") {
		t.Fatal(d.Reason)
	}
	// the default is 16
	if (&ChainConfig{}).maxCancelsPerSource() != 16 {
		t.Fatal("the default bound is not 16")
	}
}

// The views of the guards differ by design (that is the race): the gateway claimed nonce 0 for a withdrawal that the cosigner refused before it reserved
// anything. The cancel needs both; the cosigner, which holds no claim, authorizes it, the gateway, which holds one, takes it over. Every pair of views:
// (gateway claimed or not) x (cosigner claimed or not) x (cosigner has the mark or not).
func TestCompromisedCancelEveryPairOfViews(t *testing.T) {
	for _, gwClaimed := range []bool{true, false} {
		for _, cosClaimed := range []bool{true, false} {
			for _, cosMark := range []bool{true, false} {
				name := fmt.Sprintf("gw claimed=%v cos claimed=%v cos has mark=%v", gwClaimed, cosClaimed, cosMark)
				t.Run(name, func(t *testing.T) {
					r := newKSRig(t)
					cosGuard := mustGuard(t, r.harness)
					cos := NewDecider(r.cfg, r.gw.codecs, cosGuard, ModeCosigner, r.clock)
					pub := r.signer.PublicKey()
					w := r.withdrawalShard1("w0", 100, 0)
					if gwClaimed {
						r.mustSign(w)
					}
					if cosClaimed {
						if _, err := cos.Decide(t.Context(), w, pub); err != nil {
							t.Fatal(err)
						}
					}
					if cosMark {
						r.compromised(r.guard, cosGuard)
					} else {
						r.compromised(r.guard)
					}
					cj := r.cancelJob("n0", 0)
					if !cosMark {
						// the cosigner still sees an active key: it authorizes the cancel as it would any (a cancel of an active key is allowed)
						if _, err := cos.Decide(t.Context(), cj, pub); err != nil {
							t.Fatalf("cosigner without the mark: %v", err)
						}
					} else if v, err := cos.Decide(t.Context(), cj, pub); err != nil || !v.NeedSign {
						t.Fatalf("cosigner with the mark: %v", err)
					}
					d := NewDecider(r.cfg, r.gw.codecs, r.guard, ModeGateway, r.clock)
					v, err := d.Decide(t.Context(), cj, pub)
					if gwClaimed {
						if err != nil || !v.NeedSign {
							t.Fatalf("gateway that claimed nonce 0: %v", err)
						}
						// never two different intents at nonce 0: the drain is refused in the gateway, and in a cosigner that holds the cancel's claim
						if _, err := d.Decide(t.Context(), r.drain("d0", addrG2, 10, 0, "ETH"), pub); err == nil {
							t.Fatal("a drain was admitted at a nonce a cancel owns")
						}
					} else if _, refused := IsRejection(err); !refused {
						t.Fatalf("gateway that never claimed nonce 0 must refuse a compromised cancel: %v", err)
					}
				})
			}
		}
	}
}
