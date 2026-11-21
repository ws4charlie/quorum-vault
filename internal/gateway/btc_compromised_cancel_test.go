package gateway

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// The cancel of a compromised generation of the Bitcoin account key (btc_compromised_cancel.go): a payment the zone refused after the mark leaves its coins
// claimed in the guard with no signature, and a drain that spends one is refused for ever. The cancel is the way out. Software harness only.

// coins100 builds the inputs of the partition's own hot shard under generation 1, one per number, of 300 000 sats.
func coins100(ns ...int) []btc.PayloadInput {
	var in []btc.PayloadInput
	for _, n := range ns {
		in = append(in, btcIn(n, 0, 300_000, 1, 0))
	}
	return in
}

// wd1 is a withdrawal spending the coins, change back to generation 1's shard.
func (r *btcGenRig) wd1(id string, ins []btc.PayloadInput) []signjob.Job {
	var sum uint64
	for _, in := range ins {
		sum += in.Value
	}
	p := btc.Payload{Version: 2, Inputs: ins, Outputs: []btc.PayloadOutput{{Address: r.any, Value: 100_000}, {Address: r.hot0, Value: sum - 100_000 - 1000}}}
	return r.jobs(id, wdIntent("w-"+id, r.any, 100_000), p, "auto")
}

// cancelOf is the strict cancel of the coins: all of them, one output to dest (the shard of generation 1 unless a test says otherwise).
func (r *btcGenRig) cancelOf(id string, ins []btc.PayloadInput, dest string) []signjob.Job {
	var sum uint64
	for _, in := range ins {
		sum += in.Value
	}
	p := btc.Payload{Version: 2, Inputs: ins, Outputs: []btc.PayloadOutput{{Address: dest, Value: sum - 1000}}}
	return r.jobs(id, signjob.Intent{Kind: "cancel", ID: "cancel-" + id, PartitionID: btcPartition, To: dest, Amount: "0", NotAfter: r.clock().Add(24 * 3600e9).Unix()}, p)
}

func (r *btcGenRig) drainOf(id string, ins []btc.PayloadInput) []signjob.Job {
	var sum uint64
	for _, in := range ins {
		sum += in.Value
	}
	p := btc.Payload{Version: 2, Inputs: ins, Outputs: []btc.PayloadOutput{{Address: r.hot2, Value: sum - 1000}}}
	return r.jobs(id, signjob.Intent{Kind: signjob.KindDrain, ID: id, From: r.hot0, To: r.hot2, Amount: fmt.Sprint(sum)}, p)
}

func (r *btcGenRig) compromisedActive(guards ...*Guard) {
	r.t.Helper()
	if len(guards) == 0 {
		guards = []*Guard{r.guard}
	}
	r.candidate(guards...)
	r.step(btcTreeID, KeysetMarkCompromised, 1, func(c *KeysetChange) { c.Successor, c.Caps = 2, map[string]string{"BTC": "3000000"} }, guards...)
	r.activate2(guards...)
}

func (r *btcGenRig) rejects(js []signjob.Job, code string) string { return r.refuses(js, code) }

// A withdrawal signed before the mark claimed its coins; after it the key cancels them, and then neither a drain nor the withdrawal can use them. Other coins
// are not touched.
func TestBTCCompromisedGenerationCancelsAClaimedCoin(t *testing.T) {
	r := newBTCGenRig(t)
	ins := coins100(1, 2)
	r.signs(r.wd1("w0", ins), 1)
	r.compromisedActive()
	// the withdrawal itself is refused now
	r.rejects(r.wd1("w1", coins100(3)), ReasonKeyset)
	// a drain of a claimed coin is refused (that is the case); a drain of another coin goes
	r.rejects(r.drainOf("d0", coins100(1)), ReasonNonceTaken)
	r.signs(r.cancelOf("n0", ins, r.hot0), 1)
	r.rejects(r.drainOf("d1", ins), ReasonNonceCancel)
	r.signs(r.drainOf("d2", coins100(5)), 1)
	// the cancel's own output is an ordinary coin of generation 1's shard: the next drain moves it
	r.signs(r.drainOf("d3", coins100(6)), 1)
}

// What a compromised generation may not do with a cancel.
func TestBTCCompromisedCancelShape(t *testing.T) {
	r := newBTCGenRig(t)
	ins := coins100(1, 2)
	r.signs(r.wd1("w0", ins), 1)
	r.candidate()
	r.step(btcTreeID, KeysetMarkCompromised, 1, func(c *KeysetChange) { c.Successor, c.Caps = 2, map[string]string{"BTC": "3000000"} })
	// the successor is not active yet: a wait, nothing signs
	if d := r.run(r.cancelOf("early", ins, r.hot0)[0]); d.Outcome != OutcomeRetry {
		t.Fatalf("successor not active: %s %q", d.Outcome, d.Reason)
	}
	r.activate2()
	r.rejects(r.cancelOf("succ", ins, r.hot2), ReasonTx)                   // to the successor's shard: not a cancel (the verifier: its own shard)
	r.rejects(r.cancelOf("any", ins, r.any), ReasonTx)                     // to a stranger
	r.rejects(r.cancelOf("sub", ins[:1], r.hot0), ReasonCancelClaims)      // fewer coins than the intent claimed
	r.rejects(r.cancelOf("free", coins100(9), r.hot0), ReasonCancelClaims) // a coin no intent claimed (in the gateway)
	r.signs(r.cancelOf("ok", ins, r.hot0), 1)
}

// A cancel never takes over a claim held by a drain, in the gateway and in a cosigner.
func TestBTCCompromisedCancelNeverTakesADrainsClaim(t *testing.T) {
	r := newBTCGenRig(t)
	cos := mustGuard(t, r.harness)
	dec := NewDecider(r.cfg, r.gw.codecs, cos, ModeCosigner, r.clock)
	pub, _ := r.acct.PubAt(1, []uint32{1, 0})
	r.compromisedActive(r.guard, cos)
	ins := coins100(1)
	dj := r.drainOf("d0", ins)
	r.signs(dj, 1)
	if _, err := dec.Decide(context.Background(), dj[0], mustParseCompressed(t, pub)); err != nil {
		t.Fatal(err)
	}
	why := r.rejects(r.cancelOf("on-drain", ins, r.hot0), ReasonKeyset)
	if !strings.Contains(why, "claimed by a drain") {
		t.Fatal(why)
	}
	cj := r.cancelOf("on-drain-cos", ins, r.hot0)
	if _, err := dec.Decide(context.Background(), cj[0], mustParseCompressed(t, pub)); err == nil {
		t.Fatal("the cosigner authorized a cancel of a drain's coin")
	} else if why, ok := IsRejection(err); !ok || !strings.Contains(why, "claimed by a drain") {
		t.Fatal(err)
	}
}

// The bound is per compromised generation; routine cancels signed while the key was active do not count; the explicit value is honoured, the default is 16.
func TestBTCCompromisedCancelCountIsBoundedPerGeneration(t *testing.T) {
	r := newBTCGenRig(t)
	r.cfg.Chains[btcChain].MaxCancelsPerSource = 2
	var all [][]btc.PayloadInput
	for i := 0; i < 4; i++ {
		all = append(all, coins100(10+i))
		r.signs(r.wd1(fmt.Sprintf("w%d", i), all[i]), 1)
	}
	r.signs(r.cancelOf("routine0", all[0], r.hot0), 1) // while active: not counted
	r.signs(r.cancelOf("routine1", all[1], r.hot0), 1)
	r.signs(r.cancelOf("routine2", all[2], r.hot0), 1)
	r.compromisedActive()
	r.signs(r.cancelOf("em3", all[3], r.hot0), 1)
	// two more claimed coins of the same generation: the second is admitted, the third is the bound
	r.cfg.Chains[btcChain].MaxCancelsPerSource = 1
	if d := r.run(r.cancelOf("em-over", coins100(10), r.hot0)[0]); d.Outcome != OutcomeRejected {
		t.Fatalf("beyond the bound: %s %q", d.Outcome, d.Reason)
	} else if !strings.HasPrefix(d.Reason, ReasonCancelGas) || !strings.Contains(d.Reason, "max_cancels_per_source") {
		t.Fatal(d.Reason)
	}
	if (&ChainConfig{}).maxCancelsPerSource() != 16 {
		t.Fatal("the default bound is not 16")
	}
}

// Every pair of views: the gateway claimed the coin or not, the cosigner claimed it or not, the cosigner has the mark or not.
func TestBTCCompromisedCancelEveryPairOfViews(t *testing.T) {
	for _, gwClaimed := range []bool{true, false} {
		for _, cosClaimed := range []bool{true, false} {
			for _, cosMark := range []bool{true, false} {
				name := fmt.Sprintf("gw claimed=%v cos claimed=%v cos has mark=%v", gwClaimed, cosClaimed, cosMark)
				t.Run(name, func(t *testing.T) {
					r := newBTCGenRig(t)
					cos := mustGuard(t, r.harness)
					dec := NewDecider(r.cfg, r.gw.codecs, cos, ModeCosigner, r.clock)
					pub := mustParseCompressed(t, func() []byte { p, _ := r.acct.PubAt(1, []uint32{1, 0}); return p }())
					ins := coins100(1, 2)
					wj := r.wd1("w0", ins)
					if gwClaimed {
						r.signs(wj, 1)
					}
					if cosClaimed {
						if _, err := dec.Decide(context.Background(), wj[0], pub); err != nil {
							t.Fatal(err)
						}
					}
					if cosMark {
						r.compromisedActive(r.guard, cos)
					} else {
						r.compromisedActive(r.guard)
					}
					cj := r.cancelOf("n0", ins, r.hot0)
					v, err := dec.Decide(context.Background(), cj[0], pub)
					switch {
					case cosMark:
						if err != nil || !v.NeedSign {
							t.Fatalf("cosigner with the mark: %v", err)
						}
					case cosClaimed:
						if err != nil { // it still sees an active key: a cancel of a claim it holds is allowed as always
							t.Fatalf("cosigner without the mark, holding the claim: %v", err)
						}
					default:
						if _, ok := IsRejection(err); !ok { // an active key's cancel needs a claim in a cosigner too (as before this change)
							t.Fatalf("cosigner without the mark and without the claim: %v", err)
						}
					}
					if gwClaimed {
						r.signs(cj, 1)
						gd := NewDecider(r.cfg, r.gw.codecs, r.guard, ModeGateway, r.clock)
						if _, err := gd.Decide(context.Background(), r.drainOf("d0", ins)[0], pub); err == nil {
							t.Fatal("a drain was admitted at coins a cancel owns")
						}
					} else {
						r.rejects(cj, ReasonCancelClaims)
					}
					if cosMark && err == nil {
						// the cosigner took (or kept) the claims for the cancel: a drain of those coins is refused there too
						if _, err := dec.Decide(context.Background(), r.drainOf("d1", ins)[0], pub); err == nil {
							t.Fatal("the cosigner admitted a drain at coins its cancel owns")
						}
					}
				})
			}
		}
	}
}

// A cosigner that holds some of the claims (another intent holds them) refuses: all or none.
func TestBTCCompromisedCancelMixedClaimsAreRefusedByTheCosigner(t *testing.T) {
	r := newBTCGenRig(t)
	cos := mustGuard(t, r.harness)
	dec := NewDecider(r.cfg, r.gw.codecs, cos, ModeCosigner, r.clock)
	pub := mustParseCompressed(t, func() []byte { p, _ := r.acct.PubAt(1, []uint32{1, 0}); return p }())
	one := r.wd1("w0", coins100(1))
	if _, err := dec.Decide(context.Background(), one[0], pub); err != nil {
		t.Fatal(err)
	}
	r.compromisedActive(r.guard, cos)
	cj := r.cancelOf("mixed", coins100(1, 2), r.hot0)
	if _, err := dec.Decide(context.Background(), cj[0], pub); err == nil {
		t.Fatal("a cancel of coins half of which another intent claimed was admitted")
	} else if why, ok := IsRejection(err); !ok || !strings.Contains(why, ReasonCancelClaims) {
		t.Fatal(err)
	}
}

// The cancel and the original can both be signed (the original finished at a cosigner before the mark): the guard allows it, the chain mines one of them.
func TestBTCCompromisedCancelOfASignedPaymentIsAllowed(t *testing.T) {
	r := newBTCGenRig(t)
	ins := coins100(1)
	r.signs(r.wd1("w0", ins), 1) // signed: a signature exists
	r.compromisedActive()
	r.signs(r.cancelOf("n0", ins, r.hot0), 1)
}
