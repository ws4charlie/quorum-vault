package gateway

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/chain/sol"
	"github.com/ws4charlie/quorum-vault/internal/chain/sol/soltest"
	"github.com/ws4charlie/quorum-vault/internal/partition"
	"github.com/ws4charlie/quorum-vault/internal/signer"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// Replacing the key of a Solana hot shard (K4): the zone signs per generation by the state of the generation that pays the transaction fee, and a drain
// moves everything of the old generation to the successor and nothing elsewhere. The software harness only.

type solGen struct {
	k    *ksRig
	s    *solH
	hot2 *softMsg // generation 2 of the shard
	n    int
}

const solShard = "qv-us/sol-test/omnibus/0"

func newSolGen(t *testing.T) *solGen {
	t.Helper()
	k := newKSRig(t)
	g := &solGen{k: k, hot2: &softMsg{k: soltest.NewKey()}}
	g.s = newSOLHarnessOn(t, k.harness, func(cf *ChainFile) { n := 5; cf.DrainsPerHour = &n }, func(o *Options) {
		o.MessageGenerations = func(p string, base signer.MessageSigner, e *KeysetEntry) (signer.MessageSigner, error) {
			if e.KeyRef != "ref-2" {
				return nil, fmt.Errorf("unknown key reference %q", e.KeyRef)
			}
			return g.hot2, nil
		}
	})
	return g
}

func (g *solGen) candidate2() {
	g.k.step(solShard, KeysetRegisterCandidate, 2, func(c *KeysetChange) {
		c.Address, c.KeyRef, c.PublicKey = g.hot2.k.Address(), "ref-2", hex.EncodeToString(g.hot2.k.Pub[:])
	})
}

func (g *solGen) startDraining() {
	g.k.step(solShard, KeysetStartDraining, 1, func(c *KeysetChange) {
		c.Successor = 2
		c.Caps = map[string]string{"SOL": "5000000000", "TKN": "1000000"}
	})
}

func (g *solGen) activate2() { g.k.step(solShard, KeysetActivate, 2, nil) }

func (g *solGen) entry(gen int) *KeysetEntry {
	v, err := g.k.guard.EffectiveKeysets(g.k.t.Context(), g.k.cfg)
	if err != nil {
		g.k.t.Fatal(err)
	}
	return v.entry(solShard, gen)
}

// msg builds a message paid by key (a recent blockhash for a drain; the nonce of key's own pool for work that signs a nonce).
func (g *solGen) msg(key [32]byte, nonce bool, ixs ...sol.Ix) []byte {
	var all []sol.Ix
	if nonce {
		all = append(all, sol.AdvanceNonceIx(sol.NonceAddress(key, 0), key))
	}
	all = append(all, sol.SetLimitIx(100_000))
	return sol.Compile(key, g.s.bh, append(all, ixs...)...)
}

func (g *solGen) job(id string, in signjob.Intent, msg []byte, approvers ...string) signjob.Job {
	if in.PartitionID == "" {
		in.PartitionID = solPartSOL
	}
	return g.s.job(id, in, msg, in.PartitionID, sol.PathHot, nil, approvers...)
}

func (g *solGen) drainIntent(id, asset, amount string, to [32]byte) signjob.Intent {
	part := solPartSOL
	if asset == "TKN" {
		part = solPartTKN
	}
	return signjob.Intent{Kind: signjob.KindDrain, ID: id, PartitionID: part, Chain: solChain, Asset: asset, From: g.s.hot.k.Address(), To: sol.Address(to), Amount: amount,
		NotAfter: g.s.clock().Add(5 * time.Minute).Unix()}
}

func (g *solGen) wdFrom(id string, key [32]byte) signjob.Job {
	g.n++
	g.s.newBlockhash() // the nonce account holds a new value after each withdrawal
	amt := 100 + g.n   // a message of its own: the zone signs one message per intent
	in := signjob.Intent{Kind: "withdrawal", RequestedBy: "req", ID: id, Asset: "SOL", PartitionID: solPartSOL, To: sol.Address(g.s.dest), Amount: fmt.Sprint(amt), NotAfter: g.s.clock().Add(time.Hour).Unix()}
	return g.job("j-"+id, in, g.msg(key, true, sol.TransferIx(key, g.s.dest, uint64(amt))), "alice")
}

func (g *solGen) refuse(j signjob.Job, want string) {
	g.k.t.Helper()
	d := g.s.run(j)
	if d.Outcome == OutcomeSigned || !strings.Contains(d.Reason, want) {
		g.k.t.Fatalf("job %s: %s %q, want a refusal containing %q", j.ID, d.Outcome, d.Reason, want)
	}
}

func (g *solGen) sign(j signjob.Job, key *softMsg) {
	g.k.t.Helper()
	d := g.s.run(j)
	if d.Outcome != OutcomeSigned {
		g.k.t.Fatalf("job %s: %s %q, want signed", j.ID, d.Outcome, d.Reason)
	}
	if !ed25519.Verify(key.k.Pub[:], j.Digest, d.Sig) {
		g.k.t.Fatalf("job %s: the signature is not that of the payer's key", j.ID)
	}
}

func TestSolHotRecordsAreChecked(t *testing.T) {
	g := newSolGen(t)
	other := soltest.NewKey()
	bad := func(name string, f func(*KeysetChange), want string) {
		t.Helper()
		c := g.k.ch(solShard, KeysetRegisterCandidate, 2, func(c *KeysetChange) {
			c.Address, c.KeyRef, c.PublicKey = g.hot2.k.Address(), "ref-2", hex.EncodeToString(g.hot2.k.Pub[:])
			f(c)
		})
		if err := g.k.applyKS(g.k.guard, c); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: %v, want an error containing %q", name, err, want)
		}
	}
	bad("a key that is not the address's", func(c *KeysetChange) { c.PublicKey = hex.EncodeToString(other.Pub[:]) }, "not of")
	bad("a key reference without a key", func(c *KeysetChange) { c.PublicKey = "" }, "come together")
	bad("the address of generation 1", func(c *KeysetChange) {
		c.Address, c.PublicKey = g.s.hot.k.Address(), hex.EncodeToString(g.s.hot.k.Pub[:])
	}, "already a generation")
	bad("an address that is nothing", func(c *KeysetChange) { c.Address = "not an address" }, "neither an EVM address nor a Solana address")
	bad("a generation out of order", func(c *KeysetChange) { c.Generation = 3 }, "the next generation")
	// the good one goes in, as base58 in canonical form
	g.candidate2()
	if e := g.entry(2); e == nil || e.State != partition.StateCandidate || e.Address != g.hot2.k.Address() {
		t.Fatalf("generation 2: %+v", e)
	}
}

func TestSolHotStatesDecideWhatIsSigned(t *testing.T) {
	g := newSolGen(t)
	old, new2 := g.s.hot.k.Pub, g.hot2.k.Pub

	// one generation: as before
	g.sign(g.wdFrom("a0", old), g.s.hot)

	g.candidate2()
	// a candidate signs nothing but its own pool; a job that names it is refused whichever way it is built
	g.refuse(g.wdFrom("c1", new2), "candidate")
	setup := signjob.Intent{Kind: sol.KindNonceSetup, ID: "setup-2", PartitionID: solPartSOL, Chain: solChain, Asset: "SOL", To: g.hot2.k.Address(), Amount: fmt.Sprint(uint64(2) * sol.DefaultNonceRent)}
	mk := func(key [32]byte, n int) []byte {
		var ixs []sol.Ix
		for i := 0; i < n; i++ {
			ixs = append(ixs, sol.CreateNonceIxs(key, i, sol.DefaultNonceRent)...)
		}
		return g.msg(key, false, ixs...)
	}
	g.sign(g.job("setup-ok", setup, mk(new2, 2), "alice"), g.hot2)
	g.refuse(g.job("setup-old", setup, mk(new2, 2), "alice"), "") // (same job again is a replay, so only the next lines judge states)
	g.sign(g.wdFrom("a1", old), g.s.hot)                          // generation 1 is untouched by the candidate
	bhA1 := g.s.bh

	// draining generation 1 while 2 is still a candidate: a drain waits (a retry, not a refusal), and nothing else of generation 1 changes yet
	g.startDraining()
	dr := g.drainIntent("d0", "SOL", "1000", new2)
	d := g.s.run(g.job("d0", dr, g.msg(old, false, sol.TransferIx(old, new2, 1000))))
	if d.Outcome == OutcomeSigned {
		t.Fatal("a drain into a candidate was signed")
	}
	g.activate2()

	// generation 2 signs what an active key signs, from its own signer; generation 1 only drains and closes
	g.sign(g.wdFrom("b0", new2), g.hot2)
	g.refuse(g.wdFrom("a2", old), "draining")
	sweep, sm := g.s.sweepIntent("s-old", 1000)
	idx := g.s.depIdx
	g.refuse(g.s.job("sw-old", sweep, sm, solPartSOL, sol.PathHot, &idx), "draining")
	// the drain: to the successor, from the old key
	g.sign(g.job("d1", g.drainIntent("d1", "SOL", "1000", new2), g.msg(old, false, sol.TransferIx(old, new2, 1000))), g.s.hot)
	g.sign(g.job("d2", g.drainIntent("d2", "SOL", "1447680", new2), g.msg(old, false, sol.WithdrawNonceIx(sol.NonceAddress(old, 1), new2, old, 1_447_680))), g.s.hot)
	// ... never to anyone else, and never from the new key
	stranger := soltest.NewKey().Pub
	g.refuse(g.job("d3", g.drainIntent("d3", "SOL", "1000", stranger), g.msg(old, false, sol.TransferIx(old, stranger, 1000))), "not the successor")
	g.refuse(g.job("d4", g.drainIntent("d4", "SOL", "1000", old), g.msg(new2, false, sol.TransferIx(new2, old, 1000))), "")
	// the cap of the signed record: 1000 + 1447680 are counted, 5,000,000,000 is the most
	g.refuse(g.job("d5", g.drainIntent("d5", "SOL", "5000000000", new2), g.msg(old, false, sol.TransferIx(old, new2, 5_000_000_000))), "cap")
	// tokens: transfer and close to the successor, within the token's own cap
	src, dst := mustATA(old, g.s.mint), mustATA(new2, g.s.mint)
	tk := g.msg(old, false, sol.CreateATAIx(old, dst, new2, g.s.mint), sol.CheckedTransferIx(src, g.s.mint, dst, old, 400_000, 6), sol.CloseAccountIx(src, new2, old))
	g.sign(g.job("d6", g.drainIntent("d6", "TKN", "400000", new2), tk), g.s.hot)
	tkBig := g.msg(old, false, sol.CheckedTransferIx(src, g.s.mint, dst, old, 700_000, 6))
	g.refuse(g.job("d7", g.drainIntent("d7", "TKN", "700000", new2), tkBig), "cap")
	// the close of an empty token account, no amount
	g.sign(g.job("d8", g.drainIntent("d8", "TKN", "0", new2), g.msg(old, false, sol.CloseAccountIx(src, new2, old))), g.s.hot)
	// the old pool's accounts close to the old key itself while it drains (the kind with an approval), and the cancel of work it signed
	cl := signjob.Intent{Kind: sol.KindNonceClose, ID: "close-1", PartitionID: solPartSOL, Chain: solChain, Asset: "SOL", To: g.s.hot.k.Address(), Amount: "1447680"}
	g.sign(g.job("nc1", cl, g.msg(old, false, sol.WithdrawNonceIx(sol.NonceAddress(old, 2), old, old, 1_447_680)), "alice"), g.s.hot)
	g.s.bh = bhA1
	can, cm := g.s.cancelAt("cx", 1000, 0)
	g.sign(g.s.job("cx1", can, cm, solPartSOL, sol.PathHot, nil), g.s.hot)
	// the drain's own rate limit counts what was signed (d1, d2, d6, d8): the config allows 5 an hour, so one more goes and the next is refused
	g.sign(g.job("r0", g.drainIntent("r0", "SOL", "10", new2), g.msg(old, false, sol.TransferIx(old, new2, 10))), g.s.hot)
	g.refuse(g.job("r1", g.drainIntent("r1", "SOL", "10", new2), g.msg(old, false, sol.TransferIx(old, new2, 10))), "drains in the last hour")

	// retired: nothing
	g.k.step(solShard, KeysetRetire, 1, nil)
	g.refuse(g.job("d9", g.drainIntent("d9", "SOL", "1", new2), g.msg(old, false, sol.TransferIx(old, new2, 1))), "retired")
	g.refuse(g.wdFrom("a3", old), "retired")
	g.sign(g.wdFrom("b1", new2), g.hot2)
}

// A compromised generation signs a drain to its successor and nothing else: no cancel, no nonce close, no replacement.
func TestSolCompromisedGenerationOnlyDrains(t *testing.T) {
	g := newSolGen(t)
	old, new2 := g.s.hot.k.Pub, g.hot2.k.Pub
	g.candidate2()
	g.activate2Compromised(t)
	g.sign(g.job("d1", g.drainIntent("d1", "SOL", "1000", new2), g.msg(old, false, sol.TransferIx(old, new2, 1000))), g.s.hot)
	g.refuse(g.wdFrom("w1", old), "compromised")
	cl := signjob.Intent{Kind: sol.KindNonceClose, ID: "close-1", PartitionID: solPartSOL, Chain: solChain, Asset: "SOL", To: g.s.hot.k.Address(), Amount: "1447680"}
	g.refuse(g.job("nc1", cl, g.msg(old, false, sol.WithdrawNonceIx(sol.NonceAddress(old, 2), old, old, 1_447_680)), "alice"), "compromised")
	can, cm := g.s.cancelAt("cx", 1000, 0)
	g.refuse(g.s.job("cx1", can, cm, solPartSOL, sol.PathHot, nil), "compromised")
	g.refuse(g.job("d2", g.drainIntent("d2", "SOL", "1000", soltest.NewKey().Pub), g.msg(old, false, sol.TransferIx(old, soltest.NewKey().Pub, 1000))), "")
	if bytes.Equal(old[:], new2[:]) {
		t.Fatal("unreachable")
	}
}

func (g *solGen) activate2Compromised(t *testing.T) {
	t.Helper()
	g.k.step(solShard, KeysetMarkCompromised, 1, func(c *KeysetChange) {
		c.Successor = 2
		c.Caps = map[string]string{"SOL": "5000000000", "TKN": "1000000"}
	})
	g.activate2()
}

func mustATA(owner, mint [32]byte) [32]byte {
	a, err := sol.ATA(owner, mint)
	if err != nil {
		panic(err)
	}
	return a
}

var _ = json.Marshal
