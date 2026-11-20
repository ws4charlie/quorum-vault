package sol

import (
	"testing"

	"github.com/ws4charlie/quorum-vault/internal/partition"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// withGen is the fixture's verifier with a second generation of shard 0 (new) next to the configured one (fx.hot), as the gateway builds it from its records.
func (f *fx) withGen(newKey [32]byte, active2 bool) {
	f.t.Helper()
	s0, _ := partition.NewShardID("qv-us", "sol-1", "omnibus", 0)
	s1, _ := partition.NewShardID("qv-us", "sol-1", "omnibus", 1)
	v, err := f.v.WithHotGenerations([]HotGeneration{
		{Shard: s0, Gen: 1, Address: Address(f.hot), Active: !active2},
		{Shard: s0, Gen: 2, Address: Address(newKey), Active: active2},
		{Shard: s1, Gen: 1, Address: Address(f.hot2), Active: true},
	})
	if err != nil {
		f.t.Fatal(err)
	}
	f.v = v
}

// The fee payer of a job may be any generation of the partition's shard, with its own nonce pool; nothing else.
func TestHotGenerationsMayPayAndOwnAPool(t *testing.T) {
	f := newFx(t)
	newKey := pub(t)
	f.withGen(newKey, true)
	wd := func(payer [32]byte, nonceOwner [32]byte) []byte {
		return compile(payer, f.nv, f.advOn(NonceAddress(nonceOwner, 0), payer), f.cbLimit(100_000), f.sysTransfer(payer, f.dest, 5))
	}
	in := f.wIntent("SOL", f.partSOL, "5")
	f.mustPass("the configured generation", f.job(wd(f.hot, f.hot), f.partSOL, PathHot, nil), in)
	f.mustPass("the new generation on its own pool", f.job(wd(newKey, newKey), f.partSOL, PathHot, nil), in)
	f.mustFail("the new generation on the old pool", f.job(wd(newKey, f.hot), f.partSOL, PathHot, nil), in, "not in the pool")
	f.mustFail("the old generation on the new pool", f.job(wd(f.hot, newKey), f.partSOL, PathHot, nil), in, "not in the pool")
	f.mustFail("a key of no generation", f.job(wd(f.other, f.other), f.partSOL, PathHot, nil), in, "not in the pool")
	f.mustFail("another shard's key", f.job(wd(f.hot2, f.hot2), f.partSOL, PathHot, nil), in, "not in the pool")
	if !f.v.OwnsSender(Address(newKey)) || !f.v.OwnsSender(Address(f.hot)) {
		t.Fatal("every generation is a hot address of the zone")
	}
}

// A rebalance pays an ACTIVE generation of another shard, never a retired or draining one.
func TestRebalanceDestinationIsAnActiveGeneration(t *testing.T) {
	f := newFx(t)
	newKey := pub(t)
	f.withGen(newKey, true) // shard 0: generation 1 draining, generation 2 active
	// a rebalance from shard 1 to shard 0's generations
	adv := f.advOn(NonceAddress(f.hot2, 0), f.hot2)
	msg := func(to [32]byte) []byte {
		return compile(f.hot2, f.nv, adv, f.cbLimit(100_000), f.sysTransfer(f.hot2, to, 9))
	}
	in := signjob.Intent{Kind: "rebalance", ID: "r1", PartitionID: f.partSOL2, Chain: "sol-1", Asset: "SOL", To: Address(newKey), Amount: "9"}
	f.mustPass("to the active generation", f.job(msg(newKey), f.partSOL2, PathHot, nil), in)
	in.To = Address(f.hot)
	f.mustFail("to the draining generation", f.job(msg(f.hot), f.partSOL2, PathHot, nil), in, "another hot shard")
}

func (f *fx) drainJob(payer [32]byte, part string, ixs ...tix) []byte {
	return compile(payer, f.bh, append([]tix{f.cbLimit(100_000)}, ixs...)...)
}

func TestDrainShapes(t *testing.T) {
	f := newFx(t)
	succ := pub(t)
	f.withGen(succ, true)
	old := f.hot
	bh, _ := ParseAddress(SysvarRecentBlockhashes)
	rent, _ := ParseAddress(SysvarRent)
	wnd := func(nonce, dest, auth [32]byte, lamports uint64) tix {
		return tix{prog: f.sys, accts: []tmeta{{nonce, false, true}, {dest, false, true}, {bh, false, false}, {rent, false, false}, {auth, true, false}}, data: append(le32(5), le64(lamports)...)}
	}
	drain := func(asset, part, amount string) signjob.Intent {
		return signjob.Intent{Kind: signjob.KindDrain, ID: "dr-1", PartitionID: part, Chain: "sol-1", Asset: asset, From: Address(old), To: Address(succ), Amount: amount}
	}
	job := func(part string, ixs ...tix) []byte { return f.drainJob(old, part, ixs...) }
	pass := func(name, part string, m []byte, in signjob.Intent) {
		f.mustPass(name, f.job(m, part, PathHot, nil), in)
	}
	fail := func(name, part string, m []byte, in signjob.Intent, why string) {
		f.mustFail(name, f.job(m, part, PathHot, nil), in, why)
	}
	sol := drain("SOL", f.partSOL, "1000")

	// SOL
	pass("a transfer to the successor", f.partSOL, job(f.partSOL, f.sysTransfer(old, succ, 1000)), sol)
	pass("a pool account withdrawn to the successor", f.partSOL, job(f.partSOL, wnd(NonceAddress(old, 1), succ, old, 1000)), sol)
	fail("a transfer to a stranger", f.partSOL, job(f.partSOL, f.sysTransfer(old, f.other, 1000)), sol, "neither a system transfer")
	fail("another amount", f.partSOL, job(f.partSOL, f.sysTransfer(old, succ, 1001)), sol, "neither a system transfer")
	fail("a nonce account that is not in the pool", f.partSOL, job(f.partSOL, wnd(f.other, succ, old, 1000)), sol, "not in the pool")
	fail("a nonce account of the successor's pool", f.partSOL, job(f.partSOL, wnd(NonceAddress(succ, 0), succ, old, 1000)), sol, "not in the pool")
	fail("a nonce account withdrawn to a stranger", f.partSOL, job(f.partSOL, wnd(NonceAddress(old, 1), f.other, old, 1000)), sol, "pays "+Address(succ))
	fail("a nonce account withdrawn to the old key itself", f.partSOL, job(f.partSOL, wnd(NonceAddress(old, 1), old, old, 1000)), sol, "pays "+Address(succ))
	fail("two instructions", f.partSOL, job(f.partSOL, f.sysTransfer(old, succ, 500), f.sysTransfer(old, succ, 500)), sol, "one transfer or one nonce account withdrawal")
	fail("a nonce advance first (a drain signs no nonce)", f.partSOL, compile(old, f.nv, f.advOn(NonceAddress(old, 0), old), f.cbLimit(100_000), f.sysTransfer(old, succ, 1000)), sol, "")
	fail("a transfer from another account", f.partSOL, job(f.partSOL, f.sysTransfer(f.other, succ, 1000)), sol, "neither a system transfer")
	self := sol
	self.To = Address(old)
	fail("a drain to the old key itself", f.partSOL, job(f.partSOL, f.sysTransfer(old, old, 1000)), self, "another address")

	// tokens
	tkn := drain("TKN", f.partTKN, "700")
	srcATA, dstATA := f.ata(old), f.ata(succ)
	tr := f.checked(srcATA, dstATA, old, 700, 6, f.mint)
	pass("a token transfer", f.partTKN, job(f.partTKN, tr), tkn)
	pass("create the successor's account, transfer", f.partTKN, job(f.partTKN, f.create(old, dstATA, succ, f.mint), tr), tkn)
	pass("transfer and close, rent to the successor", f.partTKN, job(f.partTKN, f.create(old, dstATA, succ, f.mint), tr, f.closeAcct(srcATA, succ, old)), tkn)
	empty := drain("TKN", f.partTKN, "0")
	pass("the close of an empty account", f.partTKN, job(f.partTKN, f.closeAcct(srcATA, succ, old)), empty)
	fail("the close with the rent to a stranger", f.partTKN, job(f.partTKN, f.closeAcct(srcATA, f.other, old)), empty, "closeAccount")
	fail("the close with the rent to the old key", f.partTKN, job(f.partTKN, f.closeAcct(srcATA, old, old)), empty, "closeAccount")
	fail("an amount 0 that also transfers", f.partTKN, job(f.partTKN, f.checked(srcATA, dstATA, old, 1, 6, f.mint)), empty, "closeAccount")
	fail("a transfer to a stranger's account", f.partTKN, job(f.partTKN, f.checked(srcATA, f.ata(f.other), old, 700, 6, f.mint)), tkn, "transferChecked")
	fail("another amount", f.partTKN, job(f.partTKN, f.checked(srcATA, dstATA, old, 701, 6, f.mint)), tkn, "transferChecked")
	fail("another mint", f.partTKN, job(f.partTKN, f.checked(srcATA, dstATA, old, 700, 6, f.other)), tkn, "transferChecked")
	fail("a close of a deposit address's account", f.partTKN, job(f.partTKN, tr, f.closeAcct(f.ata(f.depAddr), succ, old)), tkn, "closeAccount")
	fail("a create for a stranger", f.partTKN, job(f.partTKN, f.create(old, f.ata(f.other), f.other, f.mint), tr), tkn, "idempotent create")
	fail("two closes", f.partTKN, job(f.partTKN, tr, f.closeAcct(srcATA, succ, old), f.closeAcct(srcATA, succ, old)), tkn, "may only close")
	fail("a SOL transfer alongside", f.partTKN, job(f.partTKN, tr, f.sysTransfer(old, succ, 1)), tkn, "closeAccount")

	// the signer is the hot shard of a generation of the partition's shard: nobody else pays
	fail("a stranger as the fee payer", f.partSOL, f.drainJob(f.other, f.partSOL, f.sysTransfer(f.other, succ, 1000)), sol, "not the hot shard")
	// an unknown kind is still refused
	bad := sol
	bad.Kind = "dreyn"
	fail("an unknown kind", f.partSOL, job(f.partSOL, f.sysTransfer(old, succ, 1000)), bad, "not signed on this chain")
}

// The funding of a new key's pool includes the priority fee the configured price makes of the setup's compute limit.
func TestNonceSetupFeeFollowsThePrice(t *testing.T) {
	for _, c := range []struct {
		price uint64
		n     int
		want  uint64
	}{{0, 3, 5000}, {1000, 3, 5000 + 35}, {100_000, 3, 5000 + 3_500}, {1_000_000_000, 3, 5000 + 35_000_000}} {
		a := &Adapter{cfg: &validatedConfig{Config: Config{ComputeUnitPrice: c.price}}}
		if got := a.NonceSetupFee(c.n); got != c.want {
			t.Errorf("price %d, %d accounts: %d, want %d", c.price, c.n, got, c.want)
		}
	}
}
