package sol

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// ---- a small legacy message compiler for the tests ----

type tmeta struct {
	k        [32]byte
	signer   bool
	writable bool
}
type tix struct {
	prog  [32]byte
	accts []tmeta
	data  []byte
}

func cu16(n int) []byte {
	var out []byte
	for {
		b := byte(n & 0x7f)
		n >>= 7
		if n == 0 {
			return append(out, b)
		}
		out = append(out, b|0x80)
	}
}

// compile builds a legacy message with payer first, then signers, then writable, then read-only accounts.
func compile(payer [32]byte, bh [32]byte, ixs ...tix) []byte {
	type a struct {
		k    [32]byte
		s, w bool
	}
	var order []*a
	idx := map[[32]byte]*a{}
	add := func(m tmeta) {
		if x, ok := idx[m.k]; ok {
			x.s, x.w = x.s || m.signer, x.w || m.writable
			return
		}
		x := &a{m.k, m.signer, m.writable}
		idx[m.k] = x
		order = append(order, x)
	}
	add(tmeta{payer, true, true})
	for _, in := range ixs {
		for _, m := range in.accts {
			add(m)
		}
		add(tmeta{in.prog, false, false})
	}
	rank := func(x *a) int {
		switch {
		case x.k == payer:
			return -1
		case x.s && x.w:
			return 0
		case x.s:
			return 1
		case x.w:
			return 2
		}
		return 3
	}
	for i := 1; i < len(order); i++ { // stable insertion sort
		for j := i; j > 0 && rank(order[j]) < rank(order[j-1]); j-- {
			order[j], order[j-1] = order[j-1], order[j]
		}
	}
	pos := map[[32]byte]int{}
	ns, nro, nrou := 0, 0, 0
	for i, x := range order {
		pos[x.k] = i
		if x.s {
			ns++
			if !x.w {
				nro++
			}
		} else if !x.w {
			nrou++
		}
	}
	m := []byte{byte(ns), byte(nro), byte(nrou)}
	m = append(m, cu16(len(order))...)
	for _, x := range order {
		m = append(m, x.k[:]...)
	}
	m = append(m, bh[:]...)
	m = append(m, cu16(len(ixs))...)
	for _, in := range ixs {
		m = append(m, byte(pos[in.prog]))
		m = append(m, cu16(len(in.accts))...)
		for _, ac := range in.accts {
			m = append(m, byte(pos[ac.k]))
		}
		m = append(m, cu16(len(in.data))...)
		m = append(m, in.data...)
	}
	return m
}

func le32(n uint32) []byte { return binary.LittleEndian.AppendUint32(nil, n) }
func le64(n uint64) []byte { return binary.LittleEndian.AppendUint64(nil, n) }

// ---- fixtures ----

type fx struct {
	t                      *testing.T
	v                      *Verifier
	cfg                    SigningConfig
	hot, dest, mint, other [32]byte
	node                   Node
	partSOL, partTKN       string
	cb, sys, tokp, atap    [32]byte
	depAddr                [32]byte
	depIdx                 uint32
	bh                     [32]byte
}

func pub(t *testing.T) [32]byte {
	p, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var out [32]byte
	copy(out[:], p)
	return out
}

func newFx(t *testing.T) *fx {
	f := &fx{t: t, hot: pub(t), dest: pub(t), mint: pub(t), other: pub(t), depIdx: 7}
	f.node = Node{PublicKey: pub(t)}
	copy(f.node.ChainCode[:], []byte("a chain code of 32 bytes for tst"))
	f.partSOL, f.partTKN = "qv-us/sol-1/SOL/hot/omnibus/0", "qv-us/sol-1/TKN/hot/omnibus/0"
	f.cb, _ = ParseAddress(ComputeBudgetProgram)
	f.sys, _ = ParseAddress(SystemProgram)
	f.tokp, _ = ParseAddress(TokenProgram)
	f.atap, _ = ParseAddress(AssociatedTokenProg)
	f.cfg = SigningConfig{Chain: "sol-1", AccountPublicKey: f.node.PublicKey, AccountChainCode: f.node.ChainCode,
		HotShards:       map[string]string{f.partSOL: Address(f.hot), f.partTKN: Address(f.hot)},
		Tokens:          map[string]Token{"TKN": {Mint: Address(f.mint), Decimals: 6}},
		MaxComputeUnits: 200_000, MaxMicroLamportsPerUnit: 100_000, MaxPriorityFeeLamports: 15_000}
	var err error
	if f.v, err = NewVerifier(f.cfg); err != nil {
		t.Fatal(err)
	}
	dk, err := f.v.DepositKey(f.depIdx)
	if err != nil {
		t.Fatal(err)
	}
	f.depAddr = dk
	f.bh = pub(t)
	return f
}

func (f *fx) cbLimit(n uint32) tix {
	return tix{prog: f.cb, data: append([]byte{2}, le32(n)...)}
}
func (f *fx) cbPrice(n uint64) tix { return tix{prog: f.cb, data: append([]byte{3}, le64(n)...)} }
func (f *fx) sysTransfer(from, to [32]byte, n uint64) tix {
	return tix{prog: f.sys, accts: []tmeta{{from, true, true}, {to, false, true}}, data: append(le32(2), le64(n)...)}
}
func (f *fx) ata(owner [32]byte) [32]byte { a, _ := ATA(owner, f.mint); return a }
func (f *fx) checked(src, dst, auth [32]byte, n uint64, dec byte, mint [32]byte) tix {
	return tix{prog: f.tokp, accts: []tmeta{{src, false, true}, {mint, false, false}, {dst, false, true}, {auth, true, false}}, data: append(append([]byte{12}, le64(n)...), dec)}
}
func (f *fx) create(payer, ata, owner, mint [32]byte) tix {
	return tix{prog: f.atap, accts: []tmeta{{payer, true, true}, {ata, false, true}, {owner, false, false}, {mint, false, false}, {f.sys, false, false}, {f.tokp, false, false}}, data: []byte{1}}
}
func (f *fx) closeAcct(acct, to, owner [32]byte) tix {
	return tix{prog: f.tokp, accts: []tmeta{{acct, false, true}, {to, false, true}, {owner, true, false}}, data: []byte{9}}
}

func (f *fx) job(msg []byte, part, keyPath string, dep *uint32) chain.UnsignedTx {
	p, _ := json.Marshal(Payload{Message: msg, DepositIndex: dep})
	return chain.UnsignedTx{Chain: "sol-1", Digest: msg, Payload: p, KeyRef: chain.KeyRef{PartitionID: part, Path: keyPath}}
}

func (f *fx) wIntent(asset, part string, amount string) signjob.Intent {
	return signjob.Intent{Kind: "withdrawal", ID: "w1", PartitionID: part, Chain: "sol-1", Asset: asset, To: Address(f.dest), Amount: amount}
}

func (f *fx) sIntent(asset, part, amount string) signjob.Intent {
	return signjob.Intent{Kind: "sweep", ID: "s1", PartitionID: part, Chain: "sol-1", Asset: asset, From: Address(f.depAddr), To: Address(f.hot), Amount: amount}
}

func (f *fx) mustPass(name string, u chain.UnsignedTx, in signjob.Intent) {
	f.t.Helper()
	if err := f.v.Verify(u, in); err != nil {
		f.t.Fatalf("%s: %v", name, err)
	}
}

func (f *fx) mustFail(name string, u chain.UnsignedTx, in signjob.Intent, why string) {
	f.t.Helper()
	err := f.v.Verify(u, in)
	if err == nil {
		f.t.Fatalf("%s: accepted", name)
	}
	if !strings.Contains(err.Error(), why) {
		f.t.Fatalf("%s: refused for %q, want a reason containing %q", name, err.Error(), why)
	}
}

// ---- allowed shapes ----

func TestAllowedShapes(t *testing.T) {
	f := newFx(t)
	idx := f.depIdx
	// SOL withdrawal, with and without a price
	m := compile(f.hot, f.bh, f.cbLimit(10_000), f.cbPrice(1000), f.sysTransfer(f.hot, f.dest, 5_000_000))
	f.mustPass("SOL withdrawal", f.job(m, f.partSOL, PathHot, nil), f.wIntent("SOL", f.partSOL, "5000000"))
	m = compile(f.hot, f.bh, f.cbLimit(10_000), f.sysTransfer(f.hot, f.dest, 5_000_000))
	f.mustPass("SOL withdrawal, no price", f.job(m, f.partSOL, PathHot, nil), f.wIntent("SOL", f.partSOL, "5000000"))

	// token withdrawal, destination account exists / is created
	src, dst := f.ata(f.hot), f.ata(f.dest)
	m = compile(f.hot, f.bh, f.cbLimit(50_000), f.checked(src, dst, f.hot, 777, 6, f.mint))
	f.mustPass("token withdrawal", f.job(m, f.partTKN, PathHot, nil), f.wIntent("TKN", f.partTKN, "777"))
	m = compile(f.hot, f.bh, f.cbLimit(50_000), f.create(f.hot, dst, f.dest, f.mint), f.checked(src, dst, f.hot, 777, 6, f.mint))
	f.mustPass("token withdrawal with create", f.job(m, f.partTKN, PathHot, nil), f.wIntent("TKN", f.partTKN, "777"))

	// SOL sweep: both jobs (fee payer, deposit owner) pass
	m = compile(f.hot, f.bh, f.cbLimit(10_000), f.sysTransfer(f.depAddr, f.hot, 3_000_000))
	f.mustPass("SOL sweep, hot job", f.job(m, f.partSOL, PathHot, &idx), f.sIntent("SOL", f.partSOL, "3000000"))
	f.mustPass("SOL sweep, deposit job", f.job(m, f.partSOL, DepositPath(idx), &idx), f.sIntent("SOL", f.partSOL, "3000000"))

	// token sweeps
	dsrc, hdst := f.ata(f.depAddr), f.ata(f.hot)
	for name, ixs := range map[string][]tix{
		"plain":        {f.checked(dsrc, hdst, f.depAddr, 900, 6, f.mint)},
		"with create":  {f.create(f.hot, hdst, f.hot, f.mint), f.checked(dsrc, hdst, f.depAddr, 900, 6, f.mint)},
		"with close":   {f.checked(dsrc, hdst, f.depAddr, 900, 6, f.mint), f.closeAcct(dsrc, f.hot, f.depAddr)},
		"create+close": {f.create(f.hot, hdst, f.hot, f.mint), f.checked(dsrc, hdst, f.depAddr, 900, 6, f.mint), f.closeAcct(dsrc, f.hot, f.depAddr)},
	} {
		m = compile(f.hot, f.bh, append([]tix{f.cbLimit(60_000)}, ixs...)...)
		f.mustPass("token sweep "+name+", hot job", f.job(m, f.partTKN, PathHot, &idx), f.sIntent("TKN", f.partTKN, "900"))
		f.mustPass("token sweep "+name+", deposit job", f.job(m, f.partTKN, DepositPath(idx), &idx), f.sIntent("TKN", f.partTKN, "900"))
	}

	// Decode: the sender is the fee payer for both jobs of a sweep, the signer key differs
	m = compile(f.hot, f.bh, f.cbLimit(10_000), f.cbPrice(1000), f.sysTransfer(f.depAddr, f.hot, 3_000_000))
	in := f.sIntent("SOL", f.partSOL, "3000000")
	a, err := f.v.Decode(f.job(m, f.partSOL, PathHot, &idx), in)
	if err != nil {
		t.Fatal(err)
	}
	b, err := f.v.Decode(f.job(m, f.partSOL, DepositPath(idx), &idx), in)
	if err != nil {
		t.Fatal(err)
	}
	if a.Sender != Address(f.hot) || b.Sender != a.Sender || string(a.SignerKey) != string(f.hot[:]) || string(b.SignerKey) != string(f.depAddr[:]) {
		t.Fatalf("decode: %+v %+v", a, b)
	}
	if a.Destination != Address(f.hot) || a.Fee.Int64() != 2*5000+10 { // two signatures, and 10,000 units x 1,000 micro-lamports = 10 lamports
		t.Fatalf("destination %q fee %v", a.Destination, a.Fee)
	}
}

// ---- attacks ----

func TestWithdrawalAttacks(t *testing.T) {
	f := newFx(t)
	good := func() []tix { return []tix{f.cbLimit(10_000), f.sysTransfer(f.hot, f.dest, 5_000_000)} }
	in := f.wIntent("SOL", f.partSOL, "5000000")
	pass := func(ixs []tix) chain.UnsignedTx { return f.job(compile(f.hot, f.bh, ixs...), f.partSOL, PathHot, nil) }
	f.mustPass("baseline", pass(good()), in)

	f.mustFail("wrong destination", pass([]tix{f.cbLimit(10_000), f.sysTransfer(f.hot, f.other, 5_000_000)}), in, "not a system transfer")
	f.mustFail("wrong amount", pass([]tix{f.cbLimit(10_000), f.sysTransfer(f.hot, f.dest, 5_000_001)}), in, "not a system transfer")
	f.mustFail("extra instruction", pass(append(good(), f.sysTransfer(f.hot, f.other, 1))), in, "one system transfer")
	f.mustFail("drain to self is not the transfer", pass([]tix{f.cbLimit(10_000), f.sysTransfer(f.other, f.dest, 5_000_000)}), in, "not a system transfer")
	// different fee payer
	f.mustFail("different fee payer", f.job(compile(f.other, f.bh, f.cbLimit(10_000), f.sysTransfer(f.other, f.dest, 5_000_000)), f.partSOL, PathHot, nil), in, "fee payer")
	// extra signer: the destination also signs
	extra := tix{prog: f.sys, accts: []tmeta{{f.hot, true, true}, {f.dest, true, true}}, data: append(le32(2), le64(5_000_000)...)}
	f.mustFail("extra signer", pass([]tix{f.cbLimit(10_000), extra}), in, "required signers")
	// compute budget
	f.mustFail("price above the cap", pass([]tix{f.cbLimit(10_000), f.cbPrice(100_001), f.sysTransfer(f.hot, f.dest, 5_000_000)}), in, "price")
	f.mustFail("limit above the cap", pass([]tix{f.cbLimit(200_001), f.sysTransfer(f.hot, f.dest, 5_000_000)}), in, "limit")
	f.mustFail("priority fee above the cap", pass([]tix{f.cbLimit(200_000), f.cbPrice(100_000), f.sysTransfer(f.hot, f.dest, 5_000_000)}), in, "priority fee")
	f.mustFail("no limit", pass([]tix{f.sysTransfer(f.hot, f.dest, 5_000_000)}), in, "no compute unit limit")
	f.mustFail("limit twice", pass([]tix{f.cbLimit(1), f.cbLimit(2), f.sysTransfer(f.hot, f.dest, 5_000_000)}), in, "twice")
	f.mustFail("heap frame request", pass([]tix{f.cbLimit(10_000), {prog: f.cb, data: append([]byte{1}, le32(65536)...)}, f.sysTransfer(f.hot, f.dest, 5_000_000)}), in, "not allowed")
	// intent mismatch
	in2 := in
	in2.To = Address(f.other)
	f.mustFail("intent names another destination", pass(good()), in2, "not a system transfer")
	in3 := in
	in3.Amount = "4999999"
	f.mustFail("intent names another amount", pass(good()), in3, "not a system transfer")
	in4 := in
	in4.Amount = "05000000"
	f.mustFail("non-canonical amount", pass(good()), in4, "canonical")
	in5 := in
	in5.To = Address(f.hot)
	f.mustFail("withdrawal to the hot shard", pass(good()), in5, "hot shard itself")
	in6 := in
	in6.Kind = "to-cold"
	f.mustFail("another kind", pass(good()), in6, "not signed on this chain")
	// partition / chain
	f.mustFail("unknown partition", f.job(compile(f.hot, f.bh, good()...), "qv-us/sol-1/SOL/hot/omnibus/9", PathHot, nil), func() signjob.Intent { x := in; x.PartitionID = "qv-us/sol-1/SOL/hot/omnibus/9"; return x }(), "no hot shard")
	// the account list carries something no instruction uses
	unused := compile(f.hot, f.bh, f.cbLimit(10_000), f.sysTransfer(f.hot, f.dest, 5_000_000))
	unused = append([]byte(nil), unused...)
	// bump the key count and add a key before the blockhash
	dec, _ := DecodeMessage(unused)
	extraKey := pub(t)
	with := []byte{unused[0], unused[1], unused[2] + 1}
	with = append(with, cu16(len(dec.Keys)+1)...)
	for _, k := range dec.Keys {
		with = append(with, k[:]...)
	}
	with = append(with, extraKey[:]...)
	with = append(with, unused[3+1+32*len(dec.Keys):]...)
	f.mustFail("unused account", f.job(with, f.partSOL, PathHot, nil), in, "used by no instruction")
	// v0 message
	v0 := append([]byte{0x80}, compile(f.hot, f.bh, good()...)...)
	f.mustFail("v0 message", f.job(v0, f.partSOL, PathHot, nil), in, "versioned")
	// digest is not the message
	u := pass(good())
	u.Digest = append([]byte(nil), u.Digest...)
	u.Digest[len(u.Digest)-1] ^= 1
	f.mustFail("digest differs from the message", u, in, "digest")
	// trailing bytes
	f.mustFail("trailing bytes", f.job(append(compile(f.hot, f.bh, good()...), 0), f.partSOL, PathHot, nil), in, "trailing")
	// a duplicate account key
	d := compile(f.hot, f.bh, f.cbLimit(10_000), f.sysTransfer(f.hot, f.dest, 5_000_000))
	dm, _ := DecodeMessage(d)
	dupKeys := []byte{d[0], d[1], d[2] + 1}
	dupKeys = append(dupKeys, cu16(len(dm.Keys)+1)...)
	for _, k := range dm.Keys {
		dupKeys = append(dupKeys, k[:]...)
	}
	dupKeys = append(dupKeys, dm.Keys[len(dm.Keys)-1][:]...)
	dupKeys = append(dupKeys, d[3+1+32*len(dm.Keys):]...)
	f.mustFail("duplicate account", f.job(dupKeys, f.partSOL, PathHot, nil), in, "twice")
	// the key reference of a withdrawal job must be the hot shard
	f.mustFail("deposit key on a withdrawal", f.job(compile(f.hot, f.bh, good()...), f.partSOL, DepositPath(1), nil), in, "not the deposit key")
	f.mustFail("garbage key reference", f.job(compile(f.hot, f.bh, good()...), f.partSOL, "x", nil), in, "neither")
}

func TestTokenWithdrawalAttacks(t *testing.T) {
	f := newFx(t)
	src, dst := f.ata(f.hot), f.ata(f.dest)
	in := f.wIntent("TKN", f.partTKN, "777")
	mk := func(ixs ...tix) chain.UnsignedTx {
		return f.job(compile(f.hot, f.bh, append([]tix{f.cbLimit(50_000)}, ixs...)...), f.partTKN, PathHot, nil)
	}
	f.mustPass("baseline", mk(f.checked(src, dst, f.hot, 777, 6, f.mint)), in)
	f.mustFail("wrong mint", mk(f.checked(src, dst, f.hot, 777, 6, f.other)), in, "transferChecked")
	f.mustFail("wrong decimals", mk(f.checked(src, dst, f.hot, 777, 9, f.mint)), in, "decimals")
	f.mustFail("wrong amount", mk(f.checked(src, dst, f.hot, 778, 6, f.mint)), in, "transferChecked")
	f.mustFail("wrong destination account", mk(f.checked(src, f.ata(f.other), f.hot, 777, 6, f.mint)), in, "transferChecked")
	f.mustFail("destination is a plain account, not the ATA", mk(f.checked(src, f.dest, f.hot, 777, 6, f.mint)), in, "transferChecked")
	f.mustFail("source is not the hot ATA", mk(f.checked(f.ata(f.other), dst, f.hot, 777, 6, f.mint)), in, "transferChecked")
	f.mustFail("another authority", mk(f.checked(src, dst, f.other, 777, 6, f.mint)), in, "transferChecked")
	// plain transfer (no mint check) instead of transferChecked
	plain := tix{prog: f.tokp, accts: []tmeta{{src, false, true}, {dst, false, true}, {f.hot, true, false}}, data: append([]byte{3}, le64(777)...)}
	f.mustFail("unchecked transfer", mk(plain), in, "transferChecked")
	// the dangerous token instructions next to the transfer
	approve := tix{prog: f.tokp, accts: []tmeta{{src, false, true}, {f.other, false, false}, {f.hot, true, false}}, data: append([]byte{4}, le64(1<<62)...)}
	f.mustFail("approve on the hot ATA", mk(f.checked(src, dst, f.hot, 777, 6, f.mint), approve), in, "associated token account")
	setAuth := tix{prog: f.tokp, accts: []tmeta{{src, false, true}, {f.hot, true, false}}, data: append([]byte{6, 2, 1}, f.other[:]...)}
	f.mustFail("setAuthority on the hot ATA", mk(f.checked(src, dst, f.hot, 777, 6, f.mint), setAuth), in, "associated token account")
	f.mustFail("closeAccount of the hot ATA", mk(f.checked(src, dst, f.hot, 777, 6, f.mint), f.closeAcct(src, f.other, f.hot)), in, "associated token account")
	// create instruction variants
	f.mustFail("create paid by someone else", mk(f.create(f.other, dst, f.dest, f.mint), f.checked(src, dst, f.hot, 777, 6, f.mint)), in, "create")
	f.mustFail("create for another owner", mk(f.create(f.hot, dst, f.other, f.mint), f.checked(src, dst, f.hot, 777, 6, f.mint)), in, "create")
	nonIdem := f.create(f.hot, dst, f.dest, f.mint)
	nonIdem.data = []byte{0}
	f.mustFail("non-idempotent create", mk(nonIdem, f.checked(src, dst, f.hot, 777, 6, f.mint)), in, "create")
	// the same account in two roles: the destination account is also the source
	f.mustFail("source = destination", mk(f.checked(src, src, f.hot, 777, 6, f.mint)), in, "transferChecked")
	f.mustFail("SOL instruction for a token intent", f.job(compile(f.hot, f.bh, f.cbLimit(50_000), f.sysTransfer(f.hot, f.dest, 777)), f.partTKN, PathHot, nil), in, "transferChecked")
	f.mustFail("token asset on the SOL partition", f.job(compile(f.hot, f.bh, f.cbLimit(50_000), f.checked(src, dst, f.hot, 777, 6, f.mint)), f.partSOL, PathHot, nil), in, "intent partition")
}

func TestSweepAttacks(t *testing.T) {
	f := newFx(t)
	idx := f.depIdx
	in := f.sIntent("SOL", f.partSOL, "3000000")
	good := compile(f.hot, f.bh, f.cbLimit(10_000), f.sysTransfer(f.depAddr, f.hot, 3_000_000))
	f.mustPass("baseline hot", f.job(good, f.partSOL, PathHot, &idx), in)
	// a sweep that pays someone else
	f.mustFail("sweep to another address", f.job(compile(f.hot, f.bh, f.cbLimit(10_000), f.sysTransfer(f.depAddr, f.other, 3_000_000)), f.partSOL, PathHot, &idx), in, "not a system transfer")
	// a different amount (drains more than the intent says)
	f.mustFail("sweep of more than the intent", f.job(compile(f.hot, f.bh, f.cbLimit(10_000), f.sysTransfer(f.depAddr, f.hot, 3_000_001)), f.partSOL, PathHot, &idx), in, "not a system transfer")
	// a second transfer out of the deposit address
	f.mustFail("second transfer", f.job(compile(f.hot, f.bh, f.cbLimit(10_000), f.sysTransfer(f.depAddr, f.hot, 3_000_000), f.sysTransfer(f.depAddr, f.other, 1)), f.partSOL, PathHot, &idx), in, "one system transfer")
	// the deposit address is not the one at the claimed index
	bad := uint32(8)
	f.mustFail("deposit index not matching the source", f.job(good, f.partSOL, PathHot, &bad), in, "source")
	f.mustFail("no deposit index", f.job(good, f.partSOL, PathHot, nil), in, "deposit index")
	// the deposit address pays the fee
	f.mustFail("deposit address as fee payer", f.job(compile(f.depAddr, f.bh, f.cbLimit(10_000), f.sysTransfer(f.depAddr, f.hot, 3_000_000)), f.partSOL, PathHot, &idx), in, "fee payer")
	// signer set: the message must have exactly the hot shard and the deposit address
	f.mustFail("deposit job with another index", f.job(good, f.partSOL, DepositPath(9), &idx), in, "not the deposit key")
	// sweep intents: to must be the hot shard
	in2 := in
	in2.To = Address(f.other)
	f.mustFail("intent pays another address", f.job(good, f.partSOL, PathHot, &idx), in2, "pays the hot shard")
	in3 := in
	in3.From = Address(f.other)
	f.mustFail("intent source is not the deposit address", f.job(good, f.partSOL, PathHot, &idx), in3, "source")

	// token sweeps
	tin := f.sIntent("TKN", f.partTKN, "900")
	dsrc, hdst := f.ata(f.depAddr), f.ata(f.hot)
	mk := func(ixs ...tix) chain.UnsignedTx {
		return f.job(compile(f.hot, f.bh, append([]tix{f.cbLimit(60_000)}, ixs...)...), f.partTKN, PathHot, &idx)
	}
	f.mustFail("closeAccount rent to someone else", mk(f.checked(dsrc, hdst, f.depAddr, 900, 6, f.mint), f.closeAcct(dsrc, f.other, f.depAddr)), tin, "closeAccount")
	f.mustFail("closeAccount of another account", mk(f.checked(dsrc, hdst, f.depAddr, 900, 6, f.mint), f.closeAcct(hdst, f.hot, f.depAddr)), tin, "closeAccount")
	f.mustFail("close before the transfer", mk(f.closeAcct(dsrc, f.hot, f.depAddr), f.checked(dsrc, hdst, f.depAddr, 900, 6, f.mint)), tin, "closeAccount")
	f.mustFail("sweep to another token account", mk(f.checked(dsrc, f.ata(f.other), f.depAddr, 900, 6, f.mint)), tin, "transferChecked")
	f.mustFail("wrong mint", mk(f.checked(dsrc, hdst, f.depAddr, 900, 6, f.other)), tin, "transferChecked")
	f.mustFail("wrong decimals", mk(f.checked(dsrc, hdst, f.depAddr, 900, 7, f.mint)), tin, "decimals")
	f.mustFail("create for the deposit address instead", mk(f.create(f.hot, dsrc, f.depAddr, f.mint), f.checked(dsrc, hdst, f.depAddr, 900, 6, f.mint)), tin, "create")
	approve := tix{prog: f.tokp, accts: []tmeta{{dsrc, false, true}, {f.other, false, false}, {f.depAddr, true, false}}, data: append([]byte{4}, le64(5)...)}
	f.mustFail("approve on the deposit ATA", mk(f.checked(dsrc, hdst, f.depAddr, 900, 6, f.mint), approve), tin, "closeAccount")
	f.mustFail("SOL instruction in a token sweep", mk(f.sysTransfer(f.depAddr, f.hot, 900)), tin, "transferChecked")
}

// The decoder on its own: nothing it accepts can have an index out of range or trailing bytes.
func TestDecodeMessageRefusals(t *testing.T) {
	f := newFx(t)
	ok := compile(f.hot, f.bh, f.cbLimit(1), f.sysTransfer(f.hot, f.dest, 1))
	if _, err := DecodeMessage(ok); err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{
		"empty":     nil,
		"header":    {1, 0},
		"too long":  make([]byte, MaxMessage+1),
		"truncated": ok[:len(ok)-3],
		"v0":        append([]byte{0x80}, ok...),
	} {
		if _, err := DecodeMessage(b); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
	// every truncation of a good message is refused
	for n := 0; n < len(ok); n++ {
		if _, err := DecodeMessage(ok[:n]); err == nil {
			t.Fatalf("a message cut to %d bytes decoded", n)
		}
	}
	// a program index out of range
	bad := append([]byte(nil), ok...)
	dm, _ := DecodeMessage(ok)
	pos := 3 + 1 + 32*len(dm.Keys) + 32 + 1
	bad[pos] = 60
	if _, err := DecodeMessage(bad); err == nil {
		t.Fatal("a program index out of range decoded")
	}
}

func TestKeyPaths(t *testing.T) {
	for in, want := range map[string]bool{"": true, "d/0": true, "d/12": true, "d/01": false, "d/-1": false, "d/2147483648": false, "e/1": false, "d/": false, "hot": false} {
		_, _, err := ParseKeyPath(in)
		if (err == nil) != want {
			t.Errorf("%q: ok=%v want %v", in, err == nil, want)
		}
	}
	if DepositPath(5) != "d/5" {
		t.Fatal(DepositPath(5))
	}
}

func TestVerifierConfigRefusals(t *testing.T) {
	f := newFx(t)
	for name, mod := range map[string]func(*SigningConfig){
		"no caps":             func(c *SigningConfig) { c.MaxComputeUnits = 0 },
		"no hot shards":       func(c *SigningConfig) { c.HotShards = nil },
		"hot shard off curve": func(c *SigningConfig) { c.HotShards = map[string]string{f.partSOL: "11111111111111111111111111111112"} }, // a made-up address, not a secret; ggignore
		"hot partition of another chain": func(c *SigningConfig) {
			c.HotShards = map[string]string{"qv-us/other/SOL/hot/omnibus/0": Address(f.hot)}
		},
		"hot partition of an unknown asset": func(c *SigningConfig) {
			c.HotShards = map[string]string{"qv-us/sol-1/XYZ/hot/omnibus/0": Address(f.hot)}
		},
		"cold partition": func(c *SigningConfig) {
			c.HotShards = map[string]string{"qv-us/sol-1/SOL/cold/omnibus/0": Address(f.hot)}
		},
		"bad token mint": func(c *SigningConfig) { c.Tokens = map[string]Token{"TKN": {Mint: "x", Decimals: 6}} },
	} {
		c := f.cfg
		mod(&c)
		if _, err := NewVerifier(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
