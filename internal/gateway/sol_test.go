package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/chain/sol"
	"github.com/ws4charlie/quorum-vault/internal/chain/sol/soltest"
	"github.com/ws4charlie/quorum-vault/internal/domain"
	"github.com/ws4charlie/quorum-vault/internal/signer"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

const (
	solChain   = "sol-test"
	solPartSOL = "qv-us/sol-test/SOL/hot/omnibus/0"
	solPartTKN = "qv-us/sol-test/TKN/hot/omnibus/0"
)

// softMsg is a Solana key held in software, standing in for the 2-of-3 hot signer; calls counts signatures made.
type softMsg struct {
	k     soltest.Key
	calls atomic.Int32
}

func (s *softMsg) Backend() domain.Backend { return domain.BackendMPC }
func (s *softMsg) PublicKey() []byte       { return append([]byte(nil), s.k.Pub[:]...) }
func (s *softMsg) SignMessage(_ context.Context, msg []byte, _ signer.SignOptions) (signer.MessageResult, error) {
	s.calls.Add(1)
	return signer.MessageResult{Signature: s.k.Sign(msg)}, nil
}

// softDeposit derives private deposit keys below a private account node, standing in for the 2-party HD signer.
type softDeposit struct {
	node  soltest.Node
	calls atomic.Int32
}

func (d *softDeposit) Backend() domain.Backend { return domain.BackendMPC }
func (d *softDeposit) PublicKey() []byte       { return nil }
func (d *softDeposit) SignMessage(context.Context, []byte, signer.SignOptions) (signer.MessageResult, error) {
	return signer.MessageResult{}, fmt.Errorf("a key tree signs through At")
}
func (d *softDeposit) At(_ context.Context, path []uint32) (signer.MessageSigner, error) {
	return &softMsg{k: d.node.At(path...).Key, calls: atomic.Int32{}}, nil
}

type solH struct {
	*harness
	gw                         *Gateway
	hot                        *softMsg
	dep                        *softDeposit
	acct                       soltest.Node
	dest, other, mint, depAddr [32]byte
	depIdx                     uint32
	bh                         [32]byte
	seq                        int
	cb, sys, tokp, atap        [32]byte
}

func raw32(a string) [32]byte { r, _ := sol.ParseAddress(a); return r }

func newSOLHarness(t *testing.T, tweak func(*ChainFile)) *solH {
	t.Helper()
	h := newHarness(t)
	ctx := context.Background()
	s := &solH{harness: h, hot: &softMsg{k: soltest.NewKey()}, acct: soltest.NewNode(), depIdx: 4}
	s.dep = &softDeposit{node: s.acct}
	s.dest, s.other, s.mint, s.bh = soltest.NewKey().Pub, soltest.NewKey().Pub, soltest.NewKey().Pub, soltest.NewKey().Pub
	s.cb, s.sys, s.tokp, s.atap = raw32(sol.ComputeBudgetProgram), raw32(sol.SystemProgram), raw32(sol.TokenProgram), raw32(sol.AssociatedTokenProg)
	dk, _ := s.acct.Public().Derive(sol.BranchExternal, s.depIdx)
	s.depAddr = dk.PublicKey

	pol := func(per, daily string) AssetFile {
		return AssetFile{AnyDestination: true, PerTxCap: per, DailyCap: daily, Tiers: []TierFile{{"0", 1}, {"50000000000", 2}}}
	}
	cf := ChainFile{Family: "sol", WithdrawalsPerHour: 1000, SweepsPerHour: 1000, CancelsPerHour: 1000,
		SOL: &SOLFile{AccountPublicKey: hex.EncodeToString(s.acct.Pub[:]), AccountChainCode: hex.EncodeToString(s.acct.ChainCode[:]),
			HotShards:       map[string]string{solPartSOL: s.hot.k.Address(), solPartTKN: s.hot.k.Address()},
			Tokens:          map[string]SOLTokenFile{"TKN": {Mint: sol.Address(s.mint), Decimals: 6}},
			MaxComputeUnits: 200_000, MaxMicroLamportsPerUnit: 100_000, MaxPriorityFeeLamports: 15_000, NoncePool: 3, NonceRentLamports: sol.DefaultNonceRent},
		Assets: map[string]AssetFile{"SOL": pol("10000000000", "20000000000"), "TKN": pol("1000000", "2000000")}}
	if tweak != nil {
		tweak(&cf)
	}
	cc, err := cf.build(solChain, 4)
	if err != nil {
		t.Fatal(err)
	}
	h.cfg.Chains[solChain] = cc
	for _, q := range []string{
		`INSERT INTO assets (chain, symbol, decimals) VALUES ('` + solChain + `','SOL',9),('` + solChain + `','TKN',6)`,
		`INSERT INTO partitions (id, entity, chain, asset, tier, pool, shard) VALUES ('` + solPartSOL + `','qv-us','` + solChain + `','SOL','hot','omnibus',0)`,
		`INSERT INTO partitions (id, entity, chain, asset, tier, pool, shard) VALUES ('` + solPartTKN + `','qv-us','` + solChain + `','TKN','hot','omnibus',0)`,
	} {
		if _, err := h.biz.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	gw, err := New(h.cfg, nil, map[string]signer.Signer{testPartition: h.signer, testColdPartition: h.signer}, h.guard, h.biz,
		Options{WorkerID: "sol-w", Lease: time.Minute, Now: h.clock,
			MessageSigners: map[string]signer.MessageSigner{solPartSOL: s.hot, solPartTKN: s.hot},
			DepositSigners: map[string]signer.MessageDeriver{solPartSOL: s.dep, solPartTKN: s.dep}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { gw.Wait(10 * time.Second) })
	s.gw = gw
	return s
}

// ---- messages ----

type mx struct {
	prog  [32]byte
	accts []solMeta
	data  []byte
}
type solMeta struct {
	k    [32]byte
	s, w bool
}

func cu(n int) []byte {
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

func (s *solH) compile(payer [32]byte, ixs ...mx) []byte {
	type a struct {
		k    [32]byte
		s, w bool
	}
	var order []*a
	idx := map[[32]byte]*a{}
	add := func(k [32]byte, sg, w bool) {
		if x, ok := idx[k]; ok {
			x.s, x.w = x.s || sg, x.w || w
			return
		}
		x := &a{k, sg, w}
		idx[k] = x
		order = append(order, x)
	}
	add(payer, true, true)
	for _, in := range ixs {
		for _, m := range in.accts {
			add(m.k, m.s, m.w)
		}
		add(in.prog, false, false)
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
	for i := 1; i < len(order); i++ {
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
	m = append(m, cu(len(order))...)
	for _, x := range order {
		m = append(m, x.k[:]...)
	}
	m = append(m, s.bh[:]...)
	m = append(m, cu(len(ixs))...)
	for _, in := range ixs {
		m = append(m, byte(pos[in.prog]))
		m = append(m, cu(len(in.accts))...)
		for _, ac := range in.accts {
			m = append(m, byte(pos[ac.k]))
		}
		m = append(m, cu(len(in.data))...)
		m = append(m, in.data...)
	}
	return m
}

func (s *solH) limit(n uint32) mx {
	return mx{prog: s.cb, data: binary.LittleEndian.AppendUint32([]byte{2}, n)}
}
func (s *solH) price(n uint64) mx {
	return mx{prog: s.cb, data: binary.LittleEndian.AppendUint64([]byte{3}, n)}
}
func (s *solH) transfer(from, to [32]byte, n uint64) mx {
	return mx{prog: s.sys, accts: []solMeta{{from, true, true}, {to, false, true}}, data: binary.LittleEndian.AppendUint64(binary.LittleEndian.AppendUint32(nil, 2), n)}
}

func (s *solH) newBlockhash() { s.bh = soltest.NewKey().Pub }

// adv is AdvanceNonceAccount on pool account i of the hot shard; s.bh plays the value that account holds.
func (s *solH) adv(i int) mx {
	return mx{prog: s.sys, accts: []solMeta{{sol.NonceAddress(s.hot.k.Pub, i), false, true}, {raw32(sol.SysvarRecentBlockhashes), false, false}, {s.hot.k.Pub, true, false}}, data: sol.AdvanceNonceData()}
}

// job builds the sign job of one signer of a message. keyPath is sol.PathHot or sol.DepositPath(...).
func (s *solH) job(id string, in signjob.Intent, msg []byte, part, keyPath string, dep *uint32, approvers ...string) signjob.Job {
	if in.Chain == "" {
		in.Chain = solChain
	}
	if in.PartitionID == "" {
		in.PartitionID = part
	}
	if in.Kind == "withdrawal" && in.NotAfter == 0 {
		in.NotAfter = s.clock().Add(time.Hour).Unix()
	}
	p, _ := json.Marshal(sol.Payload{Message: msg, DepositIndex: dep})
	return signjob.Job{ID: id, PartitionID: part, KeyRef: keyPath, Chain: solChain, Intent: mustJSON(in), Digest: msg, Payload: p, Approvals: s.approvals(in, approvers...)}
}

func (s *solH) run(j signjob.Job) Decision { return s.harness.runWith(s.gw, j) }

func (s *solH) wd(id string, amount uint64) (signjob.Intent, []byte) {
	return s.wdAt(id, amount, 1000, 0)
}

// wdAt is a withdrawal message on pool account nonceIdx with a compute unit price.
func (s *solH) wdAt(id string, amount, price uint64, nonceIdx int) (signjob.Intent, []byte) {
	in := signjob.Intent{Kind: "withdrawal", ID: id, Asset: "SOL", PartitionID: solPartSOL, To: sol.Address(s.dest), Amount: fmt.Sprint(amount)}
	return in, s.compile(s.hot.k.Pub, s.adv(nonceIdx), s.limit(10_000), s.price(price), s.transfer(s.hot.k.Pub, s.dest, amount))
}

// cancelAt is the cancel of a message on pool account nonceIdx.
func (s *solH) cancelAt(id string, price uint64, nonceIdx int) (signjob.Intent, []byte) {
	in := signjob.Intent{Kind: "cancel", ID: id, Asset: "SOL", PartitionID: solPartSOL, To: s.hot.k.Address(), Amount: "0"}
	return in, s.compile(s.hot.k.Pub, s.adv(nonceIdx), s.limit(5_000), s.price(price))
}

func (s *solH) sweepIntent(id string, amount uint64) (signjob.Intent, []byte) {
	in := signjob.Intent{Kind: "sweep", ID: id, Asset: "SOL", PartitionID: solPartSOL, From: sol.Address(s.depAddr), To: s.hot.k.Address(), Amount: fmt.Sprint(amount)}
	return in, s.compile(s.hot.k.Pub, s.limit(10_000), s.transfer(s.depAddr, s.hot.k.Pub, amount))
}

func (s *solH) mustRefuse(j signjob.Job, code string) {
	s.t.Helper()
	before := s.hot.calls.Load() + s.dep.calls.Load()
	d := s.run(j)
	if d.Outcome != OutcomeRejected || !strings.HasPrefix(d.Reason, code+":") {
		s.t.Fatalf("job %s: %s %q, want rejected %s", j.ID, d.Outcome, d.Reason, code)
	}
	if s.hot.calls.Load()+s.dep.calls.Load() != before {
		s.t.Fatalf("job %s: a key signed a refused job", j.ID)
	}
}

func (s *solH) mustSign(j signjob.Job, key []byte) Decision {
	s.t.Helper()
	d := s.run(j)
	if d.Outcome != OutcomeSigned && d.Outcome != OutcomeReplayed {
		s.t.Fatalf("job %s: %s %s", j.ID, d.Outcome, d.Reason)
	}
	if !ed25519.Verify(ed25519.PublicKey(key), j.Digest, d.Sig) {
		s.t.Fatalf("job %s: the signature does not verify against the key it should come from", j.ID)
	}
	return d
}

// ---- tests ----

func TestSOLWithdrawalSignsAndReplays(t *testing.T) {
	s := newSOLHarness(t, nil)
	in, msg := s.wd("w1", 5_000_000)
	j := s.job("j1", in, msg, solPartSOL, sol.PathHot, nil, "alice")
	d := s.mustSign(j, s.hot.k.Pub[:])
	if s.hot.calls.Load() != 1 {
		t.Fatalf("%d signatures", s.hot.calls.Load())
	}
	// the same job again returns the stored signature and signs nothing
	j2 := s.job("j1b", in, msg, solPartSOL, sol.PathHot, nil, "alice")
	d2 := s.run(j2)
	if d2.Outcome != OutcomeReplayed || !bytes.Equal(d2.Sig, d.Sig) || s.hot.calls.Load() != 1 {
		t.Fatalf("replay: %s %s calls=%d", d2.Outcome, d2.Reason, s.hot.calls.Load())
	}
}

// A sweep has two signers over one message. Both jobs sign, each under its own key; the second is not answered with the first's signature.
func TestSOLSweepSignsUnderTwoKeys(t *testing.T) {
	s := newSOLHarness(t, nil)
	in, msg := s.sweepIntent("s1", 3_000_000)
	idx := s.depIdx
	hotJob := s.job("sw-hot", in, msg, solPartSOL, sol.PathHot, &idx)
	depJob := s.job("sw-dep", in, msg, solPartSOL, sol.DepositPath(idx), &idx)
	a := s.mustSign(hotJob, s.hot.k.Pub[:])
	b := s.mustSign(depJob, s.depAddr[:])
	if bytes.Equal(a.Sig, b.Sig) {
		t.Fatal("both jobs got the same signature")
	}
	if d := s.run(s.job("sw-dep-again", in, msg, solPartSOL, sol.DepositPath(idx), &idx)); d.Outcome != OutcomeReplayed || !bytes.Equal(d.Sig, b.Sig) {
		t.Fatalf("the deposit job again: %s %s", d.Outcome, d.Reason)
	}
}

func TestSOLRefusals(t *testing.T) {
	s := newSOLHarness(t, nil)
	in, msg := s.wd("w1", 5_000_000)
	// no approval
	s.mustRefuse(s.job("a1", in, msg, solPartSOL, sol.PathHot, nil), ReasonApprovals)
	// the transaction pays someone else than the approved intent says
	bad := s.compile(s.hot.k.Pub, s.adv(0), s.limit(10_000), s.transfer(s.hot.k.Pub, s.other, 5_000_000))
	s.mustRefuse(s.job("a2", in, bad, solPartSOL, sol.PathHot, nil, "alice"), ReasonTx)
	// more than approved
	more := s.compile(s.hot.k.Pub, s.adv(0), s.limit(10_000), s.transfer(s.hot.k.Pub, s.dest, 6_000_000))
	s.mustRefuse(s.job("a3", in, more, solPartSOL, sol.PathHot, nil, "alice"), ReasonTx)
	// an extra instruction next to the right one
	extra := s.compile(s.hot.k.Pub, s.adv(0), s.limit(10_000), s.transfer(s.hot.k.Pub, s.dest, 5_000_000), s.transfer(s.hot.k.Pub, s.other, 1))
	s.mustRefuse(s.job("a4", in, extra, solPartSOL, sol.PathHot, nil, "alice"), ReasonTx)
	// a price above the cap
	pricey := s.compile(s.hot.k.Pub, s.adv(0), s.limit(10_000), s.price(100_001), s.transfer(s.hot.k.Pub, s.dest, 5_000_000))
	s.mustRefuse(s.job("a5", in, pricey, solPartSOL, sol.PathHot, nil, "alice"), ReasonTx)
	// over the per-transaction cap of the policy
	big := signjob.Intent{Kind: "withdrawal", ID: "wbig", Asset: "SOL", PartitionID: solPartSOL, To: sol.Address(s.dest), Amount: "10000000001"}
	bigMsg := s.compile(s.hot.k.Pub, s.adv(0), s.limit(10_000), s.transfer(s.hot.k.Pub, s.dest, 10_000_000_001))
	s.mustRefuse(s.job("a6", big, bigMsg, solPartSOL, sol.PathHot, nil, "alice", "bob"), ReasonPerTxCap)
	// a v0 message
	s.mustRefuse(s.job("a7", in, append([]byte{0x80}, msg...), solPartSOL, sol.PathHot, nil, "alice"), ReasonTx)
	// a digest that is not the message in the payload
	j := s.job("a8", in, msg, solPartSOL, sol.PathHot, nil, "alice")
	j.Digest = append([]byte(nil), j.Digest...)
	j.Digest[5] ^= 1
	s.mustRefuse(j, ReasonTx)
	// a sweep that pays the wrong address, the deposit key asked for another index, a deposit job on a withdrawal
	sin, smsg := s.sweepIntent("s1", 3_000_000)
	idx := s.depIdx
	evil := s.compile(s.hot.k.Pub, s.limit(10_000), s.transfer(s.depAddr, s.other, 3_000_000))
	s.mustRefuse(s.job("s-evil", sin, evil, solPartSOL, sol.PathHot, &idx), ReasonTx)
	wrongIdx := idx + 1
	s.mustRefuse(s.job("s-idx", sin, smsg, solPartSOL, sol.DepositPath(wrongIdx), &idx), ReasonTx)
	s.mustRefuse(s.job("s-dep-on-wd", in, msg, solPartSOL, sol.DepositPath(idx), nil, "alice"), ReasonTx)
	// an intent kind this chain does not sign yet
	cold := signjob.Intent{Kind: "to-cold", ID: "c1", Asset: "SOL", PartitionID: solPartSOL, To: sol.Address(s.dest), Amount: "5000000"}
	s.mustRefuse(s.job("a9", cold, msg, solPartSOL, sol.PathHot, nil), ReasonTx)
	if s.hot.calls.Load() != 0 || s.dep.calls.Load() != 0 {
		t.Fatalf("a key signed during the refusals")
	}
}

// The versions of one withdrawal share one nonce account and value; a version may raise the price and nothing else.
func TestSOLVersionsOfAWithdrawalShareOneNonce(t *testing.T) {
	s := newSOLHarness(t, nil)
	in, msg := s.wdAt("w1", 5_000_000, 1000, 0)
	first := s.mustSign(s.job("j1", in, msg, solPartSOL, sol.PathHot, nil, "alice"), s.hot.k.Pub[:])
	calls := s.hot.calls.Load()

	// a retry of the first message gets the stored signature
	if d := s.run(s.job("j1b", in, msg, solPartSOL, sol.PathHot, nil, "alice")); d.Outcome != OutcomeReplayed || !bytes.Equal(d.Sig, first.Sig) {
		t.Fatalf("retry: %s %s", d.Outcome, d.Reason)
	}
	// the same message with a lower or the same price is not a new version
	_, same := s.wdAt("w1", 5_000_000, 1000, 0)
	if !bytes.Equal(same, msg) {
		t.Fatal("same inputs, different message")
	}
	_, lower := s.wdAt("w1", 5_000_000, 999, 0)
	s.mustRefuse(s.job("lower", in, lower, solPartSOL, sol.PathHot, nil, "alice"), ReasonFeeNotHigher)
	// a higher price, same nonce account and value: signed, once, and its own retry replays
	_, higher := s.wdAt("w1", 5_000_000, 1500, 0)
	v2 := s.mustSign(s.job("v2", in, higher, solPartSOL, sol.PathHot, nil, "alice"), s.hot.k.Pub[:])
	if v2.Outcome != OutcomeSigned || s.hot.calls.Load() != calls+1 {
		t.Fatalf("the raised version: %s, %d signatures", v2.Outcome, s.hot.calls.Load()-calls)
	}
	if d := s.run(s.job("v2b", in, higher, solPartSOL, sol.PathHot, nil, "alice")); d.Outcome != OutcomeReplayed || !bytes.Equal(d.Sig, v2.Sig) {
		t.Fatalf("retry of the raised version: %s %s", d.Outcome, d.Reason)
	}
	// and the first version still replays its own signature
	if d := s.run(s.job("j1c", in, msg, solPartSOL, sol.PathHot, nil, "alice")); d.Outcome != OutcomeReplayed || !bytes.Equal(d.Sig, first.Sig) {
		t.Fatalf("the first version again: %s %s", d.Outcome, d.Reason)
	}
	// a version on another nonce account of the pool, or another value of the same account: refused
	_, otherAcct := s.wdAt("w1", 5_000_000, 2000, 1)
	s.mustRefuse(s.job("acct", in, otherAcct, solPartSOL, sol.PathHot, nil, "alice"), ReasonNonceChanged)
	was := s.bh
	s.newBlockhash()
	_, otherValue := s.wdAt("w1", 5_000_000, 2000, 0)
	s.mustRefuse(s.job("value", in, otherValue, solPartSOL, sol.PathHot, nil, "alice"), ReasonNonceChanged)
	s.bh = was
	// a different limit with a higher price is not "the price only"
	diffLimit := s.compile(s.hot.k.Pub, s.adv(0), s.limit(20_000), s.price(3000), s.transfer(s.hot.k.Pub, s.dest, 5_000_000))
	s.mustRefuse(s.job("limit", in, diffLimit, solPartSOL, sol.PathHot, nil, "alice"), ReasonFeeNotHigher)
	// another destination or amount is no version of this intent
	elsewhere := s.compile(s.hot.k.Pub, s.adv(0), s.limit(10_000), s.price(3000), s.transfer(s.hot.k.Pub, s.other, 5_000_000))
	s.mustRefuse(s.job("dest", in, elsewhere, solPartSOL, sol.PathHot, nil, "alice"), ReasonTx)
	more := s.compile(s.hot.k.Pub, s.adv(0), s.limit(10_000), s.price(3000), s.transfer(s.hot.k.Pub, s.dest, 5_000_001))
	s.mustRefuse(s.job("amount", in, more, solPartSOL, sol.PathHot, nil, "alice"), ReasonTx)
	// no price at all (a lower fee than the first) is not a version
	nop := s.compile(s.hot.k.Pub, s.adv(0), s.limit(10_000), s.transfer(s.hot.k.Pub, s.dest, 5_000_000))
	s.mustRefuse(s.job("noprice", in, nop, solPartSOL, sol.PathHot, nil, "alice"), ReasonFeeNotHigher)
	// another intent cannot take the nonce that w1 holds
	other := signjob.Intent{Kind: "withdrawal", ID: "w2", Asset: "SOL", PartitionID: solPartSOL, To: sol.Address(s.dest), Amount: "5000000"}
	_, otherMsg := s.wdAt("w2", 5_000_000, 7000, 0)
	s.mustRefuse(s.job("w2", other, otherMsg, solPartSOL, sol.PathHot, nil, "alice"), ReasonNonceTaken)
	s.mustRefuse(s.job("w2b", other, msg, solPartSOL, sol.PathHot, nil, "alice"), ReasonIntentChanged)
	// and the nonce attacks that move the account itself
	for name, ix := range map[string]mx{
		"withdraw": {prog: s.sys, accts: []solMeta{{sol.NonceAddress(s.hot.k.Pub, 0), false, true}, {s.other, false, true}, {raw32(sol.SysvarRecentBlockhashes), false, false}, {raw32(sol.SysvarRent), false, false}, {s.hot.k.Pub, true, false}},
			data: binary.LittleEndian.AppendUint64(binary.LittleEndian.AppendUint32(nil, 5), 1_000_000)},
		"authorize": {prog: s.sys, accts: []solMeta{{sol.NonceAddress(s.hot.k.Pub, 0), false, true}, {s.hot.k.Pub, true, false}}, data: append(binary.LittleEndian.AppendUint32(nil, 7), s.other[:]...)},
	} {
		evil := s.compile(s.hot.k.Pub, s.adv(0), s.limit(10_000), s.price(9000), s.transfer(s.hot.k.Pub, s.dest, 5_000_000), ix)
		s.mustRefuse(s.job("evil-"+name, in, evil, solPartSOL, sol.PathHot, nil, "alice"), ReasonTx)
	}
}

// A cancel advances exactly the nonce of an intent that was signed; it takes the claim, after which no version of the withdrawal is signed.
func TestSOLCancelTakesTheNonce(t *testing.T) {
	s := newSOLHarness(t, nil)
	in, msg := s.wdAt("w1", 5_000_000, 1000, 0)
	s.mustSign(s.job("j1", in, msg, solPartSOL, sol.PathHot, nil, "alice"), s.hot.k.Pub[:])

	// a cancel of a nonce nothing was signed at, or of another value: refused (it could burn any nonce)
	cin, cmsg := s.cancelAt("cancel-1", 1100, 1)
	s.mustRefuse(s.job("c0", cin, cmsg, solPartSOL, sol.PathHot, nil), ReasonCancelClaims)
	was := s.bh
	s.newBlockhash()
	cin, cmsg = s.cancelAt("cancel-1", 1100, 0)
	s.mustRefuse(s.job("c1", cin, cmsg, solPartSOL, sol.PathHot, nil), ReasonCancelClaims)
	s.bh = was
	// the cancel of the signed nonce is signed, without an approval
	cin, cmsg = s.cancelAt("cancel-1", 1100, 0)
	s.mustSign(s.job("c2", cin, cmsg, solPartSOL, sol.PathHot, nil), s.hot.k.Pub[:])
	// after it no version of the withdrawal is signed, not even a higher price
	_, higher := s.wdAt("w1", 5_000_000, 5000, 0)
	s.mustRefuse(s.job("late", in, higher, solPartSOL, sol.PathHot, nil, "alice"), ReasonNonceCancel)
	// a cancel that carries a transfer is not a cancel
	evil := s.compile(s.hot.k.Pub, s.adv(0), s.limit(5_000), s.transfer(s.hot.k.Pub, s.other, 1))
	s.mustRefuse(s.job("c3", cin, evil, solPartSOL, sol.PathHot, nil), ReasonTx)
	// a cancel for a withdrawal of another shard's partition cannot be made out of this one: the cancel is for the partition of the claim
	tkn := cin
	tkn.ID, tkn.PartitionID = "cancel-2", solPartTKN
	_, m4 := s.cancelAt("cancel-2", 1200, 0)
	s.mustRefuse(s.job("c4", tkn, m4, solPartTKN, sol.PathHot, nil), ReasonCancelClaims)
}

// Nonce accounts are created only under an operator's approval, only the pool's own addresses, only with the rent the config names.
func TestSOLNonceSetupNeedsAnOperator(t *testing.T) {
	s := newSOLHarness(t, nil)
	hot := s.hot.k.Pub
	mk := func(idxs ...int) []byte {
		ixs := []mx{s.limit(30_000)}
		for _, i := range idxs {
			n := sol.NonceAddress(hot, i)
			ixs = append(ixs,
				mx{prog: s.sys, accts: []solMeta{{hot, true, true}, {n, false, true}}, data: sol.CreateWithSeedData(hot, sol.NonceSeed(i), sol.DefaultNonceRent, sol.NonceAccountSize)},
				mx{prog: s.sys, accts: []solMeta{{n, false, true}, {raw32(sol.SysvarRecentBlockhashes), false, false}, {raw32(sol.SysvarRent), false, false}}, data: sol.InitNonceData(hot)})
		}
		return s.compile(hot, ixs...)
	}
	in := signjob.Intent{Kind: sol.KindNonceSetup, ID: "setup-1", Asset: "SOL", PartitionID: solPartSOL, To: s.hot.k.Address(), Amount: fmt.Sprint(2 * sol.DefaultNonceRent)}
	msg := mk(0, 1)
	s.mustRefuse(s.job("n0", in, msg, solPartSOL, sol.PathHot, nil), ReasonApprovals)
	s.mustSign(s.job("n1", in, msg, solPartSOL, sol.PathHot, nil, "alice"), s.hot.k.Pub[:])
	// an account outside the pool, more rent than the config says
	s.newBlockhash()
	in2 := in
	in2.ID, in2.Amount = "setup-2", fmt.Sprint(sol.DefaultNonceRent)
	s.mustRefuse(s.job("n2", in2, mk(3), solPartSOL, sol.PathHot, nil, "alice"), ReasonTx)
}

// A signer whose key is not the pinned hot address, or not the derived deposit key, is never asked.
func TestSOLWrongSignerKeyIsNeverAsked(t *testing.T) {
	s := newSOLHarness(t, nil)
	s.gw.opt.MessageSigners[solPartSOL] = &softMsg{k: soltest.NewKey()}
	in, msg := s.wd("w1", 5_000_000)
	d := s.run(s.job("j1", in, msg, solPartSOL, sol.PathHot, nil, "alice"))
	if d.Outcome != OutcomeFailed || !strings.Contains(d.Reason, "signer") {
		t.Fatalf("%s %s", d.Outcome, d.Reason)
	}
	if n := s.gw.opt.MessageSigners[solPartSOL].(*softMsg).calls.Load(); n != 0 {
		t.Fatalf("the wrong key signed %d times", n)
	}
	// the deposit tree of another account
	s.gw.opt.DepositSigners[solPartSOL] = &softDeposit{node: soltest.NewNode()}
	sin, smsg := s.sweepIntent("s1", 3_000_000)
	idx := s.depIdx
	d = s.run(s.job("s-dep", sin, smsg, solPartSOL, sol.DepositPath(idx), &idx))
	if d.Outcome != OutcomeFailed {
		t.Fatalf("%s %s", d.Outcome, d.Reason)
	}
}

func TestSOLConfigRefusals(t *testing.T) {
	acctPub := soltest.NewKey().Pub
	base := func() ChainFile {
		return ChainFile{Family: "sol", WithdrawalsPerHour: 1, SOL: &SOLFile{AccountPublicKey: hex.EncodeToString(acctPub[:]), AccountChainCode: hex.EncodeToString(make([]byte, 32)),
			HotShards: map[string]string{solPartSOL: sol.Address(soltest.NewKey().Pub)}, Tokens: map[string]SOLTokenFile{"TKN": {Mint: sol.Address(soltest.NewKey().Pub), Decimals: 6}},
			MaxComputeUnits: 1, MaxMicroLamportsPerUnit: 1, MaxPriorityFeeLamports: 1, NoncePool: 1, NonceRentLamports: 1},
			Assets: map[string]AssetFile{"SOL": {AnyDestination: true, PerTxCap: "1", DailyCap: "1", Tiers: []TierFile{{"0", 1}}}, "TKN": {AnyDestination: true, PerTxCap: "1", DailyCap: "1", Tiers: []TierFile{{"0", 1}}}}}
	}
	if _, err := base().build(solChain, 4); err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(*ChainFile){
		"no sol section":         func(cf *ChainFile) { cf.SOL = nil },
		"no caps":                func(cf *ChainFile) { cf.SOL.MaxComputeUnits = 0 },
		"a token without policy": func(cf *ChainFile) { delete(cf.Assets, "TKN") },
		"an asset nobody knows":  func(cf *ChainFile) { cf.Assets["XYZ"] = cf.Assets["SOL"] },
		"bad account key":        func(cf *ChainFile) { cf.SOL.AccountPublicKey = "00" },
		"no withdrawal rate":     func(cf *ChainFile) { cf.WithdrawalsPerHour = 0 },
	} {
		cf := base()
		mod(&cf)
		if _, err := cf.build(solChain, 4); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A different intent on a nonce account and value another open intent holds is refused before anything is signed, whatever else differs.
func TestSOLAnotherIntentOnAHeldNonceIsRefused(t *testing.T) {
	s := newSOLHarness(t, nil)
	in, msg := s.wdAt("w1", 5_000_000, 1000, 0)
	s.mustSign(s.job("j1", in, msg, solPartSOL, sol.PathHot, nil, "alice"), s.hot.k.Pub[:])
	calls := s.hot.calls.Load()
	in2, msg2 := s.wdAt("w2", 7_000_000, 5000, 0) // another amount, a higher price, the same account and value
	s.mustRefuse(s.job("j2", in2, msg2, solPartSOL, sol.PathHot, nil, "alice"), ReasonNonceTaken)
	if s.hot.calls.Load() != calls {
		t.Fatal("a key signed")
	}
}

// Two pool accounts advanced in one block hold the same value. Claims are the account and the value together, so two withdrawals, one on each,
// both sign.
func TestSOLEqualValuesOnTwoAccountsAreTwoNonces(t *testing.T) {
	s := newSOLHarness(t, nil)
	in1, msg1 := s.wdAt("w1", 5_000_000, 1000, 0)
	in2, msg2 := s.wdAt("w2", 6_000_000, 1000, 1) // s.bh is the value of both accounts
	s.mustSign(s.job("j1", in1, msg1, solPartSOL, sol.PathHot, nil, "alice"), s.hot.k.Pub[:])
	s.mustSign(s.job("j2", in2, msg2, solPartSOL, sol.PathHot, nil, "alice"), s.hot.k.Pub[:])
	// and each still holds its own: a third intent on either is refused
	in3, msg3 := s.wdAt("w3", 7_000_000, 1000, 1)
	s.mustRefuse(s.job("j3", in3, msg3, solPartSOL, sol.PathHot, nil, "alice"), ReasonNonceTaken)
}
