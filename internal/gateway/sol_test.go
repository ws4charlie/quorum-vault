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
	cf := ChainFile{Family: "sol", WithdrawalsPerHour: 1000, SweepsPerHour: 1000,
		SOL: &SOLFile{AccountPublicKey: hex.EncodeToString(s.acct.Pub[:]), AccountChainCode: hex.EncodeToString(s.acct.ChainCode[:]),
			HotShards:       map[string]string{solPartSOL: s.hot.k.Address(), solPartTKN: s.hot.k.Address()},
			Tokens:          map[string]SOLTokenFile{"TKN": {Mint: sol.Address(s.mint), Decimals: 6}},
			MaxComputeUnits: 200_000, MaxMicroLamportsPerUnit: 100_000, MaxPriorityFeeLamports: 15_000},
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
	in := signjob.Intent{Kind: "withdrawal", ID: id, Asset: "SOL", PartitionID: solPartSOL, To: sol.Address(s.dest), Amount: fmt.Sprint(amount)}
	return in, s.compile(s.hot.k.Pub, s.limit(10_000), s.price(1000), s.transfer(s.hot.k.Pub, s.dest, amount))
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
	bad := s.compile(s.hot.k.Pub, s.limit(10_000), s.transfer(s.hot.k.Pub, s.other, 5_000_000))
	s.mustRefuse(s.job("a2", in, bad, solPartSOL, sol.PathHot, nil, "alice"), ReasonTx)
	// more than approved
	more := s.compile(s.hot.k.Pub, s.limit(10_000), s.transfer(s.hot.k.Pub, s.dest, 6_000_000))
	s.mustRefuse(s.job("a3", in, more, solPartSOL, sol.PathHot, nil, "alice"), ReasonTx)
	// an extra instruction next to the right one
	extra := s.compile(s.hot.k.Pub, s.limit(10_000), s.transfer(s.hot.k.Pub, s.dest, 5_000_000), s.transfer(s.hot.k.Pub, s.other, 1))
	s.mustRefuse(s.job("a4", in, extra, solPartSOL, sol.PathHot, nil, "alice"), ReasonTx)
	// a price above the cap
	pricey := s.compile(s.hot.k.Pub, s.limit(10_000), s.price(100_001), s.transfer(s.hot.k.Pub, s.dest, 5_000_000))
	s.mustRefuse(s.job("a5", in, pricey, solPartSOL, sol.PathHot, nil, "alice"), ReasonTx)
	// over the per-transaction cap of the policy
	big := signjob.Intent{Kind: "withdrawal", ID: "wbig", Asset: "SOL", PartitionID: solPartSOL, To: sol.Address(s.dest), Amount: "10000000001"}
	bigMsg := s.compile(s.hot.k.Pub, s.limit(10_000), s.transfer(s.hot.k.Pub, s.dest, 10_000_000_001))
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

// One message per intent: a second message (a new blockhash) for an intent that was already signed is refused. The first message's signature
// is what a retry gets back.
func TestSOLOneMessagePerIntent(t *testing.T) {
	s := newSOLHarness(t, nil)
	in, msg := s.wd("w1", 5_000_000)
	first := s.mustSign(s.job("j1", in, msg, solPartSOL, sol.PathHot, nil, "alice"), s.hot.k.Pub[:])
	s.newBlockhash()
	_, msg2 := s.wd("w1", 5_000_000)
	if bytes.Equal(msg, msg2) {
		t.Fatal("same message")
	}
	s.mustRefuse(s.job("j2", in, msg2, solPartSOL, sol.PathHot, nil, "alice"), ReasonFeeNotHigher)
	// and the first message still returns the stored signature
	d := s.run(s.job("j3", in, msg, solPartSOL, sol.PathHot, nil, "alice"))
	if d.Outcome != OutcomeReplayed || !bytes.Equal(d.Sig, first.Sig) {
		t.Fatalf("retry of the first: %s %s", d.Outcome, d.Reason)
	}
	// another intent cannot reuse the first message
	other := signjob.Intent{Kind: "withdrawal", ID: "w2", Asset: "SOL", PartitionID: solPartSOL, To: sol.Address(s.dest), Amount: "5000000"}
	s.mustRefuse(s.job("j4", other, msg, solPartSOL, sol.PathHot, nil, "alice"), ReasonIntentChanged)
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
			MaxComputeUnits: 1, MaxMicroLamportsPerUnit: 1, MaxPriorityFeeLamports: 1},
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
