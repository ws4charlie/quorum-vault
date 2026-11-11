package cosigner_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/chain/sol"
	st "github.com/ws4charlie/quorum-vault/internal/chain/sol/soltest"
	"github.com/ws4charlie/quorum-vault/internal/cosigner"
	"github.com/ws4charlie/quorum-vault/internal/gateway"
	"github.com/ws4charlie/quorum-vault/internal/gateway/gatewaytest"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
	wire "github.com/ws4charlie/quorum-vault/mpc-party/api/cosigner"
	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

const (
	solChain = "sol-cos"
	solPart  = "qv-us/sol-cos/SOL/hot/omnibus/0"
	solTok   = "qv-us/sol-cos/TKN/hot/omnibus/0"
)

// solEnv is the cosigners of party B and party C for a Solana chain, each with its own guard database and the same config, driven by a rogue
// gateway: the test sends them whatever it likes, with the signing key it names.
type solEnv struct {
	t         *testing.T
	b, c      *cosigner.Cosigner
	hot, acct st.Key
	node      st.Node
	appr      ed25519.PrivateKey
	dest, oth [32]byte
	mint      [32]byte
	bh        [32]byte
	depIdx    uint32
	depKey    [32]byte
	notAfter  int64
}

func newSOLEnv(t *testing.T) *solEnv {
	t.Helper()
	e := &solEnv{t: t, hot: st.NewKey(), node: st.NewNode(), dest: st.NewKey().Pub, oth: st.NewKey().Pub, mint: st.NewKey().Pub, bh: st.NewKey().Pub, depIdx: 3,
		notAfter: time.Now().Add(time.Hour).Unix()}
	dk, _ := e.node.Public().Derive(sol.BranchExternal, e.depIdx)
	e.depKey = dk.PublicKey
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	e.appr = priv
	f := gateway.File{
		Approvers: map[string]gateway.ApproverFile{"alice": {PublicKey: hex.EncodeToString(pub), Enabled: true}},
		Chains: map[string]gateway.ChainFile{solChain: {Family: "sol", WithdrawalsPerHour: 100, SweepsPerHour: 100,
			SOL: &gateway.SOLFile{AccountPublicKey: hex.EncodeToString(e.node.Pub[:]), AccountChainCode: hex.EncodeToString(e.node.ChainCode[:]),
				HotShards:       map[string]string{solPart: e.hot.Address(), solTok: e.hot.Address()},
				Tokens:          map[string]gateway.SOLTokenFile{"TKN": {Mint: sol.Address(e.mint), Decimals: 6}},
				MaxComputeUnits: 200_000, MaxMicroLamportsPerUnit: 100_000, MaxPriorityFeeLamports: 15_000, NoncePool: 3, NonceRentLamports: sol.DefaultNonceRent},
			Assets: map[string]gateway.AssetFile{
				"SOL": {WithdrawalDestinations: []string{sol.Address(e.dest)}, PerTxCap: "10000000000", DailyCap: "20000000000", Tiers: []gateway.TierFile{{MinAmount: "0", Approvals: 1}}},
				"TKN": {AnyDestination: true, PerTxCap: "1000000", DailyCap: "2000000", Tiers: []gateway.TierFile{{MinAmount: "0", Approvals: 1}}}}}},
	}
	raw, _ := json.Marshal(f)
	cfg, err := gateway.ParseConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	mk := func() *cosigner.Cosigner {
		pool, _ := gatewaytest.NewGuardDB(t)
		guard, err := gateway.OpenGuard(context.Background(), pool)
		if err != nil {
			t.Fatal(err)
		}
		c, err := cosigner.New(cfg, guard, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	e.b, e.c = mk(), mk()
	return e
}

func (e *solEnv) msg(ixs ...st.Ix) []byte { return st.Compile(e.hot.Pub, e.bh, ixs...) }

// adv advances pool account i of the hot shard; e.bh plays the value it holds.
func (e *solEnv) adv(i int) st.Ix { return st.AdvanceNonce(sol.NonceAddress(e.hot.Pub, i), e.hot.Pub) }

func (e *solEnv) wdSOL(id string, amount uint64) (signjob.Intent, []byte) {
	return signjob.Intent{Kind: "withdrawal", ID: id, Asset: "SOL", PartitionID: solPart, To: sol.Address(e.dest), Amount: fmt.Sprint(amount), NotAfter: e.notAfter},
		e.msg(e.adv(0), st.SetLimit(10_000), st.SetPrice(1000), st.Transfer(e.hot.Pub, e.dest, amount))
}

// request is what a rogue gateway sends party B (or C) for a job, with the public key it says will sign.
func (e *solEnv) request(id string, in signjob.Intent, msg []byte, keyPath string, dep *uint32, key []byte, approve bool) wire.Request {
	e.t.Helper()
	in.Chain = solChain
	if in.PartitionID == "" {
		in.PartitionID = solPart
	}
	var ix []uint32
	if dep != nil {
		ix = []uint32{*dep}
	}
	p, _ := json.Marshal(sol.Payload{Message: msg, DepositIndices: ix})
	var apps []signjob.Approval
	if approve {
		h := in.Hash()
		apps = []signjob.Approval{{Actor: "alice", Signature: ed25519.Sign(e.appr, h[:])}}
	}
	j := signjob.Job{ID: id, PartitionID: in.PartitionID, KeyRef: keyPath, Chain: solChain, Intent: mustJSON(in), Digest: msg, Payload: p, Approvals: apps}
	pkg, err := gateway.EncodePackage(j)
	if err != nil {
		e.t.Fatal(err)
	}
	if key == nil {
		key = e.hot.Pub[:]
	}
	return wire.Request{JobID: id, KeyID: "k", KeysetID: "ks", Algorithm: int32(pb.Algorithm_ALGORITHM_ED25519), Digest: msg, IntentPackage: pkg, PublicKey: key}
}

func (e *solEnv) allow(c *cosigner.Cosigner, r wire.Request) {
	e.t.Helper()
	if got := c.Decide(context.Background(), r); !got.Allow {
		e.t.Fatalf("job %s refused: %s", r.JobID, got.Reason)
	}
}

func (e *solEnv) refuse(c *cosigner.Cosigner, r wire.Request, code string) {
	e.t.Helper()
	got := c.Decide(context.Background(), r)
	if got.Allow || !strings.HasPrefix(got.Reason, code) {
		e.t.Fatalf("job %s: want refusal %q, got allow=%v unavailable=%v reason=%q", r.JobID, code, got.Allow, got.Unavailable, got.Reason)
	}
}

// A correct withdrawal and a correct sweep (both signers' jobs) pass the cosigner of B and the cosigner of C alike; a retry of a job passes.
func TestCosignerSOLAllowsWhatIsApproved(t *testing.T) {
	e := newSOLEnv(t)
	in, msg := e.wdSOL("wi1", 5_000_000)
	for _, c := range []*cosigner.Cosigner{e.b, e.c} {
		r := e.request("w1", in, msg, sol.PathHot, nil, nil, true)
		e.allow(c, r)
		e.allow(c, r) // a retry of the same job
	}
	sin := signjob.Intent{Kind: "sweep", ID: "si1", Asset: "SOL", PartitionID: solPart, From: sol.Address(e.depKey), To: e.hot.Address(), Amount: "3000000"}
	smsg := e.msg(e.adv(1), st.SetLimit(10_000), st.Transfer(e.depKey, e.hot.Pub, 3_000_000))
	idx := e.depIdx
	for _, c := range []*cosigner.Cosigner{e.b, e.c} {
		e.allow(c, e.request("s-hot", sin, smsg, sol.PathHot, &idx, nil, false))
		e.allow(c, e.request("s-dep", sin, smsg, sol.DepositPath(idx), &idx, e.depKey[:], false))
	}
}

// Whatever the rogue gateway sends, party B's cosigner and party C's refuse it before any signing message: each judges alone, from its own
// config, so C refuses with B down exactly as B does.
func TestCosignerSOLRefusesEveryAttack(t *testing.T) {
	e := newSOLEnv(t)
	in, msg := e.wdSOL("wi1", 5_000_000)
	idx := e.depIdx
	type attack struct {
		name string
		req  func() wire.Request
		code string
	}
	badDest := e.msg(e.adv(0), st.SetLimit(10_000), st.Transfer(e.hot.Pub, e.oth, 5_000_000))
	moreAmt := e.msg(e.adv(0), st.SetLimit(10_000), st.Transfer(e.hot.Pub, e.dest, 6_000_000))
	extra := e.msg(e.adv(0), st.SetLimit(10_000), st.Transfer(e.hot.Pub, e.dest, 5_000_000), st.Transfer(e.hot.Pub, e.oth, 1))
	pricey := e.msg(e.adv(0), st.SetLimit(10_000), st.SetPrice(100_001), st.Transfer(e.hot.Pub, e.dest, 5_000_000))
	otherPayer := st.Compile(e.oth, e.bh, e.adv(0), st.SetLimit(10_000), st.Transfer(e.oth, e.dest, 5_000_000))
	in2 := in
	in2.Amount = "5000001"
	notListed := in
	notListed.To = sol.Address(e.oth)
	setAuth := st.Ix{Program: st.CloseAccount(e.hot.Pub, e.hot.Pub, e.hot.Pub).Program, Accts: []st.Meta{{Key: e.hot.Pub, Signer: true, Writable: true}}, Data: []byte{6, 2, 1, 9, 9}}
	sweepIn := signjob.Intent{Kind: "sweep", ID: "si1", Asset: "SOL", PartitionID: solPart, From: sol.Address(e.depKey), To: e.hot.Address(), Amount: "3000000"}
	sweepMsg := e.msg(e.adv(1), st.SetLimit(10_000), st.Transfer(e.depKey, e.hot.Pub, 3_000_000))
	sweepEvil := e.msg(e.adv(1), st.SetLimit(10_000), st.Transfer(e.depKey, e.oth, 3_000_000))
	tokIn := signjob.Intent{Kind: "withdrawal", ID: "ti1", Asset: "TKN", PartitionID: solTok, To: sol.Address(e.dest), Amount: "777", NotAfter: e.notAfter}
	tokBad := e.msg(e.adv(0), st.SetLimit(50_000), st.CheckedTransfer(st.ATAOf(e.hot.Pub, e.mint), e.mint, st.ATAOf(e.oth, e.mint), e.hot.Pub, 777, 6))
	tokDec := e.msg(e.adv(0), st.SetLimit(50_000), st.CheckedTransfer(st.ATAOf(e.hot.Pub, e.mint), e.mint, st.ATAOf(e.dest, e.mint), e.hot.Pub, 777, 9))
	short := e.request("a-short", in, msg, sol.PathHot, nil, e.hot.Pub[:31], true)
	long := e.request("a-long", in, msg, sol.PathHot, nil, nil, true)
	long.Digest = make([]byte, sol.MaxMessage+1)
	empty := e.request("a-empty", in, msg, sol.PathHot, nil, nil, true)
	empty.Digest = nil
	badPkg := e.request("a-pkg", in, msg, sol.PathHot, nil, nil, true)
	badPkg.Digest = append([]byte(nil), msg...)
	badPkg.Digest[10] ^= 1
	wrongJob := e.request("a-job", in, msg, sol.PathHot, nil, nil, true)
	wrongJob.JobID = "another"
	attacks := []attack{
		{"no approval", func() wire.Request { return e.request("a1", in, msg, sol.PathHot, nil, nil, false) }, gateway.ReasonApprovals},
		{"wrong destination in the message", func() wire.Request { return e.request("a2", in, badDest, sol.PathHot, nil, nil, true) }, gateway.ReasonTx},
		{"a larger amount in the message", func() wire.Request { return e.request("a3", in, moreAmt, sol.PathHot, nil, nil, true) }, gateway.ReasonTx},
		{"an extra instruction", func() wire.Request { return e.request("a4", in, extra, sol.PathHot, nil, nil, true) }, gateway.ReasonTx},
		{"a price above the cap", func() wire.Request { return e.request("a5", in, pricey, sol.PathHot, nil, nil, true) }, gateway.ReasonTx},
		{"another fee payer", func() wire.Request { return e.request("a6", in, otherPayer, sol.PathHot, nil, nil, true) }, gateway.ReasonTx},
		{"a destination the config does not list", func() wire.Request {
			m := e.msg(e.adv(0), st.SetLimit(10_000), st.Transfer(e.hot.Pub, e.oth, 5_000_000))
			return e.request("a7", notListed, m, sol.PathHot, nil, nil, true)
		}, gateway.ReasonDestination},
		{"an amount the approval does not cover", func() wire.Request { return e.request("a8", in2, msg, sol.PathHot, nil, nil, true) }, gateway.ReasonTx},
		{"setAuthority next to the transfer", func() wire.Request {
			return e.request("a9", in, e.msg(e.adv(0), st.SetLimit(10_000), st.Transfer(e.hot.Pub, e.dest, 5_000_000), setAuth), sol.PathHot, nil, nil, true)
		}, gateway.ReasonTx},
		{"a v0 message", func() wire.Request {
			return e.request("a10", in, append([]byte{0x80}, msg...), sol.PathHot, nil, nil, true)
		}, gateway.ReasonTx},
		{"a key that is not the hot shard's", func() wire.Request { return e.request("a11", in, msg, sol.PathHot, nil, e.oth[:], true) }, "signer_key_mismatch"},
		{"a sweep that pays someone else", func() wire.Request { return e.request("a12", sweepIn, sweepEvil, sol.PathHot, &idx, nil, false) }, gateway.ReasonTx},
		{"a deposit job signed with the hot key", func() wire.Request {
			return e.request("a13", sweepIn, sweepMsg, sol.DepositPath(idx), &idx, nil, false)
		}, "signer_key_mismatch"},
		{"a deposit job for another index", func() wire.Request {
			return e.request("a14", sweepIn, sweepMsg, sol.DepositPath(idx+1), &idx, e.depKey[:], false)
		}, gateway.ReasonTx},
		{"a token transfer to a stranger's account", func() wire.Request {
			return e.request("a15", tokIn, tokBad, sol.PathHot, nil, nil, true)
		}, gateway.ReasonTx},
		{"a token transfer with wrong decimals", func() wire.Request { return e.request("a16", tokIn, tokDec, sol.PathHot, nil, nil, true) }, gateway.ReasonTx},
		{"a key of 31 bytes", func() wire.Request { return short }, "cosigner: the key"},
		{"a message above the size of a transaction", func() wire.Request { return long }, "cosigner: a message"},
		{"no message", func() wire.Request { return empty }, "cosigner: a message"},
		{"a package for another message", func() wire.Request { return badPkg }, gateway.ReasonTx},
		{"a package for another job", func() wire.Request { return wrongJob }, gateway.ReasonIntent},
	}
	for _, a := range attacks {
		a := a
		t.Run(a.name, func(t *testing.T) {
			e.t = t
			e.refuse(e.b, a.req(), a.code)
			e.refuse(e.c, a.req(), a.code) // C alone, B down
		})
	}
}

// The cosigner keeps what it allowed: the versions of one intent share a nonce account and value and may only raise the price; anything else is
// refused, whatever the gateway says, and so is a cancel that does not match a nonce it has seen.
func TestCosignerSOLVersionsShareOneNonce(t *testing.T) {
	e := newSOLEnv(t)
	in, msg := e.wdSOL("wi1", 5_000_000)
	e.allow(e.c, e.request("w1", in, msg, sol.PathHot, nil, nil, true))
	at := func(nonceIdx int, price uint64, limit uint32, to [32]byte, amount uint64) []byte {
		return e.msg(e.adv(nonceIdx), st.SetLimit(limit), st.SetPrice(price), st.Transfer(e.hot.Pub, to, amount))
	}
	// a higher price: allowed (a new message), and its own retry too
	higher := e.request("w2", in, at(0, 1500, 10_000, e.dest, 5_000_000), sol.PathHot, nil, nil, true)
	e.allow(e.c, higher)
	e.allow(e.c, higher)
	e.allow(e.c, e.request("v-first-again", in, at(0, 1000, 10_000, e.dest, 5_000_000), sol.PathHot, nil, nil, true)) // the first message again is a retry, not a new message
	e.refuse(e.c, e.request("v-lower", in, at(0, 900, 10_000, e.dest, 5_000_000), sol.PathHot, nil, nil, true), gateway.ReasonFeeNotHigher)
	e.refuse(e.c, e.request("v-limit", in, at(0, 3000, 20_000, e.dest, 5_000_000), sol.PathHot, nil, nil, true), gateway.ReasonFeeNotHigher)
	e.refuse(e.c, e.request("v-acct", in, at(1, 3000, 10_000, e.dest, 5_000_000), sol.PathHot, nil, nil, true), gateway.ReasonNonceChanged)
	e.refuse(e.c, e.request("v-dest", in, at(0, 3000, 10_000, e.oth, 5_000_000), sol.PathHot, nil, nil, true), gateway.ReasonTx)
	e.refuse(e.c, e.request("v-amt", in, at(0, 3000, 10_000, e.dest, 5_000_001), sol.PathHot, nil, nil, true), gateway.ReasonTx)
	// the value of the nonce changed (a new blockhash field): another nonce, not a version
	was := e.bh
	e.bh = st.NewKey().Pub
	e.refuse(e.c, e.request("v-value", in, at(0, 3000, 10_000, e.dest, 5_000_000), sol.PathHot, nil, nil, true), gateway.ReasonNonceChanged)
	// attacks on the nonce account next to the transfer: authority change and withdrawal
	e.bh = was
	authority := e.msg(st.AdvanceNonce(sol.NonceAddress(e.hot.Pub, 0), e.oth), st.SetLimit(10_000), st.SetPrice(3000), st.Transfer(e.hot.Pub, e.dest, 5_000_000))
	e.refuse(e.c, e.request("v-auth", in, authority, sol.PathHot, nil, nil, true), gateway.ReasonTx)
	for name, ix := range map[string]st.Ix{
		"withdraw nonce":  st.WithdrawNonce(sol.NonceAddress(e.hot.Pub, 0), e.oth, e.hot.Pub, 1_000_000),
		"authorize nonce": st.AuthorizeNonce(sol.NonceAddress(e.hot.Pub, 0), e.hot.Pub, e.oth),
	} {
		m := e.msg(e.adv(0), st.SetLimit(10_000), st.SetPrice(3000), st.Transfer(e.hot.Pub, e.dest, 5_000_000), ix)
		e.refuse(e.c, e.request("v-"+name, in, m, sol.PathHot, nil, nil, true), gateway.ReasonTx)
	}
	// B has not seen the first: it allows its own first message, once
	e.allow(e.b, e.request("w2", in, at(0, 1500, 10_000, e.dest, 5_000_000), sol.PathHot, nil, nil, true))
	e.refuse(e.b, e.request("w3", in, at(0, 1400, 10_000, e.dest, 5_000_000), sol.PathHot, nil, nil, true), gateway.ReasonFeeNotHigher)
}

// A different intent that names a nonce account and value another open intent holds is refused by B's cosigner and by C's, each from its own
// records: a bug that hands one nonce value to two withdrawals is stopped before anything is signed. The same message under another intent is
// refused as a digest that belongs to the first.
func TestCosignerSOLRefusesAnotherIntentOnAHeldNonce(t *testing.T) {
	e := newSOLEnv(t)
	in1, msg1 := e.wdSOL("wi1", 5_000_000)
	for _, c := range []*cosigner.Cosigner{e.b, e.c} {
		e.allow(c, e.request("first-"+fmt.Sprint(c == e.b), in1, msg1, sol.PathHot, nil, nil, true))
	}
	in2 := in1
	in2.ID = "wi2"
	other := e.msg(e.adv(0), st.SetLimit(10_000), st.SetPrice(2000), st.Transfer(e.hot.Pub, e.dest, 5_000_000))
	for _, c := range []*cosigner.Cosigner{e.b, e.c} {
		e.refuse(c, e.request("second", in2, other, sol.PathHot, nil, nil, true), gateway.ReasonNonceTaken)
		e.refuse(c, e.request("same-message", in2, msg1, sol.PathHot, nil, nil, true), gateway.ReasonIntentChanged)
	}
}

// Equal nonce values on two pool accounts are two nonces for B's cosigner and C's.
func TestCosignerSOLEqualValuesOnTwoAccountsAreTwoNonces(t *testing.T) {
	e := newSOLEnv(t)
	mk := func(id string, idx int, amount uint64) (signjob.Intent, []byte) {
		in, _ := e.wdSOL(id, amount)
		return in, e.msg(e.adv(idx), st.SetLimit(10_000), st.SetPrice(1000), st.Transfer(e.hot.Pub, e.dest, amount))
	}
	in1, m1 := mk("wi1", 0, 5_000_000)
	in2, m2 := mk("wi2", 1, 6_000_000)
	in3, m3 := mk("wi3", 1, 7_000_000)
	for _, c := range []*cosigner.Cosigner{e.b, e.c} {
		e.allow(c, e.request("a", in1, m1, sol.PathHot, nil, nil, true))
		e.allow(c, e.request("b", in2, m2, sol.PathHot, nil, nil, true))
		e.refuse(c, e.request("c", in3, m3, sol.PathHot, nil, nil, true), gateway.ReasonNonceTaken)
	}
}

// A batched sweep passes B's cosigner and C's for the hot shard's job and for each deposit key's job; the attacks on a batch are refused by both.
func TestCosignerSOLBatchedSweep(t *testing.T) {
	e := newSOLEnv(t)
	idxs := []uint32{3, 8, 9}
	var keys [][32]byte
	var addrs []string
	for _, ix := range idxs {
		c, _ := e.node.Public().Derive(sol.BranchExternal, ix)
		keys = append(keys, c.PublicKey)
		addrs = append(addrs, sol.Address(c.PublicKey))
	}
	mk := func(ixs ...st.Ix) []byte { return e.msg(append([]st.Ix{e.adv(1), st.SetLimit(30_000)}, ixs...)...) }
	good := mk(st.Transfer(keys[0], e.hot.Pub, 1_000_000), st.Transfer(keys[1], e.hot.Pub, 2_000_000), st.Transfer(keys[2], e.hot.Pub, 3_000_000))
	in := signjob.Intent{Kind: "sweep", ID: "sbatch", Asset: "SOL", PartitionID: solPart, From: strings.Join(addrs, ","), To: e.hot.Address(), Amount: "6000000"}
	req := func(id, path string, key []byte, in signjob.Intent, msg []byte, ix []uint32) wire.Request {
		in.Chain = solChain
		p, _ := json.Marshal(sol.Payload{Message: msg, DepositIndices: ix})
		j := signjob.Job{ID: id, PartitionID: solPart, KeyRef: path, Chain: solChain, Intent: mustJSON(in), Digest: msg, Payload: p}
		pkg, err := gateway.EncodePackage(j)
		if err != nil {
			t.Fatal(err)
		}
		return wire.Request{JobID: id, KeyID: "k", KeysetID: "ks", Algorithm: int32(pb.Algorithm_ALGORITHM_ED25519), Digest: msg, IntentPackage: pkg, PublicKey: key}
	}
	for _, c := range []*cosigner.Cosigner{e.b, e.c} {
		e.allow(c, req("hot", sol.PathHot, e.hot.Pub[:], in, good, idxs))
		for k, ix := range idxs {
			e.allow(c, req(fmt.Sprint("d", ix), sol.DepositPath(ix), keys[k][:], in, good, idxs))
		}
	}
	e2 := in
	e2.ID = "sbatch2"
	evil := mk(st.Transfer(keys[0], e.hot.Pub, 1_000_000), st.Transfer(keys[1], e.oth, 2_000_000), st.Transfer(keys[2], e.hot.Pub, 3_000_000))
	more := mk(st.Transfer(keys[0], e.hot.Pub, 1_000_001), st.Transfer(keys[1], e.hot.Pub, 2_000_000), st.Transfer(keys[2], e.hot.Pub, 3_000_000))
	for _, c := range []*cosigner.Cosigner{e.b, e.c} {
		e.refuse(c, req("evil", sol.PathHot, e.hot.Pub[:], e2, evil, idxs), gateway.ReasonTx)
		e.refuse(c, req("more", sol.PathHot, e.hot.Pub[:], e2, more, idxs), gateway.ReasonTx)
		raised := e.msg(e.adv(1), st.SetLimit(30_000), st.SetPrice(2000), st.Transfer(keys[0], e.hot.Pub, 1_000_000), st.Transfer(keys[1], e.hot.Pub, 2_000_000), st.Transfer(keys[2], e.hot.Pub, 3_000_000))
		e.refuse(c, req("wrongkey", sol.DepositPath(idxs[0]), keys[1][:], in, raised, idxs), "signer_key_mismatch")
		e.refuse(c, req("foreign", sol.DepositPath(77), keys[0][:], in, good, idxs), gateway.ReasonTx)
	}
}
