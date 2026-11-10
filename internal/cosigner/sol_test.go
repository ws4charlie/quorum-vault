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
				MaxComputeUnits: 200_000, MaxMicroLamportsPerUnit: 100_000, MaxPriorityFeeLamports: 15_000},
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

func (e *solEnv) wdSOL(id string, amount uint64) (signjob.Intent, []byte) {
	return signjob.Intent{Kind: "withdrawal", ID: id, Asset: "SOL", PartitionID: solPart, To: sol.Address(e.dest), Amount: fmt.Sprint(amount), NotAfter: e.notAfter},
		e.msg(st.SetLimit(10_000), st.Transfer(e.hot.Pub, e.dest, amount))
}

// request is what a rogue gateway sends party B (or C) for a job, with the public key it says will sign.
func (e *solEnv) request(id string, in signjob.Intent, msg []byte, keyPath string, dep *uint32, key []byte, approve bool) wire.Request {
	e.t.Helper()
	in.Chain = solChain
	if in.PartitionID == "" {
		in.PartitionID = solPart
	}
	p, _ := json.Marshal(sol.Payload{Message: msg, DepositIndex: dep})
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
	smsg := e.msg(st.SetLimit(10_000), st.Transfer(e.depKey, e.hot.Pub, 3_000_000))
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
	badDest := e.msg(st.SetLimit(10_000), st.Transfer(e.hot.Pub, e.oth, 5_000_000))
	moreAmt := e.msg(st.SetLimit(10_000), st.Transfer(e.hot.Pub, e.dest, 6_000_000))
	extra := e.msg(st.SetLimit(10_000), st.Transfer(e.hot.Pub, e.dest, 5_000_000), st.Transfer(e.hot.Pub, e.oth, 1))
	pricey := e.msg(st.SetLimit(10_000), st.SetPrice(100_001), st.Transfer(e.hot.Pub, e.dest, 5_000_000))
	otherPayer := st.Compile(e.oth, e.bh, st.SetLimit(10_000), st.Transfer(e.oth, e.dest, 5_000_000))
	in2 := in
	in2.Amount = "5000001"
	notListed := in
	notListed.To = sol.Address(e.oth)
	setAuth := st.Ix{Program: st.CloseAccount(e.hot.Pub, e.hot.Pub, e.hot.Pub).Program, Accts: []st.Meta{{Key: e.hot.Pub, Signer: true, Writable: true}}, Data: []byte{6, 2, 1, 9, 9}}
	sweepIn := signjob.Intent{Kind: "sweep", ID: "si1", Asset: "SOL", PartitionID: solPart, From: sol.Address(e.depKey), To: e.hot.Address(), Amount: "3000000"}
	sweepMsg := e.msg(st.SetLimit(10_000), st.Transfer(e.depKey, e.hot.Pub, 3_000_000))
	sweepEvil := e.msg(st.SetLimit(10_000), st.Transfer(e.depKey, e.oth, 3_000_000))
	tokIn := signjob.Intent{Kind: "withdrawal", ID: "ti1", Asset: "TKN", PartitionID: solTok, To: sol.Address(e.dest), Amount: "777", NotAfter: e.notAfter}
	tokBad := e.msg(st.SetLimit(50_000), st.CheckedTransfer(st.ATAOf(e.hot.Pub, e.mint), e.mint, st.ATAOf(e.oth, e.mint), e.hot.Pub, 777, 6))
	tokDec := e.msg(st.SetLimit(50_000), st.CheckedTransfer(st.ATAOf(e.hot.Pub, e.mint), e.mint, st.ATAOf(e.dest, e.mint), e.hot.Pub, 777, 9))
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
			m := e.msg(st.SetLimit(10_000), st.Transfer(e.hot.Pub, e.oth, 5_000_000))
			return e.request("a7", notListed, m, sol.PathHot, nil, nil, true)
		}, gateway.ReasonDestination},
		{"an amount the approval does not cover", func() wire.Request { return e.request("a8", in2, msg, sol.PathHot, nil, nil, true) }, gateway.ReasonTx},
		{"setAuthority next to the transfer", func() wire.Request {
			return e.request("a9", in, e.msg(st.SetLimit(10_000), st.Transfer(e.hot.Pub, e.dest, 5_000_000), setAuth), sol.PathHot, nil, nil, true)
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

// The cosigner keeps what it allowed: another message for an intent it allowed is refused, whatever the gateway says.
func TestCosignerSOLRefusesASecondMessageForAnIntent(t *testing.T) {
	e := newSOLEnv(t)
	in, msg := e.wdSOL("wi1", 5_000_000)
	e.allow(e.c, e.request("w1", in, msg, sol.PathHot, nil, nil, true))
	e.bh = st.NewKey().Pub
	_, msg2 := e.wdSOL("wi1", 5_000_000)
	e.refuse(e.c, e.request("w2", in, msg2, sol.PathHot, nil, nil, true), gateway.ReasonFeeNotHigher)
	// B's cosigner has not seen the first: it allows its own first message, once
	e.allow(e.b, e.request("w2", in, msg2, sol.PathHot, nil, nil, true))
}
