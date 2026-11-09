package cosigner_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"

	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
	"github.com/ws4charlie/quorum-vault/internal/cosigner"
	"github.com/ws4charlie/quorum-vault/internal/gateway"
	"github.com/ws4charlie/quorum-vault/internal/gateway/gatewaytest"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
	wire "github.com/ws4charlie/quorum-vault/mpc-party/api/cosigner"
	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

const btcChain = "btc-cos"

// btcEnv is a cosigner for a Bitcoin chain, driven by a rogue gateway: the test sends it whatever it likes, with the signing key it names.
type btcEnv struct {
	t       *testing.T
	c       *cosigner.Cosigner
	acct    *btc.Account
	priv    *hdkeychain.ExtendedKey
	appr    ed25519.PrivateKey
	hot0    string // partition part, [1,0]
	hot1    string // partition part1, [1,1]
	hotS    string // partition partS, [1,2]: a segregated client
	cold    string
	coldS   string
	other   string
	part    string
	part1   string
	partS   string
	xpubStr string // the account xpub
	// notAfter is the expiry of every withdrawal intent of this env, fixed once: a clock read per request would put a second boundary between two
	// requests of one job and give them different intent hashes.
	notAfter int64
}

func newBTCEnv(t *testing.T) *btcEnv {
	t.Helper()
	m, _ := hdkeychain.NewMaster(bytes.Repeat([]byte{5}, 32), &chaincfg.RegressionNetParams)
	k := m
	for _, n := range []uint32{hdkeychain.HardenedKeyStart + 84, hdkeychain.HardenedKeyStart + 1, hdkeychain.HardenedKeyStart} {
		k, _ = k.Derive(n)
	}
	xpub, _ := k.Neuter()
	acct, err := btc.NewAccount("regtest", xpub.String())
	if err != nil {
		t.Fatal(err)
	}
	e := &btcEnv{t: t, notAfter: time.Now().Add(time.Hour).Unix(), acct: acct, priv: k, part: "qv-us/btc-cos/BTC/hot/omnibus/0", part1: "qv-us/btc-cos/BTC/hot/segregated:beta/0", partS: "qv-us/btc-cos/BTC/hot/segregated:acme/0"}
	e.xpubStr = xpub.String()
	e.hot0, _ = acct.Address([]uint32{1, 0})
	e.hot1, _ = acct.Address([]uint32{1, 1})
	e.hotS, _ = acct.Address([]uint32{1, 2})
	o, _ := hdkeychain.NewMaster(bytes.Repeat([]byte{6}, 32), &chaincfg.RegressionNetParams)
	op, _ := o.Neuter()
	oa, _ := btc.NewAccount("regtest", op.String())
	e.other, _ = oa.Address([]uint32{0, 0})
	e.cold, _ = oa.Address([]uint32{0, 1})
	e.coldS, _ = oa.Address([]uint32{0, 2})
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	e.appr = priv
	f := gateway.File{
		Approvers: map[string]gateway.ApproverFile{"alice": {PublicKey: hex.EncodeToString(pub), Enabled: true}},
		Chains: map[string]gateway.ChainFile{btcChain: {Family: "btc", WithdrawalsPerHour: 100, SweepsPerHour: 100, CancelsPerHour: 100, ConsolidationsPerHour: 2,
			BTC: &gateway.BTCFile{Network: "regtest", AccountXpub: xpub.String(), MaxTxFeeSats: 50_000, MaxFeeRate: 1000, MaxInputs: 4,
				HotShards:     map[string]gateway.HotShardFile{e.part: {Address: e.hot0, Path: []uint32{1, 0}}, e.part1: {Address: e.hot1, Path: []uint32{1, 1}}, e.partS: {Address: e.hotS, Path: []uint32{1, 2}}},
				ColdAddresses: map[string]string{"omnibus/native": e.cold, "segregated:acme/native": e.coldS}},
			Assets: map[string]gateway.AssetFile{"BTC": {AnyDestination: true, PerTxCap: "100000000", DailyCap: "1000000000", Tiers: []gateway.TierFile{{MinAmount: "0", Approvals: 1}}}}}},
	}
	raw, _ := json.Marshal(f)
	cfg, err := gateway.ParseConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	pool, _ := gatewaytest.NewGuardDB(t)
	guard, err := gateway.OpenGuard(context.Background(), pool)
	if err != nil {
		t.Fatal(err)
	}
	if e.c, err = cosigner.New(cfg, guard, nil, nil); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *btcEnv) pubAt(path []uint32) []byte {
	k := e.priv
	for _, n := range path {
		k, _ = k.Derive(n)
	}
	p, _ := k.ECPubKey()
	return p.SerializeCompressed()
}

func bin(n int, value uint64, path ...uint32) btc.PayloadInput {
	var h [32]byte
	h[0], h[31] = byte(n), 0xCC
	return btc.PayloadInput{TxID: hex.EncodeToString(h[:]), Value: value, Path: path, Sequence: btc.SequenceRBF}
}

func (e *btcEnv) pay(a, b uint64, to string, change uint64) btc.Payload {
	return btc.Payload{Version: 2, Inputs: []btc.PayloadInput{bin(1, a, 1, 0), bin(2, b, 1, 0)},
		Outputs: []btc.PayloadOutput{{Address: to, Value: 100_000}, {Address: e.hot0, Value: change}}}
}

// request is what a rogue gateway sends party B for input i of p: the job, and the public key it says will sign.
func (e *btcEnv) request(id string, in signjob.Intent, p btc.Payload, i int, key []byte) wire.Request {
	e.t.Helper()
	if in.PartitionID == "" {
		in.PartitionID = e.part
	}
	in.Chain, in.Asset = btcChain, "BTC"
	if in.Kind == "withdrawal" {
		in.NotAfter = e.notAfter
	}
	u, err := btc.BuildUnsigned(p, e.acct)
	if err != nil {
		e.t.Fatal(err)
	}
	h := in.Hash()
	raw, _ := json.Marshal(p)
	jid := id
	if i > 0 {
		jid = fmt.Sprintf("%s.%d", id, i)
	}
	j := signjob.Job{ID: jid, PartitionID: in.PartitionID, KeyRef: btc.PathString(p.Inputs[i].Path), Chain: btcChain, Intent: mustJSON(in), Digest: u.Digests[i], Payload: raw,
		Approvals: []signjob.Approval{{Actor: "alice", Signature: ed25519.Sign(e.appr, h[:])}}}
	pkg, err := gateway.EncodePackage(j)
	if err != nil {
		e.t.Fatal(err)
	}
	if key == nil {
		key = e.pubAt(p.Inputs[i].Path)
	}
	return wire.Request{JobID: jid, KeyID: "k", KeysetID: "ks", Algorithm: int32(pb.Algorithm_ALGORITHM_ECDSA_SECP256K1), Digest: j.Digest, IntentPackage: pkg, PublicKey: key}
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

func (e *btcEnv) allow(r wire.Request) {
	e.t.Helper()
	if got := e.c.Decide(context.Background(), r); !got.Allow {
		e.t.Fatalf("job %s refused: %s", r.JobID, got.Reason)
	}
}

func (e *btcEnv) refuse(r wire.Request, code string) {
	e.t.Helper()
	got := e.c.Decide(context.Background(), r)
	if got.Allow || !strings.HasPrefix(got.Reason, code+":") {
		e.t.Fatalf("job %s: want refusal %q, got allow=%v reason=%q", r.JobID, code, got.Allow, got.Reason)
	}
}

func wd(id, to string) signjob.Intent {
	return signjob.Intent{Kind: "withdrawal", ID: id, To: to, Amount: "100000"}
}

// A correct two-input transaction passes party B's own checks.
func TestCosignerBTCTwoInputs(t *testing.T) {
	e := newBTCEnv(t)
	p := e.pay(150_000, 150_000, e.other, 180_000)
	e.allow(e.request("w1", wd("wi1", e.other), p, 0, nil))
	e.allow(e.request("w1", wd("wi1", e.other), p, 1, nil))
	e.allow(e.request("w1", wd("wi1", e.other), p, 1, nil)) // a retry of the same digest
}

// The rogue gateway names the wrong key: the key of input 1 for input 0. Party B's check is against the key derived from its own xpub.
func TestCosignerBTCRefusesAKeyThatIsNotTheInputs(t *testing.T) {
	e := newBTCEnv(t)
	p := e.pay(150_000, 150_000, e.other, 180_000)
	r := e.request("w1", wd("wi1", e.other), p, 0, e.pubAt([]uint32{1, 1}))
	if got := e.c.Decide(context.Background(), r); got.Allow || !strings.HasPrefix(got.Reason, "signer_key_mismatch") {
		t.Fatalf("%+v", got)
	}
	outside, _ := hdkeychain.NewMaster(bytes.Repeat([]byte{99}, 32), &chaincfg.RegressionNetParams)
	pk, _ := outside.ECPubKey()
	r = e.request("w1", wd("wi1", e.other), p, 0, pk.SerializeCompressed())
	if got := e.c.Decide(context.Background(), r); got.Allow || !strings.HasPrefix(got.Reason, "signer_key_mismatch") {
		t.Fatalf("a key outside the xpub: %+v", got)
	}
}

// The combined-signature fee attack against party B, with a gateway that skipped its own checks: the second signature is refused.
func TestCosignerBTCRefusesTheCombinedSignatureFeeAttack(t *testing.T) {
	for _, sameIntent := range []bool{true, false} {
		e := newBTCEnv(t)
		pA := e.pay(150_000, 70_000, e.other, 100_000)
		pB := e.pay(70_000, 150_000, e.other, 100_000)
		ia, ib := wd("wa", e.other), wd("wa", e.other)
		if !sameIntent {
			ib = wd("wb", e.other)
		}
		e.allow(e.request("a", ia, pA, 0, nil))
		e.refuse(e.request("b", ib, pB, 1, nil), gateway.ReasonPinChanged)
	}
}

// Other rogue payloads: a destination the approvers did not approve, change to a stranger, a fee above the cap, a deposit input.
func TestCosignerBTCRefusesRoguePayloads(t *testing.T) {
	e := newBTCEnv(t)
	good := e.pay(150_000, 150_000, e.other, 180_000)
	in := wd("w1", e.other)

	evil := good
	evil.Outputs = []btc.PayloadOutput{{Address: e.hot1, Value: 100_000}, good.Outputs[1]} // paid to our own shard instead
	e.refuse(e.request("x1", in, evil, 0, nil), gateway.ReasonTx)

	stranger := good
	stranger.Outputs = []btc.PayloadOutput{good.Outputs[0], {Address: e.other, Value: 180_000}}
	e.refuse(e.request("x2", in, stranger, 0, nil), gateway.ReasonTx)

	rich := good
	rich.Outputs = []btc.PayloadOutput{good.Outputs[0], {Address: e.hot0, Value: 100_000}} // fee 100_000
	e.refuse(e.request("x3", in, rich, 0, nil), gateway.ReasonTx)

	dep := good
	dep.Inputs = []btc.PayloadInput{bin(1, 150_000, 1, 0), bin(2, 150_000, 0, 5)}
	e.refuse(e.request("x4", in, dep, 0, nil), gateway.ReasonTx)
}

// Party B binds every intent kind to its partition from its own config, whatever the gateway says.
func TestCosignerBTCBindsIntentsToTheirPartition(t *testing.T) {
	e := newBTCEnv(t)
	seg := []btc.PayloadInput{bin(1, 150_000, 1, 2), bin(2, 150_000, 1, 2)} // the segregated client's key
	for n, kind := range []string{"withdrawal", "to-cold"} {
		to := map[string]string{"withdrawal": e.other, "to-cold": e.cold}[kind]
		p := e.pay(150_000, 150_000, to, 180_000)
		p.Inputs = seg
		in := signjob.Intent{Kind: kind, ID: fmt.Sprintf("b%d", n), To: to, Amount: "100000"}
		e.refuse(e.request(fmt.Sprintf("seg%d", n), in, p, 0, nil), gateway.ReasonTx)
	}
	p := e.pay(150_000, 150_000, e.coldS, 180_000)
	e.refuse(e.request("tc", signjob.Intent{Kind: "to-cold", ID: "tc1", To: e.coldS, Amount: "100000"}, p, 0, nil), gateway.ReasonTx) // another pool's cold address
	p = e.pay(150_000, 150_000, e.other, 180_000)
	p.Outputs[1].Address = e.hot1 // change to another shard
	e.refuse(e.request("chg", wd("chg1", e.other), p, 0, nil), gateway.ReasonTx)
	sw := btc.Payload{Version: 2, Inputs: []btc.PayloadInput{bin(30, 50_000, 0, 5)}, Outputs: []btc.PayloadOutput{{Address: e.hot1, Value: 49_000}}}
	dep, _ := e.acct.Address([]uint32{0, 5})
	e.refuse(e.request("sw", signjob.Intent{Kind: "sweep", ID: "sw1", From: dep, To: e.hot1, Amount: "50000"}, sw, 0, nil), gateway.ReasonTx)
	cp := btc.Payload{Version: 2, Inputs: []btc.PayloadInput{bin(31, 50_000, 1, 0)}, Outputs: []btc.PayloadOutput{{Address: e.hot1, Value: 49_000}}}
	e.refuse(e.request("cx", signjob.Intent{Kind: "cancel", ID: "cx1", To: e.hot1, Amount: "0"}, cp, 0, nil), gateway.ReasonTx)
}

// The cosigner reads the same signing-zone config as the gateway: two hot shards in one pool refuse to start, naming the pool.
func TestCosignerBTCRefusesTwoHotShardsInOnePool(t *testing.T) {
	e := newBTCEnv(t)
	f := gateway.File{
		Approvers: map[string]gateway.ApproverFile{"alice": {PublicKey: hex.EncodeToString(make([]byte, 32)), Enabled: true}},
		Chains: map[string]gateway.ChainFile{btcChain: {Family: "btc", WithdrawalsPerHour: 100,
			BTC: &gateway.BTCFile{Network: "regtest", AccountXpub: e.xpubStr, MaxTxFeeSats: 50_000, MaxFeeRate: 1000, MaxInputs: 4,
				HotShards: map[string]gateway.HotShardFile{e.part: {Address: e.hot0, Path: []uint32{1, 0}}, "qv-us/btc-cos/BTC/hot/omnibus/1": {Address: e.hot1, Path: []uint32{1, 1}}}},
			Assets: map[string]gateway.AssetFile{"BTC": {AnyDestination: true, PerTxCap: "1", DailyCap: "1", Tiers: []gateway.TierFile{{MinAmount: "0", Approvals: 1}}}}}},
	}
	raw, _ := json.Marshal(f)
	if _, err := gateway.ParseConfig(raw); err == nil || !strings.Contains(err.Error(), `pool "omnibus" has two hot shards`) {
		t.Fatalf("two hot shards in the omnibus pool: %v", err)
	}
}

// Bitcoin has no move between hot shards: a rogue gateway's rebalance is refused by party B whatever it pays and to whom.
func TestCosignerBTCRefusesRebalance(t *testing.T) {
	e := newBTCEnv(t)
	for n, to := range []string{e.hot1, e.hotS, e.hot0, e.cold, e.other} {
		p := e.pay(150_000, 150_000, to, 180_000)
		e.refuse(e.request(fmt.Sprintf("rb%d", n), signjob.Intent{Kind: "rebalance", ID: fmt.Sprintf("rb%d", n), To: to, Amount: "100000"}, p, 0, nil), gateway.ReasonTx)
	}
}

// A cancel needs no approval, so party B refuses one that spends anything an attempt did not claim.
func TestCosignerBTCCancelMayOnlySpendWhatIsClaimed(t *testing.T) {
	e := newBTCEnv(t)
	cancel := func(inputs []btc.PayloadInput, id string, key []byte) wire.Request {
		var sum uint64
		for _, in := range inputs {
			sum += in.Value
		}
		p := btc.Payload{Version: 2, Inputs: inputs, Outputs: []btc.PayloadOutput{{Address: e.hot0, Value: sum - 10_000}}}
		return e.request(id, signjob.Intent{Kind: "cancel", ID: "cancel-" + id, To: e.hot0, Amount: "0"}, p, 0, key)
	}
	e.refuse(cancel([]btc.PayloadInput{bin(50, 80_000, 0, 5)}, "k1", nil), gateway.ReasonCancelClaims) // a deposit output nobody claimed
	pa := e.pay(150_000, 150_000, e.other, 180_000)
	e.allow(e.request("wa", wd("wa", e.other), pa, 0, nil))
	e.allow(e.request("wa", wd("wa", e.other), pa, 1, nil))
	pb := btc.Payload{Version: 2, Inputs: []btc.PayloadInput{bin(3, 150_000, 1, 0), bin(4, 150_000, 1, 0)}, Outputs: []btc.PayloadOutput{{Address: e.other, Value: 100_000}, {Address: e.hot0, Value: 180_000}}}
	e.allow(e.request("wb", wd("wb", e.other), pb, 0, nil))
	e.refuse(cancel([]btc.PayloadInput{pa.Inputs[0], pb.Inputs[0]}, "k2", nil), gateway.ReasonCancelClaims) // claims of two intents
	e.refuse(cancel(pa.Inputs[:1], "k3", nil), gateway.ReasonCancelClaims)                                  // one input left out
	e.refuse(cancel([]btc.PayloadInput{pa.Inputs[0], bin(52, 150_000, 1, 0)}, "k4", nil), gateway.ReasonCancelClaims)
	pin := []btc.PayloadInput{pa.Inputs[0], pa.Inputs[1]}
	pin[1].Value = 100_000
	e.refuse(cancel(pin, "k5", nil), gateway.ReasonPinChanged)
	e.allow(cancel(pa.Inputs, "k6", nil)) // exactly the attempt's inputs, to the partition's own shard
}

// consolidation is a consolidation of the omnibus shard: n inputs of 30,000 sats, one output back to the shard, a fee of 1,000 sats.
func (e *btcEnv) consolidation(id string, base, n int) (btc.Payload, signjob.Intent) {
	p := btc.Payload{Version: 2}
	var sum uint64
	for i := 0; i < n; i++ {
		p.Inputs = append(p.Inputs, bin(base+i, 30_000, 1, 0))
		sum += 30_000
	}
	p.Outputs = []btc.PayloadOutput{{Address: e.hot0, Value: sum - 1_000}}
	return p, signjob.Intent{Kind: "consolidate", ID: id, To: e.hot0, Amount: fmt.Sprint(sum)}
}

// Party B checks a consolidation from its own config and store: the shard's own outputs back to the shard, the amount the sum of the inputs, at most
// consolidations_per_hour new ones in an hour, whatever the gateway says.
func TestCosignerBTCConsolidation(t *testing.T) {
	e := newBTCEnv(t)
	p, in := e.consolidation("co1", 60, 3)
	for i := range p.Inputs {
		e.allow(e.request("co1", in, p, i, nil))
	}

	n := 0
	attack := func(name string, change func(p *btc.Payload, in *signjob.Intent)) {
		t.Helper()
		n++
		bp, bin := e.consolidation(fmt.Sprintf("x%d", n), 100+n*10, 3)
		change(&bp, &bin)
		e.refuse(e.request(fmt.Sprintf("x%d", n), bin, bp, 0, nil), gateway.ReasonTx)
		_ = name
	}
	attack("output to any other address", func(p *btc.Payload, _ *signjob.Intent) { p.Outputs[0].Address = e.other })
	attack("output to the cold address", func(p *btc.Payload, _ *signjob.Intent) { p.Outputs[0].Address = e.cold })
	attack("output to another partition's shard", func(p *btc.Payload, _ *signjob.Intent) { p.Outputs[0].Address = e.hot1 })
	attack("the intent names another address", func(_ *btc.Payload, in *signjob.Intent) { in.To = e.other })
	attack("a second output", func(p *btc.Payload, _ *signjob.Intent) {
		p.Outputs = []btc.PayloadOutput{{Address: e.hot0, Value: 40_000}, {Address: e.other, Value: 49_000}}
	})
	attack("one input", func(p *btc.Payload, in *signjob.Intent) {
		p.Inputs, p.Outputs, in.Amount = p.Inputs[:1], []btc.PayloadOutput{{Address: e.hot0, Value: 29_000}}, "30000"
	})
	attack("an input from another partition", func(p *btc.Payload, _ *signjob.Intent) { p.Inputs[1] = bin(1, 30_000, 1, 1) })
	attack("an input from a deposit address", func(p *btc.Payload, _ *signjob.Intent) { p.Inputs[1] = bin(2, 30_000, 0, 5) })
	attack("an input at a hot key that no shard pins", func(p *btc.Payload, _ *signjob.Intent) { p.Inputs[1].Path = []uint32{1, 7} })
	attack("an amount that is not the sum", func(_ *btc.Payload, in *signjob.Intent) { in.Amount = "89999" })
	attack("a fee above the cap", func(p *btc.Payload, _ *signjob.Intent) { p.Outputs[0].Value = 90_000 - 60_000 })

	// The hourly limit is the cosigner's own (2): the first one above, a second, then a third is refused; a fee bump of the first is not counted again.
	p2, i2 := e.consolidation("co2", 200, 2)
	e.allow(e.request("co2", i2, p2, 0, nil))
	p3, i3 := e.consolidation("co3", 210, 2)
	e.refuse(e.request("co3", i3, p3, 0, nil), gateway.ReasonConsolidateRate)
	bump := p
	bump.Outputs = []btc.PayloadOutput{{Address: e.hot0, Value: p.Outputs[0].Value - 500}}
	e.allow(e.request("co1b", in, bump, 0, nil))
}
