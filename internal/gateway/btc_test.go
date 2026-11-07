package gateway

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
	"github.com/ws4charlie/quorum-vault/internal/domain"
	"github.com/ws4charlie/quorum-vault/internal/signer"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

const (
	btcChain     = "btc-test"
	btcPartition = "qv-us/btc-test/BTC/hot/omnibus/0"
	btcPart1     = "qv-us/btc-test/BTC/hot/segregated:beta/0" // a hot shard of another pool
	btcPartSeg   = "qv-us/btc-test/BTC/hot/segregated:acme/0" // a segregated client's shard
)

// softTree is a signer for a key tree held in software, standing in for mpc-party's derive-on-demand signer in tests.
type softTree struct {
	acct  *hdkeychain.ExtendedKey // private account key
	calls atomic.Int32
}

func (s *softTree) Backend() domain.Backend     { return domain.BackendMPC }
func (s *softTree) Key() domain.Key             { return domain.Key{ID: btcPartition} }
func (s *softTree) PublicKey() *ecdsa.PublicKey { return nil }
func (s *softTree) SignDigest(context.Context, [32]byte, signer.SignOptions) (signer.Result, error) {
	return signer.Result{}, fmt.Errorf("a key tree signs through At")
}
func (s *softTree) At(_ context.Context, path []uint32) (signer.Signer, error) {
	k := s.acct
	for _, n := range path {
		var err error
		if k, err = k.Derive(n); err != nil {
			return nil, err
		}
	}
	priv, err := k.ECPrivKey()
	if err != nil {
		return nil, err
	}
	return &softKey{key: priv.ToECDSA(), calls: &s.calls}, nil
}

type softKey struct {
	key   *ecdsa.PrivateKey
	calls *atomic.Int32
}

func (k *softKey) Backend() domain.Backend     { return domain.BackendMPC }
func (k *softKey) Key() domain.Key             { return domain.Key{} }
func (k *softKey) PublicKey() *ecdsa.PublicKey { return &k.key.PublicKey }
func (k *softKey) SignDigest(_ context.Context, d [32]byte, _ signer.SignOptions) (signer.Result, error) {
	k.calls.Add(1)
	sig, err := crypto.Sign(d[:], k.key)
	if err != nil {
		return signer.Result{}, err
	}
	return signer.Result{Sig: signer.NormalizeLowS(signer.Signature{R: new(big.Int).SetBytes(sig[:32]), S: new(big.Int).SetBytes(sig[32:64])})}, nil
}

// btcH is a gateway that also serves a Bitcoin chain whose keys are a software tree.
type btcH struct {
	*harness
	gw    *Gateway
	tree  *softTree
	acct  *btc.Account
	hot0  string // partition btcPartition, [1,0]
	hot1  string // btcPart1, [1,1]
	hotS  string // btcPartSeg, [1,2]
	cold  string
	coldS string
	other string // a regtest P2WPKH nobody pinned
	dep   string // [0,5]
	seq   int
}

func foreignAddr(seed byte) string {
	m, _ := hdkeychain.NewMaster(bytes.Repeat([]byte{seed}, 32), &chaincfg.RegressionNetParams)
	pub, _ := m.Neuter()
	a, _ := btc.NewAccount("regtest", pub.String())
	s, _ := a.Address([]uint32{0, 0})
	return s
}

func newBTCHarness(t *testing.T) *btcH {
	t.Helper()
	h := newHarness(t)
	ctx := context.Background()
	m, err := hdkeychain.NewMaster(bytes.Repeat([]byte{3}, 32), &chaincfg.RegressionNetParams)
	if err != nil {
		t.Fatal(err)
	}
	acctPriv := m
	for _, n := range []uint32{hdkeychain.HardenedKeyStart + 84, hdkeychain.HardenedKeyStart + 1, hdkeychain.HardenedKeyStart} {
		if acctPriv, err = acctPriv.Derive(n); err != nil {
			t.Fatal(err)
		}
	}
	xpub, _ := acctPriv.Neuter()
	acct, err := btc.NewAccount("regtest", xpub.String())
	if err != nil {
		t.Fatal(err)
	}
	b := &btcH{harness: h, tree: &softTree{acct: acctPriv}, acct: acct, cold: foreignAddr(9), coldS: foreignAddr(11), other: foreignAddr(10)}
	b.hot0, _ = acct.Address([]uint32{1, 0})
	b.hot1, _ = acct.Address([]uint32{1, 1})
	b.hotS, _ = acct.Address([]uint32{1, 2})
	b.dep, _ = acct.Address([]uint32{0, 5})

	cf := ChainFile{Family: "btc", WithdrawalsPerHour: 1000, SweepsPerHour: 1000, CancelsPerHour: 1000, ToColdPerHour: 1000, ConsolidationsPerHour: 2,
		BTC: &BTCFile{Network: "regtest", AccountXpub: xpub.String(), MaxTxFeeSats: 50_000, MaxFeeRate: 1000, MaxInputs: 4,
			HotShards: map[string]HotShardFile{btcPartition: {Address: b.hot0, Path: []uint32{1, 0}}, btcPart1: {Address: b.hot1, Path: []uint32{1, 1}},
				btcPartSeg: {Address: b.hotS, Path: []uint32{1, 2}}},
			ColdAddresses: map[string]string{"omnibus/native": b.cold, "segregated:acme/native": b.coldS}},
		Assets: map[string]AssetFile{"BTC": {AnyDestination: true, PerTxCap: "100000000", DailyCap: "1000000000", Tiers: []TierFile{{"0", 1}},
			ToColdDailyCap: "1000000000"}}}
	cc, err := cf.build(btcChain, 4)
	if err != nil {
		t.Fatal(err)
	}
	h.cfg.Chains[btcChain] = cc
	for _, q := range []string{
		`INSERT INTO assets (chain, symbol, decimals) VALUES ('` + btcChain + `','BTC',8)`,
		`INSERT INTO partitions (id, entity, chain, asset, tier, pool, shard) VALUES ('` + btcPartition + `','qv-us','` + btcChain + `','BTC','hot','omnibus',0)`,
		`INSERT INTO partitions (id, entity, chain, asset, tier, pool, shard) VALUES ('` + btcPart1 + `','qv-us','` + btcChain + `','BTC','hot','segregated:beta',0)`,
		`INSERT INTO partitions (id, entity, chain, asset, tier, pool, shard) VALUES ('` + btcPartSeg + `','qv-us','` + btcChain + `','BTC','hot','segregated:acme',0)`,
	} {
		if _, err := h.biz.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	codecs, err := NewCodecs(h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	gw, err := New(h.cfg, codecs, map[string]signer.Signer{btcPartition: b.tree, btcPart1: b.tree, btcPartSeg: b.tree}, h.guard, h.biz, Options{WorkerID: "btc-w", Lease: time.Minute, Now: h.clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { gw.Wait(10 * time.Second) })
	b.gw = gw
	return b
}

func btcIn(n int, vout uint32, value uint64, path ...uint32) btc.PayloadInput {
	var h [32]byte
	h[0], h[31] = byte(n), 0xBB
	return btc.PayloadInput{TxID: hex.EncodeToString(h[:]), Vout: vout, Value: value, Path: path, Sequence: btc.SequenceRBF}
}

// jobs builds one sign job per input of p, as the business zone would (job IDs id, id.1, ...), for intent in.
func (b *btcH) jobs(id string, in signjob.Intent, p btc.Payload, approvers ...string) []signjob.Job {
	b.t.Helper()
	if in.Chain == "" {
		in.Chain = btcChain
	}
	if in.PartitionID == "" {
		in.PartitionID = btcPartition
	}
	if in.Asset == "" {
		in.Asset = "BTC"
	}
	if in.Kind == "withdrawal" && in.NotAfter == 0 {
		in.NotAfter = b.clock().Add(time.Hour).Unix()
	}
	u, err := btc.BuildUnsigned(p, b.acct)
	if err != nil {
		b.t.Fatal(err)
	}
	raw, _ := json.Marshal(p)
	var out []signjob.Job
	for i := range p.Inputs {
		jid := id
		if i > 0 {
			jid = fmt.Sprintf("%s.%d", id, i)
		}
		out = append(out, signjob.Job{ID: jid, PartitionID: in.PartitionID, KeyRef: btc.PathString(p.Inputs[i].Path), Chain: btcChain, Intent: mustJSON(in),
			Digest: u.Digests[i], Payload: raw, Approvals: b.approvals(in, approvers...)})
	}
	return out
}

func (b *btcH) run(j signjob.Job) Decision { return b.harness.runWith(b.gw, j) }

func (b *btcH) mustSignAll(js []signjob.Job) {
	b.t.Helper()
	for _, j := range js {
		if d := b.run(j); d.Outcome != OutcomeSigned && d.Outcome != OutcomeReplayed {
			b.t.Fatalf("job %s: %s %s", j.ID, d.Outcome, d.Reason)
		}
	}
}

func (b *btcH) mustRefuse(j signjob.Job, code string) {
	b.t.Helper()
	before := b.tree.calls.Load()
	d := b.run(j)
	if d.Outcome != OutcomeRejected || !strings.HasPrefix(d.Reason, code+":") {
		b.t.Fatalf("job %s: %s %q, want rejected %s", j.ID, d.Outcome, d.Reason, code)
	}
	if b.tree.calls.Load() != before {
		b.t.Fatalf("job %s: a key signed a refused job", j.ID)
	}
}

func wdIntent(id, to string, amount uint64) signjob.Intent {
	return signjob.Intent{Kind: "withdrawal", ID: id, Asset: "BTC", To: to, Amount: fmt.Sprint(amount)}
}

// twoInputs is the transaction every guard test builds on: two inputs of the partition's own shard, of 150_000 sats, paying 100_000 to dest and 100_000 change.
func (b *btcH) twoInputs(valueA, valueB uint64, dest string, change uint64) btc.Payload {
	return btc.Payload{Version: 2, Inputs: []btc.PayloadInput{btcIn(1, 0, valueA, 1, 0), btcIn(2, 0, valueB, 1, 0)},
		Outputs: []btc.PayloadOutput{{Address: dest, Value: 100_000}, {Address: b.hot0, Value: change}}}
}

// A correct two-input transaction signs both inputs, each under its own key, and the signatures are for the two digests.
func TestBTCTwoInputTransactionSigns(t *testing.T) {
	b := newBTCHarness(t)
	p := b.twoInputs(150_000, 150_000, b.other, 180_000)
	js := b.jobs("w1", wdIntent("wi1", b.other, 100_000), p, "auto")
	b.mustSignAll(js)
	if n := b.tree.calls.Load(); n != 2 {
		t.Fatalf("%d signatures for two inputs", n)
	}
}

// The segwit v0 fee attack: BIP143 commits an input's signature to that input's own value only. Input A is signed under a payload that
// understates B, input B under one that understates A; both pass every check alone, and both signatures are valid for the one real transaction,
// whose fee neither payload shows. The second signature is refused, whatever the order, and also with a second intent.
func TestBTCCombinedSignatureFeeAttack(t *testing.T) {
	// Real values 150_000 and 150_000, outputs 200_000: the real fee is 100_000, over the 50_000 cap.
	attack := func(t *testing.T, sameIntent bool) {
		b := newBTCHarness(t)
		pA := b.twoInputs(150_000, 70_000, b.other, 99_000) // A real, B understated: fee 20_000
		pB := b.twoInputs(70_000, 150_000, b.other, 99_000) // B real, A understated: fee 20_000
		for _, p := range []btc.Payload{pA, pB} {
			if err := b.gw.cfg.Chains[btcChain].BTC.MaxTxFeeSats; err < 20_000 {
				t.Fatal("cap")
			}
			_ = p
		}
		inA := wdIntent("wa", b.other, 100_000)
		inB := inA
		if !sameIntent {
			inB = wdIntent("wb", b.other, 100_000)
		}
		ja := b.jobs("a", inA, pA, "auto")
		jb := b.jobs("b", inB, pB, "auto")
		// Both transactions have one txid: the txid does not commit to the values.
		ua, _ := btc.BuildUnsigned(pA, b.acct)
		ub, _ := btc.BuildUnsigned(pB, b.acct)
		if ua.TxID != ub.TxID {
			t.Fatal("the two payloads were meant to be one transaction")
		}
		if d := b.run(ja[0]); d.Outcome != OutcomeSigned { // input A under payload A
			t.Fatalf("first signature: %s %s", d.Outcome, d.Reason)
		}
		b.mustRefuse(jb[1], ReasonPinChanged) // input B under payload B: claim A would now be pinned to 70_000
	}
	t.Run("one intent", func(t *testing.T) { attack(t, true) })
	t.Run("two intents", func(t *testing.T) { attack(t, false) })

	t.Run("reversed order", func(t *testing.T) {
		b := newBTCHarness(t)
		pA := b.twoInputs(150_000, 70_000, b.other, 100_000)
		pB := b.twoInputs(70_000, 150_000, b.other, 100_000)
		in := wdIntent("wa", b.other, 100_000)
		ja, jb := b.jobs("a", in, pA, "auto"), b.jobs("b", in, pB, "auto")
		if d := b.run(jb[1]); d.Outcome != OutcomeSigned {
			t.Fatalf("%s %s", d.Outcome, d.Reason)
		}
		b.mustRefuse(ja[0], ReasonPinChanged)
	})
}

// The transaction identity alone: same txid, same values, but another payload (the first input claimed under another of our keys, so another
// digest and another payload hash). Only a cancel may name inputs under any path, so the attempt is a cancel. It is not a replacement, because
// a replacement is a new transaction.
func TestBTCSameTxidOtherPayloadIsRefused(t *testing.T) {
	b := newBTCHarness(t)
	p := b.twoInputs(150_000, 150_000, b.other, 180_000)
	win := wdIntent("w1", b.other, 100_000)
	b.mustSignAll(b.jobs("w1", win, p, "auto"))
	cancel := btc.Payload{Version: 2, Inputs: p.Inputs, Outputs: []btc.PayloadOutput{{Address: b.hot0, Value: 280_000}}}
	cin := signjob.Intent{Kind: "cancel", ID: "cancel-w1", PartitionID: btcPartition, Chain: btcChain, Asset: "BTC", To: b.hot0, Amount: "0"}
	if d := b.run(b.jobs("c1", cin, cancel)[0]); d.Outcome != OutcomeSigned {
		t.Fatalf("%s %s", d.Outcome, d.Reason)
	}
	q := cancel
	q.Inputs = append([]btc.PayloadInput{}, cancel.Inputs...)
	q.Inputs[0].Path = []uint32{0, 5} // the same outpoint, claimed under another key
	b.mustRefuse(b.jobs("c2", cin, q)[1], ReasonIdentity)
}

// Outpoints are exclusive across intents, and an intent has only one transaction unless a replacement spends exactly the same inputs for more fee.
func TestBTCClaimsAndReplacements(t *testing.T) {
	b := newBTCHarness(t)
	p := b.twoInputs(150_000, 150_000, b.other, 180_000) // inputs 300_000, outputs 280_000: fee 20_000
	in := wdIntent("w1", b.other, 100_000)
	first := b.jobs("w1", in, p, "auto")
	b.mustSignAll(first)

	// Another intent spending one of the same outpoints.
	p2 := btc.Payload{Version: 2, Inputs: []btc.PayloadInput{btcIn(1, 0, 150_000, 1, 0)}, Outputs: []btc.PayloadOutput{{Address: b.other, Value: 100_000}, {Address: b.hot0, Value: 40_000}}}
	b.mustRefuse(b.jobs("x", wdIntent("w2", b.other, 100_000), p2, "auto")[0], ReasonNonceTaken)

	// A replacement of intent w1 with different inputs, with one input fewer, with a lower or equal fee.
	other := p
	other.Inputs = append([]btc.PayloadInput{}, p.Inputs...)
	other.Inputs[1] = btcIn(9, 0, 150_000, 1, 0)
	other.Outputs = []btc.PayloadOutput{p.Outputs[0], {Address: b.hot0, Value: 170_000}}
	b.mustRefuse(b.jobs("r1", in, other, "auto")[0], ReasonNonceChanged)
	fewer := btc.Payload{Version: 2, Inputs: p.Inputs[:1], Outputs: []btc.PayloadOutput{p.Outputs[0], {Address: b.hot0, Value: 40_000}}}
	b.mustRefuse(b.jobs("r2", in, fewer, "auto")[0], ReasonNonceChanged)
	lower := p
	lower.Outputs = []btc.PayloadOutput{p.Outputs[0], {Address: b.hot0, Value: 181_000}}
	b.mustRefuse(b.jobs("r3", in, lower, "auto")[0], ReasonFeeNotHigher)
	same := p
	same.Outputs = []btc.PayloadOutput{p.Outputs[0], {Address: b.hot0, Value: 180_000}}
	same.Inputs = append([]btc.PayloadInput{}, p.Inputs...)
	// the same payload again is the same digest: a replay, not a replacement
	if d := b.run(b.jobs("r3b", in, same, "auto")[0]); d.Outcome != OutcomeReplayed {
		t.Fatalf("the same digest again: %s %s", d.Outcome, d.Reason)
	}
	// A replacement over the same inputs, same destination and amount, for a higher fee: signed, both inputs.
	higher := p
	higher.Outputs = []btc.PayloadOutput{p.Outputs[0], {Address: b.hot0, Value: 175_000}}
	b.mustSignAll(b.jobs("r4", in, higher, "auto"))
	// ... and changing the destination or the amount is a different intent hash: refused.
	moved := higher
	moved.Outputs = []btc.PayloadOutput{{Address: b.cold, Value: 100_000}, {Address: b.hot0, Value: 170_000}}
	b.mustRefuse(b.jobs("r5", wdIntent("w1", b.cold, 100_000), moved, "auto")[0], ReasonIntentChanged)
}

// A cancel takes over the claims of the attempt it frees, with the same pins, and then the attempt cannot be signed any more.
func TestBTCCancelTakesTheClaims(t *testing.T) {
	b := newBTCHarness(t)
	p := b.twoInputs(150_000, 150_000, b.other, 180_000)
	in := wdIntent("w1", b.other, 100_000)
	js := b.jobs("w1", in, p, "auto")
	if d := b.run(js[0]); d.Outcome != OutcomeSigned { // input 0 signed, input 1 never was
		t.Fatalf("%s %s", d.Outcome, d.Reason)
	}
	cancel := btc.Payload{Version: 2, Inputs: p.Inputs, Outputs: []btc.PayloadOutput{{Address: b.hot0, Value: 280_000}}}
	cin := signjob.Intent{Kind: "cancel", ID: "cancel-w1", PartitionID: btcPartition, Chain: btcChain, Asset: "BTC", To: b.hot0, Amount: "0"}
	b.mustSignAll(b.jobs("c1", cin, cancel))
	// The half-signed withdrawal can no longer be finished.
	b.mustRefuse(js[1], ReasonNonceCancel)
	// A cancel with the right inputs but another value for one of them is a pin conflict.
	bad := cancel
	bad.Inputs = append([]btc.PayloadInput{}, p.Inputs...)
	bad.Inputs[1].Value = 100_000
	bad.Outputs = []btc.PayloadOutput{{Address: b.hot0, Value: 230_000}}
	b.mustRefuse(b.jobs("c2", signjob.Intent{Kind: "cancel", ID: "cancel-2", PartitionID: btcPartition, Chain: btcChain, Asset: "BTC", To: b.hot0, Amount: "0"}, bad)[1], ReasonPinChanged)
}

// The signer for a job is the derived key of the input it names; a key that is not the input's is refused before anything signs.
func TestBTCSignerMustBeTheInputsKey(t *testing.T) {
	b := newBTCHarness(t)
	p := b.twoInputs(150_000, 150_000, b.other, 180_000)
	js := b.jobs("w1", wdIntent("w1", b.other, 100_000), p, "auto")
	codec := b.gw.codecs[btcChain].(*BTCCodec)
	info, err := codec.Decode(chainUnsigned(js[0]))
	if err != nil {
		t.Fatal(err)
	}
	k1, _ := b.tree.At(context.Background(), []uint32{1, 1})
	if err := codec.CheckSigner(info, k1.PublicKey()); err == nil {
		t.Fatal("the key of input 1 was accepted for input 0")
	}
	k0, _ := b.tree.At(context.Background(), []uint32{1, 0})
	if err := codec.CheckSigner(info, k0.PublicKey()); err != nil {
		t.Fatal(err)
	}
	// A key from outside the account.
	outside, _ := hdkeychain.NewMaster(bytes.Repeat([]byte{77}, 32), &chaincfg.RegressionNetParams)
	pk, _ := outside.ECPrivKey()
	if err := codec.CheckSigner(info, &pk.ToECDSA().PublicKey); err == nil {
		t.Fatal("a key outside the xpub was accepted")
	}
}

// Wrong-network input in the gateway's own config: refuses to build.
func TestBTCGatewayConfigRefusals(t *testing.T) {
	b := newBTCHarness(t)
	good := b.gw.cfg.Chains[btcChain].BTC
	mk := func(mut func(c *ChainFile)) error {
		cf := ChainFile{Family: "btc", WithdrawalsPerHour: 10, BTC: &BTCFile{Network: "regtest", AccountXpub: good.AccountXpub, MaxTxFeeSats: 1, MaxFeeRate: 1, MaxInputs: 1,
			HotShards: map[string]HotShardFile{btcPartition: {Address: b.hot0, Path: []uint32{1, 0}}}},
			Assets: map[string]AssetFile{"BTC": {AnyDestination: true, PerTxCap: "10", DailyCap: "10", Tiers: []TierFile{{"0", 1}}}}}
		mut(&cf)
		_, err := cf.build(btcChain, 4)
		return err
	}
	if err := mk(func(*ChainFile) {}); err != nil {
		t.Fatal(err)
	}
	main := "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
	for name, mut := range map[string]func(c *ChainFile){
		"mainnet network with a regtest key": func(c *ChainFile) { c.BTC.Network = "mainnet" },
		"wrong-network cold address":         func(c *ChainFile) { c.BTC.ColdAddresses = map[string]string{"omnibus/native": main} },
		"wrong-network allowlist entry": func(c *ChainFile) {
			a := c.Assets["BTC"]
			a.AnyDestination, a.WithdrawalDestinations = false, []string{main}
			c.Assets["BTC"] = a
		},
		"missing fee cap": func(c *ChainFile) { c.BTC.MaxTxFeeSats = 0 },
		"hot shard off path": func(c *ChainFile) {
			c.BTC.HotShards = map[string]HotShardFile{btcPartition: {Address: b.hot0, Path: []uint32{1, 1}}}
		},
		"no btc section":    func(c *ChainFile) { c.BTC = nil },
		"an unknown family": func(c *ChainFile) { c.Family = "doge" },
	} {
		if err := mk(mut); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	// The allowlist holds canonical strings: upper-case bech32 means the same address.
	cf := ChainFile{Family: "btc", WithdrawalsPerHour: 10, BTC: &BTCFile{Network: "regtest", AccountXpub: good.AccountXpub, MaxTxFeeSats: 1, MaxFeeRate: 1, MaxInputs: 1,
		HotShards: map[string]HotShardFile{btcPartition: {Address: b.hot0, Path: []uint32{1, 0}}}},
		Assets: map[string]AssetFile{"BTC": {WithdrawalDestinations: []string{strings.ToUpper(b.other)}, PerTxCap: "10", DailyCap: "10", Tiers: []TierFile{{"0", 1}}}}}
	cc, err := cf.build(btcChain, 4)
	if err != nil {
		t.Fatal(err)
	}
	if !cc.Assets["BTC"].AllowsDestination(b.other) || cc.Assets["BTC"].AllowsDestination(b.cold) {
		t.Fatal("allowlist form")
	}
}

func chainUnsigned(j signjob.Job) chain.UnsignedTx {
	return chain.UnsignedTx{Chain: j.Chain, Digest: j.Digest, Payload: j.Payload, KeyRef: chain.KeyRef{PartitionID: j.PartitionID, Path: j.KeyRef}}
}

// qv-gateway refuses to start unless every Bitcoin hot partition has a key-tree signer on the account path of the network.
func TestBTCCheckSigners(t *testing.T) {
	b := newBTCHarness(t)
	cfg := *b.cfg
	cfg.Chains = map[string]*ChainConfig{btcChain: b.cfg.Chains[btcChain]}
	good := SignerFile{Backend: "mpc", KeysetID: "k", HardenedPath: []uint32{84, 1, 0}}
	cfg.Signers = map[string]SignerFile{btcPartition: good, btcPart1: good, btcPartSeg: good}
	all := map[string]signer.Signer{btcPartition: b.tree, btcPart1: b.tree, btcPartSeg: b.tree}
	if err := CheckSigners(&cfg, all); err != nil {
		t.Fatal(err)
	}
	if err := CheckSigners(&cfg, map[string]signer.Signer{btcPartition: b.tree, btcPart1: b.tree}); err == nil {
		t.Fatal("a hot partition without a signer was accepted")
	}
	one, _ := b.tree.At(context.Background(), []uint32{1, 0})
	if err := CheckSigners(&cfg, map[string]signer.Signer{btcPartition: b.tree, btcPart1: b.tree, btcPartSeg: one}); err == nil {
		t.Fatal("a single-key signer for a Bitcoin partition was accepted")
	}
	bad := good
	bad.HardenedPath = []uint32{84, 0, 0}
	cfg.Signers = map[string]SignerFile{btcPartition: bad, btcPart1: good, btcPartSeg: good}
	if err := CheckSigners(&cfg, all); err == nil {
		t.Fatal("the mainnet account path on regtest was accepted")
	}
}

// Every kind is bound to its partition at the gateway too: a compromised business zone cannot move a segregated client's funds with an
// intent of the omnibus pool, nor the other way round.
func TestBTCIntentsAreBoundToTheirPartition(t *testing.T) {
	b := newBTCHarness(t)
	seg := func(n int) btc.PayloadInput { return btcIn(n, 0, 150_000, 1, 2) } // the segregated shard's key
	mk := func(kind, to string, amount uint64) (btc.Payload, signjob.Intent) {
		p := b.twoInputs(150_000, 150_000, to, 180_000)
		in := signjob.Intent{Kind: kind, ID: "x-" + kind, Asset: "BTC", To: to, Amount: fmt.Sprint(amount)}
		return p, in
	}
	// 1. Spending the segregated shard under an omnibus intent.
	for n, kind := range []string{"withdrawal", "to-cold"} {
		to := map[string]string{"withdrawal": b.other, "to-cold": b.cold}[kind]
		p, in := mk(kind, to, 100_000)
		p.Inputs = []btc.PayloadInput{seg(10 + n*2), seg(11 + n*2)}
		in.ID = fmt.Sprintf("seg-%d", n)
		b.mustRefuse(b.jobs(fmt.Sprintf("j%d", n), in, p, "auto")[0], ReasonTx)
	}
	// 2. Change to another shard.
	for n, other := range []string{b.hot1, b.hotS} {
		p, in := mk("withdrawal", b.other, 100_000)
		p.Outputs[1].Address = other
		in.ID = fmt.Sprintf("chg-%d", n)
		b.mustRefuse(b.jobs(fmt.Sprintf("chg%d", n), in, p, "auto")[0], ReasonTx)
	}
	// 3. To-cold to another pool's cold address.
	p, in := mk("to-cold", b.coldS, 100_000)
	b.mustRefuse(b.jobs("tc", in, p)[0], ReasonTx)
	// 4. Sweep and cancel to another partition's shard.
	sw := btc.Payload{Version: 2, Inputs: []btc.PayloadInput{btcIn(30, 0, 50_000, 0, 5)}, Outputs: []btc.PayloadOutput{{Address: b.hot1, Value: 49_000}}}
	b.mustRefuse(b.jobs("sw", signjob.Intent{Kind: "sweep", ID: "sw1", From: b.dep, To: b.hot1, Amount: "50000"}, sw)[0], ReasonTx)
	cp := btc.Payload{Version: 2, Inputs: []btc.PayloadInput{btcIn(31, 0, 50_000, 1, 0)}, Outputs: []btc.PayloadOutput{{Address: b.hot1, Value: 49_000}}}
	b.mustRefuse(b.jobs("cx", signjob.Intent{Kind: "cancel", ID: "cx1", To: b.hot1, Amount: "0"}, cp)[0], ReasonTx)
	// And the right ones pass, each under its own partition: a segregated to-cold goes to the segregated pool's cold address.
	ps := btc.Payload{Version: 2, Inputs: []btc.PayloadInput{seg(40), seg(41)}, Outputs: []btc.PayloadOutput{{Address: b.coldS, Value: 100_000}, {Address: b.hotS, Value: 180_000}}}
	b.mustSignAll(b.jobs("ok", signjob.Intent{Kind: "to-cold", ID: "tc-seg", PartitionID: btcPartSeg, To: b.coldS, Amount: "100000"}, ps))
}

// Bitcoin has no move between hot shards: a rebalance intent is refused whatever it pays and to whom.
func TestBTCRefusesRebalance(t *testing.T) {
	b := newBTCHarness(t)
	for n, to := range []string{b.hot1, b.hotS, b.hot0, b.cold, b.other} {
		p := b.twoInputs(150_000, 150_000, to, 180_000)
		in := signjob.Intent{Kind: "rebalance", ID: fmt.Sprintf("rb-%d", n), Asset: "BTC", To: to, Amount: "100000"}
		b.mustRefuse(b.jobs(fmt.Sprintf("rb%d", n), in, p)[0], ReasonTx)
	}
}

// A cancel needs no approval, so it may only spend what an attempt claimed: every input already claimed with the same pin, all by one
// signed intent of the cancel's partition, and all of that intent's inputs. Anything else would let it spend any input, a deposit
// output included, under no intent.
func TestBTCCancelMayOnlySpendWhatIsClaimed(t *testing.T) {
	b := newBTCHarness(t)
	fee := uint64(10_000)
	cancelTo := func(part, to string, inputs []btc.PayloadInput, id string) []signjob.Job {
		var sum uint64
		for _, in := range inputs {
			sum += in.Value
		}
		p := btc.Payload{Version: 2, Inputs: inputs, Outputs: []btc.PayloadOutput{{Address: to, Value: sum - fee}}}
		return b.jobs(id, signjob.Intent{Kind: "cancel", ID: "cancel-" + id, PartitionID: part, To: to, Amount: "0"}, p)
	}
	// Nothing was ever claimed: a cancel of any input, a deposit one included, is refused.
	b.mustRefuse(cancelTo(btcPartition, b.hot0, []btc.PayloadInput{btcIn(50, 0, 80_000, 0, 5)}, "k1")[0], ReasonCancelClaims)
	b.mustRefuse(cancelTo(btcPartition, b.hot0, []btc.PayloadInput{btcIn(51, 0, 80_000, 1, 0)}, "k2")[0], ReasonCancelClaims)

	// Two attempts, each claiming two inputs.
	pa := b.twoInputs(150_000, 150_000, b.other, 180_000) // inputs 1 and 2
	b.mustSignAll(b.jobs("wa", wdIntent("wa", b.other, 100_000), pa, "auto"))
	pb := btc.Payload{Version: 2, Inputs: []btc.PayloadInput{btcIn(3, 0, 150_000, 1, 0), btcIn(4, 0, 150_000, 1, 0)},
		Outputs: []btc.PayloadOutput{{Address: b.other, Value: 100_000}, {Address: b.hot0, Value: 180_000}}}
	b.mustSignAll(b.jobs("wb", wdIntent("wb", b.other, 100_000), pb, "auto"))

	// Claims of two intents in one cancel.
	b.mustRefuse(cancelTo(btcPartition, b.hot0, []btc.PayloadInput{pa.Inputs[0], pb.Inputs[0]}, "k3")[0], ReasonCancelClaims)
	// One input of the attempt left out.
	b.mustRefuse(cancelTo(btcPartition, b.hot0, pa.Inputs[:1], "k4")[0], ReasonCancelClaims)
	// One claimed input and one that nobody claimed.
	b.mustRefuse(cancelTo(btcPartition, b.hot0, []btc.PayloadInput{pa.Inputs[0], btcIn(52, 0, 150_000, 1, 0)}, "k5")[0], ReasonCancelClaims)
	// A changed pin is refused as a pin conflict, before anything else.
	pin := []btc.PayloadInput{pa.Inputs[0], pa.Inputs[1]}
	pin[1].Value = 100_000
	b.mustRefuse(cancelTo(btcPartition, b.hot0, pin, "k6")[1], ReasonPinChanged)
	// The claims of an attempt of another partition (here the cancel is for the other omnibus shard, to its own shard).
	b.mustRefuse(cancelTo(btcPart1, b.hot1, pa.Inputs, "k7")[0], ReasonCancelClaims)
	// And the right cancel passes: exactly the attempt's inputs, to the partition's own shard.
	b.mustSignAll(cancelTo(btcPartition, b.hot0, pa.Inputs, "k8"))
	// It cannot be done twice by another intent: the claims are the cancel's now.
	fee = 12_000
	b.mustRefuse(cancelTo(btcPartition, b.hot0, pa.Inputs, "k9")[0], ReasonNonceCancel)
}
