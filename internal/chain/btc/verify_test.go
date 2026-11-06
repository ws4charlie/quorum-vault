package btc

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

const (
	vChain = "btc-v"
	pOmni0 = "qv-us/btc-v/BTC/hot/omnibus/0"
	pOmni1 = "qv-us/btc-v/BTC/hot/omnibus/1"
	pSeg0  = "qv-us/btc-v/BTC/hot/segregated:acme/0"
)

type fixture struct {
	t     *testing.T
	acct  *Account
	v     *Verifier
	hot0  string // [1,0]: partition pOmni0
	hot1  string // [1,1]: partition pOmni1
	hotS  string // [1,2]: partition pSeg0, another pool
	cold  string // the omnibus pool's cold address
	coldS string // the segregated pool's
	other string // a P2WPKH of another network's key tree, valid on regtest, not pinned
	dep   string // [0,5]
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	acct := testAccount(t)
	f := &fixture{t: t, acct: acct}
	f.hot0, _ = acct.Address([]uint32{1, 0})
	f.hot1, _ = acct.Address([]uint32{1, 1})
	f.hotS, _ = acct.Address([]uint32{1, 2})
	f.dep, _ = acct.Address([]uint32{0, 5})
	foreign := func(seed byte) string {
		m, _ := hdkeychain.NewMaster(bytes.Repeat([]byte{seed}, 32), &chaincfg.RegressionNetParams)
		pub, _ := m.Neuter()
		a, _ := NewAccount("regtest", pub.String())
		s, _ := a.Address([]uint32{0, 0})
		return s
	}
	f.cold, f.coldS, f.other = foreign(9), foreign(11), foreign(10)
	xpub := acctXpub(acct)
	v, err := NewVerifier(SigningConfig{Chain: vChain, Network: "regtest", AccountXpub: xpub,
		HotShards:     map[string]HotShard{pOmni0: {Address: f.hot0, Path: []uint32{1, 0}}, pOmni1: {Address: f.hot1, Path: []uint32{1, 1}}, pSeg0: {Address: f.hotS, Path: []uint32{1, 2}}},
		ColdAddresses: map[string]string{"omnibus/native": f.cold, "segregated:acme/native": f.coldS}, MaxTxFeeSats: 50_000, MaxFeeRate: 100, MaxInputs: 4})
	if err != nil {
		t.Fatal(err)
	}
	f.v = v
	return f
}

func acctXpub(a *Account) string { return a.key.String() }

func txid(n int) string {
	var h [32]byte
	h[0], h[31] = byte(n), 0xAA
	return hex.EncodeToString(h[:])
}

func in(n int, value uint64, path ...uint32) PayloadInput {
	return PayloadInput{TxID: txid(n), Vout: 0, Value: value, Path: path, Sequence: SequenceRBF}
}

// job returns the job of input i of p, as the business zone would build it, for partition pOmni0.
func (f *fixture) job(p Payload, i int) chain.UnsignedTx { return f.jobFor(pOmni0, p, i) }

func (f *fixture) jobFor(part string, p Payload, i int) chain.UnsignedTx {
	f.t.Helper()
	raw, _ := json.Marshal(p)
	u, err := BuildUnsigned(p, f.acct)
	if err != nil {
		// A payload BuildUnsigned refuses has no digest: use garbage so Verify's own refusal is what the test sees.
		return chain.UnsignedTx{Chain: vChain, Payload: raw, Digest: make([]byte, 32), KeyRef: chain.KeyRef{PartitionID: part, Path: PathString(p.Inputs[i].Path)}}
	}
	return chain.UnsignedTx{Chain: vChain, Payload: raw, Digest: u.Digests[i], KeyRef: chain.KeyRef{PartitionID: part, Path: PathString(p.Inputs[i].Path)}}
}

func (f *fixture) withdrawal(to string, amount uint64) (Payload, signjob.Intent) {
	p := Payload{Version: 2, Inputs: []PayloadInput{in(1, 300_000, 1, 0), in(2, 200_000, 1, 0)},
		Outputs: []PayloadOutput{{to, amount}, {f.hot0, 500_000 - amount - 1_000}}}
	return p, signjob.Intent{Kind: "withdrawal", ID: "w1", PartitionID: pOmni0, Chain: vChain, Asset: "BTC", To: to, Amount: fmt.Sprint(amount)}
}

func (f *fixture) mustPass(p Payload, i signjob.Intent) {
	f.t.Helper()
	for n := range p.Inputs {
		if err := f.v.Verify(f.job(p, n), i); err != nil {
			f.t.Fatalf("input %d: %v", n, err)
		}
	}
}

func (f *fixture) mustRefuse(name string, p Payload, i signjob.Intent, want string) {
	f.t.Helper()
	err := f.v.Verify(f.job(p, 0), i)
	if err == nil || !strings.Contains(err.Error(), want) {
		f.t.Fatalf("%s: got %v, want a refusal containing %q", name, err, want)
	}
}

func TestVerifyAcceptsTheRightTransactions(t *testing.T) {
	f := newFixture(t)
	p, i := f.withdrawal(f.other, 100_000)
	f.mustPass(p, i)
	// One output only (no change).
	p.Outputs = p.Outputs[:1]
	p.Outputs[0].Value = 499_000
	i.Amount = "499000"
	f.mustPass(p, i)
	// to-cold, rebalance, sweep, cancel
	pc, ic := f.withdrawal(f.cold, 100_000)
	ic.Kind = "to-cold"
	f.mustPass(pc, ic)
	pr, ir := f.withdrawal(f.hot1, 100_000)
	pr.Inputs = []PayloadInput{in(1, 300_000, 1, 0), in(2, 200_000, 1, 0+0)}
	pr.Inputs[1].Vout = 1
	ir.Kind = "rebalance"
	f.mustPass(pr, ir)
	ps := Payload{Version: 2, Inputs: []PayloadInput{in(3, 50_000, 0, 5), {TxID: txid(4), Vout: 1, Value: 30_000, Path: []uint32{0, 5}, Sequence: SequenceRBF}},
		Outputs: []PayloadOutput{{f.hot0, 79_000}}}
	is := signjob.Intent{Kind: "sweep", ID: "s1", PartitionID: pOmni0, Chain: vChain, Asset: "BTC", From: f.dep, To: f.hot0, Amount: "80000"}
	f.mustPass(ps, is)
	pk := Payload{Version: 2, Inputs: []PayloadInput{in(1, 300_000, 1, 0), in(3, 50_000, 0, 5)}, Outputs: []PayloadOutput{{f.hot0, 349_000}}}
	ik := signjob.Intent{Kind: "cancel", ID: "c1", PartitionID: pOmni0, Chain: vChain, Asset: "BTC", To: f.hot0, Amount: "0"}
	f.mustPass(pk, ik)
}

func TestVerifyRefusesTheOutputAttacks(t *testing.T) {
	f := newFixture(t)
	p, i := f.withdrawal(f.other, 100_000)

	bad := p
	bad.Outputs = []PayloadOutput{p.Outputs[0], {f.other, 399_000}}
	f.mustRefuse("change to an unpinned address", bad, i, "not the partition's own shard")

	bad = p
	bad.Outputs = []PayloadOutput{p.Outputs[0], {f.hot0, 200_000}, {f.hot1, 198_000}}
	f.mustRefuse("a third output", bad, i, "at most the payment and one change")

	f.mustRefuse("destination changed", p, signjob.Intent{Kind: "withdrawal", ID: "w1", PartitionID: pOmni0, Chain: vChain, Asset: "BTC", To: f.cold, Amount: "100000"}, "the first output pays")
	for _, amt := range []string{"99999", "100001"} {
		j := i
		j.Amount = amt
		f.mustRefuse("amount off by a satoshi ("+amt+")", p, j, "the first output pays")
	}
	// The payment may not hide in the second output.
	bad = p
	bad.Outputs = []PayloadOutput{p.Outputs[1], p.Outputs[0]}
	f.mustRefuse("payment as the second output", bad, i, "the first output pays")

	// Wrong network: the intent, and the payload.
	main := "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
	j := i
	j.To = main
	f.mustRefuse("mainnet destination in the intent", p, j, "intent destination")
	bad = p
	bad.Outputs = []PayloadOutput{{main, 100_000}, p.Outputs[1]}
	f.mustRefuse("mainnet destination in the payload", bad, i, "output 0")

	// Dust, OP_RETURN, bad forms.
	bad = p
	bad.Outputs = []PayloadOutput{{f.other, 293}, {f.hot0, 498_000}}
	j = i
	j.Amount = "293"
	f.mustRefuse("dust output", bad, j, "below the dust limit")
	raw := []byte(strings.Replace(string(f.job(p, 0).Payload), `"outputs":[`, `"outputs":[{"script":"6a0568656c6c6f","value":0},`, 1))
	u := f.job(p, 0)
	u.Payload = raw
	if err := f.v.Verify(u, i); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("an OP_RETURN script field: %v", err)
	}
	bad = p
	bad.Outputs = []PayloadOutput{{"", 0}, p.Outputs[1]}
	f.mustRefuse("an output with no address (OP_RETURN has none)", bad, i, "output 0")
}

func TestVerifyRefusesTheInputAttacks(t *testing.T) {
	f := newFixture(t)
	p, i := f.withdrawal(f.other, 100_000)

	for name, path := range map[string][]uint32{"branch 2": {2, 0}, "three levels": {1, 0, 0}, "one level": {1}, "hardened index": {1, 1 << 31}, "hardened branch": {1 << 31, 0}} {
		bad := p
		bad.Inputs = append([]PayloadInput{}, p.Inputs...)
		bad.Inputs[0].Path = path
		f.mustRefuse("path outside the allowed branches ("+name+")", bad, i, "derivation")
	}
	bad := p
	bad.Inputs = append([]PayloadInput{}, p.Inputs...)
	bad.Inputs[1].Path = []uint32{0, 5} // a deposit address in a withdrawal
	f.mustRefuse("deposit input in a withdrawal", bad, i, "not the partition's own shard")

	// The digest of another input, or of nothing.
	mixed := p
	mixed.Inputs = []PayloadInput{in(1, 300_000, 1, 0), in(2, 200_000, 0, 5)} // two keys: the digest of one under the other's key reference
	u := f.job(mixed, 0)
	u.Digest = f.job(mixed, 1).Digest
	if err := f.v.Verify(u, i); err == nil || !strings.Contains(err.Error(), "which is signed under key path 0/5") {
		t.Fatalf("the digest of input 1 under input 0's key: %v", err)
	}
	u = f.job(p, 0)
	u.Digest = bytes.Repeat([]byte{1}, 32)
	if err := f.v.Verify(u, i); err == nil || !strings.Contains(err.Error(), "none of the 2 inputs") {
		t.Fatalf("an unrelated digest: %v", err)
	}
	// SIGHASH other than ALL is impossible: the digest is computed with ALL fixed, and a digest over any other type is no input's digest.
	built, _ := BuildUnsigned(p, f.acct)
	for name, ht := range map[string]txscript.SigHashType{"NONE": txscript.SigHashNone, "SINGLE": txscript.SigHashSingle, "ALL|ANYONECANPAY": txscript.SigHashAnyOneCanPay | txscript.SigHashAll} {
		d, err := calcWith(f, p, built, 0, ht)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(d, built.Digests[0]) {
			t.Fatalf("SIGHASH_%s gives the SIGHASH_ALL digest", name)
		}
		u := f.job(p, 0)
		u.Digest = d
		if err := f.v.Verify(u, i); err == nil || !strings.Contains(err.Error(), "none of the 2 inputs") {
			t.Fatalf("a SIGHASH_%s digest: %v", name, err)
		}
	}
	// The key that would sign must be the derived one.
	good := f.job(p, 0)
	info, err := f.v.Decode(good)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := hex.DecodeString("02" + strings.Repeat("11", 32))
	if bytes.Equal(info.SignerKey, other) || len(info.SignerKey) != 33 {
		t.Fatal("signer key")
	}
	wantKey, _ := f.acct.Pub([]uint32{1, 0})
	if !bytes.Equal(info.SignerKey, wantKey) {
		t.Fatalf("signer key %x, derived %x", info.SignerKey, wantKey)
	}
}

func TestVerifyRefusesTheLimitAttacks(t *testing.T) {
	f := newFixture(t)
	p, i := f.withdrawal(f.other, 100_000)

	bad := p
	bad.Outputs = []PayloadOutput{p.Outputs[0], {f.hot0, 500_000 - 100_000 - 60_000}}
	f.mustRefuse("fee above the cap", bad, i, "exceeds the cap")

	// A fee under the cap but over the rate: 4 inputs of 10_000_000 sats, fee 40_000 over ~ 350 vbytes is 114 sat/vB.
	bad = Payload{Version: 2, Outputs: []PayloadOutput{{f.other, 100_000}, {f.hot0, 40_000_000 - 100_000 - 49_000}}}
	for n := 0; n < 4; n++ {
		bad.Inputs = append(bad.Inputs, in(10+n, 10_000_000, 1, 0))
		bad.Inputs[n].Vout = uint32(n)
	}
	j := i
	j.Amount = "100000"
	f.mustRefuse("fee rate above the cap", bad, j, "sat/vB")

	bad = p
	bad.Inputs = nil
	for n := 0; n < 5; n++ {
		x := in(20+n, 100_000, 1, 0)
		bad.Inputs = append(bad.Inputs, x)
	}
	bad.Outputs = []PayloadOutput{{f.other, 100_000}}
	f.mustRefuse("too many inputs", bad, i, "the limit is 4")

	bad = p
	bad.LockTime = 5
	f.mustRefuse("locktime set", bad, i, "locktime")
	bad = p
	bad.Version = 1
	f.mustRefuse("version 1", bad, i, "version")
	bad = p
	bad.Inputs = append([]PayloadInput{}, p.Inputs...)
	bad.Inputs[1].Sequence = 0xffffffff
	f.mustRefuse("RBF not signalled", bad, i, "does not signal RBF")
	bad.Inputs[1].Sequence = 0xfffffffe
	f.mustRefuse("RBF not signalled (0xfffffffe)", bad, i, "does not signal RBF")
	bad = p
	bad.Outputs = []PayloadOutput{{f.other, 400_000}, {f.hot0, 200_000}}
	j = i
	j.Amount = "400000"
	f.mustRefuse("outputs above inputs", bad, j, "exceed inputs")
}

func TestVerifyRefusesSweepsAndCancelsThatDoNotMatch(t *testing.T) {
	f := newFixture(t)
	ps := Payload{Version: 2, Inputs: []PayloadInput{in(3, 50_000, 0, 5)}, Outputs: []PayloadOutput{{f.hot0, 49_000}}}
	is := signjob.Intent{Kind: "sweep", ID: "s1", PartitionID: pOmni0, Chain: vChain, Asset: "BTC", From: f.dep, To: f.hot0, Amount: "50000"}
	f.mustPass(ps, is)

	bad := ps
	bad.Inputs = []PayloadInput{in(3, 50_000, 0, 5), in(4, 10_000, 0, 6)}
	bad.Outputs = []PayloadOutput{{f.hot0, 59_000}}
	j := is
	j.Amount = "60000"
	f.mustRefuse("an input from another deposit address", bad, j, "not the intent's source")
	bad = ps
	bad.Inputs = []PayloadInput{in(3, 50_000, 1, 0)}
	f.mustRefuse("a hot input in a sweep", bad, is, "not on branch 0")
	bad = ps
	bad.Outputs = []PayloadOutput{{f.hot0, 24_000}, {f.hot1, 24_000}}
	f.mustRefuse("a sweep with two outputs", bad, is, "one output")
	bad = ps
	bad.Outputs = []PayloadOutput{{f.other, 49_000}}
	j = is
	j.To = f.other
	f.mustRefuse("a sweep to an unpinned address", bad, j, "own shard")
	j = is
	j.Amount = "49000" // the fee is not part of what leaves the address
	f.mustRefuse("sweep amount that is not the sum of the inputs", ps, j, "not the sum of the inputs")

	pk := Payload{Version: 2, Inputs: []PayloadInput{in(1, 300_000, 1, 0), in(3, 50_000, 0, 5)}, Outputs: []PayloadOutput{{f.hot0, 349_000}}}
	ik := signjob.Intent{Kind: "cancel", ID: "c1", PartitionID: pOmni0, Chain: vChain, Asset: "BTC", To: f.hot0, Amount: "0"}
	f.mustPass(pk, ik)
	bad = pk
	bad.Outputs = []PayloadOutput{{f.hot0, 300_000}, {f.hot0, 49_000}}
	f.mustRefuse("a cancel with an extra output", bad, ik, "one output")
	bad = pk
	bad.Outputs = []PayloadOutput{{f.other, 349_000}}
	j = ik
	j.To = f.other
	f.mustRefuse("a cancel to an address that is not pinned", bad, j, "own shard")
	pc, ic := f.withdrawal(f.other, 100_000)
	ic.Kind = "to-cold"
	f.mustRefuse("to-cold to an unpinned address", pc, ic, "not the cold address of pool")
	pr, ir := f.withdrawal(f.hot0, 100_000)
	ir.Kind = "rebalance"
	f.mustRefuse("a rebalance to the source's own address", pr, ir, "another shard")
}

func TestCanonicalRejectsAnotherNetwork(t *testing.T) {
	f := newFixture(t)
	if _, err := f.v.Canonical("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"); err == nil {
		t.Fatal("a mainnet address was canonicalized on regtest")
	}
	up := strings.ToUpper(f.hot0)
	c, err := f.v.Canonical(up)
	if err != nil || c != f.hot0 {
		t.Fatalf("upper-case bech32: %q %v", c, err)
	}
}

func TestVerifierConfigRefusals(t *testing.T) {
	f := newFixture(t)
	base := SigningConfig{Chain: vChain, Network: "regtest", AccountXpub: acctXpub(f.acct), HotShards: map[string]HotShard{pOmni0: {Address: f.hot0, Path: []uint32{1, 0}}},
		MaxTxFeeSats: 1, MaxFeeRate: 1, MaxInputs: 1}
	if _, err := NewVerifier(base); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(c *SigningConfig){
		"wrong network": func(c *SigningConfig) { c.Network = "mainnet" },
		"hot shard off its path": func(c *SigningConfig) {
			c.HotShards = map[string]HotShard{pOmni0: {Address: f.hot0, Path: []uint32{1, 1}}}
		},
		"hot shard on the deposit branch": func(c *SigningConfig) {
			c.HotShards = map[string]HotShard{pOmni0: {Address: f.dep, Path: []uint32{0, 5}}}
		},
		"hot shard from another key": func(c *SigningConfig) {
			c.HotShards = map[string]HotShard{pOmni0: {Address: f.other, Path: []uint32{1, 0}}}
		},
		"mainnet cold address": func(c *SigningConfig) {
			c.ColdAddresses = map[string]string{"x": "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"}
		},
		"no fee cap":    func(c *SigningConfig) { c.MaxTxFeeSats = 0 },
		"no rate cap":   func(c *SigningConfig) { c.MaxFeeRate = 0 },
		"no input cap":  func(c *SigningConfig) { c.MaxInputs = 0 },
		"no hot shards": func(c *SigningConfig) { c.HotShards = nil },
	} {
		c := base
		mut(&c)
		if _, err := NewVerifier(c); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// calcWith is the BIP143 digest of input i with an arbitrary sighash type, to show that none of them is a digest the verifier accepts.
func calcWith(f *fixture, p Payload, built *Unsigned, i int, ht txscript.SigHashType) ([]byte, error) {
	fetch := map[wire.OutPoint]*wire.TxOut{}
	for n, in := range built.Tx.TxIn {
		fetch[in.PreviousOutPoint] = wire.NewTxOut(int64(p.Inputs[n].Value), built.Scripts[n])
	}
	pkh, err := btcutil.NewAddressPubKeyHash(hash160(built.Pubs[i]), f.acct.Params)
	if err != nil {
		return nil, err
	}
	sc, err := txscript.PayToAddrScript(pkh)
	if err != nil {
		return nil, err
	}
	return txscript.CalcWitnessSigHash(sc, txscript.NewTxSigHashes(built.Tx, txscript.NewMultiPrevOutFetcher(fetch)), ht, built.Tx, i, int64(p.Inputs[i].Value))
}

// Every kind is bound to the partition it names: its own shard, its own pool's cold address, another shard of its own pool.
func TestVerifyBindsEveryKindToItsPartition(t *testing.T) {
	f := newFixture(t)
	// The key partition and the intent partition are the same.
	p, i := f.withdrawal(f.other, 100_000)
	u := f.jobFor(pOmni1, p, 0)
	if err := f.v.Verify(u, i); err == nil || !strings.Contains(err.Error(), "key partition") {
		t.Fatalf("key partition differs from the intent's: %v", err)
	}
	// A partition that has no pinned shard.
	j := i
	j.PartitionID = "qv-us/btc-v/BTC/hot/omnibus/9"
	if err := f.v.Verify(f.jobFor(j.PartitionID, p, 0), j); err == nil || !strings.Contains(err.Error(), "no pinned hot shard") {
		t.Fatalf("a partition without a shard: %v", err)
	}

	// Withdrawal, to-cold and rebalance from another partition's shard (the segregated client's funds).
	for _, kind := range []string{"withdrawal", "to-cold", "rebalance"} {
		to := f.other
		switch kind {
		case "to-cold":
			to = f.cold
		case "rebalance":
			to = f.hot1
		}
		bad, in := f.withdrawal(to, 100_000)
		in.Kind = kind
		bad.Inputs = []PayloadInput{inp(1, 300_000, 1, 2), inp(2, 200_000, 1, 2)} // the segregated shard's key, under an omnibus intent
		f.mustRefuse(kind+" from another partition's shard", bad, in, "not the partition's own shard")
	}
	// Change to another shard, whether omnibus or segregated.
	for _, other := range []string{f.hot1, f.hotS} {
		bad, in := f.withdrawal(f.other, 100_000)
		bad.Outputs[1].Address = other
		f.mustRefuse("change to another shard", bad, in, "not the partition's own shard")
	}
	// To-cold: the cold address of the partition's pool only.
	pc, ic := f.withdrawal(f.coldS, 100_000)
	ic.Kind = "to-cold"
	f.mustRefuse("to-cold to another pool's cold address", pc, ic, "not the cold address of pool")
	ps, is := f.withdrawal(f.coldS, 100_000)
	is.Kind, is.PartitionID = "to-cold", pSeg0
	ps.Inputs = []PayloadInput{inp(1, 300_000, 1, 2), inp(2, 200_000, 1, 2)}
	ps.Outputs[1].Address = f.hotS
	for n := range ps.Inputs {
		if err := f.v.Verify(f.jobFor(pSeg0, ps, n), is); err != nil {
			t.Fatalf("a segregated to-cold to its own pool's cold address: %v", err)
		}
	}
	ps.Outputs[0].Address = f.cold
	is.To = f.cold
	if err := f.v.Verify(f.jobFor(pSeg0, ps, 0), is); err == nil || !strings.Contains(err.Error(), "not the cold address of pool") {
		t.Fatalf("a segregated to-cold to the omnibus cold address: %v", err)
	}
	// Rebalance: another shard of the same pool, never another pool's.
	pr, ir := f.withdrawal(f.hotS, 100_000)
	ir.Kind = "rebalance"
	f.mustRefuse("rebalance into another pool", pr, ir, "another shard")
	pr, ir = f.withdrawal(f.hot1, 100_000)
	ir.Kind = "rebalance"
	f.mustPass(pr, ir)
	// Sweep and cancel: the partition's own shard, not any hot shard.
	sw := Payload{Version: 2, Inputs: []PayloadInput{inp(3, 50_000, 0, 5)}, Outputs: []PayloadOutput{{f.hot1, 49_000}}}
	si := signjob.Intent{Kind: "sweep", ID: "s1", PartitionID: pOmni0, Chain: vChain, Asset: "BTC", From: f.dep, To: f.hot1, Amount: "50000"}
	f.mustRefuse("sweep to another partition's shard", sw, si, "own shard")
	sw.Outputs[0].Address, si.To = f.hotS, f.hotS
	f.mustRefuse("sweep to another pool's shard", sw, si, "own shard")
	cp := Payload{Version: 2, Inputs: []PayloadInput{inp(1, 300_000, 1, 0)}, Outputs: []PayloadOutput{{f.hot1, 299_000}}}
	ci := signjob.Intent{Kind: "cancel", ID: "c1", PartitionID: pOmni0, Chain: vChain, Asset: "BTC", To: f.hot1, Amount: "0"}
	f.mustRefuse("cancel to another partition's shard", cp, ci, "own shard")
}

func inp(n int, value uint64, path ...uint32) PayloadInput { return in(n, value, path...) }
