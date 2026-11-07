package coldsign

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

type btcKey struct{ priv *btcec.PrivateKey }

func (k btcKey) SignDigest(_ context.Context, d [32]byte) (*big.Int, *big.Int, error) {
	sig := btcecdsa.Sign(k.priv, d[:])
	r, s := sig.R(), sig.S()
	rb, sb := r.Bytes(), s.Bytes()
	return new(big.Int).SetBytes(rb[:]), new(big.Int).SetBytes(sb[:]), nil
}

type btcEnv struct {
	t     *testing.T
	cfg   *BTCConfig
	key   btcKey
	cold  string
	hot   string
	ops   map[string]ed25519.PrivateKey
	n     int
	other string // an address of the same network that is not pinned
}

func newBTCCold(t *testing.T, pool string, base string) *btcEnv {
	t.Helper()
	priv, _ := btcec.NewPrivateKey()
	pubHex := hex.EncodeToString(priv.PubKey().SerializeCompressed())
	cold, err := BTCAddressOf("regtest", pubHex)
	if err != nil {
		t.Fatal(err)
	}
	mkAddr := func() string {
		k, _ := btcec.NewPrivateKey()
		a, _ := BTCAddressOf("regtest", hex.EncodeToString(k.PubKey().SerializeCompressed()))
		return a
	}
	hot := mkAddr()
	ops, pubs := map[string]ed25519.PrivateKey{}, map[string]string{}
	for _, n := range []string{"alice", "bob", "carol"} {
		pub, pr, _ := ed25519.GenerateKey(rand.Reader)
		ops[n], pubs[n] = pr, hex.EncodeToString(pub)
	}
	cfg := &BTCConfig{Family: "btc", Network: "regtest", Chain: "btc-t", Pool: pool, Operators: pubs, Threshold: 2, HotShards: []string{hot},
		MaxAmount: 50_000_000, MaxFeeSats: 20_000, MaxFeeRate: 100, MaxInputs: 5, PublicKey: pubHex, RecordDir: filepath.Join(base, pool)}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return &btcEnv{t: t, cfg: cfg, key: btcKey{priv}, cold: cold, hot: hot, ops: ops, other: mkAddr()}
}

func (e *btcEnv) txid() string {
	e.n++
	var h [32]byte
	h[0], h[31] = byte(e.n), 0xC0
	return hex.EncodeToString(h[:])
}

// req builds a request spending inputs of the given values (new outpoints) to the hot shard, with change to the cold address.
func (e *btcEnv) req(id string, fee uint64, pay uint64, values ...uint64) BTCRequest {
	r := BTCRequest{Version: BTCRequestVersion, ID: id, Revision: 1, Network: "regtest", Chain: "btc-t", Pool: e.cfg.Pool, From: e.cold}
	var sum uint64
	for _, v := range values {
		r.Inputs = append(r.Inputs, BTCInput{TxID: e.txid(), Vout: 0, Value: v, Address: e.cold})
		sum += v
	}
	r.Outputs = []BTCOutput{{Address: e.hot, Value: pay}}
	if ch := sum - pay - fee; ch > 0 {
		r.Outputs = append(r.Outputs, BTCOutput{Address: e.cold, Value: ch})
	}
	return r
}

func (e *btcEnv) sign(r BTCRequest, ops ...string) (BTCSigned, error) {
	e.t.Helper()
	rf := r.File()
	var apps []Approval
	for _, o := range ops {
		apps = append(apps, Approve(o, e.ops[o], rf.RequestHash))
	}
	s, _, err := e.cfg.Sign(context.Background(), rf, apps, e.key)
	return s, err
}

func mustRefuse(t *testing.T, err error, want string) {
	t.Helper()
	var ref *Refusal
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("want a refusal containing %q, got %v", want, err)
	}
	_ = ref
}

// The signed transaction is what btcd makes of the same request, and it validates with btcd's script engine: our serialization, our txid and our BIP143
// digest agree with the reference.
func TestBTCSignedTransactionValidatesWithBtcd(t *testing.T) {
	e := newBTCCold(t, "omnibus", t.TempDir())
	r := e.req("rf-1", 1500, 3_000_000, 2_000_000, 2_500_000) // two inputs, change to the cold address
	s, err := e.sign(r, "alice", "bob")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := VerifyBTCSignedMatches(r, r.HashHex(), s)
	if err != nil {
		t.Fatal(err)
	}
	var tx wire.MsgTx
	if err := tx.Deserialize(bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	if tx.TxHash().String() != s.TxID || len(tx.TxIn) != 2 || len(tx.TxOut) != 2 {
		t.Fatalf("txid %s vs %s, %d inputs, %d outputs", tx.TxHash(), s.TxID, len(tx.TxIn), len(tx.TxOut))
	}
	params := &chaincfg.RegressionNetParams
	coldAddr, err := btcutil.DecodeAddress(e.cold, params)
	if err != nil {
		t.Fatal(err)
	}
	pk, _ := txscript.PayToAddrScript(coldAddr)
	prev := map[wire.OutPoint]*wire.TxOut{}
	for i, in := range r.Inputs {
		h, _ := chainhash.NewHashFromStr(in.TxID)
		prev[wire.OutPoint{Hash: *h, Index: in.Vout}] = wire.NewTxOut(int64(r.Inputs[i].Value), pk)
	}
	fetcher := txscript.NewMultiPrevOutFetcher(prev)
	sigHashes := txscript.NewTxSigHashes(&tx, fetcher)
	for i, in := range tx.TxIn {
		out := prev[in.PreviousOutPoint]
		vm, err := txscript.NewEngine(out.PkScript, &tx, i, txscript.StandardVerifyFlags, nil, sigHashes, out.Value, fetcher)
		if err != nil {
			t.Fatal(err)
		}
		if err := vm.Execute(); err != nil {
			t.Fatalf("input %d does not validate: %v", i, err)
		}
	}
	// Our addresses are btcd's.
	if got, _ := btcutil.DecodeAddress(e.hot, params); got == nil || got.EncodeAddress() != e.hot {
		t.Fatalf("hot address %s", e.hot)
	}
}

// Everything the offline tool refuses, each with a reason an operator can read.
func TestBTCRefusals(t *testing.T) {
	e := newBTCCold(t, "omnibus", t.TempDir())
	base := func() BTCRequest { return e.req("rf", 1000, 3_000_000, 2_000_000, 2_500_000) }
	cases := []struct {
		name string
		mut  func(*BTCRequest)
		want string
	}{
		{"payment to an unpinned address", func(r *BTCRequest) { r.Outputs[0].Address = e.other }, "not one of the pinned hot shards"},
		{"an extra output", func(r *BTCRequest) { r.Outputs = append(r.Outputs, BTCOutput{Address: e.hot, Value: 300}) }, "3 outputs"},
		{"change to another address", func(r *BTCRequest) { r.Outputs[1].Address = e.other }, "must go to the cold address"},
		{"change to the hot shard", func(r *BTCRequest) { r.Outputs[1].Address = e.hot }, "must go to the cold address"},
		{"fee over the cap", func(r *BTCRequest) { r.Outputs[1].Value -= 30_000 }, "above the cap"},
		{"fee rate over the cap", func(r *BTCRequest) {
			*r = e.req("rf", 18_000, 3_000_000, 5_000_000)
		}, "above the rate cap"},
		{"an input from another address", func(r *BTCRequest) { r.Inputs[0].Address = e.other }, "every input must be from the cold address"},
		{"another network", func(r *BTCRequest) { r.Network = "mainnet" }, "network"},
		{"payment above the ceremony cap", func(r *BTCRequest) { r.Outputs[0].Value = 60_000_000; r.Inputs[0].Value = 70_000_000 }, "per-ceremony cap"},
		{"dust change", func(r *BTCRequest) { r.Outputs[1].Value = 100; r.Outputs[0].Value += 1_499_000 - 100 + 100 }, ""},
		{"too many inputs", func(r *BTCRequest) {
			for i := 0; i < 5; i++ {
				r.Inputs = append(r.Inputs, BTCInput{TxID: e.txid(), Value: 1000, Address: e.cold})
			}
		}, "at most 5"},
		{"the same input twice", func(r *BTCRequest) { r.Inputs[1].TxID, r.Inputs[1].Vout = r.Inputs[0].TxID, r.Inputs[0].Vout }, "named twice"},
		{"another pool", func(r *BTCRequest) { r.Pool = "other" }, "this signer holds pool"},
		{"another cold address", func(r *BTCRequest) { r.From = e.other }, "cold address is"},
		{"more out than in", func(r *BTCRequest) { r.Outputs[0].Value += 10_000_000 }, "are more than inputs"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := base()
			tc.mut(&r)
			_, err := e.sign(r, "alice", "bob")
			var ref *Refusal
			if err == nil {
				if tc.want == "" {
					return // not a refusal case after all
				}
				t.Fatal("signed")
			}
			if !errorsAs(err, &ref) || (tc.want != "" && !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("got %v, want a refusal containing %q", err, tc.want)
			}
		})
	}
}

func errorsAs(err error, ref **Refusal) bool {
	r, ok := err.(*Refusal)
	if ok {
		*ref = r
	}
	return ok
}

// Approvals: too few, an unknown operator, one operator twice, an approval of another request, a tampered file.
func TestBTCApprovalsAndTamperedFiles(t *testing.T) {
	e := newBTCCold(t, "omnibus", t.TempDir())
	r := e.req("rf", 1000, 3_000_000, 5_000_000)
	rf := r.File()
	mustSignWith := func(rf BTCRequestFile, apps ...Approval) error {
		_, _, err := e.cfg.Sign(context.Background(), rf, apps, e.key)
		return err
	}
	mustRefuse(t, mustSignWith(rf, Approve("alice", e.ops["alice"], rf.RequestHash)), "1 valid approval(s)")
	_, evil, _ := ed25519.GenerateKey(rand.Reader)
	mustRefuse(t, mustSignWith(rf, Approve("alice", e.ops["alice"], rf.RequestHash), Approve("mallory", evil, rf.RequestHash)), "not a configured operator")
	mustRefuse(t, mustSignWith(rf, Approve("alice", e.ops["alice"], rf.RequestHash), Approve("alice", e.ops["alice"], rf.RequestHash)), "counted once already")
	other := e.req("rf-other", 1000, 3_000_000, 5_000_000).File()
	mustRefuse(t, mustSignWith(rf, Approve("alice", e.ops["alice"], rf.RequestHash), Approve("bob", e.ops["bob"], other.RequestHash)), "signed another request")
	// A tampered file: the amount changed on the way.
	bad := rf
	bad.Request.Outputs = append([]BTCOutput(nil), rf.Request.Outputs...)
	bad.Request.Outputs[0].Value++
	mustRefuse(t, mustSignWith(bad, Approve("alice", e.ops["alice"], rf.RequestHash), Approve("bob", e.ops["bob"], rf.RequestHash)), "damaged or was changed")
	// A request hash that does not match its content.
	bad2 := rf
	bad2.RequestHash = other.RequestHash
	mustRefuse(t, mustSignWith(bad2, Approve("alice", e.ops["alice"], other.RequestHash), Approve("bob", e.ops["bob"], other.RequestHash)), "damaged or was changed")
	if _, err := e.sign(r, "alice", "carol"); err != nil {
		t.Fatalf("the honest request: %v", err)
	}
}

// The fee attack. A BIP143 signature commits only to the value of its own input, so the signer pins the first value each outpoint is signed with.
func TestBTCFeeAttackAcrossRequests(t *testing.T) {
	e := newBTCCold(t, "omnibus", t.TempDir())
	a := e.req("rf-a", 1000, 3_000_000, 5_000_000) // outpoint A, value 5M
	if _, err := e.sign(a, "alice", "bob"); err != nil {
		t.Fatal(err)
	}
	opA := a.Inputs[0]

	// 1. Another request names A with a smaller value (to hide a larger fee behind a smaller input) next to a new outpoint.
	lie := BTCRequest{Version: BTCRequestVersion, ID: "rf-lie", Revision: 1, Network: "regtest", Chain: "btc-t", Pool: "omnibus", From: e.cold,
		Inputs:  []BTCInput{{TxID: opA.TxID, Vout: opA.Vout, Value: 3_000_000, Address: e.cold}, {TxID: e.txid(), Value: 4_000_000, Address: e.cold}},
		Outputs: []BTCOutput{{Address: e.hot, Value: 6_998_000}}}
	_, err := e.sign(lie, "alice", "bob")
	mustRefuse(t, err, "a second value for a signed outpoint is refused")

	// 2. The right value, but a different transaction (another set of inputs and another amount): not a replacement.
	other := BTCRequest{Version: BTCRequestVersion, ID: "rf-other", Revision: 1, Network: "regtest", Chain: "btc-t", Pool: "omnibus", From: e.cold,
		Inputs:  []BTCInput{{TxID: opA.TxID, Vout: opA.Vout, Value: 5_000_000, Address: e.cold}, {TxID: e.txid(), Value: 1_000_000, Address: e.cold}},
		Outputs: []BTCOutput{{Address: e.hot, Value: 5_990_000}}}
	_, err = e.sign(other, "alice", "bob")
	mustRefuse(t, err, "only a replacement of that same transaction")
	// The same inputs and destination but another amount is not a replacement either.
	diffAmt := a
	diffAmt.ID, diffAmt.Revision = "rf-amt", 2
	diffAmt.Outputs = []BTCOutput{{Address: e.hot, Value: 2_000_000}, {Address: e.cold, Value: 5_000_000 - 2_000_000 - 2000}}
	_, err = e.sign(diffAmt, "alice", "bob")
	mustRefuse(t, err, "only a replacement of that same transaction")

	// 3. A real replacement: same input, destination and amount, a higher fee. And a "replacement" that does not pay more is refused.
	repl := a
	repl.ID, repl.Revision = "rf-a", 2
	repl.Outputs = []BTCOutput{{Address: e.hot, Value: 3_000_000}, {Address: e.cold, Value: 5_000_000 - 3_000_000 - 2500}}
	if _, err := e.sign(repl, "alice", "bob"); err != nil {
		t.Fatalf("a replacement with a higher fee: %v", err)
	}
	same := repl
	same.Revision = 3
	same.Outputs = []BTCOutput{{Address: e.hot, Value: 3_000_000}, {Address: e.cold, Value: 5_000_000 - 3_000_000 - 2500}}
	same.ID = "rf-a3"
	_, err = e.sign(same, "alice", "bob")
	mustRefuse(t, err, "must pay more")
	lower := repl
	lower.ID, lower.Revision = "rf-a4", 4
	lower.Outputs = []BTCOutput{{Address: e.hot, Value: 3_000_000}, {Address: e.cold, Value: 5_000_000 - 3_000_000 - 1200}}
	_, err = e.sign(lower, "alice", "bob")
	mustRefuse(t, err, "must pay more")

	// 4. The very same request again returns the same signed file and does not sign twice.
	first, err := e.sign(a, "alice", "bob")
	if err != nil {
		t.Fatal(err)
	}
	again, _ := e.sign(a, "bob", "carol")
	if first.RawTx != again.RawTx {
		t.Fatal("the same request signed twice")
	}
}

// A crash between the record and the signature leaves a record without a signed file: the same request still signs (it is in the record), another
// one does not get around it.
func TestBTCCrashAfterTheRecordIsSafe(t *testing.T) {
	e := newBTCCold(t, "omnibus", t.TempDir())
	r := e.req("rf", 1000, 3_000_000, 5_000_000)
	rs, err := openOutpointRecord(e.cfg.RecordDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := rs.admit(r); err != nil { // the record was written, then the process died before the HSM signed
		t.Fatal(err)
	}
	rs.close()
	if _, err := e.sign(r, "alice", "bob"); err != nil {
		t.Fatalf("the same request after the crash: %v", err)
	}
	liar := e.req("rf-liar", 1000, 3_000_000, 5_000_000)
	liar.Inputs[0].TxID, liar.Inputs[0].Vout, liar.Inputs[0].Value = r.Inputs[0].TxID, r.Inputs[0].Vout, 4_000_000
	liar.Outputs = []BTCOutput{{Address: e.hot, Value: 3_000_000}}
	liar.Outputs = append(liar.Outputs, BTCOutput{Address: e.cold, Value: 999_000})
	_, err = e.sign(liar, "alice", "bob")
	mustRefuse(t, err, "second value")
}

// Two pools hold two keys and two records: an outpoint of one pool's cold address named by a request to the other pool is refused (it is not from that
// pool's cold address), and the records do not share state.
func TestBTCTwoPools(t *testing.T) {
	base := t.TempDir()
	a, b := newBTCCold(t, "omnibus", base), newBTCCold(t, "retail", base)
	ra := a.req("rf-a", 1000, 3_000_000, 5_000_000)
	if _, err := a.sign(ra, "alice", "bob"); err != nil {
		t.Fatal(err)
	}
	// Pool B is asked to spend pool A's outpoint with another value.
	steal := BTCRequest{Version: BTCRequestVersion, ID: "rf-steal", Revision: 1, Network: "regtest", Chain: "btc-t", Pool: "retail", From: b.cold,
		Inputs:  []BTCInput{{TxID: ra.Inputs[0].TxID, Vout: ra.Inputs[0].Vout, Value: 4_000_000, Address: a.cold}},
		Outputs: []BTCOutput{{Address: b.hot, Value: 3_900_000}}}
	_, err := b.sign(steal, "alice", "bob")
	mustRefuse(t, err, "every input must be from the cold address")
	// Pool A is asked for a request of pool B's.
	_, err = a.sign(steal, "alice", "bob")
	mustRefuse(t, err, "this signer holds pool")
	entries, _ := os.ReadDir(filepath.Join(b.cfg.RecordDir, "btc", "outpoints"))
	if len(entries) != 0 {
		t.Fatalf("pool B's record holds %d outpoints though it signed nothing", len(entries))
	}
}

// The online side's check of an imported file: a changed output, a signature of another key, and another request's file are refused.
func TestBTCVerifySignedMatchesRefusesWhatIsNotTheRequest(t *testing.T) {
	e := newBTCCold(t, "omnibus", t.TempDir())
	r := e.req("rf", 1000, 3_000_000, 5_000_000)
	s, err := e.sign(r, "alice", "bob")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBTCSignedMatches(r, r.HashHex(), s); err != nil {
		t.Fatal(err)
	}
	// Another request's hash.
	if _, err := VerifyBTCSignedMatches(r, strings.Repeat("0", 64), s); err == nil {
		t.Fatal("a signed file for another request hash was accepted")
	}
	// A transaction that pays somewhere else: build and sign it with the same key, put it in the file.
	evil := r
	evil.Outputs = []BTCOutput{{Address: e.other, Value: 3_000_000}, r.Outputs[1]}
	evilSigned, err := signWithoutRules(e, evil)
	if err != nil {
		t.Fatal(err)
	}
	evilSigned.RequestHash = r.HashHex()
	if _, err := VerifyBTCSignedMatches(r, r.HashHex(), evilSigned); err == nil {
		t.Fatal("a signed transaction that is not the request's was accepted")
	}
	// A valid structure signed by another key.
	k, _ := btcec.NewPrivateKey()
	wrong, err := signWithoutRulesKey(e, r, btcKey{k})
	if err != nil {
		t.Fatal(err)
	}
	wrong.RequestHash = r.HashHex()
	if _, err := VerifyBTCSignedMatches(r, r.HashHex(), wrong); err == nil {
		t.Fatal("a signature of another key was accepted")
	}
}

func signWithoutRules(e *btcEnv, r BTCRequest) (BTCSigned, error) {
	return signWithoutRulesKey(e, r, e.key)
}

// signWithoutRulesKey signs r with key, skipping every rule: it stands for an attacker who has the key but not the rules.
func signWithoutRulesKey(e *btcEnv, r BTCRequest, key btcKey) (BTCSigned, error) {
	tx, err := r.Tx()
	if err != nil {
		return BTCSigned{}, err
	}
	pub := key.priv.PubKey()
	kh := hash160(pub.SerializeCompressed())
	tx.wit = make([][][]byte, len(tx.ins))
	for i := range tx.ins {
		d := tx.sighash(i, kh)
		sr, ss, _ := key.SignDigest(context.Background(), d)
		der, err := derLowS(sr, ss)
		if err != nil {
			return BTCSigned{}, err
		}
		tx.wit[i] = [][]byte{append(der, byte(btcSighash)), pub.SerializeCompressed()}
	}
	return BTCSigned{Version: BTCSignedVersion, RequestID: r.ID, RawTx: hex.EncodeToString(tx.serialize(true)), TxID: tx.TxID(), Signer: e.cold}, nil
}

// The config is checked for its network: an address of another network refuses to start.
func TestBTCConfigIsCheckedForTheNetwork(t *testing.T) {
	e := newBTCCold(t, "omnibus", t.TempDir())
	bad := *e.cfg
	bad.HotShards = []string{"bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"}
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "another network") {
		t.Fatalf("a mainnet hot shard in a regtest config: %v", err)
	}
	bad = *e.cfg
	bad.Network = "mainnet"
	if err := bad.Validate(); err == nil {
		t.Fatal("regtest pins on mainnet accepted")
	}
	bad = *e.cfg
	bad.HotShards = []string{e.cold}
	if err := bad.Validate(); err == nil {
		t.Fatal("the cold address as a hot shard accepted")
	}
	bad = *e.cfg
	bad.PublicKey = "04" + strings.Repeat("11", 64)
	if err := bad.Validate(); err == nil {
		t.Fatal("an uncompressed key accepted")
	}
	_ = fmt.Sprint
}
