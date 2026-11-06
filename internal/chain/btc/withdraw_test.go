package btc

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
)

const wPart = "qv-us/btc-t/BTC/hot/omnibus/0"

type wEnv struct {
	t    *testing.T
	a    *Adapter
	node *fakeNode
	priv *hdkeychain.ExtendedKey
	hot  string
	dest string
	n    int
}

func newWEnv(t *testing.T) *wEnv {
	t.Helper()
	node := newNode(t)
	m, _ := hdkeychain.NewMaster(bytes.Repeat([]byte{7}, 32), &chaincfg.RegressionNetParams)
	k := m
	for _, n := range []uint32{hdkeychain.HardenedKeyStart + 84, hdkeychain.HardenedKeyStart + 1, hdkeychain.HardenedKeyStart} {
		k, _ = k.Derive(n)
	}
	xpub, _ := k.Neuter()
	acct, _ := NewAccount("regtest", xpub.String())
	hot, _ := acct.Address([]uint32{1, 0})
	dest := foreignDest()
	pool := dbtest.New(t)
	a, err := New(context.Background(), Config{Chain: "btc-t", Network: "regtest", RPCURL: node.srv.URL, AccountXpub: xpub.String(),
		HotShards: []HotShardConfig{{PartitionID: wPart, Address: hot, Path: []uint32{1, 0}}}, MaxInputs: 5, FallbackFeeRate: 10, MaxFeeRate: 50, MaxTxFeeSats: 20_000}, pool)
	if err != nil {
		t.Fatal(err)
	}
	return &wEnv{t: t, a: a, node: node, priv: k, hot: hot, dest: dest}
}

func foreignDest() string {
	m, _ := hdkeychain.NewMaster(bytes.Repeat([]byte{9}, 32), &chaincfg.RegressionNetParams)
	p, _ := m.Neuter()
	a, _ := NewAccount("regtest", p.String())
	s, _ := a.Address([]uint32{0, 0})
	return s
}

// fund inserts an available output of value sats, older than any inserted after it.
func (e *wEnv) fund(value int64) string {
	e.t.Helper()
	e.n++
	var h [32]byte
	h[0], h[31] = byte(e.n), 0xEE
	id := hex.EncodeToString(h[:])
	if _, err := e.a.pool.Exec(context.Background(), `INSERT INTO btc_utxos (chain, txid, vout, value, partition_id, path, created_at) VALUES ('btc-t',$1,0,$2,$3,'1/0', now() + $4::interval)`,
		id, value, wPart, fmt.Sprintf("%d seconds", e.n)); err != nil {
		e.t.Fatal(err)
	}
	return id
}

func (e *wEnv) build(id string, amount int64, commit bool) (chain.UnsignedTx, error) {
	e.t.Helper()
	tx, err := e.a.pool.Begin(context.Background())
	if err != nil {
		e.t.Fatal(err)
	}
	u, err := e.a.BuildWithdrawal(context.Background(), tx, chain.WithdrawalIntent{ID: id, PartitionID: wPart, Asset: "BTC", To: e.dest, Amount: big.NewInt(amount)})
	if err != nil || !commit {
		tx.Rollback(context.Background())
		return u, err
	}
	if err := tx.Commit(context.Background()); err != nil {
		e.t.Fatal(err)
	}
	return u, nil
}

func (e *wEnv) payload(u chain.UnsignedTx) Payload {
	p, err := DecodePayload(u.Payload)
	if err != nil {
		e.t.Fatal(err)
	}
	return p
}

func (e *wEnv) count(status string) int {
	var n int
	e.a.pool.QueryRow(context.Background(), `SELECT count(*) FROM btc_utxos WHERE chain='btc-t' AND status=$1`, status).Scan(&n)
	return n
}

// The oldest outputs are picked first, the payment is the first output and the change the second, the fee is rate x vsize, and the outputs
// are reserved with the attempt recorded.
func TestBuildWithdrawalSelectsOldestFirstWithChange(t *testing.T) {
	e := newWEnv(t)
	old1, old2 := e.fund(100_000), e.fund(100_000)
	e.fund(100_000)
	u, err := e.build("w1", 150_000, true)
	if err != nil {
		t.Fatal(err)
	}
	p := e.payload(u)
	if len(p.Inputs) != 2 || p.Inputs[0].TxID != old1 || p.Inputs[1].TxID != old2 || len(u.More) != 1 || u.KeyRef.Path != "1/0" || u.KeyRef.PartitionID != wPart {
		t.Fatalf("inputs %+v key %+v", p.Inputs, u.KeyRef)
	}
	fee := uint64(vsize(2, mustScript(t, e.dest), mustScript(t, e.hot))) * 10
	if len(p.Outputs) != 2 || p.Outputs[0].Address != e.dest || p.Outputs[0].Value != 150_000 || p.Outputs[1].Address != e.hot || p.Outputs[1].Value != 200_000-150_000-fee {
		t.Fatalf("outputs %+v, want 150000 to dest and %d change", p.Outputs, 50_000-fee)
	}
	if e.count("reserved") != 2 || e.count("available") != 1 {
		t.Fatalf("reserved %d available %d", e.count("reserved"), e.count("available"))
	}
	var f int64
	e.a.pool.QueryRow(context.Background(), `SELECT fee FROM btc_attempts WHERE chain='btc-t' AND owner_id='w1'`).Scan(&f)
	if uint64(f) != fee {
		t.Fatalf("attempt fee %d, want %d", f, fee)
	}
	if r, _ := e.a.Reservation(context.Background(), e.a.pool, "withdrawal", "w1"); !r.Open {
		t.Fatal("no open reservation")
	}
	// The digest is the first input's, and the signing zone's own rebuild agrees.
	built, _ := BuildUnsigned(p, e.a.acct)
	if !bytes.Equal(built.Digests[0], u.Digest) || !bytes.Equal(built.Digests[1], u.More[0].Digest) {
		t.Fatal("digests")
	}
}

func mustScript(t *testing.T, addr string) []byte {
	s, err := OutputScript(addr, &chaincfg.RegressionNetParams)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Exact amount: nothing left for change, one output. Change at dust: it goes to the fee.
func TestBuildWithdrawalExactAmountAndDustChange(t *testing.T) {
	e := newWEnv(t)
	fee1 := uint64(vsize(1, mustScript(t, e.dest))) * 10
	e.fund(int64(100_000 + fee1))
	u, err := e.build("exact", 100_000, true)
	if err != nil {
		t.Fatal(err)
	}
	if p := e.payload(u); len(p.Outputs) != 1 || p.Outputs[0].Value != 100_000 {
		t.Fatalf("%+v", p.Outputs)
	}
	// 100 sats of change is below the dust limit (294): it is not an output, it is fee.
	e2 := newWEnv(t)
	fee2 := uint64(vsize(1, mustScript(t, e2.dest), mustScript(t, e2.hot))) * 10
	e2.fund(int64(100_000 + fee2 + 100))
	u, err = e2.build("dust", 100_000, true)
	if err != nil {
		t.Fatal(err)
	}
	p := e2.payload(u)
	if len(p.Outputs) != 1 {
		t.Fatalf("dust change became an output: %+v", p.Outputs)
	}
	var f int64
	e2.a.pool.QueryRow(context.Background(), `SELECT fee FROM btc_attempts WHERE chain='btc-t' AND owner_id='dust'`).Scan(&f)
	if f != int64(p.Inputs[0].Value)-100_000 {
		t.Fatalf("fee %d, want everything but the payment", f)
	}
	// Change just above dust is an output.
	e3 := newWEnv(t)
	e3.fund(int64(100_000 + uint64(vsize(1, mustScript(t, e3.dest), mustScript(t, e3.hot)))*10 + 294))
	u, _ = e3.build("above", 100_000, true)
	if p := e3.payload(u); len(p.Outputs) != 2 || p.Outputs[1].Value != 294 {
		t.Fatalf("%+v", p.Outputs)
	}
}

// Too few outputs is a typed, retryable error and reserves nothing (the build rolled back); a fee above the cap is another, final one.
func TestBuildWithdrawalNotEnoughOutputs(t *testing.T) {
	e := newWEnv(t)
	e.fund(50_000)
	if _, err := e.build("w", 100_000, false); !errors.Is(err, chain.ErrNotEnoughOutputs) {
		t.Fatalf("%v", err)
	}
	if e.count("available") != 1 || e.count("reserved") != 0 {
		t.Fatal("a failed build reserved outputs")
	}
	// More inputs than max_inputs would be needed: also "not enough" now (consolidation is a later task).
	e = newWEnv(t)
	for i := 0; i < 6; i++ {
		e.fund(20_000)
	}
	if _, err := e.build("w", 110_000, false); !errors.Is(err, chain.ErrNotEnoughOutputs) {
		t.Fatalf("six small outputs, five inputs at most: %v", err)
	}
	if _, err := e.build("w", 80_000, true); err != nil {
		t.Fatal(err)
	}
}

// Two builds at once never pick one output (SKIP LOCKED plus reserving at once); many against few: each either builds or waits, and the committed
// transactions share no input.
func TestConcurrentBuildsNeverShareAnOutput(t *testing.T) {
	e := newWEnv(t)
	for i := 0; i < 4; i++ {
		e.fund(100_000)
	}
	var mu sync.Mutex
	used := map[string]string{}
	built, waited := 0, 0
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			id := fmt.Sprintf("c%d", i)
			u, err := e.build(id, 60_000, true)
			mu.Lock()
			defer mu.Unlock()
			if errors.Is(err, chain.ErrNotEnoughOutputs) {
				waited++
				return
			}
			if err != nil {
				t.Errorf("%s: %v", id, err)
				return
			}
			built++
			for _, in := range e.payload(u).Inputs {
				k := fmt.Sprintf("%s:%d", in.TxID, in.Vout)
				if other, dup := used[k]; dup {
					t.Errorf("%s and %s both spend %s", id, other, k)
				}
				used[k] = id
			}
		}(i)
	}
	close(start)
	wg.Wait()
	if built != 4 || waited != 8 {
		t.Fatalf("built %d, waited %d (4 outputs of 100000 fund 4 payments of 60000)", built, waited)
	}
	if e.count("reserved") != 4 {
		t.Fatalf("%d reserved", e.count("reserved"))
	}
}

// Settlement spends the inputs and makes the change an available output; a repeat changes nothing. Release gives reserved outputs back.
func TestSettleAndRelease(t *testing.T) {
	e := newWEnv(t)
	e.fund(100_000)
	u, _ := e.build("w1", 40_000, true)
	p := e.payload(u)
	built, _ := BuildUnsigned(p, e.a.acct)
	settle := func() {
		tx, _ := e.a.pool.Begin(context.Background())
		if err := e.a.Settle(context.Background(), tx, "withdrawal", "w1", built.TxID); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	settle()
	settle()
	if e.count("spent") != 1 || e.count("available") != 1 || e.count("reserved") != 0 {
		t.Fatalf("spent %d available %d reserved %d", e.count("spent"), e.count("available"), e.count("reserved"))
	}
	var v int64
	var vout int
	e.a.pool.QueryRow(context.Background(), `SELECT value, vout FROM btc_utxos WHERE chain='btc-t' AND txid=$1`, built.TxID).Scan(&v, &vout)
	if uint64(v) != p.Outputs[1].Value || vout != 1 {
		t.Fatalf("change output %d at %d", v, vout)
	}
	// Release only touches reserved outputs.
	e.fund(100_000)
	if _, err := e.build("w2", 10_000, true); err != nil { // reserves the older of the two available (the change)
		t.Fatal(err)
	}
	if e.count("reserved") == 0 {
		t.Fatal("nothing reserved")
	}
	tx, _ := e.a.pool.Begin(context.Background())
	if err := e.a.ReleaseUnsigned(context.Background(), tx, "withdrawal", "w2"); err != nil {
		t.Fatal(err)
	}
	tx.Commit(context.Background())
	if e.count("reserved") != 0 || e.count("available") != 2 {
		t.Fatalf("reserved %d available %d", e.count("reserved"), e.count("available"))
	}
}

// softSig signs the digests of a built transaction with the software key of the shard, as the gateway would, and returns 64-byte signatures.
func (e *wEnv) sign(u chain.UnsignedTx) []chain.Signature {
	k, _ := e.priv.Derive(1)
	k, _ = k.Derive(0)
	priv, _ := k.ECPrivKey()
	var out []chain.Signature
	for _, in := range u.Inputs() {
		sig := btcecdsa.Sign(priv, in.Digest)
		r, s := sig.R(), sig.S()
		var b [64]byte
		rb, sb := r.Bytes(), s.Bytes()
		copy(b[:32], rb[:])
		copy(b[32:], sb[:])
		out = append(out, chain.Signature{Bytes: b[:]})
	}
	return out
}

var _ = ecdsa.PublicKey{}
var _ = crypto.S256
var _ = btcec.S256

// Assemble makes a transaction the script interpreter accepts; a signature that does not verify is refused before anything is sent; Broadcast
// records the attempt, sends, and treats "already known" as success.
func TestAssembleBroadcastAndStatus(t *testing.T) {
	e := newWEnv(t)
	e.fund(100_000)
	e.fund(100_000)
	u, err := e.build("w1", 150_000, true)
	if err != nil {
		t.Fatal(err)
	}
	sigs := e.sign(u)
	st, err := e.a.Assemble(u, sigs)
	if err != nil {
		t.Fatal(err)
	}
	var tx wire.MsgTx
	if err := tx.Deserialize(bytes.NewReader(st.Raw)); err != nil {
		t.Fatal(err)
	}
	p := e.payload(u)
	built, _ := BuildUnsigned(p, e.a.acct)
	fetch := map[wire.OutPoint]*wire.TxOut{}
	for i, in := range tx.TxIn {
		fetch[in.PreviousOutPoint] = wire.NewTxOut(int64(p.Inputs[i].Value), built.Scripts[i])
	}
	pf := txscript.NewMultiPrevOutFetcher(fetch)
	hashes := txscript.NewTxSigHashes(&tx, pf)
	for i := range tx.TxIn {
		vm, err := txscript.NewEngine(built.Scripts[i], &tx, i, txscript.StandardVerifyFlags, nil, hashes, int64(p.Inputs[i].Value), pf)
		if err != nil {
			t.Fatal(err)
		}
		if err := vm.Execute(); err != nil {
			t.Fatalf("input %d: %v", i, err)
		}
	}
	// A signature for another digest is refused.
	bad := []chain.Signature{sigs[1], sigs[0]}
	if _, err := e.a.Assemble(u, bad); err == nil {
		t.Fatal("swapped signatures were assembled")
	}
	if _, err := e.a.Assemble(u, sigs[:1]); err == nil {
		t.Fatal("one signature for two inputs")
	}
	// Broadcast: a transaction this cell never built is refused; ours is sent; "already known" is success.
	ctx := context.Background()
	out, err := e.a.Outcome(ctx, "withdrawal", "w1")
	if err != nil || out.State != chain.OutcomeOpen || out.Attempts != 0 {
		t.Fatalf("before broadcast: %+v %v", out, err)
	}
	h, err := e.a.Broadcast(ctx, st)
	if err != nil || h != "sent" && h != built.TxID {
		t.Fatalf("broadcast: %q %v", h, err)
	}
	e.node.sendErr = &RPCError{Code: -27, Message: "Transaction already in block chain"}
	if h, err := e.a.Broadcast(ctx, st); err != nil || h != built.TxID {
		t.Fatalf("a repeat: %q %v", h, err)
	}
	e.node.sendErr = &RPCError{Code: -26, Message: "txn-mempool-conflict"}
	if _, err := e.a.Broadcast(ctx, st); err == nil {
		t.Fatal("a real refusal by the node was swallowed")
	}
	e.node.sendErr = nil
	// Status and outcome follow the node: unknown and shallow are pending, the spend depth confirms.
	if s, _ := e.a.Status(ctx, built.TxID); s != chain.TxPending {
		t.Fatalf("unknown to the node: %s", s)
	}
	e.node.txs[built.TxID] = 0
	if s, _ := e.a.Status(ctx, built.TxID); s != chain.TxPending {
		t.Fatalf("in the mempool: %s", s)
	}
	e.node.txs[built.TxID] = 1
	if s, _ := e.a.Status(ctx, built.TxID); s != chain.TxPending {
		t.Fatalf("one confirmation: %s", s)
	}
	out, _ = e.a.Outcome(ctx, "withdrawal", "w1")
	if out.State != chain.OutcomeOpen || out.Attempts != 1 {
		t.Fatalf("one confirmation: %+v", out)
	}
	e.node.txs[built.TxID] = 2
	out, _ = e.a.Outcome(ctx, "withdrawal", "w1")
	if out.State != chain.OutcomeConfirmed || out.Hash != built.TxID || out.Kind != chain.AttemptSend {
		t.Fatalf("at the spend depth: %+v", out)
	}
	fee, err := e.a.TxFee(ctx, built.TxID)
	if err != nil || fee.Int64() <= 0 {
		t.Fatalf("fee %v %v", fee, err)
	}
	// Raw transactions that are not ours are refused.
	other := tx.Copy()
	other.LockTime = 7
	var buf bytes.Buffer
	other.Serialize(&buf)
	if _, err := e.a.Broadcast(ctx, chain.SignedTx{Raw: buf.Bytes()}); err == nil {
		t.Fatal("a foreign transaction was broadcast")
	}
	_ = time.Second
	_ = pgx.ErrNoRows
}

// A payment to a hot address from outside is funding; the change of our own transaction is not (settlement records it).
func TestScanFindsFundingButNotOurOwnChange(t *testing.T) {
	e := newWEnv(t)
	e.fund(100_000)
	u, _ := e.build("w1", 40_000, true)
	built, _ := BuildUnsigned(e.payload(u), e.a.acct)
	e.node.mine()
	// Block 1: operator funding to the hot address, and our own transaction with its change (the node's txid for it is the one we built).
	e.node.mineTx(Tx{Txid: "operator-tx", Vin: []Vin{{}}, Vout: []Output{hotOut(e.hot, "0.5", 0)}}, Tx{Txid: built.TxID, Vin: []Vin{{}}, Vout: []Output{hotOut(e.dest, "0.0004", 0), hotOut(e.hot, "0.0005", 1)}})
	for e.node.height() < 8 {
		e.node.mine()
	}
	res, err := e.a.Scan(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Funding) != 1 || res.Funding[0].TxHash != "operator-tx" || res.Funding[0].Amount.Int64() != 50_000_000 || res.Funding[0].PartitionID != wPart || res.Funding[0].Vout != 0 {
		t.Fatalf("funding %+v", res.Funding)
	}
	// Recording is once only.
	tx, _ := e.a.pool.Begin(context.Background())
	first, err := e.a.RecordFunding(context.Background(), tx, res.Funding[0])
	second, err2 := e.a.RecordFunding(context.Background(), tx, res.Funding[0])
	tx.Commit(context.Background())
	if err != nil || err2 != nil || !first || second {
		t.Fatalf("first %v second %v (%v %v)", first, second, err, err2)
	}
}

func hotOut(addr, val string, n uint32) Output {
	var o Output
	o.N = n
	o.Value = jsonNumber(val)
	o.ScriptPubKey.Address = addr
	return o
}
