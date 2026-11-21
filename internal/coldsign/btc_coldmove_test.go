package coldsign

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
)

// btcMoveEnv is a Bitcoin cold signer whose config pins a successor cold address.
func btcMoveEnv(t *testing.T) (*btcEnv, string) {
	e := newBTCCold(t, "omnibus", t.TempDir())
	k, _ := btcec.NewPrivateKey()
	nc, _ := BTCAddressOf("regtest", hex.EncodeToString(k.PubKey().SerializeCompressed()))
	e.cfg.ColdMove = &BTCColdMoveConfig{NewCold: nc, MaxAmount: 900_000_000}
	if err := e.cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return e, nc
}

// move is a cold-to-cold request: every input, one output to dest, no change; the fee is what is left.
func (e *btcEnv) move(id, dest string, fee uint64, values ...uint64) BTCRequest {
	r := BTCRequest{Version: BTCRequestVersion, ID: id, Revision: 1, Network: "regtest", Chain: "btc-t", Pool: e.cfg.Pool, From: e.cold, Kind: KindColdMove}
	var sum uint64
	for _, v := range values {
		r.Inputs = append(r.Inputs, BTCInput{TxID: e.txid(), Value: v, Address: e.cold})
		sum += v
	}
	r.Outputs = []BTCOutput{{Address: dest, Value: sum - fee}}
	return r
}

func TestBTCColdMoveSignsWholeAmountToTheNewCold(t *testing.T) {
	e, nc := btcMoveEnv(t)
	r := e.move("mv-1", nc, 1500, 60_000_000, 70_000_000) // above a refill's cap of 50M, within the move cap
	s, err := e.sign(r, "alice", "bob")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := VerifyBTCSignedMatches(r, r.HashHex(), s)
	if err != nil {
		t.Fatal(err)
	}
	var tx wire.MsgTx
	if err := tx.Deserialize(bytes.NewReader(raw)); err != nil || len(tx.TxOut) != 1 || tx.TxOut[0].Value != 129_998_500 {
		t.Fatalf("outputs: %v %+v", err, tx.TxOut)
	}
	// Replay: the same request returns the same file.
	s2, err := e.sign(r, "alice", "bob")
	if err != nil || s2.RawTx != s.RawTx {
		t.Fatalf("replay: %v", err)
	}
}

func TestBTCColdMoveRefusals(t *testing.T) {
	e, nc := btcMoveEnv(t)
	cases := []struct {
		name string
		mut  func(*BTCRequest)
		ops  []string
		want string
	}{
		{"destination not pinned", func(r *BTCRequest) { r.Outputs[0].Address = e.other }, []string{"alice", "bob"}, "only go to the pinned new cold address"},
		{"destination is a hot shard", func(r *BTCRequest) { r.Outputs[0].Address = e.hot }, []string{"alice", "bob"}, "only go to the pinned new cold address"},
		{"destination is the old cold address", func(r *BTCRequest) { r.Outputs[0].Address = e.cold }, []string{"alice", "bob"}, "only go to the pinned new cold address"},
		{"change output", func(r *BTCRequest) {
			r.Outputs[0].Value -= 5000
			r.Outputs = append(r.Outputs, BTCOutput{Address: e.cold, Value: 4000})
		}, []string{"alice", "bob"}, "exactly one"},
		{"two payments", func(r *BTCRequest) {
			r.Outputs[0].Value -= 5000
			r.Outputs = append(r.Outputs, BTCOutput{Address: nc, Value: 4000})
		}, []string{"alice", "bob"}, "exactly one"},
		{"amount above the move cap", func(r *BTCRequest) {
			r.Inputs[0].Value = 950_000_000
			r.Outputs[0].Value = 950_000_000 - 1000
		}, []string{"alice", "bob"}, "cold_move cap"},
		{"amount below dust", func(r *BTCRequest) { *r = e.move("mv", nc, 100, 350) }, []string{"alice", "bob"}, "below dust"},
		{"fee above the cap", func(r *BTCRequest) { r.Outputs[0].Value -= 30_000 }, []string{"alice", "bob"}, "above the cap"},
		{"an input from another address", func(r *BTCRequest) { r.Inputs[0].Address = e.other }, []string{"alice", "bob"}, "every input must be from the cold address"},
		{"too many inputs", func(r *BTCRequest) {
			for i := 0; i < 5; i++ {
				r.Inputs = append(r.Inputs, BTCInput{TxID: e.txid(), Value: 1000, Address: e.cold})
			}
		}, []string{"alice", "bob"}, "at most 5"},
		{"too few custodians", func(r *BTCRequest) {}, []string{"alice"}, "1 valid approval(s)"},
		{"unknown kind", func(r *BTCRequest) { r.Kind = "sweep-all" }, []string{"alice", "bob"}, "is not known"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := e.move("mv", nc, 1000, 20_000_000, 30_000_000)
			tc.mut(&r)
			_, err := e.sign(r, tc.ops...)
			mustRefuse(t, err, tc.want)
		})
	}
	// A refill may not pay the new cold address.
	rr := e.req("rf", 1000, 3_000_000, 2_000_000, 2_500_000)
	rr.Outputs[0].Address = nc
	_, err := e.sign(rr, "alice", "bob")
	mustRefuse(t, err, "not one of the pinned hot shards")
	// A signer without cold_move signs no move.
	g := newBTCCold(t, "omnibus", t.TempDir())
	_, err = g.sign(g.move("mv", nc, 1000, 2_000_000), "alice", "bob")
	mustRefuse(t, err, "has no cold_move")
}

func TestBTCColdMoveReplayAndOutpointRules(t *testing.T) {
	e, nc := btcMoveEnv(t)
	e.cfg.ColdMove.MinApprovals = 3
	r := e.move("mv-1", nc, 2000, 5_000_000)
	_, err := e.sign(r, "alice", "bob")
	mustRefuse(t, err, "2 valid approval(s) from distinct configured operators, 3 required")
	if _, err := e.sign(r, "alice", "bob", "carol"); err != nil {
		t.Fatal(err)
	}
	// The same outpoint in another move, to the same pinned address but another amount, is refused: an outpoint is signed for one intent.
	r2 := r
	r2.ID = "mv-2"
	r2.Outputs = []BTCOutput{{Address: nc, Value: 4_990_000}}
	_, err = e.sign(r2, "alice", "bob", "carol")
	mustRefuse(t, err, "different set of inputs, destination or amount")
	// A refill kind on the same outpoint is another intent too.
	r3 := r
	r3.Kind = ""
	r3.Outputs = []BTCOutput{{Address: e.hot, Value: 4_000_000}, {Address: e.cold, Value: 990_000}}
	_, err = e.sign(r3, "alice", "bob", "carol")
	mustRefuse(t, err, "already signed")
}

func TestBTCColdMoveConfigIsChecked(t *testing.T) {
	e := newBTCCold(t, "omnibus", t.TempDir())
	k, _ := btcec.NewPrivateKey()
	nc, _ := BTCAddressOf("regtest", hex.EncodeToString(k.PubKey().SerializeCompressed()))
	mainnet, _ := BTCAddressOf("mainnet", hex.EncodeToString(k.PubKey().SerializeCompressed()))
	for name, m := range map[string]*BTCColdMoveConfig{
		"own address":     {NewCold: e.cold, MaxAmount: 1},
		"hot shard":       {NewCold: e.hot, MaxAmount: 1},
		"other network":   {NewCold: mainnet, MaxAmount: 1},
		"no cap":          {NewCold: nc},
		"too many people": {NewCold: nc, MaxAmount: 1, MinApprovals: 9},
	} {
		e.cfg.ColdMove = m
		if err := e.cfg.Validate(); err == nil {
			t.Errorf("%s: config accepted", name)
		}
	}
}
