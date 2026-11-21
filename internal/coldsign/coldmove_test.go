package coldsign

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

var newColdAddr = common.HexToAddress("0x00000000000000000000000000000000000c01d2")

// moveFixture is the EVM fixture with a cold_move section: the successor cold address is pinned in the offline config.
func moveFixture(t *testing.T) *fixture {
	f := newFixture(t)
	f.cfg.ColdMove = &ColdMoveConfig{NewCold: newColdAddr.Hex(), MaxAmount: map[string]string{"ETH": "1000000000000000000000", "USDT": "500000000000"}}
	if err := f.cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) move(mut func(*Request)) RequestFile {
	return f.request(func(r *Request) {
		r.Kind, r.To, r.Nonce = KindColdMove, newColdAddr.Hex(), 900
		if mut != nil {
			mut(r)
		}
	})
}

func TestColdMoveSignsToThePinnedNewCold(t *testing.T) {
	f := moveFixture(t)
	rf := f.move(func(r *Request) { r.Amount = "50000000000000000000" }) // above a refill's cap, within the move cap
	s, err := f.sign(rf, f.approvals(rf, "alice", "bob"))
	if err != nil {
		t.Fatal(err)
	}
	tx, err := VerifySignedMatches(rf.Request, rf.RequestHash, s)
	if err != nil || *tx.To() != newColdAddr {
		t.Fatalf("signed move: %v to %v", err, tx.To())
	}
	// A token move is a transfer(newCold, amount) on the configured token.
	tf := f.move(func(r *Request) {
		r.Nonce, r.Asset, r.Token, r.Amount, r.Gas = 901, "USDT", tokenAddr.Hex(), "100000000000", 70000
	})
	ts, err := f.sign(tf, f.approvals(tf, "alice", "bob"))
	if err != nil {
		t.Fatal(err)
	}
	tx, err = VerifySignedMatches(tf.Request, tf.RequestHash, ts)
	if err != nil || *tx.To() != tokenAddr || !strings.Contains(common.Bytes2Hex(tx.Data()), strings.ToLower(newColdAddr.Hex()[2:])) {
		t.Fatalf("token move: %v", err)
	}
}

// Every refusal of the offline signer for a cold-move: the online side is not trusted, so each is a thing it (or a person) might try.
func TestColdMoveRefusals(t *testing.T) {
	f := moveFixture(t)
	n := uint64(910)
	fresh := func(mut func(*Request)) RequestFile {
		n++
		return f.move(func(r *Request) {
			r.Nonce = n
			if mut != nil {
				mut(r)
			}
		})
	}
	rf := fresh(nil)
	_, err := f.sign(rf, f.approvals(rf, "alice"))
	wantRefusal(t, "too few custodians", err, "1 valid approval(s) from distinct configured operators, 2 required")

	rf = fresh(func(r *Request) { r.To = f.hot.Hex() })
	_, err = f.sign(rf, f.approvals(rf, "alice", "bob"))
	wantRefusal(t, "destination is a hot address, not the new cold", err, "may only go to the pinned new cold address")

	rf = fresh(func(r *Request) { r.To = common.HexToAddress("0x00000000000000000000000000000000000bad01").Hex() })
	_, err = f.sign(rf, f.approvals(rf, "alice", "bob"))
	wantRefusal(t, "destination not pinned", err, "may only go to the pinned new cold address")

	rf = fresh(func(r *Request) { r.Amount = "1000000000000000000001" })
	_, err = f.sign(rf, f.approvals(rf, "alice", "bob"))
	wantRefusal(t, "amount above the move cap", err, "above the per-ceremony cap")

	rf = fresh(func(r *Request) { r.Amount = "0" })
	_, err = f.sign(rf, f.approvals(rf, "alice", "bob"))
	wantRefusal(t, "amount zero", err, "zero or above")

	rf = fresh(func(r *Request) { r.Asset, r.Token = "DOGE", "" })
	_, err = f.sign(rf, f.approvals(rf, "alice", "bob"))
	wantRefusal(t, "asset not configured", err, "is not configured")

	rf = fresh(func(r *Request) { r.From = f.hot.Hex() })
	_, err = f.sign(rf, f.approvals(rf, "alice", "bob"))
	wantRefusal(t, "not from this signer's cold address", err, "this signer's cold address is")

	rf = fresh(func(r *Request) { r.MaxFeePerGas, r.MaxPriorityFeePerGas = "900000000000000", "900000000000000" })
	_, err = f.sign(rf, f.approvals(rf, "alice", "bob"))
	wantRefusal(t, "fee above the cap", err, "above the cap")

	// A refill kind with the new cold as its destination is not a cold-move: the hot list is what a refill may pay.
	rf = fresh(func(r *Request) { r.Kind = KindRefill })
	_, err = f.sign(rf, f.approvals(rf, "alice", "bob"))
	wantRefusal(t, "a refill may not pay the new cold", err, "not one of the pinned hot addresses")

	// A signer whose config has no cold_move signs none, whoever asks and however many approve.
	g := newFixture(t)
	rf = g.move(nil)
	_, err = g.sign(rf, g.approvals(rf, "alice", "bob", "carol"))
	wantRefusal(t, "wrong kind for this config", err, "has no cold_move")

	// An approval of another request does not count towards the move.
	other := fresh(func(r *Request) { r.Amount = "1" })
	rf = fresh(nil)
	_, err = f.sign(rf, append(f.approvals(other, "alice"), f.approvals(rf, "bob")...))
	wantRefusal(t, "an approval of another request", err, "1 valid approval(s)")

	// A damaged file.
	rf = fresh(nil)
	rf.Request.Amount = "2"
	_, err = f.sign(rf, f.approvals(rf, "alice", "bob"))
	wantRefusal(t, "request file changed after hashing", err, "damaged")
}

func TestColdMoveMinApprovalsAndReplay(t *testing.T) {
	f := moveFixture(t)
	f.cfg.ColdMove.MinApprovals = 3
	rf := f.move(nil)
	_, err := f.sign(rf, f.approvals(rf, "alice", "bob"))
	wantRefusal(t, "two of the three the move asks for", err, "2 valid approval(s) from distinct configured operators, 3 required")
	s, err := f.sign(rf, f.approvals(rf, "alice", "bob", "carol"))
	if err != nil {
		t.Fatal(err)
	}
	// The same request again returns the same signed file, and signs nothing more (replay).
	calls := f.sw.calls
	s2, err := f.sign(rf, f.approvals(rf, "alice", "bob", "carol"))
	if err != nil || s2.RawTx != s.RawTx || f.sw.calls != calls {
		t.Fatalf("replay: %v, same=%v, extra signatures=%d", err, s2.RawTx == s.RawTx, f.sw.calls-calls)
	}
	// Another move at the same nonce for different content is refused, even though it goes to the same pinned address.
	rf2 := f.move(func(r *Request) { r.Amount = "7" })
	_, err = f.sign(rf2, f.approvals(rf2, "alice", "bob", "carol"))
	wantRefusal(t, "same nonce, other amount", err, "already signed for different content")
}

func TestColdMoveConfigIsChecked(t *testing.T) {
	f := newFixture(t)
	cold := crypto.PubkeyToAddress(coldKey.PublicKey).Hex()
	for name, m := range map[string]*ColdMoveConfig{
		"own address":     {NewCold: cold, MaxAmount: map[string]string{"ETH": "1"}},
		"hot address":     {NewCold: f.hot.Hex(), MaxAmount: map[string]string{"ETH": "1"}},
		"no caps":         {NewCold: newColdAddr.Hex()},
		"unknown asset":   {NewCold: newColdAddr.Hex(), MaxAmount: map[string]string{"DOGE": "1"}},
		"too many people": {NewCold: newColdAddr.Hex(), MaxAmount: map[string]string{"ETH": "1"}, MinApprovals: 9},
		"not an address":  {NewCold: "0x12", MaxAmount: map[string]string{"ETH": "1"}},
		"non-canonical":   {NewCold: newColdAddr.Hex(), MaxAmount: map[string]string{"ETH": "01"}},
	} {
		f.cfg.ColdMove = m
		if err := f.cfg.Validate(); err == nil {
			t.Errorf("%s: config accepted", name)
		}
	}
	_ = ed25519.PublicKeySize
}
