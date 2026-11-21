package coldsign

import (
	"bytes"
	"context"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil/base58"

	"github.com/ws4charlie/quorum-vault/internal/chain/sol/solmsg"
)

func solMoveEnv(t *testing.T) (*solEnv, string) {
	e := newSOLEnv(t)
	nc := randAddr()
	e.cfg.NonceRent = solmsg.DefaultNonceRent
	e.cfg.ColdMove = &SOLColdMoveConfig{NewCold: nc, MaxAmount: map[string]string{"SOL": "5000000000000", "TKN": "900000000000"}}
	if err := e.cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return e, nc
}

func (e *solEnv) move(nc, asset, amount string, nonceIdx int) SOLRequest {
	r := e.req(asset, amount, nonceIdx, 0)
	r.Kind, r.To = KindSOLColdMove, nc
	return r
}

func (e *solEnv) moveClose(nc string, idx []int, lam []uint64) SOLRequest {
	var v [32]byte
	rand.Read(v[:])
	return SOLRequest{Version: SOLRequestVersion, Kind: KindSOLColdMoveClose, ID: "mc", Chain: "solana-localnet", Pool: "p1", From: e.cold, To: nc,
		NonceIndexes: idx, Lamports: lam, NonceValue: base58.Encode(v[:]), ComputeUnitLimit: 100_000}
}

func (e *solEnv) signReq(r SOLRequest, who ...string) error {
	_, _, err := e.cfg.Sign(context.Background(), r.File(), e.approvals(r, who...), e.signer)
	return err
}

func wantSolRefusal(t *testing.T, what string, err error, contains string) {
	t.Helper()
	if _, ok := err.(*Refusal); !ok || !strings.Contains(err.Error(), contains) {
		t.Errorf("%s: err = %v, want a refusal containing %q", what, err, contains)
	}
}

func TestSOLColdMoveSignsToTheNewCold(t *testing.T) {
	e, nc := solMoveEnv(t)
	for _, asset := range []string{"SOL", "TKN"} {
		r := e.move(nc, asset, "400000000000", 0) // above a refill's cap, within the move cap
		if asset == "TKN" {
			r.CloseSource, r.CreateDestAccount = true, true
		}
		s, _, err := e.cfg.Sign(context.Background(), r.File(), e.approvals(r, "alice", "bob"), e.signer)
		if err != nil {
			t.Fatalf("%s: %v", asset, err)
		}
		raw, err := VerifySOLSignedMatches(r, r.HashHex(), s)
		if err != nil {
			t.Fatalf("%s: %v", asset, err)
		}
		if bytes.Contains(raw, solmsgAddrBytes(e.hot)) {
			t.Fatalf("%s: the move names the hot shard", asset)
		}
		if !bytes.Contains(raw, solmsgAddrBytes(nc)) {
			t.Fatalf("%s: the move does not name the new cold address", asset)
		}
	}
	// The last step: nonce rent to the new cold address.
	q := e.moveClose(nc, []int{1, 2}, []uint64{solmsg.DefaultNonceRent, solmsg.DefaultNonceRent})
	s, _, err := e.cfg.Sign(context.Background(), q.File(), e.approvals(q, "alice", "bob"), e.signer)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := VerifySOLSignedMatches(q, q.HashHex(), s)
	if err != nil || !bytes.Contains(raw, solmsgAddrBytes(nc)) {
		t.Fatalf("close step: %v", err)
	}
	// A refill on a nonce account that the last step closes is refused afterwards.
	rf := e.req("SOL", "1000", 1, 0)
	wantSolRefusal(t, "refill on a closed nonce account", e.signReq(rf, "alice", "bob"), "signed for closing")
}

func TestSOLColdMoveRefusals(t *testing.T) {
	e, nc := solMoveEnv(t)
	other := randAddr()
	cases := []struct {
		name string
		mut  func(r *SOLRequest)
		who  []string
		want string
	}{
		{"destination not pinned", func(r *SOLRequest) { r.To = other }, []string{"alice", "bob"}, "may only go to the pinned new cold address"},
		{"destination is a hot shard", func(r *SOLRequest) { r.To = e.hot }, []string{"alice", "bob"}, "may only go to the pinned new cold address"},
		{"destination is the old cold address", func(r *SOLRequest) { r.To = e.cold }, []string{"alice", "bob"}, "may only go to the pinned new cold address"},
		{"amount above the move cap", func(r *SOLRequest) { r.Amount = "5000000000001" }, []string{"alice", "bob"}, "above the per-ceremony cap"},
		{"amount zero", func(r *SOLRequest) { r.Amount = "0" }, []string{"alice", "bob"}, "zero or above"},
		{"asset not configured", func(r *SOLRequest) { r.Asset = "XYZ" }, []string{"alice", "bob"}, "is not configured"},
		{"wrong mint", func(r *SOLRequest) { r.Asset, r.Mint = "TKN", other }, []string{"alice", "bob"}, "is mint"},
		{"foreign nonce", func(r *SOLRequest) { r.NonceAccount = other }, []string{"alice", "bob"}, "not a nonce account of the cold address"},
		{"another source", func(r *SOLRequest) { r.From = other }, []string{"alice", "bob"}, "this tool's cold key"},
		{"close_source on SOL", func(r *SOLRequest) { r.CloseSource = true }, []string{"alice", "bob"}, "token only"},
		{"price over the cap", func(r *SOLRequest) { r.ComputeUnitPrice = 2_000_000 }, []string{"alice", "bob"}, "outside the caps"},
		{"too few custodians", func(r *SOLRequest) {}, []string{"alice"}, "1 valid approval(s)"},
		{"another pool", func(r *SOLRequest) { r.Pool = "p2" }, []string{"alice", "bob"}, "this tool is configured for"},
	}
	for _, tc := range cases {
		r := e.move(nc, "SOL", "1000", 0)
		tc.mut(&r)
		wantSolRefusal(t, tc.name, e.signReq(r, tc.who...), tc.want)
	}
	// A refill may not pay the new cold address.
	rr := e.req("SOL", "1000", 0, 0)
	rr.To = nc
	wantSolRefusal(t, "a refill to the new cold", e.signReq(rr, "alice", "bob"), "not one of this pool's hot shards")
	// A signer without cold_move signs no move of either kind.
	g := newSOLEnv(t)
	g.cfg.NonceRent = solmsg.DefaultNonceRent
	wantSolRefusal(t, "no cold_move: transfer", g.signReq(g.move(nc, "SOL", "1000", 0), "alice", "bob"), "has no cold_move")
	wantSolRefusal(t, "no cold_move: close step", g.signReq(g.moveClose(nc, []int{1}, []uint64{solmsg.DefaultNonceRent}), "alice", "bob"), "has no cold_move")
}

func TestSOLColdMoveCloseStepRefusals(t *testing.T) {
	e, nc := solMoveEnv(t)
	rent := uint64(solmsg.DefaultNonceRent)
	cases := []struct {
		name string
		mut  func(q *SOLRequest)
		want string
	}{
		{"rent to another address", func(q *SOLRequest) { q.To = randAddr() }, "may only go to the pinned new cold address"},
		{"rent to the hot shard", func(q *SOLRequest) { q.To = e.hot }, "may only go to the pinned new cold address"},
		{"with an amount", func(q *SOLRequest) { q.Amount = "5" }, "closes nonce accounts and nothing else"},
		{"with a mint", func(q *SOLRequest) { q.Mint = e.mint }, "closes nonce accounts and nothing else"},
		{"an account outside the pool", func(q *SOLRequest) { q.NonceIndexes = []int{1, 9} }, "outside the pool"},
		{"a balance that is no nonce account's", func(q *SOLRequest) { q.Lamports = []uint64{rent * 1000, 1} }, "not a nonce account's"},
		{"a repeated account", func(q *SOLRequest) { q.NonceIndexes = []int{1, 1} }, "repeated"},
		{"no accounts", func(q *SOLRequest) { q.NonceIndexes, q.Lamports = nil, nil }, "1 to 8 nonce accounts"},
		{"a huge fee", func(q *SOLRequest) { q.ComputeUnitPrice = e.cfg.MaxMicroLamports + 1 }, "outside the caps"},
	}
	for _, tc := range cases {
		q := e.moveClose(nc, []int{1, 2}, []uint64{rent, rent})
		tc.mut(&q)
		wantSolRefusal(t, tc.name, e.signReq(q, "alice", "bob"), tc.want)
	}
	q := e.moveClose(nc, []int{2}, []uint64{rent})
	wantSolRefusal(t, "one approval", e.signReq(q, "alice"), "1 valid approval(s)")
	e.cfg.NonceRent = 0
	wantSolRefusal(t, "no nonce_rent", e.signReq(q, "alice", "bob"), "no nonce_rent")
}

func TestSOLColdMoveReplayMinApprovalsAndNonceRules(t *testing.T) {
	e, nc := solMoveEnv(t)
	e.cfg.ColdMove.MinApprovals = 3
	r := e.move(nc, "SOL", "1000", 0)
	wantSolRefusal(t, "two of three", e.signReq(r, "alice", "bob"), "3 required")
	s1, _, err := e.cfg.Sign(context.Background(), r.File(), e.approvals(r, "alice", "bob", "carol"), e.signer)
	if err != nil {
		t.Fatal(err)
	}
	s2, _, err := e.cfg.Sign(context.Background(), r.File(), e.approvals(r, "alice", "bob", "carol"), e.signer)
	if err != nil || s1.RawTx != s2.RawTx {
		t.Fatalf("replay: %v", err)
	}
	// The same nonce value for another amount is another payment: refused.
	o := r
	o.Amount, o.ID = "2000", "other"
	wantSolRefusal(t, "same nonce value, other amount", e.signReq(o, "alice", "bob", "carol"), "already signed for a different payment")
}

func TestSOLColdMoveConfigIsChecked(t *testing.T) {
	e := newSOLEnv(t)
	for name, m := range map[string]*SOLColdMoveConfig{
		"own address":     {NewCold: e.cold, MaxAmount: map[string]string{"SOL": "1"}},
		"hot shard":       {NewCold: e.hot, MaxAmount: map[string]string{"SOL": "1"}},
		"no caps":         {NewCold: randAddr()},
		"unknown asset":   {NewCold: randAddr(), MaxAmount: map[string]string{"XYZ": "1"}},
		"too many people": {NewCold: randAddr(), MaxAmount: map[string]string{"SOL": "1"}, MinApprovals: 9},
		"not an address":  {NewCold: "nope", MaxAmount: map[string]string{"SOL": "1"}},
	} {
		e.cfg.ColdMove = m
		if err := e.cfg.Validate(); err == nil {
			t.Errorf("%s: config accepted", name)
		}
	}
}
