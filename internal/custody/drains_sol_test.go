package custody

import (
	"context"
	"math/big"
	"testing"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/chain/sol"
)

// A drain step that only closes an empty token account names no amount: the table must take it (and only it), or the drain would pick the same account for ever.
func TestSolDrainMoveOfAnEmptyTokenAccountIsStored(t *testing.T) {
	ctx := context.Background()
	s, _ := drainWorld(t)
	replaceShard0(t, s)
	ks, err := shardKeysets(ctx, s.Pool, s.Cfg.shardIDOf(0))
	if err != nil || len(ks) != 2 {
		t.Fatalf("keysets %v %v", ks, err)
	}
	part := s.Cfg.PartitionKey("USDT", 0).String()
	step := func(kind string, amount int64) *sol.DrainStep {
		return &sol.DrainStep{Kind: kind, Asset: "USDT", Amount: big.NewInt(amount), Tx: chain.UnsignedTx{Chain: testChain, Digest: []byte{byte(amount) + 1}, Payload: []byte(`{}`),
			KeyRef: chain.KeyRef{PartitionID: part}}}
	}
	if _, err := s.startSolMove(ctx, ks[0], ks[1], step("sol", 0)); err == nil {
		t.Fatal("a zero-amount transfer was stored")
	}
	m, err := s.startSolMove(ctx, ks[0], ks[1], step("token-close", 0))
	if err != nil || m == nil || m.Amount.Sign() != 0 {
		t.Fatalf("the close of an empty token account: %+v %v", m, err)
	}
}
