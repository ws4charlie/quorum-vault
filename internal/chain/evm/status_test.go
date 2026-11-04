package evm

import (
	"context"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
)

// fakeNode scripts what the node answers, call by call.
type fakeNode struct {
	receipts   []*types.Receipt // answers to successive TransactionReceipt calls; nil = not found
	calls      int
	head       uint64
	nonce      uint64
	nonceAtArg *big.Int
	order      []string
}

func (f *fakeNode) TransactionReceipt(context.Context, common.Hash) (*types.Receipt, error) {
	f.order = append(f.order, "receipt")
	i := f.calls
	f.calls++
	if i < len(f.receipts) && f.receipts[i] != nil {
		return f.receipts[i], nil
	}
	return nil, ethereum.NotFound
}
func (f *fakeNode) TransactionByHash(context.Context, common.Hash) (*types.Transaction, bool, error) {
	return nil, false, ethereum.NotFound
}
func (f *fakeNode) BlockNumber(context.Context) (uint64, error) { return f.head, nil }
func (f *fakeNode) NonceAt(_ context.Context, _ common.Address, b *big.Int) (uint64, error) {
	f.order = append(f.order, "nonce")
	f.nonceAtArg = b
	return f.nonce, nil
}

func statusAdapter(t *testing.T, confirmations uint64) (*Adapter, string) {
	t.Helper()
	pool := dbtest.New(t)
	a := &Adapter{cfg: Config{Chain: "c", Confirmations: confirmations}, pool: pool}
	h := common.Hash{9}.Hex()
	if _, err := pool.Exec(context.Background(), `INSERT INTO evm_tx_attempts (tx_hash, chain, address, nonce) VALUES ($1,'c','0xhot',5)`, h); err != nil {
		t.Fatal(err)
	}
	return a, h
}

func rcpt(block uint64, status uint64) *types.Receipt {
	return &types.Receipt{Status: status, BlockNumber: new(big.Int).SetUint64(block)}
}

// A transaction that mines between the first receipt read and the nonce read is
// confirmed, not dropped: the receipt is read again after the nonce.
func TestStatusTransactionMiningBetweenTheReadsIsNotDropped(t *testing.T) {
	a, h := statusAdapter(t, 0)
	f := &fakeNode{head: 10, nonce: 6, receipts: []*types.Receipt{nil, rcpt(10, 1)}}
	st, err := a.statusWith(context.Background(), f, h)
	if err != nil || st != chain.TxConfirmed {
		t.Fatalf("status %s err %v, want confirmed", st, err)
	}
	if got := f.order; len(got) < 3 || got[0] != "receipt" || got[1] != "nonce" || got[2] != "receipt" {
		t.Fatalf("read order %v: the receipt must be read again after the nonce", got)
	}
}

func TestStatusDroppedOnlyWhenNonceMovedAndNoReceiptAfterIt(t *testing.T) {
	a, h := statusAdapter(t, 0)
	f := &fakeNode{head: 10, nonce: 6}
	if st, err := a.statusWith(context.Background(), f, h); err != nil || st != chain.TxDropped {
		t.Fatalf("status %s err %v, want dropped (nonce passed, never a receipt)", st, err)
	}
	// A forgotten transaction: the nonce is still unused, so it is pending, not dropped.
	f = &fakeNode{head: 10, nonce: 5}
	if st, err := a.statusWith(context.Background(), f, h); err != nil || st != chain.TxPending {
		t.Fatalf("status %s err %v, want pending", st, err)
	}
}

// "The nonce passed" is judged at the safe head, not the latest block.
func TestStatusJudgesTheNonceAtTheSafeHead(t *testing.T) {
	a, h := statusAdapter(t, 3)
	f := &fakeNode{head: 10, nonce: 6}
	if _, err := a.statusWith(context.Background(), f, h); err != nil {
		t.Fatal(err)
	}
	if f.nonceAtArg == nil || f.nonceAtArg.Uint64() != 7 {
		t.Fatalf("nonce read at %v, want the safe head 7", f.nonceAtArg)
	}
	// Chain younger than the confirmation depth: nothing is final, so nothing is dropped.
	f = &fakeNode{head: 2, nonce: 6}
	if st, err := a.statusWith(context.Background(), f, h); err != nil || st != chain.TxPending {
		t.Fatalf("status %s err %v, want pending", st, err)
	}
}
