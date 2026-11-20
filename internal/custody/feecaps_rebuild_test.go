package custody

import (
	"context"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
)

// rebuildChain builds a payload that carries a counter standing for the fee-cap change the core builds under, and can undo an unsent build.
type rebuildChain struct {
	*fakeChain
	seq     int
	builds  int
	undone  int
	partsOf func(id string) string
}

func (c *rebuildChain) BuildWithdrawal(_ context.Context, _ pgx.Tx, w chain.WithdrawalIntent) (chain.UnsignedTx, error) {
	c.builds++
	return chain.UnsignedTx{Chain: testChain, Digest: []byte{1, 2, 3}, Payload: []byte(fmt.Sprintf(`{"fee_caps_seq":%d}`, c.seq)),
		KeyRef: chain.KeyRef{PartitionID: c.partsOf(w.ID), Path: "1/0"}}, nil
}

func (c *rebuildChain) UndoUnsent(context.Context, pgx.Tx, string, string) error {
	c.undone++
	return nil
}

// A withdrawal whose first send the zone refused only for another fee-cap change is rebuilt under the caps now in force, with the same job id, in one
// transaction: nothing is voided and the hold stays. Any other refusal changes nothing.
func TestRebuildWithdrawalJobAfterFeeCapsRefusal(t *testing.T) {
	ctx := context.Background()
	counted0 := feeCapsRefusals.Load()
	s, fc := newSvc(t)
	rc := &rebuildChain{fakeChain: fc}
	s.Chain = rc
	if _, _, err := s.CreateCustomer(ctx, "ops", "c1", ""); err != nil {
		t.Fatal(err)
	}
	if err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		return s.transfer(ctx, tx, "pre", depAcct(testChain, "ETH"), custAcct("c1", testChain, "ETH"), big.NewInt(1000), nil)
	}); err != nil {
		t.Fatal(err)
	}
	to := common.HexToAddress("0x52908400098527886E0F7030069857D2E4169EE7").Hex()
	w, _, err := s.RequestWithdrawal(ctx, WithdrawalRequest{Actor: "ini", IdempotencyKey: "k1", Customer: "c1", Asset: "ETH", To: to, Amount: big.NewInt(300)})
	if err != nil {
		t.Fatal(err)
	}
	rc.partsOf = func(string) string { return w.PartitionID }
	jobID, err := s.BuildWithdrawalJob(ctx, w.ID)
	if err != nil {
		t.Fatal(err)
	}
	reject := func(reason string) {
		if _, err := s.Pool.Exec(ctx, `UPDATE sign_jobs SET status='rejected', reject_reason=$2 WHERE id=$1`, jobID, reason); err != nil {
			t.Fatal(err)
		}
	}
	state := func() (status, payload, jstatus string) {
		s.Pool.QueryRow(ctx, `SELECT status FROM withdrawals WHERE id=$1`, w.ID).Scan(&status)
		s.Pool.QueryRow(ctx, `SELECT payload::text, status FROM sign_jobs WHERE id=$1`, jobID).Scan(&payload, &jstatus)
		return
	}

	// Another refusal: nothing changes.
	reject("tx_mismatch: fee too high")
	if ok, err := s.RebuildWithdrawalJob(ctx, w.ID); err != nil || ok || rc.undone != 0 || rc.builds != 1 {
		t.Fatalf("another refusal: rebuilt %v %v (undone %d, builds %d)", ok, err, rc.undone, rc.builds)
	}

	// The zone refused for another fee-cap change; the core is now on change 1.
	reject("tx_mismatch: btc: transaction does not match intent: " + btc.FeeCapsSeqNote)
	rc.seq = 1
	if ok, err := s.RebuildWithdrawalJob(ctx, w.ID); err != nil || !ok {
		t.Fatalf("rebuild: %v %v", ok, err)
	}
	if st, payload, js := state(); st != WdSigning || js != "pending" || payload != `{"fee_caps_seq": 1}` || rc.undone != 1 || rc.builds != 2 {
		t.Fatalf("after the rebuild: withdrawal %s, job %s %s (undone %d, builds %d)", st, js, payload, rc.undone, rc.builds)
	}
	// The hold stays: the withdrawal is not failed and the money is still held.
	bal, _ := s.Led.Balance(ctx, s.Pool, custAcct("c1", testChain, "ETH"))
	if bal.Held.Cmp(big.NewInt(300)) != 0 {
		t.Fatalf("held %s", bal.Held)
	}
	// A signature may exist (another input of the transaction was signed before the zone changed): not ours to rebuild, the cancel path decides.
	if _, err := s.Pool.Exec(ctx, `INSERT INTO sign_jobs (id, partition_id, key_ref, chain, intent, digest, payload, status) SELECT $2, partition_id, key_ref, chain, intent, '\x04', payload, 'done' FROM sign_jobs WHERE id=$1`, jobID, jobID+".1"); err != nil {
		t.Fatal(err)
	}
	reject("tx_mismatch: " + btc.FeeCapsSeqNote)
	if ok, err := s.RebuildWithdrawalJob(ctx, w.ID); err != nil || ok || rc.builds != 2 {
		t.Fatalf("a job that may hold a signature: %v %v (builds %d)", ok, err, rc.builds)
	}
	if _, err := s.Pool.Exec(ctx, `DELETE FROM sign_jobs WHERE id=$1`, jobID+".1"); err != nil {
		t.Fatal(err)
	}
	// A pending job is not rebuilt again.
	if _, err := s.Pool.Exec(ctx, `UPDATE sign_jobs SET status='pending', reject_reason=NULL WHERE id=$1`, jobID); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.RebuildWithdrawalJob(ctx, w.ID); err != nil || ok || rc.builds != 2 {
		t.Fatalf("a pending job: %v %v", ok, err)
	}
	// If the build cannot be made now the refusal stays on record and nothing is lost: the transaction rolls back.
	reject("tx_mismatch: " + btc.FeeCapsSeqNote)
	s.Chain = &failingRebuild{rebuildChain: rc}
	for i := 0; i < 2; i++ { // the poll retries a rebuild that fails: it must not count the same refusal again
		if ok, err := s.RebuildWithdrawalJob(ctx, w.ID); err == nil || ok {
			t.Fatalf("a failed build: %v %v", ok, err)
		}
	}
	if n := feeCapsRefusals.Load() - counted0; n != 1 {
		t.Fatalf("the counter moved by %d: one refusal rebuilt once, then two failed rebuilds, want 1", n)
	}
	if st, _, js := state(); st != WdSigning || js != "rejected" {
		t.Fatalf("after a failed rebuild: withdrawal %s, job %s", st, js)
	}
}

type failingRebuild struct{ *rebuildChain }

func (f *failingRebuild) BuildWithdrawal(context.Context, pgx.Tx, chain.WithdrawalIntent) (chain.UnsignedTx, error) {
	return chain.UnsignedTx{}, chain.ErrNotEnoughOutputs
}
