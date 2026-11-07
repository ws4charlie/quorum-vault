package custody

import (
	"context"
	"log/slog"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
)

// fakeConsolidator is a Bitcoin chain cell that plans what it is told, and records what the service asks of it.
type fakeConsolidator struct {
	chain.Adapter
	plan    chain.Consolidation
	planErr error
	fee     int64
	settled []string
	built   []chain.ConsolidateIntent
	held    bool // the outputs of the consolidation are still reserved
}

func (f *fakeConsolidator) Reservation(context.Context, chain.Querier, string, string) (chain.Reservation, error) {
	return chain.Reservation{Open: f.held}, nil
}

func (f *fakeConsolidator) Chain() string { return "btc-reg" }
func (f *fakeConsolidator) PlanConsolidation(context.Context, string) (chain.Consolidation, error) {
	return f.plan, f.planErr
}
func (f *fakeConsolidator) BuildConsolidation(_ context.Context, _ pgx.Tx, c chain.ConsolidateIntent) (chain.UnsignedTx, error) {
	f.built = append(f.built, c)
	return chain.UnsignedTx{Chain: "btc-reg", Digest: make([]byte, 32), Payload: []byte(`{}`), KeyRef: chain.KeyRef{PartitionID: c.PartitionID, Path: "1/0"}}, nil
}
func (f *fakeConsolidator) TxFee(context.Context, string) (*big.Int, error) {
	return big.NewInt(f.fee), nil
}
func (f *fakeConsolidator) Settle(_ context.Context, _ pgx.Tx, kind, id, txid string) error {
	f.settled = append(f.settled, kind+":"+id+":"+txid)
	return nil
}

func newConsolidationSvc(t *testing.T, above int) (*Service, *fakeConsolidator, string) {
	t.Helper()
	xpub := xpubFor(t, &chaincfg.RegressionNetParams)
	addr, err := btc.DeriveHotAddress("regtest", xpub, 0)
	if err != nil {
		t.Fatal(err)
	}
	f := btcFile("regtest", xpub)
	f.Chain.BTC.HotShards = []BTCShardFile{{Address: addr, Path: []uint32{1, 0}}}
	f.Chain.BTC.ConsolidateAbove, f.Chain.BTC.ConsolidateMaxFeeRate = above, 5
	cfg, err := f.Build()
	if err != nil {
		t.Fatal(err)
	}
	fc := &fakeConsolidator{plan: chain.Consolidation{Amount: big.NewInt(500_000), Inputs: 20}, fee: 1_234}
	s := New(dbtest.New(t), cfg, fc, &fakeReader{})
	if err := s.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s, fc, cfg.PartitionKey("BTC", 0).String()
}

func (s *Service) openConsolidations(t *testing.T) int {
	t.Helper()
	var n int
	if err := s.Pool.QueryRow(context.Background(), `SELECT count(*) FROM consolidations WHERE status NOT IN ('confirmed','failed')`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// A round plans one consolidation per hot partition, with the amount the chain says; nothing while one is open (one at a time per partition).
func TestPlanConsolidationsOnePerPartition(t *testing.T) {
	s, _, part := newConsolidationSvc(t, 30)
	log := slog.Default()
	got, err := s.PlanConsolidations(context.Background(), log)
	if err != nil || len(got) != 1 {
		t.Fatalf("%v %v", got, err)
	}
	if got[0].PartitionID != part || got[0].Amount.Int64() != 500_000 || got[0].Status != "planned" {
		t.Fatalf("%+v", got[0])
	}
	for i := 0; i < 3; i++ {
		if got, err := s.PlanConsolidations(context.Background(), log); err != nil || len(got) != 0 {
			t.Fatalf("a second consolidation while one is open: %v %v", got, err)
		}
	}
	if s.openConsolidations(t) != 1 {
		t.Fatal("more than one open")
	}
	// The database refuses a second open row for the partition, whatever the planner does.
	if _, err := s.Pool.Exec(context.Background(), `INSERT INTO consolidations (id, chain, asset, partition_id, amount, status) VALUES ('dup','btc-reg','BTC',$1,5,'planned')`, part); err == nil {
		t.Fatal("two open consolidations on one partition")
	}
}

// Nothing runs with consolidate_above 0, while the chain says wait or has nothing to merge, while a hot-to-cold move is open on the partition, or
// while scanning is halted.
func TestPlanConsolidationsConditions(t *testing.T) {
	ctx, log := context.Background(), slog.Default()
	s, fc, part := newConsolidationSvc(t, 0)
	if got, err := s.PlanConsolidations(ctx, log); err != nil || len(got) != 0 {
		t.Fatalf("consolidate_above 0: %v %v", got, err)
	}

	s, fc, part = newConsolidationSvc(t, 30)
	fc.plan = chain.Consolidation{Amount: new(big.Int), Wait: "the fee rate is above consolidate_max_fee_rate"}
	if got, err := s.PlanConsolidations(ctx, log); err != nil || len(got) != 0 {
		t.Fatalf("fee rate above the ceiling: %v %v", got, err)
	}
	fc.plan = chain.Consolidation{Amount: new(big.Int)}
	if got, err := s.PlanConsolidations(ctx, log); err != nil || len(got) != 0 {
		t.Fatalf("below the threshold: %v %v", got, err)
	}
	fc.plan = chain.Consolidation{Amount: big.NewInt(900), Inputs: 1}
	if got, err := s.PlanConsolidations(ctx, log); err != nil || len(got) != 0 {
		t.Fatalf("one worthwhile output: %v %v", got, err)
	}
	fc.plan = chain.Consolidation{Amount: big.NewInt(500_000), Inputs: 20}

	// A hot-to-cold move is open on the partition: it is spending those outputs.
	if _, err := s.Pool.Exec(ctx, `INSERT INTO cold_moves (id, chain, asset, partition_id, to_address, amount, status) VALUES ('cm1','btc-reg','BTC',$1,'x',5,'signing')`, part); err != nil {
		t.Fatal(err)
	}
	if got, err := s.PlanConsolidations(ctx, log); err != nil || len(got) != 0 {
		t.Fatalf("a cold move is open: %v %v", got, err)
	}
	if _, err := s.Pool.Exec(ctx, `UPDATE cold_moves SET status='confirmed' WHERE id='cm1'`); err != nil {
		t.Fatal(err)
	}

	// Scanning halted (a reorganization below the safe depth): the books cannot be trusted.
	if err := s.haltScan(ctx, "test"); err != nil {
		t.Fatal(err)
	}
	if got, err := s.PlanConsolidations(ctx, log); err != nil || len(got) != 0 {
		t.Fatalf("scanning halted: %v %v", got, err)
	}
	if _, err := s.Pool.Exec(ctx, `DELETE FROM scan_halts`); err != nil {
		t.Fatal(err)
	}
	if got, err := s.PlanConsolidations(ctx, log); err != nil || len(got) != 1 {
		t.Fatalf("all conditions met: %v %v", got, err)
	}
}

// After a failed consolidation the partition is left alone for retry_after, doubling for each failure in a row.
func TestPlanConsolidationsBacksOffAfterFailures(t *testing.T) {
	ctx, log := context.Background(), slog.Default()
	s, _, part := newConsolidationSvc(t, 30)
	s.Cfg.SweepRetryAfter = time.Hour
	got, err := s.PlanConsolidations(ctx, log)
	if err != nil || len(got) != 1 {
		t.Fatalf("%v %v", got, err)
	}
	if err := s.FailConsolidationBeforeBroadcast(ctx, got[0].ID, "gateway refused: policy_consolidate_rate"); err != nil {
		t.Fatal(err)
	}
	if got, err := s.PlanConsolidations(ctx, log); err != nil || len(got) != 0 {
		t.Fatalf("planned again at once after a failure: %v %v", got, err)
	}
	// Once the wait has passed it plans again.
	if _, err := s.Pool.Exec(ctx, `UPDATE consolidations SET updated_at = now() - interval '2 hours' WHERE partition_id=$1`, part); err != nil {
		t.Fatal(err)
	}
	if got, err := s.PlanConsolidations(ctx, log); err != nil || len(got) != 1 {
		t.Fatalf("after the wait: %v %v", got, err)
	}
}

// The job is built once: the intent names the shard and the sum of the inputs, carries no approvals, and a repeat returns the same job.
func TestBuildConsolidationJobAndSettleBooksOnlyTheFee(t *testing.T) {
	ctx, log := context.Background(), slog.Default()
	s, fc, part := newConsolidationSvc(t, 30)
	got, err := s.PlanConsolidations(ctx, log)
	if err != nil || len(got) != 1 {
		t.Fatalf("%v %v", got, err)
	}
	id := got[0].ID
	job, err := s.BuildConsolidationJob(ctx, id)
	if err != nil || !strings.HasPrefix(job, "consol:"+id) {
		t.Fatalf("job %q: %v", job, err)
	}
	again, err := s.BuildConsolidationJob(ctx, id)
	if err != nil || again != job || len(fc.built) != 1 {
		t.Fatalf("a repeat built again: %q %v (%d builds)", again, err, len(fc.built))
	}
	var intent string
	if err := s.Pool.QueryRow(ctx, `SELECT intent::text FROM sign_jobs WHERE id=$1`, job).Scan(&intent); err != nil {
		t.Fatal(err)
	}
	to, _ := s.Cfg.BTCShardAddress(part)
	for _, want := range []string{`"consolidate"`, to, `"500000"`} {
		if !strings.Contains(intent, want) {
			t.Fatalf("intent %s lacks %s", intent, want)
		}
	}
	if strings.Contains(intent, "approvals") {
		t.Fatalf("a consolidation carries no approvals: %s", intent)
	}

	// Broadcast books nothing: the value does not move.
	hotBefore, err := s.posted(ctx, hotAcct(part))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RecordConsolidationBroadcast(ctx, id, "txaa"); err != nil {
		t.Fatal(err)
	}
	if after, _ := s.posted(ctx, hotAcct(part)); after.Cmp(hotBefore) != 0 {
		t.Fatalf("the hot account moved at broadcast: %s -> %s", hotBefore, after)
	}
	if c, _ := s.GetConsolidation(ctx, id); c.Status != "broadcast" || c.TxHash != "txaa" {
		t.Fatalf("%+v", c)
	}

	// Settlement books the fee, from hot to fee, once, and tells the chain cell.
	for i := 0; i < 2; i++ {
		if err := s.SettleConsolidation(ctx, id, "txaa"); err != nil {
			t.Fatal(err)
		}
	}
	hot, _ := s.posted(ctx, hotAcct(part))
	fee, _ := s.posted(ctx, feeAcct(s.Cfg.Chain, "BTC"))
	if new(big.Int).Sub(hot, hotBefore).Int64() != 1_234 || fee.Int64() != -1_234 {
		t.Fatalf("hot moved by %s, fee account %s: only the fee of 1234 may be booked", new(big.Int).Sub(hot, hotBefore), fee)
	}
	if len(fc.settled) != 1 || fc.settled[0] != "consolidate:"+id+":txaa" {
		t.Fatalf("settled %v", fc.settled)
	}
	if c, _ := s.GetConsolidation(ctx, id); c.Status != "confirmed" {
		t.Fatalf("%+v", c)
	}
	// Another consolidation may now be planned.
	if got, err := s.PlanConsolidations(ctx, log); err != nil || len(got) != 1 {
		t.Fatalf("after settlement: %v %v", got, err)
	}
}

// A consolidation that was refused before anything was signed ends failed once its outputs are released; one whose outputs are still reserved is not
// ended.
func TestFailConsolidationNeedsTheReservationReleased(t *testing.T) {
	ctx, log := context.Background(), slog.Default()
	s, fc, _ := newConsolidationSvc(t, 30)
	got, _ := s.PlanConsolidations(ctx, log)
	id := got[0].ID
	fc.held = true
	if err := s.FailConsolidationBeforeBroadcast(ctx, id, "no"); err != ErrReservationOpen {
		t.Fatalf("with the outputs still reserved: %v", err)
	}
	fc.held = false
	if err := s.FailConsolidationBeforeBroadcast(ctx, id, "no"); err != nil {
		t.Fatal(err)
	}
	if c, _ := s.GetConsolidation(ctx, id); c.Status != "failed" || c.Reason != "no" {
		t.Fatalf("%+v", c)
	}
	// A parked consolidation is not listed as open work (the failure above is older than retry_after by now).
	if _, err := s.Pool.Exec(ctx, `UPDATE consolidations SET updated_at = now() - interval '5 hours'`); err != nil {
		t.Fatal(err)
	}
	got, _ = s.PlanConsolidations(ctx, log)
	if len(got) != 1 {
		t.Fatalf("%v", got)
	}
	if err := s.ParkConsolidation(ctx, got[0].ID, "needs a person"); err != nil {
		t.Fatal(err)
	}
	if open, _ := s.OpenConsolidations(ctx); len(open) != 0 {
		t.Fatalf("a parked consolidation is listed as open: %+v", open)
	}
}
