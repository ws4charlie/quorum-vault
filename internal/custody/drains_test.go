package custody

import (
	"context"
	"encoding/json"
	"log/slog"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/chain/evm"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// drainChain is the fake chain with a drain builder: it allocates a nonce row at the old address, as the EVM cell does.
type drainChain struct {
	*fakeChain
	nonce int
}

func (d *drainChain) BuildDrain(ctx context.Context, tx pgx.Tx, r evm.DrainRequest) (chain.UnsignedTx, error) {
	d.nonce++
	if _, err := tx.Exec(ctx, `INSERT INTO evm_nonce_allocations (chain, address, nonce, owner_kind, owner_id, status) VALUES ($1,$2,$3,'drain',$4,'allocated')`,
		testChain, r.From, d.nonce, r.ID); err != nil {
		return chain.UnsignedTx{}, err
	}
	return chain.UnsignedTx{Chain: testChain, Digest: []byte{byte(d.nonce)}, Payload: []byte(`{}`)}, nil
}

func drainWorld(t *testing.T) (*Service, *evmModel) {
	t.Helper()
	s, fc, m := evmWorld(t)
	s.Chain = &drainChain{fakeChain: fc}
	s.Cfg.DrainRetryAfter = time.Hour
	return s, m
}

func plan(t *testing.T, s *Service) []DrainMove {
	t.Helper()
	mv, err := s.PlanDrains(context.Background(), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	return mv
}

func drainState(t *testing.T, s *Service) (state, reason string) {
	t.Helper()
	if err := s.Pool.QueryRow(context.Background(), `SELECT state, reason FROM keyset_drains WHERE shard_id=$1 AND generation=1`, shard0(s)).Scan(&state, &reason); err != nil {
		t.Fatal(err)
	}
	return
}

// The planner empties one asset at a time: tokens first, the native asset last and not quite all of it; it reports "drained" when nothing above
// dust is left and does not plan after that.
func TestPlanDrainsTokensFirstNativeLastThenDrained(t *testing.T) {
	ctx := context.Background()
	s, m := drainWorld(t)
	gen1 := s.Cfg.HotShards[0].Hex()
	if mv := plan(t, s); len(mv) != 0 {
		t.Fatalf("a shard with one generation is not drained: %+v", mv)
	}
	m.add(gen1, "USDT", 700)
	replaceShard0(t, s)
	m.add(gen2Addr, "ETH", 1) // the successor exists on chain
	mv := plan(t, s)
	if len(mv) != 1 || mv[0].Asset != "USDT" || mv[0].Amount.Int64() != 700 || mv[0].From != gen1 || mv[0].To != gen2Addr || mv[0].FromGeneration != 1 || mv[0].ToGeneration != 2 {
		t.Fatalf("first move: %+v", mv)
	}
	if st, _ := drainState(t, s); st != "moving" {
		t.Fatalf("state %s", st)
	}
	if again := plan(t, s); len(again) != 0 {
		t.Fatalf("one move per generation at a time: %+v", again)
	}
	// Build it: the job names the source and the successor, a short not_after, no approvals.
	jobID, err := s.BuildDrainJob(ctx, mv[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := s.BuildDrainJob(ctx, mv[0].ID); err != nil || again != jobID {
		t.Fatalf("a repeat of the build: %v %v", again, err)
	}
	j, err := signjob.Get(ctx, s.Pool, jobID)
	if err != nil {
		t.Fatal(err)
	}
	var in signjob.Intent
	if err := json.Unmarshal(j.Intent, &in); err != nil {
		t.Fatal(err)
	}
	if in.Kind != signjob.KindDrain || in.From != gen1 || in.To != gen2Addr || in.Asset != "USDT" || in.Amount != "700" || len(j.Approvals) != 0 ||
		in.NotAfter <= time.Now().Unix() || in.NotAfter > time.Now().Add(15*time.Minute).Unix() {
		t.Fatalf("intent %+v approvals %d", in, len(j.Approvals))
	}
	hot := hotAcct(s.Cfg.PartitionKey("ETH", 0).String())
	before, usdtBefore := s.mustPosted(t, hot), s.mustPosted(t, hotAcct(mv[0].PartitionID))

	// Broadcast and mined: the books move by the fee only; the shard's balance is the same.
	if err := s.RecordDrainBroadcast(ctx, mv[0].ID, "0xd1"); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordDrainBroadcast(ctx, mv[0].ID, "0xd1"); err != nil {
		t.Fatal(err)
	}
	if err := s.SettleDrain(ctx, mv[0].ID, "0xd1", chain.TxConfirmed); err != nil {
		t.Fatal(err)
	}
	if err := s.SettleDrain(ctx, mv[0].ID, "0xd1", chain.TxConfirmed); err != nil {
		t.Fatal(err)
	}
	if got := new(big.Int).Sub(s.mustPosted(t, hot), before); got.Int64() != 7 { // the fake chain's fee
		t.Fatalf("native hot account moved by %s, want the fee 7", got)
	}
	if s.mustPosted(t, hotAcct(mv[0].PartitionID)).Cmp(usdtBefore) != 0 {
		t.Fatal("the token balance of the shard must not change")
	}
	m.add(gen1, "USDT", -700)
	m.add(gen2Addr, "USDT", 700)

	// The native asset is last; the dust stays.
	mv = plan(t, s)
	want := new(big.Int).Sub(tenETH, s.Cfg.NativeReserve())
	if len(mv) != 1 || mv[0].Asset != "ETH" || mv[0].Amount.Cmp(want) != 0 {
		t.Fatalf("second move: %+v, want ETH %s", mv, want)
	}
	if _, err := s.BuildDrainJob(ctx, mv[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := s.FailDrainBeforeBroadcast(ctx, mv[0].ID, "x", ""); err != ErrReservationOpen {
		t.Fatalf("an open nonce blocks ending the move: %v", err)
	}
	if _, err := s.Pool.Exec(ctx, `UPDATE evm_nonce_allocations SET status='confirmed'`); err != nil {
		t.Fatal(err)
	}
	if err := s.SettleDrain(ctx, mv[0].ID, "0xd2", chain.TxConfirmed); err != nil {
		t.Fatal(err)
	}
}

func TestPlanDrainsEndsDrainedAndDoesNotRetire(t *testing.T) {
	s, m := drainWorld(t)
	gen1 := s.Cfg.HotShards[0].Hex()
	replaceShard0(t, s)
	m.mu.Lock()
	m.bal[key(gen1, "ETH")] = big.NewInt(5) // dust only
	m.mu.Unlock()
	if mv := plan(t, s); len(mv) != 0 {
		t.Fatalf("%+v", mv)
	}
	if st, _ := drainState(t, s); st != "drained" {
		t.Fatalf("state %s", st)
	}
	var state string
	s.Pool.QueryRow(context.Background(), `SELECT state FROM keysets WHERE shard_id=$1 AND generation=1`, shard0(s)).Scan(&state)
	if state != "draining" {
		t.Fatalf("the generation must not be retired by the planner: %s", state)
	}
	// Something arrives late: the generation is found moving again.
	m.add(gen1, "USDT", 9)
	m.mu.Lock()
	m.bal[key(gen1, "ETH")] = new(big.Int).Set(s.Cfg.NativeReserve())
	m.mu.Unlock()
	if mv := plan(t, s); len(mv) != 1 || mv[0].Asset != "USDT" {
		t.Fatalf("%+v", mv)
	}
}

func TestPlanDrainsWaitsWithAReason(t *testing.T) {
	ctx := context.Background()
	s, m := drainWorld(t)
	gen1 := s.Cfg.HotShards[0].Hex()
	m.add(gen1, "USDT", 50)

	// The successor is only a candidate: the planner shows why and plans nothing.
	if _, err := s.RegisterKeysetCandidate(WithActor(ctx, "a"), shard0(s), gen2Addr, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartDrainingKeyset(WithActor(ctx, "a"), shard0(s), 1, 2); err != nil {
		t.Fatal(err)
	}
	if mv := plan(t, s); len(mv) != 0 {
		t.Fatalf("%+v", mv)
	}
	if st, why := drainState(t, s); st != "waiting" || !strings.Contains(why, "candidate") {
		t.Fatalf("%s %q", st, why)
	}
	if _, err := s.ActivateKeyset(WithActor(ctx, "a"), shard0(s), 2); err != nil {
		t.Fatal(err)
	}

	// Work built from the old address and not final: the drain waits for it.
	attempt(t, s, gen1, "withdrawal", "w-old", "0xold", "send", 0)
	if mv := plan(t, s); len(mv) != 0 {
		t.Fatalf("%+v", mv)
	}
	if _, why := drainState(t, s); !strings.Contains(why, "in flight") {
		t.Fatalf("%q", why)
	}
	s.Pool.Exec(ctx, `UPDATE evm_nonce_allocations SET status='confirmed'`)

	// A token with no gas at the old address.
	m.mu.Lock()
	m.bal[key(gen1, "ETH")] = big.NewInt(1)
	m.mu.Unlock()
	if mv := plan(t, s); len(mv) != 0 {
		t.Fatalf("%+v", mv)
	}
	if _, why := drainState(t, s); !strings.Contains(why, "no gas") {
		t.Fatalf("%q", why)
	}
	m.mu.Lock()
	m.bal[key(gen1, "ETH")] = new(big.Int).Set(tenETH)
	m.mu.Unlock()

	// The zone refuses the move (no start-draining record yet in the zone): the move ends, the generation waits with the zone's words, and the
	// planner leaves it alone until the retry time, then makes the same move again.
	mv := plan(t, s)
	if len(mv) != 1 {
		t.Fatalf("%+v", mv)
	}
	if _, err := s.BuildDrainJob(ctx, mv[0].ID); err != nil {
		t.Fatal(err)
	}
	s.Pool.Exec(ctx, `UPDATE evm_nonce_allocations SET status='cancelled'`) // the cancel confirmed
	if err := s.FailDrainBeforeBroadcast(ctx, mv[0].ID, "the signing zone refused: generation 1 of x is active here, a drain needs it draining or compromised", ""); err != nil {
		t.Fatal(err)
	}
	if st, why := drainState(t, s); st != "waiting" || !strings.Contains(why, "signing zone refused") {
		t.Fatalf("%s %q", st, why)
	}
	if again := plan(t, s); len(again) != 0 {
		t.Fatalf("the planner waits out the retry time: %+v", again)
	}
	s.Pool.Exec(ctx, `UPDATE keyset_drains SET retry_after = now() - interval '1 second'`)
	again := plan(t, s)
	if len(again) != 1 || again[0].Asset != mv[0].Asset || again[0].Amount.Cmp(mv[0].Amount) != 0 || again[0].ID == mv[0].ID {
		t.Fatalf("the refused move is made again from the same place: %+v", again)
	}
}

// A drain is explained at every stage: broadcast and unmined, mined and unsettled, settled. Reconcile is clean throughout, and a reverted drain
// costs its fee and moves nothing.
func TestReconcileExplainsADrainInFlight(t *testing.T) {
	ctx := context.Background()
	s, m := drainWorld(t)
	gen1 := s.Cfg.HotShards[0].Hex()
	replaceShard0(t, s)
	m.add(gen2Addr, "ETH", 1)
	if err := s.FundHot(ctx, "gas2", 0, big.NewInt(1)); err != nil {
		t.Fatal(err)
	}
	requireClean(t, "before", mustReconcile(t, s))
	mv := plan(t, s)
	if len(mv) != 1 {
		t.Fatalf("%+v", mv)
	}
	if _, err := s.BuildDrainJob(ctx, mv[0].ID); err != nil {
		t.Fatal(err)
	}
	attempt(t, s, gen1, "drain", mv[0].ID, "0xdr", "send", 5)
	if err := s.RecordDrainBroadcast(ctx, mv[0].ID, "0xdr"); err != nil {
		t.Fatal(err)
	}
	requireClean(t, "in the mempool", mustReconcile(t, s))
	// mined, not settled: the chain has the transfer and the fee gone
	amt := mv[0].Amount
	m.mu.Lock()
	m.bal[key(gen1, "ETH")].Sub(m.bal[key(gen1, "ETH")], new(big.Int).Add(amt, big.NewInt(7)))
	m.bal[key(gen2Addr, "ETH")].Add(m.bal[key(gen2Addr, "ETH")], amt)
	m.rc["0xdr"] = Receipt{Block: 90, Success: true, Fee: big.NewInt(7)}
	m.mu.Unlock()
	rep := mustReconcile(t, s)
	requireClean(t, "mined, not settled", rep)
	if !hasAdjusted(rep, "hot") {
		t.Fatalf("the fee was not explained: %+v", rep.Checks)
	}
	if err := s.SettleDrain(ctx, mv[0].ID, "0xdr", chain.TxConfirmed); err != nil {
		t.Fatal(err)
	}
	requireClean(t, "settled", mustReconcile(t, s))
}
