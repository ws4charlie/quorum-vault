package custody

import (
	"context"
	"math/big"
	"sync"
	"testing"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/chain/sol"
	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
)

// solRaceChain is a Solana chain cell with one finalized refill transaction and a probe: the first time a reader asks about the probe signature
// after the refill's transaction was read, the books settle the refill, as the worker does at any moment in production.
type solRaceChain struct {
	chain.Adapter
	mu      sync.Mutex
	reads   int // how many times the probe was asked about
	fire    func()
	refill  string
	fee     *big.Int
	balance map[string]*big.Int
}

const (
	raceProbe  = "probe-op"
	raceRefill = "refill-tx"
)

func (f *solRaceChain) Chain() string { return "sol-local" }
func (f *solRaceChain) AssetView(context.Context, []string, uint64) (chain.AssetView, error) {
	return chain.AssetView{Slot: 10, Balance: map[string]map[string]*big.Int{"SOL": {}, "TKN": {}}}, nil
}
func (f *solRaceChain) Status(_ context.Context, h string) (chain.TxStatus, error) {
	if h == raceProbe {
		f.mu.Lock()
		f.reads++
		n, fire := f.reads, f.fire
		f.mu.Unlock()
		if n == 2 && fire != nil { // the second read of the landed set: the refill's transaction has just been read
			fire()
		}
	}
	return chain.TxConfirmed, nil
}
func (f *solRaceChain) TxFee(_ context.Context, h string) (*big.Int, error) {
	if h == raceRefill {
		return f.fee, nil
	}
	return new(big.Int), nil
}

type solRaceReader struct{ f *solRaceChain }

func (r solRaceReader) SafeHead(context.Context) (uint64, error)        { return 10, nil }
func (r solRaceReader) TxBlock(context.Context, string) (uint64, error) { return 10, nil }
func (r solRaceReader) Balance(_ context.Context, addr, asset string, _ uint64) (*big.Int, error) {
	if b, ok := r.f.balance[addr+"|"+asset]; ok {
		return new(big.Int).Set(b), nil
	}
	return new(big.Int), nil
}

// A cold refill is final on the chain and the worker books it (amount to the hot shard, the fee out of cold) while Reconcile is reading. The books'
// cold side must be read inside the same window as the finalized-transaction set, or the fee is counted twice and Reconcile reports a difference
// of exactly one fee ("the chain holds 5,100 lamports more than the books"). A real difference must still be reported.
func TestReconcileSOLColdBookedWhileReading(t *testing.T) {
	const (
		fund   = 20_000_000_000
		amount = 9_000_000_000
		fee    = 5100
	)
	f := &solRaceChain{fee: big.NewInt(fee), balance: map[string]*big.Int{}}
	rd := solRaceReader{f}
	run := func(t *testing.T, breakIt bool) Report {
		hot := sol.Address([32]byte{1})
		cold := sol.Address([32]byte{2})
		sf := solFile()
		sf.Chain.SOL.HotShards, sf.Chain.SOL.NoncePool, sf.Chain.SOL.NonceRentLamports = []string{hot}, 1, 1_447_680
		sf.Chain.SOL.ComputeUnitLimit, sf.Chain.SOL.ComputeUnitPrice, sf.Chain.SOL.MaxMicroLamports, sf.Chain.SOL.FeeBumpPercent = 100_000, 1000, 10_000, 25
		sf.Cold.Addresses = map[string]string{"omnibus": cold}
		cfg, err := sf.Build()
		if err != nil {
			t.Fatal(err)
		}
		s := New(dbtest.New(t), cfg, f, rd)
		ctx := context.Background()
		if err := s.Bootstrap(ctx); err != nil {
			t.Fatal(err)
		}
		hp := cfg.PartitionKey("SOL", 0).String()
		if err := s.FundCold(ctx, "f1", 0, "SOL", big.NewInt(fund)); err != nil {
			t.Fatal(err)
		}
		const id = "rf-race"
		if _, err := s.Pool.Exec(ctx, `INSERT INTO refills (id, chain, asset, partition_id, cold_address, to_address, amount, status, tx_hash, raw_tx)
			VALUES ($1,$2,'SOL',$3,$4,$5,$6,'signed',$7,'00')`, id, cfg.Chain, hp, cold, hot, big.NewInt(amount).String(), raceRefill); err != nil {
			t.Fatal(err)
		}
		if err := s.recordRefillBroadcast(ctx, id, raceRefill); err != nil { // the books: cold -> refill at broadcast
			t.Fatal(err)
		}
		if _, err := s.Pool.Exec(ctx, `INSERT INTO sol_cold_ops (chain, signature, cold, kind) VALUES ($1,$2,$3,'setup')`, cfg.Chain, raceProbe, cold); err != nil {
			t.Fatal(err)
		}
		// The chain: the refill is final (the cold address paid the amount and the fee, the hot shard has the amount).
		cb := big.NewInt(fund - amount - fee)
		if breakIt {
			cb.Sub(cb, big.NewInt(1)) // a real difference of one lamport
		}
		f.balance = map[string]*big.Int{cold + "|SOL": cb, hot + "|SOL": big.NewInt(amount)}
		f.reads = 0
		f.fire = func() { // the worker settles the refill now
			if err := s.SettleRefill(ctx, id, false); err != nil {
				t.Error(err)
			}
		}
		rep, err := s.Reconcile(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return rep
	}
	t.Run("settled during the read", func(t *testing.T) {
		rep := run(t, false)
		if !rep.Clean || rep.SkippedChainChecks != 0 {
			t.Fatalf("clean %v skipped %d: %+v", rep.Clean, rep.SkippedChainChecks, rep.Failures())
		}
	})
	t.Run("a real difference is still reported", func(t *testing.T) {
		rep := run(t, true)
		if rep.Clean {
			t.Fatal("a one-lamport difference on the cold address was not reported")
		}
	})
}
