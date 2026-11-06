package custody

import (
	"bytes"
	"context"
	"log/slog"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
)

// btcViewChain is a Bitcoin chain cell that only produces a view, with nothing in flight and nothing on chain.
type btcViewChain struct {
	chain.Adapter
	views int
}

func (f *btcViewChain) Chain() string { return "btc-reg" }
func (f *btcViewChain) ChainView(context.Context, []string) (chain.ChainView, error) {
	f.views++
	return chain.ChainView{Height: 100, Balance: map[string]*big.Int{}, SpentInFlight: map[string]*big.Int{}}, nil
}

// movingReader's safe head moves on every few calls: a block arrives during a read.
type movingReader struct {
	fakeReader
	calls    atomic.Int64
	moveFor  int64 // the first moveFor calls each return a new height; after that it holds still
	constant bool
}

func (r *movingReader) SafeHead(context.Context) (uint64, error) {
	n := r.calls.Add(1)
	if r.constant || n > r.moveFor {
		return 1000, nil
	}
	return uint64(n), nil
}

func newBTCSvc(t *testing.T, rd Reader) (*Service, *btcViewChain) {
	t.Helper()
	cfg, err := btcFile("regtest", xpubFor(t, &chaincfg.RegressionNetParams)).Build()
	if err != nil {
		t.Fatal(err)
	}
	fc := &btcViewChain{}
	s := New(dbtest.New(t), cfg, fc, rd)
	if err := s.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(context.Background(), `INSERT INTO chain_cursors (chain, next_height) VALUES ($1, 5000)`, cfg.Chain); err != nil {
		t.Fatal(err)
	}
	return s, fc
}

// A block arriving during the read makes Reconcile read again; once the tip holds still the comparison is made and the report is clean.
func TestReconcileBTCReadsAgainWhenABlockArrivesDuringTheRead(t *testing.T) {
	rd := &movingReader{moveFor: 3} // calls 1..3 move: the first read straddles a block, the second is stable
	s, fc := newBTCSvc(t, rd)
	rep, err := s.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if fc.views < 2 {
		t.Fatalf("%d reads: a block arrived during the first and it must be read again", fc.views)
	}
	if rep.SkippedChainChecks != 0 || !rep.Clean {
		t.Fatalf("skipped %d clean %v: %+v", rep.SkippedChainChecks, rep.Clean, rep.Failures())
	}
}

// If a block keeps arriving, the comparison is skipped after 3 reads, the report says so and is not clean; skipped for longer than max_skip, it raises an ALERT.
func TestReconcileBTCSkipsAreVisibleAndRepeatedSkipsAlert(t *testing.T) {
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	defer slog.SetDefault(old)
	rd := &movingReader{moveFor: 1 << 40}
	s, fc := newBTCSvc(t, rd)
	s.Cfg.ReconcileMaxSkip = time.Hour
	now := time.Now()
	s.Now = func() time.Time { return now }
	rep, err := s.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if fc.views != 3 || rep.SkippedChainChecks != 1 || rep.Clean {
		t.Fatalf("reads %d skipped %d clean %v", fc.views, rep.SkippedChainChecks, rep.Clean)
	}
	if bytes.Contains(buf.Bytes(), []byte("skipped for too long")) {
		t.Fatal("an ALERT after the first skip")
	}
	now = now.Add(2 * time.Hour)
	if _, err := s.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("skipped for too long")) {
		t.Fatalf("no ALERT after skipping for two hours: %s", buf.String())
	}
}
