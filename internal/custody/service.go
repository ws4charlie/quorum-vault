package custody

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"math/rand/v2"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/ledger"
	"github.com/ws4charlie/quorum-vault/internal/outbox"
)

// Reader reads the chain for balance reconciliation and settlement. It is
// separate from chain.Adapter because the adapter has no balance queries.
type Reader interface {
	// SafeHead is the highest height that is final.
	SafeHead(ctx context.Context) (uint64, error)
	// TxBlock is the height at which a mined transaction sits.
	TxBlock(ctx context.Context, txHash string) (uint64, error)
	// Balance of address in asset as of height.
	Balance(ctx context.Context, address, asset string, height uint64) (*big.Int, error)
}

// Service is the business core. All money moves through Led, inside the same
// database transaction as the row that explains it and its outbox event.
type Service struct {
	Pool   *pgxpool.Pool
	Led    ledger.Ledger
	Chain  chain.Adapter
	Reader Reader
	Cfg    *Config
	Now    func() time.Time

	mismatchAlerted atomic.Bool // the "destination changed on chain" ALERT was given and the mismatch has not cleared since
}

// New returns a Service. Led defaults to the Postgres ledger.
func New(pool *pgxpool.Pool, cfg *Config, adapter chain.Adapter, reader Reader) *Service {
	return &Service{Pool: pool, Led: ledger.New(), Chain: adapter, Reader: reader, Cfg: cfg, Now: time.Now}
}

// Errors returned by the service.
var (
	ErrNotFound            = errors.New("custody: not found")
	ErrInvalid             = errors.New("custody: invalid request")
	ErrIdempotencyConflict = errors.New("custody: idempotency key reused with a different request")
	ErrSelfApproval        = errors.New("custody: the initiator cannot approve")
	ErrNotPending          = errors.New("custody: withdrawal is no longer awaiting approval")
	ErrNonceOpen           = errors.New("custody: the withdrawal's nonce is still live; resolve it before voiding")
	ErrExpired             = errors.New("custody: the approval window has passed")
	ErrSweepFrozen         = errors.New("custody: sweeping is frozen")
	ErrCursorMoved         = errors.New("custody: scan cursor moved")
)

// InTx runs fn in a transaction, retrying on Postgres deadlock (40P01) and
// serialization failure (40001): callers that do several ledger operations in
// one transaction lock accounts in operation order and can deadlock.
func InTx(ctx context.Context, pool *pgxpool.Pool, fn func(tx pgx.Tx) error) error {
	var err error
	for attempt := 0; attempt < 10; attempt++ {
		if attempt > 0 {
			d := time.Duration(5+rand.IntN(20)*(attempt+1)) * time.Millisecond
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(d):
			}
		}
		if err = runTx(ctx, pool, fn); err == nil || !retryable(err) {
			return err
		}
	}
	return err
}

func runTx(ctx context.Context, pool *pgxpool.Pool, fn func(tx pgx.Tx) error) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func retryable(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && (pe.Code == "40P01" || pe.Code == "40001")
}

// emit writes one outbox event for a flow, in the flow's transaction.
func emit(ctx context.Context, tx pgx.Tx, topic, key, typ string, fields map[string]any) error {
	p := map[string]any{"type": typ, "id": key}
	for k, v := range fields {
		p[k] = v
	}
	return outbox.Write(ctx, tx, topic, key, p)
}

func parseBig(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("custody: bad numeric from database: " + s)
	}
	return n
}

func sumOf(a, b *big.Int) *big.Int { return new(big.Int).Add(a, b) }

func (s *Service) transfer(ctx context.Context, tx pgx.Tx, id, from, to string, amt *big.Int, meta map[string]any) error {
	if amt.Sign() == 0 {
		return nil
	}
	return s.Led.Transfer(ctx, tx, ledger.TransferReq{ID: id, From: from, To: to, Amount: amt, Metadata: meta})
}

// recordFee books a network fee paid by a hot wallet: fee -> hot (native asset).
func (s *Service) recordFee(ctx context.Context, tx pgx.Tx, txHash string, shardPartition string, fee *big.Int) error {
	if fee == nil || fee.Sign() == 0 {
		return nil
	}
	nativePart, err := s.nativePartitionOf(shardPartition)
	if err != nil {
		return err
	}
	return s.transfer(ctx, tx, "fee:"+txHash, feeAcct(s.Cfg.Chain, s.Cfg.Native), hotAcct(nativePart), fee,
		map[string]any{"tx": txHash, "kind": "network_fee"})
}

// nativePartitionOf maps any partition of a shard to the same shard's native-asset partition.
func (s *Service) nativePartitionOf(partitionID string) (string, error) {
	_, shard, err := s.Cfg.ShardAddress(partitionID)
	if err != nil {
		return "", err
	}
	return s.Cfg.PartitionKey(s.Cfg.Native, shard).String(), nil
}

// FundHot records the operator putting amount of asset on a hot shard (gas
// money, or seed liquidity): hot -> fee. The fee account is the operator's
// own money in the native asset (funding minus fees paid), so it mirrors the
// hot wallet exactly as customer money mirrors deposits. id makes it idempotent.
func (s *Service) FundHot(ctx context.Context, id string, shard int, amount *big.Int) error {
	if shard < 0 || shard >= len(s.Cfg.HotShards) || amount.Sign() <= 0 {
		return fmt.Errorf("%w: fund hot", ErrInvalid)
	}
	part := s.Cfg.PartitionKey(s.Cfg.Native, shard).String()
	return InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		return s.transfer(ctx, tx, "fund:"+id, hotAcct(part), feeAcct(s.Cfg.Chain, s.Cfg.Native), amount, map[string]any{"kind": "hot_funding"})
	})
}
