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

	reconSkipSince  atomic.Int64 // Unix time the chain comparisons of Reconcile began to be skipped (0: they are not)
	mismatchAlerted atomic.Bool  // the "destination changed on chain" ALERT was given and the mismatch has not cleared since
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
	ErrReservationOpen     = errors.New("custody: the transaction still holds a live reservation on the chain (EVM: a nonce); resolve it before voiding")
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

type actorKey struct{}

// WithActor names who caused what happens under ctx; the audit events written under it carry that name. The /v2 API sets it
// from the X-Actor header. Work nobody asked for (the planners, the workflows) has no actor and is recorded as "system".
func WithActor(ctx context.Context, actor string) context.Context {
	return context.WithValue(ctx, actorKey{}, actor)
}

func actorOf(ctx context.Context) string {
	if a, _ := ctx.Value(actorKey{}).(string); a != "" {
		return a
	}
	return "system"
}

// audited lists the flow events that are also audit events, with the name they carry in the audit log. The others only fan
// out to consumers. Payloads hold amounts, addresses and hashes, never keys or signatures.
var audited = map[string]string{
	"withdrawal.requested":  "withdrawal.requested",
	"withdrawal.approved":   "withdrawal.approved",
	"withdrawal.failed":     "withdrawal.voided",
	"refill.requested":      "refill.requested",
	"refill.signed":         "refill.imported",
	"refill.closed":         "refill.closed",
	"cold_action.requested": "cold_action.requested",
	"cold_move.planned":     "cold_move.started",
	"rebalance.planned":     "rebalance.started",
}

// emit writes one outbox event for a flow, in the flow's transaction. An audited event is written a second time to the audit
// topic, in the same transaction, so the audit entry exists exactly when the change does.
func emit(ctx context.Context, tx pgx.Tx, topic, key, typ string, fields map[string]any) error {
	p := map[string]any{"type": typ, "id": key}
	for k, v := range fields {
		p[k] = v
	}
	if err := outbox.Write(ctx, tx, topic, key, p); err != nil {
		return err
	}
	if name, ok := audited[typ]; ok && topic != outbox.TopicAudit {
		return auditEvent(ctx, tx, key, name, fields)
	}
	return nil
}

// audit writes an audit event: who (the "actor" field, else "by", else the actor of ctx, else the system), what, and about
// which subject, with the other fields as details.
func auditEvent(ctx context.Context, tx pgx.Tx, subject, typ string, fields map[string]any) error {
	return outbox.Write(ctx, tx, outbox.TopicAudit, subject, auditPayload(ctx, typ, subject, fields))
}

// auditOnce is audit for a step that is idempotent by caller-supplied ID: repeating it writes nothing new.
func auditOnce(ctx context.Context, tx pgx.Tx, seed, subject, typ string, fields map[string]any) error {
	return outbox.WriteOnce(ctx, tx, seed+"\x00"+typ, outbox.TopicAudit, subject, auditPayload(ctx, typ, subject, fields))
}

func auditPayload(ctx context.Context, typ, subject string, fields map[string]any) map[string]any {
	p := map[string]any{"type": typ, "id": subject}
	for k, v := range fields {
		p[k] = v
	}
	if a, _ := p["actor"].(string); a == "" {
		if by, _ := p["by"].(string); by != "" {
			p["actor"] = by
		} else {
			p["actor"] = actorOf(ctx)
		}
	}
	return p
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
	shard, err := s.Cfg.ShardIndex(partitionID)
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
	if shard < 0 || shard >= s.Cfg.shardCount() || amount.Sign() <= 0 {
		return fmt.Errorf("%w: fund hot", ErrInvalid)
	}
	part := s.Cfg.PartitionKey(s.Cfg.Native, shard).String()
	return InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		return s.transfer(ctx, tx, "fund:"+id, hotAcct(part), feeAcct(s.Cfg.Chain, s.Cfg.Native), amount, map[string]any{"kind": "hot_funding"})
	})
}

// FundHotAsset records the operator putting amount of a token on a hot shard (seed liquidity): hot -> operator funding. id makes it idempotent.
// The native asset is FundHot's.
func (s *Service) FundHotAsset(ctx context.Context, id string, shard int, asset string, amount *big.Int) error {
	if asset == s.Cfg.Native {
		return s.FundHot(ctx, id, shard, amount)
	}
	if _, ok := s.Cfg.Assets[asset]; !ok || shard < 0 || shard >= s.Cfg.shardCount() || amount.Sign() <= 0 {
		return fmt.Errorf("%w: fund hot", ErrInvalid)
	}
	part := s.Cfg.PartitionKey(asset, shard).String()
	return InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		return s.transfer(ctx, tx, "fund:"+id, hotAcct(part), opFundAcct(s.Cfg.Chain, asset), amount, map[string]any{"kind": "hot_funding"})
	})
}

// cancelFee is the fee of the cancel transaction that freed a nonce ("" means none was sent or it is not ours to book).
func (s *Service) cancelFee(ctx context.Context, feeTx string) (*big.Int, error) {
	if feeTx == "" {
		return nil, nil
	}
	return s.Chain.TxFee(ctx, feeTx)
}

// NonceSetup is implemented by a chain cell whose hot shards sign withdrawals on a pool of durable-nonce accounts (Solana).
type NonceSetup interface {
	// BuildNonceSetup builds the creation of the shard's missing pool accounts and the total rent the intent names (count 0: nothing missing).
	BuildNonceSetup(ctx context.Context, partitionID string) (u chain.UnsignedTx, amount *big.Int, count int, err error)
	// SubmitNonceSetup sends the signed creation and waits until it is final.
	SubmitNonceSetup(ctx context.Context, s chain.SignedTx, wait time.Duration) (string, error)
}
