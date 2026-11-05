package custody

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/ledger"
	"github.com/ws4charlie/quorum-vault/internal/outbox"
	"github.com/ws4charlie/quorum-vault/internal/partition"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// Withdrawal statuses (withdrawals.status).
const (
	WdRequested = "requested" // row, hold and outbox event exist; the workflow may not have started
	WdApproved  = "approved"  // enough approvals
	WdSigning   = "signing"   // sign job enqueued
	WdBroadcast = "broadcast"
	WdConfirmed = "confirmed"
	WdFailed    = "failed" // hold voided
)

// AutoApprover is the actor name of the worker's automated key.
const AutoApprover = "auto"

// Withdrawal is a row of withdrawals.
type Withdrawal struct {
	ID            string             `json:"id"`
	Customer      string             `json:"customer"`
	Chain         string             `json:"chain"`
	Asset         string             `json:"asset"`
	To            string             `json:"to"`
	Amount        *big.Int           `json:"-"`
	PartitionID   string             `json:"partition"`
	Status        string             `json:"status"`
	TxHash        string             `json:"tx_hash,omitempty"`
	RequestedBy   string             `json:"requested_by"`
	NotAfter      int64              `json:"not_after"`
	Approvals     []signjob.Approval `json:"-"`
	HotReserved   bool               `json:"-"`
	FailureReason string             `json:"failure_reason,omitempty"`
	JobID         string             `json:"job_id,omitempty"`
	Fee           string             `json:"fee,omitempty"`
}

// Owner returns the withdrawal as a transaction owner.
func (w Withdrawal) Owner() Owner {
	return Owner{Kind: "withdrawal", ID: w.ID, PartitionID: w.PartitionID}
}

const wdCols = `id, customer_id, chain, asset, to_address, amount::text, partition_id, status, COALESCE(tx_hash,''), requested_by,
	COALESCE(not_after,0), approvals, hot_reserved, COALESCE(failure_reason,''), COALESCE(job_id,''), COALESCE(fee::text,'')`

func scanWd(row pgx.Row) (Withdrawal, error) {
	var w Withdrawal
	var amt string
	var ap []byte
	err := row.Scan(&w.ID, &w.Customer, &w.Chain, &w.Asset, &w.To, &amt, &w.PartitionID, &w.Status, &w.TxHash, &w.RequestedBy,
		&w.NotAfter, &ap, &w.HotReserved, &w.FailureReason, &w.JobID, &w.Fee)
	if err != nil {
		return w, err
	}
	w.Amount = parseBig(amt)
	if err := json.Unmarshal(ap, &w.Approvals); err != nil {
		return w, err
	}
	return w, nil
}

// MarshalJSON adds the amount as a decimal string.
func (w Withdrawal) MarshalJSON() ([]byte, error) {
	type plain Withdrawal
	actors := make([]string, 0, len(w.Approvals))
	for _, a := range w.Approvals {
		actors = append(actors, a.Actor)
	}
	return json.Marshal(struct {
		plain
		Amount    string   `json:"amount"`
		Approvers []string `json:"approvers"`
	}{plain(w), w.Amount.String(), actors})
}

// GetWithdrawal reads one withdrawal.
func (s *Service) GetWithdrawal(ctx context.Context, id string) (Withdrawal, error) {
	w, err := scanWd(s.Pool.QueryRow(ctx, `SELECT `+wdCols+` FROM withdrawals WHERE id=$1`, id))
	if isNoRows(err) {
		return w, fmt.Errorf("%w: withdrawal %s", ErrNotFound, id)
	}
	return w, err
}

// OpenWithdrawals lists withdrawals that are not finished.
func (s *Service) OpenWithdrawals(ctx context.Context) ([]Withdrawal, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+wdCols+` FROM withdrawals WHERE chain=$1 AND status NOT IN ('confirmed','failed') AND COALESCE(failure_reason,'') NOT LIKE 'parked:%' ORDER BY created_at`, s.Cfg.Chain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Withdrawal
	for rows.Next() {
		w, err := scanWd(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// IntentOf is the exact statement approvers sign for a withdrawal. It depends
// only on the row, so the API, the worker and the gateway all compute the same hash.
func (s *Service) IntentOf(w Withdrawal) signjob.Intent {
	return signjob.Intent{Kind: "withdrawal", ID: w.ID, PartitionID: w.PartitionID, Chain: w.Chain, Asset: w.Asset,
		To: w.To, Amount: w.Amount.String(), NotAfter: w.NotAfter}
}

// NormalizeAddress validates an EVM destination: 0x-prefixed, 20 bytes, a valid
// EIP-55 checksum if mixed case, not the zero address. It returns the checksummed form.
func NormalizeAddress(s string) (string, error) {
	if !strings.HasPrefix(s, "0x") || !common.IsHexAddress(s) {
		return "", fmt.Errorf("%w: %q is not a 0x-prefixed address", ErrInvalid, s)
	}
	a := common.HexToAddress(s)
	if h := s[2:]; h != strings.ToLower(h) && h != strings.ToUpper(h) && a.Hex() != s {
		return "", fmt.Errorf("%w: %q has a bad checksum", ErrInvalid, s)
	}
	if a == (common.Address{}) {
		return "", fmt.Errorf("%w: zero address", ErrInvalid)
	}
	return a.Hex(), nil
}

// WithdrawalRequest is what the API passes to RequestWithdrawal.
type WithdrawalRequest struct {
	Actor          string
	IdempotencyKey string
	Customer       string
	Asset          string
	To             string
	Amount         *big.Int
}

func (r WithdrawalRequest) hash(to string) string {
	h := sha256.Sum256([]byte(strings.Join([]string{r.Customer, r.Asset, to, r.Amount.String()}, "\x00")))
	return hex.EncodeToString(h[:])
}

// WithdrawalID derives the ID from the initiator and the idempotency key, so
// the same request always lands on the same row and the same workflow.
func WithdrawalID(actor, key string) string {
	h := sha256.Sum256([]byte(actor + "\x00" + key))
	return "wd-" + hex.EncodeToString(h[:12])
}

// RequestWithdrawal, in one transaction, inserts the row, places the hold and
// writes the outbox event. A repeat with the same key and body returns the
// first result (created=false); the same key with another body is
// ErrIdempotencyConflict. Not enough available funds is ledger.ErrInsufficientFunds
// and nothing is written.
func (s *Service) RequestWithdrawal(ctx context.Context, r WithdrawalRequest) (Withdrawal, bool, error) {
	c := s.Cfg
	if r.Actor == "" || r.IdempotencyKey == "" {
		return Withdrawal{}, false, fmt.Errorf("%w: actor and idempotency key are required", ErrInvalid)
	}
	if !ValidID(r.Customer) {
		return Withdrawal{}, false, fmt.Errorf("%w: bad customer id", ErrInvalid)
	}
	if _, ok := c.Assets[r.Asset]; !ok {
		return Withdrawal{}, false, fmt.Errorf("%w: unknown asset %q", ErrInvalid, r.Asset)
	}
	if r.Amount == nil || r.Amount.Sign() <= 0 {
		return Withdrawal{}, false, fmt.Errorf("%w: amount must be positive", ErrInvalid)
	}
	to, err := NormalizeAddress(r.To)
	if err != nil {
		return Withdrawal{}, false, err
	}
	id := WithdrawalID(r.Actor, r.IdempotencyKey)
	hash := r.hash(to)
	var out Withdrawal
	created := false
	err = InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		created = false
		// Serialize duplicates of one request: the second waits, then sees the first's row.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, id); err != nil {
			return err
		}
		var have string
		err := tx.QueryRow(ctx, `SELECT request_hash FROM withdrawals WHERE id=$1`, id).Scan(&have)
		if err == nil {
			if have != hash {
				return ErrIdempotencyConflict
			}
			out, err = scanWd(tx.QueryRow(ctx, `SELECT `+wdCols+` FROM withdrawals WHERE id=$1`, id))
			return err
		}
		if !isNoRows(err) {
			return err
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM customers WHERE id=$1)`, r.Customer).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("%w: customer %q", ErrNotFound, r.Customer)
		}
		part, err := s.pickShard(ctx, tx, r.Asset, r.Amount)
		if err != nil {
			return err
		}
		notAfter := s.Now().Add(c.ApprovalWindow).Unix()
		if _, err := tx.Exec(ctx, `INSERT INTO withdrawals (id, customer_id, chain, asset, to_address, amount, partition_id, status,
			requested_by, idempotency_key, request_hash, not_after) VALUES ($1,$2,$3,$4,$5,$6::numeric,$7,'requested',$8,$9,$10,$11)`,
			id, r.Customer, c.Chain, r.Asset, to, r.Amount.String(), part, r.Actor, r.IdempotencyKey, hash, notAfter); err != nil {
			return fmt.Errorf("custody: insert withdrawal: %w", err)
		}
		if err := s.ensureCustomerAccount(ctx, tx, r.Customer, r.Asset); err != nil {
			return err
		}
		if err := s.Led.Hold(ctx, tx, ledger.HoldReq{ID: "wd-hold:" + id, Account: custAcct(r.Customer, c.Chain, r.Asset),
			CounterAccount: wdAcct(c.Chain, r.Asset), Amount: r.Amount, Metadata: map[string]any{"withdrawal": id}}); err != nil {
			return err
		}
		if err := emit(ctx, tx, outbox.TopicWithdrawals, id, "withdrawal.requested", map[string]any{
			"customer": r.Customer, "chain": c.Chain, "asset": r.Asset, "to": to, "amount": r.Amount.String(), "actor": r.Actor}); err != nil {
			return err
		}
		created = true
		out, err = scanWd(tx.QueryRow(ctx, `SELECT `+wdCols+` FROM withdrawals WHERE id=$1`, id))
		return err
	})
	return out, created, err
}

// freeHot is what the ledger says shard partition can still pay out: the hot
// balance (minus the posted ledger balance, which mirrors the chain) less
// liquidity already reserved for withdrawals in flight.
func (s *Service) freeHot(ctx context.Context, q interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}, partitionID string) (*big.Int, error) {
	var posted, reserved string
	if err := q.QueryRow(ctx, `SELECT posted::text FROM ledger_accounts WHERE id=$1`, hotAcct(partitionID)).Scan(&posted); err != nil {
		return nil, err
	}
	if err := q.QueryRow(ctx, `SELECT COALESCE(SUM(amount),0)::text FROM withdrawals WHERE partition_id=$1 AND hot_reserved AND status NOT IN ('confirmed','failed')`,
		partitionID).Scan(&reserved); err != nil {
		return nil, err
	}
	// A cold move that is planned or signing has not been booked yet (that happens at broadcast), so its amount is
	// set aside here; after the broadcast the hot balance already shows it.
	var moving string
	if err := q.QueryRow(ctx, `SELECT COALESCE(SUM(amount),0)::text FROM cold_moves WHERE partition_id=$1 AND status IN ('planned','signing')`,
		partitionID).Scan(&moving); err != nil {
		return nil, err
	}
	// The same for a rebalance leaving this shard.
	var leaving string
	if err := q.QueryRow(ctx, `SELECT COALESCE(SUM(amount),0)::text FROM rebalance_moves WHERE partition_id=$1 AND status IN ('planned','signing')`,
		partitionID).Scan(&leaving); err != nil {
		return nil, err
	}
	free := new(big.Int).Neg(parseBig(posted))
	free.Sub(free, parseBig(reserved))
	free.Sub(free, parseBig(leaving))
	return free.Sub(free, parseBig(moving)), nil
}

// pickShard returns the partition of the shard with the most free hot
// liquidity of asset. The partition is part of the intent approvers sign, so it
// is chosen at request time; if no shard covers the amount yet the workflow waits.
func (s *Service) pickShard(ctx context.Context, tx pgx.Tx, asset string, amount *big.Int) (string, error) {
	best, bestFree := "", (*big.Int)(nil)
	for i := range s.Cfg.HotShards {
		p := s.Cfg.PartitionKey(asset, i).String()
		free, err := s.freeHot(ctx, tx, p)
		if err != nil {
			return "", err
		}
		if bestFree == nil || free.Cmp(bestFree) > 0 {
			best, bestFree = p, free
		}
	}
	return best, nil
}

// AddApproval records an Ed25519 approval over the withdrawal's intent hash.
// The business zone cannot check the signature (approver public keys live only
// in the signing zone); the gateway does, and refuses the job if too few are
// valid. The initiator cannot approve; one approval per actor, the first wins.
// It returns the number of distinct approvers so far.
func (s *Service) AddApproval(ctx context.Context, id, actor string, sig []byte) (int, error) {
	if !ValidID(actor) || len(sig) != ed25519.SignatureSize {
		return 0, fmt.Errorf("%w: need an actor and a %d-byte signature", ErrInvalid, ed25519.SignatureSize)
	}
	n := 0
	err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		w, err := scanWd(tx.QueryRow(ctx, `SELECT `+wdCols+` FROM withdrawals WHERE id=$1 FOR UPDATE`, id))
		if isNoRows(err) {
			return fmt.Errorf("%w: withdrawal %s", ErrNotFound, id)
		}
		if err != nil {
			return err
		}
		if actor == w.RequestedBy {
			return ErrSelfApproval
		}
		if w.Status != WdRequested && w.Status != WdApproved {
			return ErrNotPending
		}
		for _, a := range w.Approvals {
			if a.Actor == actor {
				n = len(w.Approvals)
				return nil // a repeat (or a repeated signal): nothing changes
			}
		}
		w.Approvals = append(w.Approvals, signjob.Approval{Actor: actor, Signature: sig})
		b, err := json.Marshal(w.Approvals)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE withdrawals SET approvals=$2::jsonb, updated_at=now() WHERE id=$1`, id, string(b)); err != nil {
			return err
		}
		n = len(w.Approvals)
		return emit(ctx, tx, outbox.TopicAudit, "withdrawal:"+id, "withdrawal.approval", map[string]any{"actor": actor, "withdrawal": id})
	})
	return n, err
}

// ApprovalState says how many approvals the withdrawal has and needs.
type ApprovalState struct {
	Have     int
	Required int
	Auto     bool // the worker's automated key may supply them
	Status   string
	Expired  bool
}

// Approvals reports the withdrawal's approval state.
func (s *Service) Approvals(ctx context.Context, id string) (ApprovalState, error) {
	w, err := s.GetWithdrawal(ctx, id)
	if err != nil {
		return ApprovalState{}, err
	}
	need, auto := s.Cfg.Required(w.Asset, w.Amount)
	return ApprovalState{Have: len(w.Approvals), Required: need, Auto: auto, Status: w.Status, Expired: s.Now().Unix() >= w.NotAfter}, nil
}

// AutoApprove signs the withdrawal's intent hash with the worker's automated
// key if its amount is in the lowest tier. It is idempotent.
func (s *Service) AutoApprove(ctx context.Context, key ed25519.PrivateKey, id string) error {
	w, err := s.GetWithdrawal(ctx, id)
	if err != nil {
		return err
	}
	if _, auto := s.Cfg.Required(w.Asset, w.Amount); !auto || key == nil {
		return nil
	}
	h := s.IntentOf(w).Hash()
	_, err = s.addSystemApproval(ctx, id, AutoApprover, ed25519.Sign(key, h[:]))
	return err
}

func (s *Service) addSystemApproval(ctx context.Context, id, actor string, sig []byte) (int, error) {
	n := 0
	err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		w, err := scanWd(tx.QueryRow(ctx, `SELECT `+wdCols+` FROM withdrawals WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		for _, a := range w.Approvals {
			if a.Actor == actor {
				n = len(w.Approvals)
				return nil
			}
		}
		w.Approvals = append(w.Approvals, signjob.Approval{Actor: actor, Signature: sig})
		b, _ := json.Marshal(w.Approvals)
		n = len(w.Approvals)
		_, err = tx.Exec(ctx, `UPDATE withdrawals SET approvals=$2::jsonb, updated_at=now() WHERE id=$1`, id, string(b))
		return err
	})
	return n, err
}

// MarkApproved moves a requested withdrawal to approved.
func (s *Service) MarkApproved(ctx context.Context, id string) error {
	return InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE withdrawals SET status='approved', updated_at=now() WHERE id=$1 AND status='requested'`, id)
		if err != nil || tag.RowsAffected() == 0 {
			return err
		}
		return emit(ctx, tx, outbox.TopicWithdrawals, id, "withdrawal.approved", nil)
	})
}

// ReserveHot sets liquidity aside on the withdrawal's partition if the hot
// balance covers it. Returns false when it does not (the workflow waits).
func (s *Service) ReserveHot(ctx context.Context, id string) (bool, error) {
	ok := false
	err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		w, err := scanWd(tx.QueryRow(ctx, `SELECT `+wdCols+` FROM withdrawals WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		if w.HotReserved {
			ok = true
			return nil
		}
		// Serialize reservations per partition.
		if _, err := tx.Exec(ctx, `SELECT 1 FROM partitions WHERE id=$1 FOR UPDATE`, w.PartitionID); err != nil {
			return err
		}
		free, err := s.freeHot(ctx, tx, w.PartitionID)
		if err != nil {
			return err
		}
		if free.Cmp(w.Amount) < 0 {
			ok = false
			return nil
		}
		ok = true
		_, err = tx.Exec(ctx, `UPDATE withdrawals SET hot_reserved=true, updated_at=now() WHERE id=$1`, id)
		return err
	})
	return ok, err
}

// BuildWithdrawalJob builds the transaction (allocating the nonce) and enqueues
// the sign job with the intent and approvals, in one transaction. It repeats
// harmlessly: an existing job is returned as it is.
func (s *Service) BuildWithdrawalJob(ctx context.Context, id string) (string, error) {
	jobID := OwnerTrack(Owner{Kind: "withdrawal", ID: id}).FirstJob()
	err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		w, err := scanWd(tx.QueryRow(ctx, `SELECT `+wdCols+` FROM withdrawals WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		if w.JobID != "" {
			return nil
		}
		if s.Now().Unix() >= w.NotAfter {
			return ErrExpired
		}
		u, err := s.Chain.BuildWithdrawal(ctx, tx, chain.WithdrawalIntent{ID: id, PartitionID: w.PartitionID, Asset: w.Asset, To: w.To, Amount: w.Amount})
		if err != nil {
			return err
		}
		ib, err := json.Marshal(s.IntentOf(w))
		if err != nil {
			return err
		}
		if err := signjob.Enqueue(ctx, tx, signjob.Job{ID: jobID, PartitionID: w.PartitionID, KeyRef: u.KeyRef.Path, Chain: u.Chain,
			Intent: ib, Digest: u.Digest, Payload: u.Payload, Approvals: w.Approvals}); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE withdrawals SET status='signing', job_id=$2, updated_at=now() WHERE id=$1`, id, jobID); err != nil {
			return err
		}
		return emit(ctx, tx, outbox.TopicWithdrawals, id, "withdrawal.signing", map[string]any{"job": jobID})
	})
	return jobID, err
}

// RecordWithdrawalBroadcast stores the transaction hash and marks the withdrawal broadcast.
func (s *Service) RecordWithdrawalBroadcast(ctx context.Context, id, txHash string) error {
	return InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE withdrawals SET status='broadcast', tx_hash=$2, updated_at=now() WHERE id=$1 AND status IN ('signing','approved')`, id, txHash)
		if err != nil || tag.RowsAffected() == 0 {
			return err
		}
		return emit(ctx, tx, outbox.TopicWithdrawals, id, "withdrawal.broadcast", map[string]any{"tx": txHash})
	})
}

// SettleWithdrawal books a withdrawal whose own transaction mined and
// succeeded: post the hold (customer -> wd), then wd -> hot, and the network
// fee (fee -> hot). All in one transaction; ledger IDs derive from the
// withdrawal ID and the hash, so a repeat changes nothing.
func (s *Service) SettleWithdrawal(ctx context.Context, id, txHash string) error {
	fee, err := s.Chain.TxFee(ctx, txHash)
	if err != nil {
		return err
	}
	c := s.Cfg
	return InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		w, err := scanWd(tx.QueryRow(ctx, `SELECT `+wdCols+` FROM withdrawals WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		if w.Status == WdConfirmed {
			return nil
		}
		if w.Status == WdFailed {
			return fmt.Errorf("custody: withdrawal %s was voided; its transaction %s mined anyway", id, txHash)
		}
		if err := s.Led.Post(ctx, tx, "wd-hold:"+id, "wd-post:"+id); err != nil {
			return err
		}
		if err := s.transfer(ctx, tx, "wd-out:"+id, wdAcct(c.Chain, w.Asset), hotAcct(w.PartitionID), w.Amount,
			map[string]any{"withdrawal": id, "tx": txHash}); err != nil {
			return err
		}
		if err := s.recordFee(ctx, tx, txHash, w.PartitionID, fee); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE withdrawals SET status='confirmed', tx_hash=$2, fee=$3::numeric, updated_at=now() WHERE id=$1`, id, txHash, fee.String()); err != nil {
			return err
		}
		return emit(ctx, tx, outbox.TopicWithdrawals, id, "withdrawal.confirmed", map[string]any{
			"customer": w.Customer, "chain": c.Chain, "asset": w.Asset, "to": w.To, "amount": w.Amount.String(), "tx": txHash, "fee": fee.String()})
	})
}

// VoidWithdrawal releases the hold and ends the withdrawal as failed. It
// refuses (ErrNonceOpen) while the withdrawal's nonce is still live: a
// signature at that nonce might yet be broadcast, so releasing the money would
// risk paying twice. feeTx, if set, is a transaction of ours that mined at the
// nonce (a reverted withdrawal or a cancel) whose fee is recorded.
func (s *Service) VoidWithdrawal(ctx context.Context, id, reason, feeTx string) error {
	var fee *big.Int
	if feeTx != "" {
		var err error
		if fee, err = s.Chain.TxFee(ctx, feeTx); err != nil {
			return err
		}
	}
	return InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		w, err := scanWd(tx.QueryRow(ctx, `SELECT `+wdCols+` FROM withdrawals WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		if w.Status == WdFailed {
			return nil
		}
		if w.Status == WdConfirmed {
			return fmt.Errorf("custody: withdrawal %s is already confirmed", id)
		}
		open, err := s.NonceOpen(ctx, tx, w.Owner())
		if err != nil {
			return err
		}
		if open {
			return ErrNonceOpen
		}
		if err := s.Led.Void(ctx, tx, "wd-hold:"+id, "wd-void:"+id); err != nil {
			return err
		}
		if fee != nil {
			if err := s.recordFee(ctx, tx, feeTx, w.PartitionID, fee); err != nil {
				return err
			}
		}
		fs := ""
		if fee != nil {
			fs = fee.String()
		}
		if _, err := tx.Exec(ctx, `UPDATE withdrawals SET status='failed', failure_reason=$2, fee=NULLIF($3,'')::numeric, hot_reserved=false, updated_at=now() WHERE id=$1`, id, reason, fs); err != nil {
			return err
		}
		return emit(ctx, tx, outbox.TopicWithdrawals, id, "withdrawal.failed", map[string]any{"customer": w.Customer, "reason": reason, "fee": fs})
	})
}

var _ = errors.New
var _ = time.Second
var _ partition.Key

// ParkedPrefix marks a row that needs an operator: its workflow stopped on
// purpose, the money stays where it is, and the reconcilers leave it alone.
// An operator resumes it by clearing failure_reason.
const ParkedPrefix = "parked:"

// Parked reports whether the withdrawal is parked.
func (w Withdrawal) Parked() bool { return strings.HasPrefix(w.FailureReason, ParkedPrefix) }

// ParkWithdrawal records that the withdrawal needs a person. The hold is kept.
func (s *Service) ParkWithdrawal(ctx context.Context, id, reason string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE withdrawals SET failure_reason=$2, updated_at=now() WHERE id=$1 AND status NOT IN ('confirmed','failed')`, id, ParkedPrefix+" "+reason)
	return err
}

// RecordRejection records that actor rejected the withdrawal, and why. The rejection itself reaches the workflow as a signal;
// this is the audit trail of who said no. It does not change the withdrawal.
func (s *Service) RecordRejection(ctx context.Context, id, actor, reason string) error {
	return InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		return auditEvent(ctx, tx, id, "withdrawal.rejected", map[string]any{"actor": actor, "withdrawal": id, "reason": reason})
	})
}
