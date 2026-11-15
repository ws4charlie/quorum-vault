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
	"time"

	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/chain/sol"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// SetupNonces creates the missing nonce accounts of a hot shard's pool (Solana). It is an operator action, not part of a withdrawal: it builds the
// creation, has the signing zone sign it under the operator's approval of the intent, sends it, waits until it is final and books what it cost
// (the rent of the accounts is spent from the hot shard and not recoverable by the books, so it is booked as a cost like a fee). It returns the
// number of accounts created; zero means the pool was complete. Repeating it after a crash is safe: the job is the idempotency key, and an
// account that exists is not created twice.
func (s *Service) SetupNonces(ctx context.Context, shard int, approver string, key ed25519.PrivateKey, wait time.Duration) (int, error) {
	ns, ok := s.Chain.(NonceSetup)
	if !ok {
		return 0, fmt.Errorf("%w: this chain has no nonce pool", ErrInvalid)
	}
	if shard < 0 || shard >= s.Cfg.shardCount() {
		return 0, fmt.Errorf("%w: shard %d", ErrInvalid, shard)
	}
	part := s.Cfg.PartitionKey(s.Cfg.Native, shard).String()
	u, amount, n, err := ns.BuildNonceSetup(ctx, part)
	if err != nil || n == 0 {
		return 0, err
	}
	hotAddr := ""
	if h, ok := s.Chain.(interface {
		HotAddress(string) (string, error)
	}); ok {
		if hotAddr, err = h.HotAddress(part); err != nil {
			return 0, err
		}
	}
	sum := sha256.Sum256(u.Digest)
	id := "nonces-" + hex.EncodeToString(sum[:8])
	intent := signjob.Intent{Kind: "nonce-setup", ID: id, PartitionID: part, Chain: s.Cfg.Chain, Asset: s.Cfg.Native, To: hotAddr, Amount: amount.String()}
	h := intent.Hash()
	approvals := []signjob.Approval{{Actor: approver, Signature: ed25519.Sign(key, h[:])}}
	ib, err := json.Marshal(intent)
	if err != nil {
		return 0, err
	}
	jobID := "nonces:" + id
	if err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		if ok, err := s.JobExists(ctx, jobID); err != nil || ok {
			return err
		}
		return EnqueueUnsigned(ctx, tx, jobID, part, u, ib, approvals)
	}); err != nil {
		return 0, err
	}
	deadline := time.Now().Add(wait)
	for {
		st, reason, err := s.WaitJob(ctx, jobID, 2*time.Second, nil)
		if err != nil {
			return 0, err
		}
		switch st {
		case JobDone:
			return n, s.finishNonceSetup(ctx, ns, jobID, part, wait)
		case JobRejected:
			return 0, fmt.Errorf("custody: the signing zone refused the nonce setup: %s", reason)
		case JobFailed:
			return 0, fmt.Errorf("custody: the nonce setup could not be signed: %s", reason)
		}
		if time.Now().After(deadline) {
			return 0, errors.New("custody: the nonce setup was not signed in time")
		}
	}
}

func (s *Service) finishNonceSetup(ctx context.Context, ns NonceSetup, jobID, part string, wait time.Duration) error {
	j, err := signjob.Get(ctx, s.Pool, jobID)
	if err != nil {
		return err
	}
	st, err := s.Chain.Assemble(unsignedOf(j), []chain.Signature{{Bytes: j.Signature}})
	if err != nil {
		return err
	}
	hash, err := ns.SubmitNonceSetup(ctx, st, wait)
	if err != nil {
		return err
	}
	cost, err := s.Chain.TxFee(ctx, hash)
	if err != nil {
		return err
	}
	return InTx(ctx, s.Pool, func(tx pgx.Tx) error { return s.recordFee(ctx, tx, hash, part, cost) })
}

// RetireNonce takes pool account idx of a hot shard out of the pool (Solana). Nothing is allocated on it afterwards; the last account of a pool is
// never retired. Closing it, once it is idle, is CloseNonce.
func (s *Service) RetireNonce(ctx context.Context, shard, idx int) error {
	nc, ok := s.Chain.(NonceCloser)
	if !ok {
		return fmt.Errorf("%w: this chain has no nonce pool", ErrInvalid)
	}
	if shard < 0 || shard >= s.Cfg.shardCount() {
		return fmt.Errorf("%w: shard %d", ErrInvalid, shard)
	}
	part := s.Cfg.PartitionKey(s.Cfg.Native, shard).String()
	if err := nc.RetireNonce(ctx, part, idx); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		return auditOnce(ctx, tx, "nonce-retire:"+part+":"+fmt.Sprint(idx), part, "nonce.retired", map[string]any{"partition": part, "index": idx})
	})
}

// CloseNonce closes a retired, idle nonce account of a hot shard: the shard withdraws its whole balance back to itself, signed by the signing zone
// under the operator's approval of the intent. What the account cost comes back as a lower cost in the books (the fee account), as for a closed token
// account. It returns the lamports recovered, before the fee. Repeating it after a crash is safe: the signature of the close is recorded before it is
// sent, and the booking is keyed by it.
func (s *Service) CloseNonce(ctx context.Context, shard, idx int, approver string, key ed25519.PrivateKey, wait time.Duration) (*big.Int, error) {
	nc, ok := s.Chain.(NonceCloser)
	if !ok {
		return nil, fmt.Errorf("%w: this chain has no nonce pool", ErrInvalid)
	}
	if shard < 0 || shard >= s.Cfg.shardCount() {
		return nil, fmt.Errorf("%w: shard %d", ErrInvalid, shard)
	}
	part := s.Cfg.PartitionKey(s.Cfg.Native, shard).String()
	u, lamports, err := nc.BuildNonceClose(ctx, part, idx)
	if errors.Is(err, sol.ErrNonceGone) {
		// closed already; a crash may have kept the booking from happening
		if sig, serr := nc.NonceCloseTx(ctx, part, idx); serr == nil && sig != "" {
			return new(big.Int), s.finishNonceClose(ctx, nc, part, idx, sig)
		}
		return new(big.Int), nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	hotAddr, err := s.Chain.(interface{ HotAddress(string) (string, error) }).HotAddress(part)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(u.Digest)
	id := "nonceclose-" + hex.EncodeToString(sum[:8])
	intent := signjob.Intent{Kind: "nonce-close", ID: id, PartitionID: part, Chain: s.Cfg.Chain, Asset: s.Cfg.Native, To: hotAddr, Amount: lamports.String()}
	h := intent.Hash()
	approvals := []signjob.Approval{{Actor: approver, Signature: ed25519.Sign(key, h[:])}}
	ib, err := json.Marshal(intent)
	if err != nil {
		return nil, err
	}
	jobID := "nonces:" + id
	if err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		if ok, err := s.JobExists(ctx, jobID); err != nil || ok {
			return err
		}
		return EnqueueUnsigned(ctx, tx, jobID, part, u, ib, approvals)
	}); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(wait)
	for {
		st, reason, err := s.WaitJob(ctx, jobID, 2*time.Second, nil)
		if err != nil {
			return nil, err
		}
		switch st {
		case JobDone:
			j, err := signjob.Get(ctx, s.Pool, jobID)
			if err != nil {
				return nil, err
			}
			stx, err := s.Chain.Assemble(unsignedOf(j), []chain.Signature{{Bytes: j.Signature}})
			if err != nil {
				return nil, err
			}
			sig := base58.Encode(j.Signature)
			if err := nc.RecordNonceCloseTx(ctx, part, idx, sig); err != nil {
				return nil, err
			}
			if _, err := nc.SubmitNonceSetup(ctx, stx, wait); err != nil {
				// a close that landed and failed moved nothing and cost its fee: book that and forget the signature, so the next try starts clean
				if st, serr := s.Chain.Status(ctx, sig); serr == nil && st == chain.TxFailed {
					if fee, ferr := s.Chain.TxFee(ctx, sig); ferr == nil {
						_ = InTx(ctx, s.Pool, func(tx pgx.Tx) error {
							if err := s.recordFee(ctx, tx, sig, part, fee); err != nil {
								return err
							}
							_, err := tx.Exec(ctx, `UPDATE sol_nonce_accounts SET close_tx=NULL WHERE chain=$1 AND close_tx=$2`, s.Cfg.Chain, sig)
							return err
						})
					}
				}
				return nil, err
			}
			return lamports, s.finishNonceClose(ctx, nc, part, idx, sig)
		case JobRejected:
			return nil, fmt.Errorf("custody: the signing zone refused the nonce close: %s", reason)
		case JobFailed:
			return nil, fmt.Errorf("custody: the nonce close could not be signed: %s", reason)
		}
		if time.Now().After(deadline) {
			return nil, errors.New("custody: the nonce close was not signed in time")
		}
	}
}

// finishNonceClose books what the close cost (negative: the rent that came back, less the fee) and marks the account closed, in one transaction: between
// the close being final and this commit, Reconcile explains the difference from the recorded signature.
func (s *Service) finishNonceClose(ctx context.Context, nc NonceCloser, part string, idx int, sig string) error {
	cost, err := s.Chain.TxFee(ctx, sig)
	if err != nil {
		return err
	}
	hot, err := s.Chain.(interface{ HotAddress(string) (string, error) }).HotAddress(part)
	if err != nil {
		return err
	}
	return InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		if err := s.recordFee(ctx, tx, sig, part, cost); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE sol_nonce_accounts SET closed_at=COALESCE(closed_at, now()) WHERE chain=$1 AND hot_address=$2 AND close_tx=$3`, s.Cfg.Chain, hot, sig)
		return err
	})
}
