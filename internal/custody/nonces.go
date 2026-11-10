package custody

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
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
