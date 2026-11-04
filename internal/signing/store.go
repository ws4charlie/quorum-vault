package signing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/domain"
)

// This file holds every write to sign_requests (the Service owns that table).

const reqCols = `id::text, wallet_id::text, key_id::text, chain_id, to_address, value_wei::text, data, nonce, gas_limit,
	max_fee_per_gas::text, max_priority_fee_per_gas::text, requester, status, decision, signature, raw_tx,
	coalesce(tx_hash, ''), created_at, updated_at`

func scanRequest(row pgx.Row) (domain.SignRequest, error) {
	var r domain.SignRequest
	var value, feeCap, tip string
	var nonce, gas int64
	var decision []byte
	err := row.Scan(&r.ID, &r.WalletID, &r.KeyID, &r.ChainID, &r.To, &value, &r.Data, &nonce, &gas,
		&feeCap, &tip, &r.Requester, &r.Status, &decision, &r.Signature, &r.RawTx,
		&r.TxHash, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return r, err
	}
	r.Nonce, r.GasLimit = uint64(nonce), uint64(gas)
	var ok1, ok2, ok3 bool
	r.ValueWei, ok1 = new(big.Int).SetString(value, 10)
	r.MaxFeePerGas, ok2 = new(big.Int).SetString(feeCap, 10)
	r.MaxPriorityFeePerGas, ok3 = new(big.Int).SetString(tip, 10)
	if !ok1 || !ok2 || !ok3 {
		return r, fmt.Errorf("signing: bad numeric in request %s", r.ID)
	}
	if len(decision) > 0 {
		r.Decision = new(domain.Decision)
		if err := json.Unmarshal(decision, r.Decision); err != nil {
			return r, fmt.Errorf("signing: decode decision: %w", err)
		}
	}
	r.CreatedAt, r.UpdatedAt = r.CreatedAt.UTC(), r.UpdatedAt.UTC()
	return r, nil
}

// Get returns one sign request.
func (s *Service) Get(ctx context.Context, id string) (domain.SignRequest, error) {
	if uuid.Validate(id) != nil {
		return domain.SignRequest{}, fmt.Errorf("%w: request %q", ErrNotFound, id)
	}
	r, err := scanRequest(s.pool.QueryRow(ctx, `SELECT `+reqCols+` FROM sign_requests WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return r, fmt.Errorf("%w: request %s", ErrNotFound, id)
	}
	return r, err
}

// List returns sign requests, newest first, optionally for one wallet.
func (s *Service) List(ctx context.Context, walletID string, limit int) ([]domain.SignRequest, error) {
	if walletID != "" && uuid.Validate(walletID) != nil {
		return []domain.SignRequest{}, nil
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `SELECT `+reqCols+` FROM sign_requests
		WHERE ($1 = '' OR wallet_id::text = $1) ORDER BY created_at DESC, id LIMIT $2`, walletID, limit)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (domain.SignRequest, error) { return scanRequest(row) })
	if out == nil {
		out = []domain.SignRequest{}
	}
	return out, err
}

// insert stores a new request bound to the wallet's active key, chosen in the
// same statement so a concurrent rotation cannot slip in between.
func (s *Service) insert(ctx context.Context, r *domain.SignRequest) error {
	decision, err := json.Marshal(r.Decision)
	if err != nil {
		return err
	}
	err = s.pool.QueryRow(ctx, `INSERT INTO sign_requests
		(id, wallet_id, key_id, chain_id, to_address, value_wei, data, nonce, gas_limit,
		 max_fee_per_gas, max_priority_fee_per_gas, requester, status, decision)
		SELECT $1, $2, k.id, $3, $4, $5::numeric, $6, $7, $8, $9::numeric, $10::numeric, $11, $12, $13
		FROM keys k WHERE k.wallet_id = $2 AND k.state = 'active'
		RETURNING key_id::text, created_at, updated_at`,
		r.ID, r.WalletID, r.ChainID, r.To, r.ValueWei.String(), r.Data, int64(r.Nonce), int64(r.GasLimit),
		r.MaxFeePerGas.String(), r.MaxPriorityFeePerGas.String(), r.Requester, r.Status, decision,
	).Scan(&r.KeyID, &r.CreatedAt, &r.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%w: wallet %s has no active key", ErrInvalid, r.WalletID)
	}
	if err != nil {
		return fmt.Errorf("signing: insert request: %w", err)
	}
	r.CreatedAt, r.UpdatedAt = r.CreatedAt.UTC(), r.UpdatedAt.UTC()
	return nil
}

// transition moves a request to status `to` only if it is currently in one of
// `from`. This compare-and-set is what prevents double signing: of two callers
// racing to move approved -> signing, exactly one gets a row back.
// ok=false (and no error) means the request was not in an allowed state.
func (s *Service) transition(ctx context.Context, id string, to domain.RequestStatus, from ...domain.RequestStatus) (domain.SignRequest, bool, error) {
	fs := make([]string, len(from))
	for i, f := range from {
		fs[i] = string(f)
	}
	r, err := scanRequest(s.pool.QueryRow(ctx, `UPDATE sign_requests SET status = $2, updated_at = now()
		WHERE id = $1 AND status = ANY($3) RETURNING `+reqCols, id, to, fs))
	if errors.Is(err, pgx.ErrNoRows) {
		return r, false, nil
	}
	if err != nil {
		return r, false, fmt.Errorf("signing: set status %s: %w", to, err)
	}
	return r, true, nil
}

// storeSigned writes the signature, raw tx and the nonce actually signed
// (see Service.freshNonce) and moves signing -> signed.
func (s *Service) storeSigned(ctx context.Context, id string, nonce uint64, sig65, raw []byte, txHash string) (domain.SignRequest, error) {
	r, err := scanRequest(s.pool.QueryRow(ctx, `UPDATE sign_requests
		SET status = 'signed', nonce = $5, signature = $2, raw_tx = $3, tx_hash = $4, updated_at = now()
		WHERE id = $1 AND status = 'signing' RETURNING `+reqCols, id, sig65, raw, txHash, int64(nonce)))
	if errors.Is(err, pgx.ErrNoRows) {
		return r, fmt.Errorf("%w: request %s left status signing while being signed", ErrConflict, id)
	}
	if err != nil {
		return r, fmt.Errorf("signing: store signature: %w", err)
	}
	return r, nil
}
