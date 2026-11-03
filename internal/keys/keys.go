// Package keys is the key registry: wallets, their key versions in Postgres,
// and the lifecycle active -> sign_only -> retired.
//
// Lifecycle rule (PLAN "Key lifecycle"):
//   - active: may sign requests bound to it.
//   - sign_only (draining after a rotation): may sign only requests bound to it
//     AND created before its sign_only_at.
//   - retired: may sign nothing. For HSM keys the private key object is
//     destroyed in the token; public key and metadata stay.
//
// Key material is created by a domain.KeyGenerator per backend (HSM, MPC).
// Audit events are emitted after the DB transaction commits.
package keys

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ws4charlie/quorum-vault/internal/domain"
)

var (
	ErrNotFound          = errors.New("keys: not found")
	ErrInvalidTransition = errors.New("keys: invalid state transition")
	ErrKeyNotUsable      = errors.New("keys: key may not sign this request")
	// ErrConflict: Rotate lost to concurrent rotations maxRotateAttempts times.
	ErrConflict = errors.New("keys: concurrent rotation conflict")
)

// KeyDestroyer is implemented by generators whose backend holds key material
// the registry must destroy on retire (the HSM generator).
type KeyDestroyer interface {
	DestroyKey(ctx context.Context, key domain.Key) error
}

const maxRotateAttempts = 3

type Registry struct {
	pool *pgxpool.Pool
	aud  domain.Auditor
	gens map[domain.Backend]domain.KeyGenerator
}

func New(pool *pgxpool.Pool, aud domain.Auditor, gens ...domain.KeyGenerator) *Registry {
	r := &Registry{pool: pool, aud: aud, gens: map[domain.Backend]domain.KeyGenerator{}}
	for _, g := range gens {
		r.gens[g.Backend()] = g
	}
	return r
}

func (r *Registry) gen(b domain.Backend) (domain.KeyGenerator, error) {
	g, ok := r.gens[b]
	if !ok {
		return nil, fmt.Errorf("keys: no key generator for backend %q", b)
	}
	return g, nil
}

// destroy removes key material for keys whose backend has a KeyDestroyer.
func (r *Registry) destroy(ctx context.Context, k domain.Key) (destroyed bool, err error) {
	g, ok := r.gens[k.Backend]
	if !ok {
		return false, fmt.Errorf("keys: no key generator for backend %q", k.Backend)
	}
	d, ok := g.(KeyDestroyer)
	if !ok {
		return false, nil
	}
	return true, d.DestroyKey(ctx, k)
}

// discard destroys a freshly generated key that never made it into the DB.
// Best effort: the original error matters more.
func (r *Registry) discard(k domain.Key) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r.destroy(ctx, k)
}

// CreateWallet creates a wallet and its key v1 (active).
func (r *Registry) CreateWallet(ctx context.Context, actor, name string, tier domain.Tier, backend domain.Backend) (domain.Wallet, domain.Key, error) {
	g, err := r.gen(backend)
	if err != nil {
		return domain.Wallet{}, domain.Key{}, err
	}
	w := domain.Wallet{ID: uuid.NewString(), Name: name, Tier: tier, Backend: backend}
	k, err := g.Generate(ctx, w.ID, 1)
	if err != nil {
		return domain.Wallet{}, domain.Key{}, fmt.Errorf("keys: generate: %w", err)
	}
	prepare(&k, w.ID, 1, backend)

	err = pgx.BeginFunc(ctx, r.pool, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO wallets (id, name, tier, backend) VALUES ($1, $2, $3, $4) RETURNING created_at`,
			w.ID, w.Name, w.Tier, w.Backend).Scan(&w.CreatedAt); err != nil {
			return fmt.Errorf("keys: insert wallet: %w", err)
		}
		return insertActive(ctx, tx, &k)
	})
	if err != nil {
		r.discard(k)
		return domain.Wallet{}, domain.Key{}, err
	}
	err = r.emit(ctx,
		event(actor, domain.EventWalletCreated, w.ID, "", map[string]any{"name": w.Name, "tier": w.Tier, "backend": w.Backend}),
		event(actor, domain.EventKeyGenerated, w.ID, k.ID, keyPayload(k)),
	)
	return w, k, err
}

// prepare fills the fields the registry owns, whatever the generator set.
func prepare(k *domain.Key, walletID string, version int, backend domain.Backend) {
	if k.ID == "" {
		k.ID = uuid.NewString()
	}
	k.WalletID, k.Version, k.Backend = walletID, version, backend
	if k.Purpose == "" {
		k.Purpose = "signing"
	}
	k.State = domain.KeyStateActive
}

func insertActive(ctx context.Context, tx pgx.Tx, k *domain.Key) error {
	err := tx.QueryRow(ctx, `INSERT INTO keys
		(id, wallet_id, version, curve, backend, purpose, state, hsm_label, hsm_key_id, mpc_key_ref, public_key, address, activated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NULLIF($8, ''), $9, NULLIF($10, ''), $11, $12, now())
		RETURNING created_at, activated_at`,
		k.ID, k.WalletID, k.Version, k.Curve, k.Backend, k.Purpose, k.State,
		k.HSMLabel, k.HSMKeyID, k.MPCKeyRef, k.PublicKey, k.Address,
	).Scan(&k.CreatedAt, &k.ActivatedAt)
	if err != nil {
		return fmt.Errorf("keys: insert key: %w", err)
	}
	return nil
}

func (r *Registry) GetWallet(ctx context.Context, id string) (domain.Wallet, error) {
	if uuid.Validate(id) != nil {
		return domain.Wallet{}, fmt.Errorf("%w: wallet %q", ErrNotFound, id)
	}
	var w domain.Wallet
	err := r.pool.QueryRow(ctx, `SELECT id::text, name, tier, backend, created_at FROM wallets WHERE id = $1`, id).
		Scan(&w.ID, &w.Name, &w.Tier, &w.Backend, &w.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return w, fmt.Errorf("%w: wallet %s", ErrNotFound, id)
	}
	return w, err
}

func (r *Registry) ListWallets(ctx context.Context) ([]domain.Wallet, error) {
	rows, err := r.pool.Query(ctx, `SELECT id::text, name, tier, backend, created_at FROM wallets ORDER BY created_at, name`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (domain.Wallet, error) {
		var w domain.Wallet
		err := row.Scan(&w.ID, &w.Name, &w.Tier, &w.Backend, &w.CreatedAt)
		return w, err
	})
}

const keyCols = `id::text, wallet_id::text, version, curve, backend, purpose, state,
	coalesce(hsm_label, ''), hsm_key_id, coalesce(mpc_key_ref, ''), public_key, address,
	created_at, activated_at, sign_only_at, retired_at`

func scanKey(row pgx.Row) (domain.Key, error) {
	var k domain.Key
	err := row.Scan(&k.ID, &k.WalletID, &k.Version, &k.Curve, &k.Backend, &k.Purpose, &k.State,
		&k.HSMLabel, &k.HSMKeyID, &k.MPCKeyRef, &k.PublicKey, &k.Address,
		&k.CreatedAt, &k.ActivatedAt, &k.SignOnlyAt, &k.RetiredAt)
	return k, err
}

func (r *Registry) Get(ctx context.Context, keyID string) (domain.Key, error) {
	return getKey(ctx, r.pool, keyID, "")
}

func getKey(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, keyID, suffix string) (domain.Key, error) {
	if uuid.Validate(keyID) != nil {
		return domain.Key{}, fmt.Errorf("%w: key %q", ErrNotFound, keyID)
	}
	k, err := scanKey(q.QueryRow(ctx, `SELECT `+keyCols+` FROM keys WHERE id = $1`+suffix, keyID))
	if errors.Is(err, pgx.ErrNoRows) {
		return k, fmt.Errorf("%w: key %s", ErrNotFound, keyID)
	}
	return k, err
}

// ListKeys lists a wallet's keys by version, or every key when walletID is "".
func (r *Registry) ListKeys(ctx context.Context, walletID string) ([]domain.Key, error) {
	var rows pgx.Rows
	var err error
	if walletID == "" {
		rows, err = r.pool.Query(ctx, `SELECT `+keyCols+` FROM keys ORDER BY wallet_id, version`)
	} else {
		if uuid.Validate(walletID) != nil {
			return nil, nil
		}
		rows, err = r.pool.Query(ctx, `SELECT `+keyCols+` FROM keys WHERE wallet_id = $1 ORDER BY version`, walletID)
	}
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (domain.Key, error) { return scanKey(row) })
}

func (r *Registry) ActiveKey(ctx context.Context, walletID string) (domain.Key, error) {
	if uuid.Validate(walletID) != nil {
		return domain.Key{}, fmt.Errorf("%w: wallet %q", ErrNotFound, walletID)
	}
	k, err := scanKey(r.pool.QueryRow(ctx, `SELECT `+keyCols+` FROM keys WHERE wallet_id = $1 AND state = 'active'`, walletID))
	if errors.Is(err, pgx.ErrNoRows) {
		return k, fmt.Errorf("%w: active key for wallet %s", ErrNotFound, walletID)
	}
	return k, err
}

// Rotate generates key version N+1 (active) and moves the current active key
// to sign_only, in one DB transaction. The new key is generated before the
// transaction (an HSM or MPC keygen should not hold row locks); if the
// transaction fails, the new key's material is destroyed. If a concurrent
// rotation took version N+1 first, the new key is discarded and Rotate tries
// again, so concurrent calls serialize (each one rotates once).
func (r *Registry) Rotate(ctx context.Context, actor, walletID string) (newKey, oldKey domain.Key, err error) {
	w, err := r.GetWallet(ctx, walletID)
	if err != nil {
		return newKey, oldKey, err
	}
	g, err := r.gen(w.Backend)
	if err != nil {
		return newKey, oldKey, err
	}
	for attempt := 0; attempt < maxRotateAttempts; attempt++ {
		var maxVer int
		if err := r.pool.QueryRow(ctx, `SELECT coalesce(max(version), 0) FROM keys WHERE wallet_id = $1`, walletID).Scan(&maxVer); err != nil {
			return newKey, oldKey, err
		}
		newKey, err = g.Generate(ctx, walletID, maxVer+1)
		if err != nil {
			return domain.Key{}, domain.Key{}, fmt.Errorf("keys: generate: %w", err)
		}
		prepare(&newKey, walletID, maxVer+1, w.Backend)

		var stale bool
		err = pgx.BeginFunc(ctx, r.pool, func(tx pgx.Tx) error {
			// The wallet row lock serializes rotations of one wallet; the key
			// row locks keep Retire and other writers off these keys.
			if _, err := tx.Exec(ctx, `SELECT 1 FROM wallets WHERE id = $1 FOR UPDATE`, walletID); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `SELECT 1 FROM keys WHERE wallet_id = $1 FOR UPDATE`, walletID); err != nil {
				return err
			}
			var cur int
			if err := tx.QueryRow(ctx, `SELECT coalesce(max(version), 0) FROM keys WHERE wallet_id = $1`, walletID).Scan(&cur); err != nil {
				return err
			}
			if cur != maxVer {
				stale = true
				return ErrConflict
			}
			oldKey, err = scanKey(tx.QueryRow(ctx, `UPDATE keys SET state = 'sign_only', sign_only_at = now()
				WHERE wallet_id = $1 AND state = 'active' RETURNING `+keyCols, walletID))
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("%w: active key for wallet %s", ErrNotFound, walletID)
			}
			if err != nil {
				return fmt.Errorf("keys: demote active key: %w", err)
			}
			return insertActive(ctx, tx, &newKey)
		})
		if err != nil {
			r.discard(newKey)
			if stale {
				continue
			}
			return domain.Key{}, domain.Key{}, err
		}
		err = r.emit(ctx,
			event(actor, domain.EventKeyGenerated, walletID, newKey.ID, keyPayload(newKey)),
			event(actor, domain.EventKeyStateChanged, walletID, oldKey.ID, map[string]any{
				"version": oldKey.Version, "from": domain.KeyStateActive, "to": domain.KeyStateSignOnly}),
			event(actor, domain.EventKeyRotated, walletID, newKey.ID, map[string]any{
				"old_key_id": oldKey.ID, "old_version": oldKey.Version, "old_address": oldKey.Address,
				"new_key_id": newKey.ID, "new_version": newKey.Version, "new_address": newKey.Address}),
		)
		return newKey, oldKey, err
	}
	return domain.Key{}, domain.Key{}, fmt.Errorf("%w: wallet %s", ErrConflict, walletID)
}

// Retire moves a sign_only key to retired. For backends with key material in
// an HSM the private key is destroyed inside the transaction, before commit:
// if the destroy fails the key stays sign_only and Retire can be retried; if
// the commit fails after the destroy, a retry finds the key already gone and
// completes. A retired key never keeps a usable private key.
func (r *Registry) Retire(ctx context.Context, actor, keyID string) (domain.Key, error) {
	var k domain.Key
	var destroyed bool
	err := pgx.BeginFunc(ctx, r.pool, func(tx pgx.Tx) error {
		var err error
		if k, err = getKey(ctx, tx, keyID, " FOR UPDATE"); err != nil {
			return err
		}
		if err := checkTransition(k.State, domain.KeyStateRetired); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `UPDATE keys SET state = 'retired', retired_at = now() WHERE id = $1 RETURNING retired_at`,
			keyID).Scan(&k.RetiredAt); err != nil {
			return fmt.Errorf("keys: retire: %w", err)
		}
		k.State = domain.KeyStateRetired
		if destroyed, err = r.destroy(ctx, k); err != nil {
			return fmt.Errorf("keys: destroy key material: %w", err)
		}
		return nil
	})
	if err != nil {
		return domain.Key{}, err
	}
	evs := []domain.AuditEvent{event(actor, domain.EventKeyStateChanged, k.WalletID, k.ID, map[string]any{
		"version": k.Version, "from": domain.KeyStateSignOnly, "to": domain.KeyStateRetired})}
	if destroyed {
		evs = append(evs, event(actor, domain.EventKeyDestroyed, k.WalletID, k.ID, map[string]any{
			"version": k.Version, "backend": k.Backend, "hsm_label": k.HSMLabel, "hsm_key_id": fmt.Sprintf("%x", k.HSMKeyID),
			"object": "private_key"}))
	}
	return k, r.emit(ctx, evs...)
}

// checkTransition allows only active -> sign_only and sign_only -> retired.
func checkTransition(from, to domain.KeyState) error {
	if (from == domain.KeyStateActive && to == domain.KeyStateSignOnly) ||
		(from == domain.KeyStateSignOnly && to == domain.KeyStateRetired) {
		return nil
	}
	return fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, from, to)
}

// AuthorizeSign reports whether key may sign req under the lifecycle rule.
// It is pure: key and req must be fresh from the DB.
func (r *Registry) AuthorizeSign(key domain.Key, req domain.SignRequest) error {
	if req.KeyID != key.ID || (req.WalletID != "" && req.WalletID != key.WalletID) {
		return fmt.Errorf("%w: request %s is bound to key %s, not %s", ErrKeyNotUsable, req.ID, req.KeyID, key.ID)
	}
	switch key.State {
	case domain.KeyStateActive:
		return nil
	case domain.KeyStateSignOnly:
		if key.SignOnlyAt != nil && req.CreatedAt.Before(*key.SignOnlyAt) {
			return nil
		}
		return fmt.Errorf("%w: key %s is sign_only and request %s was created after the rotation", ErrKeyNotUsable, key.ID, req.ID)
	}
	return fmt.Errorf("%w: key %s is %s", ErrKeyNotUsable, key.ID, key.State)
}

func keyPayload(k domain.Key) map[string]any {
	p := map[string]any{"version": k.Version, "curve": k.Curve, "backend": k.Backend, "address": k.Address, "state": k.State}
	if k.HSMLabel != "" {
		p["hsm_label"] = k.HSMLabel
		p["hsm_key_id"] = fmt.Sprintf("%x", k.HSMKeyID)
	}
	if k.MPCKeyRef != "" {
		p["mpc_key_ref"] = k.MPCKeyRef
	}
	return p
}

func event(actor, typ, walletID, keyID string, payload map[string]any) domain.AuditEvent {
	b, _ := json.Marshal(payload) // only strings, ints and string types
	return domain.AuditEvent{Actor: actor, Type: typ, WalletID: walletID, KeyID: keyID, Payload: b}
}

// emit appends events in order. The state change is already committed, so an
// error here means "done, but not fully audited" and is returned to the caller.
func (r *Registry) emit(ctx context.Context, evs ...domain.AuditEvent) error {
	if r.aud == nil {
		return nil
	}
	for _, ev := range evs {
		if _, err := r.aud.Append(ctx, ev); err != nil {
			return fmt.Errorf("keys: audit %s: %w", ev.Type, err)
		}
	}
	return nil
}
