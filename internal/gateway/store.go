package gateway

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"hash/fnv"
	"math/big"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed store.sql
var storeSQL string

// Guard is the replay-guard store. It lives in its own database (its own DSN),
// never the business database, so an attacker who rewrites the business
// database can neither erase what was signed nor reset the caps and rate limits
// that are counted from here.
type Guard struct{ pool *pgxpool.Pool }

// OpenGuard applies the schema to pool and returns the guard.
func OpenGuard(ctx context.Context, pool *pgxpool.Pool) (*Guard, error) {
	// Several instances may start at once on a fresh database: CREATE TYPE and friends race and fail. One at a time.
	tx, err := pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("gateway: apply store schema: %w", err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('qv-guard-schema'))`); err != nil {
		return nil, fmt.Errorf("gateway: apply store schema: %w", err)
	}
	if _, err := tx.Exec(ctx, storeSQL); err != nil {
		return nil, fmt.Errorf("gateway: apply store schema: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("gateway: apply store schema: %w", err)
	}
	return &Guard{pool: pool}, nil
}

// IntentRecord is a signed_intents row.
type IntentRecord struct {
	ID     string
	Hash   []byte
	Kind   string
	Sender string
	Nonce  uint64
}

// SigRecord is a signed_digests row.
type SigRecord struct {
	Digest    []byte
	IntentID  string
	Nonce     uint64
	Tip       *big.Int
	FeeCap    *big.Int
	Signature []byte // nil while the digest is only reserved
	Reserved  time.Time
}

// NonceClaim is a nonce_claims row.
type NonceClaim struct {
	IntentID string
	Kind     string
}

// GuardTx is a serialized view of the guard for one chain. All methods run in
// one transaction holding a per-chain advisory lock, so two gateway instances
// deciding on the same chain take turns: the second sees the first's records.
type GuardTx struct {
	tx    pgx.Tx
	chain string
}

// Do runs fn in a transaction that holds the chain's lock. fn's records commit
// only if fn returns nil.
func (g *Guard) Do(ctx context.Context, chain string, fn func(*GuardTx) error) error {
	tx, err := g.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("gateway: guard begin: %w", err)
	}
	defer tx.Rollback(context.Background())
	h := fnv.New64a()
	h.Write([]byte("qv-guard\x00" + chain))
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(h.Sum64())); err != nil {
		return fmt.Errorf("gateway: guard lock: %w", err)
	}
	if err := fn(&GuardTx{tx: tx, chain: chain}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("gateway: guard commit: %w", err)
	}
	return nil
}

func parseBig(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("gateway: bad numeric from database: " + s)
	}
	return n
}

// bigOf renders v as a decimal string; queries cast it with ::numeric.
func bigOf(v uint64) string { return fmt.Sprint(v) }

// Intent returns the record of an intent ID, or nil.
func (t *GuardTx) Intent(ctx context.Context, id string) (*IntentRecord, error) {
	var r IntentRecord
	var nonce string
	err := t.tx.QueryRow(ctx, `SELECT intent_id, intent_hash, kind, sender, nonce::text FROM signed_intents WHERE intent_id=$1`, id).
		Scan(&r.ID, &r.Hash, &r.Kind, &r.Sender, &nonce)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r.Nonce = parseBig(nonce).Uint64()
	return &r, nil
}

// Digest returns the record of digest (signature nil while only reserved), or nil.
func (t *GuardTx) Digest(ctx context.Context, digest []byte) (*SigRecord, error) {
	return t.sig(ctx, `WHERE digest=$1`, digest)
}

// LatestSig returns the highest-fee record (reserved or signed) of an intent, or nil.
func (t *GuardTx) LatestSig(ctx context.Context, intentID string) (*SigRecord, error) {
	return t.sig(ctx, `WHERE intent_id=$1 ORDER BY fee_cap DESC, tip DESC, reserved_at DESC LIMIT 1`, intentID)
}

func (t *GuardTx) sig(ctx context.Context, where string, arg any) (*SigRecord, error) {
	var r SigRecord
	var nonce, tip, feeCap string
	err := t.tx.QueryRow(ctx, `SELECT digest, intent_id, nonce::text, tip::text, fee_cap::text, signature, reserved_at FROM signed_digests `+where, arg).
		Scan(&r.Digest, &r.IntentID, &nonce, &tip, &feeCap, &r.Signature, &r.Reserved)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r.Nonce, r.Tip, r.FeeCap = parseBig(nonce).Uint64(), parseBig(tip), parseBig(feeCap)
	return &r, nil
}

// NonceClaim returns who owns (sender, nonce) on this chain, or nil.
func (t *GuardTx) NonceClaim(ctx context.Context, sender string, nonce uint64) (*NonceClaim, error) {
	var c NonceClaim
	err := t.tx.QueryRow(ctx, `SELECT intent_id, kind FROM nonce_claims WHERE chain=$1 AND sender=$2 AND nonce=$3::numeric`,
		t.chain, sender, bigOf(nonce)).Scan(&c.IntentID, &c.Kind)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// WithdrawnSince sums the amount of withdrawal intents of (this chain, asset)
// first signed at or after since.
func (t *GuardTx) WithdrawnSince(ctx context.Context, asset string, since time.Time) (*big.Int, error) {
	return t.AmountSince(ctx, "withdrawal", asset, since)
}

// AmountSince sums the amount of intents of kind on (this chain, asset) first signed at or after since.
func (t *GuardTx) AmountSince(ctx context.Context, kind, asset string, since time.Time) (*big.Int, error) {
	var sum string
	err := t.tx.QueryRow(ctx, `SELECT COALESCE(SUM(amount), 0)::text FROM signed_intents
		WHERE chain=$1 AND asset=$2 AND kind=$3 AND created_at >= $4`, t.chain, asset, kind, since).Scan(&sum)
	if err != nil {
		return nil, err
	}
	return parseBig(sum), nil
}

// CountSince counts intents of kind on this chain first signed at or after since.
func (t *GuardTx) CountSince(ctx context.Context, kind string, since time.Time) (int, error) {
	var n int
	err := t.tx.QueryRow(ctx, `SELECT count(*) FROM signed_intents WHERE chain=$1 AND kind=$2 AND created_at >= $3`,
		t.chain, kind, since).Scan(&n)
	return n, err
}

// Release is everything recorded when a digest is reserved, before the signer
// runs. Signature stays nil until Guard.Finish stores it.
type Release struct {
	IntentID   string
	IntentHash []byte
	Kind       string
	Asset      string
	Amount     *big.Int
	Sender     string
	Nonce      uint64
	Digest     []byte
	Tip        *big.Int
	FeeCap     *big.Int
	Signature  []byte    // nil: reservation
	At         time.Time // reservation time
	NewIntent  bool      // false: another signature for an intent already recorded
	TakeNonce  bool      // a cancel replacing a different intent's claim
}

// Record stores the release. Unique keys on the intent ID, the digest and the
// nonce claim make a double release fail even if the lock were bypassed.
func (t *GuardTx) Record(ctx context.Context, r Release) error {
	if r.NewIntent {
		if _, err := t.tx.Exec(ctx, `INSERT INTO signed_intents (intent_id, intent_hash, kind, chain, asset, amount, sender, nonce, created_at)
			VALUES ($1,$2,$3,$4,$5,$6::numeric,$7,$8::numeric,$9)`,
			r.IntentID, r.IntentHash, r.Kind, t.chain, r.Asset, r.Amount.String(), r.Sender, bigOf(r.Nonce), r.At); err != nil {
			return fmt.Errorf("record intent: %w", err)
		}
	}
	if _, err := t.tx.Exec(ctx, `INSERT INTO signed_digests (digest, intent_id, nonce, tip, fee_cap, signature, reserved_at, signed_at)
		VALUES ($1,$2,$3::numeric,$4::numeric,$5::numeric,$6,$7,NULL)`, r.Digest, r.IntentID, bigOf(r.Nonce), r.Tip.String(), r.FeeCap.String(), r.Signature, r.At); err != nil {
		return fmt.Errorf("record digest: %w", err)
	}
	switch {
	case r.TakeNonce:
		if _, err := t.tx.Exec(ctx, `UPDATE nonce_claims SET intent_id=$4, kind=$5 WHERE chain=$1 AND sender=$2 AND nonce=$3::numeric`,
			t.chain, r.Sender, bigOf(r.Nonce), r.IntentID, r.Kind); err != nil {
			return fmt.Errorf("take nonce: %w", err)
		}
	case r.NewIntent:
		if _, err := t.tx.Exec(ctx, `INSERT INTO nonce_claims (chain, sender, nonce, intent_id, kind) VALUES ($1,$2,$3::numeric,$4,$5)`,
			t.chain, r.Sender, bigOf(r.Nonce), r.IntentID, r.Kind); err != nil {
			return fmt.Errorf("claim nonce: %w", err)
		}
	}
	return nil
}

// Touch marks a stale reservation as being signed again from at.
func (t *GuardTx) Touch(ctx context.Context, digest []byte, at time.Time) error {
	_, err := t.tx.Exec(ctx, `UPDATE signed_digests SET reserved_at=$2 WHERE digest=$1 AND signature IS NULL`, digest, at)
	return err
}

// Finish stores sig for a reserved digest and returns the signature that is
// stored: the first one written wins, a later one is discarded and the stored
// bytes are returned instead. Only the returned value may be released.
func (g *Guard) Finish(ctx context.Context, digest, sig []byte, at time.Time) ([]byte, error) {
	if _, err := g.pool.Exec(ctx, `UPDATE signed_digests SET signature=$2, signed_at=$3 WHERE digest=$1 AND signature IS NULL`, digest, sig, at); err != nil {
		return nil, fmt.Errorf("gateway: store signature: %w", err)
	}
	var stored []byte
	if err := g.pool.QueryRow(ctx, `SELECT signature FROM signed_digests WHERE digest=$1`, digest).Scan(&stored); err != nil {
		return nil, fmt.Errorf("gateway: read stored signature: %w", err)
	}
	if stored == nil {
		return nil, errors.New("gateway: digest has no reservation")
	}
	return stored, nil
}
