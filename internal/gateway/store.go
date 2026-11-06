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

	"github.com/ws4charlie/quorum-vault/internal/audit"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
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
	// Claims is what the intent's transaction consumes, as the codec named it (EVM: one claim, sender plus nonce).
	Claims []string
}

// SigRecord is a signed_digests row.
type SigRecord struct {
	Digest      []byte
	IntentID    string
	Fees        []*big.Int // the codec's fee components; a replacement must raise them
	PayloadHash []byte     // the transaction the digest belongs to; the digests of one transaction share it
	Signature   []byte     // nil while the digest is only reserved
	Reserved    time.Time
}

// Claim is an exclusive_claims row: who owns something a transaction consumes.
type Claim struct {
	IntentID string
	Kind     string
	Pin      string
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

// Intent returns the record of an intent ID, or nil.
func (t *GuardTx) Intent(ctx context.Context, id string) (*IntentRecord, error) {
	var r IntentRecord
	err := t.tx.QueryRow(ctx, `SELECT intent_id, intent_hash, kind, sender, COALESCE(claims, '{}') FROM signed_intents WHERE intent_id=$1`, id).
		Scan(&r.ID, &r.Hash, &r.Kind, &r.Sender, &r.Claims)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// Digest returns the record of digest (signature nil while only reserved), or nil.
func (t *GuardTx) Digest(ctx context.Context, digest []byte) (*SigRecord, error) {
	return t.sig(ctx, `WHERE digest=$1`, digest)
}

// LatestSig returns the highest-fee record (reserved or signed) of an intent, or nil.
func (t *GuardTx) LatestSig(ctx context.Context, intentID string) (*SigRecord, error) {
	return t.sig(ctx, `WHERE intent_id=$1 ORDER BY fees DESC, reserved_at DESC LIMIT 1`, intentID)
}

// SameTx returns a record of intentID whose digest belongs to the transaction with payloadHash (another signature of
// the same transaction), or nil.
func (t *GuardTx) SameTx(ctx context.Context, intentID string, payloadHash []byte) (*SigRecord, error) {
	return t.sig(ctx, `WHERE intent_id=$1 AND payload_hash=$2 LIMIT 1`, intentID, payloadHash)
}

func (t *GuardTx) sig(ctx context.Context, where string, args ...any) (*SigRecord, error) {
	var r SigRecord
	var fees []string
	err := t.tx.QueryRow(ctx, `SELECT digest, intent_id, COALESCE(fees::text[], '{}'), payload_hash, signature, reserved_at FROM signed_digests `+where, args...).
		Scan(&r.Digest, &r.IntentID, &fees, &r.PayloadHash, &r.Signature, &r.Reserved)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	for _, f := range fees {
		r.Fees = append(r.Fees, parseBig(f))
	}
	return &r, nil
}

// Claim returns who owns claim on this chain, or nil.
func (t *GuardTx) Claim(ctx context.Context, claim string) (*Claim, error) {
	var c Claim
	err := t.tx.QueryRow(ctx, `SELECT intent_id, kind, pin FROM exclusive_claims WHERE chain=$1 AND claim=$2`, t.chain, claim).Scan(&c.IntentID, &c.Kind, &c.Pin)
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
	IntentID    string
	IntentHash  []byte
	Kind        string
	Asset       string
	Amount      *big.Int
	Sender      string
	Claims      []string // what the transaction consumes
	Pins        []string // one per claim, or none (EVM); the codec's pin of each claim
	Identity    string   // the codec's identity of the transaction; empty when the chain has none
	Digest      []byte
	Fees        []*big.Int
	PayloadHash []byte
	Signature   []byte    // nil: reservation
	At          time.Time // reservation time
	NewIntent   bool      // false: another signature for an intent already recorded
	NewClaims   []string  // claims nobody holds yet, taken by this intent
	TakeClaims  []string  // a cancel taking over the claims of a different intent
}

// pinOf is the pin of claim c (empty when the release has none).
func (r Release) pinOf(c string) string {
	for i, x := range r.Claims {
		if x == c && i < len(r.Pins) {
			return r.Pins[i]
		}
	}
	return ""
}

// IdentityConflict returns the intent of a digest on this chain that has the same transaction identity as identity but another
// payload hash, or "" if there is none.
func (t *GuardTx) IdentityConflict(ctx context.Context, identity string, payloadHash []byte) (string, error) {
	var id string
	err := t.tx.QueryRow(ctx, `SELECT d.intent_id FROM signed_digests d JOIN signed_intents i ON i.intent_id = d.intent_id
		WHERE i.chain=$1 AND d.tx_identity=$2 AND d.payload_hash IS DISTINCT FROM $3 LIMIT 1`, t.chain, identity, payloadHash).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return id, err
}

// Record stores the release. Unique keys on the intent ID, the digest and the
// claim make a double release fail even if the lock were bypassed.
func (t *GuardTx) Record(ctx context.Context, r Release) error {
	if r.NewIntent {
		if _, err := t.tx.Exec(ctx, `INSERT INTO signed_intents (intent_id, intent_hash, kind, chain, asset, amount, sender, claims, created_at)
			VALUES ($1,$2,$3,$4,$5,$6::numeric,$7,$8,$9)`,
			r.IntentID, r.IntentHash, r.Kind, t.chain, r.Asset, r.Amount.String(), r.Sender, r.Claims, r.At); err != nil {
			return fmt.Errorf("record intent: %w", err)
		}
	}
	fees := make([]string, len(r.Fees))
	for i, f := range r.Fees {
		fees[i] = f.String()
	}
	var identity any
	if r.Identity != "" {
		identity = r.Identity
	}
	if _, err := t.tx.Exec(ctx, `INSERT INTO signed_digests (digest, intent_id, fees, payload_hash, tx_identity, signature, reserved_at, signed_at)
		VALUES ($1,$2,$3::numeric[],$4,$5,$6,$7,NULL)`, r.Digest, r.IntentID, fees, r.PayloadHash, identity, r.Signature, r.At); err != nil {
		return fmt.Errorf("record digest: %w", err)
	}
	for _, c := range r.TakeClaims {
		if _, err := t.tx.Exec(ctx, `UPDATE exclusive_claims SET intent_id=$3, kind=$4 WHERE chain=$1 AND claim=$2`, t.chain, c, r.IntentID, r.Kind); err != nil {
			return fmt.Errorf("take claim: %w", err)
		}
	}
	for _, c := range r.NewClaims {
		if _, err := t.tx.Exec(ctx, `INSERT INTO exclusive_claims (chain, claim, intent_id, kind, pin) VALUES ($1,$2,$3,$4,$5)`, t.chain, c, r.IntentID, r.Kind, r.pinOf(c)); err != nil {
			return fmt.Errorf("claim: %w", err)
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
// bytes are returned instead. Only the returned value may be released. The
// record "sign.completed" is written in the same transaction: no signature is
// released without it.
func (g *Guard) Finish(ctx context.Context, digest, sig []byte, at time.Time) ([]byte, error) {
	tx, err := g.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("gateway: store signature: %w", err)
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	if _, err := tx.Exec(ctx, `UPDATE signed_digests SET signature=$2, signed_at=$3 WHERE digest=$1 AND signature IS NULL`, digest, sig, at); err != nil {
		return nil, fmt.Errorf("gateway: store signature: %w", err)
	}
	var stored []byte
	var intentID string
	if err := tx.QueryRow(ctx, `SELECT signature, intent_id FROM signed_digests WHERE digest=$1`, digest).Scan(&stored, &intentID); err != nil {
		return nil, fmt.Errorf("gateway: read stored signature: %w", err)
	}
	if stored == nil {
		return nil, errors.New("gateway: digest has no reservation")
	}
	ev, err := auditRecord{mode: ModeGateway, job: signjob.Job{ID: intentID, Digest: digest}}.completedEvent(intentID)
	if err != nil {
		return nil, err
	}
	if _, err := audit.AppendTx(ctx, tx, ev, ""); err != nil {
		return nil, fmt.Errorf("gateway: audit %s: %w", EventSignCompleted, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("gateway: store signature: %w", err)
	}
	return stored, nil
}
