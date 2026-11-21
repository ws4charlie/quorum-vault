package gateway

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/fnv"
	"math/big"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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
type Guard struct {
	pool *pgxpool.Pool
	// approverIgnored is the number of ignored approver-log rows last reported, so an ALERT is raised when it changes, not at every decision.
	approverIgnored atomic.Int64
	// keysetIgnored is the same for the keyset log (keysets.go).
	keysetIgnored atomic.Int64
	// drainRefused counts the drains this process refused (keysets.go).
	drainRefused atomic.Int64
	// drainMetrics counts them by mode, chain and reason for qv_drain_refusals_total (drainmetrics.go).
	drainMetrics drainCounts
}

// storeVersion identifies the schema this binary needs: the hash of store.sql. The guard database records the version it was last brought to (guard_schema),
// and OpenGuard applies the schema only when that record is missing or different.
var storeVersion = func() string { h := sha256.Sum256([]byte(storeSQL)); return hex.EncodeToString(h[:8]) }()

// schemaCurrent reports whether the database is already at this binary's schema, with plain reads that take no table lock (to_regclass and a select take
// at most an ACCESS SHARE lock on one small table). Any error counts as "not current": the schema is then applied, as before the marker existed (a role that
// may not read the marker, a marker table that does not exist yet).
func schemaCurrent(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}) bool {
	var reg *string
	if err := q.QueryRow(ctx, `SELECT to_regclass('guard_schema')::text`).Scan(&reg); err != nil || reg == nil {
		return false
	}
	var v string
	if err := q.QueryRow(ctx, `SELECT version FROM guard_schema WHERE id=1`).Scan(&v); err != nil {
		return false
	}
	return v == storeVersion
}

// OpenGuard returns the guard of pool, applying the schema first only when the database is behind it. The schema's statements are idempotent but take table
// locks even when they change nothing, so an operator's tool (qv-rekey, qv-keysets, qv-approvers, qv-route, qv-fee-caps) that ran them at every start could
// block or deadlock the gateway's and the cosigners' decisions at the very moment it is used (a key ceremony, an emergency). The services apply the schema at
// their own start, as before; a tool finds it current and runs no DDL. When it is behind, the apply runs under an advisory lock, so two openers never race,
// and is tried again a few times if it still meets a decision in a deadlock.
func OpenGuard(ctx context.Context, pool *pgxpool.Pool) (*Guard, error) {
	if schemaCurrent(ctx, pool) {
		return &Guard{pool: pool}, nil
	}
	var err error
	for try := 0; try < 6; try++ {
		if err = applyStoreSchema(ctx, pool); err == nil {
			return &Guard{pool: pool}, nil
		}
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || (pe.Code != "40P01" && pe.Code != "40001") {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, err
		case <-time.After(time.Duration(try+1) * 200 * time.Millisecond):
		}
	}
	return nil, err
}

func applyStoreSchema(ctx context.Context, pool *pgxpool.Pool) error {
	// Several instances may start at once on a fresh database: CREATE TYPE and friends race and fail. One at a time.
	// Everything below runs on the ONE connection of this transaction: an opener that holds a connection while it waits for the lock must never need a second
	// one from the pool to finish (a small pool, several openers at once, would deadlock). Checks and the marker use savepoints, so a refused statement
	// does not abort the transaction.
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("gateway: apply store schema: %w", err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('qv-guard-schema'))`); err != nil {
		return fmt.Errorf("gateway: apply store schema: %w", err)
	}
	if sp, err := tx.Begin(ctx); err == nil { // another opener finished while this one waited for the lock
		current := schemaCurrent(ctx, sp)
		sp.Rollback(ctx)
		if current {
			return nil
		}
	}
	if _, err := tx.Exec(ctx, storeSQL); err != nil {
		return fmt.Errorf("gateway: apply store schema: %w", err)
	}
	// The marker is best effort: a role that may create tables but not write a marker table that belongs to another role must still open the guard, as it
	// always did (the next open then applies the schema again).
	if sp, err := tx.Begin(ctx); err == nil {
		if _, err := sp.Exec(ctx, `CREATE TABLE IF NOT EXISTS guard_schema (id int PRIMARY KEY CHECK (id = 1), version text NOT NULL)`); err == nil {
			if _, err := sp.Exec(ctx, `INSERT INTO guard_schema (id, version) VALUES (1, $1) ON CONFLICT (id) DO UPDATE SET version = EXCLUDED.version`, storeVersion); err == nil {
				sp.Commit(ctx)
			} else {
				sp.Rollback(ctx)
			}
		} else {
			sp.Rollback(ctx)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("gateway: apply store schema: %w", err)
	}
	return nil
}

// IntentRecord is a signed_intents row.
type IntentRecord struct {
	ID     string
	Hash   []byte
	Kind   string
	Sender string
	// PartitionID is the partition the intent was signed for (empty on rows from before it was recorded).
	PartitionID string
	// Claims is what the intent's transaction consumes, as the codec named it (EVM: one claim, sender plus nonce).
	Claims []string
	// BatchID is the batch this withdrawal was signed in; empty for a single withdrawal and for the batch's own row.
	BatchID string
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
	err := t.tx.QueryRow(ctx, `SELECT intent_id, intent_hash, kind, sender, COALESCE(partition_id, ''), COALESCE(claims, '{}'), COALESCE(batch_id, '') FROM signed_intents WHERE intent_id=$1`, id).
		Scan(&r.ID, &r.Hash, &r.Kind, &r.Sender, &r.PartitionID, &r.Claims, &r.BatchID)
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

// AmountFrom is the sum of the amounts of the intents of kind that moved asset away from sender on this chain (a drain's cap is per source address,
// for good: the source key's address is unique to its generation).
func (t *GuardTx) AmountFrom(ctx context.Context, kind, sender, asset string) (*big.Int, error) {
	var sum string
	err := t.tx.QueryRow(ctx, `SELECT COALESCE(SUM(amount), 0)::text FROM signed_intents
		WHERE chain=$1 AND kind=$2 AND sender=$3 AND asset=$4`, t.chain, kind, sender, asset).Scan(&sum)
	if err != nil {
		return nil, err
	}
	return parseBig(sum), nil
}

// SignedDrainsSince counts the drains of this chain first admitted at or after since that were SIGNED: a drain counts when the guard holds a signature for
// one of its digests, or when its digest is still being signed (reserved at or after pending). A drain the zone admitted but a cosigner or the signer then
// refused, or one that expired unsigned, stays out, so a storm of refused retries cannot use up the rate or the cap. The cosigner never stores a signature
// (party A does), so it passes the zero time as pending: every drain it authorised counts.
func (t *GuardTx) SignedDrainsSince(ctx context.Context, since, pending time.Time) (int, error) {
	var n int
	err := t.tx.QueryRow(ctx, `SELECT count(*) FROM signed_intents i WHERE i.chain=$1 AND i.kind=$2 AND i.created_at >= $3
		AND EXISTS (SELECT 1 FROM signed_digests d WHERE d.intent_id = i.intent_id AND (d.signature IS NOT NULL OR d.reserved_at >= $4))`,
		t.chain, signjob.KindDrain, since, pending).Scan(&n)
	return n, err
}

// SignedDrainAmountFrom is the sum of the signed drains (see SignedDrainsSince) of asset from sender, over all time: a drain's cap is per source address.
func (t *GuardTx) SignedDrainAmountFrom(ctx context.Context, sender, asset string, pending time.Time) (*big.Int, error) {
	var sum string
	err := t.tx.QueryRow(ctx, `SELECT COALESCE(SUM(i.amount), 0)::text FROM signed_intents i WHERE i.chain=$1 AND i.kind=$2 AND i.sender=$3 AND i.asset=$4
		AND EXISTS (SELECT 1 FROM signed_digests d WHERE d.intent_id = i.intent_id AND (d.signature IS NOT NULL OR d.reserved_at >= $5))`,
		t.chain, signjob.KindDrain, sender, asset, pending).Scan(&sum)
	if err != nil {
		return nil, err
	}
	return parseBig(sum), nil
}

// SignedDrainCountFrom is the number of signed drains (see SignedDrainsSince) from sender, of any asset, over all time.
func (t *GuardTx) SignedDrainCountFrom(ctx context.Context, sender string, pending time.Time) (int, error) {
	var n int
	err := t.tx.QueryRow(ctx, `SELECT count(*) FROM signed_intents i WHERE i.chain=$1 AND i.kind=$2 AND i.sender=$3
		AND EXISTS (SELECT 1 FROM signed_digests d WHERE d.intent_id = i.intent_id AND (d.signature IS NOT NULL OR d.reserved_at >= $4))`,
		t.chain, signjob.KindDrain, sender, pending).Scan(&n)
	return n, err
}

// SignedCancelCountFrom counts the cancels reserved or signed from sender in all while its generation was compromised in this guard's own view (the bound of a
// compromised generation's cancels). The state is the one the guard saw and recorded with the reservation (Release.GenState), never a label from the business
// side: a routine cancel signed while the key was active does not use up the emergency allowance, and the guard's own log of signed records decides when the
// state changed.
func (t *GuardTx) SignedCancelCountFrom(ctx context.Context, sender string) (int, error) {
	var n int
	err := t.tx.QueryRow(ctx, `SELECT count(*) FROM signed_intents i WHERE i.chain=$1 AND i.kind='cancel' AND i.sender=$2 AND i.gen_state='compromised'
		AND EXISTS (SELECT 1 FROM signed_digests d WHERE d.intent_id = i.intent_id)`, t.chain, sender).Scan(&n)
	return n, err
}

// CountSince counts intents of kind on this chain first signed at or after since.
func (t *GuardTx) CountSince(ctx context.Context, kind string, since time.Time) (int, error) {
	var n int
	err := t.tx.QueryRow(ctx, `SELECT count(*) FROM signed_intents WHERE chain=$1 AND kind=$2 AND created_at >= $3`,
		t.chain, kind, since).Scan(&n)
	return n, err
}

// CancelOutputs lists the outputs ("<txid>:0") of every cancel transaction the zone signed for a batch: the cancel took all of the batch's claims
// (the strict cancel rule makes it spend exactly the batch's inputs, to one output), and each of its attempts, replacements included, has a txid.
// Whichever of them confirms, the batch can never confirm.
func (t *GuardTx) CancelOutputs(ctx context.Context, batchID string) ([]string, error) {
	rows, err := t.tx.Query(ctx, `SELECT DISTINCT d.tx_identity FROM signed_intents b
		JOIN exclusive_claims c ON c.chain=$1 AND c.claim = ANY(b.claims) AND c.kind='cancel'
		JOIN signed_digests d ON d.intent_id = c.intent_id AND d.tx_identity IS NOT NULL
		WHERE b.intent_id=$2 AND b.kind='batch'`, t.chain, batchID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id+":0")
	}
	return out, rows.Err()
}

// Parent returns what the zone recorded about the change of the transaction txid, or nil if it signed none with a change.
func (t *GuardTx) Parent(ctx context.Context, txid string) (*ParentRecord, error) {
	var r ParentRecord
	var vs, fee, cv int64
	var vout int32
	err := t.tx.QueryRow(ctx, `SELECT intent_id, partition_id, vsize, fee, change_vout, change_value FROM signed_parents WHERE chain=$1 AND txid=$2`, t.chain, txid).
		Scan(&r.IntentID, &r.PartitionID, &vs, &fee, &vout, &cv)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r.TxID, r.VSize, r.Fee, r.ChangeVout, r.ChangeValue = txid, uint64(vs), uint64(fee), uint32(vout), uint64(cv)
	return &r, nil
}

// Release is everything recorded when a digest is reserved, before the signer
// runs. Signature stays nil until Guard.Finish stores it.
type Release struct {
	// GenState is the state of the sender's keyset generation as THIS guard's own view had it when the intent was admitted (EVM; empty elsewhere). It is
	// recorded with the intent, so the bound of a compromised generation's cancels counts only cancels admitted under that state.
	GenState    string
	IntentID    string
	IntentHash  []byte
	Kind        string
	Asset       string
	Amount      *big.Int
	Sender      string
	PartitionID string
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
	// Parent, when set, is recorded as the change of the transaction Identity (see ParentFacts).
	Parent *ParentFacts
	// Members are the withdrawals of a batch, recorded as rows of their own when the batch is first reserved (NewIntent).
	Members []MemberRelease
}

// MemberRelease is one withdrawal of a batch as the guard records it.
type MemberRelease struct {
	ID     string
	Hash   []byte
	Amount *big.Int
	// Resend: the withdrawal was signed in an earlier batch whose cancel the zone signed, and this batch spends an output of that cancel. Its row
	// moves to this batch; it is not counted again towards the rate and the daily cap.
	Resend bool
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
		if _, err := t.tx.Exec(ctx, `INSERT INTO signed_intents (intent_id, intent_hash, kind, chain, asset, amount, sender, claims, partition_id, created_at, gen_state)
			VALUES ($1,$2,$3,$4,$5,$6::numeric,$7,$8,$9,$10, NULLIF($11,''))`,
			r.IntentID, r.IntentHash, r.Kind, t.chain, r.Asset, r.Amount.String(), r.Sender, r.Claims, r.PartitionID, r.At, r.GenState); err != nil {
			return fmt.Errorf("record intent: %w", err)
		}
		for _, m := range r.Members {
			if m.Resend {
				if _, err := t.tx.Exec(ctx, `UPDATE signed_intents SET batch_id=$2 WHERE intent_id=$1 AND kind='withdrawal' AND intent_hash=$3`, m.ID, r.IntentID, m.Hash); err != nil {
					return fmt.Errorf("move batch member %s: %w", m.ID, err)
				}
				continue
			}
			if _, err := t.tx.Exec(ctx, `INSERT INTO signed_intents (intent_id, intent_hash, kind, chain, asset, amount, sender, claims, partition_id, created_at, batch_id)
				VALUES ($1,$2,'withdrawal',$3,$4,$5::numeric,$6,'{}',$7,$8,$9)`,
				m.ID, m.Hash, t.chain, r.Asset, m.Amount.String(), r.Sender, r.PartitionID, r.At, r.IntentID); err != nil {
				return fmt.Errorf("record batch member %s: %w", m.ID, err)
			}
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
	if r.Parent != nil && r.Identity != "" {
		if _, err := t.tx.Exec(ctx, `INSERT INTO signed_parents (chain, txid, intent_id, partition_id, vsize, fee, change_vout, change_value) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
			ON CONFLICT DO NOTHING`, t.chain, r.Identity, r.IntentID, r.PartitionID, int64(r.Parent.VSize), int64(r.Parent.Fee), int32(r.Parent.ChangeVout), int64(r.Parent.ChangeValue)); err != nil {
			return fmt.Errorf("record parent: %w", err)
		}
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
