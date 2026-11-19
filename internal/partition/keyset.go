package partition

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ws4charlie/quorum-vault/internal/outbox"
)

// Keyset states (research/Key-replacement.md §6.1). A candidate has been made and signs nothing; an active keyset serves the shard (exactly one per shard);
// a draining one only empties itself; a retired one does nothing; compromised is final.
const (
	StateCandidate   = "candidate"
	StateActive      = "active"
	StateDraining    = "draining"
	StateRetired     = "retired"
	StateCompromised = "compromised"
)

// Errors of the registry.
var (
	ErrKeysetNotFound      = errors.New("partition: keyset not found")
	ErrIllegalTransition   = errors.New("partition: keyset state change not allowed")
	ErrActiveExists        = errors.New("partition: the shard already has an active keyset")
	ErrKeysetAddressChange = errors.New("partition: the registered keyset of the shard has another address than the configuration")
)

// Keyset is one generation of the key that serves a shard.
type Keyset struct {
	ShardID    ShardID
	Generation int
	KeyRef     string // the MPC keyset ID, when known
	Address    string
	PublicKey  []byte
	State      string
	CreatedAt  time.Time
	ChangedAt  time.Time
}

const keysetCols = `shard_id, generation, key_ref, address, public_key, state, created_at, state_changed_at`

func scanKeyset(row pgx.Row) (Keyset, error) {
	var k Keyset
	var id string
	err := row.Scan(&id, &k.Generation, &k.KeyRef, &k.Address, &k.PublicKey, &k.State, &k.CreatedAt, &k.ChangedAt)
	k.ShardID = ShardID(id)
	return k, err
}

// audit writes the audit event of a keyset change into the caller's transaction, through the outbox like every other audit event of the core, so the entry
// exists exactly when the change does. The event ID is the shard, the generation and the new state, so a repeat writes nothing new.
func audit(ctx context.Context, tx pgx.Tx, actor, typ string, k Keyset, from string) error {
	id := fmt.Sprintf("%s#%d", k.ShardID, k.Generation)
	return outbox.WriteOnce(ctx, tx, id+"\x00"+typ, outbox.TopicAudit, id, map[string]any{
		"type": typ, "id": id, "actor": actor, "shard_id": string(k.ShardID), "generation": k.Generation,
		"address": k.Address, "key_ref": k.KeyRef, "from": from, "to": k.State,
	})
}

// RegisterInitial records generation 1 of a shard as active, which is what every shard is before any replacement exists. It is idempotent: when generation 1
// is registered it returns it, and refuses (ErrKeysetAddressChange) when its address is not the one given, because a shard's address changes only through a
// new generation.
func RegisterInitial(ctx context.Context, tx pgx.Tx, actor string, shard ShardID, address, keyRef string, publicKey []byte) (Keyset, error) {
	if _, err := ParseShardID(string(shard)); err != nil {
		return Keyset{}, err
	}
	if address == "" {
		return Keyset{}, errors.New("partition: keyset: empty address")
	}
	k, err := scanKeyset(tx.QueryRow(ctx, `INSERT INTO keysets (shard_id, generation, key_ref, address, public_key, state, activated_at)
		VALUES ($1, 1, $2, $3, $4, 'active', now()) ON CONFLICT (shard_id, generation) DO NOTHING RETURNING `+keysetCols, string(shard), keyRef, address, publicKey))
	if err == nil {
		return k, audit(ctx, tx, actor, "keyset.registered", k, "")
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Keyset{}, fmt.Errorf("partition: register keyset of %s: %w", shard, err)
	}
	k, err = scanKeyset(tx.QueryRow(ctx, `SELECT `+keysetCols+` FROM keysets WHERE shard_id = $1 AND generation = 1`, string(shard)))
	if err != nil {
		return Keyset{}, err
	}
	if !sameAddress(k.Address, address) {
		return Keyset{}, fmt.Errorf("%w: %s generation 1 is %s, the configuration says %s", ErrKeysetAddressChange, shard, k.Address, address)
	}
	return k, nil
}

// RegisterCandidate records the next generation of a shard as a candidate. Nothing in production calls it yet.
func RegisterCandidate(ctx context.Context, tx pgx.Tx, actor string, shard ShardID, address, keyRef string, publicKey []byte) (Keyset, error) {
	if _, err := ParseShardID(string(shard)); err != nil {
		return Keyset{}, err
	}
	if address == "" {
		return Keyset{}, errors.New("partition: keyset: empty address")
	}
	k, err := scanKeyset(tx.QueryRow(ctx, `INSERT INTO keysets (shard_id, generation, key_ref, address, public_key, state)
		SELECT $1, COALESCE(MAX(generation), 0) + 1, $2, $3, $4, 'candidate' FROM keysets WHERE shard_id = $1 RETURNING `+keysetCols, string(shard), keyRef, address, publicKey))
	if err != nil {
		return Keyset{}, fmt.Errorf("partition: register candidate of %s: %w", shard, err)
	}
	return k, audit(ctx, tx, actor, "keyset.candidate", k, "")
}

// Activate makes a candidate the active keyset of its shard. It refuses while the shard has another active one (the caller moves that one to draining
// first); the database enforces the same with a unique index.
func Activate(ctx context.Context, tx pgx.Tx, actor string, shard ShardID, gen int) (Keyset, error) {
	return transition(ctx, tx, actor, shard, gen, StateActive, "keyset.activated", "activated_at", StateCandidate)
}

// StartDraining moves the active keyset to draining.
func StartDraining(ctx context.Context, tx pgx.Tx, actor string, shard ShardID, gen int) (Keyset, error) {
	return transition(ctx, tx, actor, shard, gen, StateDraining, "keyset.draining", "draining_at", StateActive)
}

// Retire retires a draining keyset, and only that: a keyset that was not drained is never retired.
func Retire(ctx context.Context, tx pgx.Tx, actor string, shard ShardID, gen int) (Keyset, error) {
	return transition(ctx, tx, actor, shard, gen, StateRetired, "keyset.retired", "retired_at", StateDraining)
}

// MarkCompromised flags a candidate, active or draining keyset as compromised. It never goes back.
func MarkCompromised(ctx context.Context, tx pgx.Tx, actor string, shard ShardID, gen int) (Keyset, error) {
	return transition(ctx, tx, actor, shard, gen, StateCompromised, "keyset.compromised", "compromised_at", StateCandidate, StateActive, StateDraining)
}

func transition(ctx context.Context, tx pgx.Tx, actor string, shard ShardID, gen int, to, event, stamp string, from ...string) (Keyset, error) {
	if actor == "" {
		return Keyset{}, errors.New("partition: keyset change needs an actor")
	}
	cur, err := scanKeyset(tx.QueryRow(ctx, `SELECT `+keysetCols+` FROM keysets WHERE shard_id = $1 AND generation = $2 FOR UPDATE`, string(shard), gen))
	if errors.Is(err, pgx.ErrNoRows) {
		return Keyset{}, fmt.Errorf("%w: %s generation %d", ErrKeysetNotFound, shard, gen)
	}
	if err != nil {
		return Keyset{}, err
	}
	ok := false
	for _, f := range from {
		ok = ok || cur.State == f
	}
	if !ok {
		return Keyset{}, fmt.Errorf("%w: %s generation %d is %s, %s needs %s", ErrIllegalTransition, shard, gen, cur.State, to, strings.Join(from, " or "))
	}
	k, err := scanKeyset(tx.QueryRow(ctx, `UPDATE keysets SET state = $3, state_changed_at = now(), `+stamp+` = now() WHERE shard_id = $1 AND generation = $2 RETURNING `+keysetCols,
		string(shard), gen, to))
	if err != nil {
		var pe *pgconn.PgError
		if errors.As(err, &pe) && pe.Code == "23505" && to == StateActive {
			return Keyset{}, fmt.Errorf("%w: %s", ErrActiveExists, shard)
		}
		return Keyset{}, err
	}
	return k, audit(ctx, tx, actor, event, k, cur.State)
}

// Active returns the active keyset of a shard.
func Active(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, shard ShardID) (Keyset, error) {
	k, err := scanKeyset(q.QueryRow(ctx, `SELECT `+keysetCols+` FROM keysets WHERE shard_id = $1 AND state = 'active'`, string(shard)))
	if errors.Is(err, pgx.ErrNoRows) {
		return Keyset{}, fmt.Errorf("%w: no active keyset for %s", ErrKeysetNotFound, shard)
	}
	return k, err
}

// ActiveAll returns the active keyset of every shard, by shard ID.
func ActiveAll(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}) (map[ShardID]Keyset, error) {
	rows, err := q.Query(ctx, `SELECT `+keysetCols+` FROM keysets WHERE state = 'active'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[ShardID]Keyset{}
	for rows.Next() {
		k, err := scanKeyset(rows)
		if err != nil {
			return nil, err
		}
		out[k.ShardID] = k
	}
	return out, rows.Err()
}

// sameAddress compares addresses of any family: hex addresses (EVM) without regard to case, the others exactly.
func sameAddress(a, b string) bool {
	if strings.HasPrefix(a, "0x") && strings.HasPrefix(b, "0x") {
		return strings.EqualFold(a, b)
	}
	return a == b
}
