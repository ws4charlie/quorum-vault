package custody

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/chain/sol"
	"github.com/ws4charlie/quorum-vault/internal/partition"
)

// The business keyset registry is a MIRROR for planning (docs/key-replacement.md): the signing zone decides from its own operator-signed
// records (qv-keysets, internal/gateway/keysets.go), never from this table. So a wrong mirror can stall work but cannot move money:
//
//   - the core builds from generation 2 and the zone still has it as a candidate: the zone refuses the job; a withdrawal is voided with the zone's
//     reason ("generation 2 of … is a candidate: it signs nothing until it is activated") and its hold is released; a drain waits and is tried again;
//   - the zone has activated generation 2 and the core has not: the core builds from generation 1, which the zone then lets sign only the replacement
//     or cancel of work it already signed: the job is refused with that reason in the same way;
//   - a drain whose state holds in one place only waits (the zone's own "keyset lag" retry, until the intent's not_after), then the core shows the
//     zone's reason on the generation (GET /v2/keysets, field drain.reason) and plans the drain again.
//
// Run the zone steps first (docs/runbooks/key-replacement.md), then the same step here. The routes below only mirror a decision the operators already
// made in the zone; every one needs an admin with a fresh login, is human only and is audited (internal/partition writes the audit event in the same
// transaction as the change).

// DrainView is what the planner last found for a generation that is leaving.
type DrainView struct {
	State  string `json:"state"` // moving | waiting | drained
	Reason string `json:"reason,omitempty"`
}

// KeysetView is one generation as the admin API shows it.
type KeysetView struct {
	ShardID    string     `json:"shard_id"`
	Generation int        `json:"generation"`
	Address    string     `json:"address"`
	KeyRef     string     `json:"key_ref,omitempty"`
	State      string     `json:"state"`
	Successor  int        `json:"successor,omitempty"`
	Drain      *DrainView `json:"drain,omitempty"`
}

// keysetShard checks that shardID is a hot shard of this EVM chain and returns it.
func (s *Service) keysetShard(shardID string) (partition.ShardID, error) {
	c := s.Cfg
	if partition.ShardID(shardID).IsDepositTree() {
		if !s.isDepositTree(shardID) {
			return "", fmt.Errorf("%w: %s is not the deposit tree of chain %s", ErrNotFound, shardID, c.Chain)
		}
		return partition.ShardID(shardID), nil
	}
	if c.Family != FamilyEVM && c.Family != FamilySOL && c.Family != "" {
		return "", fmt.Errorf("%w: the hot shards of a %s chain are replaced with its deposit tree: name %s", ErrInvalid, c.Family, func() string { id, _ := c.depositTreeID(); return string(id) }())
	}
	id, err := partition.ParseShardID(shardID)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	for i := 0; i < c.shardCount(); i++ {
		if c.shardIDOf(i) == id {
			return id, nil
		}
	}
	return "", fmt.Errorf("%w: %s is not a hot shard of chain %s", ErrNotFound, shardID, c.Chain)
}

// ListKeysets lists every generation of every shard of this chain, with what the drain planner last found for the ones that are leaving.
func (s *Service) ListKeysets(ctx context.Context) ([]KeysetView, error) {
	var out []KeysetView
	if s.Cfg.Family == FamilyBTC || s.Cfg.Family == FamilySOL {
		id, err := s.Cfg.depositTreeID()
		if err != nil {
			return nil, err
		}
		ks, err := shardKeysets(ctx, s.Pool, id)
		if err != nil {
			return nil, err
		}
		for _, k := range ks {
			v := KeysetView{ShardID: string(k.ShardID), Generation: k.Generation, Address: k.Address, KeyRef: k.KeyRef, State: k.State, Successor: k.Successor}
			if v.Drain, err = s.treeDrainView(ctx, k.Generation); err != nil {
				return nil, err
			}
			out = append(out, v)
		}
	}
	for i := 0; i < s.Cfg.shardCount(); i++ {
		ks, err := shardKeysets(ctx, s.Pool, s.Cfg.shardIDOf(i))
		if err != nil {
			return nil, err
		}
		for _, k := range ks {
			v := KeysetView{ShardID: string(k.ShardID), Generation: k.Generation, Address: k.Address, KeyRef: k.KeyRef, State: k.State, Successor: k.Successor}
			var d DrainView
			err := s.Pool.QueryRow(ctx, `SELECT state, reason FROM keyset_drains WHERE shard_id=$1 AND generation=$2`, string(k.ShardID), k.Generation).Scan(&d.State, &d.Reason)
			switch {
			case err == nil:
				v.Drain = &d
			case !errors.Is(err, pgx.ErrNoRows):
				return nil, err
			}
			out = append(out, v)
		}
	}
	return out, nil
}

// RegisterKeysetCandidate records the next generation of a shard as a candidate (it signs nothing and receives nothing). The address must be new to
// this deployment: no generation, hot shard, cold address or contract it knows.
func (s *Service) RegisterKeysetCandidate(ctx context.Context, shardID, address, keyRef string) (KeysetInfo, error) {
	shard, err := s.keysetShard(shardID)
	if err != nil {
		return KeysetInfo{}, err
	}
	if s.isDepositTree(shardID) {
		return s.registerTreeCandidate(ctx, shard, address, keyRef)
	}
	var canon string
	if s.Cfg.Family == FamilySOL {
		raw, err := sol.ParseAddress(address)
		if err != nil || raw == ([32]byte{}) {
			return KeysetInfo{}, fmt.Errorf("%w: address %q is not a Solana address", ErrInvalid, address)
		}
		canon = sol.Address(raw)
		if err := s.solAddressIsNew(ctx, canon); err != nil {
			return KeysetInfo{}, err
		}
	} else {
		if !common.IsHexAddress(address) || common.HexToAddress(address) == (common.Address{}) {
			return KeysetInfo{}, fmt.Errorf("%w: address %q is not an EVM address", ErrInvalid, address)
		}
		addr := common.HexToAddress(address)
		if err := s.addressIsNew(ctx, addr); err != nil {
			return KeysetInfo{}, err
		}
		canon = addr.Hex()
	}
	var out KeysetInfo
	err = InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		// One candidate at a time: a second one would leave two unproven keys waiting.
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM keysets WHERE shard_id=$1 AND state='candidate'`, string(shard)).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return fmt.Errorf("%w: %s already has a candidate generation", partition.ErrIllegalTransition, shard)
		}
		k, err := partition.RegisterCandidate(ctx, tx, actorOf(ctx), shard, canon, keyRef, nil)
		out = KeysetInfo{Keyset: k}
		return err
	})
	return out, err
}

// solAddressIsNew refuses a Solana address that is already one of ours: a hot shard's key of any generation, or a pool's cold address.
func (s *Service) solAddressIsNew(ctx context.Context, addr string) error {
	for _, h := range s.Cfg.SOLHot {
		if h == addr {
			return fmt.Errorf("%w: %s is a configured hot shard", ErrInvalid, addr)
		}
	}
	for pool, cold := range s.Cfg.SOL.ColdAddresses {
		if cold == addr {
			return fmt.Errorf("%w: %s is the cold address of pool %q", ErrInvalid, addr, pool)
		}
	}
	var n int
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM keysets WHERE address=$1`, addr).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return fmt.Errorf("%w: %s is already a generation of a shard", ErrInvalid, addr)
	}
	return nil
}

// addressIsNew refuses an address that is already one of ours.
func (s *Service) addressIsNew(ctx context.Context, addr common.Address) error {
	c := s.Cfg
	known := map[common.Address]string{c.EVM.Factory: "the factory"}
	for i, a := range c.HotShards {
		known[a] = fmt.Sprintf("hot shard %d", i)
	}
	for k, a := range c.EVM.ColdAddresses {
		known[a] = "the cold address " + k
	}
	for sym, a := range c.Assets {
		if !a.Native() {
			known[a.Address] = "the " + sym + " token"
		}
	}
	if what, ok := known[addr]; ok {
		return fmt.Errorf("%w: %s is %s", ErrInvalid, addr.Hex(), what)
	}
	var n int
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM keysets WHERE lower(address)=lower($1)`, addr.Hex()).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return fmt.Errorf("%w: %s is already the address of a generation", ErrInvalid, addr.Hex())
	}
	return nil
}

// ActivateKeyset makes a candidate the active generation of its shard. The previous one must already be draining or compromised (the registry allows
// one active generation per shard); between the two steps the shard has no active address and new work for it waits.
func (s *Service) ActivateKeyset(ctx context.Context, shardID string, gen int) (KeysetInfo, error) {
	shard, err := s.keysetShard(shardID)
	if err != nil {
		return KeysetInfo{}, err
	}
	var out KeysetInfo
	err = InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		k, err := partition.Activate(ctx, tx, actorOf(ctx), shard, gen)
		out = KeysetInfo{Keyset: k}
		return err
	})
	return out, err
}

// StartDrainingKeyset moves the active generation to draining and names the generation it empties into, which must be a candidate of the same shard
// (it is activated next) and must not itself be leaving. A generation that others still drain into cannot start draining.
func (s *Service) StartDrainingKeyset(ctx context.Context, shardID string, gen, successor int) (KeysetInfo, error) {
	shard, err := s.keysetShard(shardID)
	if err != nil {
		return KeysetInfo{}, err
	}
	var out KeysetInfo
	err = InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		if err := s.checkSuccessor(ctx, tx, shard, gen, successor, partition.StateCandidate); err != nil {
			return err
		}
		k, err := partition.StartDraining(ctx, tx, actorOf(ctx), shard, gen)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE keysets SET successor=$3 WHERE shard_id=$1 AND generation=$2`, string(shard), gen, successor); err != nil {
			return err
		}
		out = KeysetInfo{Keyset: k, Successor: successor}
		return nil
	})
	return out, err
}

// MarkKeysetCompromised flags a generation as compromised. It may name the successor in the same step (once; the generation then drains into it);
// without one, the generation holds the shard's money and has nowhere to drain until a later registration names one through the zone's record.
func (s *Service) MarkKeysetCompromised(ctx context.Context, shardID string, gen, successor int) (KeysetInfo, error) {
	shard, err := s.keysetShard(shardID)
	if err != nil {
		return KeysetInfo{}, err
	}
	var out KeysetInfo
	err = InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		if successor != 0 {
			if err := s.checkSuccessor(ctx, tx, shard, gen, successor, partition.StateCandidate, partition.StateActive); err != nil {
				return err
			}
		}
		k, err := partition.MarkCompromised(ctx, tx, actorOf(ctx), shard, gen)
		if err != nil {
			return err
		}
		out = KeysetInfo{Keyset: k}
		if successor != 0 {
			if _, err := tx.Exec(ctx, `UPDATE keysets SET successor=$3 WHERE shard_id=$1 AND generation=$2`, string(shard), gen, successor); err != nil {
				return err
			}
			out.Successor = successor
		}
		return nil
	})
	return out, err
}

// checkSuccessor: the successor is another generation of the shard, in one of the states, and not itself leaving; and nothing drains into gen.
func (s *Service) checkSuccessor(ctx context.Context, tx pgx.Tx, shard partition.ShardID, gen, successor int, states ...string) error {
	if successor == 0 || successor == gen {
		return fmt.Errorf("%w: name the successor generation (another generation of %s)", ErrInvalid, shard)
	}
	var st string
	err := tx.QueryRow(ctx, `SELECT state FROM keysets WHERE shard_id=$1 AND generation=$2 FOR UPDATE`, string(shard), successor).Scan(&st)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%w: %s generation %d", partition.ErrKeysetNotFound, shard, successor)
	}
	if err != nil {
		return err
	}
	ok := false
	for _, w := range states {
		ok = ok || st == w
	}
	if !ok {
		return fmt.Errorf("%w: successor generation %d of %s is %s, it must be %s", partition.ErrIllegalTransition, successor, shard, st, strings.Join(states, " or "))
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM keysets WHERE shard_id=$1 AND successor=$2 AND state IN ('draining','compromised')`, string(shard), gen).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return fmt.Errorf("%w: another generation of %s is still draining into generation %d", partition.ErrIllegalTransition, shard, gen)
	}
	return nil
}

// dustOf is the amount of asset at an old address that does not have to be moved: nothing of a token, and of the native asset what the last transfer's
// gas needs (the chain cell's figure, else the configured worst-case fee).
func (s *Service) dustOf(ctx context.Context, asset string) (*big.Int, error) {
	if asset != s.Cfg.Native {
		return new(big.Int), nil
	}
	if r, ok := s.Chain.(interface {
		NativeDrainReserve(ctx context.Context) (*big.Int, error)
	}); ok {
		return r.NativeDrainReserve(ctx)
	}
	return new(big.Int).Set(s.Cfg.NativeReserve()), nil
}

// RetireKeyset retires a draining generation after checking the chain: nothing above dust of any asset is left at its address, no transaction of it
// is in flight, and no drain is open. What is left of the native asset (below the dust line) is written off as a cost, so the shard's ledger account
// and the addresses still watched agree. A generation that is compromised is never retired: it stays in the watch list.
func (s *Service) RetireKeyset(ctx context.Context, shardID string, gen int) (KeysetInfo, error) {
	return s.RetireKeysetAfter(ctx, shardID, gen, 0)
}

// RetireKeysetAfter is RetireKeyset for a deposit tree with the window (seconds) its signed draining record names: the generation must have been draining
// that long. The signing zone enforces the same window from its own record; this is the core's check before it mirrors the retirement.
func (s *Service) RetireKeysetAfter(ctx context.Context, shardID string, gen int, windowSeconds int64) (KeysetInfo, error) {
	shard, err := s.keysetShard(shardID)
	if err != nil {
		return KeysetInfo{}, err
	}
	if s.isDepositTree(shardID) {
		return s.retireTree(ctx, shard, gen, windowSeconds)
	}
	var cur KeysetInfo
	if cur, err = scanKeysetInfo(s.Pool.QueryRow(ctx, `SELECT `+keysetInfoCols+` FROM keysets WHERE shard_id=$1 AND generation=$2`, string(shard), gen)); err != nil {
		if isNoRows(err) {
			return KeysetInfo{}, fmt.Errorf("%w: %s generation %d", partition.ErrKeysetNotFound, shard, gen)
		}
		return KeysetInfo{}, err
	}
	if cur.State != partition.StateDraining {
		return KeysetInfo{}, fmt.Errorf("%w: %s generation %d is %s, retire needs draining", partition.ErrIllegalTransition, shard, gen, cur.State)
	}
	left, err := s.balancesAt(ctx, cur.Address)
	if err != nil {
		return KeysetInfo{}, fmt.Errorf("%w: cannot read the balances of %s: %v", ErrNotDrained, cur.Address, err)
	}
	var written *big.Int
	for _, sym := range s.Cfg.AssetList {
		dust, err := s.dustOf(ctx, sym)
		if err != nil {
			return KeysetInfo{}, err
		}
		if left[sym].Cmp(dust) > 0 {
			return KeysetInfo{}, fmt.Errorf("%w: %s still holds %s %s", ErrNotDrained, cur.Address, left[sym], sym)
		}
		if sym == s.Cfg.Native {
			written = left[sym]
		}
	}
	var out KeysetInfo
	err = InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		var open int
		inflight := `SELECT count(*) FROM evm_nonce_allocations WHERE chain=$1 AND lower(address)=lower($2) AND status IN ('allocated','broadcast')`
		if s.Cfg.Family == FamilySOL {
			inflight = `SELECT count(*) FROM sol_nonce_allocations WHERE chain=$1 AND hot_address=$2 AND status IN ('allocated','broadcast')`
		}
		if err := tx.QueryRow(ctx, `SELECT (`+inflight+`)
			+ (SELECT count(*) FROM drain_moves WHERE shard_id=$3 AND from_generation=$4 AND status NOT IN ('confirmed','failed'))`,
			s.Cfg.Chain, cur.Address, string(shard), gen).Scan(&open); err != nil {
			return err
		}
		if open > 0 {
			return fmt.Errorf("%w: %d transactions of %s are still in flight", ErrNotDrained, open, cur.Address)
		}
		k, err := partition.Retire(ctx, tx, actorOf(ctx), shard, gen)
		if err != nil {
			return err
		}
		out = KeysetInfo{Keyset: k, Successor: cur.Successor}
		if written != nil && written.Sign() > 0 {
			if _, err := tx.Exec(ctx, `UPDATE keysets SET dust_written_off=$3::numeric WHERE shard_id=$1 AND generation=$2`, string(shard), gen, written.String()); err != nil {
				return err
			}
			nativePart := s.Cfg.PartitionKey(s.Cfg.Native, shard.Shard()).String()
			return s.transfer(ctx, tx, fmt.Sprintf("retire-dust:%s#%d", shard, gen), feeAcct(s.Cfg.Chain, s.Cfg.Native), hotAcct(nativePart), written,
				map[string]any{"kind": "retire_dust", "shard": string(shard), "generation": gen, "address": cur.Address})
		}
		return nil
	})
	return out, err
}

// ErrNotDrained: the generation still holds money or work, so it is not retired.
var ErrNotDrained = errors.New("custody: the generation is not drained")

// balancesAt reads the balance of every configured asset at an address at the safe height.
func (s *Service) balancesAt(ctx context.Context, addr string) (map[string]*big.Int, error) {
	if s.Reader == nil {
		return nil, errors.New("no chain reader")
	}
	h, err := s.Reader.SafeHead(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]*big.Int{}
	for _, sym := range s.Cfg.AssetList {
		b, err := s.Reader.Balance(ctx, addr, sym, h)
		if err != nil {
			if errors.Is(err, chain.ErrNotSupported) {
				return nil, errors.New("this chain cell cannot read balances")
			}
			return nil, err
		}
		out[sym] = b
	}
	return out, nil
}

// ---- HTTP ----

func keysetStatus(err error) (int, bool) {
	switch {
	case errors.Is(err, partition.ErrKeysetNotFound):
		return http.StatusNotFound, true
	case errors.Is(err, partition.ErrIllegalTransition), errors.Is(err, partition.ErrActiveExists), errors.Is(err, ErrNotDrained):
		return http.StatusConflict, true
	}
	return 0, false
}

func (a *API) keysetFail(w http.ResponseWriter, err error) {
	if code, ok := keysetStatus(err); ok {
		writeJSON(w, code, map[string]string{"error": err.Error()})
		return
	}
	a.fail(w, err)
}

func keysetBody(k KeysetInfo) KeysetView {
	return KeysetView{ShardID: string(k.ShardID), Generation: k.Generation, Address: k.Address, KeyRef: k.KeyRef, State: k.State, Successor: k.Successor}
}

func (a *API) listKeysets(w http.ResponseWriter, r *http.Request) {
	out, err := a.svc.ListKeysets(r.Context())
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"keysets": out})
}

func (a *API) registerKeysetCandidate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ShardID string `json:"shard_id"`
		Address string `json:"address"`
		KeyRef  string `json:"key_ref"`
	}
	if err := decode(r, &body); err != nil {
		a.fail(w, err)
		return
	}
	k, err := a.svc.RegisterKeysetCandidate(r.Context(), body.ShardID, body.Address, body.KeyRef)
	if err != nil {
		a.keysetFail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, keysetBody(k))
}

type keysetRef struct {
	ShardID    string `json:"shard_id"`
	Generation int    `json:"generation"`
	Successor  int    `json:"successor"`
	// WindowSeconds (retire of a deposit tree): the window of the signed draining record.
	WindowSeconds int64 `json:"window_seconds,omitempty"`
}

func (a *API) activateKeyset(w http.ResponseWriter, r *http.Request) {
	var body keysetRef
	if err := decode(r, &body); err != nil {
		a.fail(w, err)
		return
	}
	k, err := a.svc.ActivateKeyset(r.Context(), body.ShardID, body.Generation)
	if err != nil {
		a.keysetFail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, keysetBody(k))
}

func (a *API) startDrainingKeyset(w http.ResponseWriter, r *http.Request) {
	var body keysetRef
	if err := decode(r, &body); err != nil {
		a.fail(w, err)
		return
	}
	k, err := a.svc.StartDrainingKeyset(r.Context(), body.ShardID, body.Generation, body.Successor)
	if err != nil {
		a.keysetFail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, keysetBody(k))
}

func (a *API) retireKeyset(w http.ResponseWriter, r *http.Request) {
	var body keysetRef
	if err := decode(r, &body); err != nil {
		a.fail(w, err)
		return
	}
	k, err := a.svc.RetireKeysetAfter(r.Context(), body.ShardID, body.Generation, body.WindowSeconds)
	if err != nil {
		a.keysetFail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, keysetBody(k))
}

func (a *API) compromiseKeyset(w http.ResponseWriter, r *http.Request) {
	var body keysetRef
	if err := decode(r, &body); err != nil {
		a.fail(w, err)
		return
	}
	k, err := a.svc.MarkKeysetCompromised(r.Context(), body.ShardID, body.Generation, body.Successor)
	if err != nil {
		a.keysetFail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, keysetBody(k))
}
