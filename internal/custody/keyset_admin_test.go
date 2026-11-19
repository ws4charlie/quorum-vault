package custody

import (
	"context"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/ws4charlie/quorum-vault/internal/auth/authtest"
	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/partition"
)

var gen2Addr = common.HexToAddress("0x00000000000000000000000000000000000000B2").Hex()

func shard0(s *Service) string { return string(s.Cfg.shardIDOf(0)) }

// replaceShard0 runs the business steps of a replacement of shard 0: candidate, start draining, activate.
func replaceShard0(t *testing.T, s *Service) {
	t.Helper()
	ctx := WithActor(context.Background(), "admin1")
	if _, err := s.RegisterKeysetCandidate(ctx, shard0(s), gen2Addr, "keyset-2"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartDrainingKeyset(ctx, shard0(s), 1, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ActivateKeyset(ctx, shard0(s), 2); err != nil {
		t.Fatal(err)
	}
}

func TestKeysetLifecycleAndAddressResolution(t *testing.T) {
	s, _ := newSvc(t)
	ctx := WithActor(context.Background(), "admin1")
	part := s.Cfg.PartitionKey(s.Cfg.Native, 0).String()
	usdt := s.Cfg.PartitionKey("USDT", 0).String()
	gen1 := s.Cfg.HotShards[0].Hex()

	// A candidate changes nothing: new work still goes to generation 1.
	k, err := s.RegisterKeysetCandidate(ctx, shard0(s), strings.ToLower(gen2Addr), "keyset-2")
	if err != nil || k.Generation != 2 || k.State != partition.StateCandidate || k.Address != gen2Addr {
		t.Fatalf("candidate: %+v %v", k, err)
	}
	if a, _, err := s.ShardAddressOf(part); err != nil || a != gen1 {
		t.Fatalf("with a candidate the shard still resolves to generation 1: %s %v", a, err)
	}
	// Refusals: a second candidate, a known address, a bad address, another chain's shard, a retire of an active generation.
	if _, err := s.RegisterKeysetCandidate(ctx, shard0(s), "0x00000000000000000000000000000000000000B3", ""); !errors.Is(err, partition.ErrIllegalTransition) {
		t.Errorf("second candidate: %v", err)
	}
	if _, err := s.RegisterKeysetCandidate(ctx, string(s.Cfg.shardIDOf(1)), s.Cfg.HotShards[0].Hex(), ""); !errors.Is(err, ErrInvalid) {
		t.Errorf("an address that is a hot shard: %v", err)
	}
	if _, err := s.RegisterKeysetCandidate(ctx, string(s.Cfg.shardIDOf(1)), gen2Addr, ""); !errors.Is(err, ErrInvalid) {
		t.Errorf("an address that is a generation already: %v", err)
	}
	if _, err := s.RegisterKeysetCandidate(ctx, shard0(s), "not an address", ""); !errors.Is(err, ErrInvalid) {
		t.Errorf("bad address: %v", err)
	}
	if _, err := s.RegisterKeysetCandidate(ctx, "other/chain/omnibus/0", gen2Addr, ""); err == nil {
		t.Errorf("a shard of another chain")
	}
	if _, err := s.RetireKeyset(ctx, shard0(s), 1); !errors.Is(err, partition.ErrIllegalTransition) {
		t.Errorf("retire of an active generation: %v", err)
	}
	// Activation needs the old generation out of the way first (one active per shard), and a successor must be a candidate.
	if _, err := s.ActivateKeyset(ctx, shard0(s), 2); !errors.Is(err, partition.ErrActiveExists) {
		t.Errorf("activate beside an active generation: %v", err)
	}
	if _, err := s.StartDrainingKeyset(ctx, shard0(s), 1, 1); !errors.Is(err, ErrInvalid) {
		t.Errorf("a generation as its own successor: %v", err)
	}
	if _, err := s.StartDrainingKeyset(ctx, shard0(s), 1, 7); !errors.Is(err, partition.ErrKeysetNotFound) {
		t.Errorf("an unknown successor: %v", err)
	}

	d, err := s.StartDrainingKeyset(ctx, shard0(s), 1, 2)
	if err != nil || d.State != partition.StateDraining || d.Successor != 2 {
		t.Fatalf("start draining: %+v %v", d, err)
	}
	// Between the two steps the shard has no active address: new work waits, it does not fail.
	if _, _, err := s.ShardAddressOf(part); !errors.Is(err, ErrNoActiveKeyset) {
		t.Fatalf("no active generation: %v", err)
	}
	if _, err := s.ActivateKeyset(ctx, shard0(s), 2); err != nil {
		t.Fatal(err)
	}
	// Every asset of the shard, and the sweep destination (the sink shard is shard 0), resolve to the active generation.
	for _, p := range []string{part, usdt} {
		if a, idx, err := s.ShardAddressOf(p); err != nil || a != gen2Addr || idx != 0 {
			t.Errorf("ShardAddressOf(%s) = %s %d %v, want generation 2", p, a, idx, err)
		}
	}
	if a, err := s.sweepDestination(usdt); err != nil || a != gen2Addr {
		t.Errorf("sweep destination = %s %v, want the active address of the sink shard", a, err)
	}
	if a, _, _ := s.ShardAddressOf(s.Cfg.PartitionKey(s.Cfg.Native, 1).String()); a != s.Cfg.HotShards[1].Hex() {
		t.Errorf("another shard is untouched: %s", a)
	}
	// The one that others still drain into cannot start draining.
	if _, err := s.RegisterKeysetCandidate(ctx, shard0(s), "0x00000000000000000000000000000000000000B3", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartDrainingKeyset(ctx, shard0(s), 2, 3); !errors.Is(err, partition.ErrIllegalTransition) {
		t.Errorf("generation 2 starts draining while generation 1 still drains into it: %v", err)
	}

	list, err := s.ListKeysets(ctx)
	if err != nil || len(list) != 4 {
		t.Fatalf("list: %+v %v", list, err)
	}
	states := map[int]string{}
	for _, v := range list {
		if v.ShardID == shard0(s) {
			states[v.Generation] = v.State
		}
	}
	if states[1] != "draining" || states[2] != "active" || states[3] != "candidate" {
		t.Errorf("states: %v", states)
	}
	// Every change is in the audit trail with the actor.
	var n int
	s.Pool.QueryRow(context.Background(), `SELECT count(*) FROM outbox WHERE topic='qv.audit' AND payload->>'type' LIKE 'keyset.%' AND payload->>'actor'='admin1'`).Scan(&n)
	if n != 4 { // candidate 2, draining 1, activated 2, candidate 3
		t.Errorf("audit events by admin1: %d", n)
	}
}

func TestCompromisedKeysetNamesItsSuccessor(t *testing.T) {
	s, _ := newSvc(t)
	ctx := WithActor(context.Background(), "admin1")
	if _, err := s.RegisterKeysetCandidate(ctx, shard0(s), gen2Addr, ""); err != nil {
		t.Fatal(err)
	}
	k, err := s.MarkKeysetCompromised(ctx, shard0(s), 1, 2)
	if err != nil || k.State != partition.StateCompromised || k.Successor != 2 {
		t.Fatalf("%+v %v", k, err)
	}
	if _, err := s.ActivateKeyset(ctx, shard0(s), 2); err != nil {
		t.Fatalf("activate after the active generation was compromised: %v", err)
	}
	if _, err := s.RetireKeyset(ctx, shard0(s), 1); !errors.Is(err, partition.ErrIllegalTransition) {
		t.Errorf("a compromised generation is never retired: %v", err)
	}
	if _, err := s.MarkKeysetCompromised(ctx, shard0(s), 2, 0); err != nil {
		t.Errorf("an active generation may be compromised without naming a successor: %v", err)
	}
}

func TestKeysetRoutesAreAdminHumanStepUpAndAudited(t *testing.T) {
	s, _ := newSvc(t)
	is, h := apiWith(t, s, false)
	body := map[string]any{"shard_id": shard0(s), "address": gen2Addr, "key_ref": "k2"}
	routes := []string{"/v2/keysets/candidates", "/v2/keysets/activations", "/v2/keysets/drains", "/v2/keysets/retirements", "/v2/keysets/compromises"}
	for _, p := range routes {
		for name, spec := range map[string]authtest.Spec{
			"requester": {Sub: "r", Roles: []string{"requester"}},
			"approver":  {Sub: "a", Roles: []string{"approver"}},
			"operator":  {Sub: "o", Roles: []string{"operator"}},
		} {
			if w := do(h, "POST", p, tok(is, spec), body); w.Code != 403 {
				t.Errorf("%s as %s: %d", p, name, w.Code)
			}
		}
		if w := do(h, "POST", p, tok(is, authtest.Spec{Sub: "svc", Client: "qv-svc", Service: true, Roles: []string{"admin"}}), body); w.Code != 403 {
			t.Errorf("%s as a service: %d", p, w.Code)
		}
		if w := do(h, "POST", p, tok(is, authtest.Spec{Sub: "admin1", Roles: []string{"admin"}, AuthAge: time.Hour}), body); w.Code != 401 {
			t.Errorf("%s with a stale login: %d", p, w.Code)
		}
	}
	// Reading is for operators and admins.
	if w := do(h, "GET", "/v2/keysets", tok(is, authtest.Spec{Sub: "r", Roles: []string{"requester"}}), nil); w.Code != 403 {
		t.Errorf("GET as a requester: %d", w.Code)
	}
	// The full sequence through HTTP, by a fresh admin.
	admin := tok(is, authtest.Spec{Sub: "admin1", Roles: []string{"admin"}})
	step := func(path string, b map[string]any, want int) {
		t.Helper()
		if w := do(h, "POST", path, admin, b); w.Code != want {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body)
		}
	}
	step("/v2/keysets/candidates", body, 201)
	step("/v2/keysets/candidates", body, 400)                                                                                           // the same address again
	step("/v2/keysets/candidates", map[string]any{"shard_id": shard0(s), "address": "0x00000000000000000000000000000000000000B3"}, 409) // a second candidate
	step("/v2/keysets/drains", map[string]any{"shard_id": shard0(s), "generation": 1, "successor": 2}, 200)
	step("/v2/keysets/retirements", map[string]any{"shard_id": shard0(s), "generation": 2}, 409)
	step("/v2/keysets/activations", map[string]any{"shard_id": shard0(s), "generation": 2}, 200)
	step("/v2/keysets/activations", map[string]any{"shard_id": shard0(s), "generation": 9}, 404)
	step("/v2/keysets/activations", map[string]any{"shard_id": "x", "generation": 2}, 400)
	if w := do(h, "GET", "/v2/keysets", tok(is, authtest.Spec{Sub: "o", Roles: []string{"operator"}}), nil); w.Code != 200 || !strings.Contains(w.Body.String(), `"state":"draining"`) {
		t.Fatalf("GET: %d %s", w.Code, w.Body)
	}
	// Each write left a request row naming the route, and the changes carry the actor "admin1" (the token's sub).
	var n int
	s.Pool.QueryRow(context.Background(), `SELECT count(*) FROM outbox WHERE topic='qv.audit' AND payload->>'type'='api.write' AND payload->>'route' LIKE 'POST /v2/keysets/%'`).Scan(&n)
	if n < 7 {
		t.Errorf("api.write rows: %d", n)
	}
	s.Pool.QueryRow(context.Background(), `SELECT count(*) FROM outbox WHERE topic='qv.audit' AND payload->>'type' IN ('keyset.candidate','keyset.draining','keyset.activated') AND payload->>'actor'='admin1'`).Scan(&n)
	if n != 3 {
		t.Errorf("keyset audit events by admin1: %d", n)
	}
}

// Reconcile adds up the addresses of the shard's generations that are not retired against the one ledger account.
func TestReconcileSumsTheWatchListOverGenerations(t *testing.T) {
	ctx := context.Background()
	s, _, m := evmWorld(t)
	gen1 := s.Cfg.HotShards[0].Hex()
	requireClean(t, "one generation", mustReconcile(t, s))

	// A candidate holds gas the operator sent: the books know it (hot funding), so the sum holds.
	if _, err := s.RegisterKeysetCandidate(WithActor(ctx, "admin1"), shard0(s), gen2Addr, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.FundHot(ctx, "gas-for-gen2", 0, big.NewInt(500)); err != nil {
		t.Fatal(err)
	}
	m.add(gen2Addr, "ETH", 500)
	requireClean(t, "candidate funded", mustReconcile(t, s))

	if _, err := s.StartDrainingKeyset(WithActor(ctx, "admin1"), shard0(s), 1, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ActivateKeyset(WithActor(ctx, "admin1"), shard0(s), 2); err != nil {
		t.Fatal(err)
	}
	requireClean(t, "after activation", mustReconcile(t, s))

	// A drain moves money between two addresses of the shard: the books do not change and the sum does not either, at every point.
	m.add(gen1, "ETH", -3_000_000)
	m.add(gen2Addr, "ETH", 3_000_000)
	rep := mustReconcile(t, s)
	requireClean(t, "part drained", rep)
	var hot Check
	for _, c := range rep.Checks {
		if c.Name == "hot" && c.Asset == "ETH" && strings.EqualFold(c.Subject, gen2Addr) {
			hot = c
		}
	}
	if hot.Name == "" || !strings.Contains(hot.Detail, "generation 1") || !strings.Contains(hot.Detail, "generation 2") {
		t.Errorf("the check of a shard with two generations names both addresses: %+v", hot)
	}

	// Something that arrives at the draining address and is not in the books is a difference, and the report says whose address it is.
	m.add(gen1, "ETH", 42)
	rep = mustReconcile(t, s)
	if rep.Clean {
		t.Fatal("an arrival the books do not know must be reported")
	}
	f := rep.Failures()
	if len(f) != 1 || f[0].Name != "hot" || !strings.Contains(f[0].Detail, "generation 1") {
		t.Fatalf("failures: %+v", f)
	}
	m.add(gen1, "ETH", -42)

	// Drain the rest; retire writes off the dust left for the last transfer's gas and the report is clean again with generation 1 not watched.
	m.mu.Lock()
	rest := new(big.Int).Sub(m.bal[key(gen1, "ETH")], big.NewInt(10)) // 10 wei stay: below the dust line
	m.bal[key(gen1, "ETH")] = big.NewInt(10)
	m.bal[key(gen2Addr, "ETH")].Add(m.bal[key(gen2Addr, "ETH")], rest)
	m.mu.Unlock()
	requireClean(t, "drained", mustReconcile(t, s))
	if _, err := s.RetireKeyset(WithActor(ctx, "admin1"), shard0(s), 1); err != nil {
		t.Fatal(err)
	}
	requireClean(t, "retired, dust written off", mustReconcile(t, s))
	// A late arrival at the retired address is shown, with the reason, as a difference.
	m.add(gen1, "ETH", 5)
	rep = mustReconcile(t, s)
	f = rep.Failures()
	if len(f) != 1 || f[0].Name != "hot_retired" || !strings.Contains(f[0].Detail, "late arrival") {
		t.Fatalf("a late arrival at a retired address: %+v", f)
	}
}

func TestRetireRefusesWhileMoneyOrWorkIsLeft(t *testing.T) {
	ctx := WithActor(context.Background(), "admin1")
	s, _, m := evmWorld(t)
	gen1 := s.Cfg.HotShards[0].Hex()
	replaceShard0(t, s)
	if _, err := s.RetireKeyset(ctx, shard0(s), 1); !errors.Is(err, ErrNotDrained) {
		t.Fatalf("retire with 10 ETH at the address: %v", err)
	}
	m.mu.Lock()
	m.bal[key(gen1, "ETH")] = new(big.Int)
	m.mu.Unlock()
	m.add(gen1, "USDT", 1)
	if _, err := s.RetireKeyset(ctx, shard0(s), 1); !errors.Is(err, ErrNotDrained) {
		t.Fatalf("retire with a token left: %v", err)
	}
	m.add(gen1, "USDT", -1)
	attempt(t, s, gen1, "withdrawal", "w-old", "0xold", "send", 0)
	if _, err := s.RetireKeyset(ctx, shard0(s), 1); !errors.Is(err, ErrNotDrained) {
		t.Fatalf("retire with a transaction in flight: %v", err)
	}
	if _, err := s.Pool.Exec(context.Background(), `UPDATE evm_nonce_allocations SET status='confirmed'`); err != nil {
		t.Fatal(err)
	}
	m.noBalance = true
	if _, err := s.RetireKeyset(ctx, shard0(s), 1); !errors.Is(err, ErrNotDrained) {
		t.Fatalf("retire when balances cannot be read: %v", err)
	}
	m.noBalance = false
	if k, err := s.RetireKeyset(ctx, shard0(s), 1); err != nil || k.State != partition.StateRetired {
		t.Fatalf("retire when empty: %+v %v", k, err)
	}
}

// While a shard's old key drains into the active one, work waits for the active address to hold what it needs, with the reason; it is not failed.
func TestWorkWaitsForTheFundedSuccessor(t *testing.T) {
	ctx := context.Background()
	s, _, m := evmWorld(t)
	part := s.Cfg.PartitionKey("ETH", 0).String()
	// one generation: no check at all
	if err := s.checkActiveFunded(ctx, s.Pool, part, "ETH", big.NewInt(1)); err != nil {
		t.Fatal(err)
	}
	replaceShard0(t, s)
	err := s.checkActiveFunded(ctx, s.Pool, part, "ETH", big.NewInt(1000))
	if !errors.Is(err, ErrSuccessorUnfunded) || !errors.Is(err, chain.ErrNotEnoughOutputs) || !strings.Contains(err.Error(), "generation 2") {
		t.Fatalf("an unfunded successor: %v", err)
	}
	m.add(gen2Addr, "ETH", 1000)
	if err := s.checkActiveFunded(ctx, s.Pool, part, "ETH", big.NewInt(1000)); err != nil {
		t.Fatalf("funded for a native transfer: %v", err)
	}
	// A token transfer needs the token and native gas.
	usdt := s.Cfg.PartitionKey("USDT", 0).String()
	m.add(gen2Addr, "USDT", 50)
	if err := s.checkActiveFunded(ctx, s.Pool, usdt, "USDT", big.NewInt(50)); !errors.Is(err, ErrSuccessorUnfunded) {
		t.Fatalf("a token transfer without gas: %v", err)
	}
	m.add(gen2Addr, "ETH", s.Cfg.NativeReserve().Int64())
	if err := s.checkActiveFunded(ctx, s.Pool, usdt, "USDT", big.NewInt(50)); err != nil {
		t.Fatalf("a token transfer with gas: %v", err)
	}
	// Another shard is not affected.
	if err := s.checkActiveFunded(ctx, s.Pool, s.Cfg.PartitionKey("ETH", 1).String(), "ETH", big.NewInt(1)); err != nil {
		t.Fatal(err)
	}
	// Planners leave a shard alone that is still draining: no rebalance from it and no move to cold.
	leaving, err := shardLeaving(ctx, s.Pool, s.Cfg.shardIDOf(0))
	if err != nil || !leaving {
		t.Fatalf("leaving: %v %v", leaving, err)
	}
	if _, err := s.Pool.Exec(ctx, `INSERT INTO keyset_drains (shard_id, generation, state) VALUES ($1, 1, 'drained')`, shard0(s)); err != nil {
		t.Fatal(err)
	}
	if leaving, _ = shardLeaving(ctx, s.Pool, s.Cfg.shardIDOf(0)); leaving {
		t.Fatal("a drained generation no longer holds the shard back")
	}
}
