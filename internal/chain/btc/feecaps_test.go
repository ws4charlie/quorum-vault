package btc

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
)

// fcKeys are three approvers; alice and alice2 are the same person.
type fcKeys struct {
	priv map[string]ed25519.PrivateKey
	ap   map[string]FeeCapsApprover
}

func newFCKeys() fcKeys {
	k := fcKeys{priv: map[string]ed25519.PrivateKey{}, ap: map[string]FeeCapsApprover{}}
	for name, who := range map[string]string{"alice": "alice@x", "alice2": "alice@x", "bob": "bob@x"} {
		seed := sha256.Sum256([]byte("fee-caps-test-" + name))
		p := ed25519.NewKeyFromSeed(seed[:])
		k.priv[name] = p
		k.ap[name] = FeeCapsApprover{Key: p.Public().(ed25519.PublicKey), Identity: who}
	}
	return k
}

func (k fcKeys) sign(chainName string, caps FeeCaps, seq int64, at time.Time, actors ...string) FeeCapsChange {
	var parts []FeeCapsChange
	for _, a := range actors {
		parts = append(parts, SignFeeCaps(k.priv[a], a, chainName, caps, seq, at))
	}
	c, err := MergeFeeCaps(parts...)
	if err != nil {
		panic(err)
	}
	return c
}

var (
	fcStatic = FeeCaps{MaxTxFeeSats: 25_000, MaxFeeRate: 50}
	fcRaised = FeeCaps{MaxTxFeeSats: 50_000, MaxFeeRate: 100}
	fcBounds = FeeCapsBounds{MinFeeRate: 10, MaxFeeRate: 200, MinTxFeeSats: 5_000, MaxTxFeeSats: 100_000}
)

func (k fcKeys) rules(bounds *FeeCapsBounds) FeeCapsRules {
	return FeeCapsRules{Chain: "btc-t", Approvers: k.ap, MinApprovers: 2, MaxAge: 10 * time.Minute, Bounds: bounds, MaxInputs: 5, MaxPayments: 1}
}

// Every way a change can fail the rules, with no database: unsigned, too few approvers, one person twice, a stranger's key, the wrong chain, outside the
// ceiling or the floor, and a change below the start-up rule.
func TestFeeCapsChangeRules(t *testing.T) {
	k, now := newFCKeys(), time.Now()
	r := k.rules(&fcBounds)
	if who, err := r.Verify(k.sign("btc-t", fcRaised, 1, now, "alice", "bob")); err != nil || len(who) != 2 {
		t.Fatalf("a good change: %v %v", who, err)
	}
	stranger := SignFeeCaps(ed25519.NewKeyFromSeed(make([]byte, 32)), "alice", "btc-t", fcRaised, 1, now) // a name of the zone, another key
	for name, tc := range map[string]struct {
		c    FeeCapsChange
		want string
	}{
		"unsigned":        {FeeCapsChange{Chain: "btc-t", Caps: fcRaised, Seq: 1, SignedAt: now.Unix()}, "0 valid signatures"},
		"one approver":    {k.sign("btc-t", fcRaised, 1, now, "bob"), "1 valid signatures"},
		"same person":     {k.sign("btc-t", fcRaised, 1, now, "alice", "alice2"), "1 valid signatures"},
		"same name twice": {k.sign("btc-t", fcRaised, 1, now, "alice", "alice"), "1 valid signatures"},
		"wrong key":       {stranger, "0 valid signatures"},
		"wrong chain":     {k.sign("btc-x", fcRaised, 1, now, "alice", "bob"), "for chain"},
		"above ceiling":   {k.sign("btc-t", FeeCaps{MaxTxFeeSats: 100_000, MaxFeeRate: 201}, 1, now, "alice", "bob"), "outside the zone's bounds"},
		"below floor":     {k.sign("btc-t", FeeCaps{MaxTxFeeSats: 4_000, MaxFeeRate: 5}, 1, now, "alice", "bob"), "outside the zone's bounds"},
		// 100 sat/vB x about 425 vbytes is 42,500: a cap of 30,000 cannot reach the rate ceiling for the largest transaction.
		"breaks the start-up rule": {k.sign("btc-t", FeeCaps{MaxTxFeeSats: 30_000, MaxFeeRate: 100}, 1, now, "alice", "bob"), "is below max_fee_rate"},
		"seq zero":                 {k.sign("btc-t", fcRaised, 0, now, "alice", "bob"), "sequence number of at least 1"},
	} {
		if _, err := r.Verify(tc.c); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
	// A signature over other caps does not count for these.
	c := k.sign("btc-t", fcRaised, 1, now, "alice", "bob")
	c.Caps.MaxFeeRate = 150
	if _, err := r.Verify(c); err == nil {
		t.Error("a change whose caps were altered after signing was accepted")
	}
}

// The record of a database: a change is applied with its audit row (who signed), the same change twice is a no-op, and a stale time, a replayed or lower
// sequence number, a change outside the bounds or below the start-up rule, and a row inserted straight into the table all change nothing.
func TestApplyFeeCaps(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.New(t)
	k, now := newFCKeys(), time.Now()
	r := k.rules(&fcBounds)
	apply := func(c FeeCapsChange, at time.Time) error { return ApplyFeeCaps(ctx, pool, r, fcStatic, c, at, "core") }
	cur := func() FeeCapsRecord {
		c, _, err := CurrentFeeCaps(ctx, pool, r, fcStatic)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	if c := cur(); c.Seq != 0 || c.FeeCaps != fcStatic {
		t.Fatalf("before any change: %+v", c)
	}
	if err := apply(k.sign("btc-t", fcRaised, 1, now, "alice", "bob"), now); err != nil {
		t.Fatal(err)
	}
	if c := cur(); c.Seq != 1 || c.FeeCaps != fcRaised || strings.Join(c.Signers, ",") != "alice,bob" {
		t.Fatalf("after change 1: %+v", c)
	}
	var who string
	if err := pool.QueryRow(ctx, `SELECT payload->>'approvers' FROM audit_log WHERE type = $1`, EventFeeCapsChanged).Scan(&who); err != nil || who != `["alice", "bob"]` {
		t.Fatalf("the audit row says who signed: %q %v", who, err)
	}
	if err := apply(k.sign("btc-t", fcRaised, 1, now, "alice", "bob"), now); err != nil {
		t.Fatalf("the same change again: %v", err)
	}
	for name, tc := range map[string]struct {
		c    FeeCapsChange
		at   time.Time
		want string
	}{
		"replayed seq":      {k.sign("btc-t", FeeCaps{MaxTxFeeSats: 30_000, MaxFeeRate: 50}, 1, now, "alice", "bob"), now, "not higher"},
		"lower seq":         {k.sign("btc-t", fcStatic, 0+1, now, "alice", "bob"), now, "not higher"},
		"stale":             {k.sign("btc-t", fcStatic, 2, now.Add(-11*time.Minute), "alice", "bob"), now, "from now"},
		"from the future":   {k.sign("btc-t", fcStatic, 2, now.Add(11*time.Minute), "alice", "bob"), now, "from now"},
		"one person twice":  {k.sign("btc-t", fcStatic, 2, now, "alice", "alice2"), now, "valid signatures"},
		"above the ceiling": {k.sign("btc-t", FeeCaps{MaxTxFeeSats: 100_000, MaxFeeRate: 300}, 2, now, "alice", "bob"), now, "outside the zone's bounds"},
		"breaks start-up":   {k.sign("btc-t", FeeCaps{MaxTxFeeSats: 30_000, MaxFeeRate: 100}, 2, now, "alice", "bob"), now, "is below max_fee_rate"},
	} {
		if err := apply(tc.c, tc.at); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
	if c := cur(); c.Seq != 1 || c.FeeCaps != fcRaised {
		t.Fatalf("refused changes changed the record: %+v", c)
	}
	// A row put straight into the table: unsigned, or signed by too few, is skipped and counted; the valid one under it stays in force.
	for seq, sigs := range map[int]string{2: `[]`, 3: `[{"actor":"alice","signature":"00"}]`} {
		if _, err := pool.Exec(ctx, `INSERT INTO btc_fee_cap_changes (chain, seq, max_tx_fee_sats, max_fee_rate, signed_at, signatures) VALUES ('btc-t', $1, 99999, 199, $2, $3::jsonb)`, seq, now.Unix(), sigs); err != nil {
			t.Fatal(err)
		}
	}
	c, skipped, err := CurrentFeeCaps(ctx, pool, r, fcStatic)
	if err != nil || c.Seq != 1 || c.FeeCaps != fcRaised || skipped != 2 {
		t.Fatalf("rows inserted straight into the table: %+v skipped %d %v", c, skipped, err)
	}
	// The table is append-only.
	if _, err := pool.Exec(ctx, `UPDATE btc_fee_cap_changes SET max_fee_rate = 1`); err == nil {
		t.Fatal("a row was updated")
	}
	if _, err := pool.Exec(ctx, `DELETE FROM btc_fee_cap_changes`); err == nil {
		t.Fatal("a row was deleted")
	}
}

// The core builds under the signed record: the next withdrawal uses the new caps and carries its sequence number, a transaction built before is
// unchanged, and raising the rate cap lets a send that stopped at the old cap be bumped further.
func TestCoreBuildsUnderSignedFeeCaps(t *testing.T) {
	k, now := newFCKeys(), time.Now()
	e := newWEnvWith(t, func(c *Config) {
		c.FeeCaps = &FeeCapsConfig{Approvers: k.ap, MinApprovers: 2}
	})
	ctx := context.Background()
	e.fund(2_000_000)
	orig, _ := e.broadcastOne("w1", 40_000)
	var firstSeq *string
	e.a.pool.QueryRow(ctx, `SELECT payload->>'fee_caps_seq' FROM btc_attempts WHERE chain='btc-t' AND txid=$1`, orig).Scan(&firstSeq)
	if firstSeq != nil {
		t.Fatalf("before any change the payload carries sequence %s", *firstSeq)
	}
	// Raise the fee until the send stops at the old rate cap (50 sat/vB).
	var stopped bool
	for i := 0; i < 60 && !stopped; i++ {
		u, err := e.replace()
		if errors.Is(err, chain.ErrCannotBump) {
			stopped = true
			break
		} else if err != nil {
			t.Fatal(err)
		}
		st, err := e.a.Assemble(u, e.sign(u))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.a.Broadcast(ctx, st); err != nil {
			t.Fatal(err)
		}
	}
	if !stopped {
		t.Fatal("the send was never stopped by the cap")
	}
	var atCap int64
	e.a.pool.QueryRow(ctx, `SELECT max(fee) FROM btc_attempts WHERE chain='btc-t'`).Scan(&atCap)

	rules := k.rules(nil)
	rules.MinApprovers = 2
	if err := ApplyFeeCaps(ctx, e.a.pool, rules, fcStatic, k.sign("btc-t", fcRaised, 1, now, "alice", "bob"), now, "core"); err != nil {
		t.Fatal(err)
	}
	u, err := e.replace()
	if err != nil {
		t.Fatalf("after the cap was raised the send can be bumped again: %v", err)
	}
	if p := e.payload(u); p.FeeCapsSeq != 1 {
		t.Fatalf("the replacement carries sequence %d, want 1", p.FeeCapsSeq)
	}
	if got, seq := e.a.FeeCapsNow(); seq != 1 || got != fcRaised {
		t.Fatalf("the core builds under %+v seq %d", got, seq)
	}
	var fee int64
	e.a.pool.QueryRow(ctx, `SELECT max(fee) FROM btc_attempts WHERE chain='btc-t'`).Scan(&fee)
	if fee <= atCap {
		t.Fatalf("the new attempt pays %d, not more than the old cap's %d", fee, atCap)
	}
	// The attempt signed before the change is untouched.
	if e.fee(orig) == 0 || e.fee(orig) >= uint64(atCap) {
		t.Fatalf("the first attempt's fee changed: %d", e.fee(orig))
	}
	// A row inserted straight into the core's table does not move it.
	if _, err := e.a.pool.Exec(ctx, `INSERT INTO btc_fee_cap_changes (chain, seq, max_tx_fee_sats, max_fee_rate, signed_at, signatures) VALUES ('btc-t', 9, 99999, 199, $1, '[]')`, now.Unix()); err != nil {
		t.Fatal(err)
	}
	if err := e.a.refreshCaps(ctx); err != nil {
		t.Fatal(err)
	}
	if got, seq := e.a.FeeCapsNow(); seq != 1 || got != fcRaised {
		t.Fatalf("a forged row moved the core to %+v seq %d", got, seq)
	}
}

// The zone judges payloads by its own record: a payload built under another sequence number is refused with the note the gateway turns into an ALERT,
// and one built under the zone's own is accepted with the zone's caps.
func TestVerifierRefusesAnotherFeeCapSequence(t *testing.T) {
	e := newWEnv(t)
	e.fund(100_000)
	u, err := e.build("w1", 40_000, true)
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifier(SigningConfig{Chain: e.cfg.Chain, Network: "regtest", AccountXpub: e.cfg.AccountXpub,
		HotShards:    map[string]HotShard{wPart: {Address: e.hot, Path: []uint32{1, 0}}},
		MaxTxFeeSats: e.cfg.MaxTxFeeSats, MaxFeeRate: e.cfg.MaxFeeRate, MaxInputs: e.cfg.MaxInputs})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Parse(u); err != nil {
		t.Fatalf("same sequence (0): %v", err)
	}
	v.view = NewFeeCapsView(fcRaised, nil, nil, nil)
	v.view.live.Store(&feeCapsLive{FeeCaps: fcRaised, Seq: 1}) // the zone is on change 1, the core built under 0
	if _, err := v.Parse(u); err == nil || !strings.Contains(err.Error(), FeeCapsSeqNote) {
		t.Fatalf("a payload built under another sequence: %v", err)
	}
}

// A withdrawal built under change 0 that the zone refused for being on change 1 is undone (outputs free again, attempt forgotten) and built again
// under change 1, with the same outputs and the new sequence number. A broadcast attempt cannot be undone.
func TestUndoUnsentAndRebuildUnderTheNewChange(t *testing.T) {
	k, now := newFCKeys(), time.Now()
	e := newWEnvWith(t, func(c *Config) { c.FeeCaps = &FeeCapsConfig{Approvers: k.ap, MinApprovers: 2} })
	ctx := context.Background()
	e.fund(1_000_000)
	u0, err := e.build("w1", 40_000, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyFeeCaps(ctx, e.a.pool, k.rules(nil), fcStatic, k.sign("btc-t", fcRaised, 1, now, "alice", "bob"), now, "core"); err != nil {
		t.Fatal(err)
	}
	if err := e.commit(func(tx pgx.Tx) error { return e.a.UndoUnsent(ctx, tx, "withdrawal", "w1") }); err != nil {
		t.Fatal(err)
	}
	if e.count("reserved") != 0 || e.count("available") != 1 {
		t.Fatalf("after the undo: %d reserved, %d available", e.count("reserved"), e.count("available"))
	}
	u1, err := e.build("w1", 40_000, true)
	if err != nil {
		t.Fatal(err)
	}
	p0, p1 := e.payload(u0), e.payload(u1)
	if p0.FeeCapsSeq != 0 || p1.FeeCapsSeq != 1 || len(p1.Inputs) != len(p0.Inputs) || p1.Inputs[0].TxID != p0.Inputs[0].TxID {
		t.Fatalf("rebuilt payloads: seq %d then %d", p0.FeeCapsSeq, p1.FeeCapsSeq)
	}
	var n int
	e.a.pool.QueryRow(ctx, `SELECT count(*) FROM btc_attempts WHERE chain='btc-t' AND owner_id='w1'`).Scan(&n)
	if n != 1 {
		t.Fatalf("%d attempts of w1 after the rebuild", n)
	}
	// Once the transaction is handed to the node it cannot be undone.
	st, err := e.a.Assemble(u1, e.sign(u1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.a.Broadcast(ctx, st); err != nil {
		t.Fatal(err)
	}
	if err := e.commit(func(tx pgx.Tx) error { return e.a.UndoUnsent(ctx, tx, "withdrawal", "w1") }); err == nil {
		t.Fatal("a broadcast attempt was undone")
	}
}
