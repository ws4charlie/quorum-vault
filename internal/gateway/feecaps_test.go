package gateway

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
)

// Signed fee caps in the zone (feecaps.go, internal/chain/btc/feecaps.go): the zone judges every transaction by the newest valid record of its guard
// database; a payload built under another record is refused with the note that raises an ALERT.

func feeCapsHarness(t *testing.T) *btcH {
	return newBTCHarnessWith(t, func(cf *ChainFile, b *btcH) {
		cf.BTC.FeeCapsChange = &FeeCapsChangeFile{MinFeeRate: 10, MaxFeeRate: 400, MinTxFeeSats: 10_000, MaxTxFeeSats: 200_000, MinApprovers: 2}
	})
}

func (b *btcH) feeChange(caps btc.FeeCaps, seq int64, at time.Time, actors ...string) btc.FeeCapsChange {
	b.t.Helper()
	var parts []btc.FeeCapsChange
	for _, a := range actors {
		parts = append(parts, btc.SignFeeCaps(b.keys[a], a, btcChain, caps, seq, at))
	}
	c, err := btc.MergeFeeCaps(parts...)
	if err != nil {
		b.t.Fatal(err)
	}
	return c
}

// A payload that pays 50,000 sats over about 210 vbytes (about 240 sat/vB) with a big change: over the zone's rate cap of 170, under a raised one.
func (b *btcH) dearPayload(seq int64) btc.Payload {
	p := b.twoInputs(150_000, 150_000, b.other, 150_000)
	p.FeeCapsSeq = seq
	return p
}

func TestFeeCapsSignedChangeAppliesToTheNextDecision(t *testing.T) {
	b := feeCapsHarness(t)
	ctx, now := context.Background(), time.Now()
	raised := btc.FeeCaps{MaxTxFeeSats: 100_000, MaxFeeRate: 300}

	// Under the configured caps the transaction is above the rate cap.
	b.mustRefuse(b.jobs("w1", wdIntent("wi1", b.other, 100_000), b.dearPayload(0), "auto")[0], "tx_mismatch")

	if err := b.guard.ApplyFeeCaps(ctx, b.cfg, b.feeChange(raised, 1, now, "alice", "bob"), now, "gateway"); err != nil {
		t.Fatal(err)
	}
	// The core has not applied it yet (it still builds under change 0): the zone refuses, with the note.
	j := b.jobs("w2", wdIntent("wi2", b.other, 100_000), b.dearPayload(0), "auto")[0]
	if d := b.run(j); d.Reason == "" || !strings.Contains(d.Reason, btc.FeeCapsSeqNote) {
		t.Fatalf("a payload of another change: %s %q", d.Outcome, d.Reason)
	}
	// Built under change 1 it signs, and under the raised caps.
	b.mustSignAll(b.jobs("w3", wdIntent("wi3", b.other, 100_000), b.dearPayload(1), "auto"))

	var ev *auditRow
	for _, row := range b.auditRows() {
		if row.Type == btc.EventFeeCapsChanged {
			row := row
			ev = &row
		}
	}
	if ev == nil || ev.Actor != "gateway" || ev.Payload["seq"] != float64(1) {
		t.Fatalf("the audit event: %+v", ev)
	}
	if a, _ := json.Marshal(ev.Payload["approvers"]); string(a) != `["alice","bob"]` {
		t.Fatalf("the audit event must name who signed: %s", a)
	}
	// The change can be lowered again, and then the same transaction is refused again (at the next sequence number).
	if err := b.guard.ApplyFeeCaps(ctx, b.cfg, b.feeChange(btc.FeeCaps{MaxTxFeeSats: 50_000, MaxFeeRate: 170}, 2, now, "alice", "carol"), now, "gateway"); err != nil {
		t.Fatal(err)
	}
	b.mustRefuse(b.jobs("w4", wdIntent("wi4", b.other, 100_000), b.dearPayload(2), "auto")[0], "tx_mismatch")
}

// What the zone refuses to apply, and rows it never applied itself.
func TestFeeCapsChangeRefusals(t *testing.T) {
	b := feeCapsHarness(t)
	ctx, now := context.Background(), time.Now()
	raised := btc.FeeCaps{MaxTxFeeSats: 100_000, MaxFeeRate: 300}
	b.cfg.Approvers["bob"] = Approver{Key: b.cfg.Approvers["bob"].Key, Enabled: true, Identity: "alice"} // bob is alice under another key
	cur := func() btc.FeeCapsRecord {
		c, _, err := b.guard.CurrentFeeCaps(ctx, b.cfg, btcChain)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	for name, tc := range map[string]struct {
		c    btc.FeeCapsChange
		want string
	}{
		"unsigned":                 {btc.FeeCapsChange{Chain: btcChain, Caps: raised, Seq: 1, SignedAt: now.Unix()}, "0 valid signatures"},
		"too few approvers":        {b.feeChange(raised, 1, now, "carol"), "1 valid signatures"},
		"one person with two keys": {b.feeChange(raised, 1, now, "alice", "bob"), "1 valid signatures"},
		"a disabled approver":      {b.feeChange(raised, 1, now, "carol", "dave"), "1 valid signatures"},
		"stale":                    {b.feeChange(raised, 1, now.Add(-time.Hour), "alice", "carol"), "from now"},
		"above the ceiling":        {b.feeChange(btc.FeeCaps{MaxTxFeeSats: 200_000, MaxFeeRate: 401}, 1, now, "alice", "carol"), "outside the zone's bounds"},
		"below the floor":          {b.feeChange(btc.FeeCaps{MaxTxFeeSats: 9_000, MaxFeeRate: 20}, 1, now, "alice", "carol"), "outside the zone's bounds"},
		"breaks the start-up rule": {b.feeChange(btc.FeeCaps{MaxTxFeeSats: 20_000, MaxFeeRate: 300}, 1, now, "alice", "carol"), "is below max_fee_rate"},
	} {
		if err := b.guard.ApplyFeeCaps(ctx, b.cfg, tc.c, now, "gateway"); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
	if c := cur(); c.Seq != 0 {
		t.Fatalf("a refused change was applied: %+v", c)
	}
	if err := b.guard.ApplyFeeCaps(ctx, b.cfg, b.feeChange(raised, 1, now, "alice", "carol"), now, "gateway"); err != nil {
		t.Fatal(err)
	}
	if err := b.guard.ApplyFeeCaps(ctx, b.cfg, b.feeChange(btc.FeeCaps{MaxTxFeeSats: 60_000, MaxFeeRate: 200}, 1, now, "alice", "carol"), now, "gateway"); err == nil || !strings.Contains(err.Error(), "not higher") {
		t.Fatalf("a replayed sequence number: %v", err)
	}
	// A row put straight into the table is ignored: the zone stays on change 1 and still refuses what change 1 refuses.
	if _, err := b.guardDB.Exec(ctx, `INSERT INTO btc_fee_cap_changes (chain, seq, max_tx_fee_sats, max_fee_rate, signed_at, signatures) VALUES ($1, 2, 200000, 400, $2, '[]')`, btcChain, now.Unix()); err != nil {
		t.Fatal(err)
	}
	if c := cur(); c.Seq != 1 || c.FeeCaps != raised {
		t.Fatalf("a forged row moved the zone: %+v", c)
	}
	// 80,000 sats over about 210 vbytes is above change 1's 300 sat/vB and under the forged row's 400.
	p := b.twoInputs(150_000, 150_000, b.other, 120_000)
	p.FeeCapsSeq = 1
	b.mustRefuse(b.jobs("w9", wdIntent("wi9", b.other, 100_000), p, "auto")[0], "tx_mismatch")
}

// A chain without a fee_caps_change section accepts no change at all.
func TestFeeCapsChangeOffByDefault(t *testing.T) {
	b := newBTCHarness(t)
	err := b.guard.ApplyFeeCaps(context.Background(), b.cfg, b.feeChange(btc.FeeCaps{MaxTxFeeSats: 60_000, MaxFeeRate: 200}, 1, time.Now(), "alice"), time.Now(), "gateway")
	if err == nil || !strings.Contains(err.Error(), "accepts no signed fee-cap changes") {
		t.Fatalf("%v", err)
	}
}

// The bounds must contain the configured caps, and each bound must be sane.
func TestFeeCapsChangeConfigIsChecked(t *testing.T) {
	b := newBTCHarness(t)
	good := b.gw.cfg.Chains[btcChain].BTC
	for name, fc := range map[string]*FeeCapsChangeFile{
		"caps above the ceiling": {MinFeeRate: 1, MaxFeeRate: 100, MinTxFeeSats: 1, MaxTxFeeSats: 50_000},
		"floor above ceiling":    {MinFeeRate: 300, MaxFeeRate: 200, MinTxFeeSats: 1, MaxTxFeeSats: 100_000},
		"no bounds":              {},
		"too many approvers":     {MinFeeRate: 1, MaxFeeRate: 200, MinTxFeeSats: 1, MaxTxFeeSats: 100_000, MinApprovers: 9},
	} {
		cf := ChainFile{Family: "btc", WithdrawalsPerHour: 10, BTC: &BTCFile{Network: "regtest", AccountXpub: good.AccountXpub, MaxTxFeeSats: 50_000, MaxFeeRate: 170, MaxInputs: 3,
			HotShards: map[string]HotShardFile{btcPartition: {Address: b.hot0, Path: []uint32{1, 0}}}, FeeCapsChange: fc},
			Assets: map[string]AssetFile{"BTC": {AnyDestination: true, PerTxCap: "100000000", DailyCap: "1000000000", Tiers: []TierFile{{"0", 1}}}}}
		if _, err := cf.build(btcChain, 4); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
