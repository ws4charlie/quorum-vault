package policy_test

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ws4charlie/quorum-vault/internal/audit"
	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
	"github.com/ws4charlie/quorum-vault/internal/domain"
	"github.com/ws4charlie/quorum-vault/internal/policy"
)

var now = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

const (
	dest  = "0x1111111111111111111111111111111111111111"
	other = "0x2222222222222222222222222222222222222222"
)

type fixture struct {
	pool  *pgxpool.Pool
	eng   *policy.Engine
	log   *audit.Log
	w     domain.Wallet
	keyID string
}

// newFixture creates a wallet of the given tier with a key, allowlists dest and
// sets the base policy: per-tx 50, threshold 20, daily 100, velocity 3 per 600s.
func newFixture(t *testing.T, tier domain.Tier) *fixture {
	t.Helper()
	pool := dbtest.New(t)
	ctx := context.Background()
	f := &fixture{pool: pool, log: audit.New(pool)}
	f.eng = policy.New(pool, f.log, func() time.Time { return now })
	f.w = domain.Wallet{Name: "w-" + string(tier), Tier: tier, Backend: domain.BackendHSM}
	if err := pool.QueryRow(ctx, `INSERT INTO wallets (name, tier, backend) VALUES ($1, $2, 'hsm') RETURNING id::text`,
		f.w.Name, tier).Scan(&f.w.ID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO keys (wallet_id, version, curve, backend, state, public_key, address)
		VALUES ($1, 1, 'secp256k1', 'hsm', 'active', '\x04', '0x0') RETURNING id::text`, f.w.ID).Scan(&f.keyID); err != nil {
		t.Fatal(err)
	}
	if err := f.eng.AddAllowlist(ctx, "admin", f.w.ID, dest, "dest"); err != nil {
		t.Fatal(err)
	}
	if err := f.eng.SetPolicy(ctx, "admin", basePolicy(f.w.ID)); err != nil {
		t.Fatal(err)
	}
	return f
}

func basePolicy(walletID string) domain.Policy {
	return domain.Policy{
		WalletID: walletID, PerTxLimitWei: big.NewInt(50), ApprovalThresholdWei: big.NewInt(20),
		DailyLimitWei: big.NewInt(100), VelocityMaxTx: 3, VelocityWindowSeconds: 600,
	}
}

// history inserts a past sign_request created at createdAt.
func (f *fixture) history(t *testing.T, value int64, status domain.RequestStatus, createdAt time.Time) string {
	t.Helper()
	var id string
	if err := f.pool.QueryRow(context.Background(), `INSERT INTO sign_requests (wallet_id, key_id, chain_id, to_address,
		value_wei, nonce, gas_limit, max_fee_per_gas, max_priority_fee_per_gas, requester, status, created_at)
		VALUES ($1, $2, 11155111, $3, $4, 0, 21000, 1, 1, 'alice', $5, $6) RETURNING id::text`,
		f.w.ID, f.keyID, dest, value, status, createdAt).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func (f *fixture) req(to string, value int64) domain.SignRequest {
	return domain.SignRequest{WalletID: f.w.ID, KeyID: f.keyID, To: to, ValueWei: big.NewInt(value), Requester: "alice"}
}

func (f *fixture) eval(t *testing.T, r domain.SignRequest) domain.Decision {
	t.Helper()
	d, err := f.eng.Evaluate(context.Background(), r, f.w)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	return d
}

func want(t *testing.T, d domain.Decision, outcome domain.Outcome, reasons ...string) {
	t.Helper()
	if reasons == nil {
		reasons = []string{}
	}
	if d.Outcome != outcome || !reflect.DeepEqual(d.Reasons, reasons) {
		t.Fatalf("decision = %s %q, want %s %q", d.Outcome, d.Reasons, outcome, reasons)
	}
}

func TestEvaluateRules(t *testing.T) {
	type hist struct {
		value  int64
		status domain.RequestStatus
		ago    time.Duration
	}
	cases := []struct {
		name    string
		tier    domain.Tier
		to      string
		value   int64
		history []hist
		outcome domain.Outcome
		reasons []string
	}{
		{name: "allow", to: dest, value: 10, outcome: domain.OutcomeAllow},
		{name: "allow uppercase destination", to: "0X1111111111111111111111111111111111111111", value: 10, outcome: domain.OutcomeAllow},
		{name: "deny not allowlisted", to: other, value: 10, outcome: domain.OutcomeDeny,
			reasons: []string{policy.ReasonNotAllowlisted}},
		{name: "deny per-tx limit", to: dest, value: 51, outcome: domain.OutcomeDeny,
			reasons: []string{policy.ReasonPerTxLimit}},
		{name: "per-tx limit is inclusive", to: dest, value: 50, outcome: domain.OutcomeNeedsApproval,
			reasons: []string{policy.ReasonApprovalThreshold}},
		{name: "deny velocity", to: dest, value: 1, outcome: domain.OutcomeDeny, reasons: []string{policy.ReasonVelocity},
			history: []hist{{1, domain.StatusSigned, time.Minute}, {1, domain.StatusFailed, 2 * time.Minute}, {1, domain.StatusRejected, 3 * time.Minute}}},
		{name: "velocity excludes denied", to: dest, value: 1, outcome: domain.OutcomeAllow,
			history: []hist{{1, domain.StatusSigned, time.Minute}, {1, domain.StatusSigned, 2 * time.Minute}, {1, domain.StatusDenied, 3 * time.Minute}}},
		{name: "velocity excludes requests outside window", to: dest, value: 1, outcome: domain.OutcomeAllow,
			history: []hist{{1, domain.StatusSigned, time.Minute}, {1, domain.StatusSigned, 2 * time.Minute}, {1, domain.StatusSigned, 601 * time.Second}}},
		{name: "deny reasons accumulate", to: other, value: 51, outcome: domain.OutcomeDeny,
			reasons: []string{policy.ReasonNotAllowlisted, policy.ReasonPerTxLimit, policy.ReasonVelocity},
			history: []hist{{1, domain.StatusSigned, time.Minute}, {1, domain.StatusSigned, 2 * time.Minute}, {1, domain.StatusSigned, 3 * time.Minute}}},
		{name: "hard deny wins over soft rules", tier: domain.TierCold, to: other, value: 30, outcome: domain.OutcomeDeny,
			reasons: []string{policy.ReasonNotAllowlisted}},
		{name: "needs approval over threshold", to: dest, value: 21, outcome: domain.OutcomeNeedsApproval,
			reasons: []string{policy.ReasonApprovalThreshold}},
		{name: "needs approval over daily limit", to: dest, value: 11, outcome: domain.OutcomeNeedsApproval,
			reasons: []string{policy.ReasonDailyLimit},
			history: []hist{{45, domain.StatusSigned, 2 * time.Hour}, {45, domain.StatusApproved, 3 * time.Hour}}},
		{name: "daily limit is inclusive", to: dest, value: 10, outcome: domain.OutcomeAllow,
			history: []hist{{45, domain.StatusSigned, 2 * time.Hour}, {45, domain.StatusSigned, 3 * time.Hour}}},
		{name: "spent counts pending_approval", to: dest, value: 10, outcome: domain.OutcomeNeedsApproval,
			reasons: []string{policy.ReasonDailyLimit},
			history: []hist{{91, domain.StatusPendingApproval, 2 * time.Hour}}},
		{name: "spent ignores denied rejected failed signing", to: dest, value: 10, outcome: domain.OutcomeAllow,
			history: []hist{{50, domain.StatusDenied, 2 * time.Hour}, {50, domain.StatusRejected, 2 * time.Hour},
				{50, domain.StatusFailed, 2 * time.Hour}, {50, domain.StatusSigning, 2 * time.Hour}}},
		{name: "daily window excludes now-24h-1s", to: dest, value: 10, outcome: domain.OutcomeAllow,
			history: []hist{{91, domain.StatusSigned, 24*time.Hour + time.Second}}},
		{name: "daily window includes now-23h59m", to: dest, value: 10, outcome: domain.OutcomeNeedsApproval,
			reasons: []string{policy.ReasonDailyLimit},
			history: []hist{{91, domain.StatusSigned, 23*time.Hour + 59*time.Minute}}},
		{name: "cold wallet tiny amount needs approval", tier: domain.TierCold, to: dest, value: 1,
			outcome: domain.OutcomeNeedsApproval, reasons: []string{policy.ReasonColdWallet}},
		{name: "soft reasons accumulate", tier: domain.TierCold, to: dest, value: 30, outcome: domain.OutcomeNeedsApproval,
			reasons: []string{policy.ReasonColdWallet, policy.ReasonApprovalThreshold, policy.ReasonDailyLimit},
			history: []hist{{80, domain.StatusSigned, time.Hour}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tier := tc.tier
			if tier == "" {
				tier = domain.TierHot
			}
			f := newFixture(t, tier)
			for _, h := range tc.history {
				f.history(t, h.value, h.status, now.Add(-h.ago))
			}
			want(t, f.eval(t, f.req(tc.to, tc.value)), tc.outcome, tc.reasons...)
		})
	}
}

func TestEvaluateExcludesRequestItself(t *testing.T) {
	f := newFixture(t, domain.TierHot)
	f.history(t, 1, domain.StatusSigned, now.Add(-time.Minute))
	f.history(t, 1, domain.StatusSigned, now.Add(-time.Minute))
	// The request under evaluation is already stored as pending_approval with a large value.
	id := f.history(t, 95, domain.StatusPendingApproval, now)
	r := f.req(dest, 15)
	r.ID = id
	want(t, f.eval(t, r), domain.OutcomeAllow)
}

func TestEvaluateNoPolicy(t *testing.T) {
	pool := dbtest.New(t)
	eng := policy.New(pool, audit.New(pool), func() time.Time { return now })
	var wid string
	if err := pool.QueryRow(context.Background(), `INSERT INTO wallets (name, tier, backend) VALUES ('np', 'hot', 'mpc') RETURNING id::text`).Scan(&wid); err != nil {
		t.Fatal(err)
	}
	d, err := eng.Evaluate(context.Background(), domain.SignRequest{WalletID: wid, To: dest, ValueWei: big.NewInt(1)},
		domain.Wallet{ID: wid, Tier: domain.TierHot})
	if err != nil {
		t.Fatal(err)
	}
	want(t, d, domain.OutcomeDeny, policy.ReasonNoPolicy)
}

func TestEvaluateCarriesRequiredApprovals(t *testing.T) {
	hot := newFixture(t, domain.TierHot)
	if d := hot.eval(t, hot.req(dest, 1)); d.RequiredApprovals != policy.DefaultApprovalsHot {
		t.Fatalf("hot default RequiredApprovals = %d", d.RequiredApprovals)
	}
	cold := newFixture(t, domain.TierCold)
	if d := cold.eval(t, cold.req(dest, 1)); d.RequiredApprovals != policy.DefaultApprovalsCold {
		t.Fatalf("cold default RequiredApprovals = %d", d.RequiredApprovals)
	}
	p := basePolicy(cold.w.ID)
	p.RequiredApprovals = 3
	if err := cold.eng.SetPolicy(context.Background(), "admin", p); err != nil {
		t.Fatal(err)
	}
	if d := cold.eval(t, cold.req(dest, 1)); d.RequiredApprovals != 3 {
		t.Fatalf("explicit RequiredApprovals = %d, want 3", d.RequiredApprovals)
	}
}

func TestEvaluateIsReadOnly(t *testing.T) {
	f := newFixture(t, domain.TierHot)
	ctx := context.Background()
	before, _ := f.log.List(ctx, audit.Filter{})
	f.eval(t, f.req(dest, 10))
	f.eval(t, f.req(other, 99))
	after, _ := f.log.List(ctx, audit.Filter{})
	var n int
	f.pool.QueryRow(ctx, `SELECT count(*) FROM sign_requests`).Scan(&n)
	if len(after) != len(before) || n != 0 {
		t.Fatalf("Evaluate wrote: audit %d -> %d, sign_requests %d", len(before), len(after), n)
	}
}

func TestEvaluateRejectsBadInput(t *testing.T) {
	f := newFixture(t, domain.TierHot)
	ctx := context.Background()
	if _, err := f.eng.Evaluate(ctx, domain.SignRequest{WalletID: f.w.ID, To: dest}, f.w); err == nil {
		t.Fatal("nil value accepted")
	}
	if _, err := f.eng.Evaluate(ctx, domain.SignRequest{WalletID: f.w.ID, To: dest, ValueWei: big.NewInt(-1)}, f.w); err == nil {
		t.Fatal("negative value accepted")
	}
	other := f.w
	other.ID = "00000000-0000-0000-0000-000000000000"
	if _, err := f.eng.Evaluate(ctx, f.req(dest, 1), other); err == nil {
		t.Fatal("wallet mismatch accepted")
	}
}

func TestEvaluateHugeValuesNoOverflow(t *testing.T) {
	f := newFixture(t, domain.TierHot)
	huge, _ := new(big.Int).SetString("1000000000000000000000000000000", 10) // 1e30 wei
	p := basePolicy(f.w.ID)
	p.PerTxLimitWei = huge
	p.ApprovalThresholdWei = huge
	p.DailyLimitWei = new(big.Int).Mul(huge, big.NewInt(2))
	if err := f.eng.SetPolicy(context.Background(), "admin", p); err != nil {
		t.Fatal(err)
	}
	f.history(t, 0, domain.StatusSigned, now.Add(-time.Hour)) // ensure sum path runs
	r := f.req(dest, 0)
	r.ValueWei = huge
	want(t, f.eval(t, r), domain.OutcomeAllow)
	r.ValueWei = new(big.Int).Add(huge, big.NewInt(1))
	want(t, f.eval(t, r), domain.OutcomeDeny, policy.ReasonPerTxLimit)
}

func TestSetPolicyUpsertAndAudit(t *testing.T) {
	f := newFixture(t, domain.TierHot)
	ctx := context.Background()
	p := basePolicy(f.w.ID)
	big1, _ := new(big.Int).SetString("123456789012345678901234567890", 10)
	p.DailyLimitWei = big1
	p.RequiredApprovals = 2
	if err := f.eng.SetPolicy(ctx, "bob", p); err != nil {
		t.Fatal(err)
	}
	got, err := f.eng.GetPolicy(ctx, f.w.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.DailyLimitWei.Cmp(big1) != 0 || got.RequiredApprovals != 2 || !got.UpdatedAt.Equal(now) {
		t.Fatalf("GetPolicy = %+v", got)
	}
	evs, _ := f.log.List(ctx, audit.Filter{WalletID: f.w.ID})
	last := evs[len(evs)-1]
	if last.Type != domain.EventPolicyUpdated || last.Actor != "bob" {
		t.Fatalf("last event = %+v", last)
	}
	var payload domain.Policy
	if err := json.Unmarshal(last.Payload, &payload); err != nil || payload.DailyLimitWei.Cmp(big1) != 0 {
		t.Fatalf("payload = %s (%v)", last.Payload, err)
	}
}

func TestSetPolicyValidation(t *testing.T) {
	f := newFixture(t, domain.TierHot)
	ctx := context.Background()
	bad := []func(*domain.Policy){
		func(p *domain.Policy) { p.DailyLimitWei = nil },
		func(p *domain.Policy) { p.PerTxLimitWei = big.NewInt(-1) },
		func(p *domain.Policy) { p.VelocityMaxTx = 0 },
		func(p *domain.Policy) { p.VelocityWindowSeconds = 0 },
	}
	for i, mutate := range bad {
		p := basePolicy(f.w.ID)
		mutate(&p)
		if err := f.eng.SetPolicy(ctx, "a", p); !errors.Is(err, policy.ErrInvalidPolicy) {
			t.Errorf("case %d: err = %v, want ErrInvalidPolicy", i, err)
		}
	}
	if err := f.eng.SetPolicy(ctx, "a", basePolicy("00000000-0000-0000-0000-000000000000")); !errors.Is(err, policy.ErrNotFound) {
		t.Errorf("unknown wallet: err = %v", err)
	}
	if _, err := f.eng.GetPolicy(ctx, "00000000-0000-0000-0000-000000000000"); !errors.Is(err, policy.ErrNotFound) {
		t.Errorf("GetPolicy unknown: err = %v", err)
	}
}

func TestAllowlistManagement(t *testing.T) {
	f := newFixture(t, domain.TierHot)
	ctx := context.Background()
	mixed := "0xAbCdEf0123456789aBcDeF0123456789AbCdEf01"
	if err := f.eng.AddAllowlist(ctx, "bob", f.w.ID, mixed, "exchange"); err != nil {
		t.Fatal(err)
	}
	if err := f.eng.AddAllowlist(ctx, "bob", f.w.ID, mixed, "exchange-2"); err != nil { // upsert relabels
		t.Fatal(err)
	}
	list, err := f.eng.ListAllowlist(ctx, f.w.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[1].Address != "0xabcdef0123456789abcdef0123456789abcdef01" || list[1].Label != "exchange-2" {
		t.Fatalf("list = %+v", list)
	}
	// Request to the mixed-case address matches the lowercase entry.
	want(t, f.eval(t, f.req(mixed, 1)), domain.OutcomeAllow)

	for _, badAddr := range []string{"", "0x123", "1111111111111111111111111111111111111111", "0xzz11111111111111111111111111111111111111", dest + "00"} {
		if err := f.eng.AddAllowlist(ctx, "bob", f.w.ID, badAddr, ""); !errors.Is(err, policy.ErrInvalidAddress) {
			t.Errorf("AddAllowlist(%q) err = %v", badAddr, err)
		}
	}

	if err := f.eng.RemoveAllowlist(ctx, "bob", f.w.ID, mixed); err != nil {
		t.Fatal(err)
	}
	if err := f.eng.RemoveAllowlist(ctx, "bob", f.w.ID, mixed); !errors.Is(err, policy.ErrNotFound) {
		t.Fatalf("second remove err = %v", err)
	}
	want(t, f.eval(t, f.req(mixed, 1)), domain.OutcomeDeny, policy.ReasonNotAllowlisted)

	evs, _ := f.log.List(ctx, audit.Filter{WalletID: f.w.ID})
	var adds, removes int
	for _, ev := range evs {
		if ev.Type != domain.EventAllowlistUpdated {
			continue
		}
		var p map[string]string
		json.Unmarshal(ev.Payload, &p)
		switch p["action"] {
		case "add":
			adds++
		case "remove":
			removes++
		}
	}
	if adds != 3 || removes != 1 { // dest (fixture) + 2 upserts; 1 successful remove
		t.Fatalf("allowlist audit events: adds %d removes %d", adds, removes)
	}
	if ok, _, err := f.log.Verify(ctx); !ok || err != nil {
		t.Fatalf("chain invalid: %v", err)
	}
}
