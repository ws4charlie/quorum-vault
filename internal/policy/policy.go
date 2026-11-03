// Package policy decides whether a sign request may proceed: allow, deny, or
// needs_approval. Rules (PLAN "Policy semantics"), evaluated in this order:
//
//  1. destination not in the wallet's allowlist        -> deny
//  2. value > per-tx limit                              -> deny
//  3. velocity: recent non-denied requests >= max       -> deny
//  4. if not denied, needs_approval when any of: cold wallet, value > approval
//     threshold, spent in last 24h + value > daily limit
//  5. else allow
//
// Hard (deny) rules are all checked so every failing reason is reported; soft
// reasons are reported only when no hard rule failed. A wallet without a policy
// row is denied with reason "no policy".
package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ws4charlie/quorum-vault/internal/domain"
)

// Stable, human-readable reasons carried in domain.Decision.Reasons.
const (
	ReasonNoPolicy          = "no policy"
	ReasonNotAllowlisted    = "destination not allowlisted"
	ReasonPerTxLimit        = "exceeds per-tx limit"
	ReasonVelocity          = "velocity limit reached"
	ReasonColdWallet        = "cold wallet requires approval"
	ReasonApprovalThreshold = "exceeds approval threshold"
	ReasonDailyLimit        = "exceeds daily limit"
)

// Default required approvals by tier, used when SetPolicy gets RequiredApprovals <= 0.
const (
	DefaultApprovalsHot  = 1
	DefaultApprovalsCold = 2
)

var (
	ErrNotFound       = errors.New("policy: not found")
	ErrInvalidAddress = errors.New("policy: invalid address (want 0x + 40 hex)")
	ErrInvalidPolicy  = errors.New("policy: invalid policy")
)

var addrRE = regexp.MustCompile(`^0x[0-9a-f]{40}$`)

// NormalizeAddress lowercases addr and checks it is 0x + 40 hex digits.
func NormalizeAddress(addr string) (string, error) {
	a := strings.ToLower(strings.TrimSpace(addr))
	if !addrRE.MatchString(a) {
		return "", fmt.Errorf("%w: %q", ErrInvalidAddress, addr)
	}
	return a, nil
}

// AllowEntry is one allowlisted destination of a wallet.
type AllowEntry struct {
	WalletID  string    `json:"wallet_id"`
	Address   string    `json:"address"` // lowercase 0x-hex
	Label     string    `json:"label"`
	CreatedAt time.Time `json:"created_at"`
}

// Engine evaluates and manages policies and allowlists.
type Engine struct {
	pool *pgxpool.Pool
	aud  domain.Auditor
	now  func() time.Time
}

// New returns an Engine. now controls the clock for the velocity and 24h
// windows (time.Now when nil).
func New(pool *pgxpool.Pool, aud domain.Auditor, now func() time.Time) *Engine {
	if now == nil {
		now = time.Now
	}
	return &Engine{pool: pool, aud: aud, now: now}
}

// Evaluate applies the policy rules to req for wallet w. It is read-only and
// does not audit (the caller records policy.decision). req itself is excluded
// from the velocity and daily-spend history, so Evaluate may run before or
// after req is inserted.
func (e *Engine) Evaluate(ctx context.Context, req domain.SignRequest, w domain.Wallet) (domain.Decision, error) {
	if req.WalletID != "" && req.WalletID != w.ID {
		return domain.Decision{}, fmt.Errorf("policy: request wallet %s != wallet %s", req.WalletID, w.ID)
	}
	if req.ValueWei == nil || req.ValueWei.Sign() < 0 {
		return domain.Decision{}, errors.New("policy: request value must be >= 0")
	}
	p, err := e.GetPolicy(ctx, w.ID)
	if errors.Is(err, ErrNotFound) {
		return domain.Decision{Outcome: domain.OutcomeDeny, Reasons: []string{ReasonNoPolicy}}, nil
	}
	if err != nil {
		return domain.Decision{}, err
	}
	d := domain.Decision{Reasons: []string{}, RequiredApprovals: p.RequiredApprovals}
	now := e.now()

	// 1. allowlist
	var listed bool
	if err := e.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM allowlist WHERE wallet_id = $1 AND address = $2)`,
		w.ID, strings.ToLower(req.To)).Scan(&listed); err != nil {
		return domain.Decision{}, fmt.Errorf("policy: allowlist lookup: %w", err)
	}
	if !listed {
		d.Reasons = append(d.Reasons, ReasonNotAllowlisted)
	}
	// 2. per-tx limit
	if req.ValueWei.Cmp(p.PerTxLimitWei) > 0 {
		d.Reasons = append(d.Reasons, ReasonPerTxLimit)
	}
	// 3. velocity
	var recent int
	windowStart := now.Add(-time.Duration(p.VelocityWindowSeconds) * time.Second)
	if err := e.pool.QueryRow(ctx, `SELECT count(*) FROM sign_requests
		WHERE wallet_id = $1 AND id::text <> $2 AND status <> 'denied' AND created_at > $3`,
		w.ID, req.ID, windowStart).Scan(&recent); err != nil {
		return domain.Decision{}, fmt.Errorf("policy: velocity: %w", err)
	}
	if recent >= p.VelocityMaxTx {
		d.Reasons = append(d.Reasons, ReasonVelocity)
	}
	if len(d.Reasons) > 0 {
		d.Outcome = domain.OutcomeDeny
		return d, nil
	}

	// 4. soft rules
	if w.Tier == domain.TierCold {
		d.Reasons = append(d.Reasons, ReasonColdWallet)
	}
	if req.ValueWei.Cmp(p.ApprovalThresholdWei) > 0 {
		d.Reasons = append(d.Reasons, ReasonApprovalThreshold)
	}
	var spentText string
	if err := e.pool.QueryRow(ctx, `SELECT coalesce(sum(value_wei), 0)::text FROM sign_requests
		WHERE wallet_id = $1 AND id::text <> $2 AND status IN ('approved', 'signed', 'pending_approval')
		AND created_at > $3`,
		w.ID, req.ID, now.Add(-24*time.Hour)).Scan(&spentText); err != nil {
		return domain.Decision{}, fmt.Errorf("policy: daily spend: %w", err)
	}
	spent, ok := new(big.Int).SetString(spentText, 10)
	if !ok {
		return domain.Decision{}, fmt.Errorf("policy: daily spend: bad numeric %q", spentText)
	}
	if spent.Add(spent, req.ValueWei).Cmp(p.DailyLimitWei) > 0 {
		d.Reasons = append(d.Reasons, ReasonDailyLimit)
	}
	if len(d.Reasons) > 0 {
		d.Outcome = domain.OutcomeNeedsApproval
		return d, nil
	}
	d.Outcome = domain.OutcomeAllow
	return d, nil
}

func parseWei(field, s string) (*big.Int, error) {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return nil, fmt.Errorf("policy: %s: bad numeric %q", field, s)
	}
	return v, nil
}

// GetPolicy returns the wallet's policy or ErrNotFound.
func (e *Engine) GetPolicy(ctx context.Context, walletID string) (domain.Policy, error) {
	var p domain.Policy
	var daily, perTx, threshold string
	err := e.pool.QueryRow(ctx, `SELECT wallet_id::text, daily_limit_wei::text, per_tx_limit_wei::text,
		approval_threshold_wei::text, velocity_max_tx, velocity_window_seconds, required_approvals, updated_at
		FROM policies WHERE wallet_id::text = $1`, walletID).
		Scan(&p.WalletID, &daily, &perTx, &threshold, &p.VelocityMaxTx, &p.VelocityWindowSeconds, &p.RequiredApprovals, &p.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Policy{}, fmt.Errorf("%w: wallet %s", ErrNotFound, walletID)
	}
	if err != nil {
		return domain.Policy{}, fmt.Errorf("policy: get: %w", err)
	}
	if p.DailyLimitWei, err = parseWei("daily_limit_wei", daily); err != nil {
		return domain.Policy{}, err
	}
	if p.PerTxLimitWei, err = parseWei("per_tx_limit_wei", perTx); err != nil {
		return domain.Policy{}, err
	}
	if p.ApprovalThresholdWei, err = parseWei("approval_threshold_wei", threshold); err != nil {
		return domain.Policy{}, err
	}
	p.UpdatedAt = p.UpdatedAt.UTC()
	return p, nil
}

func validWei(v *big.Int) bool { return v != nil && v.Sign() >= 0 }

// SetPolicy inserts or replaces the wallet's policy and audits policy.updated.
// RequiredApprovals <= 0 takes the tier default (hot 1, cold 2).
func (e *Engine) SetPolicy(ctx context.Context, actor string, p domain.Policy) error {
	if !validWei(p.DailyLimitWei) || !validWei(p.PerTxLimitWei) || !validWei(p.ApprovalThresholdWei) {
		return fmt.Errorf("%w: limits must be set and >= 0", ErrInvalidPolicy)
	}
	if p.VelocityMaxTx < 1 || p.VelocityWindowSeconds < 1 {
		return fmt.Errorf("%w: velocity_max_tx and velocity_window_seconds must be >= 1", ErrInvalidPolicy)
	}
	var tier domain.Tier
	err := e.pool.QueryRow(ctx, `SELECT tier FROM wallets WHERE id::text = $1`, p.WalletID).Scan(&tier)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%w: wallet %s", ErrNotFound, p.WalletID)
	}
	if err != nil {
		return fmt.Errorf("policy: wallet lookup: %w", err)
	}
	if p.RequiredApprovals <= 0 {
		p.RequiredApprovals = DefaultApprovalsHot
		if tier == domain.TierCold {
			p.RequiredApprovals = DefaultApprovalsCold
		}
	}
	p.UpdatedAt = e.now().UTC().Truncate(time.Microsecond)
	if _, err := e.pool.Exec(ctx, `INSERT INTO policies (wallet_id, daily_limit_wei, per_tx_limit_wei,
		approval_threshold_wei, velocity_max_tx, velocity_window_seconds, required_approvals, updated_at)
		VALUES ($1, $2::numeric, $3::numeric, $4::numeric, $5, $6, $7, $8)
		ON CONFLICT (wallet_id) DO UPDATE SET daily_limit_wei = EXCLUDED.daily_limit_wei,
			per_tx_limit_wei = EXCLUDED.per_tx_limit_wei, approval_threshold_wei = EXCLUDED.approval_threshold_wei,
			velocity_max_tx = EXCLUDED.velocity_max_tx, velocity_window_seconds = EXCLUDED.velocity_window_seconds,
			required_approvals = EXCLUDED.required_approvals, updated_at = EXCLUDED.updated_at`,
		p.WalletID, p.DailyLimitWei.String(), p.PerTxLimitWei.String(), p.ApprovalThresholdWei.String(),
		p.VelocityMaxTx, p.VelocityWindowSeconds, p.RequiredApprovals, p.UpdatedAt); err != nil {
		return fmt.Errorf("policy: set: %w", err)
	}
	return e.audit(ctx, actor, domain.EventPolicyUpdated, p.WalletID, p)
}

// AddAllowlist inserts or relabels an allowlisted address and audits allowlist.updated.
func (e *Engine) AddAllowlist(ctx context.Context, actor, walletID, address, label string) error {
	addr, err := NormalizeAddress(address)
	if err != nil {
		return err
	}
	if _, err := e.pool.Exec(ctx, `INSERT INTO allowlist (wallet_id, address, label, created_at)
		VALUES ($1, $2, $3, $4) ON CONFLICT (wallet_id, address) DO UPDATE SET label = EXCLUDED.label`,
		walletID, addr, label, e.now().UTC()); err != nil {
		return fmt.Errorf("policy: allowlist add: %w", err)
	}
	return e.audit(ctx, actor, domain.EventAllowlistUpdated, walletID,
		map[string]string{"action": "add", "address": addr, "label": label})
}

// RemoveAllowlist deletes an allowlisted address (ErrNotFound if absent) and audits allowlist.updated.
func (e *Engine) RemoveAllowlist(ctx context.Context, actor, walletID, address string) error {
	addr, err := NormalizeAddress(address)
	if err != nil {
		return err
	}
	tag, err := e.pool.Exec(ctx, `DELETE FROM allowlist WHERE wallet_id::text = $1 AND address = $2`, walletID, addr)
	if err != nil {
		return fmt.Errorf("policy: allowlist remove: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: %s not allowlisted for wallet %s", ErrNotFound, addr, walletID)
	}
	return e.audit(ctx, actor, domain.EventAllowlistUpdated, walletID,
		map[string]string{"action": "remove", "address": addr})
}

// ListAllowlist returns the wallet's allowlist ordered by address.
func (e *Engine) ListAllowlist(ctx context.Context, walletID string) ([]AllowEntry, error) {
	rows, err := e.pool.Query(ctx, `SELECT wallet_id::text, address, label, created_at FROM allowlist
		WHERE wallet_id::text = $1 ORDER BY address`, walletID)
	if err != nil {
		return nil, fmt.Errorf("policy: allowlist list: %w", err)
	}
	defer rows.Close()
	out := []AllowEntry{}
	for rows.Next() {
		var a AllowEntry
		if err := rows.Scan(&a.WalletID, &a.Address, &a.Label, &a.CreatedAt); err != nil {
			return nil, err
		}
		a.CreatedAt = a.CreatedAt.UTC()
		out = append(out, a)
	}
	return out, rows.Err()
}

func (e *Engine) audit(ctx context.Context, actor, typ, walletID string, payload any) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("policy: audit payload: %w", err)
	}
	if _, err := e.aud.Append(ctx, domain.AuditEvent{Actor: actor, Type: typ, WalletID: walletID, Payload: b}); err != nil {
		return fmt.Errorf("policy: audit %s: %w", typ, err)
	}
	return nil
}
