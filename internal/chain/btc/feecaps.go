package btc

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ws4charlie/quorum-vault/internal/audit"
	"github.com/ws4charlie/quorum-vault/internal/domain"
)

// Signed fee caps. max_fee_rate and max_tx_fee_sats of a Bitcoin chain are set in configuration; the zone's approvers can change them, with
// signatures, without a restart. One signed record is the truth for both sides: the signing zone reads it from its guard database, the core reads
// the same record from its own database, and each checks the signatures itself against the approver public keys of its own configuration. A row
// put into either database by anyone else is ignored.
//
// Who may change them: min_approvers distinct approvers (counted by identity), over (chain, caps, seq, time). The sequence number must be higher
// than the current one and the signing time within max_change_age of now when the change is applied. Static bounds in the zone's configuration
// are a ceiling and a floor that no signature can lift, and every change must pass CheckFeeCaps (the start-up rule) for the largest transaction.
//
// How they apply: the next build or bump of the core, and the next decision of the zone, read the current record. A transaction already signed is
// not touched. The core stamps the sequence number of the record it built under into the payload (Payload.FeeCapsSeq); the zone refuses a payload
// built under another sequence number (FeeCapsSeqNote): the core and the zone then wait for each other, with one ALERT per refusal, until the same
// change has been applied to both.

// FeeCaps are the two caps a change sets.
type FeeCaps struct {
	MaxTxFeeSats uint64 `json:"max_tx_fee_sats"`
	MaxFeeRate   uint64 `json:"max_fee_rate"` // sat/vB
}

// FeeCapsSeqNote ends the zone's refusal of a payload built under other fee caps than its own. The gateway and the cosigner raise an ALERT when
// a refusal carries it.
const FeeCapsSeqNote = "core and zone are on different fee-cap changes: apply the same signed change to both (docs/runbooks/btc-fee-caps.md)"

// FeeCapsBounds are the static ceiling and floor of the zone's configuration. No signed change can go outside them.
type FeeCapsBounds struct {
	MinFeeRate   uint64 `json:"min_fee_rate"`
	MaxFeeRate   uint64 `json:"max_fee_rate"`
	MinTxFeeSats uint64 `json:"min_tx_fee_sats"`
	MaxTxFeeSats uint64 `json:"max_tx_fee_sats"`
}

// Check reports whether c lies within the bounds.
func (b FeeCapsBounds) Check(c FeeCaps) error {
	if c.MaxFeeRate < b.MinFeeRate || c.MaxFeeRate > b.MaxFeeRate {
		return fmt.Errorf("max_fee_rate %d is outside the zone's bounds %d..%d sat/vB", c.MaxFeeRate, b.MinFeeRate, b.MaxFeeRate)
	}
	if c.MaxTxFeeSats < b.MinTxFeeSats || c.MaxTxFeeSats > b.MaxTxFeeSats {
		return fmt.Errorf("max_tx_fee_sats %d is outside the zone's bounds %d..%d", c.MaxTxFeeSats, b.MinTxFeeSats, b.MaxTxFeeSats)
	}
	return nil
}

// Validate checks that the bounds are well formed.
func (b FeeCapsBounds) Validate() error {
	if b.MinFeeRate == 0 || b.MinTxFeeSats == 0 || b.MinFeeRate > b.MaxFeeRate || b.MinTxFeeSats > b.MaxTxFeeSats || b.MaxTxFeeSats > math.MaxInt64 {
		return errors.New("fee-cap bounds need 0 < min <= max for both max_fee_rate and max_tx_fee_sats")
	}
	return nil
}

// FeeCapsMessage is what the approvers sign for a change.
func FeeCapsMessage(chain string, c FeeCaps, seq, unixSeconds int64) []byte {
	return []byte(fmt.Sprintf("qv-btc-fee-caps-v1\n%s\n%d\n%d\n%d\n%d", chain, c.MaxTxFeeSats, c.MaxFeeRate, seq, unixSeconds))
}

// FeeCapsSignature is one approver's signature of a change.
type FeeCapsSignature struct {
	Actor     string `json:"actor"`
	Signature string `json:"signature"` // hex
}

// FeeCapsChange is a signed change of the fee caps of one chain.
type FeeCapsChange struct {
	Chain      string             `json:"chain"`
	Caps       FeeCaps            `json:"caps"`
	Seq        int64              `json:"seq"`       // must be higher than the current one
	SignedAt   int64              `json:"signed_at"` // unix seconds
	Signatures []FeeCapsSignature `json:"signatures"`
}

// SignFeeCaps builds one approver's signature of a change.
func SignFeeCaps(priv ed25519.PrivateKey, actor, chain string, caps FeeCaps, seq int64, at time.Time) FeeCapsChange {
	return FeeCapsChange{Chain: chain, Caps: caps, Seq: seq, SignedAt: at.Unix(),
		Signatures: []FeeCapsSignature{{Actor: actor, Signature: hex.EncodeToString(ed25519.Sign(priv, FeeCapsMessage(chain, caps, seq, at.Unix())))}}}
}

// MergeFeeCaps joins the signatures of several approvers over the same change.
func MergeFeeCaps(parts ...FeeCapsChange) (FeeCapsChange, error) {
	if len(parts) == 0 {
		return FeeCapsChange{}, errors.New("no signatures")
	}
	out := parts[0]
	out.Signatures = append([]FeeCapsSignature(nil), parts[0].Signatures...)
	for _, p := range parts[1:] {
		if p.Chain != out.Chain || p.Caps != out.Caps || p.Seq != out.Seq || p.SignedAt != out.SignedAt {
			return FeeCapsChange{}, errors.New("the signatures are over different changes (chain, caps, seq or time differ)")
		}
		out.Signatures = append(out.Signatures, p.Signatures...)
	}
	return out, nil
}

// FeeCapsApprover is an approver as a verifier knows it: an Ed25519 key and the person behind it.
type FeeCapsApprover struct {
	Key      ed25519.PublicKey
	Identity string
}

// FeeCapsConfig is the core's side of signed changes: the approver keys it checks the signatures against (the same keys and people as the zone's
// approvers), how many must sign, and how old a change may be when it is applied.
type FeeCapsConfig struct {
	Approvers    map[string]FeeCapsApprover
	MinApprovers int           // default 1
	MaxAge       time.Duration // default 10m
}

// rules turns the core's config into the rules it judges changes by (no bounds: those are the zone's).
func (f *FeeCapsConfig) rules(chain string, maxInputs, maxPayments int) (*FeeCapsRules, error) {
	r := &FeeCapsRules{Chain: chain, Approvers: f.Approvers, MinApprovers: f.MinApprovers, MaxAge: f.MaxAge, MaxInputs: maxInputs, MaxPayments: maxPayments}
	if r.MinApprovers == 0 {
		r.MinApprovers = 1
	}
	if r.MaxAge == 0 {
		r.MaxAge = 10 * time.Minute
	}
	people := map[string]bool{}
	for n, a := range f.Approvers {
		if len(a.Key) != ed25519.PublicKeySize || a.Identity == "" {
			return nil, fmt.Errorf("btc: config: fee_caps approver %q needs an ed25519 key and an identity", n)
		}
		people[a.Identity] = true
	}
	if r.MinApprovers < 1 || r.MinApprovers > len(people) || r.MaxAge < 0 {
		return nil, fmt.Errorf("btc: config: fee_caps min_approvers %d: between 1 and the %d distinct approver identities", r.MinApprovers, len(people))
	}
	return r, nil
}

// FeeCapsRules is everything a side needs to judge a change: the approvers of its own configuration, how many must sign, how old a change may
// be when applied, the zone's bounds (nil on the core) and the largest transaction the caps must carry (CheckFeeCaps).
type FeeCapsRules struct {
	Chain        string
	Approvers    map[string]FeeCapsApprover // by name
	MinApprovers int
	MaxAge       time.Duration
	Bounds       *FeeCapsBounds
	MaxInputs    int
	MaxPayments  int
}

// Verify counts the distinct people whose signature over the change is valid and checks the change against the rules: it is for this chain, it
// has a sequence number of at least 1, enough approvers signed, it lies within the bounds, and it passes CheckFeeCaps. It returns the names of the
// approvers whose signatures counted (one per identity).
func (r FeeCapsRules) Verify(c FeeCapsChange) ([]string, error) {
	if c.Chain != r.Chain || c.Seq < 1 {
		return nil, fmt.Errorf("a change is for chain %q and has a sequence number of at least 1", r.Chain)
	}
	if c.Caps.MaxFeeRate == 0 || c.Caps.MaxTxFeeSats == 0 || c.Caps.MaxTxFeeSats > math.MaxInt64 || c.Caps.MaxFeeRate > math.MaxInt64 {
		return nil, errors.New("max_fee_rate and max_tx_fee_sats must be positive")
	}
	msg := FeeCapsMessage(c.Chain, c.Caps, c.Seq, c.SignedAt)
	byName := map[string]bool{}
	byPerson := map[string]bool{}
	var out []string
	for _, s := range c.Signatures {
		ap, ok := r.Approvers[s.Actor]
		if !ok || byName[s.Actor] || byPerson[ap.Identity] {
			continue
		}
		sig, err := hex.DecodeString(s.Signature)
		if err == nil && len(sig) == ed25519.SignatureSize && len(ap.Key) == ed25519.PublicKeySize && ed25519.Verify(ap.Key, msg, sig) {
			byName[s.Actor], byPerson[ap.Identity] = true, true
			out = append(out, s.Actor)
		}
	}
	sort.Strings(out)
	if len(out) < r.MinApprovers {
		return nil, fmt.Errorf("%d valid signatures of distinct, enabled approvers, %d needed", len(out), r.MinApprovers)
	}
	if r.Bounds != nil {
		if err := r.Bounds.Check(c.Caps); err != nil {
			return nil, err
		}
	}
	if err := CheckFeeCaps("signed change", c.Caps.MaxTxFeeSats, c.Caps.MaxFeeRate, r.MaxInputs, max(1, r.MaxPayments)); err != nil {
		return nil, err
	}
	return out, nil
}

// ---- storage ----

// FeeCapsTable is the table both sides keep: the core in its own database (a migration) and the zone in its guard database. Append-only.
const FeeCapsTable = "btc_fee_cap_changes"

// EventFeeCapsChanged is the audit event of an applied change.
const EventFeeCapsChanged = "btc.fee_caps.changed"

// FeeCapsRecord is the current record of a chain: the caps and the sequence number of the change that set them (0: configuration).
type FeeCapsRecord struct {
	FeeCaps
	Seq     int64
	Signers []string // names of the approvers that signed it
}

// Queryer is what the readers need of a pool.
type Queryer interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// CurrentFeeCaps is the newest row of the chain whose signatures verify against the rules; rows that do not are skipped and counted in skipped
// (the caller raises an alert). With no valid row, static is the record (sequence 0).
func CurrentFeeCaps(ctx context.Context, q Queryer, r FeeCapsRules, static FeeCaps) (cur FeeCapsRecord, skipped int, err error) {
	rows, err := q.Query(ctx, `SELECT seq, max_tx_fee_sats, max_fee_rate, signed_at, signatures FROM `+FeeCapsTable+` WHERE chain = $1 ORDER BY seq DESC`, r.Chain)
	if err != nil {
		return FeeCapsRecord{}, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		c := FeeCapsChange{Chain: r.Chain}
		var tx, rate int64
		var sigs []byte
		if err := rows.Scan(&c.Seq, &tx, &rate, &c.SignedAt, &sigs); err != nil {
			return FeeCapsRecord{}, skipped, err
		}
		c.Caps = FeeCaps{MaxTxFeeSats: uint64(tx), MaxFeeRate: uint64(rate)}
		if json.Unmarshal(sigs, &c.Signatures) == nil {
			if who, verr := r.Verify(c); verr == nil {
				return FeeCapsRecord{FeeCaps: c.Caps, Seq: c.Seq, Signers: who}, skipped, nil
			}
		}
		skipped++
	}
	if err := rows.Err(); err != nil {
		return FeeCapsRecord{}, skipped, err
	}
	return FeeCapsRecord{FeeCaps: static}, skipped, nil
}

// ApplyFeeCaps checks a signed change and records it with its audit event in one transaction, in the database of pool. A change that is unsigned,
// signed by too few or unknown approvers, stale, outside the bounds, below CheckFeeCaps, or not newer than the current one is refused and nothing
// changes. The same change applied twice is not an error (so an operator can finish applying it to the other databases).
func ApplyFeeCaps(ctx context.Context, pool *pgxpool.Pool, r FeeCapsRules, static FeeCaps, c FeeCapsChange, now time.Time, actor string) error {
	approvers, err := r.Verify(c)
	if err != nil {
		return fmt.Errorf("btc: fee caps change refused: %w", err)
	}
	if age := now.Sub(time.Unix(c.SignedAt, 0)); age > r.MaxAge || age < -r.MaxAge {
		return fmt.Errorf("btc: fee caps change refused: signed %s from now, the limit is %s", age.Round(time.Second), r.MaxAge)
	}
	sigs, _ := json.Marshal(c.Signatures)
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('qv-btc-fee-caps'), hashtext($1))`, c.Chain); err != nil {
		return err
	}
	cur, _, err := CurrentFeeCaps(ctx, tx, r, static)
	if err != nil {
		return err
	}
	if c.Seq == cur.Seq && c.Caps == cur.FeeCaps {
		return nil // already applied
	}
	if c.Seq <= cur.Seq {
		return fmt.Errorf("btc: fee caps change refused: sequence %d is not higher than the current %d", c.Seq, cur.Seq)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO `+FeeCapsTable+` (chain, seq, max_tx_fee_sats, max_fee_rate, signed_at, signatures) VALUES ($1, $2, $3, $4, $5, $6)`,
		c.Chain, c.Seq, int64(c.Caps.MaxTxFeeSats), int64(c.Caps.MaxFeeRate), c.SignedAt, sigs); err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]any{"chain": c.Chain, "from": cur.FeeCaps, "from_seq": cur.Seq, "to": c.Caps, "seq": c.Seq, "approvers": approvers, "signed_at": c.SignedAt})
	if _, err := audit.AppendTx(ctx, tx, domain.AuditEvent{Actor: actor, Type: EventFeeCapsChanged, Payload: payload}, ""); err != nil {
		return fmt.Errorf("btc: audit %s: %w", EventFeeCapsChanged, err)
	}
	return tx.Commit(ctx)
}

// ---- the live setting of a process ----

// feeCapsLive is the caps a process uses now, swapped as a whole.
type feeCapsLive struct {
	FeeCaps
	Seq int64
}

// FeeCapsView is the current caps of one process (the core's adapter or the zone's verifier): the static ones until the first refresh, then the
// newest valid record. Reads are lock-free; Refresh is called at the start of each build or decision.
type FeeCapsView struct {
	static  FeeCaps
	rules   atomic.Pointer[FeeCapsRules] // nil: signed changes are off, the static caps stand
	q       Queryer
	onSkip  func(skipped int)
	live    atomic.Pointer[feeCapsLive]
	skipped atomic.Int64
}

// NewFeeCapsView makes a view. rules nil turns signed changes off.
func NewFeeCapsView(static FeeCaps, rules *FeeCapsRules, q Queryer, onSkip func(skipped int)) *FeeCapsView {
	f := &FeeCapsView{static: static, q: q, onSkip: onSkip}
	f.rules.Store(rules)
	return f
}

// SetRules replaces the rules changes are judged by (the zone's approvers change while it runs). Safe against concurrent Refresh.
func (f *FeeCapsView) SetRules(rules *FeeCapsRules) { f.rules.Store(rules) }

// Now is the caps and the sequence number in force.
func (f *FeeCapsView) Now() (FeeCaps, int64) {
	if l := f.live.Load(); l != nil {
		return l.FeeCaps, l.Seq
	}
	return f.static, 0
}

// Refresh reads the current record. An error leaves what was in force; the caller does not go on with the build.
func (f *FeeCapsView) Refresh(ctx context.Context) error {
	rules := f.rules.Load()
	if rules == nil || f.q == nil {
		return nil
	}
	cur, skipped, err := CurrentFeeCaps(ctx, f.q, *rules, f.static)
	if err != nil {
		return fmt.Errorf("btc: read fee caps: %w", err)
	}
	if skipped > 0 && f.skipped.Swap(int64(skipped)) != int64(skipped) && f.onSkip != nil {
		f.onSkip(skipped)
	}
	f.live.Store(&feeCapsLive{FeeCaps: cur.FeeCaps, Seq: cur.Seq})
	return nil
}
