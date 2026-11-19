package gateway

import (
	"bytes"
	"cmp"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/audit"
	"github.com/ws4charlie/quorum-vault/internal/domain"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
	"github.com/ws4charlie/quorum-vault/internal/webauthn"
)

// The approvers of the zone are the people whose signatures release money. They come from two places: the static config file (the bootstrap set)
// and a signed change log in each guard database (this file). The effective set, which every decision uses, is the bootstrap set with the
// verified log applied in order.
//
// Who may change the set: OPERATORS, a key set of its own in the config's "operators" section, never the approvers: an approver cannot enrol,
// enable, disable or revoke anyone, itself included (an operator key may not equal an approver key). A change needs min_operators distinct
// operators (default 2) over (action, name, the full approver entry for an enrolment, seq, signing time); the sequence number must be higher than
// the current one, the signing time within max_change_age of now when applied. It is stored append-only in the guard database of the gateway and of
// every cosigner, with an audit event naming the operators, in one transaction. Every read verifies the signatures again against the config, so a
// row written by anyone else (SQL access to the guard database) is ignored, counted, and raises an ALERT.
//
// Bootstrap approvers: a signed revoke, disable or enable may also name an approver of the config file. The reason is a compromised bootstrap key:
// removing it must not need a restart or a config edit that an attacker with file access could undo. The other direction is closed: the config
// file alone can add approvers, since it is the root of trust, but a signed revoke outlives it (a revoked name stays revoked; the config entry is
// ignored while the revoke is in the log).
//
// A change applies to the next decision of the gateway and of every cosigner: each reads its own log at every decision, so no restart is needed. A
// job is judged by the set in force when it is decided, including a job queued before the change (a revoked approver's signature stops counting
// at once).
//
// When the gateway and a cosigner are on different sequence numbers each judges by its own verified log. A job whose approvals name an approver this
// zone does not know yet, or has disabled in a way the other side may not share (not revoked), is not refused finally: the decision is a retry
// (ErrApproverLag) until the job's own not_after, with an ALERT, like a mismatch of the fee-cap sequence. A revoked approver's signature is a
// refusal.

// Actions of an approver change.
const (
	ActionEnrol   = "enrol"
	ActionDisable = "disable"
	ActionEnable  = "enable"
	ActionRevoke  = "revoke"
)

// EventApproverChanged is the audit event of an applied change.
const EventApproverChanged = "approver.changed"

// ApproverLagNote ends the reason of a decision that waits because this zone's approver list may be behind the other side's.
const ApproverLagNote = "an approval names an approver this zone does not count yet: apply the same signed approver changes to the gateway and every cosigner (docs/runbooks/approvers.md)"

// ErrApproverLag marks a decision that is a retry, not a refusal: see the comment above.
var ErrApproverLag = errors.New("approver list may be behind")

// OperatorsFile is the operators section: the key set that signs approver changes.
type OperatorsFile struct {
	// Keys maps operator name to its Ed25519 public key (hex).
	Keys map[string]OperatorFile `json:"keys"`
	// MinOperators: distinct operators a change needs. Default 2 (1 when only one operator is configured); at least 2 when several are.
	MinOperators int `json:"min_operators,omitempty"`
	// MaxChangeAge: how far from now the signing time of a change may be when it is applied (default "10m").
	MaxChangeAge string `json:"max_change_age,omitempty"`
}

// OperatorFile is one operator.
type OperatorFile struct {
	PublicKey string `json:"public_key"` // 64 hex chars
}

// OperatorConfig is the validated operators section.
type OperatorConfig struct {
	Keys   map[string]ed25519.PublicKey
	Min    int
	MaxAge time.Duration
}

// build validates the section. approverKeys is the set of the static approvers' key identifiers (no operator may use an approver's key).
func (o *OperatorsFile) build(approverKeys map[string]string) (*OperatorConfig, error) {
	if len(o.Keys) == 0 {
		return nil, errors.New("gateway: config: operators.keys is empty")
	}
	oc := &OperatorConfig{Keys: map[string]ed25519.PublicKey{}, Min: o.MinOperators, MaxAge: 10 * time.Minute}
	seen := map[string]string{}
	for name, k := range o.Keys {
		raw, err := hex.DecodeString(k.PublicKey)
		if name == "" || err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("gateway: config: operator %q: public_key must be %d hex bytes", name, ed25519.PublicKeySize)
		}
		if other, dup := seen[string(raw)]; dup {
			return nil, fmt.Errorf("gateway: config: operators %q and %q share one public key", other, name)
		}
		if ap, clash := approverKeys[string(raw)]; clash {
			return nil, fmt.Errorf("gateway: config: operator %q uses the key of approver %q: operators and approvers are different people with different keys", name, ap)
		}
		seen[string(raw)] = name
		oc.Keys[name] = ed25519.PublicKey(raw)
	}
	if oc.Min == 0 {
		oc.Min = min(2, len(oc.Keys))
	}
	if oc.Min > len(oc.Keys) || oc.Min < 1 || (len(oc.Keys) > 1 && oc.Min < 2) {
		return nil, fmt.Errorf("gateway: config: operators.min_operators %d: at least 2 (1 only with a single operator) and at most the %d configured operators", oc.Min, len(oc.Keys))
	}
	if o.MaxChangeAge != "" {
		v, err := time.ParseDuration(o.MaxChangeAge)
		if err != nil || v <= 0 {
			return nil, fmt.Errorf("gateway: config: operators.max_change_age %q is not a positive duration", o.MaxChangeAge)
		}
		oc.MaxAge = v
	}
	return oc, nil
}

// OperatorSignature is one operator's signature of a change.
type OperatorSignature struct {
	Operator  string `json:"operator"`
	Signature string `json:"signature"` // hex
}

// ApproverChange is a signed change of the approver set. Approver is the full entry of an enrolment and nil for the other actions.
type ApproverChange struct {
	Action     string              `json:"action"`
	Name       string              `json:"name"`
	Approver   *ApproverFile       `json:"approver,omitempty"`
	Seq        int64               `json:"seq"`       // must be higher than the current one
	SignedAt   int64               `json:"signed_at"` // unix seconds
	Signatures []OperatorSignature `json:"signatures"`
}

// ApproverChangeMessage is what the operators sign: a domain prefix and the change without its signatures, as JSON of a fixed field order.
func ApproverChangeMessage(c ApproverChange) []byte {
	body, _ := json.Marshal(struct {
		Action   string        `json:"action"`
		Name     string        `json:"name"`
		Approver *ApproverFile `json:"approver,omitempty"`
		Seq      int64         `json:"seq"`
		SignedAt int64         `json:"signed_at"`
	}{c.Action, c.Name, c.Approver, c.Seq, c.SignedAt})
	return append([]byte("qv-approver-change-v1\n"), body...)
}

// SignApproverChange adds one operator's signature to c (whose Signatures it replaces).
func SignApproverChange(priv ed25519.PrivateKey, operator string, c ApproverChange) ApproverChange {
	c.Signatures = []OperatorSignature{{Operator: operator, Signature: hex.EncodeToString(ed25519.Sign(priv, ApproverChangeMessage(c)))}}
	return c
}

// MergeApproverChanges joins the signatures of several operators over the same change.
func MergeApproverChanges(parts ...ApproverChange) (ApproverChange, error) {
	if len(parts) == 0 {
		return ApproverChange{}, errors.New("no signatures")
	}
	out := parts[0]
	out.Signatures = slices.Clone(parts[0].Signatures)
	for _, p := range parts[1:] {
		if !bytes.Equal(ApproverChangeMessage(p), ApproverChangeMessage(out)) {
			return ApproverChange{}, errors.New("the signatures are over different changes (action, name, approver, seq or time differ)")
		}
		out.Signatures = append(out.Signatures, p.Signatures...)
	}
	return out, nil
}

// shape checks what no state is needed for.
func (c ApproverChange) shape() error {
	if c.Seq < 1 {
		return errors.New("a change has a sequence number of at least 1")
	}
	if c.Name == "" {
		return errors.New("a change names an approver")
	}
	switch c.Action {
	case ActionEnrol:
		if c.Approver == nil || !c.Approver.Enabled {
			return errors.New("an enrolment carries the full approver entry, enabled")
		}
	case ActionDisable, ActionEnable, ActionRevoke:
		if c.Approver != nil {
			return fmt.Errorf("a %s carries no approver entry", c.Action)
		}
	default:
		return fmt.Errorf("action %q is none of enrol, disable, enable, revoke", c.Action)
	}
	return nil
}

// verify returns the distinct operators whose signature over c is valid, and an error when there are fewer than the config needs.
func (o *OperatorConfig) verify(c ApproverChange) ([]string, error) {
	if o == nil {
		return nil, errors.New("the zone's config has no operators section: signed approver changes are off")
	}
	msg := ApproverChangeMessage(c)
	seen := map[string]bool{}
	var out []string
	for _, s := range c.Signatures {
		key, ok := o.Keys[s.Operator]
		if !ok || seen[s.Operator] {
			continue
		}
		sig, err := hex.DecodeString(s.Signature)
		if err == nil && len(sig) == ed25519.SignatureSize && ed25519.Verify(key, msg, sig) {
			seen[s.Operator] = true
			out = append(out, s.Operator)
		}
	}
	sort.Strings(out)
	if len(out) < o.Min {
		return nil, fmt.Errorf("%d valid signatures of distinct configured operators, %d needed", len(out), o.Min)
	}
	return out, nil
}

// ---- the effective set ----

// ApproverSet is the approvers in force at one moment: the config's approvers with the verified change log applied.
type ApproverSet struct {
	// Approvers are the approvers that are not revoked, enabled or not. Only an enabled one counts.
	Approvers map[string]Approver
	// Revoked names the approvers a signed revoke removed for good (a name is never enrolled again, nor its key).
	Revoked map[string]bool
	// Seq is the sequence number of the last change applied (0: none, the config alone).
	Seq int64
	// Ignored counts the rows of the log that did not verify (signatures, order, content) and were skipped.
	Ignored int

	keys    map[string]string // key identifier of every approver ever known (revoked too) -> name
	applied map[int64][]byte  // sequence number -> message of the change applied
}

// keyID identifies the key or credential of an approver, the same way the config check for shared keys does.
func keyID(a Approver) string {
	if a.WebAuthn != nil {
		return string(append([]byte("webauthn:"), a.WebAuthn.CredentialID...))
	}
	return string(a.Key)
}

// StaticApprovers is the set of the config file alone.
func (c *Config) StaticApprovers() *ApproverSet {
	s := &ApproverSet{Approvers: maps.Clone(c.Approvers), Revoked: map[string]bool{}, keys: map[string]string{}, applied: map[int64][]byte{}}
	if s.Approvers == nil {
		s.Approvers = map[string]Approver{}
	}
	for n, a := range s.Approvers {
		s.keys[keyID(a)] = n
	}
	return s
}

func (s *ApproverSet) clone() *ApproverSet {
	return &ApproverSet{Approvers: maps.Clone(s.Approvers), Revoked: maps.Clone(s.Revoked), Seq: s.Seq, Ignored: s.Ignored, keys: maps.Clone(s.keys),
		applied: maps.Clone(s.applied)}
}

// Enabled lists the names of the enabled approvers.
func (s *ApproverSet) Enabled() []string {
	var out []string
	for n, a := range s.Approvers {
		if a.Enabled {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// enabledPeople counts the distinct people with an enabled key (only Ed25519 keys when ed25519Only: route and fee-cap changes use no other).
func (s *ApproverSet) enabledPeople(ed25519Only bool) int {
	people := map[string]bool{}
	for _, a := range s.Approvers {
		if a.Enabled && (!ed25519Only || a.WebAuthn == nil) {
			people[a.Identity] = true
		}
	}
	return len(people)
}

// MinEnabledApprovers is what a change must leave enabled: the highest number of approvals any tier asks (distinct people), and the number a route
// or fee-cap change asks (distinct people with an Ed25519 key).
func (c *Config) MinEnabledApprovers() (people, ed25519People int) {
	people, ed25519People = 1, 0
	for _, cc := range c.Chains {
		for _, p := range cc.Assets {
			for _, t := range p.Tiers {
				people = max(people, t.Approvals)
			}
		}
		if cc.BTC.FeeCaps != nil {
			ed25519People = max(ed25519People, cc.BTC.FeeCaps.MinApprovers)
		}
	}
	if c.Route != nil {
		ed25519People = max(ed25519People, c.Route.MinApprovers)
	}
	return people, ed25519People
}

// apply puts one change into the set. strict adds the checks of applying a new change (the state must really change, and the set must keep enough
// enabled approvers); reading the log back applies only what makes a change meaningful, so a signed revoke is never dropped because the config's tiers
// changed since. A refused change leaves the set as it was.
func (s *ApproverSet) apply(cfg *Config, c ApproverChange, strict bool) error {
	if err := c.shape(); err != nil {
		return err
	}
	next := s.clone()
	switch c.Action {
	case ActionEnrol:
		ap, kid, err := c.Approver.build(c.Name)
		if err != nil {
			return err
		}
		if _, known := next.Approvers[c.Name]; known || next.Revoked[c.Name] {
			return fmt.Errorf("approver %q already exists (or was revoked: a name is never used again)", c.Name)
		}
		if other, dup := next.keys[kid]; dup {
			return fmt.Errorf("the key or credential is already used by approver %q (revoked ones too)", other)
		}
		if cfg.Operators != nil {
			for op, k := range cfg.Operators.Keys {
				if c.Approver.Scheme != "webauthn" && string(k) == kid {
					return fmt.Errorf("the key is operator %q's: operators and approvers have different keys", op)
				}
			}
		}
		next.Approvers[c.Name], next.keys[kid] = ap, c.Name
	case ActionRevoke:
		if next.Revoked[c.Name] {
			if strict {
				return fmt.Errorf("approver %q is already revoked", c.Name)
			}
			break
		}
		if _, ok := next.Approvers[c.Name]; !ok {
			return fmt.Errorf("approver %q is unknown", c.Name)
		}
		delete(next.Approvers, c.Name)
		next.Revoked[c.Name] = true
	case ActionDisable, ActionEnable:
		ap, ok := next.Approvers[c.Name]
		if !ok {
			return fmt.Errorf("approver %q is unknown or revoked", c.Name)
		}
		want := c.Action == ActionEnable
		if ap.Enabled == want && strict {
			return fmt.Errorf("approver %q is already %sd", c.Name, c.Action)
		}
		ap.Enabled = want
		next.Approvers[c.Name] = ap
	}
	if strict && (c.Action == ActionDisable || c.Action == ActionRevoke) {
		need, needEd := cfg.MinEnabledApprovers()
		if have := next.enabledPeople(false); have < need {
			return fmt.Errorf("the change would leave %d enabled approvers (distinct people), the highest approval tier needs %d", have, need)
		}
		if have := next.enabledPeople(true); have < needEd {
			return fmt.Errorf("the change would leave %d enabled approvers with an Ed25519 key, route and fee-cap changes need %d", have, needEd)
		}
	}
	next.Seq = c.Seq
	next.applied[c.Seq] = ApproverChangeMessage(c)
	*s = *next
	return nil
}

// foldApprovers is the effective set: the config's approvers with every row of the log that verifies applied in sequence order. A row is ignored (and
// counted) when its signatures do not satisfy the operators of the config, its sequence number is not higher than the last one applied, or its
// content does not fit the set.
func (c *Config) foldApprovers(rows []ApproverChange) *ApproverSet {
	s := c.StaticApprovers()
	for _, r := range rows {
		if _, err := c.Operators.verify(r); err != nil || r.Seq <= s.Seq {
			s.Ignored++
			continue
		}
		if err := s.apply(c, r, false); err != nil {
			s.Ignored++
		}
	}
	return s
}

// ---- storage ----

type queryer interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// loadApproverRows reads the whole log, oldest first.
func loadApproverRows(ctx context.Context, q queryer) ([]ApproverChange, error) {
	rows, err := q.Query(ctx, `SELECT seq, action, name, approver, signed_at, signatures FROM approver_changes ORDER BY seq, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ApproverChange
	for rows.Next() {
		var c ApproverChange
		var ap, sigs []byte
		if err := rows.Scan(&c.Seq, &c.Action, &c.Name, &ap, &c.SignedAt, &sigs); err != nil {
			return nil, err
		}
		// A row that does not parse stays in the list as a change nothing can verify, so it is counted.
		if len(ap) > 0 {
			var f ApproverFile
			if json.Unmarshal(ap, &f) == nil {
				c.Approver = &f
			} else {
				c.Action = "unreadable"
			}
		}
		if json.Unmarshal(sigs, &c.Signatures) != nil {
			c.Signatures = nil
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// EffectiveApprovers reads the guard database's log and returns the set in force. Without an operators section the config's approvers are the
// whole set and the database is not read. An error is an outage: the caller retries.
func (g *Guard) EffectiveApprovers(ctx context.Context, cfg *Config) (*ApproverSet, error) {
	if cfg.Operators == nil || g == nil {
		return cfg.StaticApprovers(), nil
	}
	rows, err := loadApproverRows(ctx, g.pool)
	if err != nil {
		return nil, fmt.Errorf("gateway: read approver changes: %w", err)
	}
	s := cfg.foldApprovers(rows)
	if s.Ignored > 0 && g.approverIgnored.Swap(int64(s.Ignored)) != int64(s.Ignored) {
		slog.Error("ALERT approver registry: rows of the approver_changes table do not carry valid operator signatures (or do not fit) and are ignored", "rows", s.Ignored)
	}
	return s, nil
}

// ApplyApproverChange checks a signed change and records it, with its audit event, in one transaction. A change signed by too few operators (or by
// one operator twice, or by approvers), stale, not newer than the log, naming an unknown or already used approver, or leaving too few enabled
// approvers is refused and nothing changes. The same change applied twice is not an error (so an operator can finish applying it to the other
// databases). actor names the zone process in the audit event (gateway, cosigner).
func (g *Guard) ApplyApproverChange(ctx context.Context, cfg *Config, c ApproverChange, now time.Time, actor string) error {
	refuse := func(err error) error { return fmt.Errorf("gateway: approver change refused: %w", err) }
	if err := c.shape(); err != nil {
		return refuse(err)
	}
	operators, err := cfg.Operators.verify(c)
	if err != nil {
		return refuse(err)
	}
	if age := now.Sub(time.Unix(c.SignedAt, 0)); age > cfg.Operators.MaxAge || age < -cfg.Operators.MaxAge {
		return refuse(fmt.Errorf("signed %s from now, the limit is %s", age.Round(time.Second), cfg.Operators.MaxAge))
	}
	tx, err := g.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('qv-approver-registry'))`); err != nil {
		return err
	}
	rows, err := loadApproverRows(ctx, tx)
	if err != nil {
		return err
	}
	cur := cfg.foldApprovers(rows)
	if msg, done := cur.applied[c.Seq]; done && bytes.Equal(msg, ApproverChangeMessage(c)) {
		return nil // already applied
	}
	if c.Seq <= cur.Seq {
		return refuse(fmt.Errorf("sequence %d is not higher than the current %d", c.Seq, cur.Seq))
	}
	next := cur.clone()
	if err := next.apply(cfg, c, true); err != nil {
		return refuse(err)
	}
	sigs, _ := json.Marshal(c.Signatures)
	var entry []byte
	if c.Approver != nil {
		entry, _ = json.Marshal(c.Approver)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO approver_changes (seq, action, name, approver, signed_at, signatures) VALUES ($1, $2, $3, $4, $5, $6)`,
		c.Seq, c.Action, c.Name, entry, c.SignedAt, sigs); err != nil {
		return err
	}
	payload := map[string]any{"action": c.Action, "name": c.Name, "seq": c.Seq, "operators": operators, "signed_at": c.SignedAt, "enabled_after": next.Enabled()}
	if c.Approver != nil {
		payload["identity"], payload["scheme"] = cmp.Or(c.Approver.Identity, c.Name), cmp.Or(c.Approver.Scheme, "ed25519")
	}
	pj, _ := json.Marshal(payload)
	if _, err := audit.AppendTx(ctx, tx, domain.AuditEvent{Actor: actor, Type: EventApproverChanged, Payload: pj}, ""); err != nil {
		return fmt.Errorf("gateway: audit %s: %w", EventApproverChanged, err)
	}
	return tx.Commit(ctx)
}

// ---- use in a decision ----

// validApprovers names the distinct approvers whose approval over hash verifies: enabled, in the set, one per person (the same actor or two keys of
// one identity count once). Unknown or disabled actors and bad signatures count for nothing. The order is the order given.
func (s *ApproverSet) validApprovers(hash []byte, approvals []signjob.Approval) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, a := range approvals {
		ap, ok := s.Approvers[a.Actor]
		if !ok || !ap.Enabled || seen[ap.Identity] {
			continue
		}
		if approvalHolds(ap, hash, a) {
			seen[ap.Identity] = true
			out = append(out, a.Actor)
		}
	}
	return out
}

// lagging reports whether an approval names an approver this set does not count but another zone's set may: unknown here, or known and disabled.
// Revoked approvers are final.
func (s *ApproverSet) lagging(approvals []signjob.Approval) bool {
	for _, a := range approvals {
		if s.Revoked[a.Actor] {
			continue
		}
		if ap, ok := s.Approvers[a.Actor]; !ok || !ap.Enabled {
			return true
		}
	}
	return false
}

// identity is the person behind an approver name ("" when unknown).
func (s *ApproverSet) identity(name string) string { return s.Approvers[name].Identity }

// approvalHolds reports whether a is a valid approval over hash by the key ap. An approval carries exactly the proof its key's scheme asks for: an
// Ed25519 signature, or a WebAuthn assertion whose challenge is the intent hash. The other field present makes it invalid.
func approvalHolds(ap Approver, hash []byte, a signjob.Approval) bool {
	if ap.WebAuthn != nil {
		if a.WebAuthn == nil || len(a.Signature) != 0 {
			return false
		}
		return webauthn.Verify(ap.WebAuthn, hash, (*webauthn.Assertion)(a.WebAuthn)) == nil
	}
	return a.WebAuthn == nil && len(a.Signature) == ed25519.SignatureSize && ed25519.Verify(ap.Key, hash, a.Signature)
}
