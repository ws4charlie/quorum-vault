package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/audit"
	"github.com/ws4charlie/quorum-vault/internal/domain"
	"github.com/ws4charlie/quorum-vault/internal/gatecred"
	"github.com/ws4charlie/quorum-vault/internal/partition"
)

// The Gate setting (docs/gate-credential.md, "Keys and rotation" and "Gate-governed wallets and the fast lane") says which wallets pay only with a
// Gate credential, what a credential must name (this deployment's audience), which Gate keys sign credentials, the clock limits, and each wallet's
// fast-lane limits. Whoever can change it can mint payments, so it is kept like the approver registry: a version of the whole setting is signed by
// min_operators distinct zone operators, stored append-only in the guard database of the gateway and of every cosigner, and checked again at every
// read, so a row written by anyone else is ignored (counted, ALERT). The effective setting is the highest version whose signatures and content verify.
//
// The config file holds only the bootstrap key set (section "gate"), used as Gate's keys before any signed version names its own, as the approver
// registry's bootstrap approvers are. A signed version may retire a bootstrap key without a restart; a retired kid and a retired public key are never
// used again (the retirement of every version applied so far holds for every later one). A zone with no signed version has no Gate-governed wallet.
//
// A wallet is named by a hot partition id, as the business zone names its wallets (lead decision on GC4-q1). The zone governs the whole hot shard of
// that partition: every partition of the same shard (every asset) and every address of every generation of the shard, so neither another asset's
// partition nor a key replacement opens a way around the credential (gaterule.go, walletFor).

// EventGateSettingChanged is the audit event of an applied version.
const EventGateSettingChanged = "gate.setting_changed"

const gateChangeDomain = "qv-gate-setting-v1\n"

// GateFile is the config section "gate": the bootstrap key set only.
type GateFile struct {
	BootstrapKeys []GateKeyFile `json:"bootstrap_keys"`
}

// GateKeyFile is one Gate public key: its kid, the 32-byte Ed25519 key in base64url without padding, and the Unix seconds from which (not_before) and
// until which (not_after, exclusive; 0 = no end) it verifies credentials.
type GateKeyFile struct {
	KID       string `json:"kid"`
	PublicKey string `json:"public_key"`
	NotBefore int64  `json:"not_before,omitempty"`
	NotAfter  int64  `json:"not_after,omitempty"`
}

// GateLimitFile is the fast lane of one asset of one wallet, in the asset's base units: the largest single payment, and the totals of credential-only
// payments in a rolling hour and a rolling day.
type GateLimitFile struct {
	PerPayment string `json:"per_payment"`
	PerHour    string `json:"per_hour"`
	PerDay     string `json:"per_day"`
}

// GateWalletFile is one Gate-governed wallet: Gate's wallet id (what credentials name), the hot partition the zone knows it by, and its fast-lane
// limits by the zone's asset symbol (an asset not listed has all three at 0, so it pays nothing).
type GateWalletFile struct {
	WalletID  string                   `json:"wallet_id"`
	Partition string                   `json:"partition"`
	Limits    map[string]GateLimitFile `json:"limits,omitempty"`
}

// GateSettingFile is the content of one version, as operators write and sign it.
type GateSettingFile struct {
	Audience      string           `json:"audience"`
	Keys          []GateKeyFile    `json:"keys,omitempty"`
	Retired       []string         `json:"retired,omitempty"` // kids retired for good (bootstrap ones included)
	SkewSeconds   int64            `json:"skew_seconds,omitempty"`
	MaxTTLSeconds int64            `json:"max_ttl_seconds,omitempty"`
	Wallets       []GateWalletFile `json:"wallets"`
}

// GateChange is a signed version of the Gate setting.
type GateChange struct {
	Version    int64               `json:"version"`   // must be higher than the current one
	SignedAt   int64               `json:"signed_at"` // unix seconds
	Setting    GateSettingFile     `json:"setting"`
	Signatures []OperatorSignature `json:"signatures"`
}

// GateChangeMessage is what the operators sign: a domain prefix and the change without its signatures, as JSON of a fixed field order (maps are
// written with sorted keys).
func GateChangeMessage(c GateChange) []byte {
	body, _ := json.Marshal(struct {
		Version  int64           `json:"version"`
		SignedAt int64           `json:"signed_at"`
		Setting  GateSettingFile `json:"setting"`
	}{c.Version, c.SignedAt, c.Setting})
	return append([]byte(gateChangeDomain), body...)
}

// SignGateChange adds one operator's signature to c (whose Signatures it replaces).
func SignGateChange(priv ed25519.PrivateKey, operator string, c GateChange) GateChange {
	c.Signatures = []OperatorSignature{{Operator: operator, Signature: hex.EncodeToString(ed25519.Sign(priv, GateChangeMessage(c)))}}
	return c
}

// MergeGateChanges joins the signatures of several operators over the same version.
func MergeGateChanges(parts ...GateChange) (GateChange, error) {
	if len(parts) == 0 {
		return GateChange{}, errors.New("no signatures")
	}
	out := parts[0]
	out.Signatures = slices.Clone(parts[0].Signatures)
	for _, p := range parts[1:] {
		if !bytes.Equal(GateChangeMessage(p), GateChangeMessage(out)) {
			return GateChange{}, errors.New("the signatures are over different versions (version, time or setting differ)")
		}
		out.Signatures = append(out.Signatures, p.Signatures...)
	}
	return out, nil
}

// GateKey is a validated Gate public key.
type GateKey struct {
	KID       string
	Public    ed25519.PublicKey
	NotBefore int64
	NotAfter  int64 // 0: no end
}

// usableAt reports whether the key verifies credentials at t (the checker's own clock).
func (k GateKey) usableAt(t int64) bool {
	return t >= k.NotBefore && (k.NotAfter == 0 || t < k.NotAfter)
}

// GateLimits is a validated fast lane of one asset.
type GateLimits struct {
	PerPayment, PerHour, PerDay *big.Int
}

// GateWallet is a validated Gate-governed wallet.
type GateWallet struct {
	WalletID  string
	Partition string
	Limits    map[string]GateLimits
}

// limits returns the fast lane of an asset; an asset not listed has all three limits at 0.
func (w *GateWallet) limits(asset string) GateLimits {
	if l, ok := w.Limits[asset]; ok {
		return l
	}
	return GateLimits{PerPayment: new(big.Int), PerHour: new(big.Int), PerDay: new(big.Int)}
}

// GateSetting is the setting in force: the bootstrap keys with the verified log applied.
type GateSetting struct {
	// Version is the version applied (0: none, so no wallet is Gate-governed).
	Version  int64
	Audience string
	// Keys are the keys that are not retired, bootstrap ones first, by kid. Which of them verifies is decided at verification time (usableAt).
	Keys    []GateKey
	Skew    time.Duration
	MaxTTL  time.Duration
	Wallets []GateWallet
	// Ignored counts the rows of the log that did not verify (signatures, order, content) and were skipped.
	Ignored int

	retiredKIDs map[string]bool
	retiredKeys map[string]bool // public keys, as strings
	applied     map[int64][]byte
}

// KeysAt is the key set of a verification at t: the keys usable at that moment, by kid.
func (s *GateSetting) KeysAt(t time.Time) map[string]ed25519.PublicKey {
	out := map[string]ed25519.PublicKey{}
	for _, k := range s.Keys {
		if k.usableAt(t.Unix()) {
			out[k.KID] = k.Public
		}
	}
	return out
}

// Wallet returns the wallet with Gate's id, or nil.
func (s *GateSetting) Wallet(id string) *GateWallet {
	for i := range s.Wallets {
		if s.Wallets[i].WalletID == id {
			return &s.Wallets[i]
		}
	}
	return nil
}

func (s *GateSetting) clone() *GateSetting {
	c := *s
	c.Keys, c.Wallets = slices.Clone(s.Keys), slices.Clone(s.Wallets)
	c.retiredKIDs, c.retiredKeys, c.applied = cloneSet(s.retiredKIDs), cloneSet(s.retiredKeys), map[int64][]byte{}
	for k, v := range s.applied {
		c.applied[k] = v
	}
	return &c
}

func cloneSet(m map[string]bool) map[string]bool {
	out := make(map[string]bool, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

var reKID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
var reWalletID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// build validates one key entry.
func (k GateKeyFile) build() (GateKey, error) {
	if !reKID.MatchString(k.KID) {
		return GateKey{}, fmt.Errorf("kid %q is not 1-64 characters of [A-Za-z0-9._-]", k.KID)
	}
	pub, ok := gatecred.DecodeBase64URL(k.PublicKey, ed25519.PublicKeySize)
	if !ok {
		return GateKey{}, fmt.Errorf("key %q: public_key must be %d bytes in base64url without padding", k.KID, ed25519.PublicKeySize)
	}
	if k.NotBefore < 0 || k.NotAfter < 0 || (k.NotAfter != 0 && k.NotAfter <= k.NotBefore) {
		return GateKey{}, fmt.Errorf("key %q: not_after must be 0 (no end) or after not_before", k.KID)
	}
	return GateKey{KID: k.KID, Public: ed25519.PublicKey(pub), NotBefore: k.NotBefore, NotAfter: k.NotAfter}, nil
}

// build validates the config section: at least one key, kids and keys distinct. A node with a bad section does not start.
func (f *GateFile) build() ([]GateKey, error) {
	if len(f.BootstrapKeys) == 0 {
		return nil, errors.New("gateway: config: gate.bootstrap_keys is empty (leave the gate section out when Gate has no key yet)")
	}
	var out []GateKey
	for _, kf := range f.BootstrapKeys {
		k, err := kf.build()
		if err != nil {
			return nil, fmt.Errorf("gateway: config: gate: %w", err)
		}
		for _, o := range out {
			if o.KID == k.KID || bytes.Equal(o.Public, k.Public) {
				return nil, fmt.Errorf("gateway: config: gate: keys %q and %q share a kid or a public key", o.KID, k.KID)
			}
		}
		out = append(out, k)
	}
	return out, nil
}

// StaticGate is the setting of the config alone: the bootstrap keys and no Gate-governed wallet.
func (c *Config) StaticGate() *GateSetting {
	return &GateSetting{Keys: slices.Clone(c.GateBootstrap), Skew: gatecred.DefaultSkew, MaxTTL: gatecred.DefaultMaxTTL,
		retiredKIDs: map[string]bool{}, retiredKeys: map[string]bool{}, applied: map[int64][]byte{}}
}

// apply puts one version into the setting. strict adds the checks of applying a new version against this zone's config (every wallet is a hot
// partition of an EVM chain here, every limit an asset of that chain); reading the log back applies what the version itself makes valid, so a signed
// retirement is never dropped because the config changed since. A refused version leaves the setting as it was.
func (s *GateSetting) apply(cfg *Config, c GateChange, strict bool) error {
	f := c.Setting
	if c.Version < 1 {
		return errors.New("a version is at least 1")
	}
	next := s.clone()
	for _, kid := range f.Retired {
		if !reKID.MatchString(kid) {
			return fmt.Errorf("retired kid %q is not a kid", kid)
		}
		next.retiredKIDs[kid] = true
	}
	// The complete retired set of this version first: what earlier versions retired, and the public key of every key known so far (bootstrap or
	// earlier version) whose kid this version retires. Every candidate key is then checked against it by public key, so a key retired now cannot come
	// back in the same version under a new kid, and one retired before never comes back under any kid.
	for _, k := range append(slices.Clone(s.Keys), cfg.GateBootstrap...) {
		if next.retiredKIDs[k.KID] {
			next.retiredKeys[string(k.Public)] = true
		}
	}
	// The key set: the bootstrap keys and this version's, without what is retired. A key a version names that is retired (by kid or by public key)
	// refuses the version: retired is for good.
	keys := map[string]GateKey{}
	order := []string{}
	for _, k := range cfg.GateBootstrap {
		if next.retiredKIDs[k.KID] || next.retiredKeys[string(k.Public)] {
			continue
		}
		keys[k.KID] = k
		order = append(order, k.KID)
	}
	seen := map[string]bool{}
	for _, kf := range f.Keys {
		k, err := kf.build()
		if err != nil {
			return err
		}
		if seen[k.KID] {
			return fmt.Errorf("kid %q is listed twice", k.KID)
		}
		seen[k.KID] = true
		if next.retiredKIDs[k.KID] || next.retiredKeys[string(k.Public)] {
			return fmt.Errorf("key %q was retired: a retired kid or key is never used again", k.KID)
		}
		if b, ok := keys[k.KID]; ok && !bytes.Equal(b.Public, k.Public) {
			return fmt.Errorf("kid %q is a bootstrap key with another public key", k.KID)
		}
		if _, ok := keys[k.KID]; !ok {
			order = append(order, k.KID)
		}
		keys[k.KID] = k
	}
	for _, kid := range order {
		for _, other := range order {
			if kid < other && bytes.Equal(keys[kid].Public, keys[other].Public) {
				return fmt.Errorf("keys %q and %q are the same public key", kid, other)
			}
		}
	}
	kmap := map[string]ed25519.PublicKey{}
	next.Keys = nil
	for _, kid := range order {
		next.Keys = append(next.Keys, keys[kid])
		kmap[kid] = keys[kid].Public
	}
	if f.SkewSeconds < 0 || f.MaxTTLSeconds < 0 {
		return errors.New("skew_seconds and max_ttl_seconds are not negative")
	}
	gc, err := gatecred.NewConfig(f.Audience, kmap, time.Duration(f.SkewSeconds)*time.Second, time.Duration(f.MaxTTLSeconds)*time.Second)
	if err != nil {
		return err
	}
	next.Audience, next.Skew, next.MaxTTL = gc.Audience, gc.Skew, gc.MaxTTL

	// The wallets: one entry per Gate wallet id and per hot shard.
	next.Wallets = nil
	ids, shards := map[string]bool{}, map[string]string{}
	for _, wf := range f.Wallets {
		if !reWalletID.MatchString(wf.WalletID) {
			return fmt.Errorf("wallet_id %q is not a lower-case UUID", wf.WalletID)
		}
		if ids[wf.WalletID] {
			return fmt.Errorf("wallet %s is listed twice", wf.WalletID)
		}
		ids[wf.WalletID] = true
		if wf.Partition == "" {
			return fmt.Errorf("wallet %s names no partition", wf.WalletID)
		}
		shard := wf.Partition
		if k, err := partition.Parse(wf.Partition); err == nil && k.Tier == partition.TierHot {
			shard = string(k.ShardID())
		}
		if other, dup := shards[shard]; dup {
			return fmt.Errorf("wallets %s and %s are the same hot shard: one wallet per shard", other, wf.WalletID)
		}
		shards[shard] = wf.WalletID
		w := GateWallet{WalletID: wf.WalletID, Partition: wf.Partition, Limits: map[string]GateLimits{}}
		for asset, lf := range wf.Limits {
			if asset == "" {
				return fmt.Errorf("wallet %s: a limit names no asset", wf.WalletID)
			}
			var l GateLimits
			for _, v := range []struct {
				what string
				s    string
				dst  **big.Int
			}{{"per_payment", lf.PerPayment, &l.PerPayment}, {"per_hour", lf.PerHour, &l.PerHour}, {"per_day", lf.PerDay, &l.PerDay}} {
				n, err := amount(fmt.Sprintf("wallet %s %s %s", wf.WalletID, asset, v.what), v.s)
				if err != nil {
					return err
				}
				*v.dst = n
			}
			w.Limits[asset] = l
		}
		if strict {
			if err := cfg.gateWalletFits(w); err != nil {
				return fmt.Errorf("wallet %s: %w", wf.WalletID, err)
			}
		}
		next.Wallets = append(next.Wallets, w)
	}
	next.Version = c.Version
	next.applied[c.Version] = GateChangeMessage(c)
	*s = *next
	return nil
}

// gateWalletFits checks a wallet against this zone's config: its partition is a hot partition of an EVM chain here (credentials name EVM payments
// only in version 1), and every limit is an asset of that chain.
func (c *Config) gateWalletFits(w GateWallet) error {
	for _, cc := range c.Chains {
		if cc.Family != "" && cc.Family != FamilyEVM {
			continue
		}
		if _, ok := cc.EVM.HotAddresses[w.Partition]; !ok {
			continue
		}
		for asset := range w.Limits {
			if _, ok := cc.Assets[asset]; !ok {
				return fmt.Errorf("limit for %q: no such asset on chain %q", asset, cc.Name)
			}
		}
		return nil
	}
	return fmt.Errorf("partition %q is not a hot partition of an EVM chain of this zone", w.Partition)
}

// foldGate is the effective setting: the bootstrap keys with every row of the log that verifies applied in version order. A row is ignored (and
// counted) when its signatures do not satisfy the operators of the config, its version is not higher than the last one applied, or its content does not
// hold.
func (c *Config) foldGate(rows []GateChange) *GateSetting {
	s := c.StaticGate()
	for _, r := range rows {
		if _, err := c.Operators.verifyMsg(GateChangeMessage(r), r.Signatures); err != nil || r.Version <= s.Version {
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

func loadGateRows(ctx context.Context, q queryer) ([]GateChange, error) {
	rows, err := q.Query(ctx, `SELECT version, setting, signed_at, signatures FROM gate_setting_changes ORDER BY version, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GateChange
	for rows.Next() {
		var c GateChange
		var setting, sigs []byte
		if err := rows.Scan(&c.Version, &setting, &c.SignedAt, &sigs); err != nil {
			return nil, err
		}
		// A row that does not parse stays in the list as a version nothing can verify (no signatures), so it is counted.
		dec := json.NewDecoder(bytes.NewReader(setting))
		dec.DisallowUnknownFields()
		if dec.Decode(&c.Setting) != nil || json.Unmarshal(sigs, &c.Signatures) != nil {
			c.Signatures = nil
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// EffectiveGate reads the guard database's log and returns the setting in force. Without an operators section no version can verify: the config's
// bootstrap keys and no Gate-governed wallet. An error is an outage: the caller retries.
func (g *Guard) EffectiveGate(ctx context.Context, cfg *Config) (*GateSetting, error) {
	if cfg.Operators == nil || g == nil {
		return cfg.StaticGate(), nil
	}
	rows, err := loadGateRows(ctx, g.pool)
	if err != nil {
		return nil, fmt.Errorf("gateway: read gate setting: %w", err)
	}
	s := cfg.foldGate(rows)
	if s.Ignored > 0 && g.gateIgnored.Swap(int64(s.Ignored)) != int64(s.Ignored) {
		slog.Error("ALERT gate setting: rows of the gate_setting_changes table do not carry valid operator signatures (or do not fit) and are ignored", "rows", s.Ignored)
	}
	return s, nil
}

// ApplyGateChange checks a signed version and records it, with its audit event, in one transaction. A version signed by too few operators, stale, not
// newer than the log, re-using a retired key, or naming a wallet that is not a hot partition of an EVM chain of this zone is refused and nothing
// changes. The same version applied twice is not an error (so an operator can finish applying it to the other databases).
func (g *Guard) ApplyGateChange(ctx context.Context, cfg *Config, c GateChange, now time.Time, actor string) error {
	refuse := func(err error) error { return fmt.Errorf("gateway: gate setting refused: %w", err) }
	if cfg.Operators == nil {
		return refuse(errors.New("the zone's config has no operators section: the gate setting cannot be signed"))
	}
	operators, err := cfg.Operators.verifyMsg(GateChangeMessage(c), c.Signatures)
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
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('qv-gate-setting'))`); err != nil {
		return err
	}
	rows, err := loadGateRows(ctx, tx)
	if err != nil {
		return err
	}
	cur := cfg.foldGate(rows)
	if msg, done := cur.applied[c.Version]; done && bytes.Equal(msg, GateChangeMessage(c)) {
		return nil // already applied
	}
	if c.Version <= cur.Version {
		return refuse(fmt.Errorf("version %d is not higher than the current %d", c.Version, cur.Version))
	}
	next := cur.clone()
	if err := next.apply(cfg, c, true); err != nil {
		return refuse(err)
	}
	setting, _ := json.Marshal(c.Setting)
	sigs, _ := json.Marshal(c.Signatures)
	if _, err := tx.Exec(ctx, `INSERT INTO gate_setting_changes (version, setting, signed_at, signatures) VALUES ($1, $2, $3, $4)`,
		c.Version, setting, c.SignedAt, sigs); err != nil {
		return err
	}
	var wallets, kids []string
	for _, w := range next.Wallets {
		wallets = append(wallets, w.WalletID+"="+w.Partition)
	}
	for _, k := range next.Keys {
		kids = append(kids, k.KID)
	}
	sort.Strings(wallets)
	pj, _ := json.Marshal(map[string]any{"version": c.Version, "operators": operators, "signed_at": c.SignedAt, "audience": next.Audience,
		"kids": kids, "retired": c.Setting.Retired, "wallets": wallets, "skew_seconds": int64(next.Skew / time.Second),
		"max_ttl_seconds": int64(next.MaxTTL / time.Second)})
	if _, err := audit.AppendTx(ctx, tx, domain.AuditEvent{Actor: actor, Type: EventGateSettingChanged, Payload: pj}, ""); err != nil {
		return fmt.Errorf("gateway: audit %s: %w", EventGateSettingChanged, err)
	}
	return tx.Commit(ctx)
}

// Describe is a one-line summary of the setting, for operator tools.
func (s *GateSetting) Describe() string {
	if s.Version == 0 {
		return "no signed version: no wallet is Gate-governed"
	}
	var kids, wallets []string
	for _, k := range s.Keys {
		kids = append(kids, k.KID)
	}
	for _, w := range s.Wallets {
		wallets = append(wallets, w.WalletID+" ("+w.Partition+")")
	}
	return fmt.Sprintf("version %d, audience %q, keys %s, wallets %s", s.Version, s.Audience, strings.Join(kids, ","), strings.Join(wallets, ", "))
}
