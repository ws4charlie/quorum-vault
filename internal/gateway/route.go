package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/audit"
	"github.com/ws4charlie/quorum-vault/internal/domain"
	"github.com/ws4charlie/quorum-vault/internal/mpcsigner"
)

// Which pair of parties signs a 2-of-3 keyset is an operator setting of the signing zone, and health checks of the gateway may route away from
// a pair for a while. This file is the setting; the checks and the choice are in internal/mpcsigner.
//
// The setting is GLOBAL, not per keyset: the reason to move signing is "take party X out for maintenance", which concerns every keyset on
// that party at once, and one setting is one thing to sign, audit and undo. (A per-keyset choice can be added later in the same record.)
//
// Who may change it: the approvers of this zone's own config, with the keys that already sign intents (no new key type). A change is
// signed over (pair, seq, time) by min_approvers distinct enabled approvers, and written to the guard database (the one the business zone
// cannot reach) with an audit event in the same transaction. The gateway checks the signatures again every time it reads the setting, so a
// row put there by anyone else is ignored. A route can only reduce availability: every pair runs the same checks on the same parties (B or C
// always judges the intent with its own cosigner, A never follows in a Sign), so a wrong or hostile choice can stall signing but cannot make a
// signature skip a check.

// RouteMessage is what the approvers sign for a change.
func RouteMessage(pair mpcsigner.Pair, seq int64, unixSeconds int64) []byte {
	return []byte(fmt.Sprintf("qv-mpc-route-v1\n%s\n%d\n%d", pair, seq, unixSeconds))
}

// RouteSignature is one approver's signature of a change.
type RouteSignature struct {
	Actor     string `json:"actor"`
	Signature string `json:"signature"` // hex
}

// RouteChange is a signed change of the preferred pair.
type RouteChange struct {
	Pair       string           `json:"pair"`
	Seq        int64            `json:"seq"`       // must be higher than the current one
	SignedAt   int64            `json:"signed_at"` // unix seconds
	Signatures []RouteSignature `json:"signatures"`
}

// SignRoute builds one approver's signature of a change.
func SignRoute(priv ed25519.PrivateKey, actor string, pair mpcsigner.Pair, seq int64, at time.Time) RouteChange {
	return RouteChange{Pair: string(pair), Seq: seq, SignedAt: at.Unix(),
		Signatures: []RouteSignature{{Actor: actor, Signature: hex.EncodeToString(ed25519.Sign(priv, RouteMessage(pair, seq, at.Unix())))}}}
}

// MergeRoute joins the signatures of several approvers over the same change.
func MergeRoute(parts ...RouteChange) (RouteChange, error) {
	if len(parts) == 0 {
		return RouteChange{}, errors.New("no signatures")
	}
	out := parts[0]
	out.Signatures = append([]RouteSignature(nil), parts[0].Signatures...)
	for _, p := range parts[1:] {
		if p.Pair != out.Pair || p.Seq != out.Seq || p.SignedAt != out.SignedAt {
			return RouteChange{}, errors.New("the signatures are over different changes (pair, seq or time differ)")
		}
		out.Signatures = append(out.Signatures, p.Signatures...)
	}
	return out, nil
}

// RouteConfig is the validated mpc_route section.
type RouteConfig struct {
	Parties      []mpcsigner.PartyEndpoint
	Probe        mpcsigner.MonitorConfig // Parties filled in; the rest are the health rules
	MinApprovers int                     // distinct approvers a change needs
	MaxAge       time.Duration           // how far the signing time of a change may be from now when it is applied
}

// MPCRouteFile is the mpc_route section: where the parties' caller ports are, the health rules, and how many approvers a change needs.
type MPCRouteFile struct {
	Parties []MPCRouteParty `json:"parties"` // A, B and C
	// Health rules: a party is routed away from after FailCount failed checks within FailWindow, and routed back after RecoverCount good ones in a
	// row. Defaults: probe every 5s (timeout 3s), 3 failures within 30s, 6 good checks.
	ProbeInterval string `json:"probe_interval,omitempty"`
	ProbeTimeout  string `json:"probe_timeout,omitempty"`
	FailCount     int    `json:"fail_count,omitempty"`
	FailWindow    string `json:"fail_window,omitempty"`
	RecoverCount  int    `json:"recover_count,omitempty"`
	// MinApprovers: distinct enabled approvers a change of the preferred pair needs (default 1).
	MinApprovers int `json:"min_approvers,omitempty"`
	// MaxChangeAge: how far from now the signing time of a change may be when it is applied (default "10m").
	MaxChangeAge string `json:"max_change_age,omitempty"`
}

// MPCRouteParty is one party's caller port.
type MPCRouteParty struct {
	Name      string `json:"name"` // A, B or C
	Address   string `json:"address"`
	CertFile  string `json:"cert_file"`
	KeyFile   string `json:"key_file"`
	ServerPin string `json:"server_pin"`
}

func (f *MPCRouteFile) build(enabledApprovers int) (*RouteConfig, error) {
	rc := &RouteConfig{MinApprovers: f.MinApprovers, MaxAge: 10 * time.Minute}
	if rc.MinApprovers == 0 {
		rc.MinApprovers = 1
	}
	if rc.MinApprovers < 1 || rc.MinApprovers > enabledApprovers {
		return nil, fmt.Errorf("gateway: config: mpc_route.min_approvers %d: between 1 and the %d enabled approvers", rc.MinApprovers, enabledApprovers)
	}
	th := mpcsigner.DefaultThresholds()
	if f.FailCount != 0 {
		th.FailCount = f.FailCount
	}
	if f.RecoverCount != 0 {
		th.RecoverCount = f.RecoverCount
	}
	m := mpcsigner.MonitorConfig{Interval: 5 * time.Second, Timeout: 3 * time.Second}
	for _, d := range []struct {
		name, val string
		dst       *time.Duration
	}{{"probe_interval", f.ProbeInterval, &m.Interval}, {"probe_timeout", f.ProbeTimeout, &m.Timeout}, {"fail_window", f.FailWindow, &th.Window},
		{"max_change_age", f.MaxChangeAge, &rc.MaxAge}} {
		if d.val == "" {
			continue
		}
		v, err := time.ParseDuration(d.val)
		if err != nil || v <= 0 {
			return nil, fmt.Errorf("gateway: config: mpc_route.%s %q is not a positive duration", d.name, d.val)
		}
		*d.dst = v
	}
	if err := th.Validate(m.Interval); err != nil {
		return nil, fmt.Errorf("gateway: config: mpc_route: %w", err)
	}
	m.Thresholds = th
	seen := map[string]bool{}
	for _, p := range f.Parties {
		if p.Name != "A" && p.Name != "B" && p.Name != "C" || seen[p.Name] || p.Address == "" || p.CertFile == "" || p.KeyFile == "" || p.ServerPin == "" {
			return nil, fmt.Errorf("gateway: config: mpc_route.parties: each of A, B and C once, with address, cert_file, key_file and server_pin (got %q)", p.Name)
		}
		seen[p.Name] = true
		rc.Parties = append(rc.Parties, mpcsigner.PartyEndpoint{Name: p.Name, Address: p.Address, ServerPin: p.ServerPin})
	}
	if len(seen) != 3 {
		return nil, errors.New("gateway: config: mpc_route.parties must list A, B and C")
	}
	rc.Probe = m
	return rc, nil
}

// NewRouteMonitor dials the parties named in the mpc_route section (loading the gateway's client certificates).
func NewRouteMonitor(cfg *Config, raw *MPCRouteFile) (*mpcsigner.Monitor, error) {
	mc := cfg.Route.Probe
	for i, p := range raw.Parties {
		cert, err := tls.LoadX509KeyPair(p.CertFile, p.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("gateway: mpc_route: party %s: client certificate: %w", p.Name, err)
		}
		cfg.Route.Parties[i].ClientCert = cert
	}
	mc.Parties = cfg.Route.Parties
	return mpcsigner.NewMonitor(mc)
}

// ---- storage ----

// EventRouteChanged is the audit event of an applied change of the preferred pair.
const EventRouteChanged = "mpc.route.changed"

// RouteSetting is the current preferred pair.
type RouteSetting struct {
	Pair mpcsigner.Pair
	Seq  int64 // 0: nothing was ever set, the default A+B
}

// verifyRoute counts the distinct enabled approvers of the config whose signature over the change is valid.
func verifyRoute(cfg *Config, c RouteChange) ([]string, error) {
	pair, err := mpcsigner.ParsePair(c.Pair)
	if err != nil || !pair.Valid() || c.Seq < 1 {
		return nil, fmt.Errorf("a change needs a pair (A+B, A+C or B+C) and a sequence number of at least 1")
	}
	msg := RouteMessage(pair, c.Seq, c.SignedAt)
	seen := map[string]bool{}
	var out []string
	for _, s := range c.Signatures {
		ap, ok := cfg.Approvers[s.Actor]
		if !ok || !ap.Enabled || ap.WebAuthn != nil || seen[s.Actor] { // route changes are signed with Ed25519 keys only
			continue
		}
		sig, err := hex.DecodeString(s.Signature)
		if err == nil && len(sig) == ed25519.SignatureSize && ed25519.Verify(ap.Key, msg, sig) {
			seen[s.Actor] = true
			out = append(out, s.Actor)
		}
	}
	sort.Strings(out)
	need := 1
	if cfg.Route != nil {
		need = cfg.Route.MinApprovers
	}
	if len(out) < need {
		return nil, fmt.Errorf("%d valid signatures of configured, enabled approvers, %d needed", len(out), need)
	}
	return out, nil
}

// ApplyRoute checks a signed change and records it, with its audit event, in one transaction. A change that is unsigned, signed by too few or
// unknown approvers, stale, or not newer than the current one is refused and nothing changes.
func (g *Guard) ApplyRoute(ctx context.Context, cfg *Config, c RouteChange, now time.Time) error {
	approvers, err := verifyRoute(cfg, c)
	if err != nil {
		return fmt.Errorf("gateway: route change refused: %w", err)
	}
	maxAge := 10 * time.Minute
	if cfg.Route != nil {
		maxAge = cfg.Route.MaxAge
	}
	if age := now.Sub(time.Unix(c.SignedAt, 0)); age > maxAge || age < -maxAge {
		return fmt.Errorf("gateway: route change refused: signed %s from now, the limit is %s", age.Round(time.Second), maxAge)
	}
	pair, _ := mpcsigner.ParsePair(c.Pair)
	sigs, _ := json.Marshal(c.Signatures)
	tx, err := g.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('qv-mpc-route'))`); err != nil {
		return err
	}
	var cur int64
	var prev string
	err = tx.QueryRow(ctx, `SELECT seq, pair FROM mpc_route_changes ORDER BY seq DESC LIMIT 1`).Scan(&cur, &prev)
	if errors.Is(err, pgx.ErrNoRows) {
		cur, prev = 0, string(mpcsigner.PairAB)
	} else if err != nil {
		return err
	}
	if c.Seq <= cur {
		return fmt.Errorf("gateway: route change refused: sequence %d is not higher than the current %d", c.Seq, cur)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO mpc_route_changes (seq, pair, signed_at, signatures) VALUES ($1, $2, $3, $4)`, c.Seq, string(pair), c.SignedAt, sigs); err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]any{"from": prev, "to": string(pair), "seq": c.Seq, "approvers": approvers, "signed_at": c.SignedAt})
	if _, err := audit.AppendTx(ctx, tx, domain.AuditEvent{Actor: ModeGateway.actor(), Type: EventRouteChanged, Payload: payload}, ""); err != nil {
		return fmt.Errorf("gateway: audit %s: %w", EventRouteChanged, err)
	}
	return tx.Commit(ctx)
}

// CurrentRoute is the newest row whose signatures verify against cfg; rows that do not verify are skipped (and counted in skipped, so the
// caller can raise an alert). No valid row: A+B.
func (g *Guard) CurrentRoute(ctx context.Context, cfg *Config) (cur RouteSetting, skipped int, err error) {
	rows, err := g.pool.Query(ctx, `SELECT seq, pair, signed_at, signatures FROM mpc_route_changes ORDER BY seq DESC`)
	if err != nil {
		return RouteSetting{}, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var c RouteChange
		var sigs []byte
		if err := rows.Scan(&c.Seq, &c.Pair, &c.SignedAt, &sigs); err != nil {
			return RouteSetting{}, skipped, err
		}
		if json.Unmarshal(sigs, &c.Signatures) == nil {
			if _, verr := verifyRoute(cfg, c); verr == nil {
				p, _ := mpcsigner.ParsePair(c.Pair)
				return RouteSetting{Pair: p, Seq: c.Seq}, skipped, nil
			}
		}
		skipped++
	}
	if err := rows.Err(); err != nil {
		return RouteSetting{}, skipped, err
	}
	return RouteSetting{Pair: mpcsigner.PairAB}, skipped, nil
}

// PreferredSource is the Router's source of the operators' choice: the current signed setting of this guard database.
func (g *Guard) PreferredSource(cfg *Config, onSkipped func(n int)) func(context.Context) (mpcsigner.Pair, error) {
	return func(ctx context.Context) (mpcsigner.Pair, error) {
		cur, skipped, err := g.CurrentRoute(ctx, cfg)
		if err != nil {
			return "", err
		}
		if skipped > 0 && onSkipped != nil {
			onSkipped(skipped)
		}
		return cur.Pair, nil
	}
}
