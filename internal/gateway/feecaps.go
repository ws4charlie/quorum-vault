package gateway

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
)

// Signed fee caps of a Bitcoin chain: the zone's side. The rules, the signatures and the storage are in internal/chain/btc/feecaps.go (the core uses
// the same code); this file gives them the zone's approvers and its guard database. The zone reads the newest valid record before every decision, so
// a change applies to the next build or bump and a transaction already signed is not touched.

// FeeCapsRules are the rules the zone judges a change of the fee caps of chain by, or nil when the chain is not a Bitcoin chain or accepts none
// (no fee_caps_change section). Approvers count by identity, and only enabled Ed25519 keys sign: the keys that already sign intents, no new key type.
func (c *Config) FeeCapsRules(chain string) *btc.FeeCapsRules {
	return c.FeeCapsRulesFor(chain, c.Approvers)
}

// FeeCapsRulesFor is FeeCapsRules with an approver set of the caller's: the effective set of a decision (approvers.go) instead of the config's alone.
func (c *Config) FeeCapsRulesFor(chain string, approvers map[string]Approver) *btc.FeeCapsRules {
	cc := c.Chains[chain]
	if cc == nil || cc.Family != FamilyBTC || cc.BTC.FeeCaps == nil {
		return nil
	}
	p := cc.BTC.FeeCaps
	r := &btc.FeeCapsRules{Chain: chain, Approvers: map[string]btc.FeeCapsApprover{}, MinApprovers: p.MinApprovers, MaxAge: p.MaxAge, Bounds: &p.Bounds,
		MaxInputs: cc.BTC.MaxInputs, MaxPayments: max(1, cc.BTC.MaxBatchOutputs)}
	for name, ap := range approvers {
		if ap.Enabled && ap.WebAuthn == nil {
			r.Approvers[name] = btc.FeeCapsApprover{Key: ap.Key, Identity: ap.Identity}
		}
	}
	return r
}

// FeeCapsStatic is the caps of the configuration of a Bitcoin chain: the caps until the first signed change.
func (c *Config) FeeCapsStatic(chain string) btc.FeeCaps {
	cc := c.Chains[chain]
	return btc.FeeCaps{MaxTxFeeSats: cc.BTC.MaxTxFeeSats, MaxFeeRate: cc.BTC.MaxFeeRate}
}

// feeCapsRefresher is what a Bitcoin codec offers the decider.
type feeCapsRefresher interface {
	BindFeeCaps(rules *btc.FeeCapsRules, q btc.Queryer, onSkip func(skipped int))
	// SetFeeCapsRules replaces the rules a bound view judges changes by (the approvers of the effective set).
	SetFeeCapsRules(rules *btc.FeeCapsRules)
	RefreshFeeCaps(ctx context.Context) error
}

// bindFeeCaps gives every Bitcoin codec that accepts signed changes its record: the guard database. Called once, by NewDecider.
func bindFeeCaps(cfg *Config, codecs map[string]ChainCodec, guard *Guard) {
	if guard == nil {
		return
	}
	for name, codec := range codecs {
		if fc, ok := codec.(feeCapsRefresher); ok {
			if rules := cfg.FeeCapsRules(name); rules != nil {
				chainName := name
				fc.BindFeeCaps(rules, guard.pool, func(n int) {
					slog.Error("ALERT btc fee caps: rows of the fee-cap table do not carry valid approver signatures and are ignored", "chain", chainName, "rows", n)
				})
			}
		}
	}
}

// refreshFeeCaps reads the current record of a codec that has one, judged by the approvers in force now (set). An error is an outage, not a
// refusal: the caller retries.
func (d *Decider) refreshFeeCaps(ctx context.Context, name string, codec ChainCodec, set *ApproverSet) error {
	fc, ok := codec.(feeCapsRefresher)
	if !ok {
		return nil
	}
	if d.cfg.Operators != nil {
		if rules := d.cfg.FeeCapsRulesFor(name, set.Approvers); rules != nil {
			fc.SetFeeCapsRules(rules)
		}
	}
	return fc.RefreshFeeCaps(ctx)
}

// ApplyFeeCaps checks a signed change and records it, with its audit event, in one transaction. A change that is unsigned, signed by too few or
// unknown approvers (or by one person twice), stale, outside the zone's bounds, below the start-up rule, or not newer than the current one is
// refused and nothing changes. actor names the zone process in the audit event (gateway, cosigner).
func (g *Guard) ApplyFeeCaps(ctx context.Context, cfg *Config, c btc.FeeCapsChange, now time.Time, actor string) error {
	set, err := g.EffectiveApprovers(ctx, cfg)
	if err != nil {
		return err
	}
	rules := cfg.FeeCapsRulesFor(c.Chain, set.Approvers)
	if rules == nil {
		return fmt.Errorf("gateway: fee caps change refused: chain %q accepts no signed fee-cap changes (no fee_caps_change section)", c.Chain)
	}
	return btc.ApplyFeeCaps(ctx, g.pool, *rules, cfg.FeeCapsStatic(c.Chain), c, now, actor)
}

// CurrentFeeCaps is the newest record of chain that verifies, and how many newer rows did not.
func (g *Guard) CurrentFeeCaps(ctx context.Context, cfg *Config, chain string) (btc.FeeCapsRecord, int, error) {
	set, err := g.EffectiveApprovers(ctx, cfg)
	if err != nil {
		return btc.FeeCapsRecord{}, 0, err
	}
	rules := cfg.FeeCapsRulesFor(chain, set.Approvers)
	if rules == nil {
		return btc.FeeCapsRecord{FeeCaps: cfg.FeeCapsStatic(chain)}, 0, nil
	}
	return btc.CurrentFeeCaps(ctx, g.pool, *rules, cfg.FeeCapsStatic(chain))
}
