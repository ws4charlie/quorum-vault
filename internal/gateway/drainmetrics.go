package gateway

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
)

// qv_drain_refusals_total{mode,chain,reason}: the drains this process refused. Labels are small fixed sets: the mode of the process, a configured chain name
// (or "other"), and a reason class. Never an address, key, intent id or amount. monitoring/drain.rules.yml alerts on it.
//
// Every combination is written from the first scrape (value 0), so a first refusal is an increase that Prometheus sees; a series that appears at 1 is
// the trap that monitoring/ had to work around (reports/D10-r1.md).

// drainReasonOther collects a rejection code that is not in drainReasons, so the label set stays fixed.
const drainReasonOther = "other"

// drainReasons are the reason classes of a refused drain, as rejection codes; every replay_* code is one class "replay".
var drainReasons = []string{ReasonIntent, ReasonExpired, ReasonTx, ReasonApprovals, ReasonRequester, ReasonKeyset, ReasonDrainRate, ReasonDrainCap, "replay", drainReasonOther}

// drainChainOther collects a chain name that the config does not have (the intent names a chain the zone does not know).
const drainChainOther = "other"

// drainReasonClass maps a rejection to its class. The refusal text is "<code>: <detail>" (IsRejection); a bare code is accepted too. The detail is never a label.
func drainReasonClass(reason string) string {
	code, _, _ := strings.Cut(reason, ":")
	if strings.HasPrefix(code, "replay_") {
		return "replay"
	}
	for _, r := range drainReasons {
		if r == code {
			return code
		}
	}
	return drainReasonOther
}

type drainKey struct{ mode, chain, reason string }

// drainCounts counts refused drains by label set. The zero value is ready.
type drainCounts struct {
	mu sync.Mutex
	n  map[drainKey]uint64
}

func (c *drainCounts) add(k drainKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.n == nil {
		c.n = map[drainKey]uint64{}
	}
	c.n[k]++
}

// noteDrainMetric counts one refused drain of the given chain and rejection code.
func (d *Decider) noteDrainMetric(chain, code string) {
	if _, ok := d.cfg.Chains[chain]; !ok {
		chain = drainChainOther
	}
	d.guard.drainMetrics.add(drainKey{mode: d.mode.actorLabel(), chain: chain, reason: drainReasonClass(code)})
}

func (m Mode) actorLabel() string {
	if m == ModeCosigner {
		return "cosigner"
	}
	return "gateway"
}

// WriteDrainMetrics writes qv_drain_refusals_total in the Prometheus text format for a process of this mode, with every combination of the config's chains and
// the reason classes present (0 until the first refusal).
func (g *Guard) WriteDrainMetrics(w io.Writer, cfg *Config, mode Mode) {
	g.drainMetrics.write(w, cfg, mode.actorLabel())
}

func (c *drainCounts) write(w io.Writer, cfg *Config, mode string) {
	chains := []string{drainChainOther}
	if cfg != nil {
		for name := range cfg.Chains {
			chains = append(chains, name)
		}
	}
	sort.Strings(chains)
	c.mu.Lock()
	defer c.mu.Unlock()
	fmt.Fprintln(w, "# TYPE qv_drain_refusals_total counter")
	for _, ch := range chains {
		for _, r := range drainReasons {
			fmt.Fprintf(w, "qv_drain_refusals_total{mode=%q,chain=%q,reason=%q} %d\n", mode, ch, r, c.n[drainKey{mode, ch, r}])
		}
	}
}
