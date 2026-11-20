package gateway

import (
	"bytes"
	"strings"
	"testing"
)

func TestDrainMetricsZeroThenCount(t *testing.T) {
	cfg := &Config{Chains: map[string]*ChainConfig{"eth": {Name: "eth"}, "base": {Name: "base"}}}
	d := &Decider{cfg: cfg, guard: &Guard{}, mode: ModeCosigner}
	var b bytes.Buffer
	d.guard.WriteDrainMetrics(&b, cfg, ModeCosigner)
	out := b.String()
	// 3 chains (eth, base, other) x every reason class, all 0, before any refusal
	if got, want := strings.Count(out, "qv_drain_refusals_total{"), 3*len(drainReasons); got != want {
		t.Fatalf("%d series, want %d", got, want)
	}
	if strings.Contains(out, "} 1") || !strings.Contains(out, `qv_drain_refusals_total{mode="cosigner",chain="eth",reason="policy_drain_cap"} 0`) {
		t.Fatalf("not zero-initialised:\n%s", out)
	}
	d.noteDrainMetric("eth", ReasonDrainCap)
	d.noteDrainMetric("eth", ReasonDrainCap)
	d.noteDrainMetric("eth", ReasonNonceTaken)           // a replay_* code is the class "replay"
	d.noteDrainMetric("0xdeadbeef-no-such-chain", "zzz") // neither label can grow without bound
	b.Reset()
	d.guard.WriteDrainMetrics(&b, cfg, ModeCosigner)
	out = b.String()
	for _, want := range []string{
		`{mode="cosigner",chain="eth",reason="policy_drain_cap"} 2`,
		`{mode="cosigner",chain="eth",reason="replay"} 1`,
		`{mode="cosigner",chain="other",reason="other"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "deadbeef") || strings.Count(out, "qv_drain_refusals_total{") != 3*len(drainReasons) {
		t.Errorf("label set grew:\n%s", out)
	}
}
