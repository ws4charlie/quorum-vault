package custody

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestEmergencyMetricsShowACompromisedGenerationAndItsStall(t *testing.T) {
	s, _ := newSvc(t)
	ctx := WithActor(context.Background(), "admin1")
	scrape := func() string {
		var b strings.Builder
		writeEmergencyMetrics(ctx, &b, s.Pool, time.Now())
		return b.String()
	}
	// Nothing is compromised: no series, and no error.
	if m := scrape(); !strings.Contains(m, "qv_emergency_metrics_error 0") || strings.Contains(m, "qv_keyset_compromised{") {
		t.Fatalf("before:\n%s", m)
	}
	if _, err := s.RegisterKeysetCandidate(ctx, shard0(s), gen2Addr, "keyset-2"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.MarkKeysetCompromised(ctx, shard0(s), 1, 2); err != nil {
		t.Fatal(err)
	}
	m := scrape()
	want := `qv_keyset_compromised{shard="` + shard0(s) + `",generation="1"} 1`
	if !strings.Contains(m, want) || !strings.Contains(m, `qv_emergency_drain_stalled_seconds{shard="`+shard0(s)+`",generation="1"} `) {
		t.Fatalf("after the mark:\n%s", m)
	}
	// Found drained: the stall is 0, the generation is still listed.
	if _, err := s.Pool.Exec(ctx, `UPDATE keysets SET state_changed_at = now() - interval '1 hour' WHERE shard_id=$1 AND generation=1`, shard0(s)); err != nil {
		t.Fatal(err)
	}
	if m := scrape(); !strings.Contains(m, `generation="1"} 3`) { // 3600 s
		t.Fatalf("an hour without progress:\n%s", m)
	}
	if _, err := s.Pool.Exec(ctx, `INSERT INTO keyset_drains (shard_id, generation, state) VALUES ($1,1,'drained')`, shard0(s)); err != nil {
		t.Fatal(err)
	}
	if m := scrape(); !strings.Contains(m, `qv_emergency_drain_stalled_seconds{shard="`+shard0(s)+`",generation="1"} 0`) || !strings.Contains(m, want) {
		t.Fatalf("drained:\n%s", m)
	}
}
