package custody

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// EmergencyMetrics serves what an on-call person needs when a key may be stolen (docs/runbooks/stolen-hot-key.md), read from the business database at
// every scrape:
//
//	qv_keyset_compromised{shard,generation}                 1 for every generation marked compromised (the mark never goes away)
//	qv_emergency_drain_stalled_seconds{shard,generation}    for a compromised generation: seconds since the last sign of progress (the mark, or the last
//	                                                        confirmed drain move); 0 once the core found it drained
//
// A scrape that cannot read the database says so with qv_emergency_metrics_error 1 and no series, so a broken scrape never looks like "nothing is compromised".
func EmergencyMetrics(pool *pgxpool.Pool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		writeEmergencyMetrics(r.Context(), w, pool, time.Now())
	})
}

func writeEmergencyMetrics(ctx context.Context, w io.Writer, pool *pgxpool.Pool, _ time.Time) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rows, err := pool.Query(ctx, `SELECT k.shard_id, k.generation, COALESCE(d.state, ''),
		GREATEST(0, extract(epoch FROM now() - GREATEST(k.state_changed_at, COALESCE((SELECT max(m.updated_at) FROM drain_moves m
			WHERE m.shard_id = k.shard_id AND m.from_generation = k.generation AND m.status = 'confirmed'), k.state_changed_at))))::bigint
		FROM keysets k LEFT JOIN keyset_drains d ON d.shard_id = k.shard_id AND d.generation = k.generation
		WHERE k.state = 'compromised' ORDER BY k.shard_id, k.generation`)
	if err != nil {
		fmt.Fprint(w, "# HELP qv_emergency_metrics_error 1 when the emergency metrics could not be read from the database.\n# TYPE qv_emergency_metrics_error gauge\nqv_emergency_metrics_error 1\n")
		return
	}
	defer rows.Close()
	var comp, stall strings.Builder
	for rows.Next() {
		var shard, state string
		var gen int
		var secs int64
		if err := rows.Scan(&shard, &gen, &state, &secs); err != nil {
			fmt.Fprint(w, "qv_emergency_metrics_error 1\n")
			return
		}
		if state == "drained" {
			secs = 0
		}
		fmt.Fprintf(&comp, "qv_keyset_compromised{shard=%q,generation=\"%d\"} 1\n", shard, gen)
		fmt.Fprintf(&stall, "qv_emergency_drain_stalled_seconds{shard=%q,generation=\"%d\"} %d\n", shard, gen, secs)
	}
	if rows.Err() != nil {
		fmt.Fprint(w, "qv_emergency_metrics_error 1\n")
		return
	}
	fmt.Fprint(w, "# HELP qv_emergency_metrics_error 1 when the emergency metrics could not be read from the database.\n# TYPE qv_emergency_metrics_error gauge\nqv_emergency_metrics_error 0\n")
	fmt.Fprint(w, "# HELP qv_keyset_compromised 1 for each key generation marked compromised.\n# TYPE qv_keyset_compromised gauge\n"+comp.String())
	fmt.Fprint(w, "# HELP qv_emergency_drain_stalled_seconds Seconds since a compromised generation last made progress (the mark, or its last confirmed drain move); 0 when drained.\n# TYPE qv_emergency_drain_stalled_seconds gauge\n"+stall.String())
}
