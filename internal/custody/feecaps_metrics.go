package custody

import (
	"fmt"
	"io"
	"sync/atomic"
)

// feeCapsRefusals counts the times the zone refused a withdrawal this process built, because the core and the zone were on different fee caps
// (the core reads its own fee-cap rows as a hint; the zone's record is the rule: internal/chain/btc/feecaps.go). It starts at zero.
var feeCapsRefusals atomic.Int64

// WriteFeeCapsMetrics writes the counter in the Prometheus text format; it is 0 until the first refusal, so an alert on its increase has a series
// from the start. The worker's metrics endpoint serves it (the Metrics-B task wires it).
func WriteFeeCapsMetrics(w io.Writer) {
	fmt.Fprintln(w, "# HELP qv_btc_fee_caps_zone_refusals_total Withdrawals the signing zone refused because the core built them under other fee caps than the zone's, since process start.")
	fmt.Fprintln(w, "# TYPE qv_btc_fee_caps_zone_refusals_total counter")
	fmt.Fprintf(w, "qv_btc_fee_caps_zone_refusals_total %d\n", feeCapsRefusals.Load())
}
