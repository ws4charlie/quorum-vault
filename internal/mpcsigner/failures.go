package mpcsigner

import (
	"fmt"
	"io"
	"sync"
)

// Failed sign calls by pair and kind, for central, read-only monitoring. The gateway only counts and writes them to its metrics file; nothing in
// the signing zone reads them back (routing is driven by the health checks, not by these counts). The pair is the pair the call went through, not a
// verdict on either party: a failure through A+B says that A, B or the link between them is suspect.

// failureKinds is the fixed label set of the counter, in the order the metrics are written.
var failureKinds = []struct {
	k    Kind
	name string
}{
	{KindTransport, "TRANSPORT"}, {KindUnavailable, "UNAVAILABLE"}, {KindCryptographic, "CRYPTOGRAPHIC"}, {KindRefused, "REFUSED"},
	{KindLimit, "LIMIT"}, {KindInternal, "INTERNAL"}, {KindFrozen, "FROZEN"},
}

type failureCounts struct {
	mu sync.Mutex
	n  map[[2]string]uint64 // pair, kind
}

func newFailureCounts() *failureCounts {
	f := &failureCounts{n: map[[2]string]uint64{}}
	for _, p := range PairOrder { // every series starts at zero, so the first failure is an increase for Prometheus
		for _, k := range failureKinds {
			f.n[[2]string{string(p), k.name}] = 0
		}
	}
	return f
}

func kindName(k Kind) string {
	for _, x := range failureKinds {
		if x.k == k {
			return x.name
		}
	}
	return "INTERNAL"
}

func (f *failureCounts) add(p Pair, k Kind) {
	if !p.Valid() {
		return
	}
	f.mu.Lock()
	f.n[[2]string{string(p), kindName(k)}]++
	f.mu.Unlock()
}

// NoteSignFailure counts one failed sign call through pair p. A call that failed on one pair and then succeeded through another is counted once
// for the pair that failed.
func (r *Router) NoteSignFailure(p Pair, k Kind) { r.fails.add(p, k) }

// SignFailures is the number counted so far for a pair and a kind name (tests and diagnostics).
func (r *Router) SignFailures(p Pair, kind string) uint64 {
	r.fails.mu.Lock()
	defer r.fails.mu.Unlock()
	return r.fails.n[[2]string{string(p), kind}]
}

func (r *Router) writeFailureMetrics(w io.Writer) {
	fmt.Fprintln(w, "# HELP qv_mpc_gateway_sign_failures_total Failed sign calls of the gateway by the pair they went through and the error kind. A failure on a pair makes A, B or the link between them suspect, not guilty. Counters only grow; use increase() or rate().")
	fmt.Fprintln(w, "# TYPE qv_mpc_gateway_sign_failures_total counter")
	r.fails.mu.Lock()
	defer r.fails.mu.Unlock()
	for _, p := range PairOrder {
		for _, k := range failureKinds {
			fmt.Fprintf(w, "qv_mpc_gateway_sign_failures_total{pair=%q,kind=%q} %d\n", string(p), k.name, r.fails.n[[2]string{string(p), k.name}])
		}
	}
}
