package mpcsigner

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

// Each failed sign call is counted once, by the pair it went through and its kind; the route does not change.
func TestGatewayCountsFailedSignCallsByPairAndKind(t *testing.T) {
	kinds := []struct {
		k    pb.ErrorKind
		code codes.Code
		name string
	}{
		{pb.ErrorKind_ERROR_KIND_REFUSED, codes.PermissionDenied, "REFUSED"},
		{pb.ErrorKind_ERROR_KIND_CRYPTOGRAPHIC, codes.Aborted, "CRYPTOGRAPHIC"},
		{pb.ErrorKind_ERROR_KIND_FROZEN, codes.FailedPrecondition, "FROZEN"},
		{pb.ErrorKind_ERROR_KIND_LIMIT, codes.ResourceExhausted, "LIMIT"},
		{pb.ErrorKind_ERROR_KIND_INTERNAL, codes.Internal, "INTERNAL"},
	}
	for _, pref := range []struct {
		pair  Pair
		coord string
	}{{PairAB, "A"}, {PairAC, "A"}, {PairBC, "B"}} {
		for _, c := range kinds {
			r := newRig(t, th(3, 30*time.Second, 2))
			r.pref.Store(pref.pair)
			r.parties[pref.coord].failSign = func(int) error { return typedCode(c.code, c.k, 0, "x") }
			if _, err := r.sign("job"); err == nil {
				t.Fatalf("%s %s: signed", pref.pair, c.name)
			}
			// every failed call counts once: the final kinds end the job at the first call, LIMIT is retried by the round rule
			calls := uint64(r.parties[pref.coord].signs.Load())
			if got := r.router.SignFailures(pref.pair, c.name); got != calls || calls == 0 {
				t.Fatalf("%s %s: counted %d for %d calls", pref.pair, c.name, got, calls)
			}
			var total uint64
			for _, p := range PairOrder {
				for _, k := range failureKinds {
					total += r.router.SignFailures(p, k.name)
				}
			}
			if total != calls {
				t.Fatalf("%s %s: %d counts in all, want %d (only the failed pair and kind)", pref.pair, c.name, total, calls)
			}
		}
	}
}

// An availability failure before signing rescues the job on another pair: the failed pair is counted, the pair that signed is not. (A coordinator
// that did not answer at all is skipped for its other pairs, so the rescue is B+C.)
func TestGatewayCountsTheFailedPairNotTheRescuingOne(t *testing.T) {
	r := newRig(t, th(3, 30*time.Second, 2))
	n := 0
	r.parties["A"].failSign = func(int) error {
		n++
		if n == 1 {
			return errBefore(pb.ErrorKind_ERROR_KIND_TRANSPORT)
		}
		return nil
	}
	got, err := r.sign("rescued")
	if err != nil || got != PairBC {
		t.Fatalf("pair %q err %v", got, err)
	}
	if r.router.SignFailures(PairAB, "TRANSPORT") != 1 || r.router.SignFailures(PairBC, "TRANSPORT") != 0 {
		t.Fatal("the failed pair, and only it, must be counted")
	}
	if p := r.router.Plan(context.Background()); p.Effective != PairAB {
		t.Fatal("counting a failure moved the route")
	}
}

func TestGatewayFailureMetricsText(t *testing.T) {
	r := newRig(t, th(3, 30*time.Second, 2))
	var b strings.Builder
	r.router.WriteMetrics(context.Background(), &b, r.mon)
	out := b.String()
	for _, want := range []string{
		`# TYPE qv_mpc_gateway_sign_failures_total counter`,
		`qv_mpc_gateway_sign_failures_total{pair="A+B",kind="TRANSPORT"} 0`,
		`qv_mpc_gateway_sign_failures_total{pair="B+C",kind="CRYPTOGRAPHIC"} 0`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("metrics lack %q", want)
		}
	}
	if n := strings.Count(out, "\nqv_mpc_gateway_sign_failures_total{"); n != 3*7 {
		t.Fatalf("%d series, want 21 (pairs x kinds)", n)
	}
}
