package broker

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"time"
)

// writeCertMetrics writes qv_attest_broker_cert_seconds_to_expiry, one line per certificate the broker is using:
//
//	kind="leaf"        its serving certificate, as the listener loaded it (Serve).
//	kind="trust_root"  the soonest end of the vendor roots the evidence verifier was built from (Open), which every piece of evidence must chain to.
//
// The broker loads both once at start and never reloads them (a new certificate or root means a restart), so these are the ends of the material in force, not of whatever is
// in the files now: a replaced file that the broker has not loaded cannot hide an expiring active certificate. The broker has no client CA: callers are pinned keys (Config.Parties).
// The name and kind label follow the other certificate metrics (qv_tls_cert_seconds_to_expiry{kind}); the broker has no pki.Source (it is a separate module), so it writes the lines itself.
// Nothing is written for a kind that is not loaded yet (the health port can answer before the listener has loaded its certificate). The value is negative once the certificate has expired.
func (s *Server) writeCertMetrics(w io.Writer) {
	writeCertMetricsFor(w, s.leafEnd.Load(), s.rootEnd.Load(), time.Now())
}

func writeCertMetricsFor(w io.Writer, leafEnd, rootEnd int64, now time.Time) {
	fmt.Fprintln(w, "# TYPE qv_attest_broker_cert_seconds_to_expiry gauge")
	for _, k := range []struct {
		kind string
		end  int64
	}{{"leaf", leafEnd}, {"trust_root", rootEnd}} {
		if k.end != 0 {
			fmt.Fprintf(w, "qv_attest_broker_cert_seconds_to_expiry{kind=%q} %.0f\n", k.kind, time.Unix(k.end, 0).Sub(now).Seconds())
		}
	}
}

// soonestNotAfter is the earliest NotAfter of the certificates, in unix seconds; 0 for none.
func soonestNotAfter(cs []*x509.Certificate) int64 {
	var end int64
	for _, c := range cs {
		if t := c.NotAfter.Unix(); end == 0 || t < end {
			end = t
		}
	}
	return end
}

// leafNotAfter is the NotAfter of the first certificate (the leaf) of the first key pair of the TLS configuration the listener serves with; 0 if it cannot be read.
func leafNotAfter(tc *tls.Config) int64 {
	if len(tc.Certificates) == 0 || len(tc.Certificates[0].Certificate) == 0 {
		return 0
	}
	c, err := x509.ParseCertificate(tc.Certificates[0].Certificate[0])
	if err != nil {
		return 0
	}
	return c.NotAfter.Unix()
}
