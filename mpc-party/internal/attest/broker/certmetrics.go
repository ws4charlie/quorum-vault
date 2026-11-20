package broker

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"time"
)

// writeCertMetrics writes qv_attest_broker_cert_seconds_to_expiry, one line per certificate the broker depends on:
//
//	kind="leaf"        its own serving certificate (tls_cert). The parties pin it and it is renewed by hand, so it is read from the file at each scrape.
//	kind="trust_root"  the soonest end of the vendor roots in trust_roots, which every piece of evidence must chain to.
//
// The broker has no client CA: callers are pinned keys (Config.Parties), not certificates that expire. The name and kind label follow the other certificate
// metrics (qv_tls_cert_seconds_to_expiry{kind}); the broker has no pki.Source (it is a separate module and does not use the business PKI), so it writes the lines itself.
// A file that cannot be read or parsed writes nothing for that kind (the broker would not have started with a bad serving certificate).
// The value is negative once the certificate has expired.
func (s *Server) writeCertMetrics(w io.Writer) {
	writeCertMetricsFor(w, s.cfg.TLSCert, s.cfg.TrustRoots, time.Now())
}

func writeCertMetricsFor(w io.Writer, leafFile, rootsFile string, now time.Time) {
	fmt.Fprintln(w, "# TYPE qv_attest_broker_cert_seconds_to_expiry gauge")
	if end, ok := soonestEnd(leafFile); ok {
		fmt.Fprintf(w, "qv_attest_broker_cert_seconds_to_expiry{kind=\"leaf\"} %.0f\n", end.Sub(now).Seconds())
	}
	if end, ok := soonestEnd(rootsFile); ok {
		fmt.Fprintf(w, "qv_attest_broker_cert_seconds_to_expiry{kind=\"trust_root\"} %.0f\n", end.Sub(now).Seconds())
	}
}

// soonestEnd is the earliest NotAfter of the CERTIFICATE blocks of a PEM file; for a serving certificate file that is the leaf, listed first.
func soonestEnd(path string) (time.Time, bool) {
	if path == "" {
		return time.Time{}, false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, false
	}
	var end time.Time
	found := false
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			continue
		}
		if !found || c.NotAfter.Before(end) {
			end, found = c.NotAfter, true
		}
	}
	return end, found
}
