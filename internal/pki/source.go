package pki

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"
)

// DefaultReloadInterval is how often a Source re-reads its files.
const DefaultReloadInterval = time.Minute

// SourceConfig names the three files of one identity: a certificate and key (the service's own), and the CA bundle it trusts.
type SourceConfig struct {
	Name     string // for messages and metrics, e.g. "core"
	Zone     string // the zone whose CA must have signed our certificate and whose CA we trust
	CertFile string
	KeyFile  string
	CAFile   string
	Interval time.Duration // reload interval; DefaultReloadInterval when zero
	Now      func() time.Time
	Log      *slog.Logger
}

// Source holds the current certificate, key and CA pool of one identity, and re-reads the files while the service runs. A new
// connection uses whatever is loaded then; established connections are not touched. A failed reload (a half-written pair, an expired
// replacement) keeps the previous material and is counted and logged.
type Source struct {
	cfg SourceConfig

	mu       sync.RWMutex
	cert     *tls.Certificate
	leaf     *x509.Certificate
	pool     *x509.CertPool
	ca       []*x509.Certificate
	reloads  int
	failures int
	lastOK   time.Time
}

// NewSource loads the files and refuses to start with material that is unusable: an expired or not yet valid certificate, a
// certificate its CA did not sign, a name of the wrong zone.
func NewSource(cfg SourceConfig) (*Source, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultReloadInterval
	}
	if err := ValidZone(cfg.Zone); err != nil {
		return nil, err
	}
	s := &Source{cfg: cfg}
	if err := s.load(); err != nil {
		return nil, err
	}
	l := s.Leaf()
	cfg.Log.Info("TLS identity loaded", "name", cfg.Name, "zone", cfg.Zone, "certificate", cfg.CertFile, "ca", cfg.CAFile, "spiffe", l.URIs[0].String(), "serial", l.SerialNumber.String(), "not_after", l.NotAfter.UTC().Format(time.RFC3339))
	return s, nil
}

func (s *Source) load() error {
	now := s.cfg.Now()
	c := s.cfg
	pair, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
	if err != nil {
		return fmt.Errorf("%s: TLS certificate %s and key %s: %w", c.Name, c.CertFile, c.KeyFile, err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return fmt.Errorf("%s: TLS certificate %s: %w", c.Name, c.CertFile, err)
	}
	pair.Leaf = leaf
	if now.After(leaf.NotAfter) {
		return fmt.Errorf("%s: TLS certificate %s expired at %s (now %s, %s ago): renew it (docs/runbooks/certificates.md)", c.Name, c.CertFile,
			leaf.NotAfter.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339), now.Sub(leaf.NotAfter).Round(time.Second))
	}
	if now.Before(leaf.NotBefore) {
		return fmt.Errorf("%s: TLS certificate %s is not valid before %s but the clock says %s: check this machine's clock (skew over 5 minutes is refused)", c.Name,
			c.CertFile, leaf.NotBefore.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	caPEM, err := os.ReadFile(c.CAFile)
	if err != nil {
		return fmt.Errorf("%s: CA bundle: %w", c.Name, err)
	}
	pool := x509.NewCertPool()
	var cas []*x509.Certificate
	for rest := caPEM; len(rest) > 0; {
		var cert *x509.Certificate
		blk, r := pemDecode(rest)
		rest = r
		if blk == nil {
			break
		}
		if cert, err = x509.ParseCertificate(blk); err != nil {
			return fmt.Errorf("%s: CA bundle %s: %w", c.Name, c.CAFile, err)
		}
		if now.After(cert.NotAfter) {
			return fmt.Errorf("%s: CA certificate %q in %s expired at %s: the zone's authority needs replacing (docs/runbooks/certificates.md)", c.Name, cert.Subject.CommonName, c.CAFile, cert.NotAfter.UTC().Format(time.RFC3339))
		}
		pool.AddCert(cert)
		cas = append(cas, cert)
	}
	if len(cas) == 0 {
		return fmt.Errorf("%s: no CA certificate in %s", c.Name, c.CAFile)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return fmt.Errorf("%s: TLS certificate %s is not signed by the CA in %s: %w", c.Name, c.CertFile, c.CAFile, err)
	}
	z, _, err := nameOf(leaf)
	if err != nil {
		return fmt.Errorf("%s: TLS certificate %s: %w", c.Name, c.CertFile, err)
	}
	if z != c.Zone {
		return fmt.Errorf("%s: TLS certificate %s is named for the %s zone but this service is configured for %s", c.Name, c.CertFile, z, c.Zone)
	}
	s.mu.Lock()
	s.cert, s.leaf, s.pool, s.ca = &pair, leaf, pool, cas
	s.reloads++
	s.lastOK = now
	s.mu.Unlock()
	return nil
}

// Reload re-reads the files now. On error the previous material stays in use.
func (s *Source) Reload() error {
	err := s.load()
	if err != nil {
		s.mu.Lock()
		s.failures++
		s.mu.Unlock()
	}
	return err
}

// Run reloads every interval until stop is closed or ctx is done.
func (s *Source) Run(done <-chan struct{}) {
	t := time.NewTicker(s.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			if err := s.Reload(); err != nil {
				s.cfg.Log.Error("ALERT TLS certificate reload failed; the previous certificate stays in use", "name", s.cfg.Name, "error", err.Error())
			}
		}
	}
}

// Name is the configured name.
func (s *Source) Name() string { return s.cfg.Name }

// Zone is the configured zone.
func (s *Source) Zone() string { return s.cfg.Zone }

// Leaf returns the certificate in use.
func (s *Source) Leaf() *x509.Certificate {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.leaf
}

func (s *Source) current() (*tls.Certificate, *x509.CertPool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cert, s.pool
}

// GetCertificate serves tls.Config.GetCertificate.
func (s *Source) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c, _ := s.current()
	return c, nil
}

// GetClientCertificate serves tls.Config.GetClientCertificate.
func (s *Source) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	c, _ := s.current()
	return c, nil
}

// caKeyIDs lists the subject key ids of the CA bundle in use, for error messages.
func (s *Source) caKeyIDs() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := ""
	for _, c := range s.ca {
		out += fmt.Sprintf("%x ", c.SubjectKeyId)
	}
	return out
}

// SecondsToExpiry is the time left on the certificate in use, negative once it expired.
func (s *Source) SecondsToExpiry() float64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.leaf.NotAfter.Sub(s.cfg.Now()).Seconds()
}

// WriteMetrics writes the certificate metrics of this source in the Prometheus text format (names are stable; see monitoring/tls-cert.rules.yml).
func (s *Source) WriteMetrics(w io.Writer) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := s.cfg.Now()
	lb := fmt.Sprintf(`name=%q,zone=%q`, s.cfg.Name, s.cfg.Zone)
	fmt.Fprintf(w, "qv_tls_cert_seconds_to_expiry{%s,kind=\"leaf\"} %.0f\n", lb, s.leaf.NotAfter.Sub(now).Seconds())
	for _, c := range s.ca {
		fmt.Fprintf(w, "qv_tls_cert_seconds_to_expiry{%s,kind=\"ca\"} %.0f\n", lb, c.NotAfter.Sub(now).Seconds())
	}
	fmt.Fprintf(w, "qv_tls_cert_reloads_total{%s} %d\n", lb, s.reloads)
	fmt.Fprintf(w, "qv_tls_cert_reload_failures_total{%s} %d\n", lb, s.failures)
	fmt.Fprintf(w, "qv_tls_cert_last_reload_timestamp_seconds{%s} %d\n", lb, s.lastOK.Unix())
}

// MetricsHandler serves the metrics of several sources in the Prometheus text format.
func MetricsHandler(srcs ...*Source) http.Handler {
	sorted := append([]*Source(nil), srcs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].cfg.Name < sorted[j].cfg.Name })
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		for _, s := range sorted {
			s.WriteMetrics(w)
		}
	})
}

// nameOf returns the zone and service of a certificate's single spiffe URI SAN.
func nameOf(c *x509.Certificate) (zone, service string, err error) {
	if len(c.URIs) != 1 {
		return "", "", fmt.Errorf("certificate has %d URI names, want exactly one spiffe://%s/<zone>/<service>", len(c.URIs), TrustDomain)
	}
	return parseURI(c.URIs[0])
}
