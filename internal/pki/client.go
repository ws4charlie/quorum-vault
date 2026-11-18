package pki

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/url"
	"os"
	"time"
)

// HTTPClient returns an http client for rawURL. For an https URL it presents our certificate, checks the server's against the zone's CA
// for the URL's host name, and, with serverAllow, its spiffe name. For a plain http URL it is the default client, which only a
// dev setup (QV_ALLOW_PLAINTEXT=1) gets to use: with TLS configured, an http URL is refused.
func (s *Source) HTTPClient(rawURL string, serverAllow Allow, timeout time.Duration) (*http.Client, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" {
		return nil, errors.New("pki: " + rawURL + " is not an https URL")
	}
	tr := &http.Transport{TLSClientConfig: s.ClientConfig(u.Hostname(), serverAllow), ForceAttemptHTTP2: true, MaxIdleConnsPerHost: 4, IdleConnTimeout: 30 * time.Second}
	return &http.Client{Transport: tr, Timeout: timeout}, nil
}

// HTTPClientWithCA is a client for an https service (the identity provider) whose certificate was signed by the CA in file: no client certificate, the
// system roots are not used.
func HTTPClientWithCA(caFile string, timeout time.Duration) (*http.Client, error) {
	b, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, errors.New("pki: no certificate in " + caFile)
	}
	return &http.Client{Timeout: timeout, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}}, nil
}
