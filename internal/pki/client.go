package pki

import (
	"errors"
	"net/http"
	"net/url"
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
