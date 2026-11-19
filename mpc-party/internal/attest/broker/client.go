package broker

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ws4charlie/quorum-vault/mpc-party/api/cosigner"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/attest"
)

// Client calls the broker over mutual TLS with pinned keys (the party's side; task T3 builds on it).
type Client struct {
	base string
	hc   *http.Client
}

// RefusedError is a refusal by the broker; Code is its short reason (e.g. "allowlist:measurement_not_allowed", "nonce:reused").
type RefusedError struct {
	Status int
	Code   string
}

func (e *RefusedError) Error() string {
	return fmt.Sprintf("broker refused (%d): %s", e.Status, e.Code)
}

// NewClient makes a client for baseURL ("https://host:port") presenting cert and trusting exactly the broker keys in brokerPins.
func NewClient(baseURL string, cert tls.Certificate, brokerPins map[cosigner.Pin]bool) *Client {
	return &Client{base: baseURL, hc: &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: cosigner.ClientTLS(cert, brokerPins), DisableKeepAlives: true}}}
}

func (c *Client) post(ctx context.Context, path string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		var e attest.ErrorResponse
		_ = json.Unmarshal(data, &e)
		return &RefusedError{Status: resp.StatusCode, Code: e.Error}
	}
	return json.Unmarshal(data, out)
}

// Challenge asks for a fresh nonce.
func (c *Client) Challenge(ctx context.Context) (attest.ChallengeResponse, error) {
	var out attest.ChallengeResponse
	return out, c.post(ctx, "/v1/challenge", struct{}{}, &out)
}

// Release asks for the data keys wrapped in req.Blobs.
func (c *Client) Release(ctx context.Context, req attest.ReleaseRequest) (attest.ReleaseResponse, error) {
	var out attest.ReleaseResponse
	return out, c.post(ctx, "/v1/release", req, &out)
}

// NewKey asks for new data keys, one per generation of req.Context.
func (c *Client) NewKey(ctx context.Context, req attest.ReleaseRequest) (attest.ReleaseResponse, error) {
	var out attest.ReleaseResponse
	return out, c.post(ctx, "/v1/newkey", req, &out)
}
