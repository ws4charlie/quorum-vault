package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// CosignerRequest / CosignerResponse are the wire format between party B's mpc-party and the qv-cosigner process next to
// it (JSON over HTTP on a unix socket of mode 0600). The intent package is opaque here.
type CosignerRequest struct {
	JobID         string `json:"job_id"`
	KeyID         string `json:"key_id"`
	KeysetID      string `json:"keyset_id"`
	Algorithm     int32  `json:"algorithm"`
	Digest        []byte `json:"digest"`
	IntentPackage []byte `json:"intent_package"`
	PublicKey     []byte `json:"public_key"` // the key that will sign: compressed point
}

type CosignerResponse struct {
	Allow  bool   `json:"allow"`
	Reason string `json:"reason"`
}

// cosignerAuthorizer asks the qv-cosigner process, which holds the signing-zone config and its own replay guard (the
// root module links go-ethereum, which cannot link into this module). Fail closed: any problem is a refusal.
type cosignerAuthorizer struct {
	client  *http.Client
	timeout time.Duration
}

// NewCosignerAuthorizer talks to the cosigner on the unix socket path.
func NewCosignerAuthorizer(socket string, timeout time.Duration) Authorizer {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		},
		DisableKeepAlives: false, MaxIdleConns: 16,
	}
	return &cosignerAuthorizer{client: &http.Client{Transport: tr}, timeout: timeout}
}

func (c *cosignerAuthorizer) Authorize(ctx context.Context, r AuthRequest) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	body, _ := json.Marshal(CosignerRequest{JobID: r.JobID, KeyID: r.KeyID, KeysetID: r.KeysetID, Algorithm: int32(r.Algorithm),
		Digest: r.Digest, IntentPackage: r.IntentPackage, PublicKey: r.PublicKey})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://cosigner/authorize", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("cosigner unreachable (refusing): %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return fmt.Errorf("cosigner response (refusing): %w", err)
	}
	var out CosignerResponse
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if resp.StatusCode != http.StatusOK || dec.Decode(&out) != nil {
		return fmt.Errorf("cosigner answered %d with an unusable body (refusing)", resp.StatusCode)
	}
	if !out.Allow {
		if out.Reason == "" {
			out.Reason = "no reason given"
		}
		return errors.New(out.Reason)
	}
	return nil
}

// PinnedCaller is party A's authorizer: A's pinned caller (the gateway) has already decided. A compromised A is party B's
// problem to stop (B asks its cosigner).
type PinnedCaller struct{}

func (PinnedCaller) Authorize(context.Context, AuthRequest) error { return nil }
