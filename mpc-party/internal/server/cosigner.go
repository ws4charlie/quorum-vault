package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	wire "github.com/ws4charlie/quorum-vault/mpc-party/api/cosigner"
	"io"
	"net"
	"net/http"
	"time"
)

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

// UnavailableError: the authorizer could not decide (cosigner socket down, timeout, non-200, bad body, or the cosigner
// itself reports an operational failure). B does not sign, but the caller must treat it as an outage, not a refusal.
type UnavailableError struct{ Msg string }

func (e *UnavailableError) Error() string { return e.Msg }

func unavailable(format string, a ...any) error {
	return &UnavailableError{Msg: fmt.Sprintf(format, a...)}
}

func (c *cosignerAuthorizer) Authorize(ctx context.Context, r AuthRequest) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	body, _ := json.Marshal(wire.Request{JobID: r.JobID, KeyID: r.KeyID, KeysetID: r.KeysetID, Algorithm: int32(r.Algorithm),
		Digest: r.Digest, IntentPackage: r.IntentPackage, PublicKey: r.PublicKey})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://cosigner"+wire.Path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return unavailable("cosigner unreachable (refusing, will not sign): %v", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return unavailable("cosigner response unreadable (refusing): %v", err)
	}
	var out wire.Response
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if resp.StatusCode != http.StatusOK || dec.Decode(&out) != nil {
		return unavailable("cosigner answered %d with an unusable body (refusing)", resp.StatusCode)
	}
	if !out.Allow && out.Unavailable {
		return unavailable("cosigner could not decide (refusing): %s", out.Reason)
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
