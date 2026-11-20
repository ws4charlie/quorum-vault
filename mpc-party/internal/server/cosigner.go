package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	wire "github.com/ws4charlie/quorum-vault/mpc-party/api/cosigner"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// cosignerAuthorizer asks the qv-cosigner process, which holds the signing-zone config and its own replay guard (the
// root module links go-ethereum, which cannot link into this module). Fail closed: any problem is a refusal.
type cosignerAuthorizer struct {
	client  *http.Client
	timeout time.Duration
	base    string
	ident   atomic.Pointer[func() (*tls.Certificate, error)] // sealed TLS identity (tls_sealed): set by the server
}

// SetIdentity gives the authorizer the source of the party's certificate when its key is sealed (config tls_sealed: no cert_file and key_file).
func (c *cosignerAuthorizer) SetIdentity(get func() (*tls.Certificate, error)) { c.ident.Store(&get) }

// plaintextAllowed is the one switch that lets the cosigner channel run without TLS: QV_ALLOW_PLAINTEXT=1 together with
// QV_ENV=dev or test (the same rule as every other service). Production refuses.
func plaintextAllowed() bool {
	env := strings.ToLower(strings.TrimSpace(os.Getenv("QV_ENV")))
	return os.Getenv("QV_ALLOW_PLAINTEXT") == "1" && (env == "dev" || env == "test")
}

// NewCosignerAuthorizer talks to the cosigner on the unix socket path over mutual TLS: it presents this party's own
// certificate (certFile, keyFile: the one used on the party's ports) and accepts only a cosigner certificate listed in
// cosignerPins. It refuses to build (so the party refuses to start) when the pins are missing, the party's certificate
// is missing or outside its validity period. With no pins at all, and only under the development switch, the channel is
// plain text.
func NewCosignerAuthorizer(socket string, timeout time.Duration, cosignerPins []string, certFile, keyFile string) (Authorizer, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	a := &cosignerAuthorizer{}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		},
		DisableKeepAlives: false, MaxIdleConns: 16,
	}
	scheme := "http"
	if len(cosignerPins) == 0 {
		if !plaintextAllowed() {
			return nil, errors.New("authorizer cosigner needs authorizer.cosigner_pins (the pinned certificate of the cosigner): the channel is mutually authenticated; plain text needs QV_ALLOW_PLAINTEXT=1 and QV_ENV=dev or test, and production refuses it")
		}
	} else {
		pins, err := wire.ParsePins(cosignerPins)
		if err != nil {
			return nil, fmt.Errorf("authorizer.cosigner_pins: %w", err)
		}
		scheme = "https"
		if certFile == "" && keyFile == "" { // sealed TLS key: the certificate arrives through SetIdentity once the data keys are released
			cfg := wire.ClientTLS(tls.Certificate{}, pins)
			cfg.Certificates = nil
			cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				if f := a.ident.Load(); f != nil {
					return (*f)()
				}
				return nil, errors.New("the party's sealed TLS key is not available yet")
			}
			tr.TLSClientConfig = cfg
		} else {
			cert, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				return nil, fmt.Errorf("authorizer cosigner: this party's certificate: %w", err)
			}
			if err := wire.CheckValid(cert, time.Now()); err != nil {
				return nil, fmt.Errorf("authorizer cosigner: this party's certificate: %w", err)
			}
			tr.TLSClientConfig = wire.ClientTLS(cert, pins)
		}
	}
	a.client, a.timeout, a.base = &http.Client{Transport: tr}, timeout, scheme+"://cosigner"
	return a, nil
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
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+wire.Path, bytes.NewReader(body))
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
