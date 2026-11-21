// Package kmsrelease is the production releaser of the attested sealer: AWS KMS instead of our own broker (cmd/qv-attest-broker).
//
// The enclave calls KMS Decrypt (to open a wrapped data key it stored next to its sealed shares) or GenerateDataKey (to make a new one), each with
// the Nitro attestation document as Recipient. KMS checks the document and the PCR conditions of the key policy and answers with the data key encrypted
// to the RSA public key in the document (CiphertextForRecipient). [KMS-API] https://docs.aws.amazon.com/kms/latest/developerguide/attested-calls.html and
// https://docs.aws.amazon.com/kms/latest/developerguide/conditions-nitro-enclave.html (read 2026-11-20). It implements the sealer's BrokerAPI
// (Challenge, Release, NewKey) and attest.RecipientKeyMaker, so the sealer, the envelope and the cache are the same code as with the broker.
//
// Differences from the broker that the sealer must live with (and the tests pin):
//   - KMS issues no nonce and does not check one. Replay defence is the encryption to the document's key: a stolen document is useless without its private key.
//     Challenge returns a local random nonce so the document is still fresh-bound in our own log; KMS ignores it.
//   - KMS does not check user_data. The binding of a blob to party, keyset and generation is the KMS EncryptionContext, which Decrypt requires to equal the
//     one used at GenerateDataKey: a blob of generation 3 does not open as generation 4, nor for another party or keyset.
//   - The allowlist is the key policy (PCR conditions). A change of image is a key-policy change (CloudTrail, two people), not a signed file.
package kmsrelease

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/ws4charlie/quorum-vault/mpc-party/internal/attest"
)

const (
	service      = "kms"
	targetPrefix = "TrentService."
	keyAlg       = "RSAES_OAEP_SHA_256"
	rsaBits      = 2048
	maxResponse  = 1 << 20
)

// Config says how to reach KMS.
type Config struct {
	KeyID    string // key id or ARN; Decrypt needs none (the blob names its key) but the key policy is on this key, so it is always sent and always checked
	Region   string
	Endpoint string // default https://kms.<region>.amazonaws.com; any other must be https (or http on a loopback address, for tests)
	Creds    CredentialSource
	// Dial reaches the endpoint. Inside an enclave it is the vsock dialer to the parent's vsock-proxy (VsockDialer); nil uses the network.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	Now  func() time.Time
}

// Client is the releaser. It is safe for concurrent use.
type Client struct {
	cfg  Config
	base *url.URL
	hc   *http.Client
}

var _ attest.RecipientKeyMaker = (*Client)(nil)

// New checks the configuration.
func New(cfg Config) (*Client, error) {
	if cfg.KeyID == "" || cfg.Region == "" || cfg.Creds == nil {
		return nil, errors.New("kmsrelease: key id, region and a credential source are required")
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = "https://kms." + cfg.Region + ".amazonaws.com"
	}
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || u.Host == "" || (u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf("kmsrelease: endpoint %q is not a URL without a path", cfg.Endpoint)
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && isLoopback(u.Hostname())) {
		return nil, fmt.Errorf("kmsrelease: endpoint %q must be https", cfg.Endpoint)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	tr := &http.Transport{DialContext: cfg.Dial, DisableKeepAlives: true, TLSHandshakeTimeout: 15 * time.Second}
	return &Client{cfg: cfg, base: u, hc: &http.Client{Transport: tr, Timeout: 30 * time.Second}}, nil
}

func isLoopback(h string) bool {
	ip := net.ParseIP(h)
	return h == "localhost" || (ip != nil && ip.IsLoopback())
}

// ---- attest.RecipientKeyMaker ----

// NewRecipient makes the RSA-2048 key pair of one exchange (KMS accepts RSA only). The private key stays in the returned closure.
func (c *Client) NewRecipient() ([]byte, func(aad, sealed []byte) ([]byte, error), error) {
	k, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return nil, nil, err
	}
	pub, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	return pub, func(_, sealed []byte) ([]byte, error) { return OpenEnvelope(k, sealed) }, nil
}

// ---- the sealer's BrokerAPI ----

// Challenge returns a local nonce: KMS has none (see the package comment).
func (c *Client) Challenge(context.Context) (attest.ChallengeResponse, error) {
	n := make([]byte, 32)
	if _, err := rand.Read(n); err != nil {
		return attest.ChallengeResponse{}, err
	}
	return attest.ChallengeResponse{Nonce: n, ExpiresAt: c.cfg.Now().Add(time.Minute)}, nil
}

func encContext(rc attest.RequestContext, gen uint64) map[string]string {
	return map[string]string{"qv-party": rc.Party, "qv-keyset": rc.Keyset, "qv-generation": strconv.FormatUint(gen, 10)}
}

type recipient struct {
	AttestationDocument string `json:"AttestationDocument"`
	KeyEncryptionAlg    string `json:"KeyEncryptionAlgorithm"`
}

// Release opens the wrapped data keys of the request: one Decrypt per generation, each with the evidence as Recipient.
func (c *Client) Release(ctx context.Context, req attest.ReleaseRequest) (attest.ReleaseResponse, error) {
	rc := req.Context
	if err := rc.Validate(); err != nil || rc.Purpose != attest.PurposeUnseal || len(req.Blobs) != len(rc.Generations) || len(req.Evidence) == 0 {
		return attest.ReleaseResponse{}, errors.New("kmsrelease: malformed release request")
	}
	var out attest.ReleaseResponse
	for i, g := range rc.Generations {
		var resp struct {
			CiphertextForRecipient []byte `json:"CiphertextForRecipient"`
			KeyID                  string `json:"KeyId"`
		}
		err := c.call(ctx, "Decrypt", map[string]any{
			"CiphertextBlob": req.Blobs[i], "KeyId": c.cfg.KeyID, "EncryptionContext": encContext(rc, g),
			"EncryptionAlgorithm": "SYMMETRIC_DEFAULT", "Recipient": recipient{base64.StdEncoding.EncodeToString(req.Evidence), keyAlg},
		}, &resp)
		if err != nil {
			return attest.ReleaseResponse{}, err
		}
		if len(resp.CiphertextForRecipient) == 0 {
			return attest.ReleaseResponse{}, errors.New("kmsrelease: KMS answered without CiphertextForRecipient")
		}
		out.Keys = append(out.Keys, attest.ReleasedKey{Generation: g, Sealed: resp.CiphertextForRecipient})
	}
	return out, nil
}

// NewKey makes one new AES-256 data key per generation (GenerateDataKey with the evidence as Recipient): Blob is KMS's wrapped form, Sealed the key for us.
func (c *Client) NewKey(ctx context.Context, req attest.ReleaseRequest) (attest.ReleaseResponse, error) {
	rc := req.Context
	if err := rc.Validate(); err != nil || rc.Purpose != attest.PurposeCreate || len(req.Evidence) == 0 {
		return attest.ReleaseResponse{}, errors.New("kmsrelease: malformed newkey request")
	}
	var out attest.ReleaseResponse
	for _, g := range rc.Generations {
		var resp struct {
			CiphertextBlob         []byte `json:"CiphertextBlob"`
			CiphertextForRecipient []byte `json:"CiphertextForRecipient"`
		}
		err := c.call(ctx, "GenerateDataKey", map[string]any{
			"KeyId": c.cfg.KeyID, "KeySpec": "AES_256", "EncryptionContext": encContext(rc, g),
			"Recipient": recipient{base64.StdEncoding.EncodeToString(req.Evidence), keyAlg},
		}, &resp)
		if err != nil {
			return attest.ReleaseResponse{}, err
		}
		if len(resp.CiphertextBlob) == 0 || len(resp.CiphertextForRecipient) == 0 {
			return attest.ReleaseResponse{}, errors.New("kmsrelease: KMS answered without a wrapped key or CiphertextForRecipient")
		}
		out.Keys = append(out.Keys, attest.ReleasedKey{Generation: g, Blob: resp.CiphertextBlob, Sealed: resp.CiphertextForRecipient})
	}
	return out, nil
}

// ---- the HTTP call ----

// RefusedError is an error answer of KMS (HTTP 4xx/5xx); Code is the exception name, for example AccessDeniedException. The sealer counts any such answer as "refused".
type RefusedError struct {
	Status int
	Code   string
}

func (e *RefusedError) Error() string { return fmt.Sprintf("kms refused (%d): %s", e.Status, e.Code) }

func (c *Client) call(ctx context.Context, op string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	creds, err := c.cfg.Creds.Get(ctx)
	if err != nil {
		return fmt.Errorf("kmsrelease: credentials: %w", err)
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base.String()+"/", bytes.NewReader(body))
	if err != nil {
		return err
	}
	r.Header.Set("Content-Type", "application/x-amz-json-1.1")
	r.Header.Set("X-Amz-Target", targetPrefix+op)
	SignRequest(r, body, creds, c.cfg.Region, service, c.cfg.Now())
	resp, err := c.hc.Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Type string `json:"__type"`
		}
		_ = json.Unmarshal(data, &e)
		code := e.Type
		if code == "" || len(code) > 64 {
			code = "unknown"
		}
		return &RefusedError{Status: resp.StatusCode, Code: code}
	}
	return json.Unmarshal(data, out)
}
