package kmsrelease

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// CredentialSource gives the AWS credentials KMS calls are signed with.
type CredentialSource interface {
	Get(ctx context.Context) (Creds, error)
}

// StaticCreds is a fixed credential (tests).
type StaticCreds Creds

func (s StaticCreds) Get(context.Context) (Creds, error) { return Creds(s), nil }

// IMDSCreds reads the parent instance's role credentials from the instance metadata service (IMDSv2) through a dialer: inside an enclave the dialer is a
// vsock connection to a forwarder on the parent that reaches 169.254.169.254:80 (docs/runbooks/nitro-first-run.md). [IMDS]
// https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-retrieval-examples.html (read 2026-11-20): PUT /latest/api/token with the TTL header, then GET
// /latest/meta-data/iam/security-credentials/ and the role name, with the token header.
//
// What the parent can do with this: it sees the credentials in the clear (it is its own role). They are not enough to read a key: the key policy
// requires an attestation document with the image's PCRs (see deploy/cloud/aws/modules/nitro-enclave-key). What it can do is refuse to forward them,
// and that is a denial of service, nothing more.
type IMDSCreds struct {
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	Now  func() time.Time

	mu     sync.Mutex
	cached Creds
}

const imdsHost = "169.254.169.254"

func (s *IMDSCreds) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *IMDSCreds) Get(ctx context.Context) (Creds, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cached.AccessKeyID != "" && s.now().Add(5*time.Minute).Before(s.cached.Expiration) {
		return s.cached, nil
	}
	hc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DialContext: s.Dial, DisableKeepAlives: true}}
	do := func(method, path string, hdr map[string]string) ([]byte, error) {
		r, err := http.NewRequestWithContext(ctx, method, "http://"+imdsHost+path, nil)
		if err != nil {
			return nil, err
		}
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		resp, err := hc.Do(r)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("imds %s: status %d", path, resp.StatusCode)
		}
		return b, nil
	}
	tok, err := do(http.MethodPut, "/latest/api/token", map[string]string{"X-aws-ec2-metadata-token-ttl-seconds": "300"})
	if err != nil {
		return Creds{}, err
	}
	h := map[string]string{"X-aws-ec2-metadata-token": strings.TrimSpace(string(tok))}
	role, err := do(http.MethodGet, "/latest/meta-data/iam/security-credentials/", h)
	if err != nil {
		return Creds{}, err
	}
	name := strings.TrimSpace(strings.SplitN(string(role), "\n", 2)[0])
	if name == "" || strings.ContainsAny(name, "/ ?#") {
		return Creds{}, errors.New("imds: no usable role name")
	}
	b, err := do(http.MethodGet, "/latest/meta-data/iam/security-credentials/"+name, h)
	if err != nil {
		return Creds{}, err
	}
	var j struct {
		Code            string
		AccessKeyID     string `json:"AccessKeyId"`
		SecretAccessKey string
		Token           string
		Expiration      time.Time
	}
	if err := json.Unmarshal(b, &j); err != nil || j.AccessKeyID == "" || j.SecretAccessKey == "" || j.Token == "" || (j.Code != "" && j.Code != "Success") {
		return Creds{}, errors.New("imds: credentials are malformed or not a success")
	}
	s.cached = Creds{AccessKeyID: j.AccessKeyID, SecretAccessKey: j.SecretAccessKey, SessionToken: j.Token, Expiration: j.Expiration}
	return s.cached, nil
}
