package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/ws4charlie/quorum-vault/mpc-party/internal/attest/kmsrelease"
)

// The KMS release (task T7-prep): the data keys are released by AWS KMS instead of qv-attest-broker. See package kmsrelease for the protocol and
// docs/runbooks/nitro-first-run.md for the whole chain. It has not run against AWS: it is tested against a fake KMS (kmsrelease/kmsfake).

// ReleaseConfig is sealer.release.
type ReleaseConfig struct {
	Type string    `json:"type"` // "broker" (default) or "kms"
	KMS  KMSConfig `json:"kms"`
}

// KMSConfig says how an enclave reaches KMS. There is no network in an enclave: every connection goes over vsock to the parent instance, which runs AWS's
// vsock-proxy for the KMS endpoint (TLS ends inside the enclave, so the parent sees ciphertext and the endpoint's name only) and a forwarder to the instance
// metadata service for the instance role's credentials.
type KMSConfig struct {
	KeyID    string `json:"key_id"`   // KMS key id or ARN; its key policy holds the PCR conditions
	Region   string `json:"region"`   // for the endpoint name and the signing scope
	Endpoint string `json:"endpoint"` // default https://kms.<region>.amazonaws.com
	// VsockPort: the port of the parent's vsock-proxy for the KMS endpoint (CID 3). 0: connect over the network (tests, never in an enclave).
	VsockPort uint32 `json:"vsock_port"`
	// CredsVsockPort: the port of the parent's forwarder to 169.254.169.254:80. 0: credentials from AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and
	// AWS_SESSION_TOKEN (tests, never in an enclave).
	CredsVsockPort uint32 `json:"creds_vsock_port"`
}

func (c SealerConfig) validateKMS() error {
	var errs []error
	k := c.Release.KMS
	if strings.TrimSpace(k.KeyID) == "" {
		errs = append(errs, errors.New("sealer.release.kms.key_id is required"))
	}
	if strings.TrimSpace(k.Region) == "" {
		errs = append(errs, errors.New("sealer.release.kms.region is required"))
	}
	if strings.TrimSpace(c.Attester.Type) == "" {
		errs = append(errs, errors.New("sealer.attester.type is required"))
	}
	if k.VsockPort != 0 && k.VsockPort <= 2 {
		errs = append(errs, errors.New("sealer.release.kms.vsock_port must be above 2 (or 0 for a direct connection)"))
	}
	if productionEnv() && strings.TrimSpace(c.Attester.Type) == "nitro" {
		// An enclave has no network: port 0 would mean the party is not in an enclave, or reaches KMS some way the design does not have. And
		// credentials from AWS_* variables are not the instance role's. Both are for tests, so production refuses them instead of falling back.
		if k.VsockPort == 0 {
			errs = append(errs, errors.New("sealer.release.kms.vsock_port is required with attester nitro in production (QV_ENV unset, or not dev or test): 0 would connect to KMS over the network"))
		}
		if k.CredsVsockPort == 0 {
			errs = append(errs, errors.New("sealer.release.kms.creds_vsock_port is required with attester nitro in production (QV_ENV unset, or not dev or test): 0 would take credentials from the AWS_* environment variables"))
		}
	}
	return errors.Join(errs...)
}

// newKMSReleaser builds the KMS client of a party.
func newKMSReleaser(k KMSConfig) (BrokerAPI, error) {
	var dial func(ctx context.Context, network, addr string) (net.Conn, error)
	if k.VsockPort != 0 {
		dial = kmsrelease.VsockDialer(kmsrelease.ParentCID, k.VsockPort)
	}
	var creds kmsrelease.CredentialSource
	if k.CredsVsockPort != 0 {
		creds = &kmsrelease.IMDSCreds{Dial: kmsrelease.VsockDialer(kmsrelease.ParentCID, k.CredsVsockPort)}
	} else {
		c := kmsrelease.Creds{AccessKeyID: os.Getenv("AWS_ACCESS_KEY_ID"), SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"), SessionToken: os.Getenv("AWS_SESSION_TOKEN")}
		if c.AccessKeyID == "" || c.SecretAccessKey == "" {
			return nil, errors.New("sealer attested: no credentials: set sealer.release.kms.creds_vsock_port (an enclave) or the AWS_* environment variables (tests)")
		}
		creds = kmsrelease.StaticCreds(c)
	}
	cl, err := kmsrelease.New(kmsrelease.Config{KeyID: k.KeyID, Region: k.Region, Endpoint: k.Endpoint, Creds: creds, Dial: dial})
	if err != nil {
		return nil, fmt.Errorf("sealer attested: %w", err)
	}
	return cl, nil
}
