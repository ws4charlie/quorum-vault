package attest

import (
	"errors"
	"fmt"
	"sync"

	"github.com/fxamacker/cbor/v2"
)

// The Nitro attester: asks the Nitro Secure Module (NSM) of the enclave for an attestation document.
//
// [NSM-API] https://github.com/aws/aws-nitro-enclaves-nsm-api (read 2026-11-20): the enclave opens /dev/nsm and sends one CBOR request per ioctl
// (magic 0x0A, number 0, read-write, argument = two iovecs: the request, at most 0x1000 bytes, and the response buffer, 0x3000 bytes). The request is
// the serde encoding of the Rust enum Request, which is a CBOR map with one key, the variant name; for attestation:
//
//	{"Attestation": {"user_data": bstr|null, "nonce": bstr|null, "public_key": bstr|null}}
//
// and the answer is {"Attestation": {"document": bstr}} (the tagged COSE_Sign1 that NitroVerifier reads) or {"Error": "<ErrorCode>"}.
//
// The device is a small interface so the encoding and the error handling are tested without one; the Linux implementation (nsm_linux.go) is
// twenty lines of ioctl. Dependency choice: no NSM library. hf/nsm (MIT) does the same in about the same size but would add a module for one
// ioctl and one CBOR map, and this package already depends on fxamacker/cbor for the verifier. The ioctl layer is the one part a test here cannot
// reach: docs/runbooks/nitro-first-run.md, step "attestation document", is its hardware check.

// NSM limits from [NSM-API] (driver/mod.rs) and the document layout (attestation_process.md).
const (
	nsmRequestMax  = 0x1000
	nsmResponseMax = 0x3000
)

// NSMDevice is one request/response exchange with the Nitro Secure Module: CBOR in, CBOR out.
type NSMDevice interface {
	Exchange(request []byte) (response []byte, err error)
	Close() error
}

// NSMAttester is the production Attester: it returns the document the NSM signs for the enclave it runs in.
type NSMAttester struct {
	mu  sync.Mutex // the device handles one request at a time
	dev NSMDevice
}

var _ Attester = (*NSMAttester)(nil)

// NewNSMAttester wraps an open device (tests pass a fake).
func NewNSMAttester(dev NSMDevice) *NSMAttester { return &NSMAttester{dev: dev} }

// OpenNSM opens /dev/nsm. It fails outside a Nitro enclave: there is no fallback to any other source of evidence.
func OpenNSM() (*NSMAttester, error) {
	dev, err := openNSMDevice()
	if err != nil {
		return nil, err
	}
	return NewNSMAttester(dev), nil
}

// Close releases the device.
func (a *NSMAttester) Close() error { return a.dev.Close() }

type nsmAttestationRequest struct {
	UserData  []byte `cbor:"user_data"`
	Nonce     []byte `cbor:"nonce"`
	PublicKey []byte `cbor:"public_key"`
}

// Attest asks the NSM for a document bound to the caller's nonce, public key (DER) and user data.
func (a *NSMAttester) Attest(nonce, publicKey, userData []byte) ([]byte, error) {
	switch {
	case len(nonce) > maxNonce:
		return nil, fmt.Errorf("attest: nsm: nonce is %d bytes, max %d", len(nonce), maxNonce)
	case len(publicKey) > maxPublicKey:
		return nil, fmt.Errorf("attest: nsm: public key is %d bytes, max %d", len(publicKey), maxPublicKey)
	case len(userData) > maxUserData:
		return nil, fmt.Errorf("attest: nsm: user data is %d bytes, max %d", len(userData), maxUserData)
	}
	req, err := encMode.Marshal(map[string]nsmAttestationRequest{"Attestation": {
		UserData: nsmOpt(userData), Nonce: nsmOpt(nonce), PublicKey: nsmOpt(publicKey)}})
	if err != nil {
		return nil, err
	}
	if len(req) > nsmRequestMax {
		return nil, fmt.Errorf("attest: nsm: request is %d bytes, max %d", len(req), nsmRequestMax)
	}
	a.mu.Lock()
	resp, err := a.dev.Exchange(req)
	a.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("attest: nsm: %w", err)
	}
	return parseNSMAttestationResponse(resp)
}

// parseNSMAttestationResponse reads {"Attestation": {"document": bstr}} or {"Error": code}. Anything else is an error.
func parseNSMAttestationResponse(resp []byte) ([]byte, error) {
	if len(resp) == 0 || len(resp) > nsmResponseMax {
		return nil, fmt.Errorf("attest: nsm: response is %d bytes (allowed 1..%d)", len(resp), nsmResponseMax)
	}
	var m map[string]cbor.RawMessage
	if err := strictDec.Unmarshal(resp, &m); err != nil || len(m) != 1 {
		return nil, errors.New("attest: nsm: response is not a CBOR map with one variant")
	}
	if raw, ok := m["Error"]; ok {
		var code string
		if strictDec.Unmarshal(raw, &code) != nil || len(code) > 64 {
			code = "?"
		}
		return nil, fmt.Errorf("attest: nsm: the module refused the request: %s", code)
	}
	raw, ok := m["Attestation"]
	if !ok {
		return nil, errors.New("attest: nsm: response is neither Attestation nor Error")
	}
	var body struct {
		Document []byte `cbor:"document"`
	}
	if err := strictDec.Unmarshal(raw, &body); err != nil || len(body.Document) == 0 {
		return nil, errors.New("attest: nsm: Attestation response has no document")
	}
	return body.Document, nil
}

func nsmOpt(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}
