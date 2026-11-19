//go:build teesim

package attest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// This file exists only in simulation builds (-tags teesim). It writes documents with the same bytes as a real Nitro attestation document
// (tagged COSE_Sign1, ES384, cabundle root first, the same payload map), signed by a test CA with one intermediate, so the production
// NitroVerifier accepts them once its trust root is the test root.

// MockCA is a test root plus one intermediate. The root key is dropped after it signed the intermediate.
type MockCA struct {
	Root         *x509.Certificate
	Intermediate *x509.Certificate
	interKey     *ecdsa.PrivateKey
}

func newKey() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P384(), rand.Reader) }

func serial() *big.Int { n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120)); return n }

// NewMockCA makes a fresh in-memory CA valid from now-1h for ttl.
func NewMockCA(now time.Time, ttl time.Duration) (*MockCA, error) {
	rootKey, err := newKey()
	if err != nil {
		return nil, err
	}
	interKey, err := newKey()
	if err != nil {
		return nil, err
	}
	rootTmpl := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: "QV mock Nitro root (TEST ONLY)"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(ttl), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return nil, err
	}
	interTmpl := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: "QV mock Nitro intermediate (TEST ONLY)"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(ttl), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, root, &interKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}
	inter, err := x509.ParseCertificate(interDER)
	if err != nil {
		return nil, err
	}
	return &MockCA{Root: root, Intermediate: inter, interKey: interKey}, nil
}

// Write stores root.crt, intermediate.crt and intermediate.key (0600) in dir, the gitignored dev PKI directory.
func (ca *MockCA) Write(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	kd, err := x509.MarshalECPrivateKey(ca.interKey)
	if err != nil {
		return err
	}
	for name, p := range map[string]*pem.Block{
		"root.crt":         {Type: "CERTIFICATE", Bytes: ca.Root.Raw},
		"intermediate.crt": {Type: "CERTIFICATE", Bytes: ca.Intermediate.Raw},
		"intermediate.key": {Type: "EC PRIVATE KEY", Bytes: kd},
	} {
		if err := os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(p), 0o600); err != nil {
			return err
		}
	}
	return nil
}

// LoadMockCA reads what Write stored.
func LoadMockCA(dir string) (*MockCA, error) {
	read := func(name string) (*pem.Block, error) {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		blk, _ := pem.Decode(b)
		if blk == nil {
			return nil, fmt.Errorf("attest: %s: no PEM block", name)
		}
		return blk, nil
	}
	rb, err := read("root.crt")
	if err != nil {
		return nil, err
	}
	ib, err := read("intermediate.crt")
	if err != nil {
		return nil, err
	}
	kb, err := read("intermediate.key")
	if err != nil {
		return nil, err
	}
	root, err := x509.ParseCertificate(rb.Bytes)
	if err != nil {
		return nil, err
	}
	inter, err := x509.ParseCertificate(ib.Bytes)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	return &MockCA{Root: root, Intermediate: inter, interKey: key}, nil
}

// MeasureImage computes the mock PCR0 of a party: SHA-384 over its binary and its config file, each preceded by its 8-byte big-endian length so
// the two cannot trade bytes. Changing either file changes the measurement. (A real PCR0 is the hash of the whole enclave image file; see
// the report for what a containerised party would measure.)
func MeasureImage(bin, config []byte) []byte {
	h := sha512.New384()
	for _, part := range [][]byte{bin, config} {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(part)))
		h.Write(n[:])
		h.Write(part)
	}
	return h.Sum(nil)
}

// MeasureFiles is MeasureImage over two files.
func MeasureFiles(binaryPath, configPath string) ([]byte, error) {
	b, err := os.ReadFile(binaryPath)
	if err != nil {
		return nil, err
	}
	c, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	return MeasureImage(b, c), nil
}

// MeasureCert is the mock PCR8: SHA-384 of the (mock) image signing certificate's DER.
func MeasureCert(der []byte) []byte { s := sha512.Sum384(der); return s[:] }

// Fault is a failure the mock can inject, for tests.
type Fault int

const (
	FaultNone             Fault = iota
	FaultBadSignature           // one bit of the COSE signature flipped
	FaultExpiredCert            // the leaf certificate expired before the document time
	FaultWrongChainOrder        // cabundle holds [intermediate, root] instead of [root, intermediate]
	FaultWrongPCR               // PCR0 differs from the real measurement (the verifier accepts it; the allowlist must refuse it)
	FaultZeroPCRs               // all-zero PCRs, as a debug-mode enclave produces
	FaultMissingNonce           // no nonce in the document
	FaultWrongNonce             // a random nonce, not the requested one
	FaultUserDataMismatch       // different user_data
	FaultFutureTimestamp        // document time one hour ahead
	FaultStaleTimestamp         // document time one hour behind
)

// MockAttester is an Attester that signs Nitro-format documents with a test CA. Set Fault to break one thing.
type MockAttester struct {
	CA       *MockCA
	PCR0     []byte // 48 bytes; use MeasureImage / MeasureFiles
	PCR8     []byte // 48 bytes; use MeasureCert; nil leaves the PCR out
	Debug    bool   // zero PCRs (same as FaultZeroPCRs)
	Fault    Fault
	ModuleID string
	Now      func() time.Time // default time.Now
}

var _ Attester = (*MockAttester)(nil)

// Attest returns a document bound to nonce, publicKey and userData.
func (m *MockAttester) Attest(nonce, publicKey, userData []byte) ([]byte, error) {
	if m.CA == nil {
		return nil, errors.New("attest: mock attester has no CA")
	}
	now := time.Now()
	if m.Now != nil {
		now = m.Now()
	}
	ts := now
	switch m.Fault {
	case FaultFutureTimestamp:
		ts = now.Add(time.Hour)
	case FaultStaleTimestamp:
		ts = now.Add(-time.Hour)
	}

	// A fresh leaf per document, like a real Nitro document (leaf valid for a few hours).
	leafKey, err := newKey()
	if err != nil {
		return nil, err
	}
	notBefore, notAfter := now.Add(-2*time.Hour), now.Add(3*time.Hour)
	if m.Fault == FaultExpiredCert {
		notBefore, notAfter = now.Add(-48*time.Hour), now.Add(-24*time.Hour)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: "i-mock-enc0123456789abcdef.mock"},
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, m.CA.Intermediate, &leafKey.PublicKey, m.CA.interKey)
	if err != nil {
		return nil, err
	}

	pcrs := map[uint64][]byte{}
	pcr0 := append([]byte(nil), m.PCR0...)
	if len(pcr0) != 48 {
		return nil, errors.New("attest: mock PCR0 must be 48 bytes")
	}
	if m.Fault == FaultWrongPCR {
		pcr0[0] ^= 0xff
	}
	pcrs[0], pcrs[1], pcrs[2] = pcr0, make([]byte, 48), make([]byte, 48)
	copy(pcrs[1], MeasureImage([]byte("mock kernel"), nil))
	copy(pcrs[2], MeasureImage([]byte("mock application"), nil))
	if len(m.PCR8) > 0 {
		pcrs[8] = append([]byte(nil), m.PCR8...)
	}
	if m.Debug || m.Fault == FaultZeroPCRs {
		for i := range pcrs {
			pcrs[i] = make([]byte, 48)
		}
	}

	n, ud := nonce, userData
	switch m.Fault {
	case FaultMissingNonce:
		n = nil
	case FaultWrongNonce:
		n = make([]byte, len(nonce)+1)
		if _, err := io.ReadFull(rand.Reader, n); err != nil {
			return nil, err
		}
	case FaultUserDataMismatch:
		ud = append(append([]byte(nil), userData...), 'x')
	}
	mod := m.ModuleID
	if mod == "" {
		mod = "i-mock-enc0123456789abcdef-mock"
	}
	bundle := [][]byte{m.CA.Root.Raw, m.CA.Intermediate.Raw}
	if m.Fault == FaultWrongChainOrder {
		bundle = [][]byte{m.CA.Intermediate.Raw, m.CA.Root.Raw}
	}
	doc := nitroDoc{
		ModuleID: mod, Digest: nitroDigest, Timestamp: uint64(ts.UnixMilli()), PCRs: pcrs,
		Certificate: leafDER, CABundle: bundle, PublicKey: nilIfEmpty(publicKey), UserData: nilIfEmpty(ud), Nonce: nilIfEmpty(n),
	}
	payload, err := encMode.Marshal(doc)
	if err != nil {
		return nil, err
	}
	protected, err := encMode.Marshal(map[int]int{coseHeaderAlg: coseAlgES384})
	if err != nil {
		return nil, err
	}
	tbs, err := sigStructure(protected, payload)
	if err != nil {
		return nil, err
	}
	h := sha512.Sum384(tbs)
	r, s, err := ecdsa.Sign(rand.Reader, leafKey, h[:])
	if err != nil {
		return nil, err
	}
	sig := make([]byte, es384SigBytes)
	r.FillBytes(sig[:es384SigBytes/2])
	s.FillBytes(sig[es384SigBytes/2:])
	if m.Fault == FaultBadSignature {
		sig[10] ^= 1
	}
	body, err := encMode.Marshal(coseSign1{Protected: protected, Unprotected: []byte{0xA0}, Payload: payload, Signature: sig})
	if err != nil {
		return nil, err
	}
	return append([]byte{0xC0 | coseTagSign1}, body...), nil // tag 18, as the NSM writes it
}

func nilIfEmpty(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}
