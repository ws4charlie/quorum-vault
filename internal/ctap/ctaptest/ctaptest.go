// Package ctaptest is a software FIDO2 authenticator. SIMULATED: it is not hardware, it has no secure element, and "user verification" and "touch"
// are flags the test sets, not something a person did. It makes credentials and assertions in the byte layout of CTAP2 (authenticator data, COSE
// keys, a packed attestation with a certificate), so the CLI and the zone's verifier are tested against the real layout.
//
// It must never be linked into qv-approve: cmd/qv-approve has a build test (TestBinaryHasNoSoftwareAuthenticator) that lists the binary's
// dependencies and its symbols.
package ctaptest

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"math/big"
	"sync"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/ctap"
)

// Soft is one simulated key (it can hold many credentials).
type Soft struct {
	// Algs the key offers; default both. A key that offers only ES256 stands for an older firmware.
	Algs []ctap.Alg
	// NoUV makes the key answer without verifying the user (flag UV clear): a misconfigured or non-compliant key. NoUP clears user presence.
	NoUV, NoUP bool
	// None makes the key give no attestation (format "none").
	None bool
	// AAGUID is the model id the key reports.
	AAGUID [16]byte

	mu    sync.Mutex
	creds map[string]*cred
	attK  *ecdsa.PrivateKey
	attC  []byte
	Calls struct{ Make, Assert int } // how many times each was asked
}

type cred struct {
	alg   ctap.Alg
	es    *ecdsa.PrivateKey
	ed    ed25519.PrivateKey
	count uint32
}

// New makes a key with a fresh attestation key and certificate.
func New() *Soft {
	s := &Soft{Algs: []ctap.Alg{ctap.ES256, ctap.EdDSA}, creds: map[string]*cred{}}
	rand.Read(s.AAGUID[:])
	s.attK, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "SIMULATED authenticator attestation", Organization: []string{"qv test"}},
		NotBefore:    time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: []int{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}, Value: append([]byte{0x04, 16}, s.AAGUID[:]...)}},
	}
	s.attC, _ = x509.CreateCertificate(rand.Reader, tpl, tpl, &s.attK.PublicKey, s.attK)
	return s
}

func (s *Soft) offers(a ctap.Alg) bool {
	for _, x := range s.Algs {
		if x == a {
			return true
		}
	}
	return false
}

func (s *Soft) flags() byte {
	f := byte(0x01 | 0x04)
	if s.NoUP {
		f &^= 0x01
	}
	if s.NoUV {
		f &^= 0x04
	}
	return f
}

func cborUint(major byte, n int) []byte {
	if n < 24 {
		return []byte{major<<5 | byte(n)}
	}
	if n < 256 {
		return []byte{major<<5 | 24, byte(n)}
	}
	return []byte{major<<5 | 25, byte(n >> 8), byte(n)}
}

func cborInt(n int) []byte {
	if n >= 0 {
		return cborUint(0, n)
	}
	return cborUint(1, -1-n)
}

func cborBytes(b []byte) []byte { return append(cborUint(2, len(b)), b...) }

// MakeCredential makes a credential for the first algorithm of r that the key offers.
func (s *Soft) MakeCredential(ctx context.Context, r ctap.MakeRequest) (*ctap.MakeResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Calls.Make++
	var alg ctap.Alg
	for _, a := range r.Algs {
		if s.offers(a) {
			alg = a
			break
		}
	}
	if alg == 0 {
		return nil, ctap.ErrUnsupportedAlg
	}
	c := &cred{alg: alg}
	var key []byte
	id := make([]byte, 32)
	rand.Read(id)
	switch alg {
	case ctap.ES256:
		c.es, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		x, y := c.es.X.FillBytes(make([]byte, 32)), c.es.Y.FillBytes(make([]byte, 32))
		key = append(key, 0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01)
		key = append(append(key, 0x21), cborBytes(x)...)
		key = append(append(key, 0x22), cborBytes(y)...)
	case ctap.EdDSA:
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		c.ed = priv
		key = append(key, 0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06)
		key = append(append(key, 0x21), cborBytes(pub)...)
	}
	s.creds[string(id)] = c
	rp := sha256.Sum256([]byte(r.RPID))
	ad := append(rp[:len(rp):len(rp)], s.flags()|0x40, 0, 0, 0, 0)
	ad = append(ad, s.AAGUID[:]...)
	ad = binary.BigEndian.AppendUint16(ad, uint16(len(id)))
	ad = append(append(ad, id...), key...)
	res := &ctap.MakeResult{Alg: alg, Format: "packed", AuthData: ad, CredentialID: id}
	if s.None {
		res.Format = "none"
		return res, nil
	}
	d := sha256.Sum256(append(append([]byte{}, ad...), r.ClientDataHash[:]...))
	res.Signature, _ = ecdsa.SignASN1(rand.Reader, s.attK, d[:])
	res.X5C = s.attC
	return res, nil
}

// GetAssertion signs authenticatorData || clientDataHash with the credential.
func (s *Soft) GetAssertion(ctx context.Context, r ctap.AssertRequest) (*ctap.AssertResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Calls.Assert++
	c := s.creds[string(r.CredentialID)]
	if c == nil {
		return nil, errors.New("ctaptest: no such credential on this key")
	}
	c.count++
	rp := sha256.Sum256([]byte(r.RPID))
	ad := append(rp[:len(rp):len(rp)], s.flags())
	ad = binary.BigEndian.AppendUint32(ad, c.count)
	msg := append(append([]byte{}, ad...), r.ClientDataHash[:]...)
	res := &ctap.AssertResult{AuthData: ad}
	if c.es != nil {
		d := sha256.Sum256(msg)
		res.Signature, _ = ecdsa.SignASN1(rand.Reader, c.es, d[:])
	} else {
		res.Signature = ed25519.Sign(c.ed, msg)
	}
	return res, nil
}
