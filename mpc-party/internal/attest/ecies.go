package attest

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
)

// Encryption of a released key to the public key inside the evidence: ephemeral-static ECDH (X25519 or P-256), HKDF-SHA256, AES-256-GCM.
// Layout of the output: ephemeral public key | 12-byte nonce | ciphertext+tag. Only the holder of the matching private key can open it.

// NewReleaseKey makes the key pair a party puts into its evidence (X25519). pubDER is the PKIX DER of the public key.
func NewReleaseKey() (priv *ecdh.PrivateKey, pubDER []byte, err error) {
	priv, err = ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pubDER, err = x509.MarshalPKIXPublicKey(priv.PublicKey())
	return priv, pubDER, err
}

// ParseReleasePublicKey reads the evidence's public key: PKIX DER, X25519 or ECDSA P-256 (used as ECDH).
func ParseReleasePublicKey(der []byte) (*ecdh.PublicKey, error) {
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("attest: public key: %w", err)
	}
	switch k := k.(type) {
	case *ecdh.PublicKey:
		if k.Curve() == ecdh.X25519() || k.Curve() == ecdh.P256() {
			return k, nil
		}
	case *ecdsa.PublicKey:
		if e, err := k.ECDH(); err == nil && e.Curve() == ecdh.P256() {
			return e, nil
		}
	}
	return nil, errors.New("attest: public key must be X25519 or P-256")
}

func eciesKey(shared, ephPub, recvPub []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, shared, nil, "qv-attest-ecies-v1"+string(ephPub)+string(recvPub), 32)
}

// SealTo encrypts plaintext to the public key pubDER, bound to aad.
func SealTo(pubDER, aad, plaintext []byte) ([]byte, error) {
	pub, err := ParseReleasePublicKey(pubDER)
	if err != nil {
		return nil, err
	}
	eph, err := pub.Curve().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := eph.ECDH(pub)
	if err != nil {
		return nil, err
	}
	key, err := eciesKey(shared, eph.PublicKey().Bytes(), pub.Bytes())
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := append([]byte(nil), eph.PublicKey().Bytes()...)
	out = append(out, nonce...)
	return gcm.Seal(out, nonce, plaintext, aad), nil
}

// OpenFrom decrypts what SealTo made for priv's public key under the same aad. A wrong key, wrong aad or changed byte is an error.
func OpenFrom(priv *ecdh.PrivateKey, aad, sealed []byte) ([]byte, error) {
	pl := len(priv.PublicKey().Bytes())
	if len(sealed) < pl+12+16 {
		return nil, errors.New("attest: sealed value too short")
	}
	eph, err := priv.Curve().NewPublicKey(sealed[:pl])
	if err != nil {
		return nil, fmt.Errorf("attest: sealed value: %w", err)
	}
	shared, err := priv.ECDH(eph)
	if err != nil {
		return nil, err
	}
	key, err := eciesKey(shared, sealed[:pl], priv.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	pt, err := gcm.Open(nil, sealed[pl:pl+12], sealed[pl+12:], aad)
	if err != nil {
		return nil, errors.New("attest: sealed value does not open under this key and context")
	}
	return pt, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}
