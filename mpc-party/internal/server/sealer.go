package server

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Sealer protects key material at rest. P5b-4 adds the HSM implementation (AES-GCM under an in-token key).
type Sealer interface {
	Seal(aad, plaintext []byte) ([]byte, error)
	Open(aad, sealed []byte) ([]byte, error)
}

// InsecureStaticKeySealer encrypts with an AES-256-GCM key that sits in a file next to the data. It exists ONLY for
// tests and local runs: anyone who can read the key file can read every share. It is not a production sealer.
type InsecureStaticKeySealer struct{ gcm cipher.AEAD }

const InsecureSealerType = "insecure-static-key-for-tests"

func NewInsecureStaticKeySealer(key []byte) (*InsecureStaticKeySealer, error) {
	if len(key) != 32 {
		return nil, errors.New("sealer key must be 32 bytes")
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	return &InsecureStaticKeySealer{g}, nil
}

func (s *InsecureStaticKeySealer) Seal(aad, pt []byte) ([]byte, error) {
	nonce := make([]byte, s.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return s.gcm.Seal(nonce, nonce, pt, aad), nil
}

func (s *InsecureStaticKeySealer) Open(aad, sealed []byte) ([]byte, error) {
	n := s.gcm.NonceSize()
	if len(sealed) < n+s.gcm.Overhead() {
		return nil, errors.New("sealed blob too short")
	}
	return s.gcm.Open(nil, sealed[:n], sealed[n:], aad)
}

// NewSealer builds the sealer named in the config.
func NewSealer(c SealerConfig) (Sealer, error) {
	switch c.Type {
	case InsecureSealerType:
		raw, err := os.ReadFile(c.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("sealer key: %w", err)
		}
		key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil {
			return nil, fmt.Errorf("sealer key file must hold 64 hex chars: %w", err)
		}
		return NewInsecureStaticKeySealer(key)
	default:
		return nil, fmt.Errorf("unknown sealer type %q (available: %s)", c.Type, InsecureSealerType)
	}
}
