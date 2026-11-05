package server

import "fmt"

// Sealer protects key material at rest. P5b-4 adds the HSM implementation (AES-GCM under an in-token key).
type Sealer interface {
	Seal(aad, plaintext []byte) ([]byte, error)
	Open(aad, sealed []byte) ([]byte, error)
}

// extraSealers are registered by build-tagged files (sealer_insecure.go, only with -tags devauth). A production build has none.
var extraSealers = map[string]func(SealerConfig) (Sealer, error){}

// NewSealer builds the sealer named in the config. Production: "pkcs11". The insecure test sealer exists only in binaries
// built with -tags devauth; a production binary asked for it refuses to start.
func NewSealer(c SealerConfig) (Sealer, error) {
	switch c.Type {
	case "pkcs11":
		return NewPKCS11Sealer(c)
	}
	if f, ok := extraSealers[c.Type]; ok {
		return f(c)
	}
	return nil, fmt.Errorf("sealer type %q is not available in this build (production builds have: pkcs11)", c.Type)
}
