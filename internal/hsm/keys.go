package hsm

// Key objects: generation, lookup and destruction.
//
// Every key pair lives on the token (CKA_TOKEN=true) and is addressed by its
// CKA_ID (16 random bytes chosen by the caller), never by object handle:
// handles are per-session numbers and not stable across sessions or restarts.
// The private half is CKA_SENSITIVE and not CKA_EXTRACTABLE, so its scalar
// never leaves the token; only C_Sign uses it.

import (
	"bytes"
	"context"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/miekg/pkcs11"

	"github.com/ws4charlie/quorum-vault/internal/domain"
)

// ErrKeyNotFound is returned (wrapped) when no object with the requested
// CKA_ID and class exists on the token, e.g. a private key after
// DestroyPrivateKey.
var ErrKeyNotFound = errors.New("hsm: key not found")

// DER-encoded named-curve OIDs for CKA_EC_PARAMS.
var (
	oidSecp256k1 = []byte{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A}                   // 1.3.132.0.10
	oidP256      = []byte{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07} // 1.2.840.10045.3.1.7
)

func ecParams(curve domain.Curve) ([]byte, error) {
	switch curve {
	case domain.CurveSecp256k1:
		return oidSecp256k1, nil
	case domain.CurveP256:
		return oidP256, nil
	}
	return nil, fmt.Errorf("hsm: unsupported curve %q", curve)
}

func curveFromParams(params []byte) (domain.Curve, error) {
	switch {
	case bytes.Equal(params, oidSecp256k1):
		return domain.CurveSecp256k1, nil
	case bytes.Equal(params, oidP256):
		return domain.CurveP256, nil
	}
	return "", fmt.Errorf("hsm: unknown CKA_EC_PARAMS % X", params)
}

// GenerateECKeyPair creates a persistent EC key pair on the token with the
// given CKA_LABEL and CKA_ID and returns the public key as a 65-byte SEC1
// uncompressed point. The private key is sensitive and non-extractable.
func (t *Token) GenerateECKeyPair(ctx context.Context, curve domain.Curve, label string, id []byte) (pubUncompressed []byte, err error) {
	params, err := ecParams(curve)
	if err != nil {
		return nil, err
	}
	if len(id) == 0 {
		return nil, errors.New("hsm: empty CKA_ID")
	}
	pubTmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, params),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}
	privTmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}
	err = t.WithSession(ctx, func(p *pkcs11.Ctx, s pkcs11.SessionHandle) error {
		mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)}
		pubH, _, err := p.GenerateKeyPair(s, mech, pubTmpl, privTmpl)
		if err != nil {
			return fmt.Errorf("hsm: C_GenerateKeyPair (%s): %w", curve, err)
		}
		attrs, err := p.GetAttributeValue(s, pubH, []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil)})
		if err != nil {
			return fmt.Errorf("hsm: C_GetAttributeValue(CKA_EC_POINT): %w", err)
		}
		pubUncompressed, err = unwrapECPoint(attrs[0].Value)
		return err
	})
	if err != nil {
		return nil, err
	}
	return pubUncompressed, nil
}

// unwrapECPoint turns CKA_EC_POINT into a 65-byte uncompressed point. The
// spec says the value is a DER OCTET STRING (04 41 04 X Y); some modules
// return the raw point (04 X Y). Both are accepted.
func unwrapECPoint(v []byte) ([]byte, error) {
	if len(v) == 65 && v[0] == 0x04 {
		return v, nil
	}
	var raw []byte
	if rest, err := asn1.Unmarshal(v, &raw); err == nil && len(rest) == 0 && len(raw) == 65 && raw[0] == 0x04 {
		return raw, nil
	}
	return nil, fmt.Errorf("hsm: unexpected CKA_EC_POINT encoding (%d bytes)", len(v))
}

// DestroyPrivateKey deletes the private key object with CKA_ID id from the
// token (C_DestroyObject). The public key object is left in place. Returns
// ErrKeyNotFound (wrapped) if there is no such private key.
func (t *Token) DestroyPrivateKey(ctx context.Context, id []byte) error {
	return t.WithSession(ctx, func(p *pkcs11.Ctx, s pkcs11.SessionHandle) error {
		h, err := findObject(p, s, pkcs11.CKO_PRIVATE_KEY, id)
		if err != nil {
			return err
		}
		if err := p.DestroyObject(s, h); err != nil {
			return fmt.Errorf("hsm: C_DestroyObject: %w", err)
		}
		return nil
	})
}

// HasObject reports whether an object of the given class (pkcs11.CKO_*) with
// CKA_ID id exists on the token.
func (t *Token) HasObject(ctx context.Context, class uint, id []byte) (bool, error) {
	var found bool
	err := t.WithSession(ctx, func(p *pkcs11.Ctx, s pkcs11.SessionHandle) error {
		_, err := findObject(p, s, class, id)
		if errors.Is(err, ErrKeyNotFound) {
			return nil
		}
		found = err == nil
		return err
	})
	return found, err
}

// findObject returns the single object of class with CKA_ID id. The find
// operation is always finalized, because the session goes back to the pool.
func findObject(p *pkcs11.Ctx, s pkcs11.SessionHandle, class uint, id []byte) (h pkcs11.ObjectHandle, err error) {
	tmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}
	if err := p.FindObjectsInit(s, tmpl); err != nil {
		return 0, fmt.Errorf("hsm: C_FindObjectsInit: %w", err)
	}
	defer func() {
		if ferr := p.FindObjectsFinal(s); ferr != nil && err == nil {
			err = fmt.Errorf("hsm: C_FindObjectsFinal: %w", ferr)
		}
	}()
	hs, _, err := p.FindObjects(s, 2)
	if err != nil {
		return 0, fmt.Errorf("hsm: C_FindObjects: %w", err)
	}
	switch len(hs) {
	case 0:
		return 0, fmt.Errorf("%w: class %d id %X", ErrKeyNotFound, class, id)
	case 1:
		return hs[0], nil
	}
	return 0, fmt.Errorf("hsm: more than one object with class %d id %X", class, id)
}
