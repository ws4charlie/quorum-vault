package hsm

// Ed25519 keys on the token (PKCS#11 v3.0 mechanisms, which the pinned miekg/pkcs11 does not name): the cold key of a Solana pool. As with the EC keys
// the private half is sensitive and not extractable; only C_Sign uses it. CKM_EDDSA signs the message itself (the token hashes it as Ed25519 does), so
// the signature is the 64 bytes Solana expects.

import (
	"context"
	"crypto/ed25519"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/miekg/pkcs11"
)

const (
	ckkECEdwards        = 0x00000040             // CKK_EC_EDWARDS
	ckmECEdwardsKeyPair = 0x00001055             // CKM_EC_EDWARDS_KEY_PAIR_GEN
	ckmEdDSA            = 0x00001057             // CKM_EDDSA
	oidEd25519DER       = "\x06\x03\x2B\x65\x70" // 1.3.101.112
)

// GenerateEd25519KeyPair creates a persistent Ed25519 key pair with the given CKA_LABEL and CKA_ID and returns the 32-byte public key.
func (t *Token) GenerateEd25519KeyPair(ctx context.Context, label string, id []byte) (ed25519.PublicKey, error) {
	if len(id) == 0 {
		return nil, errors.New("hsm: empty CKA_ID")
	}
	pubTmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, ckkECEdwards),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, []byte(oidEd25519DER)),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}
	privTmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, ckkECEdwards),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}
	var pub ed25519.PublicKey
	err := t.WithSession(ctx, func(p *pkcs11.Ctx, s pkcs11.SessionHandle) error {
		pubH, _, err := p.GenerateKeyPair(s, []*pkcs11.Mechanism{pkcs11.NewMechanism(ckmECEdwardsKeyPair, nil)}, pubTmpl, privTmpl)
		if err != nil {
			return fmt.Errorf("hsm: C_GenerateKeyPair (Ed25519): %w", err)
		}
		attrs, err := p.GetAttributeValue(s, pubH, []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil)})
		if err != nil {
			return fmt.Errorf("hsm: C_GetAttributeValue(CKA_EC_POINT): %w", err)
		}
		pub, err = unwrapEdPoint(attrs[0].Value)
		return err
	})
	return pub, err
}

// unwrapEdPoint reads CKA_EC_POINT of an Ed25519 key: a DER OCTET STRING around the 32-byte point (04 20 ..), or the raw point.
func unwrapEdPoint(v []byte) (ed25519.PublicKey, error) {
	if len(v) == ed25519.PublicKeySize {
		return ed25519.PublicKey(append([]byte(nil), v...)), nil
	}
	var raw []byte
	if rest, err := asn1.Unmarshal(v, &raw); err == nil && len(rest) == 0 && len(raw) == ed25519.PublicKeySize {
		return ed25519.PublicKey(raw), nil
	}
	return nil, fmt.Errorf("hsm: unexpected CKA_EC_POINT encoding of an Ed25519 key (%d bytes)", len(v))
}

// SignEd25519 signs msg (the whole message, not a digest) with the private key whose CKA_ID is id, using CKM_EDDSA. Returns ErrKeyNotFound (wrapped)
// if the private key does not exist.
func (t *Token) SignEd25519(ctx context.Context, id, msg []byte) ([]byte, error) {
	var sig []byte
	err := t.WithSession(ctx, func(p *pkcs11.Ctx, sh pkcs11.SessionHandle) error {
		h, err := findObject(p, sh, pkcs11.CKO_PRIVATE_KEY, id)
		if err != nil {
			return err
		}
		if err := p.SignInit(sh, []*pkcs11.Mechanism{pkcs11.NewMechanism(ckmEdDSA, nil)}, h); err != nil {
			return fmt.Errorf("hsm: C_SignInit(CKM_EDDSA): %w", err)
		}
		if sig, err = p.Sign(sh, msg); err != nil {
			return fmt.Errorf("hsm: C_Sign: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("hsm: CKM_EDDSA returned %d bytes, want 64", len(sig))
	}
	return sig, nil
}
