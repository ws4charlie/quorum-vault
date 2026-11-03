package hsm

import (
	"context"
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/miekg/pkcs11"

	"github.com/ws4charlie/quorum-vault/internal/domain"
	"github.com/ws4charlie/quorum-vault/internal/signer"
)

// SignECDSA signs a 32-byte digest with the private key whose CKA_ID is id,
// using CKM_ECDSA (the token does no hashing). The token returns raw r || s,
// each half the length of the curve order; S is normalized to low-S
// (S <= N/2), which Ethereum requires. Returns ErrKeyNotFound (wrapped) if the
// private key does not exist, e.g. after DestroyPrivateKey.
func (t *Token) SignECDSA(ctx context.Context, id []byte, digest [32]byte) (r, s *big.Int, err error) {
	var raw []byte
	var curve domain.Curve
	err = t.WithSession(ctx, func(p *pkcs11.Ctx, sh pkcs11.SessionHandle) error {
		h, err := findObject(p, sh, pkcs11.CKO_PRIVATE_KEY, id)
		if err != nil {
			return err
		}
		attrs, err := p.GetAttributeValue(sh, h, []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil)})
		if err != nil {
			return fmt.Errorf("hsm: C_GetAttributeValue(CKA_EC_PARAMS): %w", err)
		}
		if curve, err = curveFromParams(attrs[0].Value); err != nil {
			return err
		}
		if err := p.SignInit(sh, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}, h); err != nil {
			return fmt.Errorf("hsm: C_SignInit(CKM_ECDSA): %w", err)
		}
		// A single-part C_Sign ends the operation whether it succeeds or fails
		// (except CKR_BUFFER_TOO_SMALL, which the wrapper never triggers).
		if raw, err = p.Sign(sh, digest[:]); err != nil {
			return fmt.Errorf("hsm: C_Sign: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	if len(raw) != 64 {
		return nil, nil, fmt.Errorf("hsm: CKM_ECDSA returned %d bytes, want 64", len(raw))
	}
	r = new(big.Int).SetBytes(raw[:32])
	s = new(big.Int).SetBytes(raw[32:])
	switch curve {
	case domain.CurveSecp256k1:
		sig := signer.NormalizeLowS(signer.Signature{R: r, S: s})
		return sig.R, sig.S, nil
	default: // P-256
		n := elliptic.P256().Params().N
		if s.Cmp(new(big.Int).Rsh(n, 1)) > 0 {
			s.Sub(n, s)
		}
		return r, s, nil
	}
}
