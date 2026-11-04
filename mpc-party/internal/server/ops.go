package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"google.golang.org/grpc/codes"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/cbmpc"
)

// FaultInjection lets tests force failures at precise points. It is nil in the binary; nothing sets it outside tests.
type FaultInjection struct {
	// FailSelfTest, if it returns true for (op, role), makes that party's SelfTest report a cryptographic failure
	// after the real one ran, exactly as if the shares did not work together.
	FailSelfTest func(op string, role string) bool
	// BeforeSign runs on the party before it joins the sign protocol (after authorization).
	BeforeSign func(role string)
}

// opResult is what one party's side of an operation produced.
type opResult struct {
	public    []byte                          // what the caller gets (root key, node, derived key); signature for sign
	compare   []byte                          // what both parties must agree on
	signature []byte                          // sign, party A only
	apply     func(ctx context.Context) error // commit (DKG, Refresh); nil for other ops
	cleanup   func()                          // always called
}

func algForCurve(c pb.Curve) (cbmpc.Alg, error) {
	switch c {
	case pb.Curve_CURVE_SECP256K1:
		return cbmpc.ECDSA, nil
	case pb.Curve_CURVE_ED25519:
		return cbmpc.Ed25519, nil
	}
	return 0, fmt.Errorf("unsupported curve %v", c)
}

func algForAlgorithm(a pb.Algorithm) (cbmpc.Alg, error) {
	switch a {
	case pb.Algorithm_ALGORITHM_ECDSA_SECP256K1:
		return cbmpc.ECDSA, nil
	case pb.Algorithm_ALGORITHM_ED25519:
		return cbmpc.Ed25519, nil
	}
	return 0, fmt.Errorf("unsupported algorithm %v", a)
}

func (s *Server) opts() []cbmpc.Option {
	return []cbmpc.Option{cbmpc.WithRecvTimeout(s.cfg.Limits.RecvTimeout()), cbmpc.WithMaxFrame(s.cfg.Limits.MaxFrameBytes)}
}

func roleOf(r string) cbmpc.Role {
	if r == "A" {
		return cbmpc.P1
	}
	return cbmpc.P2
}

// selfTest runs Keyset.SelfTest, with test fault injection.
func (s *Server) selfTest(ctx context.Context, op string, ks *cbmpc.Keyset, tr cbmpc.Transport) ([]byte, error) {
	pub, err := ks.SelfTest(ctx, tr, s.opts()...)
	if err != nil {
		return nil, err
	}
	if fi := s.fi; fi != nil && fi.FailSelfTest != nil && fi.FailSelfTest(op, s.cfg.Role) {
		return nil, &cbmpc.Error{Kind: cbmpc.KindCryptographic, Op: "hd.selftest", Msg: "injected self-test failure"}
	}
	return pub, nil
}

// execOp runs this party's side of one operation over tr.
func (s *Server) execOp(ctx context.Context, open *pb.Open, tr cbmpc.Transport) (*opResult, error) {
	role := roleOf(s.cfg.Role)
	switch open.Op {
	case pb.Op_OP_DKG:
		alg, err := algForCurve(open.Curve)
		if err != nil {
			return nil, invalid("dkg", "%v", err)
		}
		ks, err := cbmpc.DKG(ctx, tr, role, alg, s.opts()...)
		if err != nil {
			return nil, fromWrapper("dkg", err)
		}
		root, err := ks.RootPublicKey()
		if err != nil {
			ks.Wipe()
			return nil, fromWrapper("dkg", err)
		}
		// Mandatory: DKG can succeed on both sides with shares that do not work together (P5b-1 finding 3).
		st, err := s.selfTest(ctx, "dkg", ks, tr)
		if err != nil {
			ks.Wipe()
			return nil, fromWrapper("dkg.selftest", err)
		}
		id := open.KeysetId
		return &opResult{public: root, compare: append(append([]byte{}, root...), st...),
			apply: func(ctx context.Context) error {
				if err := s.store.PutKeyset(ctx, id, ks, false); err != nil {
					return err
				}
				s.cache.drop(id)
				return nil
			},
			cleanup: ks.Wipe}, nil

	case pb.Op_OP_REFRESH:
		old, err := s.cache.get(ctx, s.store, open.KeysetId)
		if err != nil {
			return nil, err
		}
		nk, err := old.Refresh(ctx, tr, s.opts()...)
		if err != nil {
			return nil, fromWrapper("refresh", err)
		}
		root, err := nk.RootPublicKey()
		oldRoot, err2 := old.RootPublicKey()
		if err != nil || err2 != nil || !bytes.Equal(root, oldRoot) {
			nk.Wipe()
			return nil, failf(pb.ErrorKind_ERROR_KIND_CRYPTOGRAPHIC, codes.Aborted, "refresh", "refreshed keyset has a different root public key")
		}
		st, err := s.selfTest(ctx, "refresh", nk, tr)
		if err != nil {
			nk.Wipe() // the old shares stay in force
			return nil, fromWrapper("refresh.selftest", err)
		}
		id := open.KeysetId
		return &opResult{public: root, compare: append(append([]byte{}, root...), st...),
			apply: func(ctx context.Context) error {
				if err := s.store.PutKeyset(ctx, id, nk, true); err != nil {
					return err
				}
				s.cache.drop(id)
				return nil
			},
			cleanup: nk.Wipe}, nil

	case pb.Op_OP_NODE:
		ks, err := s.cache.get(ctx, s.store, open.KeysetId)
		if err != nil {
			return nil, err
		}
		n, err := ks.NodeExport(ctx, tr, open.HardenedPath, s.opts()...)
		if err != nil {
			return nil, fromWrapper("node", err)
		}
		res := append(append([]byte{}, n.PublicKey...), n.ChainCode...)
		return &opResult{public: res, compare: res}, nil

	case pb.Op_OP_DERIVE:
		ks, err := s.cache.get(ctx, s.store, open.KeysetId)
		if err != nil {
			return nil, err
		}
		sk, err := ks.Derive(ctx, tr, open.HardenedPath, open.Path, s.opts()...)
		if err != nil {
			return nil, fromWrapper("derive", err)
		}
		defer sk.Wipe()
		pub, err := sk.PublicKey()
		if err != nil {
			return nil, fromWrapper("derive", err)
		}
		return &opResult{public: pub, compare: pub}, nil

	case pb.Op_OP_SIGN:
		ks, err := s.cache.get(ctx, s.store, open.KeysetId)
		if err != nil {
			return nil, err
		}
		alg, err := algForAlgorithm(open.Algorithm)
		if err != nil || alg != ks.Alg() {
			return nil, invalid("sign", "algorithm does not match the keyset")
		}
		sk, err := ks.Derive(ctx, tr, open.HardenedPath, open.Path, s.opts()...)
		if err != nil {
			return nil, fromWrapper("sign.derive", err)
		}
		defer sk.Wipe()
		pub, err := sk.PublicKey()
		if err != nil {
			return nil, fromWrapper("sign", err)
		}
		// The key an authorizer judged must be the key that signs: an OPEN without an expected key never gets this far
		// (peer.go refuses it), and a derived key that differs aborts before any signing message.
		if len(open.ExpectedPublicKey) == 0 || !bytes.Equal(pub, open.ExpectedPublicKey) {
			return nil, failf(pb.ErrorKind_ERROR_KIND_CRYPTOGRAPHIC, codes.Aborted, "sign", "derived key differs from the expected public key")
		}
		if fi := s.fi; fi != nil && fi.BeforeSign != nil {
			fi.BeforeSign(s.cfg.Role)
		}
		sig, err := sk.Sign(ctx, tr, open.Digest, s.opts()...)
		if err != nil {
			return nil, fromWrapper("sign", err)
		}
		if role := roleOf(s.cfg.Role); role == cbmpc.P1 {
			if err := verifySignature(alg, pub, open.Digest, sig); err != nil {
				return nil, failf(pb.ErrorKind_ERROR_KIND_CRYPTOGRAPHIC, codes.Aborted, "sign", "signature failed local verification: %v", err)
			}
		}
		return &opResult{public: sig, signature: sig, compare: pub}, nil
	}
	return nil, invalid("session", "unknown op %v", open.Op)
}

type derSig struct{ R, S *big.Int }

// verifySignature checks a signature with independent code (btcec / crypto/ed25519), not with cb-mpc.
func verifySignature(alg cbmpc.Alg, pub, digest, sig []byte) error {
	switch alg {
	case cbmpc.Ed25519:
		if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(ed25519.PublicKey(pub), digest, sig) {
			return fmt.Errorf("ed25519 verification failed")
		}
		return nil
	case cbmpc.ECDSA:
		pk, err := btcec.ParsePubKey(pub)
		if err != nil {
			return err
		}
		var ds derSig
		if rest, err := asn1.Unmarshal(sig, &ds); err != nil || len(rest) != 0 {
			return fmt.Errorf("signature is not canonical DER")
		}
		if ds.S.Cmp(new(big.Int).Rsh(btcec.S256().N, 1)) > 0 {
			return fmt.Errorf("high-S signature")
		}
		parsed, err := ecdsa.ParseDERSignature(sig)
		if err != nil {
			return err
		}
		if !parsed.Verify(digest, pk) {
			return fmt.Errorf("ecdsa verification failed")
		}
		return nil
	}
	return fmt.Errorf("unsupported algorithm")
}
