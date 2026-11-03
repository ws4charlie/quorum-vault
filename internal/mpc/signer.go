package mpc

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/ws4charlie/quorum-vault/internal/domain"
	"github.com/ws4charlie/quorum-vault/internal/signer"
)

type generator struct{ c *Cluster }

// NewGenerator returns the MPC KeyGenerator: each Generate runs one DKG
// ceremony and stores the shares under MPCKeyRef "<walletID>-v<version>".
func NewGenerator(c *Cluster) domain.KeyGenerator { return generator{c} }

func (generator) Backend() domain.Backend { return domain.BackendMPC }

func (g generator) Generate(ctx context.Context, walletID string, version int) (domain.Key, error) {
	ref := fmt.Sprintf("%s-v%d", walletID, version)
	pub, _, err := g.c.Keygen(ctx, ref)
	if err != nil {
		return domain.Key{}, err
	}
	return domain.Key{
		WalletID:  walletID,
		Version:   version,
		Curve:     domain.CurveSecp256k1,
		Backend:   domain.BackendMPC,
		MPCKeyRef: ref,
		PublicKey: crypto.FromECDSAPub(pub),
		Address:   crypto.PubkeyToAddress(*pub).Hex(), // EIP-55 checksummed
		CreatedAt: time.Now().UTC(),
	}, nil
}

type mpcSigner struct {
	c   *Cluster
	key domain.Key
	pub *ecdsa.PublicKey
}

// NewSigner signs with an MPC key. SignOptions.Quorum 0 (or 2) uses the
// threshold set {1,2}; 3 uses all parties {1,2,3} (cold wallets).
func NewSigner(c *Cluster, key domain.Key) (signer.Signer, error) {
	if key.Backend != domain.BackendMPC || key.MPCKeyRef == "" {
		return nil, errors.New("mpc: not an MPC key")
	}
	if err := checkKeyRef(key.MPCKeyRef); err != nil {
		return nil, err
	}
	pub, err := signer.ParseUncompressed(key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &mpcSigner{c: c, key: key, pub: pub}, nil
}

func (s *mpcSigner) Backend() domain.Backend     { return domain.BackendMPC }
func (s *mpcSigner) Key() domain.Key             { return s.key }
func (s *mpcSigner) PublicKey() *ecdsa.PublicKey { return s.pub }

func (s *mpcSigner) SignDigest(ctx context.Context, digest [32]byte, opts signer.SignOptions) (signer.Result, error) {
	all := s.c.PartyIDs()
	var parties []int
	switch opts.Quorum {
	case 0, s.c.cfg.Threshold + 1:
		parties = all[:s.c.cfg.Threshold+1]
	case len(all):
		parties = all
	default:
		return signer.Result{}, fmt.Errorf("mpc: unsupported quorum %d", opts.Quorum)
	}
	sig, st, err := s.c.Sign(ctx, s.key.MPCKeyRef, digest, parties)
	if err != nil {
		return signer.Result{}, err
	}
	if !signer.Verify(s.pub, digest, sig) {
		return signer.Result{}, errors.New("mpc: signature does not verify against the registered key")
	}
	names := make([]string, len(parties))
	for i, id := range parties {
		names[i] = partyName(id)
	}
	return signer.Result{
		Sig:          sig,
		Participants: names,
		Meta: map[string]any{
			"rounds":      st.Rounds,
			"messages":    st.Messages,
			"bytes":       st.Bytes,
			"duration_ms": st.Duration.Milliseconds(),
		},
	}, nil
}
