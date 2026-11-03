package mpc

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"slices"

	"github.com/bnb-chain/tss-lib/v4/common"
	"github.com/bnb-chain/tss-lib/v4/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v4/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/v4/tss"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/ws4charlie/quorum-vault/internal/mpc/seal"
	"github.com/ws4charlie/quorum-vault/internal/signer"
)

// Sign runs a GG20 signing ceremony on digest among the given parties (at
// least Threshold+1 of them; any subset works, e.g. {1,3}, or all). Each
// party's share is unsealed with its own token just for this ceremony. The
// result is low-S normalised and verified against the joint public key.
func (c *Cluster) Sign(ctx context.Context, keyRef string, digest [32]byte, parties []int) (signer.Signature, Stats, error) {
	if err := checkKeyRef(keyRef); err != nil {
		return signer.Signature{}, Stats{}, err
	}
	ids := slices.Clone(parties)
	slices.Sort(ids)
	ids = slices.Compact(ids)
	if len(ids) < c.cfg.Threshold+1 {
		return signer.Signature{}, Stats{}, fmt.Errorf("%w: %d given, %d needed", ErrNotEnoughParties, len(ids), c.cfg.Threshold+1)
	}
	for _, id := range ids {
		if _, err := c.party(id); err != nil {
			return signer.Signature{}, Stats{}, err
		}
	}
	if _, err := os.Stat(c.keyDir(keyRef)); err != nil {
		return signer.Signature{}, Stats{}, fmt.Errorf("%w: %s", ErrKeyNotFound, keyRef)
	}
	saves := make([]keygen.LocalPartySaveData, len(ids))
	for i, id := range ids {
		s, err := c.loadShare(ctx, keyRef, id)
		if err != nil {
			return signer.Signature{}, Stats{}, err
		}
		saves[i] = s
	}
	return c.signCeremony(ctx, ids, saves, digest)
}

// loadShare unseals one party's save data. The plaintext exists only in memory.
func (c *Cluster) loadShare(ctx context.Context, keyRef string, id int) (keygen.LocalPartySaveData, error) {
	var s keygen.LocalPartySaveData
	p, err := c.party(id)
	if err != nil {
		return s, err
	}
	env, err := os.ReadFile(filepath.Join(c.keyDir(keyRef), partyName(id)+".sealed"))
	if err != nil {
		return s, fmt.Errorf("mpc: party %d share of %s: %w", id, keyRef, err)
	}
	bz, err := seal.Open(ctx, p.tok, env, shareAAD(keyRef, id))
	if err != nil {
		return s, fmt.Errorf("mpc: party %d share of %s: %w", id, keyRef, err)
	}
	defer clear(bz)
	if err := json.Unmarshal(bz, &s); err != nil {
		return s, fmt.Errorf("mpc: party %d share of %s: %w", id, keyRef, err)
	}
	if s.ShareID == nil || s.ShareID.Cmp(big.NewInt(int64(id))) != 0 || s.ECDSAPub == nil {
		return s, fmt.Errorf("mpc: party %d share of %s: share id mismatch", id, keyRef)
	}
	for _, x := range s.BigXj {
		x.SetCurve(tss.S256())
	}
	s.ECDSAPub.SetCurve(tss.S256())
	return s, nil
}

// signCeremony runs tss-lib signing for parties ids (sorted) holding saves.
// It does not check the party count itself, so tests can show that tss-lib
// refuses a single party.
func (c *Cluster) signCeremony(ctx context.Context, ids []int, saves []keygen.LocalPartySaveData, digest [32]byte) (_ signer.Signature, _ Stats, err error) {
	pub := &ecdsa.PublicKey{Curve: crypto.S256(), X: saves[0].ECDSAPub.X(), Y: saves[0].ECDSAPub.Y()}
	for _, s := range saves[1:] {
		if s.ECDSAPub.X().Cmp(pub.X) != 0 || s.ECDSAPub.Y().Cmp(pub.Y) != 0 {
			return signer.Signature{}, Stats{}, ErrPublicKeyMismatch
		}
	}
	nonce, err := sessionNonce()
	if err != nil {
		return signer.Signature{}, Stats{}, err
	}
	unsorted := make(tss.UnSortedPartyIDs, len(ids))
	saveByPID := map[string]keygen.LocalPartySaveData{}
	for i, id := range ids {
		unsorted[i] = newPID(id)
		saveByPID[unsorted[i].Id] = saves[i]
	}
	msg := new(big.Int).SetBytes(digest[:])
	outCh := make(chan tss.Message, outBuffer)
	endCh := make(chan *common.SignatureData, len(ids))
	tparties := make([]tss.Party, len(ids))
	if err := func() (err error) {
		defer recoverErr(&err)
		sorted := tss.SortPartyIDs(unsorted)
		peers := tss.NewPeerContext(sorted)
		for i, pid := range sorted {
			params := tss.NewParameters(tss.S256(), peers, pid, len(sorted), c.cfg.Threshold)
			params.SetSessionNonce(nonce)
			// fullBytesLen 32 keeps leading zero bytes of the digest.
			tparties[i] = signing.NewLocalParty(msg, params, saveByPID[pid.Id], outCh, endCh, len(digest))
		}
		return nil
	}(); err != nil {
		return signer.Signature{}, Stats{}, err
	}

	outs, st, err := route(ctx, tparties, outCh, endCh)
	if err != nil {
		return signer.Signature{}, st, fmt.Errorf("mpc: sign: %w", err)
	}
	r, s := new(big.Int).SetBytes(outs[0].R), new(big.Int).SetBytes(outs[0].S)
	for _, o := range outs[1:] {
		if new(big.Int).SetBytes(o.R).Cmp(r) != 0 || new(big.Int).SetBytes(o.S).Cmp(s) != 0 {
			return signer.Signature{}, st, errors.New("mpc: parties produced different signatures")
		}
	}
	sig := signer.NormalizeLowS(signer.Signature{R: r, S: s})
	if !signer.Verify(pub, digest, sig) {
		return signer.Signature{}, st, errors.New("mpc: ceremony signature does not verify against the joint public key")
	}
	return sig, st, nil
}
