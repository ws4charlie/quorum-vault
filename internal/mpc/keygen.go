package mpc

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/bnb-chain/tss-lib/v4/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v4/tss"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/ws4charlie/quorum-vault/internal/mpc/seal"
)

func (c *Cluster) preParamsPath(id int) string {
	return filepath.Join(c.cfg.DataDir, "preparams", partyName(id)+".json")
}

func preParamsAAD(id int) []byte { return []byte("preparams|" + partyName(id)) }

// PreParams makes sure every party has cached pre-params (two safe primes for
// its Paillier key and ring-Pedersen parameters; the slow part of keygen) and
// returns how long generating the missing ones took (0 if all were cached).
// fresh regenerates all of them. Parties generate in parallel. The cache is
// sealed like a share: it holds the party's Paillier private key.
func (c *Cluster) PreParams(ctx context.Context, fresh bool) (time.Duration, error) {
	_, d, err := c.preParams(ctx, fresh)
	return d, err
}

func (c *Cluster) preParams(ctx context.Context, fresh bool) ([]keygen.LocalPreParams, time.Duration, error) {
	c.ppMu.Lock()
	defer c.ppMu.Unlock()
	out := make([]keygen.LocalPreParams, len(c.parties))
	var missing []int
	for i, p := range c.parties {
		if !fresh {
			pp, err := c.loadPreParams(ctx, p)
			if err == nil {
				out[i] = pp
				continue
			}
			if !errors.Is(err, os.ErrNotExist) {
				return nil, 0, err
			}
		}
		missing = append(missing, i)
	}
	if len(missing) == 0 {
		return out, 0, nil
	}

	start := time.Now()
	gctx, cancel := context.WithTimeout(ctx, c.cfg.PreParamsTimeout)
	defer cancel()
	errs := make(chan error, len(missing))
	for _, i := range missing {
		go func() {
			pp, err := keygen.GeneratePreParamsWithContext(gctx)
			if err != nil {
				errs <- fmt.Errorf("mpc: party %d pre-params: %w", c.parties[i].cfg.ID, err)
				return
			}
			out[i] = *pp
			errs <- nil
		}()
	}
	var gerr error
	for range missing {
		gerr = errors.Join(gerr, <-errs)
	}
	if gerr != nil {
		return nil, 0, gerr
	}
	took := time.Since(start)
	for _, i := range missing {
		p := c.parties[i]
		bz, err := json.Marshal(out[i])
		if err != nil {
			return nil, 0, err
		}
		env, err := seal.Seal(ctx, p.tok, bz, preParamsAAD(p.cfg.ID))
		clear(bz)
		if err != nil {
			return nil, 0, err
		}
		if err := seal.WriteFile(c.preParamsPath(p.cfg.ID), env); err != nil {
			return nil, 0, err
		}
	}
	return out, took, nil
}

func (c *Cluster) loadPreParams(ctx context.Context, p *party) (keygen.LocalPreParams, error) {
	var pp keygen.LocalPreParams
	env, err := os.ReadFile(c.preParamsPath(p.cfg.ID))
	if err != nil {
		return pp, err
	}
	bz, err := seal.Open(ctx, p.tok, env, preParamsAAD(p.cfg.ID))
	if err != nil {
		return pp, fmt.Errorf("mpc: party %d pre-params: %w", p.cfg.ID, err)
	}
	defer clear(bz)
	if err := json.Unmarshal(bz, &pp); err != nil {
		return pp, fmt.Errorf("mpc: party %d pre-params: %w", p.cfg.ID, err)
	}
	if !pp.ValidateWithProof() {
		return pp, fmt.Errorf("mpc: party %d cached pre-params are invalid (delete %s)", p.cfg.ID, c.preParamsPath(p.cfg.ID))
	}
	return pp, nil
}

// Keygen runs a dealerless DKG among all configured parties and stores each
// party's save data sealed under its own token in keys/<keyRef>/. It returns
// the joint public key. On any error nothing is left under keys/<keyRef>.
// Pre-params are generated first if not cached (not counted in Stats).
func (c *Cluster) Keygen(ctx context.Context, keyRef string) (_ *ecdsa.PublicKey, _ Stats, err error) {
	if err := checkKeyRef(keyRef); err != nil {
		return nil, Stats{}, err
	}
	final := c.keyDir(keyRef)
	if _, err := os.Stat(final); err == nil {
		return nil, Stats{}, fmt.Errorf("%w: %s", ErrKeyExists, keyRef)
	}
	pps, _, err := c.preParams(ctx, false)
	if err != nil {
		return nil, Stats{}, err
	}
	nonce, err := sessionNonce()
	if err != nil {
		return nil, Stats{}, err
	}

	ids := make(tss.UnSortedPartyIDs, len(c.parties))
	byKey := map[string]int{} // PartyID.Id -> index into c.parties / pps
	for i, p := range c.parties {
		ids[i] = newPID(p.cfg.ID)
		byKey[ids[i].Id] = i
	}
	sorted := tss.SortPartyIDs(ids)
	peers := tss.NewPeerContext(sorted)
	outCh := make(chan tss.Message, outBuffer)
	endCh := make(chan *keygen.LocalPartySaveData, len(sorted))
	tparties := make([]tss.Party, len(sorted))
	if err := func() (err error) {
		defer recoverErr(&err)
		for i, pid := range sorted {
			params := tss.NewParameters(tss.S256(), peers, pid, len(sorted), c.cfg.Threshold)
			params.SetSessionNonce(nonce)
			tparties[i] = keygen.NewLocalParty(params, outCh, endCh, pps[byKey[pid.Id]])
		}
		return nil
	}(); err != nil {
		return nil, Stats{}, err
	}

	saves, st, err := route(ctx, tparties, outCh, endCh)
	if err != nil {
		return nil, st, fmt.Errorf("mpc: keygen %s: %w", keyRef, err)
	}

	// Every party must have derived the same joint public key.
	byID := map[int]*keygen.LocalPartySaveData{}
	var pub *ecdsa.PublicKey
	for _, s := range saves {
		if s.ShareID == nil || !s.ShareID.IsInt64() {
			return nil, st, errors.New("mpc: keygen output without a share id")
		}
		id := int(s.ShareID.Int64())
		if _, err := c.party(id); err != nil {
			return nil, st, err
		}
		byID[id] = s
		k := &ecdsa.PublicKey{Curve: crypto.S256(), X: s.ECDSAPub.X(), Y: s.ECDSAPub.Y()}
		if pub == nil {
			pub = k
		} else if pub.X.Cmp(k.X) != 0 || pub.Y.Cmp(k.Y) != 0 {
			return nil, st, ErrPublicKeyMismatch
		}
	}
	if len(byID) != len(c.parties) {
		return nil, st, fmt.Errorf("mpc: keygen produced %d distinct shares, want %d", len(byID), len(c.parties))
	}

	// Seal into a temp dir, then rename: either all shares appear or none.
	keysDir := filepath.Dir(final)
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		return nil, st, err
	}
	tmp, err := os.MkdirTemp(keysDir, ".tmp-"+keyRef+"-")
	if err != nil {
		return nil, st, err
	}
	defer func() {
		if err != nil {
			os.RemoveAll(tmp)
		}
	}()
	for id, s := range byID {
		p, _ := c.party(id)
		bz, err := json.Marshal(s)
		if err != nil {
			return nil, st, err
		}
		env, err := seal.Seal(ctx, p.tok, bz, shareAAD(keyRef, id))
		clear(bz)
		if err != nil {
			return nil, st, fmt.Errorf("mpc: seal party %d: %w", id, err)
		}
		if err := seal.WriteFile(filepath.Join(tmp, partyName(id)+".sealed"), env); err != nil {
			return nil, st, err
		}
	}
	if err := os.Rename(tmp, final); err != nil {
		return nil, st, fmt.Errorf("mpc: store %s: %w", keyRef, err)
	}
	return pub, st, nil
}
