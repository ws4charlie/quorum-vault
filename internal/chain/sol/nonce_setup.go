package sol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/chain"
)

// Creating the nonce pool of a hot shard. The accounts are made by CreateAccountWithSeed + InitializeNonceAccount, all signed by the hot shard
// alone through the signing zone (an operator approves the intent). The message carries a normal recent blockhash, since there is no nonce yet to
// sign; if it expires unsigned or unsent, the operator builds a new one.

// LatestBlockhash is the newest blockhash at a commitment.
func (r *RPC) LatestBlockhash(ctx context.Context, c string) ([32]byte, error) {
	var out struct {
		Value struct {
			Blockhash string `json:"blockhash"`
		} `json:"value"`
	}
	if err := r.Call(ctx, &out, "getLatestBlockhash", commitment{c}); err != nil {
		return [32]byte{}, err
	}
	return ParseAddress(out.Value.Blockhash)
}

// MissingNonces lists the pool accounts of the shard of partitionID that do not exist yet. An account that exists but is not a nonce account of
// this shard is an error: something else sits at an address the pool needs.
func (a *Adapter) MissingNonces(ctx context.Context, partitionID string) ([]int, error) {
	hot, ok := a.cfg.hot[partitionID]
	if !ok {
		return nil, fmt.Errorf("sol: partition %q has no hot shard", partitionID)
	}
	var missing []int
	for i := 0; i < a.cfg.NoncePool; i++ {
		addr := Address(NonceAddress(hot, i))
		st, err := a.rpc.GetNonce(ctx, addr, Confirmed)
		switch {
		case errors.Is(err, ErrNoAccount):
			missing = append(missing, i)
		case err != nil:
			return nil, fmt.Errorf("sol: pool account %d (%s) exists and is not a usable nonce account: %w", i, addr, err)
		case st.Authority != hot:
			return nil, fmt.Errorf("sol: pool account %d (%s) has another authority than the hot shard", i, addr)
		}
	}
	return missing, nil
}

// BuildNonceSetup builds the creation of every missing pool account of the partition's shard (in one message). It returns the unsigned
// transaction and the total rent the intent must name; nothing when no account is missing.
func (a *Adapter) BuildNonceSetup(ctx context.Context, partitionID string) (u chain.UnsignedTx, amount *big.Int, count int, err error) {
	hot := a.cfg.hot[partitionID]
	missing, err := a.MissingNonces(ctx, partitionID)
	if err != nil || len(missing) == 0 {
		return chain.UnsignedTx{}, new(big.Int), 0, err
	}
	// The rent the zone and the core agree on must be what the node asks for, or the accounts would be created without rent exemption.
	if rent, err := a.rpc.MinimumRent(ctx, NonceAccountSize); err != nil {
		return chain.UnsignedTx{}, nil, 0, err
	} else if rent != a.cfg.NonceRent {
		return chain.UnsignedTx{}, nil, 0, fmt.Errorf("sol: the node asks %d lamports for a nonce account, the config says %d", rent, a.cfg.NonceRent)
	}
	bh, err := a.rpc.LatestBlockhash(ctx, Confirmed)
	if err != nil {
		return chain.UnsignedTx{}, nil, 0, err
	}
	ixs := []Ix{SetLimitIx(20_000 + uint32(len(missing))*5_000)}
	if a.cfg.ComputeUnitPrice > 0 {
		ixs = append(ixs, SetPriceIx(a.cfg.ComputeUnitPrice))
	}
	for _, i := range missing {
		ixs = append(ixs, CreateNonceIxs(hot, i, a.cfg.NonceRent)...)
	}
	msg := Compile(hot, bh, ixs...)
	pl, err := json.Marshal(Payload{Message: msg})
	if err != nil {
		return chain.UnsignedTx{}, nil, 0, err
	}
	u = chain.UnsignedTx{Chain: a.cfg.Chain, Digest: msg, Payload: pl, KeyRef: chain.KeyRef{PartitionID: partitionID, Path: PathHot}}
	return u, new(big.Int).Mul(new(big.Int).SetUint64(a.cfg.NonceRent), big.NewInt(int64(len(missing)))), len(missing), nil
}

// SubmitNonceSetup sends the signed creation and waits until it is final. A creation that fails on the chain is an error (the fee was paid).
func (a *Adapter) SubmitNonceSetup(ctx context.Context, s chain.SignedTx, wait time.Duration) (string, error) {
	sig, _, err := splitTx(s.Raw)
	if err != nil {
		return "", err
	}
	hash, err := a.rpc.SendRaw(ctx, s.Raw)
	if err != nil {
		return "", err
	}
	_ = sig
	deadline := time.Now().Add(wait)
	for {
		st, err := a.sigStatus(ctx, hash)
		if err != nil {
			return hash, err
		}
		if st != nil && st.Status == Finalized {
			if st.Failed() {
				return hash, fmt.Errorf("sol: the nonce setup %s landed and failed: %s", hash, st.Err)
			}
			return hash, nil
		}
		if time.Now().After(deadline) {
			return hash, fmt.Errorf("sol: the nonce setup %s did not finalize in %s (its blockhash may have expired: build it again)", hash, wait)
		}
		select {
		case <-ctx.Done():
			return hash, ctx.Err()
		case <-time.After(400 * time.Millisecond):
		}
	}
}
