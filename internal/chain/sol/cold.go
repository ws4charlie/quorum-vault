package sol

import (
	"context"
	"errors"
	"fmt"
	"sort"
)

// What a cold refill needs from the chain, read-only: the cold address signs offline, so none of the hot nonce manager applies. A cold nonce account is
// one of the pool accounts derived from the COLD address (the same derivation as the hot ones) whose authority is the cold address.

// ColdNonce is a nonce account of a cold address and the value it holds at finalized commitment.
type ColdNonce struct {
	Index   int
	Account string
	Value   string
}

// ColdNonces lists the existing nonce accounts of the cold address, lowest index first. An account at a pool address that is not a nonce account of
// the cold address is an error.
func (a *Adapter) ColdNonces(ctx context.Context, cold string) ([]ColdNonce, error) {
	ck, err := ParseAddress(cold)
	if err != nil {
		return nil, err
	}
	var out []ColdNonce
	for i := 0; i < a.cfg.NoncePool; i++ {
		addr := Address(NonceAddress(ck, i))
		st, err := a.rpc.GetNonce(ctx, addr, Finalized)
		switch {
		case errors.Is(err, ErrNoAccount):
		case err != nil:
			return nil, fmt.Errorf("sol: cold pool account %d (%s) is not a usable nonce account: %w", i, addr, err)
		case st.Authority != ck:
			return nil, fmt.Errorf("sol: cold pool account %d (%s) has another authority than the cold address", i, addr)
		default:
			out = append(out, ColdNonce{Index: i, Account: addr, Value: Address(st.Value)})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out, nil
}

// ColdNonceValue is the value a nonce account holds now at finalized commitment.
func (a *Adapter) ColdNonceValue(ctx context.Context, account string) (string, error) {
	st, err := a.rpc.GetNonce(ctx, account, Finalized)
	if err != nil {
		return "", err
	}
	return Address(st.Value), nil
}

// ColdSetupState says what the one-time setup of a cold address still has to create: the missing pool nonce accounts, the missing associated
// token accounts of the configured tokens, and a recent blockhash for the setup message.
func (a *Adapter) ColdSetupState(ctx context.Context, cold string) (missing []int, mints []string, blockhash string, rent uint64, err error) {
	ck, err := ParseAddress(cold)
	if err != nil {
		return nil, nil, "", 0, err
	}
	have, err := a.ColdNonces(ctx, cold)
	if err != nil {
		return nil, nil, "", 0, err
	}
	present := map[int]bool{}
	for _, n := range have {
		present[n.Index] = true
	}
	for i := 0; i < a.cfg.NoncePool; i++ {
		if !present[i] {
			missing = append(missing, i)
		}
	}
	syms := make([]string, 0, len(a.cfg.Tokens))
	for s := range a.cfg.Tokens {
		syms = append(syms, s)
	}
	sort.Strings(syms)
	for _, s := range syms {
		m := a.cfg.Tokens[s]
		mk, err := ParseAddress(m)
		if err != nil {
			return nil, nil, "", 0, err
		}
		ata, err := ATA(ck, mk)
		if err != nil {
			return nil, nil, "", 0, err
		}
		if _, err := a.rpc.GetAccount(ctx, Address(ata), Finalized); errors.Is(err, ErrNoAccount) {
			mints = append(mints, m)
		} else if err != nil {
			return nil, nil, "", 0, err
		}
	}
	bh, err := a.rpc.LatestBlockhash(ctx, Finalized)
	if err != nil {
		return nil, nil, "", 0, err
	}
	return missing, mints, Address(bh), a.cfg.NonceRent, nil
}

// SendRawTx broadcasts a transaction signed elsewhere (a cold refill or the cold setup) and returns its signature.
func (a *Adapter) SendRawTx(ctx context.Context, raw []byte) (string, error) {
	return a.rpc.SendRaw(ctx, raw)
}

// TokenAccountMissing reports whether owner has no associated token account of mint at finalized commitment.
func (a *Adapter) TokenAccountMissing(ctx context.Context, owner, mint string) (bool, error) {
	o, err := ParseAddress(owner)
	if err != nil {
		return false, err
	}
	m, err := ParseAddress(mint)
	if err != nil {
		return false, err
	}
	ata, err := ATA(o, m)
	if err != nil {
		return false, err
	}
	if _, err := a.rpc.GetAccount(ctx, Address(ata), Finalized); errors.Is(err, ErrNoAccount) {
		return true, nil
	} else if err != nil {
		return false, err
	}
	return false, nil
}

// MintOf is the mint address of a configured token symbol.
func (a *Adapter) MintOf(symbol string) (string, bool) { m, ok := a.cfg.Tokens[symbol]; return m, ok }
