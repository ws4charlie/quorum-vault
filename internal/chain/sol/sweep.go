package sol

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
)

// Sweeps from deposit addresses to a hot shard. One transaction takes the funds of several deposit addresses of one asset: the hot shard pays the fee
// and is the first signer; each deposit key (the 2-party HD keyset) signs once, as the owner of its own address. Like a withdrawal it signs the value of
// a nonce account of the shard's pool, because the signatures of several parties would otherwise race a blockhash that expires in about a minute, and
// so at most one version of a sweep can land.

// sweepLegs is the addresses of a sweep intent: its legs, or the one address it names.
func sweepLegs(s chain.SweepIntent) []chain.SweepLeg {
	if len(s.Legs) > 0 {
		return s.Legs
	}
	return []chain.SweepLeg{{From: s.From, Amount: s.Amount}}
}

// BuildSweep builds the sweep of s on a free nonce account of the shard that serves s.ToPartition. The allocation commits or rolls back with tx.
func (a *Adapter) BuildSweep(ctx context.Context, tx pgx.Tx, s chain.SweepIntent) (chain.UnsignedTx, error) {
	hot, ok := a.cfg.hot[s.ToPartition]
	if !ok {
		return chain.UnsignedTx{}, fmt.Errorf("sol: partition %q has no hot shard", s.ToPartition)
	}
	if s.ID == "" {
		return chain.UnsignedTx{}, errors.New("sol: empty owner id")
	}
	if have, err := a.ownerAlloc(ctx, tx, "sweep", s.ID, false, true); err == nil {
		if have.status == "allocated" || have.status == "broadcast" {
			msg, err := msgOfPayload(have.payload)
			if err != nil {
				return chain.UnsignedTx{}, err
			}
			return a.unsignedFromStored(s.ToPartition, have.payload, msg)
		}
		return chain.UnsignedTx{}, fmt.Errorf("sol: sweep %s already landed", s.ID)
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return chain.UnsignedTx{}, err
	}
	legs := sweepLegs(s)
	if len(legs) > MaxSweepLegs {
		return chain.UnsignedTx{}, fmt.Errorf("sol: a sweep takes at most %d addresses", MaxSweepLegs)
	}
	type leg struct {
		key   [32]byte
		idx   uint32
		amt   uint64
		close bool
	}
	var ls []leg
	total := new(big.Int)
	for _, l := range legs {
		if l.Amount == nil || l.Amount.Sign() <= 0 || !l.Amount.IsUint64() {
			return chain.UnsignedTx{}, fmt.Errorf("sol: sweep amount of %s", l.From)
		}
		var idx int64
		if err := tx.QueryRow(ctx, `SELECT derivation_index FROM deposit_addresses WHERE chain=$1 AND address=$2 AND kind='ed25519'`, a.cfg.Chain, l.From).Scan(&idx); err != nil {
			return chain.UnsignedTx{}, fmt.Errorf("sol: %s is not a known deposit address: %w", l.From, err)
		}
		want, err := a.cfg.node.DepositAddressAt(uint32(idx))
		if err != nil || want != l.From {
			return chain.UnsignedTx{}, fmt.Errorf("sol: deposit address %s does not match its derivation index %d", l.From, idx)
		}
		k, _ := ParseAddress(l.From)
		ls = append(ls, leg{k, uint32(idx), l.Amount.Uint64(), l.Close})
		total.Add(total, l.Amount)
	}
	if len(s.Legs) > 0 && s.Amount != nil && s.Amount.Cmp(total) != 0 {
		return chain.UnsignedTx{}, fmt.Errorf("sol: the sweep amount %s is not the sum of its legs %s", s.Amount, total)
	}
	var body []Ix
	if s.Asset == Native {
		for _, l := range ls {
			body = append(body, TransferIx(l.key, hot, l.amt))
		}
	} else {
		m, ok := a.mintOf(s.Asset)
		if !ok {
			return chain.UnsignedTx{}, fmt.Errorf("sol: asset %q is not configured", s.Asset)
		}
		hotATA, err := ATA(hot, m.raw)
		if err != nil {
			return chain.UnsignedTx{}, err
		}
		if _, err := a.rpc.GetAccount(ctx, Address(hotATA), Confirmed); errors.Is(err, ErrNoAccount) {
			body = append(body, CreateATAIx(hot, hotATA, hot, m.raw)) // the hot shard opens its own account once, and pays its rent
		} else if err != nil {
			return chain.UnsignedTx{}, err
		}
		dec := uint8(a.cfg.TokenDecimals[s.Asset])
		for _, l := range ls {
			depATA, err := ATA(l.key, m.raw)
			if err != nil {
				return chain.UnsignedTx{}, err
			}
			body = append(body, CheckedTransferIx(depATA, m.raw, hotATA, l.key, l.amt, dec))
			if l.close {
				// Closing needs the account empty: only when this sweep takes everything the account holds now.
				accts, err := a.rpc.TokenAccountsByOwner(ctx, Address(l.key), m.address, Confirmed)
				if err != nil {
					return chain.UnsignedTx{}, err
				}
				for _, t := range accts {
					if t.Pubkey == Address(depATA) && t.Amount == l.amt {
						body = append(body, CloseAccountIx(depATA, hot, l.key))
					}
				}
			}
		}
	}
	idxs := make([]uint32, len(ls))
	for i, l := range ls {
		idxs[i] = l.idx
	}
	return a.takeSlot(ctx, tx, "sweep", s.ID, s.ToPartition, hot, body, a.cfg.ComputeUnitLimit, a.cfg.ComputeUnitPrice, idxs...)
}

// EstimateSweepFee is the most one sweep of one address costs in lamports: two signatures and the priority fee at the configured price. A batch
// costs less per address, so the planner's rule errs on the side of leaving dust.
func (a *Adapter) EstimateSweepFee(_ context.Context, _ chain.SweepIntent) (*big.Int, error) {
	prio := new(big.Int).Mul(new(big.Int).SetUint64(uint64(a.cfg.ComputeUnitLimit)), new(big.Int).SetUint64(a.cfg.ComputeUnitPrice))
	prio.Div(prio, big.NewInt(1_000_000))
	return prio.Add(prio, big.NewInt(2*5000)), nil
}

// MovedAssets lists what a final sweep took out of each deposit address, as the chain reports it: the lamports a deposit signer's account lost, and the
// tokens its token accounts lost, per configured token. The rent of a closed token account is not the deposit address's money and is not listed (it is part
// of the transaction's cost, see TxFee).
func (a *Adapter) MovedAssets(ctx context.Context, hash string) ([]chain.MovedAsset, error) {
	tx, err := a.rpc.GetTransaction(ctx, hash)
	if err != nil {
		return nil, err
	}
	if tx == nil || tx.Meta == nil {
		return nil, fmt.Errorf("sol: transaction %s has no finalized record yet", hash)
	}
	var out []chain.MovedAsset
	keys := tx.Transaction.Message.AccountKeys
	for i, k := range keys {
		if i == 0 || !k.Signer || i >= len(tx.Meta.PreBalances) || i >= len(tx.Meta.PostBalances) {
			continue
		}
		if pre, post := tx.Meta.PreBalances[i], tx.Meta.PostBalances[i]; pre > post {
			out = append(out, chain.MovedAsset{Address: k.Pubkey, Asset: Native, Amount: new(big.Int).SetUint64(pre - post)})
		}
	}
	type key struct{ owner, mint string }
	pre, post := map[key]*big.Int{}, map[key]*big.Int{}
	add := func(m map[key]*big.Int, tbs []TokenBalance) {
		for _, tb := range tbs {
			n, ok := new(big.Int).SetString(tb.UITokenAmount.Amount, 10)
			if !ok {
				continue
			}
			k := key{tb.Owner, tb.Mint}
			if m[k] == nil {
				m[k] = new(big.Int)
			}
			m[k].Add(m[k], n)
		}
	}
	add(pre, tx.Meta.PreTokenBalances)
	add(post, tx.Meta.PostTokenBalances)
	for k, p := range pre {
		after := post[k]
		if after == nil {
			after = new(big.Int)
		}
		d := new(big.Int).Sub(p, after)
		if d.Sign() <= 0 {
			continue
		}
		for _, m := range a.cfg.mints {
			if m.address == k.mint {
				out = append(out, chain.MovedAsset{Address: k.owner, Asset: m.symbol, Amount: d})
			}
		}
	}
	return out, nil
}

// MaxBatch is how many deposit addresses one sweep of the asset kind can take in the worst case (a token sweep that also opens the hot shard's
// account and closes every deposit account, all keys distinct, a compute price set) without the transaction passing MaxTransaction bytes. A SOL sweep
// is limited by the same bound.
func MaxBatch(token bool) int {
	hot := [32]byte{1}
	mint := [32]byte{2}
	best := 0
	for n := 1; n <= MaxSweepLegs; n++ {
		ixs := []Ix{AdvanceNonceIx(NonceAddress(hot, 0), hot), SetLimitIx(1), SetPriceIx(1)}
		hotATA := [32]byte{3}
		if token {
			ixs = append(ixs, CreateATAIx(hot, hotATA, hot, mint))
		}
		for k := 0; k < n; k++ {
			dk := [32]byte{10, byte(k)}
			if token {
				depATA := [32]byte{20, byte(k)}
				ixs = append(ixs, CheckedTransferIx(depATA, mint, hotATA, dk, 1, 6), CloseAccountIx(depATA, hot, dk))
			} else {
				ixs = append(ixs, TransferIx(dk, hot, 1))
			}
		}
		if 1+64*(1+n)+len(Compile(hot, [32]byte{4}, ixs...)) > MaxTransaction {
			break
		}
		best = n
	}
	return best
}
