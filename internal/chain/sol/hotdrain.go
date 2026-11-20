package sol

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sort"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/partition"
)

// Draining an old generation of a hot shard (K4). The planner of the core asks, one step at a time, for the next transaction that moves what the old key
// holds to its successor; each step is one message on a RECENT blockhash (the old key's nonce accounts are among what is drained, so no nonce can carry the
// last steps), paid and signed by the old key alone. The order is the one that leaves nothing behind and needs nothing the old key cannot give:
//
//  1. every configured token: transfer all of it, and close the old token account with its rent paid to the successor (an empty account is only closed)
//  2. SOL to the successor for its own nonce pool, which the operator then creates; withdrawals from the new generation wait for it, so the old pool is only
//     drained once it exists
//  3. every nonce account of the old pool: withdraw its balance to the successor
//  4. the SOL that is left, all but the fee of this last transaction: the old address ends at zero
//
// Every step is derived from what the chain shows at finalized commitment, so a step repeated after a crash moves what is left and nothing else. What the
// old address holds besides this (tokens of a mint the config does not list, token accounts that are not the associated one) is reported, never moved or
// burned: only the configured tokens are the books' business.

// DrainFee is the network fee of one drain transaction: one signature, no priority fee.
const DrainFee = 5000

// DrainStep is one transaction of a drain.
type DrainStep struct {
	Kind   string   // "token", "token-close", "nonce" or "sol"
	Asset  string   // the asset the intent names
	Amount *big.Int // what the intent names: lamports or token units (zero for the close of an empty token account)
	Note   string
	Tx     chain.UnsignedTx
}

// DrainReport is what NextDrainStep found besides the step.
type DrainReport struct {
	// Done: nothing movable is left at the old address.
	Done bool
	// Wait: why no step can be taken now (empty when there is one, or when Done).
	Wait string
	// Unknown lists holdings the drain does not move: tokens of a mint the config does not list, token accounts that are not an associated one.
	Unknown []string
}

// partitionFor is the partition of asset in the shard of the hot partition part.
func partitionFor(part, asset string) (string, error) {
	k, err := partition.Parse(part)
	if err != nil {
		return "", err
	}
	k.Asset = asset
	return k.String(), nil
}

func tokenAmount(accts []TokenAccount, ata string) (uint64, bool) {
	for _, t := range accts {
		if t.Pubkey == ata {
			return t.Amount, true
		}
	}
	return 0, false
}

// NextDrainStep builds the next drain transaction from the old key (oldAddr) to the successor (succAddr, generation succGen of the shard whose native partition
// is shardPart), reading the chain at finalized commitment.
func (a *Adapter) NextDrainStep(ctx context.Context, shardPart, oldAddr, succAddr string, succGen int) (*DrainStep, DrainReport, error) {
	var rep DrainReport
	old, err := ParseAddress(oldAddr)
	if err != nil {
		return nil, rep, err
	}
	succ, err := ParseAddress(succAddr)
	if err != nil {
		return nil, rep, err
	}
	lamports, _, err := a.rpc.Lamports(ctx, oldAddr, Finalized)
	if err != nil {
		return nil, rep, err
	}
	all, err := a.rpc.TokenAccountsByOwner(ctx, oldAddr, "", Finalized)
	if err != nil {
		return nil, rep, err
	}
	bh, err := a.rpc.LatestBlockhash(ctx, Confirmed)
	if err != nil {
		return nil, rep, err
	}
	build := func(ixs ...Ix) []byte {
		return Compile(old, bh, append([]Ix{SetLimitIx(a.cfg.ComputeUnitLimit)}, ixs...)...)
	}
	mk := func(kind, asset string, amount uint64, note string, msg []byte) (*DrainStep, DrainReport, error) {
		part, err := partitionFor(shardPart, asset)
		if err != nil {
			return nil, rep, err
		}
		u, err := a.unsigned(part, msg)
		if err != nil {
			return nil, rep, err
		}
		return &DrainStep{Kind: kind, Asset: asset, Amount: new(big.Int).SetUint64(amount), Note: note, Tx: u}, rep, nil
	}
	known := map[string]bool{}

	// 1. tokens
	for _, m := range a.cfg.mints {
		ata, err := ATA(old, m.raw)
		if err != nil {
			return nil, rep, err
		}
		known[Address(ata)] = true
		amt, exists := tokenAmount(all, Address(ata))
		if !exists {
			continue
		}
		dst, err := ATA(succ, m.raw)
		if err != nil {
			return nil, rep, err
		}
		need := uint64(DrainFee)
		var ixs []Ix
		if amt > 0 {
			if _, err := a.rpc.GetAccount(ctx, Address(dst), Finalized); errors.Is(err, ErrNoAccount) {
				ixs = append(ixs, CreateATAIx(old, dst, succ, m.raw))
				rent, err := a.rpc.MinimumRent(ctx, 165)
				if err != nil {
					return nil, rep, err
				}
				need += rent // the rent of the successor's account, paid by the old key (the zone's shape)
			} else if err != nil {
				return nil, rep, err
			}
			ixs = append(ixs, CheckedTransferIx(ata, m.raw, dst, old, amt, uint8(a.cfg.TokenDecimals[m.symbol])))
		}
		ixs = append(ixs, CloseAccountIx(ata, succ, old))
		if lamports < need {
			rep.Wait = fmt.Sprintf("the old address holds %d %s and only %d lamports: its next transaction needs about %d; send SOL to it", amt, m.symbol, lamports, need)
			return nil, rep, nil
		}
		kind := "token"
		if amt == 0 {
			kind = "token-close"
		}
		return mk(kind, m.symbol, amt, fmt.Sprintf("%d %s and the token account to the successor", amt, m.symbol), build(ixs...))
	}
	for _, t := range all {
		if !known[t.Pubkey] && t.Amount > 0 {
			rep.Unknown = append(rep.Unknown, fmt.Sprintf("%d of mint %s in token account %s", t.Amount, t.Mint, t.Pubkey))
		} else if !known[t.Pubkey] {
			rep.Unknown = append(rep.Unknown, fmt.Sprintf("an empty token account %s of mint %s", t.Pubkey, t.Mint))
		}
	}
	sort.Strings(rep.Unknown)

	// 2. the successor's own nonce pool: its key creates it, from the SOL it holds, so a first transfer funds it, and then the operator creates the pool
	// (qv-sol-nonces -generation N, or qv-rekey nonces): withdrawals from the new generation wait for it. The old pool is not touched before it exists.
	missing, err := a.MissingNoncesGen(ctx, shardPart, succGen)
	if err != nil {
		return nil, rep, err
	}
	if len(missing) > 0 {
		have, _, err := a.rpc.Lamports(ctx, succAddr, Finalized)
		if err != nil {
			return nil, rep, err
		}
		// the new address must stay rent-exempt after it pays for the accounts and the fee, or the creation fails on the chain
		floor, err := a.rpc.MinimumRent(ctx, 0)
		if err != nil {
			return nil, rep, err
		}
		need := uint64(len(missing))*a.cfg.NonceRent + floor + a.NonceSetupFee(len(missing)) + DrainFee
		keep := uint64(a.cfg.NoncePool+1) * DrainFee // what the old key still pays for: a withdrawal of each pool account and the last transfer
		if have < need {
			give := need - have
			if lamports < give+keep {
				rep.Wait = fmt.Sprintf("the successor needs %d lamports to create its nonce pool and the old address holds only %d (it keeps %d for its own last transactions); send SOL to the successor", give, lamports, keep)
				return nil, rep, nil
			}
			return mk("sol", Native, give, fmt.Sprintf("%d lamports to fund the successor's nonce pool", give), build(TransferIx(old, succ, give)))
		}
		rep.Wait = fmt.Sprintf("the successor's nonce pool is not complete (%d accounts missing): create it (qv-rekey nonces, or qv-sol-nonces -generation %d); the old pool is drained after", len(missing), succGen)
		return nil, rep, nil
	}

	// 3. the nonce accounts of the old pool
	for i := 0; i < a.cfg.NoncePool; i++ {
		na := NonceAddress(old, i)
		acct, err := a.rpc.GetAccount(ctx, Address(na), Finalized)
		if errors.Is(err, ErrNoAccount) {
			continue
		}
		if err != nil {
			return nil, rep, err
		}
		st, err := ParseNonceAccount(acct.Data)
		if err != nil || acct.Owner != SystemProgram || st.Authority != old {
			return nil, rep, fmt.Errorf("sol: pool account %d (%s) of the old key is not a nonce account of it", i, Address(na))
		}
		// the last owner of the account landed and the node still shows the value it signed: the node lags, a version may still be on its way
		var last string
		if err := a.pool.QueryRow(ctx, `SELECT nonce_value FROM sol_nonce_allocations WHERE chain=$1 AND address=$2 AND status IN ('confirmed','cancelled') ORDER BY id DESC LIMIT 1`,
			a.cfg.Chain, Address(na)).Scan(&last); err == nil && last == Address(st.Value) {
			rep.Wait = fmt.Sprintf("the node still shows the value the last owner of pool account %d signed", i)
			return nil, rep, nil
		} else if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return nil, rep, err
		}
		var open int
		if err := a.pool.QueryRow(ctx, `SELECT count(*) FROM sol_nonce_allocations WHERE chain=$1 AND address=$2 AND status IN ('allocated','broadcast')`, a.cfg.Chain, Address(na)).Scan(&open); err != nil {
			return nil, rep, err
		}
		if open > 0 {
			rep.Wait = fmt.Sprintf("pool account %d still carries a withdrawal or sweep", i)
			return nil, rep, nil
		}
		if lamports < DrainFee {
			rep.Wait = fmt.Sprintf("the old address holds %d lamports, its next transaction costs %d; send SOL to it", lamports, DrainFee)
			return nil, rep, nil
		}
		return mk("nonce", Native, acct.Lamports, fmt.Sprintf("pool account %d (%d lamports) to the successor", i, acct.Lamports),
			build(WithdrawNonceIx(na, succ, old, acct.Lamports)))
	}

	// 4. the SOL that is left
	if lamports <= DrainFee {
		rep.Done = true
		return nil, rep, nil
	}
	return mk("sol", Native, lamports-DrainFee, fmt.Sprintf("the last %d lamports to the successor", lamports-DrainFee), build(TransferIx(old, succ, lamports-DrainFee)))
}

// RecentSubmit sends a signed drain transaction (a recent blockhash, no nonce). Sending one the node already knows is not an error.
func (a *Adapter) RecentSubmit(ctx context.Context, raw []byte) (string, error) {
	return a.rpc.SendRaw(ctx, raw)
}

// RecentState is what became of a transaction on a recent blockhash.
type RecentState string

const (
	RecentPending RecentState = "pending"
	RecentOK      RecentState = "ok"      // final and succeeded
	RecentFailed  RecentState = "failed"  // final and failed (the fee was paid, nothing moved)
	RecentExpired RecentState = "expired" // not final and its blockhash is no longer valid: it can never land
)

// BlockhashValid asks whether the node would still take a transaction on this blockhash.
func (r *RPC) BlockhashValid(ctx context.Context, bh [32]byte) (bool, error) {
	var out struct {
		Value bool `json:"value"`
	}
	if err := r.Call(ctx, &out, "isBlockhashValid", Address(bh), commitment{"processed"}); err != nil {
		return false, err
	}
	return out.Value, nil
}

// RecentStatus tells what became of the transaction with signature hash whose message has the blockhash bh.
func (a *Adapter) RecentStatus(ctx context.Context, hash string, bh [32]byte) (RecentState, error) {
	st, err := a.sigStatus(ctx, hash)
	if err != nil {
		return "", err
	}
	if st != nil {
		if st.Status != Finalized {
			return RecentPending, nil
		}
		if st.Failed() {
			return RecentFailed, nil
		}
		return RecentOK, nil
	}
	valid, err := a.rpc.BlockhashValid(ctx, bh)
	if err != nil {
		return "", err
	}
	if valid {
		return RecentPending, nil
	}
	// the blockhash is dead: one more look, in case the transaction finalized between the two reads
	if st, err = a.sigStatus(ctx, hash); err != nil {
		return "", err
	} else if st != nil {
		return a.RecentStatus(ctx, hash, bh)
	}
	return RecentExpired, nil
}

// DrainCost is what the finalized drain transaction cost the shard, in lamports: the change in what the old key and the successor hold together (a nonce
// account withdrawn into the successor, or a token account closed into it, brings rent back and makes the cost negative). A transaction that failed cost its fee.
func (a *Adapter) DrainCost(ctx context.Context, hash, oldAddr, succAddr string) (*big.Int, error) {
	tx, err := a.rpc.GetTransaction(ctx, hash)
	if err != nil {
		return nil, err
	}
	if tx == nil || tx.Meta == nil {
		return nil, fmt.Errorf("sol: transaction %s has no finalized record yet", hash)
	}
	keys := tx.Transaction.Message.AccountKeys
	if len(tx.Meta.PreBalances) != len(keys) || len(tx.Meta.PostBalances) != len(keys) {
		return nil, fmt.Errorf("sol: transaction %s: balances do not match its accounts", hash)
	}
	pre, post := new(big.Int), new(big.Int)
	for i, k := range keys {
		if k.Pubkey == oldAddr || k.Pubkey == succAddr {
			pre.Add(pre, new(big.Int).SetUint64(tx.Meta.PreBalances[i]))
			post.Add(post, new(big.Int).SetUint64(tx.Meta.PostBalances[i]))
		}
	}
	return pre.Sub(pre, post), nil
}

// HoldsLamports is the finalized SOL balance of an address.
func (a *Adapter) HoldsLamports(ctx context.Context, addr string) (uint64, error) {
	n, _, err := a.rpc.Lamports(ctx, addr, Finalized)
	return n, err
}

// OpenOwnWork counts the nonce allocations of the hot key at address that are still open: work built from it that has not finished.
func (a *Adapter) OpenOwnWork(ctx context.Context, q chain.Querier, addr string) (int, error) {
	var n int
	err := q.QueryRow(ctx, `SELECT count(*) FROM sol_nonce_allocations WHERE chain=$1 AND hot_address=$2 AND status IN ('allocated','broadcast')`, a.cfg.Chain, addr).Scan(&n)
	return n, err
}

// BlockhashOf is the recent blockhash a job payload's message signs.
func BlockhashOf(payload []byte) ([32]byte, error) {
	p, err := parsePayload(payload)
	if err != nil {
		return [32]byte{}, err
	}
	m, err := DecodeMessage(p.Message)
	if err != nil {
		return [32]byte{}, err
	}
	return m.Blockhash, nil
}

// NativeDrainReserve is what an old address may keep without having to be drained: less than the fee of the last transaction cannot be moved.
func (a *Adapter) NativeDrainReserve(context.Context) (*big.Int, error) {
	return big.NewInt(DrainFee), nil
}
