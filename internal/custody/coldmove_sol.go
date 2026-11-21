package custody

import (
	"context"
	"fmt"
	"math/big"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/coldsign"
)

// The Solana side of a cold key replacement (docs/runbooks/cold-key-replacement.md). Like the cold setup and close it is not a refill: each step is exported
// as a request file, carried through the ceremony and submitted, and the submit waits until the transaction is final and books its network cost. The books
// keep the same cold account; Reconcile counts the retiring address with the new one.
//
// The steps come in one order, found again from the chain each time, so every call is safe to repeat:
//
//	1. each token the old address holds: transfer everything to the new address on a durable nonce, and close the old token account (its rent returns to the old
//	   cold address); the new address's token account is opened by the move if the new address has none
//	2. SOL: everything but the fee of this transaction and a reserve that keeps the account above the rent minimum
//	3. the old address's nonce accounts are closed, their rent going to the new cold address, and the reserve is sent with them less the fee of this
//	   transaction, so the old address ends at exactly zero
//
// Prices are zero here: the fee of a transaction is then exactly 5000 lamports per signature, which is what lets the last step end at zero.

const (
	solMoveFee = 5000
	// solMoveReserve is what the SOL step leaves: a system account may not be left between zero and the rent minimum (890880 lamports), so the old address keeps
	// this much until the last step sends it on, with the fee of that step paid from it.
	solMoveReserve = 1_000_000
)

// currentColdOf maps a retiring cold address to the configured cold address of its pool (anything else is returned as it is).
func (s *Service) currentColdOf(addr string) string {
	for pool, old := range s.Cfg.ColdRetiring {
		if old == addr {
			if cur, ok := s.Cfg.SOL.ColdAddresses[pool]; ok {
				return cur
			}
		}
	}
	return addr
}

// ExportColdMoveSOL returns the request file of the next step of the replacement of a pool's cold address, or done when the old address holds nothing.
func (s *Service) ExportColdMoveSOL(ctx context.Context, pool string) (rf coldsign.SOLRequestFile, done bool, err error) {
	var zero coldsign.SOLRequestFile
	sc, err := s.solCold()
	if err != nil {
		return zero, false, err
	}
	old, ok := s.Cfg.ColdRetiring[pool]
	nc, ok2 := s.Cfg.SOL.ColdAddresses[pool]
	if !ok || !ok2 {
		return zero, false, fmt.Errorf("%w: pool %q has no retiring cold address", ErrInvalid, pool)
	}
	nonces, err := sc.ColdNonces(ctx, old)
	if err != nil {
		return zero, false, err
	}
	limit := s.Cfg.SOL.ComputeUnitLimit
	base := coldsign.SOLRequest{Version: coldsign.SOLRequestVersion, Chain: s.Cfg.Chain, Pool: pool, From: old, To: nc, Revision: 1, ComputeUnitPrice: 0}
	for _, sym := range s.Cfg.AssetList {
		if sym == s.Cfg.Native {
			continue
		}
		bal, err := s.Reader.Balance(ctx, old, sym, 0)
		if err != nil {
			return zero, false, err
		}
		if bal.Sign() == 0 {
			continue
		}
		if len(nonces) == 0 {
			return zero, false, fmt.Errorf("%w: the old cold address has no nonce account left to sign a move on", ErrInvalid)
		}
		mint, ok := sc.MintOf(sym)
		if !ok {
			return zero, false, fmt.Errorf("%w: %s is no configured token", ErrInvalid, sym)
		}
		r := base
		r.Kind, r.ID, r.Asset, r.Mint, r.Decimals, r.Amount = coldsign.KindSOLColdMove, "mvs-"+nonces[0].Value[:10], sym, mint, s.Cfg.Assets[sym].Decimals, bal.String()
		r.NonceAccount, r.NonceValue, r.ComputeUnitLimit, r.CloseSource = nonces[0].Account, nonces[0].Value, limit+30_000, true
		if r.CreateDestAccount, err = sc.TokenAccountMissing(ctx, nc, mint); err != nil {
			return zero, false, err
		}
		return r.File(), false, nil
	}
	sol, err := s.Reader.Balance(ctx, old, s.Cfg.Native, 0)
	if err != nil {
		return zero, false, err
	}
	if len(nonces) > 0 && sol.Cmp(big.NewInt(solMoveReserve+2*solMoveFee)) > 0 {
		r := base
		amount := new(big.Int).Sub(sol, big.NewInt(solMoveReserve+solMoveFee))
		r.Kind, r.ID, r.Asset, r.Decimals, r.Amount = coldsign.KindSOLColdMove, "mvs-"+nonces[0].Value[:10], s.Cfg.Native, s.Cfg.Assets[s.Cfg.Native].Decimals, amount.String()
		r.NonceAccount, r.NonceValue, r.ComputeUnitLimit = nonces[0].Account, nonces[0].Value, limit
		return r.File(), false, nil
	}
	if len(nonces) == 0 {
		return zero, true, nil
	}
	bh, err := sc.ColdBlockhash(ctx)
	if err != nil {
		return zero, false, err
	}
	r := base
	r.Kind, r.ID, r.NonceValue, r.ComputeUnitLimit = coldsign.KindSOLColdMoveClose, "mvc-"+bh[:10], bh, 10_000+5_000*uint32(min(len(nonces), 8))
	if sol.Cmp(big.NewInt(solMoveFee)) > 0 { // what is left goes with the rent, less this step's own fee
		r.Asset, r.Amount = "", new(big.Int).Sub(sol, big.NewInt(solMoveFee)).String()
	}
	for _, n := range nonces[:min(len(nonces), 8)] {
		lam, err := sc.AccountLamports(ctx, n.Account)
		if err != nil {
			return zero, false, err
		}
		r.NonceIndexes, r.Lamports = append(r.NonceIndexes, n.Index), append(r.Lamports, lam)
	}
	return r.File(), false, nil
}

// SubmitColdMoveSOL sends the signed file of a step and waits until it is final, then books its network cost against the cold account: the fee, and the rent of
// a token account the move opened, less the rent of one it closed (which returned to the old cold address), less the rent of the nonce accounts a last step
// sent to the new cold address.
func (s *Service) SubmitColdMoveSOL(ctx context.Context, req coldsign.SOLRequest, signed coldsign.SOLSigned, wait func(ctx context.Context, sig string) (chain.TxStatus, error)) (string, error) {
	sc, err := s.solCold()
	if err != nil {
		return "", err
	}
	if req.Kind != coldsign.KindSOLColdMove && req.Kind != coldsign.KindSOLColdMoveClose {
		return "", fmt.Errorf("%w: not a cold move request", ErrInvalid)
	}
	old, ok := s.Cfg.ColdRetiring[req.Pool]
	if !ok || req.From != old || req.To != s.Cfg.SOL.ColdAddresses[req.Pool] {
		return "", fmt.Errorf("%w: the request does not move the retiring cold address of pool %q to its configured cold address", ErrInvalid, req.Pool)
	}
	raw, err := coldsign.VerifySOLSignedMatches(req, req.HashHex(), signed)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	credit := new(big.Int)
	if req.Kind == coldsign.KindSOLColdMoveClose {
		for _, l := range req.Lamports {
			credit.Add(credit, new(big.Int).SetUint64(l))
		}
	}
	if _, err := s.Pool.Exec(ctx, `INSERT INTO sol_cold_ops (chain, signature, cold, kind, credit) VALUES ($1,$2,$3,$4,$5::numeric) ON CONFLICT DO NOTHING`,
		s.Cfg.Chain, signed.TxHash, req.From, req.Kind, credit.String()); err != nil {
		return "", err
	}
	sig, err := sc.SendRawTx(ctx, raw)
	if err != nil {
		return "", err
	}
	st, err := wait(ctx, sig)
	if err != nil {
		return sig, err
	}
	if st != chain.TxConfirmed && st != chain.TxFailed {
		return sig, fmt.Errorf("custody: the cold move %s ended %s", sig, st)
	}
	cost, err := s.Chain.TxFee(ctx, sig)
	if err != nil {
		return sig, err
	}
	if st == chain.TxConfirmed {
		cost.Sub(cost, credit)
	} else {
		credit = new(big.Int) // a failed transaction paid its fee and moved nothing
	}
	var part string
	for i := 0; i < s.Cfg.shardCount(); i++ {
		if p := s.Cfg.PartitionKey(s.Cfg.Native, i); string(p.Pool) == req.Pool {
			part = p.String()
			break
		}
	}
	if part == "" {
		return sig, fmt.Errorf("%w: pool %q has no partition", ErrInvalid, req.Pool)
	}
	err = InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		switch {
		case cost.Sign() > 0:
			if err := s.transfer(ctx, tx, "cold-setup:"+sig, feeAcct(s.Cfg.Chain, s.Cfg.Native), coldAcct(part), cost, map[string]any{"kind": "cold_" + req.Kind, "tx": sig}); err != nil {
				return err
			}
		case cost.Sign() < 0:
			if err := s.transfer(ctx, tx, "cold-setup:"+sig, coldAcct(part), feeAcct(s.Cfg.Chain, s.Cfg.Native), new(big.Int).Neg(cost), map[string]any{"kind": "cold_" + req.Kind, "tx": sig}); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE sol_cold_ops SET booked=true WHERE chain=$1 AND signature=$2`, s.Cfg.Chain, sig); err != nil {
			return err
		}
		return auditOnce(ctx, tx, "cold-setup:"+sig, sig, "cold.move", map[string]any{"pool": req.Pool, "kind": req.Kind, "asset": req.Asset, "amount": req.Amount, "cost": cost.String(), "status": string(st)})
	})
	if err == nil && st == chain.TxFailed {
		err = fmt.Errorf("custody: the cold move %s failed on the chain (its fee was booked); export the step again", sig)
	}
	return sig, err
}
