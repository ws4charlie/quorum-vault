package custody

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/chain/sol"
	"github.com/ws4charlie/quorum-vault/internal/coldsign"
	"github.com/ws4charlie/quorum-vault/internal/outbox"
)

// Solana refills. The cold address owns the pool's SOL and token accounts and signs offline, on a durable nonce account of its own: a request names the
// nonce account and the value it holds, so the signature never expires and can mine once. The flow is the one of the other families (requested, exported,
// signed, broadcast, confirmed), and the books are the same: refill -> cold at broadcast, hot -> refill at confirmation.

// SOLColdChain is what Solana refills and the cold setup need from the chain cell.
type SOLColdChain interface {
	ColdNonces(ctx context.Context, cold string) ([]sol.ColdNonce, error)
	ColdNonceValue(ctx context.Context, account string) (string, error)
	ColdSetupState(ctx context.Context, cold string) (missing []int, mints []string, blockhash string, rent uint64, err error)
	SendRawTx(ctx context.Context, raw []byte) (string, error)
	TokenAccountMissing(ctx context.Context, owner, mint string) (bool, error)
	MintOf(symbol string) (string, bool)
}

// solCold returns the chain cell's cold operations.
func (s *Service) solCold() (SOLColdChain, error) {
	c, ok := s.Chain.(SOLColdChain)
	if !ok {
		return nil, fmt.Errorf("%w: this chain cell has no cold operations", ErrInvalid)
	}
	return c, nil
}

// coldKeepNative is what a Solana refill leaves in the cold address's SOL: the next fees and rent of its own ceremonies.
const coldKeepNative = 5_000_000

// solRequestFee is the compute price of a Solana refill request: the configured price at first, raised by the bump percent with every re-export, never above the cap.
func (s *Service) solRequestFee(prev *coldsign.SOLRequest) (limit uint32, price uint64) {
	c := s.Cfg.SOL
	limit, price = c.ComputeUnitLimit, c.ComputeUnitPrice
	if prev != nil && prev.ComputeUnitPrice > 0 || prev != nil && price > 0 {
		price = prev.ComputeUnitPrice
		bump := price * uint64(c.FeeBumpPercent) / 100
		if bump < 1 {
			bump = 1
		}
		price += bump
	}
	if c.MaxMicroLamports > 0 && price > c.MaxMicroLamports {
		price = c.MaxMicroLamports
	}
	return limit, price
}

// ExportSOLRefill builds the request file of a Solana refill from the chain: the cold nonce account and its value, the amount the cold address can pay,
// and whether the hot shard still needs its token account. Another export of a request that has not been signed keeps the nonce value and raises the
// price, which is what the offline signer accepts as a replacement of what it may already have signed.
func (s *Service) ExportSOLRefill(ctx context.Context, id string) (coldsign.SOLRequestFile, error) {
	var zero coldsign.SOLRequestFile
	sc, err := s.solCold()
	if err != nil {
		return zero, err
	}
	r, err := s.GetRefill(ctx, id)
	if err != nil {
		return zero, err
	}
	if r.Status != RefillRequested {
		return zero, fmt.Errorf("%w: refill %s is %s; only a request that has not been signed can be exported again", ErrInvalid, id, r.Status)
	}
	pool, err := partitionPool(r.PartitionID)
	if err != nil {
		return zero, err
	}
	var account, value string
	if r.SOL != nil {
		if cur, err := sc.ColdNonceValue(ctx, r.SOL.NonceAccount); err == nil && cur == r.SOL.NonceValue {
			account, value = r.SOL.NonceAccount, r.SOL.NonceValue // the same value: a replacement (a higher price)
		}
	}
	if account == "" {
		ns, err := sc.ColdNonces(ctx, r.ColdAddress)
		if err != nil {
			return zero, err
		}
		for _, n := range ns {
			var used bool
			if err := s.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM refills WHERE request->>'nonce_account'=$1 AND request->>'nonce_value'=$2 AND id<>$3)`,
				n.Account, n.Value, id).Scan(&used); err != nil {
				return zero, err
			}
			if !used {
				account, value = n.Account, n.Value
				break
			}
		}
		if account == "" {
			return zero, fmt.Errorf("%w: the cold address %s has no nonce account free of an earlier request: run the cold setup, or resolve the open ones", ErrInvalid, r.ColdAddress)
		}
	}
	a := s.Cfg.Assets[r.Asset]
	amount := new(big.Int).Set(r.Amount)
	bal, err := s.Reader.Balance(ctx, r.ColdAddress, r.Asset, 0)
	if err != nil {
		return zero, err
	}
	avail := bal
	if r.Asset == s.Cfg.Native {
		avail = new(big.Int).Sub(bal, big.NewInt(coldKeepNative))
	}
	if avail.Sign() <= 0 {
		return zero, fmt.Errorf("%w: the cold address holds %s of %s, nothing to refill from", ErrInvalid, bal, r.Asset)
	}
	if amount.Cmp(avail) > 0 {
		amount = avail
	}
	limit, price := s.solRequestFee(r.SOL)
	req := coldsign.SOLRequest{Version: coldsign.SOLRequestVersion, Kind: coldsign.KindSOLRefill, ID: r.ID, Chain: s.Cfg.Chain, Pool: pool, Asset: r.Asset, Decimals: a.Decimals,
		From: r.ColdAddress, To: r.To, Amount: amount.String(), NonceAccount: account, NonceValue: value, ComputeUnitLimit: limit, ComputeUnitPrice: price}
	if sym := r.Asset; sym != s.Cfg.Native {
		mint, ok := sc.MintOf(sym)
		if !ok {
			return zero, fmt.Errorf("%w: %s is no configured token", ErrInvalid, sym)
		}
		req.Mint = mint
		if req.CreateDestAccount, err = sc.TokenAccountMissing(ctx, r.To, mint); err != nil {
			return zero, err
		}
		if req.CreateDestAccount {
			req.ComputeUnitLimit += 30_000
		}
	}
	var out coldsign.SOLRequestFile
	err = InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		cur, err := scanRefill(tx.QueryRow(ctx, `SELECT `+refillCols+` FROM refills WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		if cur.Status != RefillRequested {
			return fmt.Errorf("%w: refill %s is %s", ErrInvalid, id, cur.Status)
		}
		req.Revision = cur.Revision + 1
		out = req.File()
		b, _ := json.Marshal(req)
		if _, err = tx.Exec(ctx, `UPDATE refills SET revision=$2, request=$3::jsonb, request_hash=$4, amount=$5::numeric, updated_at=now() WHERE id=$1`,
			id, req.Revision, string(b), out.RequestHash, amount.String()); err != nil {
			return err
		}
		return auditEvent(ctx, tx, id, "refill.exported", map[string]any{"revision": req.Revision, "request_hash": out.RequestHash, "nonce_account": account})
	})
	return out, err
}

// ImportSOLRefill takes the signed file that came back from the ceremony. It must answer the CURRENT export, and the transaction inside must be exactly
// the request's message, signed by the cold address.
func (s *Service) ImportSOLRefill(ctx context.Context, id string, signed coldsign.SOLSigned) (Refill, error) {
	var out Refill
	err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		r, err := scanRefill(tx.QueryRow(ctx, `SELECT `+refillCols+` FROM refills WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		out = r
		if signed.RequestID != "" && signed.RequestID != id {
			return fmt.Errorf("%w: the signed file is for request %s, not %s", ErrInvalid, signed.RequestID, id)
		}
		if r.Status != RefillRequested {
			if r.TxHash != "" && strings.EqualFold(r.TxHash, signed.TxHash) {
				return nil // the same file again
			}
			return fmt.Errorf("%w: refill %s is already %s with another transaction", ErrInvalid, id, r.Status)
		}
		if r.SOL == nil {
			return fmt.Errorf("%w: refill %s was never exported", ErrInvalid, id)
		}
		raw, err := coldsign.VerifySOLSignedMatches(*r.SOL, r.RequestHash, signed)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		if _, err := tx.Exec(ctx, `UPDATE refills SET status='signed', raw_tx=$2, tx_hash=$3, updated_at=now() WHERE id=$1`, id, hex.EncodeToString(raw), signed.TxHash); err != nil {
			return err
		}
		out.Status, out.RawTx, out.TxHash = RefillSigned, hex.EncodeToString(raw), signed.TxHash
		return emit(ctx, tx, outbox.TopicColdMoves, id, "refill.signed", map[string]any{"tx": signed.TxHash})
	})
	return out, err
}

// broadcastSOLRefill sends the imported transaction; sending it again is harmless (the same signature).
func (s *Service) broadcastSOLRefill(ctx context.Context, r Refill, afterSend func()) (string, error) {
	sc, err := s.solCold()
	if err != nil {
		return "", err
	}
	raw, err := hex.DecodeString(r.RawTx)
	if err != nil {
		return "", err
	}
	h, err := sc.SendRawTx(ctx, raw)
	if err != nil {
		return "", err
	}
	if afterSend != nil {
		afterSend()
	}
	return h, s.recordRefillBroadcast(ctx, r.ID, h)
}

// solRefillState maps the chain's state of the refill's transaction to the workflow's: pending, confirmed, reverted (landed and failed: the fee was paid) or
// consumed (the nonce account no longer holds the value the request signed and the transaction did not land, so it can never mine).
func (s *Service) solRefillState(ctx context.Context, id string) (string, error) {
	r, err := s.GetRefill(ctx, id)
	if err != nil {
		return "", err
	}
	st, err := s.Chain.Status(ctx, r.TxHash)
	if err != nil {
		return "", err
	}
	switch st {
	case chain.TxConfirmed:
		return "confirmed", nil
	case chain.TxFailed:
		return "reverted", nil
	}
	if r.SOL != nil {
		sc, err := s.solCold()
		if err != nil {
			return "", err
		}
		cur, err := sc.ColdNonceValue(ctx, r.SOL.NonceAccount)
		if err != nil {
			return "", err
		}
		if cur != r.SOL.NonceValue {
			// Read the signature once more: our transaction may be the one that advanced the nonce and finalized after the first read.
			if st, err = s.Chain.Status(ctx, r.TxHash); err != nil {
				return "", err
			}
			switch st {
			case chain.TxConfirmed:
				return "confirmed", nil
			case chain.TxFailed:
				return "reverted", nil
			}
			return "consumed", nil
		}
	}
	return "pending", nil
}

// closeSOLBroadcast closes a parked Solana refill that was broadcast and whose nonce was consumed by something else: the transaction can never mine, so the
// broadcast booking is undone (cold -> refill). It is refused while the transaction could still land.
func (s *Service) closeSOLBroadcast(ctx context.Context, tx pgx.Tx, r Refill, actor, reason string) error {
	st, err := s.solRefillState(ctx, r.ID)
	if err != nil {
		return err
	}
	if st != "consumed" {
		return fmt.Errorf("%w: %s is broadcast and %s on the chain: it can still land, so it is not closed", ErrInvalid, r.ID, st)
	}
	if err := s.transfer(ctx, tx, "rf-back:"+r.ID, coldAcct(r.PartitionID), refillAcct(s.Cfg.Chain, r.Asset), r.Amount, map[string]any{"refill": r.ID, "closed_by": actor}); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE refills SET status='failed', failure_reason=$2, updated_at=now() WHERE id=$1`, r.ID, "closed by "+actor+": "+reason); err != nil {
		return err
	}
	return emit(ctx, tx, outbox.TopicColdMoves, r.ID, "refill.closed", map[string]any{"by": actor, "reason": reason, "was_parked": r.Reason})
}

// ---- cold setup ----

// ExportColdSetup builds the request file of the one-time setup of a pool's cold address: the nonce accounts it does not have and the token accounts it
// does not have. It returns ok=false when nothing is missing.
func (s *Service) ExportColdSetup(ctx context.Context, pool string) (coldsign.SOLRequestFile, bool, error) {
	var zero coldsign.SOLRequestFile
	sc, err := s.solCold()
	if err != nil {
		return zero, false, err
	}
	cold, ok := s.Cfg.SOL.ColdAddresses[pool]
	if !ok {
		return zero, false, fmt.Errorf("%w: pool %q has no cold address", ErrInvalid, pool)
	}
	missing, mints, bh, rent, err := sc.ColdSetupState(ctx, cold)
	if err != nil {
		return zero, false, err
	}
	if len(missing) == 0 && len(mints) == 0 {
		return zero, false, nil
	}
	req := coldsign.SOLRequest{Version: coldsign.SOLRequestVersion, Kind: coldsign.KindSOLSetup, ID: "setup-" + bh[:8], Revision: 1, Chain: s.Cfg.Chain, Pool: pool,
		From: cold, NonceValue: bh, NonceIndexes: missing, Mints: mints, ComputeUnitLimit: uint32(40_000 + 10_000*len(missing) + 30_000*len(mints))}
	if len(missing) > 0 {
		req.NonceRent = rent
	}
	_, req.ComputeUnitPrice = s.solRequestFee(nil)
	return req.File(), true, nil
}

// SubmitColdSetup sends the signed setup and waits until it is final, then books its cost (fees and rent, paid by the cold address) as the network cost
// of the pool's cold address, so the books keep mirroring the chain.
func (s *Service) SubmitColdSetup(ctx context.Context, req coldsign.SOLRequest, signed coldsign.SOLSigned, wait func(ctx context.Context, sig string) (chain.TxStatus, error)) (string, error) {
	sc, err := s.solCold()
	if err != nil {
		return "", err
	}
	raw, err := coldsign.VerifySOLSignedMatches(req, req.HashHex(), signed)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if req.Kind != coldsign.KindSOLSetup {
		return "", fmt.Errorf("%w: not a setup request", ErrInvalid)
	}
	sig, err := sc.SendRawTx(ctx, raw)
	if err != nil {
		return "", err
	}
	st, err := wait(ctx, sig)
	if err != nil {
		return sig, err
	}
	if st != chain.TxConfirmed {
		return sig, fmt.Errorf("custody: the cold setup %s ended %s", sig, st)
	}
	cost, err := s.Chain.TxFee(ctx, sig)
	if err != nil {
		return sig, err
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
	return sig, InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		if cost.Sign() != 0 {
			if err := s.transfer(ctx, tx, "cold-setup:"+sig, feeAcct(s.Cfg.Chain, s.Cfg.Native), coldAcct(part), cost, map[string]any{"kind": "cold_setup", "tx": sig}); err != nil {
				return err
			}
		}
		return auditOnce(ctx, tx, "cold-setup:"+sig, sig, "cold.setup", map[string]any{"pool": req.Pool, "nonces": req.NonceIndexes, "mints": req.Mints, "cost": cost.String()})
	})
}

var _ = errors.New

// waitFinal polls a transaction until it is final (or a minute passes).
func (s *Service) waitFinal(ctx context.Context, sig string) (chain.TxStatus, error) {
	deadline := time.Now().Add(time.Minute)
	for {
		st, err := s.Chain.Status(ctx, sig)
		if err != nil {
			return "", err
		}
		if st != chain.TxPending {
			return st, nil
		}
		if time.Now().After(deadline) {
			return st, fmt.Errorf("custody: %s is not final after a minute (its blockhash may have expired: export the setup again)", sig)
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(400 * time.Millisecond):
		}
	}
}
