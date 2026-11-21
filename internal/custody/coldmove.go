package custody

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/coldsign"
	"github.com/ws4charlie/quorum-vault/internal/outbox"
)

// A cold key replacement moves what the old cold address holds to the new one (docs/runbooks/cold-key-replacement.md). In the books it is the SAME cold
// account with a new address: the books count value per pool, not per address, and a move between two cold addresses of one pool changes who owns
// nothing. So a cold-move books nothing at broadcast and, at settlement, only the network fee (old cold -> fee). Reconcile counts the old address
// (config cold.retiring) together with the new one, so the cold check stays exact before, during and after the move.
//
// It rides the refills table (kind "cold-move"): the same export, offline ceremony, import, broadcast and tracking, and the same rule of one open request
// per cold address, here the OLD one.

// isColdSigner reports whether addr is the configured cold address of the partition's native pool, or the retiring one: a fee paid by either is paid out
// of the cold books.
func (s *Service) isColdSigner(nativePart, addr string) bool {
	if cold, err := s.Cfg.EVM.ColdAddress(nativePart, s.Cfg.Native); err == nil && strings.EqualFold(cold.Hex(), addr) {
		return true
	}
	if key, err := s.Cfg.EVM.ColdKey(nativePart, s.Cfg.Native); err == nil {
		if old, ok := s.Cfg.ColdRetiring[key]; ok && strings.EqualFold(old, addr) {
			return true
		}
	}
	return false
}

// retiringFor is the old cold address that retires into the configured cold address cur for asset ("" when none).
func (s *Service) retiringFor(cur, asset string) string {
	for shard := 0; shard < s.Cfg.shardCount(); shard++ {
		p := s.Cfg.PartitionKey(asset, shard).String()
		key, err := s.Cfg.EVM.ColdKey(p, asset)
		if err != nil {
			continue
		}
		if a, ok := s.Cfg.EVM.ColdAddresses[key]; ok && strings.EqualFold(a.Hex(), cur) {
			return s.Cfg.ColdRetiring[key]
		}
	}
	return ""
}

// RequestColdMove opens the cold-to-cold request for one asset of the retiring cold address: everything it holds (tokens first, the native coin last,
// because the native coin pays the gas of the rest). One request is open per old address, so it is called again for the next asset; it returns the open one
// if there is one, and ErrNotFound-like "done" (nil, false) when the old address holds nothing of any asset.
func (s *Service) RequestColdMove(ctx context.Context) (Refill, bool, error) {
	if len(s.Cfg.ColdRetiring) == 0 {
		return Refill{}, false, fmt.Errorf("%w: cold.retiring is empty: no cold key is being replaced", ErrInvalid)
	}
	if s.Cfg.Family == FamilyBTC {
		return s.requestBTCColdMove(ctx)
	}
	if s.Cfg.Family == FamilySOL {
		return Refill{}, false, fmt.Errorf("%w: a Solana cold move is requested with the Solana steps", ErrInvalid)
	}
	rc, err := s.refillChain()
	if err != nil {
		return Refill{}, false, err
	}
	h, err := s.Reader.SafeHead(ctx)
	if err != nil {
		return Refill{}, false, err
	}
	// Tokens first, native last.
	var order []string
	for _, sym := range s.Cfg.AssetList {
		if sym != s.Cfg.Native {
			order = append(order, sym)
		}
	}
	order = append(order, s.Cfg.Native)
	var out Refill
	found := false
	err = InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		for _, sym := range order {
			part := s.Cfg.PartitionKey(sym, 0).String()
			key, err := s.Cfg.EVM.ColdKey(part, sym)
			if err != nil {
				continue
			}
			old, ok := s.Cfg.ColdRetiring[key]
			if !ok {
				continue
			}
			if id, open, err := s.openRefillFor(ctx, tx, old); err != nil {
				return err
			} else if open {
				r, err := scanRefill(tx.QueryRow(ctx, `SELECT `+refillCols+` FROM refills WHERE id=$1`, id))
				out, found = r, true
				return err
			}
			bal, err := s.Reader.Balance(ctx, old, sym, h)
			if err != nil {
				return err
			}
			if bal.Sign() == 0 || (sym == s.Cfg.Native && bal.Cmp(big.NewInt(21000)) <= 0) {
				continue
			}
			nc, err := s.Cfg.EVM.ColdAddress(part, sym)
			if err != nil {
				return err
			}
			id := "mv-" + uuid.NewString()
			if _, err := tx.Exec(ctx, `INSERT INTO refills (id, chain, kind, asset, partition_id, cold_address, to_address, amount, status)
				VALUES ($1,$2,'cold-move',$3,$4,$5,$6,$7::numeric,'requested')`, id, s.Cfg.Chain, sym, part, old, nc.Hex(), bal.String()); err != nil {
				return fmt.Errorf("custody: insert cold move: %w", err)
			}
			if err := emit(ctx, tx, outbox.TopicColdMoves, id, "cold_move.requested",
				map[string]any{"chain": s.Cfg.Chain, "asset": sym, "from": old, "to": nc.Hex()}); err != nil {
				return err
			}
			r, err := scanRefill(tx.QueryRow(ctx, `SELECT `+refillCols+` FROM refills WHERE id=$1`, id))
			out, found = r, true
			return err
		}
		return nil
	})
	_ = rc
	return out, found, err
}

// coldMoveRequest builds the request of a cold-move at export time: the balance and the fee are read now. Tokens move whole. The native coin moves whole
// minus its own fee: the fee cap equals the tip so the price paid is exactly the cap, and nothing is left behind.
func (s *Service) coldMoveRequest(ctx context.Context, r Refill, nonce uint64, tip, maxFee *big.Int) (coldsign.Request, error) {
	pool, err := partitionPool(r.PartitionID)
	if err != nil {
		return coldsign.Request{}, err
	}
	h, err := s.Reader.SafeHead(ctx)
	if err != nil {
		return coldsign.Request{}, err
	}
	bal, err := s.Reader.Balance(ctx, r.ColdAddress, r.Asset, h)
	if err != nil {
		return coldsign.Request{}, err
	}
	a := s.Cfg.Assets[r.Asset]
	req := coldsign.Request{Version: coldsign.RequestVersion, ID: r.ID, Chain: s.Cfg.Chain, ChainID: s.Cfg.EVM.ChainID, Pool: pool, Kind: coldsign.KindColdMove, Asset: r.Asset,
		From: r.ColdAddress, To: r.To, Nonce: nonce, Gas: 21000, MaxFeePerGas: maxFee.String(), MaxPriorityFeePerGas: tip.String()}
	if a.Native() {
		req.MaxPriorityFeePerGas = maxFee.String()
		cost := new(big.Int).Mul(maxFee, big.NewInt(21000))
		bal = new(big.Int).Sub(bal, cost)
	} else {
		req.Token, req.Gas = a.Address.Hex(), s.Cfg.RefillTokenGas
	}
	if bal.Sign() <= 0 {
		return coldsign.Request{}, fmt.Errorf("%w: the old cold address holds nothing of %s that a move could carry after its fee", ErrInvalid, r.Asset)
	}
	req.Amount = bal.String()
	return req, nil
}

var _ = common.Address{}

// requestBTCColdMove opens the next cold-to-cold request of a Bitcoin cold key replacement: the retiring address's available outputs, one transaction at a
// time (max_inputs of them). One request is open per old address; (nil, false) when the old address holds nothing available.
func (s *Service) requestBTCColdMove(ctx context.Context) (Refill, bool, error) {
	cm, ok := s.Chain.(chain.ColdMover)
	if !ok {
		return Refill{}, false, fmt.Errorf("%w: this chain cell cannot move a cold address", ErrInvalid)
	}
	var out Refill
	found := false
	err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		for key := range s.Cfg.ColdRetiring {
			pool := strings.TrimSuffix(key, "/native")
			old, avail, err := cm.ColdRetiringAvailable(ctx, pool)
			if err != nil {
				return err
			}
			if id, open, err := s.openRefillFor(ctx, tx, old); err != nil {
				return err
			} else if open {
				r, err := scanRefill(tx.QueryRow(ctx, `SELECT `+refillCols+` FROM refills WHERE id=$1`, id))
				out, found = r, true
				return err
			}
			if avail.Sign() == 0 {
				continue
			}
			part := s.Cfg.PartitionKey(s.Cfg.Native, 0).String()
			nc, err := s.Cfg.ColdAddressOf(part, s.Cfg.Native)
			if err != nil {
				return err
			}
			id := "mv-" + uuid.NewString()
			if _, err := tx.Exec(ctx, `INSERT INTO refills (id, chain, kind, asset, partition_id, cold_address, to_address, amount, status)
				VALUES ($1,$2,'cold-move',$3,$4,$5,$6,$7::numeric,'requested')`, id, s.Cfg.Chain, s.Cfg.Native, part, old, nc, avail.String()); err != nil {
				return fmt.Errorf("custody: insert cold move: %w", err)
			}
			if err := emit(ctx, tx, outbox.TopicColdMoves, id, "cold_move.requested", map[string]any{"chain": s.Cfg.Chain, "asset": s.Cfg.Native, "from": old, "to": nc}); err != nil {
				return err
			}
			r, err := scanRefill(tx.QueryRow(ctx, `SELECT `+refillCols+` FROM refills WHERE id=$1`, id))
			out, found = r, true
			return err
		}
		return nil
	})
	return out, found, err
}

// RebuildColdMove discards the exported request of an open cold-to-cold move, so that the next export builds a new one (new fees, other outputs). It is refused
// once a signed file was imported (that file is the move), and it needs the operator to say why and to confirm the offline step: the offline signer remembers
// what it signed at a nonce (EVM), for an outpoint (Bitcoin) or for a nonce value (Solana) and refuses a different request there, so before a rebuilt request
// can be signed the custodians must remove that record on the offline machine, or know that nothing was signed (docs/runbooks/cold-key-replacement.md,
// "A request that must be rebuilt"). If a signed file of the old request exists it must be imported, or destroyed: a signed file whose hash was replaced
// cannot be imported.
func (s *Service) RebuildColdMove(ctx context.Context, id, actor, reason string, offlineRecordCleared bool) error {
	if !ValidID(actor) || strings.TrimSpace(reason) == "" {
		return fmt.Errorf("%w: an actor and a reason are required", ErrInvalid)
	}
	if !offlineRecordCleared {
		return fmt.Errorf("%w: confirm that the offline record of the old request was cleared, or that nothing was signed for it", ErrInvalid)
	}
	return InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		r, err := scanRefill(tx.QueryRow(ctx, `SELECT `+refillCols+` FROM refills WHERE id=$1 FOR UPDATE`, id))
		if isNoRows(err) {
			return fmt.Errorf("%w: refill %s", ErrNotFound, id)
		}
		if err != nil {
			return err
		}
		if r.Kind != coldsign.KindColdMove || r.Status != RefillRequested {
			return fmt.Errorf("%w: %s is a %s in status %s: only a cold-to-cold move that has not been imported can be rebuilt", ErrInvalid, id, r.Kind, r.Status)
		}
		if _, err := tx.Exec(ctx, `UPDATE refills SET request=NULL, request_hash=NULL, updated_at=now() WHERE id=$1`, id); err != nil {
			return err
		}
		return auditEvent(ctx, tx, id, "cold_move.rebuilt", map[string]any{"by": actor, "reason": reason, "previous_request_hash": r.RequestHash, "revision": r.Revision})
	})
}
