package custody

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain/evm"
	"github.com/ws4charlie/quorum-vault/internal/coldsign"
	"github.com/ws4charlie/quorum-vault/internal/outbox"
	"github.com/ws4charlie/quorum-vault/internal/partition"
)

// A refill brings funds from the cold address back to a hot partition that fell below its low-water mark. The cold key is in an
// offline HSM and the online side cannot use it, so a refill is a request that people act on:
//
//	requested  the planner opened it; an operator exports the request file (nonce and fees read online), takes it across the air
//	           gap, the offline ceremony approves and signs it, the signed file comes back and is imported
//	signed     the imported file was checked against the request; the workflow broadcasts it
//	broadcast  sent; tracked to confirmation, with an ALERT (never a new nonce) if it does not confirm
//	confirmed / failed
//
// Booking, through the clearing account refill:<chain>:<asset>:
//
//	broadcast  refill -> cold   cold's on-chain balance is going down
//	confirmed  hot -> refill    the hot wallet received it; the fee comes out of cold (fee -> cold, native)
//	reverted   cold -> refill   the broadcast booking is undone; only the fee stays

// Refill statuses.
const (
	RefillRequested = "requested"
	RefillSigned    = "signed"
	RefillBroadcast = "broadcast"
	RefillConfirmed = "confirmed"
	RefillFailed    = "failed"
)

// Refill is a row of refills.
type Refill struct {
	ID          string
	Asset       string
	PartitionID string
	ColdAddress string
	To          string
	Amount      *big.Int
	Status      string
	Revision    int
	RequestHash string
	Request     *coldsign.Request
	RawTx       string
	TxHash      string
	Reason      string
	Stuck       bool
}

// Parked reports whether the refill needs an operator for something the workflow cannot do.
func (r Refill) Parked() bool { return strings.HasPrefix(r.Reason, ParkedPrefix) }

const refillCols = `id, asset, partition_id, cold_address, to_address, amount::text, status, revision, COALESCE(request_hash,''), request,
	COALESCE(raw_tx,''), COALESCE(tx_hash,''), COALESCE(failure_reason,''), stuck_alerted`

func scanRefill(row pgx.Row) (Refill, error) {
	var r Refill
	var amt string
	var req []byte
	if err := row.Scan(&r.ID, &r.Asset, &r.PartitionID, &r.ColdAddress, &r.To, &amt, &r.Status, &r.Revision, &r.RequestHash, &req, &r.RawTx, &r.TxHash, &r.Reason, &r.Stuck); err != nil {
		return r, err
	}
	r.Amount = parseBig(amt)
	if len(req) > 0 {
		var q coldsign.Request
		if err := json.Unmarshal(req, &q); err != nil {
			return r, err
		}
		r.Request = &q
	}
	return r, nil
}

// RefillChain is what a refill needs from the chain cell; the EVM adapter has it.
type RefillChain interface {
	ColdTxParams(ctx context.Context, from common.Address) (nonce uint64, tip, maxFee *big.Int, err error)
	SendRaw(ctx context.Context, raw []byte) (string, error)
	RefillTxState(ctx context.Context, txHash string) (evm.RefillState, *big.Int, error)
}

func (s *Service) refillChain() (RefillChain, error) {
	rc, ok := s.Chain.(RefillChain)
	if !ok {
		return nil, fmt.Errorf("%w: this chain cell cannot do refills", ErrInvalid)
	}
	return rc, nil
}

// GetRefill reads one refill.
func (s *Service) GetRefill(ctx context.Context, id string) (Refill, error) {
	r, err := scanRefill(s.Pool.QueryRow(ctx, `SELECT `+refillCols+` FROM refills WHERE id=$1`, id))
	if isNoRows(err) {
		return r, fmt.Errorf("%w: refill %s", ErrNotFound, id)
	}
	return r, err
}

// ListRefills lists refills, newest first.
func (s *Service) ListRefills(ctx context.Context) ([]Refill, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+refillCols+` FROM refills WHERE chain=$1 ORDER BY created_at DESC`, s.Cfg.Chain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Refill
	for rows.Next() {
		r, err := scanRefill(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// OpenRefills lists refills whose workflow must be running: not finished, not parked.
func (s *Service) OpenRefills(ctx context.Context) ([]Refill, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+refillCols+` FROM refills WHERE chain=$1 AND status NOT IN ('confirmed','failed')
		AND COALESCE(failure_reason,'') NOT LIKE 'parked:%' ORDER BY created_at`, s.Cfg.Chain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Refill
	for rows.Next() {
		r, err := scanRefill(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// openRefillFor returns the open refill for the cold address of partition p, if any.
func (s *Service) openRefillFor(ctx context.Context, q interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}, cold string) (string, bool, error) {
	var id string
	err := q.QueryRow(ctx, `SELECT id FROM refills WHERE chain=$1 AND cold_address=$2 AND status NOT IN ('confirmed','failed')`, s.Cfg.Chain, cold).Scan(&id)
	if isNoRows(err) {
		return "", false, nil
	}
	return id, err == nil, err
}

// openRefill opens a refill request for a partition that is below its low mark, unless one is open for the same cold address
// (it has one nonce, so one refill at a time). need is the amount that brings the partition to its target.
func (s *Service) openRefill(ctx context.Context, tx pgx.Tx, partitionID, asset string, need *big.Int) (id string, opened bool, err error) {
	cold, err := s.Cfg.EVM.ColdAddress(partitionID, asset)
	if err != nil {
		return "", false, err
	}
	if id, open, err := s.openRefillFor(ctx, tx, cold.Hex()); err != nil || open {
		return id, false, err
	}
	hot := s.Cfg.EVM.HotAddresses[partitionID]
	id = "rf-" + uuid.NewString()
	tag, err := tx.Exec(ctx, `INSERT INTO refills (id, chain, asset, partition_id, cold_address, to_address, amount, status)
		VALUES ($1,$2,$3,$4,$5,$6,$7::numeric,'requested') ON CONFLICT DO NOTHING`, id, s.Cfg.Chain, asset, partitionID, cold.Hex(), hot.Hex(), need.String())
	if err != nil {
		return "", false, fmt.Errorf("custody: insert refill: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return "", false, nil
	}
	return id, true, emit(ctx, tx, outbox.TopicColdMoves, id, "refill.requested",
		map[string]any{"chain": s.Cfg.Chain, "asset": asset, "partition": partitionID, "from": cold.Hex(), "to": hot.Hex(), "amount": need.String()})
}

// ExportRefill reads the nonce and fees from the node and returns the request file for the ceremony. It can be called again
// (the fees may be stale by the time the ceremony finishes, or the cold nonce moved): each export is a new revision with a new
// hash, so a signed file made for an older export can no longer be imported. Only a request that has not been signed can be exported.
func (s *Service) ExportRefill(ctx context.Context, id string) (coldsign.RequestFile, error) {
	rc, err := s.refillChain()
	if err != nil {
		return coldsign.RequestFile{}, err
	}
	r, err := s.GetRefill(ctx, id)
	if err != nil {
		return coldsign.RequestFile{}, err
	}
	if r.Status != RefillRequested {
		return coldsign.RequestFile{}, fmt.Errorf("%w: refill %s is %s; only a request that has not been signed can be exported again", ErrInvalid, id, r.Status)
	}
	nonce, tip, maxFee, err := rc.ColdTxParams(ctx, common.HexToAddress(r.ColdAddress))
	if err != nil {
		return coldsign.RequestFile{}, err
	}
	a := s.Cfg.Assets[r.Asset]
	req := coldsign.Request{Version: coldsign.RequestVersion, ID: r.ID, Chain: s.Cfg.Chain, ChainID: s.Cfg.EVM.ChainID, Asset: r.Asset,
		From: r.ColdAddress, To: r.To, Amount: r.Amount.String(), Nonce: nonce, Gas: 21000, MaxFeePerGas: maxFee.String(), MaxPriorityFeePerGas: tip.String()}
	if k, perr := partitionPool(r.PartitionID); perr == nil {
		req.Pool = k
	} else {
		return coldsign.RequestFile{}, perr
	}
	if !a.Native() {
		req.Token, req.Gas = a.Address.Hex(), s.Cfg.RefillTokenGas
	}
	var out coldsign.RequestFile
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
		_, err = tx.Exec(ctx, `UPDATE refills SET revision=$2, request=$3::jsonb, request_hash=$4, updated_at=now() WHERE id=$1`, id, req.Revision, string(b), out.RequestHash)
		return err
	})
	return out, err
}

// ImportRefill takes the signed file that came back from the ceremony. It must answer the CURRENT export of this request, and
// the transaction inside must be exactly what the request describes and be signed by the cold address. Importing the same file
// again changes nothing; a different file for a request that is already signed is refused.
func (s *Service) ImportRefill(ctx context.Context, id string, signed coldsign.Signed) (Refill, error) {
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
		if r.Request == nil {
			return fmt.Errorf("%w: refill %s was never exported", ErrInvalid, id)
		}
		if _, err := coldsign.VerifySignedMatches(*r.Request, r.RequestHash, signed); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		raw := strings.TrimPrefix(signed.RawTx, "0x")
		if _, err := hex.DecodeString(raw); err != nil {
			return fmt.Errorf("%w: raw_tx: %v", ErrInvalid, err)
		}
		if _, err := tx.Exec(ctx, `UPDATE refills SET status='signed', raw_tx=$2, tx_hash=$3, updated_at=now() WHERE id=$1`, id, raw, signed.TxHash); err != nil {
			return err
		}
		out.Status, out.RawTx, out.TxHash = RefillSigned, raw, signed.TxHash
		return emit(ctx, tx, outbox.TopicColdMoves, id, "refill.signed", map[string]any{"tx": signed.TxHash})
	})
	return out, err
}

// BroadcastRefill sends the imported transaction and books it as on its way (refill -> cold). It repeats harmlessly: a
// transaction the node already has is fine, and once booked nothing is booked twice. It returns the transaction hash.
func (s *Service) BroadcastRefill(ctx context.Context, id string, afterSend func()) (string, error) {
	rc, err := s.refillChain()
	if err != nil {
		return "", err
	}
	r, err := s.GetRefill(ctx, id)
	if err != nil {
		return "", err
	}
	if r.Status == RefillBroadcast || r.Status == RefillConfirmed {
		return r.TxHash, nil
	}
	if r.Status != RefillSigned {
		return "", fmt.Errorf("custody: refill %s is %s, nothing to broadcast", id, r.Status)
	}
	raw, err := hex.DecodeString(r.RawTx)
	if err != nil {
		return "", err
	}
	h, err := rc.SendRaw(ctx, raw)
	if err != nil {
		return "", err
	}
	if afterSend != nil {
		afterSend()
	}
	return h, s.recordRefillBroadcast(ctx, id, h)
}

func (s *Service) recordRefillBroadcast(ctx context.Context, id, txHash string) error {
	return InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		r, err := scanRefill(tx.QueryRow(ctx, `SELECT `+refillCols+` FROM refills WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		return s.bookRefillBroadcast(ctx, tx, r, txHash)
	})
}

func (s *Service) bookRefillBroadcast(ctx context.Context, tx pgx.Tx, r Refill, txHash string) error {
	if r.Status != RefillSigned {
		return nil
	}
	if err := s.transfer(ctx, tx, "rf-bcast:"+r.ID, refillAcct(s.Cfg.Chain, r.Asset), coldAcct(r.PartitionID), r.Amount, map[string]any{"refill": r.ID, "tx": txHash}); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE refills SET status='broadcast', tx_hash=$2, updated_at=now() WHERE id=$1`, r.ID, txHash); err != nil {
		return err
	}
	return emit(ctx, tx, outbox.TopicColdMoves, r.ID, "refill.broadcast", map[string]any{"tx": txHash, "asset": r.Asset, "amount": r.Amount.String()})
}

// RefillState reports where the refill's transaction is.
func (s *Service) RefillTxState(ctx context.Context, id string) (evm.RefillState, error) {
	rc, err := s.refillChain()
	if err != nil {
		return "", err
	}
	r, err := s.GetRefill(ctx, id)
	if err != nil {
		return "", err
	}
	st, _, err := rc.RefillTxState(ctx, r.TxHash)
	return st, err
}

// MarkRefillStuck records that the "has not confirmed" ALERT was given. It returns true the first time.
func (s *Service) MarkRefillStuck(ctx context.Context, id string) (bool, error) {
	tag, err := s.Pool.Exec(ctx, `UPDATE refills SET stuck_alerted=true, updated_at=now() WHERE id=$1 AND NOT stuck_alerted`, id)
	return tag.RowsAffected() == 1, err
}

// SettleRefill books a mined refill. Confirmed: hot -> refill (the hot wallet has the funds). Reverted: cold -> refill undoes the
// broadcast booking. Either way the network fee, which the cold address paid, comes out of cold: fee -> cold (native).
func (s *Service) SettleRefill(ctx context.Context, id string, reverted bool) error {
	rc, err := s.refillChain()
	if err != nil {
		return err
	}
	r, err := s.GetRefill(ctx, id)
	if err != nil {
		return err
	}
	_, fee, err := rc.RefillTxState(ctx, r.TxHash)
	if err != nil {
		return err
	}
	return InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		r, err := scanRefill(tx.QueryRow(ctx, `SELECT `+refillCols+` FROM refills WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		if r.Status == RefillConfirmed || r.Status == RefillFailed {
			return nil
		}
		if r.Status == RefillSigned { // a crash between the broadcast and its record
			if err := s.bookRefillBroadcast(ctx, tx, r, r.TxHash); err != nil {
				return err
			}
		}
		final, evt, reason := RefillConfirmed, "refill.confirmed", ""
		if reverted {
			final, evt, reason = RefillFailed, "refill.failed", "transaction reverted"
			if err := s.transfer(ctx, tx, "rf-back:"+id, coldAcct(r.PartitionID), refillAcct(s.Cfg.Chain, r.Asset), r.Amount, map[string]any{"refill": id}); err != nil {
				return err
			}
		} else if err := s.transfer(ctx, tx, "rf-hot:"+id, hotAcct(r.PartitionID), refillAcct(s.Cfg.Chain, r.Asset), r.Amount, map[string]any{"refill": id, "tx": r.TxHash}); err != nil {
			return err
		}
		fs := ""
		if fee != nil && fee.Sign() > 0 {
			nativePart, err := s.nativePartitionOf(r.PartitionID)
			if err != nil {
				return err
			}
			if err := s.transfer(ctx, tx, "rf-fee:"+r.TxHash, feeAcct(s.Cfg.Chain, s.Cfg.Native), coldAcct(nativePart), fee, map[string]any{"refill": id, "kind": "cold_network_fee"}); err != nil {
				return err
			}
			fs = fee.String()
		}
		if _, err := tx.Exec(ctx, `UPDATE refills SET status=$2, fee=NULLIF($3,'')::numeric, failure_reason=NULLIF($4,''), updated_at=now() WHERE id=$1`, id, final, fs, reason); err != nil {
			return err
		}
		return emit(ctx, tx, outbox.TopicColdMoves, id, evt, map[string]any{"tx": r.TxHash, "fee": fs})
	})
}

// ParkRefill records that the refill needs a person (for example its nonce was used by another transaction).
func (s *Service) ParkRefill(ctx context.Context, id, reason string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE refills SET failure_reason=$2, updated_at=now() WHERE id=$1 AND status NOT IN ('confirmed','failed')`, id, ParkedPrefix+" "+reason)
	return err
}

// FundCold books that the operator put amount of asset into the cold address (a deposit from outside the system), so the
// ledger keeps mirroring the chain: cold -> opfund. id makes it idempotent. shard picks the partition the amount is booked to.
func (s *Service) FundCold(ctx context.Context, id string, shard int, asset string, amount *big.Int) error {
	if shard < 0 || shard >= len(s.Cfg.HotShards) || amount == nil || amount.Sign() <= 0 {
		return fmt.Errorf("%w: fund cold", ErrInvalid)
	}
	if _, ok := s.Cfg.Assets[asset]; !ok {
		return fmt.Errorf("%w: unknown asset %q", ErrInvalid, asset)
	}
	p := s.Cfg.PartitionKey(asset, shard).String()
	return InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		return s.transfer(ctx, tx, "fund-cold:"+id, coldAcct(p), opFundAcct(s.Cfg.Chain, asset), amount, map[string]any{"kind": "cold_funding"})
	})
}

var _ = errors.New

// partitionPool is the pool of a partition ID.
func partitionPool(partitionID string) (string, error) {
	k, err := partition.Parse(partitionID)
	if err != nil {
		return "", err
	}
	return k.Pool, nil
}
