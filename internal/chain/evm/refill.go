package evm

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// The cold address is not one of ours to sign for: its transactions are built offline and signed in a ceremony, so none of
// the nonce manager applies. These are the few chain operations a refill needs from the online side.

// ColdTxParams reads what an unsigned refill request needs from the node: the cold address's next nonce (counting pending
// transactions) and generous fees. The fee cap leaves room for the days a ceremony may take: three times the current base fee
// plus the tip. The offline signer has its own cap on gas x fee.
func (a *Adapter) ColdTxParams(ctx context.Context, from common.Address) (nonce uint64, tip, maxFee *big.Int, err error) {
	if nonce, err = a.ec.PendingNonceAt(ctx, from); err != nil {
		return 0, nil, nil, fmt.Errorf("evm: nonce of %s: %w", from, err)
	}
	if tip, err = a.ec.SuggestGasTipCap(ctx); err != nil {
		return 0, nil, nil, fmt.Errorf("evm: tip: %w", err)
	}
	h, err := a.ec.HeaderByNumber(ctx, nil)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("evm: header: %w", err)
	}
	base := h.BaseFee
	if base == nil {
		base = new(big.Int)
	}
	maxFee = new(big.Int).Add(new(big.Int).Mul(base, big.NewInt(3)), tip)
	return nonce, tip, maxFee, nil
}

// SendRaw broadcasts a signed transaction made elsewhere. A transaction the node already has, or that already mined, is not an
// error; a nonce that is used by some other transaction is.
func (a *Adapter) SendRaw(ctx context.Context, raw []byte) (string, error) {
	t := new(types.Transaction)
	if err := t.UnmarshalBinary(raw); err != nil {
		return "", fmt.Errorf("evm: decode raw transaction: %w", err)
	}
	if t.ChainId().Uint64() != a.cfg.ChainID {
		return "", fmt.Errorf("evm: transaction chain id %s, want %d", t.ChainId(), a.cfg.ChainID)
	}
	if err := a.ec.SendTransaction(ctx, t); err != nil {
		msg := strings.ToLower(err.Error())
		switch {
		case strings.Contains(msg, "already known") || strings.Contains(msg, "known transaction") || strings.Contains(msg, "already imported"):
		case strings.Contains(msg, "nonce too low"):
			if r, rerr := a.ec.TransactionReceipt(ctx, t.Hash()); rerr != nil || r == nil {
				return "", fmt.Errorf("evm: broadcast: %w", err) // the nonce was used by another transaction
			}
		default:
			return "", fmt.Errorf("evm: broadcast: %w", err)
		}
	}
	return t.Hash().Hex(), nil
}

// RefillState is the state of a refill transaction.
type RefillState string

const (
	RefillPending   RefillState = "pending"   // no final receipt yet (not mined, or not deep enough)
	RefillConfirmed RefillState = "confirmed" // mined, successful and past the confirmations
	RefillReverted  RefillState = "reverted"  // mined and failed
)

// RefillTxState reads a transaction's receipt. The fee is set once there is a receipt.
func (a *Adapter) RefillTxState(ctx context.Context, txHash string) (RefillState, *big.Int, error) {
	h := common.HexToHash(txHash)
	r, err := a.ec.TransactionReceipt(ctx, h)
	if errors.Is(err, ethereum.NotFound) {
		return RefillPending, nil, nil
	}
	if err != nil {
		return "", nil, fmt.Errorf("evm: receipt: %w", err)
	}
	var fee *big.Int
	if r.EffectiveGasPrice != nil {
		fee = new(big.Int).Mul(new(big.Int).SetUint64(r.GasUsed), r.EffectiveGasPrice)
	}
	if r.Status != types.ReceiptStatusSuccessful {
		return RefillReverted, fee, nil
	}
	_, safe, ok, err := a.safeHead(ctx)
	if err != nil {
		return "", nil, err
	}
	if !ok || r.BlockNumber.Uint64() > safe {
		return RefillPending, fee, nil
	}
	return RefillConfirmed, fee, nil
}
