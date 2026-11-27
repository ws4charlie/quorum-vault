package evm

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"
)

// ReadReceipt reads the receipt of a transaction with one eth_getTransactionReceipt call and returns it with the fee its sender paid (ParseReceipt).
// The error is ethereum.NotFound while the node has no receipt. Every place that books a paid EVM fee reads it here.
func ReadReceipt(ctx context.Context, c *rpc.Client, txHash common.Hash) (*types.Receipt, *big.Int, error) {
	var raw json.RawMessage
	if err := c.CallContext(ctx, &raw, "eth_getTransactionReceipt", txHash); err != nil {
		return nil, nil, err
	}
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil, ethereum.NotFound
	}
	return ParseReceipt(raw)
}

// ParseReceipt decodes a receipt and the fee its sender paid: gasUsed × effectiveGasPrice + l1Fee.
//
// l1Fee is the L1 data fee an OP-stack chain (Base, Optimism) charges on top of the gas. The node reports it in the receipt, and go-ethereum's
// types.Receipt drops it, so it is read here from the same JSON. Absent or null: 0 (an L1 chain, or a deposit transaction). Present but not a
// hex quantity: an error, never 0, because a fee booked short leaves the shard's books above the chain for good.
// The fee is nil when the receipt has no effectiveGasPrice (each caller handles that as before).
func ParseReceipt(raw []byte) (*types.Receipt, *big.Int, error) {
	var r types.Receipt
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, nil, fmt.Errorf("evm: receipt: %w", err)
	}
	var op struct {
		L1Fee json.RawMessage `json:"l1Fee"`
	}
	if err := json.Unmarshal(raw, &op); err != nil {
		return nil, nil, fmt.Errorf("evm: receipt %s: %w", r.TxHash.Hex(), err)
	}
	l1 := new(big.Int)
	if len(op.L1Fee) > 0 && string(op.L1Fee) != "null" {
		var s string
		err := json.Unmarshal(op.L1Fee, &s)
		if err == nil {
			l1, err = hexutil.DecodeBig(s) // strict: 0x prefix, no leading zeros, not empty
		}
		if err != nil {
			return nil, nil, fmt.Errorf("evm: receipt %s: l1Fee %s is not a hex quantity: %w", r.TxHash.Hex(), op.L1Fee, err)
		}
	}
	if r.EffectiveGasPrice == nil {
		return &r, nil, nil
	}
	fee := new(big.Int).Mul(new(big.Int).SetUint64(r.GasUsed), r.EffectiveGasPrice)
	return &r, fee.Add(fee, l1), nil
}
