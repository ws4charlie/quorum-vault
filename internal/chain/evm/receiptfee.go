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

// L1FeeMode says whether a chain's receipts carry an OP-stack L1 data fee.
type L1FeeMode string

const (
	// L1FeeRequired: an OP-stack chain. Every receipt must carry l1Fee; a receipt without it is an error, never a fee of 0.
	L1FeeRequired L1FeeMode = "required"
	// L1FeeNone: no L1 data fee. A receipt that still carries l1Fee is booked with it (the chain charged it).
	L1FeeNone L1FeeMode = "none"
)

// opStackChainIDs are the OP-stack chains whose receipts carry l1Fee: Base (8453), Base Sepolia (84532), OP Mainnet (10), OP Sepolia (11155420).
var opStackChainIDs = map[uint64]bool{8453: true, 84532: true, 10: true, 11155420: true}

// DefaultL1FeeMode is required for a known OP-stack chain id, none otherwise.
func DefaultL1FeeMode(chainID uint64) L1FeeMode {
	if opStackChainIDs[chainID] {
		return L1FeeRequired
	}
	return L1FeeNone
}

// ParseL1FeeMode reads a config value: "required", "none", or "" (the chain id's default, decided by L1FeeModeOf).
func ParseL1FeeMode(s string) (L1FeeMode, error) {
	switch m := L1FeeMode(s); m {
	case "", L1FeeRequired, L1FeeNone:
		return m, nil
	}
	return "", fmt.Errorf("l1_fee %q is not %q or %q", s, L1FeeRequired, L1FeeNone)
}

// L1FeeModeOf is the configured mode, or the chain id's default when none is set.
func (c Config) L1FeeModeOf() L1FeeMode {
	if c.L1Fee != "" {
		return c.L1Fee
	}
	return DefaultL1FeeMode(c.ChainID)
}

// ReadReceipt reads the receipt of a transaction with one eth_getTransactionReceipt call and returns it with the fee its sender paid (ParseReceipt).
// The error is ethereum.NotFound while the node has no receipt. Every place that books a paid EVM fee reads it here.
func ReadReceipt(ctx context.Context, c *rpc.Client, txHash common.Hash, mode L1FeeMode) (*types.Receipt, *big.Int, error) {
	var raw json.RawMessage
	if err := c.CallContext(ctx, &raw, "eth_getTransactionReceipt", txHash); err != nil {
		return nil, nil, err
	}
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil, ethereum.NotFound
	}
	return ParseReceipt(raw, mode)
}

// ParseReceipt decodes a receipt and the fee its sender paid: gasUsed × effectiveGasPrice + l1Fee.
//
// l1Fee is the L1 data fee an OP-stack chain (Base, Optimism) charges on top of the gas. The node reports it in the receipt, and go-ethereum's
// types.Receipt drops it, so it is read here from the same JSON. Present but not a hex quantity: an error. Absent or null: an error when mode
// is L1FeeRequired, else 0. Never a silent 0 on an OP-stack chain, because a fee booked short leaves the shard's books above the chain for good.
// The fee is nil when the receipt has no effectiveGasPrice (each caller handles that as before).
func ParseReceipt(raw []byte, mode L1FeeMode) (*types.Receipt, *big.Int, error) {
	if mode != L1FeeRequired && mode != L1FeeNone {
		return nil, nil, fmt.Errorf("evm: receipt: l1 fee mode %q is not %q or %q", mode, L1FeeRequired, L1FeeNone)
	}
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
	if len(op.L1Fee) == 0 || string(op.L1Fee) == "null" {
		if mode == L1FeeRequired {
			return nil, nil, fmt.Errorf("evm: receipt %s has no l1Fee, and the chain's l1_fee is %q (an OP-stack chain); set %q only for a node that charges none", r.TxHash.Hex(), L1FeeRequired, L1FeeNone)
		}
	} else {
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
