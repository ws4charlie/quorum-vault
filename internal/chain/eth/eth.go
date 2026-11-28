// Package eth builds EIP-1559 (type 2) transactions, returns the digest a
// signer must sign, decodes raw transactions, and checks that a signed
// transaction's recovered sender is the wallet address. The chain adapter
// (internal/chain/evm) uses it; tests assemble and broadcast with
// internal/chain/eth/ethtest.
package eth

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// Defaults used when a request omits them and no RPC node is configured.
const (
	SepoliaChainID   int64  = 11155111
	DefaultGasLimit  uint64 = 21000
	DefaultTipWei    int64  = 1_000_000_000  // 1 gwei
	DefaultFeeCapWei int64  = 30_000_000_000 // 30 gwei
)

var (
	ErrInvalidTx      = errors.New("eth: invalid transaction parameters")
	ErrSenderMismatch = errors.New("eth: recovered sender is not the wallet address")
)

// TxParams are the fields of an EIP-1559 transfer or call.
type TxParams struct {
	ChainID   *big.Int
	Nonce     uint64
	To        common.Address
	Value     *big.Int
	Data      []byte
	Gas       uint64
	GasTipCap *big.Int // max priority fee per gas
	GasFeeCap *big.Int // max fee per gas
}

func (p TxParams) validate() error {
	switch {
	case p.ChainID == nil || p.ChainID.Sign() <= 0:
		return fmt.Errorf("%w: chain id must be > 0", ErrInvalidTx)
	case p.Value == nil || p.Value.Sign() < 0:
		return fmt.Errorf("%w: value must be >= 0", ErrInvalidTx)
	case p.Gas == 0:
		return fmt.Errorf("%w: gas limit must be > 0", ErrInvalidTx)
	case p.GasTipCap == nil || p.GasTipCap.Sign() < 0 || p.GasFeeCap == nil || p.GasFeeCap.Sign() < 0:
		return fmt.Errorf("%w: fees must be set and >= 0", ErrInvalidTx)
	case p.GasTipCap.Cmp(p.GasFeeCap) > 0:
		return fmt.Errorf("%w: max priority fee exceeds max fee", ErrInvalidTx)
	}
	return nil
}

// BuildTx returns the unsigned transaction and the digest to sign:
// keccak256(0x02 || rlp([chainId, nonce, tip, feeCap, gas, to, value, data, accessList])).
func BuildTx(p TxParams) (*types.Transaction, [32]byte, error) {
	if err := p.validate(); err != nil {
		return nil, [32]byte{}, err
	}
	to := p.To
	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   new(big.Int).Set(p.ChainID),
		Nonce:     p.Nonce,
		GasTipCap: new(big.Int).Set(p.GasTipCap),
		GasFeeCap: new(big.Int).Set(p.GasFeeCap),
		Gas:       p.Gas,
		To:        &to,
		Value:     new(big.Int).Set(p.Value),
		Data:      bytes.Clone(p.Data),
	})
	return tx, Digest(tx), nil
}

// Digest is the EIP-1559 signing hash of tx.
func Digest(tx *types.Transaction) [32]byte {
	return types.LatestSignerForChainID(tx.ChainId()).Hash(tx)
}

// VerifySender recovers the sender of a signed tx and compares it to want.
func VerifySender(tx *types.Transaction, want common.Address) error {
	got, err := types.Sender(types.LatestSignerForChainID(tx.ChainId()), tx)
	if err != nil {
		return fmt.Errorf("eth: recover sender: %w", err)
	}
	if got != want {
		return fmt.Errorf("%w: got %s, want %s", ErrSenderMismatch, got.Hex(), want.Hex())
	}
	return nil
}

// DecodeRaw parses a raw EIP-2718 transaction.
func DecodeRaw(raw []byte) (*types.Transaction, error) {
	tx := new(types.Transaction)
	if err := tx.UnmarshalBinary(raw); err != nil {
		return nil, fmt.Errorf("eth: decode raw tx: %w", err)
	}
	return tx, nil
}
