package evm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/ws4charlie/quorum-vault/internal/chain/eth"
)

// Payload is UnsignedTx.Payload: every field of the EIP-1559 transaction plus
// the sender. Assemble and Verify need nothing else (no RPC, no database).
type Payload struct {
	ChainID uint64 `json:"chain_id"`
	From    string `json:"from"`
	Nonce   uint64 `json:"nonce"`
	To      string `json:"to"`
	Value   string `json:"value"` // decimal wei
	Data    string `json:"data"`  // 0x hex
	Gas     uint64 `json:"gas"`
	Tip     string `json:"max_priority_fee_per_gas"`
	FeeCap  string `json:"max_fee_per_gas"`
}

func newPayload(chainID uint64, from common.Address, p eth.TxParams) Payload {
	return Payload{
		ChainID: chainID, From: from.Hex(), Nonce: p.Nonce, To: p.To.Hex(),
		Value: p.Value.String(), Data: hexutil.Encode(p.Data), Gas: p.Gas,
		Tip: p.GasTipCap.String(), FeeCap: p.GasFeeCap.String(),
	}
}

func (p Payload) marshal() ([]byte, error) { return json.Marshal(p) }

// decodePayload parses strictly: unknown fields and trailing data are errors.
func decodePayload(b []byte) (Payload, error) {
	var p Payload
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return Payload{}, fmt.Errorf("evm: decode payload: %w", err)
	}
	if dec.More() {
		return Payload{}, fmt.Errorf("evm: decode payload: trailing data")
	}
	return p, nil
}

func decBig(name, s string) (*big.Int, error) {
	n, err := parseAmount(s)
	if err != nil {
		return nil, fmt.Errorf("evm: payload %s: %w", name, err)
	}
	return n, nil
}

// params converts the payload to eth.TxParams and returns the sender.
func (p Payload) params() (eth.TxParams, common.Address, error) {
	if !common.IsHexAddress(p.From) || !common.IsHexAddress(p.To) {
		return eth.TxParams{}, common.Address{}, fmt.Errorf("evm: payload: bad address")
	}
	val, err := decBig("value", p.Value)
	if err != nil {
		return eth.TxParams{}, common.Address{}, err
	}
	tip, err := decBig("max_priority_fee_per_gas", p.Tip)
	if err != nil {
		return eth.TxParams{}, common.Address{}, err
	}
	feeCap, err := decBig("max_fee_per_gas", p.FeeCap)
	if err != nil {
		return eth.TxParams{}, common.Address{}, err
	}
	data, err := hexutil.Decode(p.Data)
	if err != nil {
		return eth.TxParams{}, common.Address{}, fmt.Errorf("evm: payload data: %w", err)
	}
	return eth.TxParams{
		ChainID: new(big.Int).SetUint64(p.ChainID), Nonce: p.Nonce, To: common.HexToAddress(p.To),
		Value: val, Data: data, Gas: p.Gas, GasTipCap: tip, GasFeeCap: feeCap,
	}, common.HexToAddress(p.From), nil
}

// tx rebuilds the unsigned transaction and its digest.
func (p Payload) tx() (*types.Transaction, [32]byte, common.Address, error) {
	params, from, err := p.params()
	if err != nil {
		return nil, [32]byte{}, common.Address{}, err
	}
	tx, d, err := eth.BuildTx(params)
	return tx, d, from, err
}
