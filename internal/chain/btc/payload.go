package btc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// PayloadVersion is the transaction version the signing zone accepts (BIP68 relative locks and RBF both work with version 2).
const PayloadVersion = 2

// SequenceRBF is the only sequence the signing zone accepts: it signals replace-by-fee (BIP125) and sets no relative lock.
const SequenceRBF uint32 = 0xfffffffd

// Payload is the unsigned transaction as it travels in a sign job: every input with its outpoint, value, derivation path and
// sequence, and every output with its address and value. It is strict JSON: unknown fields are refused. The input a job signs is
// not in the payload; it follows from the job's key reference and digest.
type Payload struct {
	Version  int32           `json:"version"`
	LockTime uint32          `json:"locktime"`
	Inputs   []PayloadInput  `json:"inputs"`
	Outputs  []PayloadOutput `json:"outputs"`
}

// PayloadInput is one input. Path is the derivation path below the account key: [branch, index], branch 0 for deposit addresses and
// 1 for hot shards. Value is the satoshis of the output being spent.
type PayloadInput struct {
	TxID     string   `json:"txid"`
	Vout     uint32   `json:"vout"`
	Value    uint64   `json:"value"`
	Path     []uint32 `json:"path"`
	Sequence uint32   `json:"sequence"`
}

// PayloadOutput pays value satoshis to address.
type PayloadOutput struct {
	Address string `json:"address"`
	Value   uint64 `json:"value"`
}

// DecodePayload reads a payload strictly: unknown fields and trailing data are errors.
func DecodePayload(b []byte) (Payload, error) {
	var p Payload
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return p, fmt.Errorf("btc payload: %w", err)
	}
	if dec.More() {
		return p, errors.New("btc payload: trailing data")
	}
	return p, nil
}

// Encode is the JSON a sign job carries.
func (p Payload) Encode() ([]byte, error) { return json.Marshal(p) }

// Derivation branches below the account key.
const (
	BranchDeposit uint32 = 0 // deposit addresses, one per customer
	BranchHot     uint32 = 1 // the fixed hot shards
)

// PathString is the key reference of a derivation path: "0/5".
func PathString(path []uint32) string {
	parts := make([]string, len(path))
	for i, n := range path {
		parts[i] = strconv.FormatUint(uint64(n), 10)
	}
	return strings.Join(parts, "/")
}

// ParsePath is the inverse of PathString. Only the two-element paths of the allowed branches are valid.
func ParsePath(s string) ([]uint32, error) {
	parts := strings.Split(s, "/")
	if len(parts) != 2 {
		return nil, fmt.Errorf("btc: key path %q is not <branch>/<index>", s)
	}
	out := make([]uint32, 2)
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 10, 32)
		if err != nil || strconv.FormatUint(n, 10) != p {
			return nil, fmt.Errorf("btc: key path %q: %q is not a canonical number", s, p)
		}
		out[i] = uint32(n)
	}
	if err := CheckPath(out); err != nil {
		return nil, err
	}
	return out, nil
}

// CheckPath refuses a path outside the deposit and hot branches, or a hardened index.
func CheckPath(path []uint32) error {
	if len(path) != 2 {
		return fmt.Errorf("btc: derivation path %v must be [branch, index]", path)
	}
	if path[0] != BranchDeposit && path[0] != BranchHot {
		return fmt.Errorf("btc: derivation branch %d is neither the deposit branch (0) nor the hot branch (1)", path[0])
	}
	if path[1] >= 1<<31 {
		return fmt.Errorf("btc: derivation index %d is hardened", path[1])
	}
	return nil
}
