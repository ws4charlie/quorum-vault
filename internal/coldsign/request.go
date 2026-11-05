// Package coldsign is the file formats and the signing rules of the offline cold signer (cmd/qv-cold) and the checks the online
// side runs on what comes back. It is pure: no network client, no database, no HSM. The offline tool is a program that must not
// be able to talk to anything; keeping its rules in a package with that property (and a test that checks the import graph)
// is how that is kept true.
package coldsign

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// Versions of the files that cross the air gap.
const (
	RequestVersion  = "qv-refill-request-v1"
	SignedVersion   = "qv-refill-signed-v1"
	approvalDomain  = "qv-refill-approval-v1\n"
	requestHashTag  = "qv-refill-request-hash-v1\n"
	contentHashTag  = "qv-refill-content-hash-v1\n"
	transferSigHex  = "a9059cbb"
	nativeTransfer  = 21000
	addressSuffixLn = 20
)

// Request is a refill from the cold address to a hot address, as the online side exports it and the operators approve it. The
// offline tool builds the transaction from these fields itself; it does not take a transaction from the online side.
type Request struct {
	Version  string `json:"version"`
	ID       string `json:"id"`
	Revision int    `json:"revision"` // grows with every re-export (new fees or nonce)
	Chain    string `json:"chain"`
	ChainID  uint64 `json:"chain_id"`
	Pool     string `json:"pool"`
	Asset    string `json:"asset"`
	Token    string `json:"token,omitempty"` // ERC-20 contract; empty for the native asset
	From     string `json:"from"`            // the cold address
	To       string `json:"to"`              // the hot address that receives the funds
	Amount   string `json:"amount"`          // base units, decimal

	Nonce                uint64 `json:"nonce"`
	Gas                  uint64 `json:"gas"`
	MaxFeePerGas         string `json:"max_fee_per_gas"`
	MaxPriorityFeePerGas string `json:"max_priority_fee_per_gas"`
}

// RequestFile is what is carried to the offline machine: the request and its hash, so a file damaged on the way is noticed.
type RequestFile struct {
	Request     Request `json:"request"`
	RequestHash string  `json:"request_hash"`
}

// Approval is one operator's signature over a request hash.
type Approval struct {
	RequestHash string `json:"request_hash"`
	Operator    string `json:"operator"`
	Signature   string `json:"signature"` // Ed25519, hex
}

// Signed is what comes back: the signed raw transaction for one request.
type Signed struct {
	Version     string `json:"version"`
	RequestID   string `json:"request_id"`
	RequestHash string `json:"request_hash"`
	RawTx       string `json:"raw_tx"` // hex
	TxHash      string `json:"tx_hash"`
	Signer      string `json:"signer"` // the cold address that signed
}

func lp(b []byte, f string) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(f)))
	return append(b, f...)
}

func (r Request) fields() []string {
	return []string{r.Version, r.ID, strconv.Itoa(r.Revision), r.Chain, strconv.FormatUint(r.ChainID, 10), r.Pool, r.Asset, r.Token,
		strings.ToLower(r.From), strings.ToLower(r.To), r.Amount, strconv.FormatUint(r.Nonce, 10), strconv.FormatUint(r.Gas, 10),
		r.MaxFeePerGas, r.MaxPriorityFeePerGas}
}

// Hash is what operators approve: every field, length-prefixed, under a domain tag.
func (r Request) Hash() [32]byte {
	b := []byte(requestHashTag)
	for _, f := range r.fields() {
		b = lp(b, f)
	}
	return sha256.Sum256(b)
}

// HashHex is Hash in hex.
func (r Request) HashHex() string { h := r.Hash(); return hex.EncodeToString(h[:]) }

// ContentHash identifies WHAT the request moves, without the fees: two requests with the same content are the same payment
// at the same nonce (a re-export with higher fees), so signing both cannot pay twice. Two requests with different content at
// one nonce are what the offline tool must refuse.
func (r Request) ContentHash() string {
	b := []byte(contentHashTag)
	for _, f := range []string{r.Chain, strconv.FormatUint(r.ChainID, 10), r.Asset, r.Token, strings.ToLower(r.From), strings.ToLower(r.To), r.Amount,
		strconv.FormatUint(r.Nonce, 10)} {
		b = lp(b, f)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// File wraps the request with its hash.
func (r Request) File() RequestFile { return RequestFile{Request: r, RequestHash: r.HashHex()} }

// ApprovalMessage is what an operator signs for a request hash.
func ApprovalMessage(requestHashHex string) []byte { return []byte(approvalDomain + requestHashHex) }

func parseAmt(what, s string) (*big.Int, error) {
	n, ok := new(big.Int).SetString(s, 10)
	if !ok || n.Sign() < 0 || n.String() != s {
		return nil, fmt.Errorf("%s %q is not a canonical non-negative decimal", what, s)
	}
	return n, nil
}

func parseAddr(what, s string) (common.Address, error) {
	if !strings.HasPrefix(s, "0x") || !common.IsHexAddress(s) {
		return common.Address{}, fmt.Errorf("%s %q is not a 0x address", what, s)
	}
	a := common.HexToAddress(s)
	if a == (common.Address{}) {
		return a, fmt.Errorf("%s is the zero address", what)
	}
	return a, nil
}

// Tx builds the unsigned EIP-1559 transaction the request describes.
func (r Request) Tx() (*types.Transaction, error) {
	if r.Version != RequestVersion {
		return nil, fmt.Errorf("request version %q, want %q", r.Version, RequestVersion)
	}
	to, err := parseAddr("destination", r.To)
	if err != nil {
		return nil, err
	}
	amount, err := parseAmt("amount", r.Amount)
	if err != nil {
		return nil, err
	}
	if amount.Sign() == 0 {
		return nil, errors.New("amount is zero")
	}
	maxFee, err := parseAmt("max_fee_per_gas", r.MaxFeePerGas)
	if err != nil {
		return nil, err
	}
	tip, err := parseAmt("max_priority_fee_per_gas", r.MaxPriorityFeePerGas)
	if err != nil {
		return nil, err
	}
	if tip.Cmp(maxFee) > 0 {
		return nil, errors.New("priority fee exceeds the max fee")
	}
	if r.Gas == 0 {
		return nil, errors.New("gas is zero")
	}
	d := &types.DynamicFeeTx{ChainID: new(big.Int).SetUint64(r.ChainID), Nonce: r.Nonce, GasTipCap: tip, GasFeeCap: maxFee, Gas: r.Gas}
	if r.Token == "" {
		if r.Gas != nativeTransfer {
			return nil, fmt.Errorf("a native transfer uses %d gas, the request says %d", nativeTransfer, r.Gas)
		}
		d.To, d.Value = &to, amount
	} else {
		tok, err := parseAddr("token", r.Token)
		if err != nil {
			return nil, err
		}
		d.To, d.Value, d.Data = &tok, new(big.Int), TransferData(to, amount)
	}
	return types.NewTx(d), nil
}

// TransferData is the calldata of ERC-20 transfer(to, amount).
func TransferData(to common.Address, amount *big.Int) []byte {
	b, _ := hex.DecodeString(transferSigHex)
	b = append(b, common.LeftPadBytes(to.Bytes(), 32)...)
	return append(b, common.LeftPadBytes(amount.Bytes(), 32)...)
}

// Summary is the human-readable statement operators check: where from, where to, what, how much, what it may cost.
func (r Request) Summary(decimals int) string {
	amt, _ := new(big.Int).SetString(r.Amount, 10)
	maxFee, _ := new(big.Int).SetString(r.MaxFeePerGas, 10)
	worst := new(big.Int).Mul(maxFee, new(big.Int).SetUint64(r.Gas))
	kind := "native " + r.Asset
	if r.Token != "" {
		kind = r.Asset + " token " + r.Token
	}
	var b strings.Builder
	fmt.Fprintf(&b, "  request   %s (revision %d)\n", r.ID, r.Revision)
	fmt.Fprintf(&b, "  chain     %s (chain id %d), pool %s\n", r.Chain, r.ChainID, r.Pool)
	fmt.Fprintf(&b, "  from      %s (the cold address)\n", r.From)
	fmt.Fprintf(&b, "  to        %s\n", r.To)
	fmt.Fprintf(&b, "  asset     %s\n", kind)
	fmt.Fprintf(&b, "  amount    %s (%s base units)\n", Human(amt, decimals), r.Amount)
	fmt.Fprintf(&b, "  nonce     %d\n", r.Nonce)
	fmt.Fprintf(&b, "  fee       at most %s wei (%d gas x %s wei max fee per gas, tip %s)\n", worst, r.Gas, r.MaxFeePerGas, r.MaxPriorityFeePerGas)
	return b.String()
}

// Human formats base units with decimals.
func Human(n *big.Int, decimals int) string {
	if n == nil {
		return "?"
	}
	if decimals <= 0 {
		return n.String()
	}
	s := n.String()
	for len(s) <= decimals {
		s = "0" + s
	}
	i := len(s) - decimals
	return strings.TrimSuffix(strings.TrimRight(s[:i]+"."+s[i:], "0"), ".")
}
