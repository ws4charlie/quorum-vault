package sol

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
)

// Durable nonces. A withdrawal does not sign a recent blockhash (which expires in about a minute and cannot be checked offline); it signs the
// value held by a nonce account of the system program, whose authority is the hot shard. The first instruction of the message advances the
// nonce, so the value is used up the moment any version of the withdrawal lands, and no other version can land afterwards. A hot shard owns a
// small pool of such accounts; one carries at most one withdrawal in flight, as an EVM nonce does.
//
// The accounts of the pool are not random keys: each is created with CreateAccountWithSeed from the hot shard as base, so its address is
// sha256(hot shard, seed, system program) with a seed the zone can compute. Creating one needs no signature but the hot shard's, and the signing
// zone knows every address of every pool from its own config.

// Sysvars the nonce instructions name.
const (
	SysvarRecentBlockhashes = "SysvarRecentB1ockHashes11111111111111111111" // public sysvar id, not a secret; ggignore
	SysvarRent              = "SysvarRent111111111111111111111111111111111" // public sysvar id, not a secret; ggignore
)

// NonceAccountSize is the size of a system-program nonce account.
const NonceAccountSize = 80

// DefaultNonceRent is the rent-exempt minimum of an 80-byte account at the default rent parameters ((128+80) x 3480 x 2). The zone's config
// and the core's must carry the same number; the core checks it against the node at start.
const DefaultNonceRent = 1_447_680

// System program instruction numbers.
const (
	sysCreateWithSeed = 3
	sysAdvanceNonce   = 4
	sysInitNonce      = 6
)

// NonceSeed is the seed of pool account i of a hot shard.
func NonceSeed(i int) string { return fmt.Sprintf("qv-nonce-%d", i) }

// NonceAddress is the address of pool account i of the hot shard: create_with_seed(base = hot shard, seed, owner = system program).
func NonceAddress(hot [32]byte, i int) [32]byte {
	sys, _ := ParseAddress(SystemProgram)
	h := sha256.New()
	h.Write(hot[:])
	h.Write([]byte(NonceSeed(i)))
	h.Write(sys[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// AdvanceNonceData is the data of an AdvanceNonceAccount instruction.
func AdvanceNonceData() []byte { return binary.LittleEndian.AppendUint32(nil, sysAdvanceNonce) }

// InitNonceData is the data of an InitializeNonceAccount instruction for authority.
func InitNonceData(authority [32]byte) []byte {
	return append(binary.LittleEndian.AppendUint32(nil, sysInitNonce), authority[:]...)
}

// CreateWithSeedData is the data of a CreateAccountWithSeed instruction whose owner is the system program.
func CreateWithSeedData(base [32]byte, seed string, lamports, space uint64) []byte {
	sys, _ := ParseAddress(SystemProgram)
	d := binary.LittleEndian.AppendUint32(nil, sysCreateWithSeed)
	d = append(d, base[:]...)
	d = binary.LittleEndian.AppendUint64(d, uint64(len(seed)))
	d = append(d, seed...)
	d = binary.LittleEndian.AppendUint64(d, lamports)
	d = binary.LittleEndian.AppendUint64(d, space)
	return append(d, sys[:]...)
}

// IsAdvanceNonce / IsInitNonce / IsCreateWithSeed tell the system instructions apart by their leading u32.
func systemOp(data []byte) (uint32, bool) {
	if len(data) < 4 {
		return 0, false
	}
	return binary.LittleEndian.Uint32(data), true
}

// NonceState is an initialized nonce account.
type NonceState struct {
	Authority [32]byte
	Value     [32]byte // the durable nonce: what a message signs as its blockhash
	Lamports  uint64   // the account's balance
}

// ParseNonceAccount reads the 80 bytes of a nonce account: version u32 (1 = current), state u32 (1 = initialized), authority, durable nonce, fee
// calculator (lamports per signature).
func ParseNonceAccount(data []byte) (NonceState, error) {
	var s NonceState
	if len(data) != NonceAccountSize {
		return s, fmt.Errorf("sol: nonce account data is %d bytes, not %d", len(data), NonceAccountSize)
	}
	if v := binary.LittleEndian.Uint32(data[0:4]); v != 1 {
		return s, fmt.Errorf("sol: nonce account version %d", v)
	}
	if st := binary.LittleEndian.Uint32(data[4:8]); st != 1 {
		return s, errors.New("sol: nonce account is not initialized")
	}
	copy(s.Authority[:], data[8:40])
	copy(s.Value[:], data[40:72])
	return s, nil
}

// ErrNoAccount: the account does not exist at the commitment.
var ErrNoAccount = errors.New("sol: account does not exist")

// Account is the raw account the node returns.
type Account struct {
	Lamports uint64
	Owner    string
	Data     []byte
	Slot     uint64
}

// GetAccount reads an account at a commitment (base64 data). A missing account is ErrNoAccount.
func (r *RPC) GetAccount(ctx context.Context, address, c string) (Account, error) {
	var out struct {
		Context struct {
			Slot uint64 `json:"slot"`
		} `json:"context"`
		Value *struct {
			Lamports uint64   `json:"lamports"`
			Owner    string   `json:"owner"`
			Data     []string `json:"data"`
		} `json:"value"`
	}
	if err := r.Call(ctx, &out, "getAccountInfo", address, map[string]any{"encoding": "base64", "commitment": c}); err != nil {
		return Account{}, err
	}
	if out.Value == nil {
		return Account{Slot: out.Context.Slot}, ErrNoAccount
	}
	a := Account{Lamports: out.Value.Lamports, Owner: out.Value.Owner, Slot: out.Context.Slot}
	if len(out.Value.Data) > 0 {
		b, err := base64.StdEncoding.DecodeString(out.Value.Data[0])
		if err != nil {
			return a, fmt.Errorf("sol: account %s data: %w", address, err)
		}
		a.Data = b
	}
	return a, nil
}

// GetNonce reads a nonce account at a commitment and requires it to be a system-owned, initialized nonce account.
func (r *RPC) GetNonce(ctx context.Context, address, c string) (NonceState, error) {
	a, err := r.GetAccount(ctx, address, c)
	if err != nil {
		return NonceState{}, err
	}
	if a.Owner != SystemProgram {
		return NonceState{}, fmt.Errorf("sol: %s is owned by %s, not by the system program", address, a.Owner)
	}
	s, err := ParseNonceAccount(a.Data)
	s.Lamports = a.Lamports
	return s, err
}

// MinimumRent is the rent-exempt minimum for an account of size bytes.
func (r *RPC) MinimumRent(ctx context.Context, size int) (uint64, error) {
	var n uint64
	return n, r.Call(ctx, &n, "getMinimumBalanceForRentExemption", size)
}

// SigStatus is the node's status of one signature.
type SigStatus struct {
	Slot   uint64
	Err    json.RawMessage
	Status string // "processed", "confirmed" or "finalized"
}

// Failed reports whether the transaction landed with an error.
func (s SigStatus) Failed() bool { return len(s.Err) != 0 && string(s.Err) != "null" }

// SignatureStatuses asks about signatures, searching the node's ledger history; a signature the node does not know has a nil entry.
func (r *RPC) SignatureStatuses(ctx context.Context, sigs []string) ([]*SigStatus, error) {
	var out struct {
		Value []*struct {
			Slot   uint64          `json:"slot"`
			Err    json.RawMessage `json:"err"`
			Status string          `json:"confirmationStatus"`
		} `json:"value"`
	}
	if err := r.Call(ctx, &out, "getSignatureStatuses", sigs, map[string]any{"searchTransactionHistory": true}); err != nil {
		return nil, err
	}
	res := make([]*SigStatus, len(sigs))
	for i, v := range out.Value {
		if v != nil && i < len(res) {
			res[i] = &SigStatus{Slot: v.Slot, Err: v.Err, Status: v.Status}
		}
	}
	return res, nil
}

// SendRaw sends a signed transaction. It skips the node's preflight simulation: a withdrawal that will fail on the chain (a bad token account)
// must land and pay its fee like an EVM transaction that reverts, so the books and the nonce see one outcome, instead of being turned away
// by one node and sent by another.
func (r *RPC) SendRaw(ctx context.Context, raw []byte) (string, error) {
	var sig string
	err := r.Call(ctx, &sig, "sendTransaction", base64.StdEncoding.EncodeToString(raw),
		map[string]any{"encoding": "base64", "skipPreflight": true, "preflightCommitment": Confirmed})
	return sig, err
}
