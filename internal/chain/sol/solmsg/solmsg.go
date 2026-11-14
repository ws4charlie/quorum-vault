// Package solmsg is the part of the Solana cell that builds and names things without any network client or database: addresses, program ids, associated
// token accounts, nonce account addresses and the legacy-message compiler with the few instructions custody uses. The offline cold signer builds its
// messages with it, so this package (and what it imports) must stay free of every network package; internal/coldsign's tests check that.
package solmsg

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"filippo.io/edwards25519"
	"github.com/btcsuite/btcd/btcutil/base58"
)

// ComputeBudgetProgram is the compute budget program.
const ComputeBudgetProgram = "ComputeBudget111111111111111111111111111111" // public program id, not a secret; ggignore

// Address is the base58 form of a 32-byte public key: the Solana address.
func Address(pub [32]byte) string { return base58.Encode(pub[:]) }

// ParseAddress decodes a base58 address to its 32 bytes.
func ParseAddress(s string) ([32]byte, error) {
	var out [32]byte
	b := base58.Decode(s)
	if len(b) != 32 {
		return out, fmt.Errorf("sol: %q is not a 32-byte base58 address", s)
	}
	copy(out[:], b)
	return out, nil
}

// Program ids (classic SPL Token and the Associated Token Account program; Token-2022 is not supported).
const (
	SystemProgram       = "11111111111111111111111111111111"             // public program id, not a secret; ggignore
	TokenProgram        = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"  // public program id, not a secret; ggignore
	AssociatedTokenProg = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL" // public program id, not a secret; ggignore
)

// onCurve reports whether 32 bytes decode to a point of the Ed25519 curve.
func OnCurve(b []byte) bool {
	_, err := new(edwards25519.Point).SetBytes(b)
	return err == nil
}

// FindProgramAddress is Solana's PDA search: the first bump from 255 down for which sha256(seeds || bump || program || "ProgramDerivedAddress")
// is not on the curve.
func FindProgramAddress(seeds [][]byte, program [32]byte) ([32]byte, error) {
	for bump := 255; bump >= 0; bump-- {
		h := sha256.New()
		for _, s := range seeds {
			h.Write(s)
		}
		h.Write([]byte{byte(bump)})
		h.Write(program[:])
		h.Write([]byte("ProgramDerivedAddress"))
		var out [32]byte
		copy(out[:], h.Sum(nil))
		if !OnCurve(out[:]) {
			return out, nil
		}
	}
	return [32]byte{}, errors.New("sol: no program address found")
}

// ATA is the associated token account of owner for mint: the PDA of the Associated Token program at seeds (owner, token program, mint).
// Deposits of a token are credited only when they arrive here.
func ATA(owner, mint [32]byte) ([32]byte, error) {
	tok, err := ParseAddress(TokenProgram)
	if err != nil {
		return [32]byte{}, err
	}
	ata, err := ParseAddress(AssociatedTokenProg)
	if err != nil {
		return [32]byte{}, err
	}
	return FindProgramAddress([][]byte{owner[:], tok[:], mint[:]}, ata)
}

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

// Meta is an account of an instruction.
type Meta struct {
	Key      [32]byte
	Signer   bool
	Writable bool
}

// Ix is an instruction.
type Ix struct {
	Program [32]byte
	Accts   []Meta
	Data    []byte
}

func CompactU16(n int) []byte {
	var out []byte
	for {
		b := byte(n & 0x7f)
		n >>= 7
		if n == 0 {
			return append(out, b)
		}
		out = append(out, b|0x80)
	}
}

// Compile builds a legacy message with payer as the fee payer: signers first (payer first of them), then writable, then read-only accounts.
// Compiling the instructions of a decoded message (Message.Ixs) gives the same message back.
func Compile(payer, blockhash [32]byte, ixs ...Ix) []byte {
	type a struct {
		k    [32]byte
		s, w bool
	}
	var order []*a
	idx := map[[32]byte]*a{}
	add := func(k [32]byte, sg, w bool) {
		if x, ok := idx[k]; ok {
			x.s, x.w = x.s || sg, x.w || w
			return
		}
		x := &a{k, sg, w}
		idx[k] = x
		order = append(order, x)
	}
	add(payer, true, true)
	for _, in := range ixs {
		for _, m := range in.Accts {
			add(m.Key, m.Signer, m.Writable)
		}
		add(in.Program, false, false)
	}
	rank := func(x *a) int {
		switch {
		case x.k == payer:
			return -1
		case x.s && x.w:
			return 0
		case x.s:
			return 1
		case x.w:
			return 2
		}
		return 3
	}
	for i := 1; i < len(order); i++ {
		for j := i; j > 0 && rank(order[j]) < rank(order[j-1]); j-- {
			order[j], order[j-1] = order[j-1], order[j]
		}
	}
	pos := map[[32]byte]int{}
	ns, nro, nrou := 0, 0, 0
	for i, x := range order {
		pos[x.k] = i
		if x.s {
			ns++
			if !x.w {
				nro++
			}
		} else if !x.w {
			nrou++
		}
	}
	m := []byte{byte(ns), byte(nro), byte(nrou)}
	m = append(m, CompactU16(len(order))...)
	for _, x := range order {
		m = append(m, x.k[:]...)
	}
	m = append(m, blockhash[:]...)
	m = append(m, CompactU16(len(ixs))...)
	for _, in := range ixs {
		m = append(m, byte(pos[in.Program]))
		m = append(m, CompactU16(len(in.Accts))...)
		for _, ac := range in.Accts {
			m = append(m, byte(pos[ac.Key]))
		}
		m = append(m, CompactU16(len(in.Data))...)
		m = append(m, in.Data...)
	}
	return m
}

func MustAddr(s string) [32]byte { p, _ := ParseAddress(s); return p }

// SetLimitIx and SetPriceIx are the compute budget instructions.
func SetLimitIx(n uint32) Ix {
	return Ix{Program: MustAddr(ComputeBudgetProgram), Data: binary.LittleEndian.AppendUint32([]byte{2}, n)}
}
func SetPriceIx(microLamports uint64) Ix {
	return Ix{Program: MustAddr(ComputeBudgetProgram), Data: binary.LittleEndian.AppendUint64([]byte{3}, microLamports)}
}

// AdvanceNonceIx advances nonce; authority signs.
func AdvanceNonceIx(nonce, authority [32]byte) Ix {
	return Ix{Program: MustAddr(SystemProgram), Accts: []Meta{{nonce, false, true}, {MustAddr(SysvarRecentBlockhashes), false, false}, {authority, true, false}},
		Data: AdvanceNonceData()}
}

// TransferIx is a system program transfer.
func TransferIx(from, to [32]byte, lamports uint64) Ix {
	return Ix{Program: MustAddr(SystemProgram), Accts: []Meta{{from, true, true}, {to, false, true}},
		Data: binary.LittleEndian.AppendUint64(binary.LittleEndian.AppendUint32(nil, 2), lamports)}
}

// CheckedTransferIx is a Token program transferChecked.
func CheckedTransferIx(src, mint, dst, authority [32]byte, amount uint64, decimals uint8) Ix {
	return Ix{Program: MustAddr(TokenProgram), Accts: []Meta{{src, false, true}, {mint, false, false}, {dst, false, true}, {authority, true, false}},
		Data: append(binary.LittleEndian.AppendUint64([]byte{12}, amount), decimals)}
}

// CreateATAIx is an idempotent associated-token-account create paid by payer.
func CreateATAIx(payer, ata, owner, mint [32]byte) Ix {
	return Ix{Program: MustAddr(AssociatedTokenProg), Data: []byte{1}, Accts: []Meta{{payer, true, true}, {ata, false, true}, {owner, false, false}, {mint, false, false},
		{MustAddr(SystemProgram), false, false}, {MustAddr(TokenProgram), false, false}}}
}

// CreateNonceIxs are the two instructions that create pool account i of hot and make hot its authority.
func CreateNonceIxs(hot [32]byte, i int, lamports uint64) []Ix {
	n := NonceAddress(hot, i)
	return []Ix{
		{Program: MustAddr(SystemProgram), Accts: []Meta{{hot, true, true}, {n, false, true}}, Data: CreateWithSeedData(hot, NonceSeed(i), lamports, NonceAccountSize)},
		{Program: MustAddr(SystemProgram), Accts: []Meta{{n, false, true}, {MustAddr(SysvarRecentBlockhashes), false, false}, {MustAddr(SysvarRent), false, false}}, Data: InitNonceData(hot)},
	}
}

// CloseAccountIx is a Token program closeAccount: the empty token account acct goes away and its rent to rentTo; owner signs.
func CloseAccountIx(acct, rentTo, owner [32]byte) Ix {
	return Ix{Program: MustAddr(TokenProgram), Accts: []Meta{{acct, false, true}, {rentTo, false, true}, {owner, true, false}}, Data: []byte{9}}
}
