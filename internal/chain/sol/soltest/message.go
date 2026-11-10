package soltest

import (
	"encoding/binary"

	"github.com/ws4charlie/quorum-vault/internal/chain/sol"
)

// A legacy-message compiler and the few instructions the signing zone allows, for tests that play the business zone (or an attacker).

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

// Prod converts to the production instruction type.
func (x Ix) Prod() sol.Ix {
	o := sol.Ix{Program: x.Program, Data: x.Data}
	for _, m := range x.Accts {
		o.Accts = append(o.Accts, sol.Meta{Key: m.Key, Signer: m.Signer, Writable: m.Writable})
	}
	return o
}

// Compile builds a legacy message with payer as the fee payer (the compiler of package sol).
func Compile(payer, blockhash [32]byte, ixs ...Ix) []byte {
	p := make([]sol.Ix, len(ixs))
	for i, x := range ixs {
		p[i] = x.Prod()
	}
	return sol.Compile(payer, blockhash, p...)
}

func compactU16(n int) []byte {
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

func prog(s string) [32]byte { p, _ := sol.ParseAddress(s); return p }

// SetLimit and SetPrice are the compute budget instructions.
func SetLimit(n uint32) Ix {
	return Ix{Program: prog(sol.ComputeBudgetProgram), Data: binary.LittleEndian.AppendUint32([]byte{2}, n)}
}
func SetPrice(microLamports uint64) Ix {
	return Ix{Program: prog(sol.ComputeBudgetProgram), Data: binary.LittleEndian.AppendUint64([]byte{3}, microLamports)}
}

// Transfer is a System Program transfer.
func Transfer(from, to [32]byte, lamports uint64) Ix {
	return Ix{Program: prog(sol.SystemProgram), Accts: []Meta{{from, true, true}, {to, false, true}},
		Data: binary.LittleEndian.AppendUint64(binary.LittleEndian.AppendUint32(nil, 2), lamports)}
}

// CheckedTransfer is a Token program transferChecked.
func CheckedTransfer(src, mint, dst, authority [32]byte, amount uint64, decimals uint8) Ix {
	return Ix{Program: prog(sol.TokenProgram), Accts: []Meta{{src, false, true}, {mint, false, false}, {dst, false, true}, {authority, true, false}},
		Data: append(binary.LittleEndian.AppendUint64([]byte{12}, amount), decimals)}
}

// CreateATA is an idempotent associated-token-account create.
func CreateATA(payer, ata, owner, mint [32]byte) Ix {
	return Ix{Program: prog(sol.AssociatedTokenProg), Data: []byte{1}, Accts: []Meta{{payer, true, true}, {ata, false, true}, {owner, false, false}, {mint, false, false},
		{prog(sol.SystemProgram), false, false}, {prog(sol.TokenProgram), false, false}}}
}

// CloseAccount is a Token program closeAccount.
func CloseAccount(acct, rentTo, owner [32]byte) Ix {
	return Ix{Program: prog(sol.TokenProgram), Accts: []Meta{{acct, false, true}, {rentTo, false, true}, {owner, true, false}}, Data: []byte{9}}
}

// ATAOf is the associated token account of owner for mint.
func ATAOf(owner, mint [32]byte) [32]byte {
	a, err := sol.ATA(owner, mint)
	if err != nil {
		panic(err)
	}
	return a
}

// CreateAccount is a System Program createAccount (the new account signs).
func CreateAccount(from, newAcct, owner [32]byte, lamports, space uint64) Ix {
	d := binary.LittleEndian.AppendUint64(binary.LittleEndian.AppendUint64(binary.LittleEndian.AppendUint32(nil, 0), lamports), space)
	return Ix{Program: prog(sol.SystemProgram), Accts: []Meta{{from, true, true}, {newAcct, true, true}}, Data: append(d, owner[:]...)}
}

// InitMint2 initializes a mint with no freeze authority.
func InitMint2(mint, authority [32]byte, decimals uint8) Ix {
	return Ix{Program: prog(sol.TokenProgram), Accts: []Meta{{mint, false, true}}, Data: append(append([]byte{20, decimals}, authority[:]...), 0)}
}

// InitAccount3 initializes a token account.
func InitAccount3(acct, mint, owner [32]byte) Ix {
	return Ix{Program: prog(sol.TokenProgram), Accts: []Meta{{acct, false, true}, {mint, false, false}}, Data: append([]byte{18}, owner[:]...)}
}

// MintTo mints tokens to an account.
func MintTo(mint, dest, authority [32]byte, amount uint64) Ix {
	return Ix{Program: prog(sol.TokenProgram), Accts: []Meta{{mint, false, true}, {dest, false, true}, {authority, true, false}}, Data: binary.LittleEndian.AppendUint64([]byte{7}, amount)}
}

// Assemble is the wire form of a transaction: the signatures in the order of the message's signers, then the message.
func Assemble(msg []byte, sigs ...[]byte) []byte {
	out := compactU16(len(sigs))
	for _, s := range sigs {
		out = append(out, s...)
	}
	return append(out, msg...)
}

// AdvanceNonce is the system program's AdvanceNonceAccount; authority signs.
func AdvanceNonce(nonce, authority [32]byte) Ix {
	return Ix{Program: prog(sol.SystemProgram), Accts: []Meta{{nonce, false, true}, {prog(sol.SysvarRecentBlockhashes), false, false}, {authority, true, false}},
		Data: sol.AdvanceNonceData()}
}

// CreateNonceWithSeed is CreateAccountWithSeed for pool account i of hot (the hot shard is the base and pays).
func CreateNonceWithSeed(hot [32]byte, i int, lamports uint64) Ix {
	return Ix{Program: prog(sol.SystemProgram), Accts: []Meta{{hot, true, true}, {sol.NonceAddress(hot, i), false, true}},
		Data: sol.CreateWithSeedData(hot, sol.NonceSeed(i), lamports, sol.NonceAccountSize)}
}

// InitNonce is InitializeNonceAccount with authority.
func InitNonce(nonce, authority [32]byte) Ix {
	return Ix{Program: prog(sol.SystemProgram), Accts: []Meta{{nonce, false, true}, {prog(sol.SysvarRecentBlockhashes), false, false}, {prog(sol.SysvarRent), false, false}},
		Data: sol.InitNonceData(authority)}
}

// WithdrawNonce is the system program's WithdrawNonceAccount (index 5): authority takes lamports out of nonce to dest. The zone must refuse it.
func WithdrawNonce(nonce, dest, authority [32]byte, lamports uint64) Ix {
	return Ix{Program: prog(sol.SystemProgram), Accts: []Meta{{nonce, false, true}, {dest, false, true}, {prog(sol.SysvarRecentBlockhashes), false, false},
		{prog(sol.SysvarRent), false, false}, {authority, true, false}},
		Data: binary.LittleEndian.AppendUint64(binary.LittleEndian.AppendUint32(nil, 5), lamports)}
}

// AuthorizeNonce is AuthorizeNonceAccount (index 7): it hands the nonce account to newAuthority. The zone must refuse it.
func AuthorizeNonce(nonce, authority, newAuthority [32]byte) Ix {
	return Ix{Program: prog(sol.SystemProgram), Accts: []Meta{{nonce, false, true}, {authority, true, false}},
		Data: append(binary.LittleEndian.AppendUint32(nil, 7), newAuthority[:]...)}
}
