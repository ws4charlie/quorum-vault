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

// Compile builds a legacy message with payer as the fee payer: signers first (payer first of them), then writable, then read-only accounts.
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
	m = append(m, compactU16(len(order))...)
	for _, x := range order {
		m = append(m, x.k[:]...)
	}
	m = append(m, blockhash[:]...)
	m = append(m, compactU16(len(ixs))...)
	for _, in := range ixs {
		m = append(m, byte(pos[in.Program]))
		m = append(m, compactU16(len(in.Accts))...)
		for _, ac := range in.Accts {
			m = append(m, byte(pos[ac.Key]))
		}
		m = append(m, compactU16(len(in.Data))...)
		m = append(m, in.Data...)
	}
	return m
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
