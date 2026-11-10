package sol

import (
	"encoding/binary"
)

// A legacy-message compiler and the instructions a custody cell builds. The signing zone does not use it: it only decodes (message.go).

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

func mustAddr(s string) [32]byte { p, _ := ParseAddress(s); return p }

// SetLimitIx and SetPriceIx are the compute budget instructions.
func SetLimitIx(n uint32) Ix {
	return Ix{Program: mustAddr(ComputeBudgetProgram), Data: binary.LittleEndian.AppendUint32([]byte{2}, n)}
}
func SetPriceIx(microLamports uint64) Ix {
	return Ix{Program: mustAddr(ComputeBudgetProgram), Data: binary.LittleEndian.AppendUint64([]byte{3}, microLamports)}
}

// AdvanceNonceIx advances nonce; authority signs.
func AdvanceNonceIx(nonce, authority [32]byte) Ix {
	return Ix{Program: mustAddr(SystemProgram), Accts: []Meta{{nonce, false, true}, {mustAddr(SysvarRecentBlockhashes), false, false}, {authority, true, false}},
		Data: AdvanceNonceData()}
}

// TransferIx is a system program transfer.
func TransferIx(from, to [32]byte, lamports uint64) Ix {
	return Ix{Program: mustAddr(SystemProgram), Accts: []Meta{{from, true, true}, {to, false, true}},
		Data: binary.LittleEndian.AppendUint64(binary.LittleEndian.AppendUint32(nil, 2), lamports)}
}

// CheckedTransferIx is a Token program transferChecked.
func CheckedTransferIx(src, mint, dst, authority [32]byte, amount uint64, decimals uint8) Ix {
	return Ix{Program: mustAddr(TokenProgram), Accts: []Meta{{src, false, true}, {mint, false, false}, {dst, false, true}, {authority, true, false}},
		Data: append(binary.LittleEndian.AppendUint64([]byte{12}, amount), decimals)}
}

// CreateATAIx is an idempotent associated-token-account create paid by payer.
func CreateATAIx(payer, ata, owner, mint [32]byte) Ix {
	return Ix{Program: mustAddr(AssociatedTokenProg), Data: []byte{1}, Accts: []Meta{{payer, true, true}, {ata, false, true}, {owner, false, false}, {mint, false, false},
		{mustAddr(SystemProgram), false, false}, {mustAddr(TokenProgram), false, false}}}
}

// CreateNonceIxs are the two instructions that create pool account i of hot and make hot its authority.
func CreateNonceIxs(hot [32]byte, i int, lamports uint64) []Ix {
	n := NonceAddress(hot, i)
	return []Ix{
		{Program: mustAddr(SystemProgram), Accts: []Meta{{hot, true, true}, {n, false, true}}, Data: CreateWithSeedData(hot, NonceSeed(i), lamports, NonceAccountSize)},
		{Program: mustAddr(SystemProgram), Accts: []Meta{{n, false, true}, {mustAddr(SysvarRecentBlockhashes), false, false}, {mustAddr(SysvarRent), false, false}}, Data: InitNonceData(hot)},
	}
}

// Ixs turns a decoded message back into instructions, with the signer and writable flags its header gives each account.
func (m *Message) Ixs() []Ix {
	out := make([]Ix, 0, len(m.Instructions))
	for _, in := range m.Instructions {
		x := Ix{Program: in.Program, Data: append([]byte(nil), in.Data...)}
		for j, ai := range in.AcctIdx {
			x.Accts = append(x.Accts, Meta{Key: in.Accts[j], Signer: m.IsSigner(ai), Writable: m.IsWritable(ai)})
		}
		out = append(out, x)
	}
	return out
}
