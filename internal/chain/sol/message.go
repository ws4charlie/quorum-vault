package sol

import (
	"errors"
	"fmt"
)

// A legacy Solana message, decoded just far enough for the signing zone to judge it. Layout: three header bytes (required signatures,
// read-only signed accounts, read-only unsigned accounts), the account keys, the recent blockhash, then the instructions. Lengths are
// compact-u16. Versioned (v0) messages start with a byte whose high bit is set and carry address lookup tables, which hide accounts from
// the message itself; the zone refuses them, since it could not say who an instruction pays.

// MaxMessage is the largest message a transaction can carry (1232 bytes: the packet minus the signature count and one signature).
const MaxMessage = 1232

// MsgInstruction is a decoded instruction with its accounts resolved to keys.
type MsgInstruction struct {
	Program [32]byte
	Accts   [][32]byte
	Data    []byte
	// AcctIdx are the indices into Message.Keys of Accts.
	AcctIdx []int
}

// Message is a decoded legacy message.
type Message struct {
	NumSigners    int
	NumROSigned   int
	NumROUnsigned int
	Keys          [][32]byte
	Blockhash     [32]byte
	Instructions  []MsgInstruction
	ProgramIdx    []int
	rawLen        int
}

func readCompactU16(b []byte) (n int, used int, err error) {
	var v uint
	for i := 0; i < 3; i++ {
		if i >= len(b) {
			return 0, 0, errors.New("truncated length")
		}
		c := b[i]
		v |= uint(c&0x7f) << (7 * uint(i))
		if c&0x80 == 0 {
			if i > 0 && c == 0 {
				return 0, 0, errors.New("non-canonical length")
			}
			if v > 0xffff {
				return 0, 0, errors.New("length too large")
			}
			return int(v), i + 1, nil
		}
	}
	return 0, 0, errors.New("length too long")
}

// DecodeMessage parses a legacy message and refuses everything else: a versioned message, trailing bytes, an instruction or account index out
// of range, a duplicate account key, a message with no instruction.
func DecodeMessage(b []byte) (*Message, error) {
	if len(b) == 0 || len(b) > MaxMessage {
		return nil, fmt.Errorf("message of %d bytes (1 to %d)", len(b), MaxMessage)
	}
	if b[0]&0x80 != 0 {
		return nil, errors.New("versioned (v0) message: address lookup tables are not accepted")
	}
	if len(b) < 3 {
		return nil, errors.New("message shorter than its header")
	}
	m := &Message{NumSigners: int(b[0]), NumROSigned: int(b[1]), NumROUnsigned: int(b[2])}
	p := 3
	nk, used, err := readCompactU16(b[p:])
	if err != nil {
		return nil, fmt.Errorf("account count: %w", err)
	}
	p += used
	if nk == 0 || nk > 64 || p+nk*32+32 > len(b) {
		return nil, fmt.Errorf("%d account keys do not fit the message", nk)
	}
	if m.NumSigners < 1 || m.NumSigners > nk || m.NumROSigned >= m.NumSigners || m.NumROUnsigned > nk-m.NumSigners {
		return nil, errors.New("inconsistent message header")
	}
	seen := map[[32]byte]bool{}
	for i := 0; i < nk; i++ {
		var k [32]byte
		copy(k[:], b[p:p+32])
		p += 32
		if seen[k] {
			return nil, fmt.Errorf("account %s appears twice in the message", Address(k))
		}
		seen[k] = true
		m.Keys = append(m.Keys, k)
	}
	copy(m.Blockhash[:], b[p:p+32])
	p += 32
	ni, used, err := readCompactU16(b[p:])
	if err != nil {
		return nil, fmt.Errorf("instruction count: %w", err)
	}
	p += used
	if ni == 0 || ni > 32 {
		return nil, fmt.Errorf("%d instructions", ni)
	}
	for i := 0; i < ni; i++ {
		if p >= len(b) {
			return nil, errors.New("truncated instruction")
		}
		pi := int(b[p])
		p++
		if pi >= nk {
			return nil, fmt.Errorf("instruction %d: program index %d out of range", i, pi)
		}
		na, used, err := readCompactU16(b[p:])
		if err != nil {
			return nil, fmt.Errorf("instruction %d accounts: %w", i, err)
		}
		p += used
		if p+na > len(b) {
			return nil, errors.New("truncated instruction accounts")
		}
		ins := MsgInstruction{Program: m.Keys[pi]}
		for j := 0; j < na; j++ {
			ai := int(b[p+j])
			if ai >= nk {
				return nil, fmt.Errorf("instruction %d: account index %d out of range", i, ai)
			}
			ins.Accts = append(ins.Accts, m.Keys[ai])
			ins.AcctIdx = append(ins.AcctIdx, ai)
		}
		p += na
		nd, used, err := readCompactU16(b[p:])
		if err != nil {
			return nil, fmt.Errorf("instruction %d data: %w", i, err)
		}
		p += used
		if p+nd > len(b) {
			return nil, errors.New("truncated instruction data")
		}
		ins.Data = append([]byte(nil), b[p:p+nd]...)
		p += nd
		m.Instructions = append(m.Instructions, ins)
		m.ProgramIdx = append(m.ProgramIdx, pi)
	}
	if p != len(b) {
		return nil, fmt.Errorf("%d trailing bytes after the last instruction", len(b)-p)
	}
	m.rawLen = len(b)
	return m, nil
}

// IsSigner reports whether the key at index i must sign.
func (m *Message) IsSigner(i int) bool { return i < m.NumSigners }

// IsWritable reports whether the key at index i is writable under the header.
func (m *Message) IsWritable(i int) bool {
	if i < m.NumSigners {
		return i < m.NumSigners-m.NumROSigned
	}
	return i < len(m.Keys)-m.NumROUnsigned
}
