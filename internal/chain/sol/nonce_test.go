package sol

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestNonceAddressIsDeterministicAndDistinct(t *testing.T) {
	hot := [32]byte{1, 2, 3}
	seen := map[[32]byte]bool{}
	for i := 0; i < 64; i++ {
		a := NonceAddress(hot, i)
		if a != NonceAddress(hot, i) || seen[a] {
			t.Fatalf("pool account %d repeats or changes", i)
		}
		seen[a] = true
	}
	if NonceAddress(hot, 0) == NonceAddress([32]byte{9}, 0) {
		t.Fatal("two shards share a pool address")
	}
}

func TestParseNonceAccount(t *testing.T) {
	data := make([]byte, NonceAccountSize)
	binary.LittleEndian.PutUint32(data[0:], 1) // current
	binary.LittleEndian.PutUint32(data[4:], 1) // initialized
	auth, val := [32]byte{7}, [32]byte{8}
	copy(data[8:], auth[:])
	copy(data[40:], val[:])
	st, err := ParseNonceAccount(data)
	if err != nil || st.Authority != auth || st.Value != val {
		t.Fatalf("%+v %v", st, err)
	}
	for name, mod := range map[string]func([]byte) []byte{
		"short":         func(b []byte) []byte { return b[:79] },
		"uninitialized": func(b []byte) []byte { b[4] = 0; return b },
		"old version":   func(b []byte) []byte { b[0] = 0; return b },
	} {
		if _, err := ParseNonceAccount(mod(append([]byte(nil), data...))); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

// A message decoded and compiled again is the same message; raising the price changes the price and nothing else.
func TestRaisingThePriceChangesOnlyThePrice(t *testing.T) {
	hot, dest, value := [32]byte{1}, [32]byte{2}, [32]byte{3}
	n := NonceAddress(hot, 1)
	for name, ixs := range map[string][]Ix{
		"with a price":    {AdvanceNonceIx(n, hot), SetLimitIx(50_000), SetPriceIx(1000), TransferIx(hot, dest, 5)},
		"without a price": {AdvanceNonceIx(n, hot), SetLimitIx(50_000), TransferIx(hot, dest, 5)},
	} {
		msg := Compile(hot, value, ixs...)
		m, err := DecodeMessage(msg)
		if err != nil {
			t.Fatal(name, err)
		}
		if !bytes.Equal(Compile(m.Keys[0], m.Blockhash, m.Ixs()...), msg) {
			t.Fatalf("%s: decoding and compiling again changes the message", name)
		}
		raised := Compile(hot, value, withPrice(m, 2500)...)
		rm, err := DecodeMessage(raised)
		if err != nil {
			t.Fatal(name, err)
		}
		if rm.Blockhash != value || len(rm.Instructions) != 4 {
			t.Fatalf("%s: %d instructions, blockhash %x", name, len(rm.Instructions), rm.Blockhash)
		}
		want := Compile(hot, value, AdvanceNonceIx(n, hot), SetLimitIx(50_000), SetPriceIx(2500), TransferIx(hot, dest, 5))
		if !bytes.Equal(raised, want) {
			t.Fatalf("%s: the raised message differs from one built with the new price", name)
		}
	}
}

func TestBump(t *testing.T) {
	a := &Adapter{cfg: &validatedConfig{Config: Config{FeeBumpPercent: 20}}}
	for old, want := range map[uint64]uint64{0: 1000, 1: 2, 5: 6, 1000: 1200, 1001: 1202} {
		if got := a.bump(old); got != want {
			t.Errorf("bump(%d) = %d, want %d", old, got, want)
		}
	}
}
