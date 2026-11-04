package cbmpc

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

// Truncated and bit-flipped frames and blobs return errors (or, for a flip in a value the format does not validate, a
// blob that parses): they never crash, and every error is classified.
func TestMalformedBlobsNeverCrash(t *testing.T) {
	doc := readGolden(t)
	var parsed, rejected int
	for _, g := range doc.Sets {
		alg := ECDSA
		if g.Alg == "ed25519" {
			alg = Ed25519
		}
		blob, _ := base64.StdEncoding.DecodeString(g.P1Blob)
		try := func(b []byte) {
			k, err := LoadKeyset(alg, P1, append([]byte(nil), b...))
			if err != nil {
				if KindOf(err) == 0 {
					t.Fatalf("unclassified error: %v", err)
				}
				rejected++
				return
			}
			parsed++
			k.RootPublicKey()
			if sp, err := k.Split(); err == nil {
				sp.Wipe()
			}
			k.Wipe()
		}
		for n := 0; n < len(blob); n++ { // every truncation
			try(blob[:n])
		}
		for i := 0; i < len(blob); i++ { // every single-bit flip of one bit per byte
			m := append([]byte(nil), blob...)
			m[i] ^= 1 << (uint(i) % 8)
			try(m)
		}
		try(append(append([]byte(nil), blob...), 0)) // trailing garbage
		try(bytes.Repeat([]byte{0xff}, len(blob)))
		try(make([]byte, len(blob)))
	}
	t.Logf("blob mutations: %d rejected, %d still parse (flips in unvalidated value bytes)", rejected, parsed)
	if rejected == 0 {
		t.Fatal("no malformed blob was rejected")
	}
}

func TestMalformedFrames(t *testing.T) {
	frame := func(n uint32, payload []byte) []byte {
		b := make([]byte, 4, 4+len(payload))
		binary.BigEndian.PutUint32(b, n)
		return append(b, payload...)
	}
	good := frame(3, []byte("abc"))
	if m, err := ReadFrame(bytes.NewReader(good), 16); err != nil || string(m) != "abc" {
		t.Fatalf("good frame: %q %v", m, err)
	}
	for name, in := range map[string][]byte{
		"empty":            nil,
		"short header":     {0, 0},
		"truncated body":   good[:6],
		"header only":      good[:4],
		"length too large": frame(1<<31, []byte("x")),
		"max uint32":       frame(0xffffffff, nil),
	} {
		m, err := ReadFrame(bytes.NewReader(in), 16)
		if err == nil {
			t.Errorf("%s: accepted %q", name, m)
			continue
		}
		if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, ErrBadFrame) {
			t.Errorf("%s: unexpected error %v", name, err)
		}
	}
	// A bit flip in the length of a valid frame either fails or yields a different, bounded frame.
	for bit := 0; bit < 32; bit++ {
		in := append([]byte(nil), good...)
		in[bit/8] ^= 1 << (uint(bit) % 8)
		if m, err := ReadFrame(bytes.NewReader(in), 16); err == nil && len(m) > 16 {
			t.Errorf("bit %d: oversize frame accepted", bit)
		}
	}
}
