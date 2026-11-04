package cbmpc

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

// FuzzEntryPoints feeds arbitrary bytes to every parser and verifier that takes untrusted input:
//
//	0 frame reader        1 ECDSA keyset blob   2 Ed25519 keyset blob   3 sign-key blobs (3 algs)
//	4 stripped-blob join  5 PVE verify          6 PVE restore            7 a peer that sends the fuzz data as protocol messages
//
// Contract: never crash, never hang, always return an error (or a well-formed result) of the documented classes.
// Run: go test ./internal/cbmpc -run '^$' -fuzz FuzzEntryPoints -fuzztime 60s
var (
	fuzzOnce sync.Once
	fz       struct {
		ecdsaP1, ecdsaP2, edP1 []byte
		ek                     []byte
		dk                     *Secret
		ct                     []byte
		label                  []byte
		sp                     *KeysetSplit
		spEd                   *KeysetSplit
		k                      *Keyset
		edk                    *Keyset
	}
)

func fuzzSetup(t testing.TB) {
	fuzzOnce.Do(func() {
		doc := readGolden(t)
		dec := func(s string) []byte { b, _ := base64.StdEncoding.DecodeString(s); return b }
		fz.ecdsaP1, fz.ecdsaP2, fz.edP1 = dec(doc.Sets[0].P1Blob), dec(doc.Sets[0].P2Blob), dec(doc.Sets[2].P1Blob)
		var err error
		fz.k, err = LoadKeyset(ECDSA, P1, append([]byte(nil), fz.ecdsaP1...))
		must(t, err)
		fz.edk, err = LoadKeyset(Ed25519, P1, append([]byte(nil), fz.edP1...))
		must(t, err)
		fz.sp, err = fz.k.Split()
		must(t, err)
		fz.spEd, err = fz.edk.Split()
		must(t, err)
		fz.ek, fz.dk, err = GeneratePVEKeys()
		must(t, err)
		fz.label = BackupLabel("fuzz", ECDSA, P1)
		fz.ct, err = fz.sp.PVEExport(fz.ek, fz.label)
		must(t, err)
	})
}

type garbagePeer struct {
	data []byte
	n    int
}

func (g *garbagePeer) Send(ctx context.Context, msg []byte) error { return nil }
func (g *garbagePeer) Recv(ctx context.Context) ([]byte, error) {
	if g.n >= 3 {
		return nil, io.EOF
	}
	g.n++
	return g.data, nil
}

func FuzzEntryPoints(f *testing.F) {
	fuzzSetup(f)
	f.Add(byte(0), []byte{0, 0, 0, 3, 'a', 'b', 'c'})
	f.Add(byte(0), []byte{0xff, 0xff, 0xff, 0xff})
	f.Add(byte(1), fz.ecdsaP1)
	f.Add(byte(1), fz.ecdsaP2)
	f.Add(byte(2), fz.edP1)
	f.Add(byte(3), fz.ecdsaP1[:len(fz.ecdsaP1)/2])
	f.Add(byte(4), mustBytes(f, fz.sp.Stripped))
	f.Add(byte(4), mustBytes(f, fz.spEd.Stripped))
	f.Add(byte(5), fz.ct)
	f.Add(byte(6), fz.ct)
	f.Add(byte(7), []byte{1, 2, 3})
	f.Add(byte(7), fz.ct[:64])
	f.Fuzz(func(t *testing.T, sel byte, data []byte) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		checkErr := func(err error) {
			if err == nil {
				return
			}
			var e *Error
			if !errors.As(err, &e) && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, ErrBadFrame) {
				t.Fatalf("error of unexpected type %T: %v", err, err)
			}
		}
		cp := func() []byte { return append([]byte(nil), data...) }
		switch sel % 8 {
		case 0:
			b, err := ReadFrame(bytes.NewReader(data), 1<<16)
			checkErr(err)
			if err == nil && len(b) > 1<<16 {
				t.Fatal("frame above limit accepted")
			}
		case 1:
			k, err := LoadKeyset(ECDSA, Role(sel>>3&1), cp())
			checkErr(err)
			if err == nil {
				k.RootPublicKey()
				sp, err := k.Split()
				checkErr(err)
				sp.Wipe()
				k.Wipe()
			}
		case 2:
			k, err := LoadKeyset(Ed25519, Role(sel>>3&1), cp())
			checkErr(err)
			if err == nil {
				k.RootPublicKey()
				k.Wipe()
			}
		case 3:
			for _, alg := range []Alg{ECDSA, Ed25519, BIP340} {
				k, err := LoadSignKey(alg, Role(sel>>3&1), cp())
				checkErr(err)
				if err == nil {
					k.PublicKey()
					k.Wipe()
				}
			}
		case 4:
			for _, c := range []struct {
				alg Alg
				sp  *KeysetSplit
			}{{ECDSA, fz.sp}, {Ed25519, fz.spEd}} {
				s, err := NewKeysetSplit(c.alg, P1, cp(), c.sp.PubX, c.sp.PubK)
				if err != nil {
					checkErr(err)
					continue
				}
				s.X, s.K = c.sp.X, c.sp.K
				k, err := Join(s)
				checkErr(err)
				if err == nil {
					k.Wipe()
				}
				s.Stripped.Wipe() // do not wipe the shared X, K
			}
		case 5:
			checkErr(PVEVerify(ECDSA, fz.ek, cp(), fz.label, fz.sp.PubX, fz.sp.PubK))
			checkErr(PVEVerify(ECDSA, cp(), fz.ct, fz.label, fz.sp.PubX, fz.sp.PubK))
		case 6:
			x, k, err := PVERestore(ECDSA, fz.dk, fz.ek, cp(), fz.label)
			checkErr(err)
			if err == nil {
				x.Wipe()
				k.Wipe()
			}
			x, k, err = PVERestore(ECDSA, fz.dk, cp(), fz.ct, fz.label)
			checkErr(err)
			if err == nil {
				x.Wipe()
				k.Wipe()
			}
		case 7:
			// a peer that answers every protocol message with fuzz data
			_, err := fz.k.NodeExport(ctx, &garbagePeer{data: cp()}, []uint32{1}, WithRecvTimeout(5*time.Second))
			checkErr(err)
			if err == nil {
				t.Fatal("garbage peer completed a protocol")
			}
			if IsInternal(err) {
				t.Fatalf("garbage peer produced an internal error: %v", err)
			}
			_, err = fz.edk.Refresh(ctx, &garbagePeer{data: cp()}, WithRecvTimeout(5*time.Second))
			checkErr(err)
			if err == nil {
				t.Fatal("garbage peer completed a refresh")
			}
		}
	})
}

func mustBytes(t testing.TB, s *Secret) []byte {
	b, err := s.Bytes()
	must(t, err)
	return b
}
