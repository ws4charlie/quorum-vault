package cbmpc

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"time"
)

// FuzzEntryPoints feeds arbitrary bytes to every parser and verifier that takes untrusted input:
//
//	0 frame reader        1 ECDSA keyset blob   2 Ed25519 keyset blob   3 sign-key blobs (3 algs)
//	4 stripped-blob join  5 PVE verify          6 PVE restore            7 a peer that sends the fuzz data as protocol messages
//	8 threshold share blob  9 threshold backup join  10 threshold PVE verify/restore
//	11 a peer (or two) that sends the fuzz data as messages in threshold DKG / sign / refresh / self-test
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
		tk                     *TKey // threshold fixture, member 0
		tshare                 []byte
		tpub, tx, tpubX, tct   []byte
		tlabel                 []byte
		tdkSecret              *Secret
		etk                    *TKey // Ed25519 threshold fixture, member 0
		eshare                 []byte
		epub, ex, epubX, ect   []byte
		elabel                 []byte
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
		_, tblobs := readGoldenT(t)
		fz.tshare = tblobs[0]
		fz.tk, err = LoadTKey(0, append([]byte(nil), tblobs[0]...))
		must(t, err)
		tsp, err := fz.tk.Split()
		must(t, err)
		fz.tpub, fz.tpubX = tsp.Public, tsp.PubX
		fz.tx = secretBytes(t, tsp.X)
		fz.tlabel = TBackupLabel("fuzz", 0, 1)
		fz.tct, err = tsp.PVEExport(fz.ek, fz.tlabel)
		must(t, err)
		tsp.Wipe()
		raw, err := os.ReadFile(goldenTEdFile)
		must(t, err)
		var eg goldenT
		must(t, json.Unmarshal(raw, &eg))
		fz.eshare = dec(eg.Blobs[0])
		fz.etk, err = LoadTKeyAlg(Ed25519, 0, append([]byte(nil), fz.eshare...))
		must(t, err)
		esp, err := fz.etk.Split()
		must(t, err)
		fz.epub, fz.epubX = esp.Public, esp.PubX
		fz.ex = secretBytes(t, esp.X)
		fz.elabel = TBackupLabelAlg(Ed25519, "fuzz", 0, 1)
		fz.ect, err = esp.PVEExport(fz.ek, fz.elabel)
		must(t, err)
		esp.Wipe()
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

// garbageMesh answers every Recv from any member with the fuzz data (a few times, then EOF) and swallows every Send.
type garbageMesh struct {
	data []byte
	mu   sync.Mutex
	n    map[Member]int
}

func (g *garbageMesh) Send(ctx context.Context, to Member, msg []byte) error { return nil }
func (g *garbageMesh) Recv(ctx context.Context, from Member) ([]byte, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.n == nil {
		g.n = map[Member]int{}
	}
	if g.n[from] >= 3 {
		return nil, io.EOF
	}
	g.n[from]++
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
	f.Add(byte(8), fz.tshare)
	f.Add(byte(8), fz.tshare[:len(fz.tshare)/2])
	f.Add(byte(9), fz.tpub)
	f.Add(byte(10), fz.tct)
	f.Add(byte(11), []byte{1, 2, 3})
	f.Add(byte(11), fz.tct[:64])
	f.Add(byte(12), fz.eshare)
	f.Add(byte(12), fz.eshare[:len(fz.eshare)/2])
	f.Add(byte(13), fz.epub)
	f.Add(byte(14), fz.ect)
	f.Add(byte(15), []byte{1, 2, 3})
	f.Add(byte(15), fz.ect[:64])
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
		switch sel % 16 {
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
		case 8:
			k, err := LoadTKey(Member(sel>>4%3), cp())
			checkErr(err)
			if err == nil {
				k.PublicKey()
				sp, err := k.Split()
				checkErr(err)
				sp.Wipe()
				k.Wipe()
			}
		case 9:
			x := SecretFromBytes(append([]byte(nil), fz.tx...))
			k, err := TJoin(Member(sel>>4%3), cp(), x, fz.tpubX)
			checkErr(err)
			if err == nil {
				k.Wipe()
			}
			x.Wipe()
		case 10:
			checkErr(TPVEVerify(fz.ek, cp(), fz.tlabel, fz.tpubX))
			checkErr(TPVEVerify(cp(), fz.tct, fz.tlabel, fz.tpubX))
			x, err := TRestoreScalar(fz.dk, fz.ek, cp(), fz.tlabel)
			checkErr(err)
			if err == nil {
				x.Wipe()
			}
			x, err = TRestoreScalar(fz.dk, cp(), fz.tct, fz.tlabel)
			checkErr(err)
			if err == nil {
				x.Wipe()
			}
		case 11:
			// peers that answer every protocol message with fuzz data: the garbage must never complete a protocol
			opt := WithRecvTimeout(5 * time.Second)
			_, err := TDKG(ctx, &garbageMesh{data: cp()}, Member(sel>>4%3), opt)
			checkErr(err)
			if err == nil {
				t.Fatal("garbage peers completed a threshold DKG")
			}
			peer := Member(1 + sel>>4%2)
			sig, err := fz.tk.Sign(ctx, &garbageMesh{data: cp()}, peer, 0, digest32(1), opt)
			checkErr(err)
			if err == nil || sig != nil {
				t.Fatal("garbage peer completed a threshold signature")
			}
			if IsInternal(err) {
				t.Fatalf("garbage peer produced an internal error: %v", err)
			}
			_, err = fz.tk.Refresh(ctx, &garbageMesh{data: cp()}, opt)
			checkErr(err)
			if err == nil {
				t.Fatal("garbage peers completed a threshold refresh")
			}
			err = fz.tk.SelfTest(ctx, &garbageMesh{data: cp()}, []byte("fuzz"), opt)
			checkErr(err)
			if err == nil {
				t.Fatal("garbage peers passed the threshold self-test")
			}
		case 12: // Ed25519 threshold share
			k, err := LoadTKeyAlg(Ed25519, Member(sel>>4%3), cp())
			checkErr(err)
			if err == nil {
				k.PublicKey()
				sp, err := k.Split()
				checkErr(err)
				sp.Wipe()
				k.Wipe()
			}
		case 13:
			x := SecretFromBytes(append([]byte(nil), fz.ex...))
			k, err := TJoin(Member(sel>>4%3), cp(), x, fz.epubX)
			checkErr(err)
			if err == nil {
				k.Wipe()
			}
			x.Wipe()
		case 14:
			checkErr(TPVEVerify(fz.ek, cp(), fz.elabel, fz.epubX))
			checkErr(TPVEVerify(cp(), fz.ect, fz.elabel, fz.epubX))
			x, err := TRestoreScalarAlg(Ed25519, fz.dk, fz.ek, cp(), fz.elabel)
			checkErr(err)
			if err == nil {
				x.Wipe()
			}
			x, err = TRestoreScalarAlg(Ed25519, fz.dk, cp(), fz.ect, fz.elabel)
			checkErr(err)
			if err == nil {
				x.Wipe()
			}
		case 15:
			opt := WithRecvTimeout(5 * time.Second)
			_, err := TDKGAlg(ctx, &garbageMesh{data: cp()}, Member(sel>>4%3), Ed25519, opt)
			checkErr(err)
			if err == nil {
				t.Fatal("garbage peers completed an Ed25519 threshold DKG")
			}
			peer := Member(1 + sel>>4%2)
			sig, err := fz.etk.Sign(ctx, &garbageMesh{data: cp()}, peer, 0, edMsg(32, 1), opt)
			checkErr(err)
			if err == nil || sig != nil {
				t.Fatal("garbage peer completed an Ed25519 threshold signature")
			}
			if IsInternal(err) {
				t.Fatalf("garbage peer produced an internal error: %v", err)
			}
			_, err = fz.etk.Refresh(ctx, &garbageMesh{data: cp()}, opt)
			checkErr(err)
			if err == nil {
				t.Fatal("garbage peers completed an Ed25519 threshold refresh")
			}
			err = fz.etk.SelfTest(ctx, &garbageMesh{data: cp()}, []byte("fuzz"), opt)
			checkErr(err)
			if err == nil {
				t.Fatal("garbage peers passed the Ed25519 threshold self-test")
			}
		}
	})
}

func mustBytes(t testing.TB, s *Secret) []byte {
	b, err := s.Bytes()
	must(t, err)
	return b
}
