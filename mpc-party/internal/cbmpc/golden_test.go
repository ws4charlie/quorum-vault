package cbmpc

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"testing"
)

// Golden tests pin everything the shim copies from cb-mpc internals:
//   - the HD keyset blob layout (field order and encoding): src/cbmpc/api/hd_keyset_ecdsa_2p.cpp and
//     src/cbmpc/api/hd_keyset_eddsa_2p.cpp (struct keyset_blob_v1_t),
//   - the hardened-step derivation (VRF, delta, chain code): src/cbmpc/protocol/hd_keyset_ecdsa_2p.cpp and
//     src/cbmpc/protocol/hd_keyset_eddsa_2p.cpp (derive_keys), non-hardened rule: src/cbmpc/protocol/hd_tree_bip32.cpp.
//
// The fixtures in testdata/golden.json are TEST-ONLY keyset shares generated from throwaway keys. They protect nothing.
// Regenerate (deliberately, after an upgrade review) with: go test ./internal/cbmpc -run TestGolden -update-golden

var updateGolden = flag.Bool("update-golden", false, "regenerate testdata/golden.json from fresh throwaway keys")

const goldenFile = "testdata/golden.json"

type goldenKS struct {
	Alg      string   `json:"alg"`
	P1Blob   string   `json:"p1_keyset_b64"`
	P2Blob   string   `json:"p2_keyset_b64"`
	P1SHA256 string   `json:"p1_sha256"`
	P2SHA256 string   `json:"p2_sha256"`
	RootPub  string   `json:"root_pub"`
	P1X      string   `json:"p1_x_mod_q"`
	P1K      string   `json:"p1_k"`
	P2X      string   `json:"p2_x_mod_q"`
	P2K      string   `json:"p2_k"`
	P1PubX   string   `json:"p1_pub_x"`
	P1PubK   string   `json:"p1_pub_k"`
	P2PubX   string   `json:"p2_pub_x"`
	P2PubK   string   `json:"p2_pub_k"`
	Hardened []uint32 `json:"hardened"`
	NodePub  string   `json:"node_pub"`
	NodeCC   string   `json:"node_chain_code"`
	Path     []uint32 `json:"path"`
	ChildPub string   `json:"child_pub"`
	P1XRed   bool     `json:"p1_x_reduced"`
}

type goldenDoc struct {
	Warning string     `json:"WARNING"`
	Pin     string     `json:"cbmpc_commit"`
	Sets    []goldenKS `json:"sets"`
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
func hx(b []byte) string  { return hex.EncodeToString(b) }

func secretBytes(t testing.TB, s *Secret) []byte {
	t.Helper()
	b, err := s.Bytes()
	must(t, err)
	return b
}

func snapshot(t testing.TB, name string, alg Alg, k1, k2 *Keyset) goldenKS {
	ctx := ctx5(t)
	g := goldenKS{Alg: name, Hardened: []uint32{44, 60, 0}, Path: []uint32{0, 7}}
	if alg == Ed25519 {
		g.Hardened = []uint32{44, 501, 0}
	}
	b1, b2 := secretBytes(t, k1.Secret), secretBytes(t, k2.Secret)
	s1, s2 := sha256.Sum256(b1), sha256.Sum256(b2)
	g.P1Blob, g.P2Blob, g.P1SHA256, g.P2SHA256 = b64(b1), b64(b2), hx(s1[:]), hx(s2[:])
	r, err := k1.RootPublicKey()
	must(t, err)
	g.RootPub = hx(r)
	sp1, err := k1.Split()
	must(t, err)
	sp2, err := k2.Split()
	must(t, err)
	g.P1X, g.P1K = hx(secretBytes(t, sp1.X)), hx(secretBytes(t, sp1.K))
	g.P2X, g.P2K = hx(secretBytes(t, sp2.X)), hx(secretBytes(t, sp2.K))
	g.P1PubX, g.P1PubK, g.P2PubX, g.P2PubK = hx(sp1.PubX), hx(sp1.PubK), hx(sp2.PubX), hx(sp2.PubK)
	g.P1XRed = sp1.XReduced
	sp1.Wipe()
	sp2.Wipe()
	var n Node
	e1, e2 := both(
		func(tr Transport) (err error) { n, err = k1.NodeExport(ctx, tr, g.Hardened); return },
		func(tr Transport) (err error) { _, err = k2.NodeExport(ctx, tr, g.Hardened); return })
	must(t, e1)
	must(t, e2)
	g.NodePub, g.NodeCC = hx(n.PublicKey), hx(n.ChainCode)
	c1, _ := derivePair(t, k1, k2, g.Hardened, g.Path)
	cp, err := c1.PublicKey()
	must(t, err)
	g.ChildPub = hx(cp)
	return g
}

func TestGoldenUpdate(t *testing.T) {
	if !*updateGolden {
		t.Skip("run with -update-golden to regenerate")
	}
	doc := goldenDoc{
		Warning: "TEST-ONLY keyset shares generated from throwaway keys for pinning cb-mpc's blob layout. Never use for funds.",
		Pin:     PinnedCommit,
	}
	k1, k2 := dkgPair(t, ECDSA)
	doc.Sets = append(doc.Sets, snapshot(t, "ecdsa", ECDSA, k1, k2))
	// A refreshed ECDSA keyset whose P1 share exceeds q: pins the "exact x lives in the Paillier plaintext" behaviour.
	cur1, cur2 := k1, k2
	for i := 0; ; i++ {
		if i == 40 {
			t.Fatal("no refresh produced x >= q in 40 tries")
		}
		var n1, n2 *Keyset
		ctx := ctx5(t)
		e1, e2 := both(
			func(tr Transport) (err error) { n1, err = cur1.Refresh(ctx, tr); return },
			func(tr Transport) (err error) { n2, err = cur2.Refresh(ctx, tr); return })
		must(t, e1)
		must(t, e2)
		cur1, cur2 = n1, n2
		sp, err := cur1.Split()
		must(t, err)
		red := sp.XReduced
		sp.Wipe()
		if red {
			break
		}
	}
	doc.Sets = append(doc.Sets, snapshot(t, "ecdsa-refreshed", ECDSA, cur1, cur2))
	e1, e2 := dkgPair(t, Ed25519)
	doc.Sets = append(doc.Sets, snapshot(t, "ed25519", Ed25519, e1, e2))
	out, err := json.MarshalIndent(doc, "", " ")
	must(t, err)
	must(t, os.WriteFile(goldenFile, append(out, '\n'), 0o644))
	t.Logf("wrote %s", goldenFile)
}

func readGolden(t testing.TB) goldenDoc {
	raw, err := os.ReadFile(goldenFile)
	must(t, err)
	var d goldenDoc
	must(t, json.Unmarshal(raw, &d))
	return d
}

func layoutFail(t testing.TB, alg string, what string, args ...any) {
	t.Helper()
	files := "src/cbmpc/api/hd_keyset_ecdsa_2p.cpp (keyset_blob_v1_t), src/cbmpc/protocol/hd_keyset_ecdsa_2p.cpp (derive_keys), src/cbmpc/protocol/hd_tree_bip32.cpp"
	if alg == "ed25519" {
		files = "src/cbmpc/api/hd_keyset_eddsa_2p.cpp (keyset_blob_v1_t), src/cbmpc/protocol/hd_keyset_eddsa_2p.cpp (derive_keys), src/cbmpc/protocol/hd_tree_bip32.cpp"
	}
	t.Fatalf("GOLDEN MISMATCH [%s]: %s\n"+
		"cb-mpc's internal layout or derivation changed (or the shim regressed). Compare upstream %s with mpc-party/internal/cbmpc/shim.cpp (ks_ecdsa_t, ks_eddsa_t, qv_hd_node), "+
		"follow README 'Upgrade procedure', and only then regenerate with -update-golden.",
		alg, fmt.Sprintf(what, args...), files)
}

func TestGolden(t *testing.T) {
	doc := readGolden(t)
	if doc.Pin != PinnedCommit {
		t.Fatalf("golden fixtures were generated for cb-mpc %s but the pin is %s: finish the upgrade procedure and regenerate", doc.Pin, PinnedCommit)
	}
	if len(doc.Sets) != 3 {
		t.Fatalf("expected 3 fixture sets, got %d", len(doc.Sets))
	}
	for _, g := range doc.Sets {
		g := g
		t.Run(g.Alg, func(t *testing.T) {
			alg := ECDSA
			if g.Alg == "ed25519" {
				alg = Ed25519
			}
			ctx := ctx5(t)
			raw1, _ := base64.StdEncoding.DecodeString(g.P1Blob)
			raw2, _ := base64.StdEncoding.DecodeString(g.P2Blob)
			if h := sha256.Sum256(raw1); hx(h[:]) != g.P1SHA256 {
				t.Fatal("fixture file corrupted (p1 sha256)")
			}
			orig1, orig2 := append([]byte(nil), raw1...), append([]byte(nil), raw2...)
			k1, err := LoadKeyset(alg, P1, raw1)
			if err != nil {
				layoutFail(t, g.Alg, "fixture P1 keyset no longer parses: %v", err)
			}
			k2, err := LoadKeyset(alg, P2, raw2)
			if err != nil {
				layoutFail(t, g.Alg, "fixture P2 keyset no longer parses: %v", err)
			}
			defer k1.Wipe()
			defer k2.Wipe()

			if r, _ := k1.RootPublicKey(); hx(r) != g.RootPub {
				layoutFail(t, g.Alg, "root public key %x != pinned %s", r, g.RootPub)
			}
			// Field positions: split must find the scalars where the fixture says they are.
			for i, k := range []*Keyset{k1, k2} {
				sp, err := k.Split()
				must(t, err)
				wantX, wantK, px, pk := g.P1X, g.P1K, g.P1PubX, g.P1PubK
				orig := orig1
				if i == 1 {
					wantX, wantK, px, pk = g.P2X, g.P2K, g.P2PubX, g.P2PubK
					orig = orig2
				}
				if hx(secretBytes(t, sp.X)) != wantX || hx(secretBytes(t, sp.K)) != wantK {
					layoutFail(t, g.Alg, "party %d: x/k scalars are not where the pinned layout puts them", i+1)
				}
				if hx(sp.PubX) != px || hx(sp.PubK) != pk {
					layoutFail(t, g.Alg, "party %d: public share points differ", i+1)
				}
				if sp.XReduced != (i == 0 && g.P1XRed) {
					layoutFail(t, g.Alg, "party %d: x >= q flag %v differs from fixture", i+1, sp.XReduced)
				}
				// Canonical re-serialization: join(split(blob)) is byte-identical to the original.
				j, err := Join(sp)
				if err != nil {
					layoutFail(t, g.Alg, "party %d: join(split) failed: %v", i+1, err)
				}
				if !bytes.Equal(secretBytes(t, j.Secret), orig) {
					layoutFail(t, g.Alg, "party %d: join(split(blob)) is not byte-identical: encoding of the blob changed", i+1)
				}
				j.Wipe()
				sp.Wipe()
			}

			// Hardened step: node public key and chain code are deterministic functions of the shares and the path.
			var n Node
			e1, e2 := both(
				func(tr Transport) (err error) { n, err = k1.NodeExport(ctx, tr, g.Hardened); return },
				func(tr Transport) (err error) { _, err = k2.NodeExport(ctx, tr, g.Hardened); return })
			must(t, e1)
			must(t, e2)
			if hx(n.PublicKey) != g.NodePub {
				layoutFail(t, g.Alg, "node public key %x != pinned %s (VRF / delta derivation changed)", n.PublicKey, g.NodePub)
			}
			if hx(n.ChainCode) != g.NodeCC {
				layoutFail(t, g.Alg, "chain code %x != pinned %s (chain code extraction changed)", n.ChainCode, g.NodeCC)
			}
			// Full derivation + signing with the fixture shares.
			c1, c2 := derivePair(t, k1, k2, g.Hardened, g.Path)
			cp, _ := c1.PublicKey()
			if hx(cp) != g.ChildPub {
				layoutFail(t, g.Alg, "derived child key %x != pinned %s", cp, g.ChildPub)
			}
			d := digest32(77)
			sig, e1, e2 := signPair(ctx, c1, c2, d)
			must(t, e1)
			must(t, e2)
			if alg == ECDSA {
				verifyECDSA(t, cp, d, sig)
			} else {
				verifyEd25519(t, cp, d, sig)
			}
		})
	}
}
