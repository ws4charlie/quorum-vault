package cbmpc

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

// Golden fixtures for the threshold calls. They pin what the shim copies from cb-mpc internals:
//   - the access-structure key blob layout: src/cbmpc/api/ecdsa_mp.cpp (struct key_blob_v1_t, version 2 for access
//     structure blobs) mirrored by tkey_blob_t in shim.cpp;
//   - the fixed party names qv-t0..qv-t2 (blobs and every proof are bound to them);
//   - that a share blob made by dkg_ac / refresh_ac keeps working in sign_ac / refresh_ac / detach/attach_private_scalar
//     (src/cbmpc/api/ecdsa_mp.cpp, src/cbmpc/protocol/ec_dkg.cpp dkg_or_refresh_ac).
//
// testdata/golden_tecdsa.json holds TEST-ONLY shares of a throwaway key. Regenerate, deliberately, after an upgrade
// review, with: go test ./internal/cbmpc -run TestGoldenThresholdUpdate -update-golden

const goldenTFile = "testdata/golden_tecdsa.json"

type goldenT struct {
	Warning string      `json:"WARNING"`
	Pin     string      `json:"cbmpc_commit"`
	Blobs   [3]string   `json:"share_blobs_b64"`
	SHA256  [3]string   `json:"share_sha256"`
	Pub     string      `json:"group_pub"`
	Qi      [3]string   `json:"share_points"`
	X       [3]string   `json:"x_share"`
	Public  [3]string   `json:"public_blob_sha256"`
	Names   [3]string   `json:"party_names"`
	Version uint32      `json:"blob_version"`
	_       interface{} `json:"-"`
}

func TestGoldenThresholdUpdate(t *testing.T) {
	if !*updateGolden {
		t.Skip("run with -update-golden to regenerate")
	}
	ks := tDKG(t)
	g := goldenT{
		Warning: "TEST-ONLY threshold shares from a throwaway key for pinning cb-mpc's ecdsa_mp blob layout. Never use for funds.",
		Pin:     PinnedCommit,
		Pub:     hx(ks[0].PublicKey()),
		Names:   [3]string{"qv-t0", "qv-t1", "qv-t2"},
		Version: 2,
	}
	for i, k := range ks {
		b := secretBytes(t, k.Secret)
		h := sha256.Sum256(b)
		g.Blobs[i], g.SHA256[i], g.Qi[i] = b64(b), hx(h[:]), hx(k.SharePoint())
		sp, err := k.Split()
		must(t, err)
		g.X[i] = hx(secretBytes(t, sp.X))
		ph := sha256.Sum256(sp.Public)
		g.Public[i] = hx(ph[:])
		sp.Wipe()
	}
	out, err := json.MarshalIndent(g, "", " ")
	must(t, err)
	must(t, os.WriteFile(goldenTFile, append(out, '\n'), 0o644))
	t.Logf("wrote %s", goldenTFile)
}

func readGoldenT(t testing.TB) (goldenT, [3][]byte) {
	raw, err := os.ReadFile(goldenTFile)
	must(t, err)
	var g goldenT
	must(t, json.Unmarshal(raw, &g))
	var blobs [3][]byte
	for i := range blobs {
		blobs[i], err = base64.StdEncoding.DecodeString(g.Blobs[i])
		must(t, err)
	}
	return g, blobs
}

func tLayoutFail(t testing.TB, what string, args ...any) {
	t.Helper()
	t.Fatalf("GOLDEN MISMATCH [threshold ecdsa]: "+what+"\n"+
		"cb-mpc's ecdsa_mp blob layout or protocol changed (or the shim regressed). Compare upstream src/cbmpc/api/ecdsa_mp.cpp "+
		"(key_blob_v1_t, ac_key_blob_version_v1) and src/cbmpc/protocol/ec_dkg.cpp with mpc-party/internal/cbmpc/shim.cpp "+
		"(tkey_blob_t, t_parse), follow README 'Upgrade procedure', and only then regenerate with -update-golden.", args...)
}

func loadGoldenT(t testing.TB) (g goldenT, ks [NumMembers]*TKey, raw [3][]byte) {
	g, raw = readGoldenT(t)
	if g.Pin != PinnedCommit {
		t.Fatalf("threshold golden fixtures were generated for cb-mpc %s but the pin is %s: finish the upgrade procedure and regenerate", g.Pin, PinnedCommit)
	}
	for i := range ks {
		if h := sha256.Sum256(raw[i]); hx(h[:]) != g.SHA256[i] {
			t.Fatal("fixture file corrupted (sha256)")
		}
		var err error
		ks[i], err = LoadTKey(Member(i), append([]byte(nil), raw[i]...))
		if err != nil {
			tLayoutFail(t, "fixture share %d no longer parses: %v", i, err)
		}
	}
	t.Cleanup(func() {
		for _, k := range ks {
			k.Wipe()
		}
	})
	return
}

func TestGoldenThreshold(t *testing.T) {
	g, ks, raw := loadGoldenT(t)
	ctx := ctx5(t)
	for i, k := range ks {
		if hx(k.PublicKey()) != g.Pub {
			tLayoutFail(t, "group public key of share %d changed", i)
		}
		if hx(k.SharePoint()) != g.Qi[i] {
			tLayoutFail(t, "share point of member %d changed", i)
		}
		// names and version are in the blob: bind them
		if !bytes.Contains(raw[i], []byte(g.Names[i])) {
			tLayoutFail(t, "party name %q is not in the blob of member %d", g.Names[i], i)
		}
		if raw[i][0] != byte(g.Version) && raw[i][3] != byte(g.Version) { // either endianness of the leading u32
			tLayoutFail(t, "blob version byte is not %d", g.Version)
		}
		// backup split/join is deterministic on the fixture
		sp, err := k.Split()
		must(t, err)
		if hx(secretBytes(t, sp.X)) != g.X[i] {
			tLayoutFail(t, "detach_private_scalar output of member %d changed", i)
		}
		if h := sha256.Sum256(sp.Public); hx(h[:]) != g.Public[i] {
			tLayoutFail(t, "public blob of member %d changed", i)
		}
		rk, err := TJoin(Member(i), sp.Public, sp.X, sp.PubX)
		if err != nil || !bytes.Equal(secretBytes(t, rk.Secret), raw[i]) {
			tLayoutFail(t, "attach_private_scalar does not rebuild the fixture of member %d (%v)", i, err)
		}
		rk.Wipe()
		sp.Wipe()
	}
	// every pair signs with the fixture, in both receiver roles
	for _, pr := range allPairs {
		for _, recv := range []Member{pr[0], pr[1]} {
			d := digest32(byte(40 + pr[0] + pr[1]))
			sig, ea, eb := tSign(ctx, ks, pr[0], pr[1], recv, d)
			if ea != nil || eb != nil {
				tLayoutFail(t, "fixture pair %v cannot sign: %v / %v", pr, ea, eb)
			}
			verifyECDSA(t, ks[0].PublicKey(), d, sig)
		}
	}
	// refresh works on the fixture and its output passes the self-test
	nk := tRefresh(t, ks)
	for i, e := range tSelfTest(ctx, nk, []byte("golden")) {
		if e != nil {
			tLayoutFail(t, "self-test after refreshing the fixture, member %d: %v", i, e)
		}
	}
}
