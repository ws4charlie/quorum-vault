package cbmpc

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

// Golden fixtures for the Ed25519 threshold calls (P8-1), the twin of threshold_golden_test.go. They pin what the shim
// copies from cb-mpc internals: the access-structure key blob layout of src/cbmpc/api/eddsa_mp.cpp (key_blob_v1_t,
// version 2), the fixed party names, and that a blob made by dkg_ac / refresh_ac keeps working in sign_ac, refresh_ac and
// detach/attach_private_scalar. testdata/golden_teddsa.json holds TEST-ONLY shares of a throwaway key. Regenerate,
// deliberately, after an upgrade review: go test ./internal/cbmpc -run TestGoldenEdThresholdUpdate -update-golden

const goldenTEdFile = "testdata/golden_teddsa.json"

func TestGoldenEdThresholdUpdate(t *testing.T) {
	if !*updateGolden {
		t.Skip("run with -update-golden to regenerate")
	}
	ks := tDKGAlg(t, Ed25519)
	g := goldenT{
		Warning: "TEST-ONLY threshold shares from a throwaway key for pinning cb-mpc's eddsa_mp blob layout. Never use for funds.",
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
	must(t, os.WriteFile(goldenTEdFile, append(out, '\n'), 0o644))
	t.Logf("wrote %s", goldenTEdFile)
}

func edLayoutFail(t testing.TB, what string, args ...any) {
	t.Helper()
	t.Fatalf("GOLDEN MISMATCH [threshold ed25519]: "+what+"\n"+
		"cb-mpc's eddsa_mp blob layout or protocol changed (or the shim regressed). Compare upstream src/cbmpc/api/eddsa_mp.cpp "+
		"(key_blob_v1_t, ac_key_blob_version_v1) and src/cbmpc/protocol/schnorr_mp.cpp with mpc-party/internal/cbmpc/shim.cpp "+
		"(tkey_blob_t, t_parse), follow README 'Upgrade procedure', and only then regenerate with -update-golden.", args...)
}

func TestGoldenEdThreshold(t *testing.T) {
	raw0, err := os.ReadFile(goldenTEdFile)
	must(t, err)
	var g goldenT
	must(t, json.Unmarshal(raw0, &g))
	if g.Pin != PinnedCommit {
		t.Fatalf("Ed25519 threshold golden fixtures were generated for cb-mpc %s but the pin is %s: finish the upgrade procedure and regenerate", g.Pin, PinnedCommit)
	}
	var ks [NumMembers]*TKey
	var raw [3][]byte
	for i := range ks {
		raw[i], err = base64.StdEncoding.DecodeString(g.Blobs[i])
		must(t, err)
		if h := sha256.Sum256(raw[i]); hx(h[:]) != g.SHA256[i] {
			t.Fatal("fixture file corrupted (sha256)")
		}
		ks[i], err = LoadTKeyAlg(Ed25519, Member(i), append([]byte(nil), raw[i]...))
		if err != nil {
			edLayoutFail(t, "fixture share %d no longer parses: %v", i, err)
		}
	}
	t.Cleanup(func() {
		for _, k := range ks {
			k.Wipe()
		}
	})
	ctx := ctx5(t)
	for i, k := range ks {
		if hx(k.PublicKey()) != g.Pub {
			edLayoutFail(t, "group public key of share %d changed", i)
		}
		if hx(k.SharePoint()) != g.Qi[i] {
			edLayoutFail(t, "share point of member %d changed", i)
		}
		if !bytes.Contains(raw[i], []byte(g.Names[i])) {
			edLayoutFail(t, "party name %q is not in the blob of member %d", g.Names[i], i)
		}
		if raw[i][0] != byte(g.Version) && raw[i][3] != byte(g.Version) {
			edLayoutFail(t, "blob version byte is not %d", g.Version)
		}
		sp, err := k.Split()
		must(t, err)
		if hx(secretBytes(t, sp.X)) != g.X[i] {
			edLayoutFail(t, "detach_private_scalar output of member %d changed", i)
		}
		if h := sha256.Sum256(sp.Public); hx(h[:]) != g.Public[i] {
			edLayoutFail(t, "public blob of member %d changed", i)
		}
		rk, err := TJoin(Member(i), sp.Public, sp.X, sp.PubX)
		if err != nil || !bytes.Equal(secretBytes(t, rk.Secret), raw[i]) {
			edLayoutFail(t, "attach_private_scalar does not rebuild the fixture of member %d (%v)", i, err)
		}
		rk.Wipe()
		sp.Wipe()
	}
	for _, pr := range allPairs {
		for _, recv := range []Member{pr[0], pr[1]} {
			m := edMsg(48, byte(40+pr[0]+pr[1]))
			sig, ea, eb := tSign(ctx, ks, pr[0], pr[1], recv, m)
			if ea != nil || eb != nil {
				edLayoutFail(t, "fixture pair %v cannot sign: %v / %v", pr, ea, eb)
			}
			verifyEd25519(t, ks[0].PublicKey(), m, sig)
		}
	}
	nk := tRefresh(t, ks)
	for i, e := range tSelfTest(ctx, nk, []byte("golden")) {
		if e != nil {
			edLayoutFail(t, "self-test after refreshing the fixture, member %d: %v", i, e)
		}
	}
}
