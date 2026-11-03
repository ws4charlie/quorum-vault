package mpc

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bnb-chain/tss-lib/v4/ecdsa/keygen"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/ws4charlie/quorum-vault/internal/domain"
	"github.com/ws4charlie/quorum-vault/internal/hsm/hsmtest"
	"github.com/ws4charlie/quorum-vault/internal/mpc/seal"
	"github.com/ws4charlie/quorum-vault/internal/signer"
)

// testDataDir is <repo>/data/mpc-test: fixed so cached pre-params survive
// across test runs (generating them takes minutes).
func testDataDir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return filepath.Join(dir, "data", "mpc-test")
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

func newTestCluster(t *testing.T) *Cluster {
	t.Helper()
	lib := hsmtest.Lib(t)
	c, err := NewCluster(DefaultConfig(testDataDir(t), hsmtest.PIN()), lib)
	if err != nil {
		if os.Getenv("QV_REQUIRE_HSM") != "1" {
			t.Skipf("mpc: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func randRef(t *testing.T, prefix string) string {
	b := make([]byte, 6)
	rand.Read(b)
	return prefix + "-" + hex.EncodeToString(b)
}

func TestConfigValidation(t *testing.T) {
	lib := hsmtest.Lib(t)
	bad := []Config{
		{Parties: DefaultConfig("x", "p").Parties},                   // no data dir
		{DataDir: "x", Parties: DefaultConfig("x", "p").Parties[:1]}, // one party
		{DataDir: "x", Parties: DefaultConfig("x", "p").Parties, Threshold: 3},
		{DataDir: "x", Parties: []PartyConfig{{ID: 1}, {ID: 1}}},
	}
	for i, cfg := range bad {
		if _, err := NewCluster(cfg, lib); err == nil {
			t.Errorf("config %d accepted", i)
		}
	}
}

// (a, policy layer) Sign refuses fewer than Threshold+1 parties before any
// share is unsealed. Fast: no ceremony.
func TestSignRefusesOneParty(t *testing.T) {
	c := newTestCluster(t)
	for _, ps := range [][]int{{1}, {2}, {3, 3}, nil} {
		_, _, err := c.Sign(context.Background(), "whatever-v1", [32]byte{1}, ps)
		if !errors.Is(err, ErrNotEnoughParties) {
			t.Errorf("Sign(%v) err = %v, want ErrNotEnoughParties", ps, err)
		}
	}
	if _, _, err := c.Sign(context.Background(), "whatever-v1", [32]byte{1}, []int{1, 4}); !errors.Is(err, ErrUnknownParty) {
		t.Errorf("unknown party: %v", err)
	}
}

func TestCeremony(t *testing.T) {
	if testing.Short() {
		t.Skip("slow: GG20 keygen + signing")
	}
	ctx := context.Background()
	c := newTestCluster(t)

	took, err := c.PreParams(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("pre-params: %v (0 = cached)", took)

	walletID := randRef(t, "test-wallet")
	key, err := NewGenerator(c).Generate(ctx, walletID, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(c.keyDir(key.MPCKeyRef)) })

	// Key shape.
	if key.Backend != domain.BackendMPC || key.Curve != domain.CurveSecp256k1 || key.MPCKeyRef != walletID+"-v1" ||
		key.WalletID != walletID || key.Version != 1 || len(key.PublicKey) != 65 {
		t.Fatalf("key = %+v", key)
	}
	if !common.IsHexAddress(key.Address) || common.HexToAddress(key.Address).Hex() != key.Address {
		t.Fatalf("address %q is not EIP-55", key.Address)
	}
	pub, err := signer.ParseUncompressed(key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if crypto.PubkeyToAddress(*pub).Hex() != key.Address {
		t.Fatal("address does not match public key")
	}

	// Sealed files: one per party, 0600, no plaintext save data.
	for _, id := range c.PartyIDs() {
		fi, err := os.Stat(filepath.Join(c.keyDir(key.MPCKeyRef), partyName(id)+".sealed"))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("party %d sealed file: %v %v", id, fi, err)
		}
	}
	assertNoPlaintextShares(t, c.cfg.DataDir)

	digest := sha256.Sum256([]byte("quorum-vault mpc test"))
	zeroLead := digest
	zeroLead[0], zeroLead[1] = 0, 0

	// Every 2-of-3 subset and the full set produce a valid signature under
	// the joint public key.
	for _, ps := range [][]int{{1, 2}, {1, 3}, {2, 3}, {1, 2, 3}} {
		t.Run(fmt.Sprint(ps), func(t *testing.T) {
			d := digest
			if len(ps) == 3 {
				d = zeroLead
			}
			sig, st, err := c.Sign(ctx, key.MPCKeyRef, d, ps)
			if err != nil {
				t.Fatal(err)
			}
			if !signer.Verify(pub, d, sig) {
				t.Fatal("signature does not verify against joint public key")
			}
			if sig.S.Cmp(new(big.Int).Rsh(crypto.S256().Params().N, 1)) > 0 {
				t.Fatal("high-S signature")
			}
			assertEthRecovers(t, pub, d, sig)
			t.Logf("parties %v: %v rounds=%d messages=%d bytes=%d", ps, st.Duration, st.Rounds, st.Messages, st.Bytes)
		})
	}

	// Signer interface.
	sgn, err := NewSigner(c, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		quorum int
		want   []string
	}{{0, []string{"party-1", "party-2"}}, {3, []string{"party-1", "party-2", "party-3"}}} {
		res, err := sgn.SignDigest(ctx, digest, signer.SignOptions{Quorum: tc.quorum})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(res.Participants, ",") != strings.Join(tc.want, ",") || !signer.Verify(sgn.PublicKey(), digest, res.Sig) {
			t.Fatalf("quorum %d: %+v", tc.quorum, res)
		}
		for _, k := range []string{"rounds", "messages", "bytes", "duration_ms"} {
			if _, ok := res.Meta[k]; !ok {
				t.Fatalf("Meta lacks %s: %v", k, res.Meta)
			}
		}
	}
	if _, err := sgn.SignDigest(ctx, digest, signer.SignOptions{Quorum: 1}); err == nil {
		t.Fatal("quorum 1 accepted")
	}

	// (a, crypto layer) Even bypassing the party-count check, tss-lib will
	// not run a signing ceremony with one share.
	share, err := c.loadShare(ctx, key.MPCKeyRef, 1)
	if err != nil {
		t.Fatal(err)
	}
	if sig, _, err := c.signCeremony(ctx, []int{1}, []keygen.LocalPartySaveData{share}, digest); err == nil {
		t.Fatalf("one party produced a signature: %+v", sig)
	} else {
		t.Logf("one-party ceremony refused: %v", err)
	}

	// Copied share at the cluster level: party-1's file placed as party-2's
	// fails to unseal (other token, other AAD), so {1,2} cannot sign.
	stolen := key.MPCKeyRef + "-stolen"
	sdir := c.keyDir(stolen)
	os.MkdirAll(sdir, 0o700)
	t.Cleanup(func() { os.RemoveAll(sdir) })
	for _, id := range []int{1, 2} {
		b, _ := os.ReadFile(filepath.Join(c.keyDir(key.MPCKeyRef), "party-1.sealed"))
		os.WriteFile(filepath.Join(sdir, partyName(id)+".sealed"), b, 0o600)
	}
	if _, _, err := c.Sign(ctx, stolen, digest, []int{1, 2}); !errors.Is(err, seal.ErrOpen) {
		t.Fatalf("signing with copied shares: %v, want seal.ErrOpen", err)
	}

	// Keygen never overwrites an existing key.
	if _, _, err := c.Keygen(ctx, key.MPCKeyRef); !errors.Is(err, ErrKeyExists) {
		t.Fatalf("re-keygen: %v", err)
	}
}

// Cancellation stops keygen and leaves no files behind.
func TestKeygenCancel(t *testing.T) {
	if testing.Short() {
		t.Skip("slow: needs pre-params")
	}
	c := newTestCluster(t)
	if _, err := c.PreParams(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	ref := randRef(t, "test-cancel")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, _, err := c.Keygen(ctx, ref)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded", err)
	}
	if _, err := os.Stat(c.keyDir(ref)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("key dir left behind: %v", err)
	}
	matches, _ := filepath.Glob(filepath.Join(c.cfg.DataDir, "keys", ".tmp-"+ref+"*"))
	if len(matches) != 0 {
		t.Fatalf("temp dirs left: %v", matches)
	}
}

// assertNoPlaintextShares greps every file under dir for save-data JSON keys.
func assertNoPlaintextShares(t *testing.T, dir string) {
	t.Helper()
	filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, needle := range []string{`"Xi"`, `"ShareID"`, `"PaillierSK"`, `"NTildei"`} {
			if bytes.Contains(b, []byte(needle)) {
				t.Errorf("%s contains plaintext %s", path, needle)
			}
		}
		return nil
	})
}

// assertEthRecovers checks the signature is Ethereum-usable: some v in {0,1}
// recovers the joint public key.
func assertEthRecovers(t *testing.T, pub *ecdsa.PublicKey, d [32]byte, sig signer.Signature) {
	t.Helper()
	raw := make([]byte, 65)
	sig.R.FillBytes(raw[:32])
	sig.S.FillBytes(raw[32:64])
	for v := byte(0); v < 2; v++ {
		raw[64] = v
		if got, err := crypto.SigToPub(d[:], raw); err == nil && got.X.Cmp(pub.X) == 0 && got.Y.Cmp(pub.Y) == 0 {
			return
		}
	}
	t.Fatal("no recovery id recovers the joint public key")
}
