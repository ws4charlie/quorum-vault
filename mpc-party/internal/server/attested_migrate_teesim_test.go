//go:build teesim

package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/server"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/testenv"
)

// dirState returns every file of a data directory (but the lock and the staging directory) with its content.
func dirState(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	filepath.WalkDir(dir, func(p string, de os.DirEntry, err error) error {
		rel, _ := filepath.Rel(dir, p)
		if err != nil || de.IsDir() || de.Name() == ".lock" || strings.HasPrefix(rel, ".migrate-v2") {
			return nil
		}
		b, _ := os.ReadFile(p)
		out[rel] = string(b)
		return nil
	})
	return out
}

func sameState(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// A party that ran with the PKCS#11 sealer moves to the attested sealer offline. A crash at any stage leaves the old files untouched until the
// new set is verified, and the command can be run again.
func TestMigrationFromPKCS11IsCrashSafeAndOneWay(t *testing.T) {
	env := testenv.NewEnv(t)
	r := newAttRigOn(t, env)
	p := startPair(t, pairOpts{env: env, sealerA: pkcs11Sealer(t, "qv-party-1"), sealerB: pkcs11Sealer(t, "qv-party-2")})
	p.dkg(t, "ks", pb.Curve_CURVE_SECP256K1)
	d := p.derive(t, "ks", []uint32{44, 60, 0}, []uint32{0})
	if _, err := p.Client.Sign(ctx30(t), &pb.SignRequest{KeyId: d.KeyId, Algorithm: pb.Algorithm_ALGORITHM_ECDSA_SECP256K1, Digest: digest(1), JobId: "job-before"}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10_000_000_000)
	defer cancel()
	p.A.Shutdown(ctx)
	p.B.Shutdown(ctx)

	c := newAttClusterOn(t, r)
	migrate := func(cfg *server.Config, token string, stage func(string) error) (server.MigrateReport, error) {
		from := *cfg
		from.Sealer = server.SealerConfig{Type: "pkcs11", Token: token, PinEnv: "QV_TEST_PIN"}
		to := *cfg
		to.Sealer = r.sealerConfig(cfg.Role, "")
		return server.MigrateSeal(context.Background(), &from, &to, server.MigrateOptions{Stage: stage})
	}
	crashAt := func(name string) func(string) error {
		return func(s string) error {
			if s == name {
				return errors.New("simulated crash at " + s)
			}
			return nil
		}
	}

	before := dirState(t, c.cfgA.DataDir)
	// the attested sealer does not read the old data (no automatic migration)
	if _, _, err := r.store("A", c.cfgA.DataDir); err == nil {
		t.Fatal("the attested sealer started on PKCS#11 data")
	}
	if !sameState(before, dirState(t, c.cfgA.DataDir)) {
		t.Fatal("a refused start changed the data directory")
	}

	// a crash before the new set is verified: the old files are untouched, the staging directory is only garbage
	if _, err := migrate(c.cfgA, "qv-party-1", crashAt("staged")); err == nil {
		t.Fatal("no crash")
	}
	if !sameState(before, dirState(t, c.cfgA.DataDir)) {
		t.Fatal("old files changed before the new set was verified")
	}
	// a crash after the verification, before any move
	if _, err := migrate(c.cfgA, "qv-party-1", crashAt("verified")); err == nil {
		t.Fatal("no crash")
	}
	if !sameState(before, dirState(t, c.cfgA.DataDir)) {
		t.Fatal("old files changed before the commit marker")
	}
	// a crash after the marker, in the middle of the moves: a mixture on disk; running the command again finishes
	if _, err := migrate(c.cfgA, "qv-party-1", crashAt("moved:2")); err == nil {
		t.Fatal("no crash")
	}
	if _, _, err := r.store("A", c.cfgA.DataDir); err == nil {
		t.Fatal("a half-moved directory started")
	}
	rep, err := migrate(c.cfgA, "qv-party-1", nil)
	if err != nil || !rep.Resumed {
		t.Fatalf("resume: %+v %v", rep, err)
	}
	if _, err := os.Stat(filepath.Join(c.cfgA.DataDir, ".migrate-v2")); err == nil {
		t.Fatal("the staging directory is still there")
	}
	// a clean run for B
	rep, err = migrate(c.cfgB, "qv-party-2", nil)
	if err != nil || rep.Generations != 1 || rep.Keysets != 1 {
		t.Fatalf("B: %+v %v", rep, err)
	}
	// one-way: the PKCS#11 sealer cannot read the new files
	if _, err := os.ReadFile(filepath.Join(c.cfgA.DataDir, "keysets", "ks", "g1.json")); err != nil {
		t.Fatal(err)
	}
	st, err := server.NewFileStore(c.cfgA.DataDir, "A", pkcs11Sealer(t, "qv-party-1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.State(context.Background(), "ks"); err == nil {
		t.Fatal("the old sealer read the migrated state")
	}
	// the key shares are not in the clear anywhere
	for name, content := range dirState(t, c.cfgA.DataDir) {
		if strings.HasPrefix(name, "keysets") && strings.HasSuffix(name, "g1.json") {
			var kf struct{ Sealed []byte }
			var env struct {
				V   int
				KID string
			}
			if json.Unmarshal([]byte(content), &kf) != nil || json.Unmarshal(kf.Sealed, &env) != nil || env.V != 2 || env.KID != "ks/1" {
				t.Fatalf("%s does not hold an envelope v2 for ks/1", name)
			}
		}
	}

	// the parties start on the migrated directories and sign with the same key
	c.up()
	defer c.down()
	c.waitReady(30_000_000_000)
	c.waitResolved("ks", 1)
	if err := c.sign(d.KeyId, "job-after", digest(2), d.PublicKey); err != nil {
		t.Fatal(err)
	}
	resp, err := c.p.Client.Sign(ctx30(t), &pb.SignRequest{KeyId: d.KeyId, Algorithm: pb.Algorithm_ALGORITHM_ECDSA_SECP256K1, Digest: digest(1), JobId: "job-before"})
	if err != nil || !resp.Replayed {
		t.Fatalf("the stored signature of a job from before the migration: %v", err)
	}
	if bytes.Contains([]byte(c.logA.String()), []byte("wrapped_dek")) {
		t.Fatal("log carries key material")
	}
}
