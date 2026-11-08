package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/server"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/testenv"
)

// pkcs11Tweak seals every party's shares in its own SoftHSM token (A: qv-party-1, B: qv-party-2).
func pkcs11Tweak(t *testing.T) func(role string, c *server.Config) {
	pin := testenv.HSMEnv(t)
	t.Setenv("QV_TEST_PIN", pin)
	return func(role string, c *server.Config) {
		tok := map[string]string{"A": "qv-party-1", "B": "qv-party-2", "C": "qv-party-3"}[role]
		c.Sealer = server.SealerConfig{Type: "pkcs11", Token: tok, PinEnv: "QV_TEST_PIN"}
	}
}

func cli(t *testing.T, bin string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(bin, append([]string{"backup"}, args...)...)
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func mustCLI(t *testing.T, args ...string) string {
	t.Helper()
	out, err := cli(t, binProd, args...)
	if err != nil {
		t.Fatalf("mpc-party backup %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

func (cl *cluster) refresh(t *testing.T, id string) {
	t.Helper()
	_, err := cl.client.Refresh(ctx(t, 60*time.Second), &pb.RefreshRequest{KeysetId: id, Admin: cl.env.Admin("refresh", id)})
	must(t, err)
}

func (cl *cluster) signOK(t *testing.T, id string, curve pb.Curve, job string) {
	t.Helper()
	x := ctx(t, 60*time.Second)
	hard, path := []uint32{44, 60, 0}, []uint32{0}
	var d *pb.DeriveResponse
	retry(t, 30*time.Second, func() (err error) {
		d, err = cl.client.Derive(x, &pb.DeriveRequest{KeysetId: id, HardenedPath: hard, Path: path})
		return
	})
	if curve == pb.Curve_CURVE_ED25519 {
		r, err := cl.client.Sign(x, &pb.SignRequest{KeyId: d.KeyId, Algorithm: pb.Algorithm_ALGORITHM_ED25519, Digest: []byte("msg " + job), JobId: job})
		must(t, err)
		verifyEd25519(t, d.PublicKey, []byte("msg "+job), r.Signature)
		return
	}
	dg := dgst(len(job))
	r, err := cl.client.Sign(x, &pb.SignRequest{KeyId: d.KeyId, Algorithm: pb.Algorithm_ALGORITHM_ECDSA_SECP256K1, Digest: dg, JobId: job})
	must(t, err)
	verifyECDSA(t, d.PublicKey, dg, r.Signature)
}

func (cl *cluster) dataDir(role string) string { return filepath.Join(cl.env.Dir, "data-"+role) }

// Backup and restore through the CLI, both parties, ECDSA and Ed25519, each after refreshes, with the shares sealed in
// SoftHSM tokens; then a stale backup is refused and the right one accepted.
func TestBackupRestoreCLI(t *testing.T) {
	for _, curve := range []pb.Curve{pb.Curve_CURVE_SECP256K1, pb.Curve_CURVE_ED25519} {
		curve := curve
		name := "ecdsa"
		if curve == pb.Curve_CURVE_ED25519 {
			name = "ed25519"
		}
		t.Run(name, func(t *testing.T) {
			cl := newCluster(t, pkcs11Tweak(t), false)
			x := ctx(t, 5*time.Minute)
			_, err := cl.client.DKG(x, &pb.DKGRequest{KeysetId: "k", Curve: curve, Admin: cl.env.Admin("dkg", "k")})
			must(t, err)
			cl.refresh(t, "k")
			cl.refresh(t, "k") // generation 3
			cl.waitConverged(t, "k", true)

			dir := t.TempDir()
			priv, pub := filepath.Join(dir, "recovery.private"), filepath.Join(dir, "recovery.public")
			mustCLI(t, "gen-recovery-key", "-private", priv, "-public", pub)
			if fi, _ := os.Stat(priv); fi.Mode().Perm() != 0o400 {
				t.Fatalf("recovery private key has mode %v", fi.Mode().Perm())
			}
			exportBoth := func(suffix string) (a, b string) {
				a, b = filepath.Join(dir, "a-"+suffix+".bk"), filepath.Join(dir, "b-"+suffix+".bk")
				for _, p := range []struct{ cfg, out string }{{cl.cfgA, a}, {cl.cfgB, b}} {
					out := mustCLI(t, "export", "-config", p.cfg, "-keyset", "k", "-recovery-public", pub, "-out", p.out)
					if !strings.Contains(out, "VERIFIED") {
						t.Fatalf("export did not verify:\n%s", out)
					}
					mustCLI(t, "verify", "-file", p.out, "-recovery-public", pub)
				}
				return
			}
			_, b3 := exportBoth("g3")
			ha, hb := cl.health(t)
			for _, h := range []*pb.HealthResponse{ha, hb} {
				if s := status(h, "k"); s.BackupGeneration != 3 || s.BackupStale {
					t.Fatalf("health after export: %+v", s)
				}
			}
			cl.refresh(t, "k") // generation 4: backups are stale
			cl.waitConverged(t, "k", true)
			ha, hb = cl.health(t)
			for _, h := range []*pb.HealthResponse{ha, hb} {
				if s := status(h, "k"); s.Generation != 4 || s.BackupGeneration != 3 || !s.BackupStale {
					t.Fatalf("health after refresh: %+v", s)
				}
			}
			waitLogText(t, cl.a.stderr, "backups are STALE", 5*time.Second)
			waitLogText(t, cl.b.stderr, "backups are STALE", 5*time.Second)
			a4, b4 := exportBoth("g4")

			// A is destroyed (data directory gone) and restored from its generation-4 backup
			cl.a.kill()
			must(t, os.RemoveAll(cl.dataDir("A")))
			mustCLI(t, "restore", "-config", cl.cfgA, "-recovery-private", priv, "-file", a4)
			cl.restartA(t)
			cl.waitConverged(t, "k", true)
			cl.signOK(t, "k", curve, "after-restore-A")
			// B is destroyed and restored
			cl.b.kill()
			must(t, os.RemoveAll(cl.dataDir("B")))
			mustCLI(t, "restore", "-config", cl.cfgB, "-recovery-private", priv, "-file", b4)
			cl.restartB(t)
			cl.waitConverged(t, "k", true)
			cl.signOK(t, "k", curve, "after-restore-B")

			if curve != pb.Curve_CURVE_SECP256K1 {
				return
			}
			// A stale backup against a newer peer is refused with a clear error, and the right one is accepted.
			cl.refresh(t, "k") // generation 5
			cl.waitConverged(t, "k", true)
			a5, b5 := exportBoth("g5")
			_, _ = a5, b5
			cl.b.kill()
			must(t, os.RemoveAll(cl.dataDir("B")))
			mustCLI(t, "restore", "-config", cl.cfgB, "-recovery-private", priv, "-file", b3) // generation 3 vs A at 5
			cl.restartB(t)
			waitLogText(t, cl.a.stderr, "party B is on generation 3 but party A is on 5", 30*time.Second)
			if s := status(func() *pb.HealthResponse { h, _ := cl.health(t); return h }(), "k"); s == nil || s.Resolved {
				t.Fatalf("a stale restore must stay unresolved, got %+v", s)
			}
			if _, err := cl.client.Sign(x, &pb.SignRequest{KeyId: "x", Algorithm: pb.Algorithm_ALGORITHM_ECDSA_SECP256K1, Digest: dgst(1), JobId: "stale"}); err == nil {
				t.Fatal("signed with an unresolved keyset")
			}
			cl.b.kill()
			must(t, os.RemoveAll(cl.dataDir("B")))
			mustCLI(t, "restore", "-config", cl.cfgB, "-recovery-private", priv, "-file", b5)
			cl.restartB(t)
			cl.waitConverged(t, "k", true)
			cl.signOK(t, "k", curve, "after-stale-fixed")

			// CLI refusals, each with a clear message and no crash
			bad := func(what string, wantIn string, args ...string) {
				t.Helper()
				out, err := cli(t, binProd, args...)
				if err == nil || !strings.Contains(out, wantIn) {
					t.Errorf("%s: want failure containing %q, got err=%v out=%s", what, wantIn, err, out)
				}
				if strings.Contains(out, "panic") || strings.Contains(out, "goroutine") {
					t.Errorf("%s: crashed:\n%s", what, out)
				}
			}
			otherPriv, otherPub := filepath.Join(dir, "other.private"), filepath.Join(dir, "other.public")
			mustCLI(t, "gen-recovery-key", "-private", otherPriv, "-public", otherPub)
			bad("verify with another recovery key", "recovery key", "verify", "-file", a5, "-recovery-public", otherPub)
			bad("restore with another recovery key", "not the recovery key", "restore", "-config", cl.cfgA, "-recovery-private", otherPriv, "-file", a5)
			bad("restore into a directory that already has the keyset", "already has keyset", "restore", "-config", cl.cfgA, "-recovery-private", priv, "-file", a5)
			bad("restore A's backup with B's config", "wrong slot", "restore", "-config", cl.cfgB, "-recovery-private", priv, "-file", a5)
			raw, _ := os.ReadFile(a5)
			tam := filepath.Join(dir, "tampered.bk")
			raw[len(raw)/2] ^= 1
			os.WriteFile(tam, raw, 0o600)
			bad("verify a tampered backup", "", "verify", "-file", tam, "-recovery-public", pub)
			bad("overwrite an existing key file", "refusing to overwrite", "gen-recovery-key", "-private", priv, "-public", pub)
		})
	}
}

func waitLogText(t *testing.T, b *syncBuf, want string, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if strings.Contains(b.String(), want) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("log never contained %q:\n%s", want, tail(b.String()))
}

// A production binary has no insecure sealer and refuses to start with it, with a wrong PIN, with a missing token.
func TestProductionBinaryRefusals(t *testing.T) {
	pin := testenv.HSMEnv(t)
	env := testenv.NewEnv(t)
	base := func(role string, sealer server.SealerConfig, authz string) string {
		c := env.Config(t, role, "127.0.0.1:1", testenv.FreeAddr(t), testenv.FreeAddr(t))
		c.Sealer = sealer
		c.Authorizer = server.AuthorizerConfig{Type: authz}
		if authz == "cosigner" {
			c.Authorizer.Socket = filepath.Join(env.Dir, "x.sock")
		}
		return env.WriteConfig(t, c, "cfg-"+role+"-"+sealer.Type+sealer.Token+".json")
	}
	run := func(cfg string, extraEnv ...string) (int, string) {
		cmd := exec.Command(binProd, "-config", cfg)
		cmd.Env = append(os.Environ(), extraEnv...)
		out, err := cmd.CombinedOutput()
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode(), string(out)
		}
		return 0, string(out)
	}
	// the insecure test sealer: not in this binary
	code, out := run(base("B", server.SealerConfig{Type: server.InsecureSealerType, KeyFile: env.SealKeyFile}, "deny-all"))
	if code == 0 || !strings.Contains(out, "not available in this build") {
		t.Errorf("production binary accepted the insecure sealer (exit %d): %s", code, out)
	}
	// wrong PIN
	code, out = run(base("B", server.SealerConfig{Type: "pkcs11", Token: "qv-party-2", PinEnv: "QV_BADPIN"}, "deny-all"), "QV_BADPIN=definitely-wrong-pin")
	if code == 0 || !strings.Contains(out, "login to token") || strings.Contains(out, "definitely-wrong-pin") {
		t.Errorf("wrong PIN: exit %d out=%s", code, out)
	}
	// missing token
	code, out = run(base("B", server.SealerConfig{Type: "pkcs11", Token: "no-such-token", PinEnv: "QV_GOODPIN"}, "deny-all"), "QV_GOODPIN="+pin)
	if code == 0 || !strings.Contains(out, "not found") {
		t.Errorf("missing token: exit %d out=%s", code, out)
	}
	// PIN not given at all
	code, out = run(base("B", server.SealerConfig{Type: "pkcs11", Token: "qv-party-2"}, "deny-all"))
	if code == 0 || !strings.Contains(out, "pin_env or pin_file") {
		t.Errorf("no PIN: exit %d out=%s", code, out)
	}
	// the binary does not contain the insecure sealer or the failpoints; the dev binary does
	for bin, want := range map[string]bool{binProd: false, binDev: true} {
		o, err := exec.Command("go", "tool", "nm", bin).CombinedOutput()
		if err != nil {
			t.Fatalf("go tool nm: %v", err)
		}
		has := strings.Contains(string(o), "NewInsecureStaticKeySealer")
		hasFP := strings.Contains(string(o), "QV_FAILPOINT") || strings.Contains(string(o), "server.failpoint") && strings.Contains(string(o), "os.Exit")
		_ = hasFP
		if has != want {
			t.Errorf("%s: insecure sealer symbol present=%v, want %v", filepath.Base(bin), has, want)
		}
	}
}
