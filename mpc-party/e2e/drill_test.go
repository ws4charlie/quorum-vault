package e2e

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

// TestRestoreDrill is what scripts/restore-drill.sh runs: in a local stack with SoftHSM-sealed shares, party B is destroyed
// (its data directory deleted), restored from its backup with the offline recovery key, reconciles with A, and signing works.
func TestRestoreDrill(t *testing.T) {
	cl := newCluster(t, pkcs11Tweak(t), false)
	x := ctx(t, 3*time.Minute)
	step := func(s string) { t.Logf("DRILL %s", s) }

	step("1/7 DKG, refresh, sign (stack running, shares sealed in SoftHSM tokens qv-party-1 and qv-party-2)")
	_, err := cl.client.DKG(x, &pb.DKGRequest{KeysetId: "drill", Curve: pb.Curve_CURVE_SECP256K1, Admin: cl.env.Admin("dkg", "drill")})
	must(t, err)
	cl.refresh(t, "drill")
	cl.waitConverged(t, "drill", true)
	cl.signOK(t, "drill", pb.Curve_CURVE_SECP256K1, "drill-before")

	step("2/7 offline: generate the recovery key; export and verify both parties' backups")
	dir := t.TempDir()
	priv, pub := filepath.Join(dir, "recovery.private"), filepath.Join(dir, "recovery.public")
	mustCLI(t, "gen-recovery-key", "-private", priv, "-public", pub)
	var bk [2]string
	for i, p := range []struct{ name, cfg string }{{"a", cl.cfgA}, {"b", cl.cfgB}} {
		bk[i] = filepath.Join(dir, p.name+".backup")
		mustCLI(t, "export", "-config", p.cfg, "-keyset", "drill", "-recovery-public", pub, "-out", bk[i])
		mustCLI(t, "verify", "-file", bk[i], "-recovery-public", pub)
	}

	step("3/7 DISASTER: party B is destroyed (process killed, data directory deleted)")
	cl.b.kill()
	must(t, os.RemoveAll(cl.dataDir("B")))
	if _, err := cl.client.Sign(x, &pb.SignRequest{KeyId: "x", Algorithm: pb.Algorithm_ALGORITHM_ECDSA_SECP256K1, Digest: dgst(1), JobId: "drill-down"}); err == nil {
		t.Fatal("signing worked without party B")
	}

	step("4/7 restore B from its backup with the recovery private key, sealing for B's HSM token")
	mustCLI(t, "restore", "-config", cl.cfgB, "-recovery-private", priv, "-file", bk[1])

	step("5/7 start B: it reconciles with A and proves the keyset with a self-test")
	cl.restartB(t)
	g := cl.waitConverged(t, "drill", true)

	step("6/7 sign with the restored party")
	cl.signOK(t, "drill", pb.Curve_CURVE_SECP256K1, "drill-after")

	step("7/7 done")
	t.Logf("DRILL PASS: party B destroyed and restored from backup; both parties converged on generation %d; signature verified", g)
}
