package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/mpc-party/internal/server"
)

func resealCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(binProd, append([]string{"reseal"}, args...)...)
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// The wrap key of every party is replaced inside its real (SoftHSM) token: stop, reseal, switch the label, restart, destroy the old key, restart
// again. The keysets never change, and every pair signs at each step. The keys have their own labels (the shared test tokens' default key is not touched).
func TestResealWrapKeyOnRealToken(t *testing.T) {
	suffix := fmt.Sprint(time.Now().UnixNano() % 1e9)
	oldL, newL := "k7a-old-"+suffix, "k7a-new-"+suffix
	base := pkcs11Tweak(t)
	cl := newCluster3(t, func(role string, c *server.Config) { base(role, c); c.Sealer.WrapKeyLabel = oldL })
	t.Cleanup(func() {
		// Leave the shared test tokens as they were: a sealer on a fixed third label removes both keys (a sealer cannot remove the key it seals under;
		// the third key is one small AES key per token, the same for every run).
		for _, role := range []string{"A", "B", "C"} {
			c := cl.cfgs[role].Sealer
			c.WrapKeyLabel = "k7a-cleanup"
			if s, err := server.NewPKCS11Sealer(c); err == nil {
				s.DestroyKey(newL)
				s.DestroyKey(oldL)
			}
		}
	})
	pub := cl.dkg(t, "k1")
	cl.refresh(t, "k1")
	cl.waitConverged3(t, "k1", true)
	cl.signEveryPair(t, "k1", pub, "before")

	for _, role := range []string{"A", "B", "C"} {
		cl.stop(role)
		out, err := resealCLI(t, "-config", cl.paths[role], "-status")
		if err != nil || !strings.Contains(out, oldL+": 2 generation file(s)") && !strings.Contains(out, oldL+": 1 generation file(s)") {
			t.Fatalf("status before on %s: %v\n%s", role, err, out)
		}
		out, err = resealCLI(t, "-config", cl.paths[role], "-new-label", newL)
		if err != nil || !strings.Contains(out, "resealed") {
			t.Fatalf("reseal on %s: %v\n%s", role, err, out)
		}
		// the key cannot go while the configuration still seals under it, or before the restart is confirmed
		if out, err := resealCLI(t, "-config", cl.paths[role], "-destroy-label", oldL, "-confirm-restarted"); err == nil || !strings.Contains(out, "seals under") {
			t.Fatalf("destroy under the old configuration on %s: %v\n%s", role, err, out)
		}
		cl.cfgs[role].Sealer.WrapKeyLabel = newL
		cl.env.WriteConfig(t, cl.cfgs[role], strings.ToLower(role)+".json")
		if out, err := resealCLI(t, "-config", cl.paths[role], "-destroy-label", oldL); err == nil || !strings.Contains(out, "-confirm-restarted is required") {
			t.Fatalf("destroy without the confirmation on %s: %v\n%s", role, err, out)
		}
		cl.start(t, role)
		cl.waitReady(t)
		cl.waitConverged3(t, "k1", true)
	}
	cl.signEveryPair(t, "k1", pub, "resealed")

	// the old keys go, one party at a time, and the parties keep signing
	for _, role := range []string{"A", "B", "C"} {
		out, err := resealCLI(t, "-config", cl.paths[role], "-destroy-label", oldL, "-confirm-restarted")
		if err != nil || !strings.Contains(out, "removed") {
			t.Fatalf("destroy on %s: %v\n%s", role, err, out)
		}
		if out, err := resealCLI(t, "-config", cl.paths[role], "-destroy-label", oldL, "-confirm-restarted"); err == nil || !strings.Contains(out, "no wrap key") {
			t.Fatalf("destroying twice on %s: %v\n%s", role, err, out)
		}
	}
	for _, role := range []string{"A", "B", "C"} {
		cl.restart(t, role)
		cl.waitReady(t)
	}
	cl.waitConverged3(t, "k1", true)
	cl.signEveryPair(t, "k1", pub, "after-destroy")
	// a refresh seals the new generation under the new key and nothing is left under another
	cl.refresh(t, "k1")
	cl.waitConverged3(t, "k1", true)
	for _, role := range []string{"A", "B", "C"} {
		by, err := server.WrapKeysInUse(cl.cfgs[role].DataDir)
		if err != nil || len(by) != 1 || by[newL] == 0 {
			t.Fatalf("party %s: shares are under %v (%v), want only %s", role, by, err, newL)
		}
	}
	cl.signEveryPair(t, "k1", pub, "refreshed")
}
