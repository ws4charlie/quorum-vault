package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/mpc-party/api/admin"
	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

func (cl *cluster3) registryOf(t *testing.T, role string) *pb.RecoveryKeyStatus {
	t.Helper()
	h, err := cl.client[role].Health(ctx(t, 5*time.Second), &pb.HealthRequest{})
	must(t, err)
	if h.RecoveryKey == nil {
		t.Fatalf("party %s reports no recovery-key registry", role)
	}
	return h.RecoveryKey
}

// registryChange sends the registry change that makes `current` the key backups are made under and retires `retire`, signed by two admins.
func (cl *cluster3) registryChange(t *testing.T, current string, retire ...string) []*pb.RecordMember {
	t.Helper()
	reg := cl.registryOf(t, "A")
	var prev [32]byte
	copy(prev[:], reg.Hash)
	body := admin.RecoveryKeyBody(reg.Version+1, current, retire, prev)
	now := time.Now()
	a, err := admin.Authorize(admin.OpRecoveryKey, body, "", now, now.Add(10*time.Minute), cl.env.AdminKeys[:2]...)
	must(t, err)
	body.Admin = a
	resp, err := cl.client["A"].RecoveryKey(ctx(t, 30*time.Second), body)
	must(t, err)
	return resp.Members
}

func fingerprintOf(t *testing.T, publicFile string) string {
	t.Helper()
	raw, err := os.ReadFile(publicFile)
	must(t, err)
	f, err := admin.RecoveryFingerprint(raw)
	must(t, err)
	return f
}

// exportAll makes every party's backup of keyset id under the recovery public key; it returns the files by role.
func (cl *cluster3) exportAll(t *testing.T, dir, id, pub, tag string) map[string]string {
	t.Helper()
	files := map[string]string{}
	for _, r := range []string{"A", "B", "C"} {
		f := filepath.Join(dir, fmt.Sprintf("%s-%s-%s.bk", id, tag, r))
		out := mustCLI(t, "export", "-config", cl.paths[r], "-keyset", id, "-recovery-public", pub, "-out", f)
		if !strings.Contains(out, "VERIFIED") {
			t.Fatalf("export on %s:\n%s", r, out)
		}
		files[r] = f
	}
	return files
}

func (cl *cluster3) wantBackups(t *testing.T, id string, gen uint64, fpr string, stale, retired bool) {
	t.Helper()
	for role, h := range cl.health(t) {
		s := statusOf(h, id)
		if s == nil || s.Generation != gen || s.BackupStale != stale || s.BackupKeyRetired != retired || (!stale && !retired && (s.BackupGeneration != gen || s.BackupRecoveryKey != fpr)) {
			t.Fatalf("party %s keyset %s: %+v (want generation %d, stale=%v, retired=%v, backup under %s)", role, id, s, gen, stale, retired, fpr)
		}
	}
}

// Replace the recovery key while the keyset is signing. The registry change retires the old key on every party (no backup is made under it any
// more, Health says which backups are under a retired key), the keyset is refreshed (every old backup is now of a dead generation), new backups are
// made under the new key. Then: a restore from a new backup works; a restore from an old one is refused when the registry is given, and does not give a
// working share when it is not; every pair signs.
func TestRecoveryKeyReplacementWithSigningInFlight(t *testing.T) {
	cl := newCluster3(t, pkcs11Tweak(t))
	pub := cl.dkg(t, "k1")
	dir := t.TempDir()
	oldPriv, oldPub := filepath.Join(dir, "old.private"), filepath.Join(dir, "old.public")
	newPriv, newPub := filepath.Join(dir, "new.private"), filepath.Join(dir, "new.public")
	mustCLI(t, "gen-recovery-key", "-private", oldPriv, "-public", oldPub)
	mustCLI(t, "gen-recovery-key", "-private", newPriv, "-public", newPub)
	oldFpr, newFpr := fingerprintOf(t, oldPub), fingerprintOf(t, newPub)

	// before anything is registered, backups are as they always were; register the key in use, then back up under it
	for _, r := range []string{"A", "B", "C"} {
		if reg := cl.registryOf(t, r); reg.Version != 0 || reg.Current != "" {
			t.Fatalf("party %s: %v", r, reg)
		}
	}
	for _, m := range cl.registryChange(t, oldFpr) {
		if m.Outcome != pb.RecordOutcome_RECORD_OUTCOME_APPLIED {
			t.Fatalf("registering the key in use: %v", m)
		}
	}
	oldBackups := cl.exportAll(t, dir, "k1", oldPub, "old")
	cl.wantBackups(t, "k1", 1, oldFpr, false, false)
	// a key that is not the current one is refused
	if out, err := cli(t, binProd, "export", "-config", cl.paths["A"], "-keyset", "k1", "-recovery-public", newPub, "-out", filepath.Join(dir, "x.bk")); err == nil || !strings.Contains(out, "is not the current one") {
		t.Fatalf("export under a key the registry does not name: %v\n%s", err, out)
	}

	// signing goes on from here to the end of the replacement
	type sig struct {
		seed int
		sig  []byte
	}
	var (
		mu       sync.Mutex
		sigs     []sig
		kinds    = map[pb.ErrorKind]int{}
		failures []string
		stop     = make(chan struct{})
		done     = make(chan struct{})
	)
	go func() {
		defer close(done)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			r, err := cl.signRaw("A", "k1", fmt.Sprintf("flight-%d", i), 1000+i)
			mu.Lock()
			if err == nil {
				sigs = append(sigs, sig{1000 + i, r.Signature})
			} else {
				k, _ := kindOf(err)
				kinds[k]++
				failures = append(failures, err.Error())
			}
			mu.Unlock()
			time.Sleep(40 * time.Millisecond)
		}
	}()
	signed := func() int { mu.Lock(); defer mu.Unlock(); return len(sigs) }
	waitSigned := func(n int) {
		t.Helper()
		deadline := time.Now().Add(60 * time.Second)
		for signed() < n {
			if time.Now().After(deadline) {
				t.Fatalf("signing stalled at %d signatures", signed())
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	waitSigned(5)

	// replace: the new key is current, the old one retired, on all three parties
	for _, m := range cl.registryChange(t, newFpr, oldFpr) {
		if m.Outcome != pb.RecordOutcome_RECORD_OUTCOME_APPLIED {
			t.Fatalf("the replacement: %v", m)
		}
	}
	for _, r := range []string{"A", "B", "C"} {
		if reg := cl.registryOf(t, r); reg.Version != 2 || reg.Current != newFpr || len(reg.Retired) != 1 || reg.Retired[0] != oldFpr {
			t.Fatalf("party %s: %v", r, reg)
		}
	}
	cl.wantBackups(t, "k1", 1, "", false, true) // the backups on record are under a retired key
	for _, r := range []string{"A", "B", "C"} {
		out, err := cli(t, binProd, "export", "-config", cl.paths[r], "-keyset", "k1", "-recovery-public", oldPub, "-out", filepath.Join(dir, "refused-"+r+".bk"))
		if err == nil || !strings.Contains(out, "RETIRED") {
			t.Fatalf("party %s exported under the retired key: %v\n%s", r, err, out)
		}
		if _, err := os.Stat(filepath.Join(dir, "refused-"+r+".bk")); err == nil {
			t.Fatalf("party %s left a backup file under the retired key", r)
		}
	}
	waitSigned(signed() + 3)

	// refresh while signing goes on: the old shares, and every backup of them, are dead
	var rerr error
	for try := 0; try < 20; try++ {
		if rerr = cl.refreshBy(t, "k1", cl.env.AdminKeys[0], cl.env.AdminKeys[1]); rerr == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	must(t, rerr)
	gen := cl.waitConverged3(t, "k1", true)
	if gen != 2 {
		t.Fatalf("generation %d after the refresh", gen)
	}
	waitSigned(signed() + 3)
	cl.wantBackups(t, "k1", 2, "", true, true)
	newBackups := cl.exportAll(t, dir, "k1", newPub, "new")
	cl.wantBackups(t, "k1", 2, newFpr, false, false)

	close(stop)
	<-done
	mu.Lock()
	for _, s := range sigs {
		cl.verify(t, pub, cl.msg(s.seed), s.sig)
	}
	for k, n := range kinds {
		if k != pb.ErrorKind_ERROR_KIND_UNAVAILABLE && k != pb.ErrorKind_ERROR_KIND_TRANSPORT && k != pb.ErrorKind_ERROR_KIND_UNSPECIFIED {
			t.Errorf("signing in flight failed %d time(s) with %v: %v", n, k, failures)
		}
	}
	t.Logf("signing in flight: %d signatures verified, failures by kind %v", len(sigs), kinds)
	mu.Unlock()
	cl.signEveryPair(t, "k1", pub, "after-replacement")

	// the registry the offline machine restores with
	reg := cl.registryOf(t, "A")
	regFile := filepath.Join(dir, "registry.json")
	raw, _ := json.Marshal(map[string]any{"version": reg.Version, "current": reg.Current, "retired": reg.Retired})
	must(t, os.WriteFile(regFile, raw, 0o644))

	loseC := func() {
		t.Helper()
		cl.stop("C")
		must(t, os.RemoveAll(cl.cfgs["C"].DataDir))
	}
	// a restore from a NEW backup works
	loseC()
	mustCLI(t, "restore", "-config", cl.paths["C"], "-recovery-private", newPriv, "-file", newBackups["C"], "-registry", regFile)
	cl.start(t, "C")
	cl.waitReady(t)
	cl.waitConverged3(t, "k1", true)
	cl.signEveryPair(t, "k1", pub, "restored-new")

	// a restore from an OLD backup is refused when the registry is given, and nothing is written
	loseC()
	out, err := cli(t, binProd, "restore", "-config", cl.paths["C"], "-recovery-private", oldPriv, "-file", oldBackups["C"], "-registry", regFile)
	if err == nil || !strings.Contains(out, "RETIRED") {
		t.Fatalf("restore of a backup under the retired key: %v\n%s", err, out)
	}
	if ents, _ := os.ReadDir(filepath.Join(cl.cfgs["C"].DataDir, "keysets")); len(ents) > 0 {
		t.Fatalf("a refused restore left a keyset behind: %v", ents)
	}
	// without the registry the tool cannot tell, says so, and the party still does not take the share: it is of a generation the keyset has left
	out, err = cli(t, binProd, "restore", "-config", cl.paths["C"], "-recovery-private", oldPriv, "-file", oldBackups["C"])
	if err != nil || !strings.Contains(out, "WARNING") {
		t.Fatalf("restore without a registry: %v\n%s", err, out)
	}
	cl.start(t, "C")
	cl.waitUp(t, "C")
	cl.waitLog(t, "A", "ALERT keyset cannot be reconciled", 40*time.Second)
	if hc := statusOf(cl.health(t)["C"], "k1"); hc == nil || hc.Resolved || hc.Generation != 1 {
		t.Fatalf("the share of the old backup must stay unresolved on generation 1: %+v", hc)
	}
	// A and B keep signing without it, and it signs nothing
	cl.signUntil(t, "A", "k1", "ab-while-c-is-stale", 77, pub)
	cl.stop("C")
	must(t, os.RemoveAll(cl.cfgs["C"].DataDir))
	mustCLI(t, "restore", "-config", cl.paths["C"], "-recovery-private", newPriv, "-file", newBackups["C"], "-registry", regFile)
	cl.start(t, "C")
	cl.waitReady(t)
	cl.waitConverged3(t, "k1", true)
	cl.signEveryPair(t, "k1", pub, "repaired")
}
