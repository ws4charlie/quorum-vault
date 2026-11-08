package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

// The crash matrix for three members: kill a member (os.Exit(86) at a failpoint, only in -tags devauth builds) at every step
// of the three-way two-phase commit of Refresh and DKG, restart it, and check that the three converge on one generation that
// works. Same steps as the two-party matrix, once for each of B and C.
var crashSteps3 = []crashStep{
	{"after_selftest", "A", "candidate only in memory (A)"},
	{"after_selftest", "B", "candidate only in memory (B)"},
	{"after_selftest", "C", "candidate only in memory (C)"},
	{"b_after_candidate_stored", "B", "B stored the candidate, A knows nothing"},
	{"c_after_candidate_stored", "C", "C stored the candidate, A knows nothing"},
	{"a_after_candidate_stored", "A", "all stored the candidate, no decision"},
	{"a_after_decision", "A", "A decided to commit (durable), B and C not told"},
	{"b_after_commit_received", "B", "B got the commit message, did not switch"},
	{"c_after_commit_received", "C", "C got the commit message, did not switch"},
	{"b_after_promote", "B", "B switched, A did not know"},
	{"c_after_promote", "C", "C switched, A did not know"},
	{"a_after_switched_recv", "A", "B and C switched and told A, A did not switch"},
	{"a_after_promote", "A", "all switched, nobody confirmed or deleted the old generation"},
	{"b_after_confirm_recv", "B", "A confirmed, B did not delete the old generation"},
	{"c_after_confirm_recv", "C", "A confirmed, C did not delete the old generation"},
	{"a_after_delete_old", "A", "all done on A, the response to the caller is lost"},
}

func (cl *cluster3) armed(t *testing.T, role, failpoint string) {
	t.Helper()
	cl.restart(t, role, "QV_FAILPOINT="+failpoint)
	cl.waitReady(t)
}

func (cl *cluster3) diedAt(t *testing.T, role string) {
	t.Helper()
	select {
	case <-cl.procs[role].done:
	case <-time.After(20 * time.Second):
		t.Fatalf("party %s did not die at the failpoint", role)
	}
}

func TestCrashMatrixThresholdRefresh(t *testing.T) {
	for _, st := range crashSteps3 {
		st := st
		t.Run(fmt.Sprintf("%s@%s", st.name, st.role), func(t *testing.T) {
			cl := newCluster3(t, nil)
			pub := cl.dkg(t, "k")
			g0 := cl.waitConverged3(t, "k", true)
			cl.armed(t, st.role, st.name)
			cl.waitConverged3(t, "k", true)

			_, rerr := cl.client["A"].Refresh(ctx(t, 3*time.Minute), &pb.RefreshRequest{KeysetId: "k", Admin: cl.env.Admin("refresh", "k")})
			cl.diedAt(t, st.role)
			t.Logf("died at %s (%s); Refresh returned: %v", st.name, st.what, rerr)
			cl.restart(t, st.role)
			cl.waitReady(t)
			g1 := cl.waitConverged3(t, "k", true)
			if g1 != g0 && g1 != g0+1 {
				t.Fatalf("generation %d is neither %d nor %d", g1, g0, g0+1)
			}
			cl.signUntil(t, "A", "k", "after-crash", 7, pub)
			for role, h := range cl.health(t) {
				if ks := statusOf(h, "k"); ks.Frozen || !bytes_equal(ks.PublicKey, pub) {
					t.Fatalf("party %s after the crash: %v", role, ks)
				}
			}
			t.Logf("RESULT %-30s generation %d -> %d (%s), sign OK, public key unchanged", fmt.Sprintf("%s@%s", st.name, st.role), g0, g1,
				map[bool]string{true: "committed", false: "aborted"}[g1 > g0])
		})
	}
}

func bytes_equal(a, b []byte) bool { return string(a) == string(b) }

func TestCrashMatrixThresholdDKG(t *testing.T) {
	for _, st := range crashSteps3 {
		st := st
		t.Run(fmt.Sprintf("%s@%s", st.name, st.role), func(t *testing.T) {
			cl := newCluster3(t, nil)
			cl.armed(t, st.role, st.name)
			_, derr := cl.client["A"].DKG(ctx(t, 3*time.Minute), &pb.DKGRequest{KeysetId: "k", Scheme: pb.Scheme_SCHEME_ECDSA_2OF3, Admin: cl.env.Admin("dkg", "k")})
			cl.diedAt(t, st.role)
			t.Logf("died at %s (%s); DKG returned: %v", st.name, st.what, derr)
			cl.restart(t, st.role)
			cl.waitReady(t)
			// converge: either the keyset exists on all three and works (committed), or party A has none (aborted; B and C may
			// still hold an orphaned candidate, which a new DKG replaces).
			deadline := time.Now().Add(60 * time.Second)
			exists := false
			for time.Now().Before(deadline) {
				h := cl.health(t)
				if len(h) < 3 {
					time.Sleep(200 * time.Millisecond)
					continue
				}
				ok := true
				for _, hr := range h {
					if ks := statusOf(hr, "k"); ks == nil || !ks.Resolved || ks.Generation != 1 {
						ok = false
					}
				}
				if ok {
					exists = true
					break
				}
				if statusOf(h["A"], "k") == nil {
					break
				}
				time.Sleep(200 * time.Millisecond)
			}
			if !exists {
				cl.dkg(t, "k") // nothing half-created on A: the id is free and a new DKG works
			}
			pub := statusOf(cl.health(t)["A"], "k").PublicKey
			cl.waitConverged3(t, "k", true)
			cl.signUntil(t, "A", "k", "after-dkg-crash", 8, pub)
			t.Logf("RESULT %-30s DKG %s, sign OK", fmt.Sprintf("%s@%s", st.name, st.role), map[bool]string{true: "committed (keyset usable)", false: "aborted (retried)"}[exists])
		})
	}
}

// ---- backup and restore of one lost member ----

func TestThresholdBackupRestoreLostMember(t *testing.T) {
	cl := newCluster3(t, pkcs11Tweak(t))
	pub := cl.dkg(t, "k")
	cl.refresh(t, "k")
	cl.waitConverged3(t, "k", true) // generation 2

	dir := t.TempDir()
	priv, rpub := filepath.Join(dir, "recovery.private"), filepath.Join(dir, "recovery.public")
	mustCLI(t, "gen-recovery-key", "-private", priv, "-public", rpub)
	export := func(suffix string) map[string]string {
		files := map[string]string{}
		for _, role := range []string{"A", "B", "C"} {
			f := filepath.Join(dir, strings.ToLower(role)+"-"+suffix+".bk")
			out := mustCLI(t, "export", "-config", cl.paths[role], "-keyset", "k", "-recovery-public", rpub, "-out", f)
			if !strings.Contains(out, "VERIFIED") {
				t.Fatalf("export did not verify:\n%s", out)
			}
			mustCLI(t, "verify", "-file", f, "-recovery-public", rpub)
			files[role] = f
		}
		return files
	}
	g2 := export("g2")
	for role, h := range cl.health(t) {
		if s := statusOf(h, "k"); s.BackupGeneration != 2 || s.BackupStale {
			t.Fatalf("party %s health after export: %+v", role, s)
		}
	}
	cl.refresh(t, "k") // generation 3: the backups are stale
	cl.waitConverged3(t, "k", true)
	for role, h := range cl.health(t) {
		if s := statusOf(h, "k"); s.Generation != 3 || s.BackupGeneration != 2 || !s.BackupStale {
			t.Fatalf("party %s health after the refresh: %+v", role, s)
		}
	}
	for _, role := range []string{"A", "B", "C"} {
		waitLogText(t, cl.procs[role].stderr, "backups are STALE", 5*time.Second)
	}
	g3 := export("g3")

	// C is lost: process gone, data directory gone. A stale (generation 2) backup is refused by the others, the
	// current one is accepted; then a refresh moves all three on and every pair signs.
	cl.stop("C")
	must(t, os.RemoveAll(cl.cfgs["C"].DataDir))
	mustCLI(t, "restore", "-config", cl.paths["C"], "-recovery-private", priv, "-file", g2["C"])
	cl.start(t, "C")
	cl.waitReady(t)
	waitLogText(t, cl.procs["A"].stderr, "party C is on generation 2 but another party is on 3", 30*time.Second)
	// the stale member is out (unresolved, never signs); the other two keep signing; with B down A has nobody to use
	if s := statusOf(cl.health(t)["C"], "k"); s == nil || s.Resolved {
		t.Fatalf("a stale restore must leave the restored member unresolved, got %+v", s)
	}
	cl.signUntil(t, "A", "k", "stale-ab", 1, pub)
	cl.stop("B")
	if _, err := cl.signRaw("A", "k", "stale-needs-c", 4); err == nil {
		t.Fatal("signed with a stale member")
	}
	cl.start(t, "B")
	cl.waitUp(t, "B")
	cl.stop("C")
	must(t, os.RemoveAll(cl.cfgs["C"].DataDir))
	mustCLI(t, "restore", "-config", cl.paths["C"], "-recovery-private", priv, "-file", g3["C"])
	cl.start(t, "C")
	cl.waitReady(t)
	cl.waitConverged3(t, "k", true)
	cl.signUntil(t, "A", "k", "after-restore", 2, pub)
	cl.refresh(t, "k") // the documented step after a restore
	if g := cl.waitConverged3(t, "k", true); g != 4 {
		t.Fatalf("generation %d", g)
	}
	cl.signEveryPair(t, "k", pub, "restored-c")

	// B is lost as well (one at a time): restore from a fresh backup and sign with every pair again
	g4 := export("g4")
	cl.stop("B")
	must(t, os.RemoveAll(cl.cfgs["B"].DataDir))
	mustCLI(t, "restore", "-config", cl.paths["B"], "-recovery-private", priv, "-file", g4["B"])
	cl.start(t, "B")
	cl.waitReady(t)
	cl.waitConverged3(t, "k", true)
	cl.refresh(t, "k")
	cl.waitConverged3(t, "k", true)
	cl.signEveryPair(t, "k", pub, "restored-b")

	// CLI refusals: a share restored into the wrong slot, a tampered file, another recovery key
	otherPriv, otherPub := filepath.Join(dir, "other.private"), filepath.Join(dir, "other.public")
	mustCLI(t, "gen-recovery-key", "-private", otherPriv, "-public", otherPub)
	bad := func(what, wantIn string, args ...string) {
		t.Helper()
		out, err := cli(t, binProd, args...)
		if err == nil || !strings.Contains(out, wantIn) {
			t.Errorf("%s: want failure containing %q, got err=%v out=%s", what, wantIn, err, out)
		}
		if strings.Contains(out, "panic") || strings.Contains(out, "goroutine") {
			t.Errorf("%s: crashed:\n%s", what, out)
		}
	}
	bad("C's share with B's config", "wrong slot", "restore", "-config", cl.paths["B"], "-recovery-private", priv, "-file", g4["C"])
	bad("verify with another recovery key", "recovery key", "verify", "-file", g4["C"], "-recovery-public", otherPub)
	bad("restore with another recovery key", "not the recovery key", "restore", "-config", cl.paths["C"], "-recovery-private", otherPriv, "-file", g4["C"])
	raw, _ := os.ReadFile(g4["C"])
	tam := filepath.Join(dir, "tampered.bk")
	raw[len(raw)/2] ^= 1
	os.WriteFile(tam, raw, 0o600)
	bad("verify a tampered backup", "", "verify", "-file", tam, "-recovery-public", rpub)
}
