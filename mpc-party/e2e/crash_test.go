package e2e

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/testenv"
)

// The crash matrix: kill a party (os.Exit(86) at a failpoint compiled only into -tags devauth builds, no cleanup, like a
// crash) at every step of the two-phase commit of Refresh and DKG, restart it, and check that the parties converge on one
// generation that works.

type crashStep struct {
	name string // failpoint
	role string // the party that has the failpoint site and dies there
	what string // what has happened when it dies
}

var crashSteps = []crashStep{
	{"after_selftest", "A", "candidate exists only in memory (A)"},
	{"after_selftest", "B", "candidate exists only in memory (B)"},
	{"b_after_candidate_stored", "B", "B stored the candidate, A knows nothing"},
	{"a_after_candidate_stored", "A", "both stored the candidate, no decision"},
	{"a_after_decision", "A", "A decided to commit (durable), B not told"},
	{"b_after_commit_received", "B", "B got the commit message, did not switch"},
	{"b_after_promote", "B", "B switched, A did not know"},
	{"a_after_switched_recv", "A", "B switched and told A, A did not switch"},
	{"a_after_promote", "A", "both switched, nobody confirmed or deleted the old generation"},
	{"b_after_confirm_recv", "B", "both switched, A confirmed, B did not delete the old generation"},
	{"a_after_delete_old", "A", "all done on A, the response to the caller is lost"},
}

func (cl *cluster) health(t *testing.T) (a, b *pb.HealthResponse) {
	t.Helper()
	bc, _ := testenv.Dial(t, cl.callerB, cl.env.CertCaller, cl.env.CertB.Pin)
	ha, err := cl.client.Health(ctx(t, 5*time.Second), &pb.HealthRequest{})
	if err != nil {
		return nil, nil
	}
	hb, err := bc.Health(ctx(t, 5*time.Second), &pb.HealthRequest{})
	if err != nil {
		return ha, nil
	}
	return ha, hb
}

func status(h *pb.HealthResponse, id string) *pb.KeysetStatus {
	if h == nil {
		return nil
	}
	for _, k := range h.Keysets {
		if k.KeysetId == id {
			return k
		}
	}
	return nil
}

// waitConverged waits until both parties report the keyset resolved on the same generation, or (want==0) not at all.
func (cl *cluster) waitConverged(t *testing.T, id string, mustExist bool) uint64 {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	var ha, hb *pb.HealthResponse
	for time.Now().Before(deadline) {
		ha, hb = cl.health(t)
		sa, sb := status(ha, id), status(hb, id)
		switch {
		case sa != nil && sb != nil && sa.Resolved && sb.Resolved && sa.Generation == sb.Generation && sa.Generation > 0:
			return sa.Generation
		case !mustExist && ha != nil && hb != nil && sa == nil && sb == nil:
			return 0
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("parties did not converge on keyset %s\nA health: %v\nB health: %v\nA log: %s\nB log: %s", id, ha, hb, tail(cl.a.stderr.String()), tail(cl.b.stderr.String()))
	return 0
}

func tail(s string) string {
	if len(s) > 1800 {
		return "..." + s[len(s)-1800:]
	}
	return s
}

func (cl *cluster) deadParty(t *testing.T, role string) *proc {
	p := cl.a
	if role == "B" {
		p = cl.b
	}
	select {
	case <-p.done:
	case <-time.After(15 * time.Second):
		t.Fatalf("party %s did not die at the failpoint", role)
	}
	return p
}

func TestCrashMatrixRefresh(t *testing.T) {
	for _, st := range crashSteps {
		st := st
		t.Run(fmt.Sprintf("%s@%s", st.name, st.role), func(t *testing.T) {
			cl := newCluster(t, nil, false)
			x := ctx(t, 3*time.Minute)
			root, err := cl.client.DKG(x, &pb.DKGRequest{KeysetId: "k", Curve: pb.Curve_CURVE_SECP256K1, Admin: cl.env.Admin("dkg", "k")})
			must(t, err)
			hard, path := []uint32{44, 60, 0}, []uint32{0}
			d, err := cl.client.Derive(x, &pb.DeriveRequest{KeysetId: "k", HardenedPath: hard, Path: path})
			must(t, err)
			g0 := cl.waitConverged(t, "k", true)

			// restart the party that will die, with the failpoint armed, and wait until it is reconciled again
			env := "QV_FAILPOINT=" + st.name
			if st.role == "A" {
				cl.a.kill()
				cl.restartA(t, env)
			} else {
				cl.b.kill()
				cl.restartB(t, env)
			}
			cl.waitReady(t)
			cl.waitConverged(t, "k", true)

			_, rerr := cl.client.Refresh(x, &pb.RefreshRequest{KeysetId: "k", Admin: cl.env.Admin("refresh", "k")})
			dead := cl.deadParty(t, st.role)
			_ = dead
			t.Logf("died at %s (%s); Refresh returned: %v", st.name, st.what, rerr)

			// restart without the failpoint
			if st.role == "A" {
				cl.restartA(t)
			} else {
				cl.restartB(t)
			}
			g1 := cl.waitConverged(t, "k", true)
			if g1 != g0 && g1 != g0+1 {
				t.Fatalf("generation %d is neither %d nor %d", g1, g0, g0+1)
			}
			// signing works and the root public key is unchanged: the derived key is the same
			retry(t, 30*time.Second, func() error {
				d2, err := cl.client.Derive(x, &pb.DeriveRequest{KeysetId: "k", HardenedPath: hard, Path: path})
				if err != nil {
					return err
				}
				if !bytes.Equal(d2.PublicKey, d.PublicKey) {
					t.Fatalf("derived key changed: the root public key is not the same")
				}
				return nil
			})
			dg := dgst(7)
			var r *pb.SignResponse
			retryUnavailable(t, 30*time.Second, func() (err error) {
				r, err = cl.client.Sign(x, &pb.SignRequest{KeyId: d.KeyId, Algorithm: pb.Algorithm_ALGORITHM_ECDSA_SECP256K1, Digest: dg, JobId: "after-crash"})
				return
			})
			verifyECDSA(t, d.PublicKey, dg, r.Signature)
			_ = root
			// the parties are not frozen by a crash
			ha, hb := cl.health(t)
			if status(ha, "k").Frozen || status(hb, "k").Frozen {
				t.Fatal("a crash froze the keyset")
			}
			t.Logf("RESULT %-28s generation %d -> %d (%s), sign OK, root key unchanged", fmt.Sprintf("%s@%s", st.name, st.role), g0, g1, map[bool]string{true: "committed", false: "aborted"}[g1 > g0])
		})
	}
}

func TestCrashMatrixDKG(t *testing.T) {
	for _, st := range crashSteps {
		st := st
		t.Run(fmt.Sprintf("%s@%s", st.name, st.role), func(t *testing.T) {
			cl := newCluster(t, nil, false)
			x := ctx(t, 3*time.Minute)
			env := "QV_FAILPOINT=" + st.name
			if st.role == "A" {
				cl.a.kill()
				cl.restartA(t, env)
			} else {
				cl.b.kill()
				cl.restartB(t, env)
			}
			cl.waitReady(t)
			_, derr := cl.client.DKG(x, &pb.DKGRequest{KeysetId: "k", Curve: pb.Curve_CURVE_SECP256K1, Admin: cl.env.Admin("dkg", "k")})
			cl.deadParty(t, st.role)
			t.Logf("died at %s (%s); DKG returned: %v", st.name, st.what, derr)
			if st.role == "A" {
				cl.restartA(t)
			} else {
				cl.restartB(t)
			}
			cl.waitReady(t)
			// converge: party A has no pending entry. Either the keyset exists on both and works (committed), or party A has
			// none (aborted; party B may still hold an orphaned candidate, which a new DKG replaces).
			deadline := time.Now().Add(60 * time.Second)
			var exists bool
			for time.Now().Before(deadline) {
				ha, hb := cl.health(t)
				sa, sb := status(ha, "k"), status(hb, "k")
				if ha == nil {
					time.Sleep(200 * time.Millisecond)
					continue
				}
				if sa != nil && sb != nil && sa.Resolved && sb.Resolved && sa.Generation == 1 && sb.Generation == 1 {
					exists = true
					break
				}
				if sa == nil && hb != nil {
					break
				}
				time.Sleep(200 * time.Millisecond)
			}
			if !exists {
				// nothing half-created on A: the id is free and a new DKG works
				_, err := cl.client.DKG(x, &pb.DKGRequest{KeysetId: "k", Curve: pb.Curve_CURVE_SECP256K1, Admin: cl.env.Admin("dkg", "k")})
				must(t, err)
				cl.waitConverged(t, "k", true)
			}
			// UNAVAILABLE while the parties reconcile is correct behaviour (bounded: one self-test); wait for it, never
			// accept any other error.
			var d *pb.DeriveResponse
			retryUnavailable(t, 30*time.Second, func() (err error) {
				d, err = cl.client.Derive(x, &pb.DeriveRequest{KeysetId: "k", HardenedPath: []uint32{1}, Path: []uint32{0}})
				return
			})
			dg := dgst(8)
			var r *pb.SignResponse
			retryUnavailable(t, 30*time.Second, func() (err error) {
				r, err = cl.client.Sign(x, &pb.SignRequest{KeyId: d.KeyId, Algorithm: pb.Algorithm_ALGORITHM_ECDSA_SECP256K1, Digest: dg, JobId: "after-dkg-crash"})
				return
			})
			verifyECDSA(t, d.PublicKey, dg, r.Signature)
			t.Logf("RESULT %-28s DKG %s, sign OK", fmt.Sprintf("%s@%s", st.name, st.role), map[bool]string{true: "committed (keyset usable)", false: "aborted (nothing half-created, retried)"}[exists])
		})
	}
}

// retryUnavailable retries f while it fails with the typed UNAVAILABLE kind (a keyset being reconciled, a party coming back)
// and fails the test at once on any other error or when the deadline passes. Unlike retry it does not hide real failures.
func retryUnavailable(t *testing.T, d time.Duration, f func() error) {
	t.Helper()
	deadline := time.Now().Add(d)
	var err error
	start := time.Now()
	for time.Now().Before(deadline) {
		if err = f(); err == nil {
			if w := time.Since(start); w > time.Second {
				t.Logf("waited %v for reconciliation", w.Round(time.Millisecond))
			}
			return
		}
		if k, ok := kindOf(err); !ok || k != pb.ErrorKind_ERROR_KIND_UNAVAILABLE {
			t.Fatalf("not an UNAVAILABLE: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("still UNAVAILABLE after %v: %v", d, err)
}

// Reconciliation always finishes and is quick: after restarting either party (and after a dropped link), the keyset is
// resolved again within a bounded time, and a restart triggers it exactly once (a reconnect does not re-trigger it for ever).
func TestReconcileLatencyAfterRestart(t *testing.T) {
	cl := newCluster(t, nil, false)
	x := ctx(t, 5*time.Minute)
	_, err := cl.client.DKG(x, &pb.DKGRequest{KeysetId: "k", Curve: pb.Curve_CURVE_SECP256K1, Admin: cl.env.Admin("dkg", "k")})
	must(t, err)
	cl.waitConverged(t, "k", true)
	var worst time.Duration
	for i, role := range []string{"B", "A", "B", "A", "B"} {
		start := time.Now()
		if role == "A" {
			cl.a.kill()
			cl.restartA(t)
		} else {
			cl.b.kill()
			cl.restartB(t)
		}
		cl.waitConverged(t, "k", true)
		d := time.Since(start)
		if d > worst {
			worst = d
		}
		// no re-trigger: the keyset stays resolved for a few seconds after it converged
		time.Sleep(2 * time.Second)
		ha, hb := cl.health(t)
		if sa, sb := status(ha, "k"), status(hb, "k"); sa == nil || sb == nil || !sa.Resolved || !sb.Resolved {
			t.Fatalf("restart %d (%s): keyset unresolved again 2 s after convergence: %v / %v", i, role, sa, sb)
		}
		t.Logf("restart %d of party %s: resolved on both parties after %v", i, role, d.Round(time.Millisecond))
	}
	if worst > 15*time.Second {
		t.Fatalf("slowest convergence %v", worst)
	}
	t.Logf("slowest convergence after a restart: %v", worst.Round(time.Millisecond))
}
