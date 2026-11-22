package server_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/server"
)

// swapAdmins restarts one member with an admin set the test's operators are not in: from then on that member refuses every
// admin request the operators sign (ERROR_KIND_REFUSED), while the other two accept them. Its keysets are on disk as before.
func (tr *trio) swapAdmins(t *testing.T, role string) {
	t.Helper()
	tr.stop(role)
	var keys []string
	for i := 0; i < 3; i++ {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, hex.EncodeToString(pub))
	}
	tr.Cfg[role].AdminKeys = keys
	tr.start(t, role)
	tr.waitReady(t)
}

// waitResolved waits until every member has reconciled the keyset since its (re)start.
func (tr *trio) waitResolved(t *testing.T, id string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		all := true
		for _, role := range []string{"A", "B", "C"} {
			h, err := tr.Client[role].Health(ctx30(t), &pb.HealthRequest{})
			mustOK(t, err)
			ok := false
			for _, k := range h.Keysets {
				if k.KeysetId == id && k.Resolved {
					ok = true
				}
			}
			all = all && ok
		}
		if all {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("keyset %s not reconciled on all three", id)
}

// wantNamedRefusal checks what the operator is told when one member refuses: the refusal itself (not retryable, not a
// transport error), the member's name, its reason, and promptly (long before the coordinator's own waits run out).
func wantNamedRefusal(t *testing.T, err error, member string, took, bound time.Duration) {
	t.Helper()
	wantKind(t, err, codes.PermissionDenied, pb.ErrorKind_ERROR_KIND_REFUSED)
	msg := err.Error()
	if !strings.Contains(msg, "party "+member) || !strings.Contains(msg, "admin authorization") {
		t.Fatalf("the refusal does not name party %s and its reason: %v", member, err)
	}
	if took > bound {
		t.Fatalf("the refusal took %v, want under %v (a wait ran out instead of the answer being read)", took, bound)
	}
}

// A member that refuses an admin request is reported to the caller as that member's refusal, at once. Before, with C refusing,
// A waited for B's ACK first, B waited for C's link, and the caller got a transport timeout after twice the receive limit.
func TestTrioMemberRefusalReachesTheCaller(t *testing.T) {
	const recv = 3000 // ms; a lost refusal shows as DeadlineExceeded after 2*recv
	bound := 2 * time.Second
	for _, op := range []string{"dkg", "refresh", "unfreeze"} {
		for _, refuser := range []string{"B", "C"} {
			t.Run(op+"/"+refuser, func(t *testing.T) {
				tr := startTrio(t, trioOpts{proxyAB: op == "unfreeze", recvMS: recv})
				call := func() error {
					switch op {
					case "dkg":
						_, err := tr.Client["A"].DKG(ctx30(t), &pb.DKGRequest{KeysetId: "fresh", Scheme: tr.sc(), Admin: tr.Env.Admin("dkg", "fresh")})
						return err
					case "refresh":
						_, err := tr.Client["A"].Refresh(ctx30(t), &pb.RefreshRequest{KeysetId: "k", Admin: tr.Env.Admin("refresh", "k")})
						return err
					}
					_, err := tr.Client["A"].Unfreeze(ctx30(t), &pb.UnfreezeRequest{KeysetId: "k", Admin: tr.Env.Admin("unfreeze", "k")})
					return err
				}
				if op != "dkg" {
					tr.dkg(t, "k")
				}
				if op == "unfreeze" {
					px := tr.Proxy["AB"]
					for n := 0; ; n++ {
						px.set(0, n)
						if _, err := tr.sign("A", "k", "t"+string(rune('a'+n)), byte(n+1)); px.hit.Load() && err != nil {
							break
						}
						if n == 5 {
							t.Fatal("no tampering produced a failure")
						}
					}
					px.set(0, -1)
					for _, role := range []string{"A", "B", "C"} {
						tr.waitFrozen(t, role, "k", true)
					}
				}
				tr.swapAdmins(t, refuser)
				if op != "dkg" { // after the restart the member must be reconciled again before it judges a refresh
					tr.waitResolved(t, "k")
				}
				start := time.Now()
				err := call()
				wantNamedRefusal(t, err, refuser, time.Since(start), bound)
				if op == "unfreeze" {
					for _, role := range []string{"A", "B", "C"} {
						if !tr.frozen(t, role, "k") {
							t.Fatalf("a refused unfreeze lifted the freeze on %s", role)
						}
					}
				}
				// the refusal is not retryable: the same request signed again is refused the same way
				start = time.Now()
				wantNamedRefusal(t, call(), refuser, time.Since(start), bound)
			})
		}
	}
}

// Both members refuse: a refusal is still a refusal, and it names a member that refused.
func TestTrioBothMembersRefuse(t *testing.T) {
	tr := startTrio(t, trioOpts{recvMS: 3000})
	tr.swapAdmins(t, "B")
	tr.swapAdmins(t, "C")
	start := time.Now()
	_, err := tr.Client["A"].DKG(ctx30(t), &pb.DKGRequest{KeysetId: "k", Scheme: tr.sc(), Admin: tr.Env.Admin("dkg", "k")})
	wantKind(t, err, codes.PermissionDenied, pb.ErrorKind_ERROR_KIND_REFUSED)
	if time.Since(start) > 2*time.Second {
		t.Fatalf("took %v", time.Since(start))
	}
}

// A member that is down is not a refusal: the caller sees the link failure (retryable kinds), naming the member.
func TestTrioMemberDownIsNotARefusal(t *testing.T) {
	for _, down := range []string{"B", "C"} {
		t.Run(down, func(t *testing.T) {
			tr := startTrio(t, trioOpts{recvMS: 3000})
			tr.stop(down)
			start := time.Now()
			_, err := tr.Client["A"].DKG(ctx30(t), &pb.DKGRequest{KeysetId: "k", Scheme: tr.sc(), Admin: tr.Env.Admin("dkg", "k")})
			if err == nil {
				t.Fatal("DKG succeeded with a member down")
			}
			k, _ := server.KindOfStatus(err)
			if k == pb.ErrorKind_ERROR_KIND_REFUSED || k == pb.ErrorKind_ERROR_KIND_CRYPTOGRAPHIC {
				t.Fatalf("a member that is down was reported as %v: %v", k, err)
			}
			if !strings.Contains(err.Error(), "party "+down) {
				t.Fatalf("the error does not name party %s: %v", down, err)
			}
			t.Logf("%s down: %v after %v", down, err, time.Since(start))
		})
	}
}

// Two-party keysets: B refuses the admin request, A reports it as B's refusal.
func TestPairPeerRefusalReachesTheCaller(t *testing.T) {
	p := startPair(t, pairOpts{tweak: func(role string, c *server.Config) {
		if role != "B" {
			return
		}
		var keys []string
		for i := 0; i < 3; i++ {
			pub, _, _ := ed25519.GenerateKey(rand.Reader)
			keys = append(keys, hex.EncodeToString(pub))
		}
		c.AdminKeys = keys
	}})
	start := time.Now()
	_, err := p.Client.DKG(ctx30(t), &pb.DKGRequest{KeysetId: "ks", Curve: pb.Curve_CURVE_SECP256K1, Admin: p.Env.Admin("dkg", "ks")})
	wantNamedRefusal(t, err, "B", time.Since(start), 2*time.Second)
}

// The proxy's slow return path must not change what A is told: B's verdict (its FIN) reaches A even when A has already
// sent more frames after the tampered one and the return path lags. (The proxy used to close A's stream as soon as its
// forward direction ended, which dropped B's FIN: A saw "peer closed the session" and answered Unavailable.)
func TestTrioTamperVerdictSurvivesASlowReturnPath(t *testing.T) {
	tr := startTrio(t, trioOpts{proxyAB: true})
	tr.dkg(t, "k")
	px := tr.Proxy["AB"]
	px.slowBA.Store(int64(150 * time.Millisecond))
	hits := 0
	for n := 0; n < 6; n++ {
		px.set(0, n)
		_, err := tr.sign("A", "k", "slow"+string(rune('a'+n)), byte(n+1))
		if !px.hit.Load() || err == nil {
			continue
		}
		hits++
		wantKind(t, err, codes.Aborted, pb.ErrorKind_ERROR_KIND_CRYPTOGRAPHIC)
		for _, role := range []string{"A", "B", "C"} {
			tr.waitFrozen(t, role, "k", true)
		}
		px.set(0, -1)
		_, uerr := tr.Client["A"].Unfreeze(ctx30(t), &pb.UnfreezeRequest{KeysetId: "k", Admin: tr.Env.Admin("unfreeze", "k")})
		mustOK(t, uerr)
		for _, role := range []string{"A", "B", "C"} {
			tr.waitFrozen(t, role, "k", false)
		}
	}
	if hits == 0 {
		t.Fatal("no tampering produced a failure")
	}
}
