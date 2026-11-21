package server_test

import (
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/server"
)

// tamperUntilLost signs through the A-B proxy with one A-to-B frame flipped, trying frame numbers until a hit leaves A without B's
// verdict (some frame numbers make A itself find the failure: those runs are unfrozen again and the next number is tried).
func tamperUntilLost(t *testing.T, tr *trio, job string, setup func(px *tamperProxy)) error {
	t.Helper()
	px := tr.Proxy["AB"]
	for n := 0; n < 8; n++ {
		px.set(0, n)
		setup(px)
		_, err := tr.sign("A", "k", job+string(rune('a'+n)), byte(n+1))
		if !px.hit.Load() || err == nil {
			continue
		}
		if k, _ := server.KindOfStatus(err); k != pb.ErrorKind_ERROR_KIND_CRYPTOGRAPHIC {
			return err
		}
		px.set(0, -1)
		for _, role := range []string{"A", "B", "C"} {
			tr.waitFrozen(t, role, "k", true)
		}
		_, uerr := tr.Client["A"].Unfreeze(ctx30(t), &pb.UnfreezeRequest{KeysetId: "k", Admin: tr.Env.Admin("unfreeze", "k")})
		mustOK(t, uerr)
		for _, role := range []string{"A", "B", "C"} {
			tr.waitFrozen(t, role, "k", false)
		}
	}
	t.Fatal("no tampering left A without B's verdict")
	return nil
}

// B finds tampering and tells A in a FIN that never arrives. A must not answer "retryable" while it is the one member that does not
// know: it asks B, freezes, and answers FROZEN. All three are frozen.
func TestTrioLostVerdictFreezesTheCoordinator(t *testing.T) {
	tr := startTrio(t, trioOpts{proxyAB: true})
	tr.dkg(t, "k")
	err := tamperUntilLost(t, tr, "lost", func(px *tamperProxy) { px.dropFinBA.Store(true) })
	wantKind(t, err, codes.FailedPrecondition, pb.ErrorKind_ERROR_KIND_FROZEN)
	for _, role := range []string{"A", "B", "C"} {
		tr.waitFrozen(t, role, "k", true)
	}
	tr.Proxy["AB"].set(0, -1)
	_, ferr := tr.sign("A", "k", "after", 9)
	wantKind(t, ferr, codes.FailedPrecondition, pb.ErrorKind_ERROR_KIND_FROZEN)
}

// The verdict is lost and B cannot be asked either: A does not know, answers Unavailable-class TRANSPORT as before, and is NOT frozen
// (cutting the network must never freeze a keyset). B has frozen itself.
func TestTrioLostVerdictAndNoProbeAnswerDoesNotFreeze(t *testing.T) {
	tr := startTrio(t, trioOpts{proxyAB: true})
	tr.dkg(t, "k")
	err := tamperUntilLost(t, tr, "cut", func(px *tamperProxy) { px.dropFinBA.Store(true); px.refuseFrom.Store(1) })
	wantKind(t, err, codes.Unavailable, pb.ErrorKind_ERROR_KIND_TRANSPORT)
	tr.waitFrozen(t, "B", "k", true)
	time.Sleep(500 * time.Millisecond)
	if tr.frozen(t, "A", "k") {
		t.Fatal("A froze although it only lost the link to B")
	}
}

// An ordinary outage before any signing message (B is down) triggers no probe: the proxy sees exactly the one session A tried.
func TestTrioOutageBeforeTheProtocolIsNotProbed(t *testing.T) {
	tr := startTrio(t, trioOpts{proxyAB: true})
	pub := tr.dkg(t, "k")
	tr.stop("B")
	px := tr.Proxy["AB"]
	px.set(0, -1)
	r, err := tr.sign("A", "k", "outage", 3)
	mustOK(t, err)
	tr.verify(t, pub, 3, r.Signature)
	if n := px.sessions.Load(); n != 1 {
		t.Fatalf("the A-B link saw %d sessions, want 1 (no probe after a failure before the protocol)", n)
	}
	if tr.frozen(t, "A", "k") {
		t.Fatal("an outage froze the keyset")
	}
}
