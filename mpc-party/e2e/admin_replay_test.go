package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/server"
)

// An admin request is accepted once, also across a restart of the party (admin.go: durable seen set + start-time rule).

func adminReplayCluster(t *testing.T) (*cluster, string) {
	cl := newCluster(t, nil, false)
	x := ctx(t, 3*time.Minute)
	if _, err := cl.client.DKG(x, &pb.DKGRequest{KeysetId: "k", Curve: pb.Curve_CURVE_SECP256K1, Admin: cl.env.Admin("dkg", "k")}); err != nil {
		t.Fatal(err)
	}
	cl.waitConverged(t, "k", true)
	return cl, filepath.Join(cl.env.Dir, "data-A", "admin-seen.json")
}

func wantAdminRefused(t *testing.T, what string, err error, contains string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: the replayed request was accepted", what)
	}
	if grpcstatus.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), contains) {
		t.Fatalf("%s: want PermissionDenied containing %q, got %v", what, contains, err)
	}
}

// Replay after a restart: the request is dated ahead of the party's start (inside the window), so only the durable file can refuse it.
func TestAdminReplayAfterRestart(t *testing.T) {
	cl, seen := adminReplayCluster(t)
	x := ctx(t, 3*time.Minute)
	req := &pb.RefreshRequest{KeysetId: "k", Admin: server.SignAdmin(cl.env.AdminPriv, "refresh", "k", time.Now().Add(2*time.Minute))}
	if _, err := cl.client.Refresh(x, req); err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	if _, err := cl.client.Refresh(x, req); err == nil {
		t.Fatal("replay without a restart accepted")
	}
	if _, err := os.Stat(seen); err != nil {
		t.Fatalf("seen file not written: %v", err)
	}
	cl.a.kill()
	cl.restartA(t)
	cl.waitReady(t)
	cl.waitConverged(t, "k", true)
	_, err := cl.client.Refresh(x, req)
	wantAdminRefused(t, "after restart of A", err, "already used")

	// two quick restarts
	cl.a.kill()
	cl.restartA(t)
	cl.waitReady(t)
	_, err = cl.client.Refresh(x, req)
	wantAdminRefused(t, "after a second restart of A", err, "already used")

	// a fresh request after the restart is accepted
	retry(t, 30*time.Second, func() error {
		_, err := cl.client.Refresh(x, &pb.RefreshRequest{KeysetId: "k", Admin: cl.env.Admin("refresh", "k")})
		return err
	})
}

// Replay with the data directory rolled back (the seen file gone): the start-time rule refuses a request signed before the restart.
func TestAdminReplayRolledBackDataDir(t *testing.T) {
	cl, seen := adminReplayCluster(t)
	x := ctx(t, 3*time.Minute)
	req := &pb.RefreshRequest{KeysetId: "k", Admin: server.SignAdmin(cl.env.AdminPriv, "refresh", "k", time.Now())}
	if _, err := cl.client.Refresh(x, req); err != nil {
		t.Fatal(err)
	}
	cl.a.kill()
	if err := os.Remove(seen); err != nil { // an older copy of the directory: it has no record of this request
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond) // the start second must be later than the request's second
	cl.restartA(t)
	cl.waitReady(t)
	_, err := cl.client.Refresh(x, req)
	wantAdminRefused(t, "rolled-back data directory", err, "older than this party's start")
	retry(t, 30*time.Second, func() error {
		_, err := cl.client.Refresh(x, &pb.RefreshRequest{KeysetId: "k", Admin: cl.env.Admin("refresh", "k")})
		return err
	})
}

// A replay that reaches party A while A has forgotten (file removed, request dated ahead so the start rule passes) is still refused as a whole
// operation: B remembers and refuses its half; nothing changes and nothing freezes.
func TestAdminReplayOneForgetfulParty(t *testing.T) {
	cl, seen := adminReplayCluster(t)
	x := ctx(t, 3*time.Minute)
	req := &pb.RefreshRequest{KeysetId: "k", Admin: server.SignAdmin(cl.env.AdminPriv, "refresh", "k", time.Now().Add(2*time.Minute))}
	if _, err := cl.client.Refresh(x, req); err != nil {
		t.Fatal(err)
	}
	g0 := cl.waitConverged(t, "k", true)
	cl.a.kill()
	os.Remove(seen)
	cl.restartA(t)
	cl.waitReady(t)
	cl.waitConverged(t, "k", true)
	_, err := cl.client.Refresh(x, req)
	if err == nil {
		t.Fatal("B accepted a replayed request that A had forgotten")
	}
	t.Logf("A forgot, B remembered: %v", err)
	if g1 := cl.waitConverged(t, "k", true); g1 != g0 {
		t.Fatalf("generation moved %d -> %d", g0, g1)
	}
	ha, hb := cl.health(t)
	if status(ha, "k").Frozen || status(hb, "k").Frozen {
		t.Fatal("a refused replay froze the keyset")
	}
}
