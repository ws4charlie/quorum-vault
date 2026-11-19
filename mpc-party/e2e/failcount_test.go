package e2e

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/server"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/testenv"
)

// Failure counters on real party processes, read from each party's metrics port (config metrics_listen) as Prometheus would.

// withMetrics gives every party a metrics port and returns the addresses; tweak (may be nil) runs after it.
func withMetrics(t *testing.T, tweak func(role string, c *server.Config)) (func(role string, c *server.Config), map[string]string) {
	addrs := map[string]string{"A": testenv.FreeAddr(t), "B": testenv.FreeAddr(t), "C": testenv.FreeAddr(t)}
	return func(role string, c *server.Config) {
		c.MetricsListen = addrs[role]
		if tweak != nil {
			tweak(role, c)
		}
	}, addrs
}

// scrape returns the failure counters of a party: "side/op/peer/kind" -> value, and the raw text.
func scrape(t *testing.T, addr string) (map[string]uint64, string) {
	t.Helper()
	resp, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	out := map[string]uint64{}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "qv_mpc_party_session_failures_total{") {
			continue
		}
		labels := line[strings.Index(line, "{")+1 : strings.LastIndex(line, "}")]
		v, _ := strconv.ParseUint(strings.TrimSpace(line[strings.LastIndex(line, " ")+1:]), 10, 64)
		get := func(k string) string {
			i := strings.Index(labels, k+`="`)
			rest := labels[i+len(k)+2:]
			return rest[:strings.Index(rest, `"`)]
		}
		out[get("side")+"/"+get("op")+"/"+get("peer")+"/"+get("kind")] = v
	}
	return out, string(b)
}

func waitCounter(t *testing.T, addr, key string, min uint64) map[string]uint64 {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		m, _ := scrape(t, addr)
		if m[key] >= min {
			return m
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: counter %s = %d, want >= %d (%v)", addr, key, m[key], min, nonZero(m))
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func nonZero(m map[string]uint64) map[string]uint64 {
	out := map[string]uint64{}
	for k, v := range m {
		if v > 0 {
			out[k] = v
		}
	}
	return out
}

func total(m map[string]uint64) (n uint64) {
	for _, v := range m {
		n += v
	}
	return
}

// A party killed in the middle of a signature: the coordinator counts an availability failure (TRANSPORT) against that peer, and only that peer.
func TestFailCountKillPartyMidSession(t *testing.T) {
	tweak, addrs := withMetrics(t, func(role string, c *server.Config) { c.Limits.RecvTimeoutMS = 1500; c.Limits.SessionTimeoutMS = 8000 })
	cl := newCluster3(t, tweak)
	pub := cl.dkg(t, "k")
	cl.mustSignPeer(t, "A", "k", "warm", 1, "C", pub)
	before, _ := scrape(t, addrs["A"])
	if total(before) != 0 {
		t.Fatalf("a good signature counted a failure: %v", nonZero(before))
	}
	var err error
	for attempt := 0; attempt < 20; attempt++ {
		done := make(chan struct{})
		go func() { time.Sleep(15 * time.Millisecond); cl.procs["C"].signal(syscall.SIGKILL); close(done) }()
		_, err = cl.signPeer("A", "k", fmt.Sprintf("kill-%d", attempt), 2+attempt, "C")
		<-done
		if err != nil {
			break
		}
		cl.restart(t, "C") // the kill came too late: bring C back and try again
		cl.waitReady(t)
	}
	if err == nil {
		t.Fatal("no attempt failed")
	}
	if k, _ := kindOf(err); k != pb.ErrorKind_ERROR_KIND_TRANSPORT && k != pb.ErrorKind_ERROR_KIND_UNAVAILABLE {
		t.Fatalf("kind %v, want an availability failure: %v", k, err)
	}
	got := waitCounter(t, addrs["A"], "coordinator/sign/C/"+k2s(err), 1)
	for k, v := range nonZero(got) {
		if !strings.Contains(k, "/C/") {
			t.Fatalf("a failure with C was counted against another peer: %s=%d", k, v)
		}
	}
	// B never failed with anyone
	if m, _ := scrape(t, addrs["B"]); total(m) != 0 {
		t.Fatalf("B counted failures it was not part of: %v", nonZero(m))
	}
}

func k2s(err error) string {
	k, _ := kindOf(err)
	return strings.TrimPrefix(k.String(), "ERROR_KIND_")
}

// A cosigner refusal: REFUSED counted by the coordinator against the party that refused, and by the refusing party against the one that asked;
// a good pair next to it counts nothing.
func TestFailCountCosignerRefusal(t *testing.T) {
	forSchemes(t, func(t *testing.T, sc pb.Scheme) {
		tweak, addrs := withMetrics(t, func(role string, c *server.Config) {
			if role == "C" {
				c.Authorizer = server.AuthorizerConfig{Type: "deny-all"}
			}
		})
		cl := newCluster3S(t, sc, tweak)
		pub := cl.dkg(t, "k")
		_, err := cl.signPeer("A", "k", "refused-ac", 1, "C")
		wantKind(t, err, pb.ErrorKind_ERROR_KIND_REFUSED)
		waitCounter(t, addrs["A"], "coordinator/sign/C/REFUSED", 1)
		waitCounter(t, addrs["C"], "follower/sign/A/REFUSED", 1)
		_, err = cl.signPeer("B", "k", "refused-bc", 2, "C")
		wantKind(t, err, pb.ErrorKind_ERROR_KIND_REFUSED)
		waitCounter(t, addrs["B"], "coordinator/sign/C/REFUSED", 1)
		waitCounter(t, addrs["C"], "follower/sign/B/REFUSED", 1)
		// A+B signs; no failure with B is counted anywhere
		cl.mustSignPeer(t, "A", "k", "ok-ab", 3, "B", pub)
		for _, role := range []string{"A", "B"} {
			m, _ := scrape(t, addrs[role])
			for k, v := range nonZero(m) {
				if role == "A" && strings.Contains(k, "/B/") || v > 1 {
					t.Fatalf("party %s: unexpected counter %s=%d (%v)", role, k, v, nonZero(m))
				}
			}
		}
	})
}
