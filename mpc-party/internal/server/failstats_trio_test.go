package server_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/server"
)

// waitFails waits until the party has counted at least min failures for the labels (a follower counts when its session returns).
func waitFails(t *testing.T, tr *trio, party, side, op, peer, kind string, min uint64) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if tr.Srv[party].FailureCount(side, op, peer, kind) >= min {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("party %s: %s %s peer=%s kind=%s counted %d, want >= %d (all: %d)", party, side, op, peer, kind,
		tr.Srv[party].FailureCount(side, op, peer, kind), min, tr.Srv[party].FailureCountTotal("", "", "", ""))
}

func (tr *trio) signPeer(via, id, job string, seed byte, peer string) error {
	_, err := tr.Client[via].Sign(context.Background(), &pb.SignRequest{KeyId: id, Algorithm: tr.algorithm(), Digest: digest(seed), JobId: job, Peer: peer})
	return err
}

// A cosigner refusal: the coordinator counts REFUSED against the party that refused, the refusing follower against the one that asked.
func TestFailCountRefusedByEachPair(t *testing.T) {
	var refuseB, refuseC atomic.Bool
	denyIf := func(f *atomic.Bool) *countAuth {
		return &countAuth{f: func() error {
			if f.Load() {
				return errors.New("policy says no")
			}
			return nil
		}}
	}
	tr := startTrio(t, trioOpts{auth: map[string]server.Authorizer{"B": denyIf(&refuseB), "C": denyIf(&refuseC)}})
	tr.dkg(t, "k")
	cases := []struct {
		name, coord, follower, via, peer string
		flag                             *atomic.Bool // the follower's cosigner refuses
	}{
		{"A+B", "A", "B", "A", "B", &refuseB},
		{"A+C", "A", "C", "A", "C", &refuseC},
		{"B+C", "B", "C", "B", "", &refuseC},
	}
	for i, c := range cases {
		refuseB.Store(false)
		refuseC.Store(false)
		c.flag.Store(true)
		if err := tr.signPeer(c.via, "k", fmt.Sprintf("refused-%d", i), byte(i+1), c.peer); err == nil {
			t.Fatalf("%s: signed although the cosigner refused", c.name)
		} else if k, _ := server.KindOfStatus(err); k != pb.ErrorKind_ERROR_KIND_REFUSED {
			t.Fatalf("%s: kind %v, want REFUSED: %v", c.name, k, err)
		}
		waitFails(t, tr, c.coord, "coordinator", "sign", c.follower, "REFUSED", 1)
		waitFails(t, tr, c.follower, "follower", "sign", c.coord, "REFUSED", 1)
	}
	// the refusals moved no other series on A: nothing against C when C was never asked, nothing cryptographic anywhere
	for _, p := range []string{"A", "B", "C"} {
		if n := tr.Srv[p].FailureCountTotal("", "", "", "CRYPTOGRAPHIC"); n != 0 {
			t.Fatalf("party %s counted %d cryptographic failures after refusals", p, n)
		}
	}
}

// A party that is down: the coordinator counts a TRANSPORT failure against it, for each coordinator and peer.
func TestFailCountPartyDown(t *testing.T) {
	tr := startTrio(t, trioOpts{})
	tr.dkg(t, "k")
	tr.stop("C")
	if err := tr.signPeer("A", "k", "down-c-from-a", 1, "C"); err == nil {
		t.Fatal("signed with C down")
	}
	waitFails(t, tr, "A", "coordinator", "sign", "C", "TRANSPORT", 1)
	if err := tr.signPeer("B", "k", "down-c-from-b", 2, ""); err == nil {
		t.Fatal("B signed with C down")
	}
	waitFails(t, tr, "B", "coordinator", "sign", "C", "TRANSPORT", 1)
	tr.start(t, "C")
	tr.stop("B")
	if err := tr.signPeer("A", "k", "down-b", 3, "B"); err == nil {
		t.Fatal("signed with B down")
	}
	waitFails(t, tr, "A", "coordinator", "sign", "B", "TRANSPORT", 1)
	// the party that is up is never the suspect of a failure it did not cause
	if n := tr.Srv["A"].FailureCount("coordinator", "sign", "none", "TRANSPORT"); n != 0 {
		t.Fatalf("a failed link counted against nobody: %d", n)
	}
}

// A corrupted message (existing tamper proxy): CRYPTOGRAPHIC against the party the message came in from, on both ends of the link.
func TestFailCountCryptographicOnEachLink(t *testing.T) {
	tr := startTrio(t, trioOpts{proxyAB: true, proxyAC: true, proxyBC: true})
	cases := []struct{ link, coord, follower, via, peer string }{
		{"AB", "A", "B", "A", "B"},
		{"AC", "A", "C", "A", "C"},
		{"BC", "B", "C", "B", ""},
	}
	for _, c := range cases {
		id := "k-" + c.link
		tr.dkg(t, id)
		px := tr.Proxy[c.link]
		hit := false
		for _, dir := range []int{0, 1} {
			for _, n := range []int{0, 2, 4} {
				px.set(dir, n)
				err := tr.signPeer(c.via, id, fmt.Sprintf("%s-%d-%d", id, dir, n), byte(n+1), c.peer)
				if err == nil || !px.hit.Load() {
					continue
				}
				if k, _ := server.KindOfStatus(err); k != pb.ErrorKind_ERROR_KIND_CRYPTOGRAPHIC {
					t.Fatalf("%s: kind %v, want CRYPTOGRAPHIC: %v", c.link, k, err)
				}
				hit = true
				break
			}
			if hit {
				break
			}
		}
		if !hit {
			t.Fatalf("%s: no tampering produced a failure", c.link)
		}
		waitFails(t, tr, c.coord, "coordinator", "sign", c.follower, "CRYPTOGRAPHIC", 1)
		waitFails(t, tr, c.follower, "follower", "sign", c.coord, "CRYPTOGRAPHIC", 1)
		px.set(0, -1)
	}
}

// The metrics port is read-only: GET /metrics only, counters only.
func TestFailMetricsEndpointIsReadOnly(t *testing.T) {
	tr := startTrio(t, trioOpts{metrics: true, auth: map[string]server.Authorizer{"B": &countAuth{f: func() error { return errors.New("no") }}}})
	tr.dkg(t, "secret-keyset-name")
	_ = tr.signPeer("A", "secret-keyset-name", "job-id-should-not-leak", 1, "B")
	waitFails(t, tr, "A", "coordinator", "sign", "B", "REFUSED", 1)
	addr := tr.Srv["A"].MetricsAddr()
	if addr == "" {
		t.Fatal("no metrics address")
	}
	get := func(method, path string) (int, string) {
		req, _ := http.NewRequest(method, "http://"+addr+path, strings.NewReader("x"))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	code, body := get("GET", "/metrics")
	want := `qv_mpc_party_session_failures_total{party="A",side="coordinator",op="sign",peer="B",kind="REFUSED"} 1`
	if code != 200 || !strings.Contains(body, want) {
		t.Fatalf("GET /metrics: %d, missing %q in:\n%s", code, want, body)
	}
	for _, leak := range []string{"secret-keyset-name", "job-id-should-not-leak"} {
		if strings.Contains(body, leak) {
			t.Fatalf("the metrics reveal %q", leak)
		}
	}
	for _, m := range []string{"POST", "PUT", "DELETE", "PATCH"} {
		if code, _ := get(m, "/metrics"); code != http.StatusMethodNotAllowed {
			t.Fatalf("%s /metrics: %d, want 405", m, code)
		}
	}
	if code, _ := get("GET", "/"); code != http.StatusNotFound {
		t.Fatalf("GET /: %d, want 404", code)
	}
	if tr.Srv["C"].MetricsAddr() == "" || tr.Srv["B"].MetricsAddr() == "" {
		t.Fatal("every party serves its metrics")
	}
}
