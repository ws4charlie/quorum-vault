package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	wire "github.com/ws4charlie/quorum-vault/mpc-party/api/cosigner"
	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

// Failure counters for central, read-only monitoring.
//
// Every failed peer session is counted once, by the party that saw it: which side it was on (coordinator or follower), which
// operation, which peer, and which error kind. Nothing in this process reads the counters back: no freeze, no refusal and no
// route change depends on them. They are exposed on the optional metrics port (config metrics_listen) for Prometheus, whose
// rules live outside the signing zone.
//
// "Peer" is a SUSPECT, not proof. cb-mpc aborts without blame: the peer is the party the failed message came from, or the link
// that failed, and the cause may equally be this party's own host, the link, or the third party.

const (
	sideCoordinator = "coordinator"
	sideFollower    = "follower"
	peerNone        = "none" // no single peer: a limit or a check on this party before any peer was contacted, or a three-party session
)

var failSides = []string{sideCoordinator, sideFollower}

// Operations are a fixed small set (labels must not grow with keysets or jobs). Derive, node, unfreeze and freeze notices are
// "other".
var failOps = []string{"sign", "dkg", "refresh", "reconcile", "other"}

// All error kinds a failure can have; the label is the kind name without the ERROR_KIND_ prefix.
var failKinds = []pb.ErrorKind{
	pb.ErrorKind_ERROR_KIND_TRANSPORT, pb.ErrorKind_ERROR_KIND_UNAVAILABLE, pb.ErrorKind_ERROR_KIND_CRYPTOGRAPHIC,
	pb.ErrorKind_ERROR_KIND_REFUSED, pb.ErrorKind_ERROR_KIND_LIMIT, pb.ErrorKind_ERROR_KIND_INTERNAL, pb.ErrorKind_ERROR_KIND_FROZEN,
}

func kindLabel(k pb.ErrorKind) string {
	switch k {
	case pb.ErrorKind_ERROR_KIND_TRANSPORT, pb.ErrorKind_ERROR_KIND_UNAVAILABLE, pb.ErrorKind_ERROR_KIND_CRYPTOGRAPHIC,
		pb.ErrorKind_ERROR_KIND_REFUSED, pb.ErrorKind_ERROR_KIND_LIMIT, pb.ErrorKind_ERROR_KIND_FROZEN:
		return k.String()[len("ERROR_KIND_"):]
	}
	return "INTERNAL"
}

func opLabel(op pb.Op) string {
	switch op {
	case pb.Op_OP_SIGN:
		return "sign"
	case pb.Op_OP_DKG:
		return "dkg"
	case pb.Op_OP_REFRESH:
		return "refresh"
	case pb.Op_OP_RECONCILE:
		return "reconcile"
	}
	return "other"
}

type failKey struct{ side, op, peer, kind string }

type failStats struct {
	mu   sync.Mutex
	role string
	n    map[failKey]uint64
}

// newFailStats starts every series this party can ever have at zero, so that Prometheus sees the first failure as an increase
// (a series that appears at 1 gives increase() nothing to compare with).
func newFailStats(role string) *failStats {
	f := &failStats{role: role, n: map[failKey]uint64{}}
	peers := []string{peerNone}
	for _, r := range []string{"A", "B", "C"} {
		if r != role {
			peers = append(peers, r)
		}
	}
	for _, side := range failSides {
		for _, op := range failOps {
			for _, peer := range peers {
				for _, k := range failKinds {
					f.n[failKey{side, op, peer, kindLabel(k)}] = 0
				}
			}
		}
	}
	return f
}

func (f *failStats) add(side, op, peer string, kind pb.ErrorKind) {
	if peer == f.role || peer == "" || len(peer) != 1 || peer[0] < 'A' || peer[0] > 'C' {
		peer = peerNone
	}
	f.mu.Lock()
	f.n[failKey{side, op, peer, kindLabel(kind)}]++
	f.mu.Unlock()
}

// noteFail counts one failed session of this party. err is the failure as the operation returned it.
func (s *Server) noteFail(side string, op pb.Op, peer string, err error) {
	if err == nil {
		return
	}
	var f *Fail
	if !errors.As(err, &f) {
		f = fromWrapper(op.String(), err)
	}
	s.fails.add(side, opLabel(op), peer, f.Kind)
}

// FailureCount is the number of failed sessions counted so far (tests and diagnostics).
func (s *Server) FailureCount(side, op, peer, kind string) uint64 {
	s.fails.mu.Lock()
	defer s.fails.mu.Unlock()
	return s.fails.n[failKey{side, op, peer, kind}]
}

// FailureCountTotal sums the counters whose labels match; an empty argument matches anything.
func (s *Server) FailureCountTotal(side, op, peer, kind string) (total uint64) {
	s.fails.mu.Lock()
	defer s.fails.mu.Unlock()
	for k, v := range s.fails.n {
		if (side == "" || k.side == side) && (op == "" || k.op == op) && (peer == "" || k.peer == peer) && (kind == "" || k.kind == kind) {
			total += v
		}
	}
	return total
}

const failMetricName = "qv_mpc_party_session_failures_total"

// WriteMetrics renders the counters in the Prometheus text format.
func (s *Server) WriteMetrics(w io.Writer) {
	s.fails.mu.Lock()
	keys := make([]failKey, 0, len(s.fails.n))
	vals := make(map[failKey]uint64, len(s.fails.n))
	for k, v := range s.fails.n {
		keys = append(keys, k)
		vals[k] = v
	}
	s.fails.mu.Unlock()
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.side != b.side {
			return a.side < b.side
		}
		if a.op != b.op {
			return a.op < b.op
		}
		if a.peer != b.peer {
			return a.peer < b.peer
		}
		return a.kind < b.kind
	})
	fmt.Fprintf(w, "# HELP %s Failed peer sessions of this party. peer is the SUSPECTED party (where the failed message came in, or the link that failed), not proven guilty: the protocol aborts without blame. peer=\"none\": no single peer. side: coordinator (this party opened the session) or follower. kind: TRANSPORT, UNAVAILABLE, CRYPTOGRAPHIC, REFUSED, LIMIT, INTERNAL, FROZEN. Counters only grow; use increase() or rate().\n", failMetricName)
	fmt.Fprintf(w, "# TYPE %s counter\n", failMetricName)
	for _, k := range keys {
		fmt.Fprintf(w, "%s{party=%q,side=%q,op=%q,peer=%q,kind=%q} %d\n", failMetricName, s.cfg.Role, k.side, k.op, k.peer, k.kind, vals[k])
	}
	// the party's own certificate (its ports and the channel to its cosigner); pinned, never reloaded, so the time left is that of the loaded one
	wire.WriteCertMetrics(w, "mpc-party-"+strings.ToLower(s.cfg.Role), "signing", s.certNow(), time.Now())
	if s.gate != nil {
		s.gate.writeMetrics(w)
	}
	fmt.Fprintf(w, "# HELP qv_mpc_party_info The party's role and version.\n# TYPE qv_mpc_party_info gauge\nqv_mpc_party_info{party=%q,version=%q} 1\n", s.cfg.Role, Version)
}

// startMetrics serves GET /metrics on metrics_listen, plain HTTP, read-only: counters only, no secrets, no way to change anything. Bind
// it to an address only the monitoring host can reach.
func (s *Server) startMetrics() error {
	if s.cfg.MetricsListen == "" {
		return nil
	}
	ln, err := net.Listen("tcp", s.cfg.MetricsListen)
	if err != nil {
		return fmt.Errorf("metrics_listen: %w", err)
	}
	s.metricsLn = ln
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "read-only", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		if r.Method == http.MethodGet {
			s.WriteMetrics(w)
		}
	})
	s.metricsSrv = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second,
		MaxHeaderBytes: 8 << 10}
	go s.metricsSrv.Serve(ln)
	return nil
}

// MetricsAddr is where the metrics endpoint listens ("" when it is off).
func (s *Server) MetricsAddr() string {
	if s.metricsLn == nil {
		return ""
	}
	return s.metricsLn.Addr().String()
}

func (s *Server) stopMetrics() {
	if s.metricsSrv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		s.metricsSrv.Shutdown(ctx)
	}
}

// followWatch wraps the stream of an incoming peer session and notes the worst failing FIN that crossed it, in either direction:
// one the follower sent (its own finding or a rejection) or one the coordinator sent. The session counts once, on return.
type followWatch struct {
	pb.Peer_SessionServer
	mu    sync.Mutex
	op    pb.Op
	worst pb.ErrorKind
	seen  bool
}

func (w *followWatch) look(f *pb.Frame) {
	if f == nil || f.GetKind() != pb.FrameKind_FRAME_KIND_FIN {
		return
	}
	var fin pb.Fin
	if proto.Unmarshal(f.Payload, &fin) != nil || fin.GetOk() {
		return
	}
	k := fin.GetKind()
	w.mu.Lock()
	if !w.seen || severity(k) > severity(w.worst) {
		w.worst = k
	}
	w.seen = true
	w.mu.Unlock()
}

func (w *followWatch) setOp(op pb.Op) { w.mu.Lock(); w.op = op; w.mu.Unlock() }

func (w *followWatch) Send(f *pb.Frame) error {
	w.look(f)
	return w.Peer_SessionServer.Send(f)
}

func (w *followWatch) Recv() (*pb.Frame, error) {
	f, err := w.Peer_SessionServer.Recv()
	w.look(f)
	return f, err
}

// finishFollow counts the session if a failing FIN crossed it. peer is the party that opened the session.
func (s *Server) finishFollow(w *followWatch) {
	w.mu.Lock()
	seen, kind, op := w.seen, w.worst, w.op
	w.mu.Unlock()
	if !seen {
		return
	}
	s.fails.add(sideFollower, opLabel(op), s.callerRole(w.Context()), kind)
}
