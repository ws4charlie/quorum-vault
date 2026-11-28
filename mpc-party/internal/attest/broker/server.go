// Package broker is the attestation release broker: it holds (through its HSM) the keys that wrap each MPC party's data keys, and releases a
// data key only to an enclave whose evidence verifies, matches a signed allowlist entry of that party and is bound to this very request.
// Every refusal is final and audited; nothing leaves in plaintext. Design: docs/enclaves.md ("The key is released only on proof").
package broker

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ws4charlie/quorum-vault/mpc-party/internal/attest"
)

// Options are the parts a test replaces.
type Options struct {
	Now func() time.Time // default time.Now
	Log *log.Logger      // default: stderr
}

// Server is the broker.
type Server struct {
	cfg      Config
	set      *settings
	ops      *attest.Operators
	verifier attest.Verifier
	keys     KeyWrapper
	audit    *Audit
	nonces   *nonceStore
	limit    *limiter
	now      func() time.Time
	log      *log.Logger

	list     atomic.Pointer[attest.SignedAllowlist]
	loadedAt atomic.Int64 // unix seconds when the list in force was loaded
	// NotAfter (unix seconds, 0 = not loaded) of the material in use: the serving certificate the listener loaded, the soonest vendor root the verifier was built from (certmetrics.go).
	leafEnd, rootEnd atomic.Int64
	reloadMu         sync.Mutex
	lastHash         [32]byte

	cmu      sync.Mutex
	counters map[string]int
	rules    map[string]int // refusals by rule code (bounded set: verify:*, allowlist:*, nonce:*, ...)
}

// Open builds a broker from its config, or fails. It refuses to start without trust roots, without a valid signed allowlist, with an
// unreadable audit log or token, and (production build) with debug evidence allowed or a test root.
func Open(cfg Config, opt Options) (*Server, error) {
	set, err := cfg.settings()
	if err != nil {
		return nil, err
	}
	ops, err := cfg.Operators.Build()
	if err != nil {
		return nil, err
	}
	rootPEM, err := os.ReadFile(cfg.TrustRoots)
	if err != nil {
		return nil, fmt.Errorf("broker: trust roots: %w", err)
	}
	roots, err := attest.ParseRootsPEM(rootPEM)
	if err != nil || len(roots) == 0 {
		return nil, fmt.Errorf("broker: trust roots: no certificate in %s (%v)", cfg.TrustRoots, err)
	}
	if err := checkBuildPolicy(cfg, roots); err != nil {
		return nil, err
	}
	v, err := attest.NewNitroVerifier(attest.NitroConfig{Roots: roots, AllowDebug: cfg.AllowDebug})
	if err != nil {
		return nil, err
	}
	var parties []string
	for p := range cfg.Parties {
		parties = append(parties, p)
	}
	hsm, err := OpenHSM(cfg.PKCS11, parties)
	if err != nil {
		return nil, err
	}
	s, err := newServer(cfg, set, ops, v, hsm, opt)
	if err != nil {
		return nil, err
	}
	s.rootEnd.Store(soonestNotAfter(roots))
	return s, nil
}

// newServer is Open after the I/O of roots and token; the allowlist and the audit log are loaded here.
func newServer(cfg Config, set *settings, ops *attest.Operators, v attest.Verifier, keys KeyWrapper, opt Options) (*Server, error) {
	s := &Server{cfg: cfg, set: set, ops: ops, verifier: v, keys: keys, nonces: newNonceStore(set.nonceTTL), limit: newLimiter(set.rate, set.burst),
		now: opt.Now, log: opt.Log, counters: map[string]int{}, rules: map[string]int{}}
	if s.now == nil {
		s.now = time.Now
	}
	if s.log == nil {
		s.log = log.New(os.Stderr, "qv-attest-broker: ", log.LstdFlags)
	}
	var err error
	if s.audit, err = OpenAudit(cfg.AuditLog); err != nil {
		return nil, err
	}
	floor, err := MaxLoadedSeq(cfg.AuditLog)
	if err != nil {
		return nil, fmt.Errorf("broker: audit log: %w", err)
	}
	l, err := attest.LoadSignedAllowlist(cfg.AllowlistFile, ops)
	if err != nil {
		return nil, fmt.Errorf("broker: refusing to start: %w", err)
	}
	if l.Seq < floor { // an old list, once valid, put back while the broker was down
		_ = s.audit.Write(Record{Event: "allowlist_load", Outcome: "refused", Seq: floor, Detail: fmt.Sprintf("at start: sequence %d is below %d, the highest this broker loaded", l.Seq, floor)}, s.now())
		return nil, fmt.Errorf("broker: refusing to start: allowlist sequence %d is older than %d, the highest this broker has loaded (a replayed list?)", l.Seq, floor)
	}
	s.list.Store(l)
	s.loadedAt.Store(s.now().Unix())
	s.lastHash = fileHash(cfg.AllowlistFile)
	if err := s.audit.Write(Record{Event: "allowlist_load", Outcome: "loaded", Seq: l.Seq, Detail: fmt.Sprintf("%d entries, at start", len(l.Entries))}, s.now()); err != nil {
		return nil, err
	}
	return s, nil
}

// Close closes the audit log.
func (s *Server) Close() error { return s.audit.Close() }

func fileHash(path string) [32]byte {
	b, _ := os.ReadFile(path)
	return sha256.Sum256(b)
}

// Reload re-reads the allowlist file. A list that is unsigned, signed by too few operators, malformed or not newer than the one in force is
// refused and the previous list stays; the outcome is audited either way. Identical content is a no-op.
func (s *Server) Reload() error {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	h := fileHash(s.cfg.AllowlistFile)
	if h == s.lastHash {
		return nil
	}
	s.lastHash = h // act once per distinct content; a fixed file is a new content
	cur := s.list.Load()
	l, err := attest.LoadSignedAllowlist(s.cfg.AllowlistFile, s.ops)
	if err == nil && l.Seq <= cur.Seq {
		err = fmt.Errorf("attest: allowlist sequence %d is not higher than the one in force (%d)", l.Seq, cur.Seq)
	}
	if err != nil {
		s.count("reload_refused")
		s.log.Printf("allowlist reload refused, keeping sequence %d: %v", cur.Seq, err)
		_ = s.audit.Write(Record{Event: "allowlist_load", Outcome: "refused", Seq: cur.Seq, Detail: err.Error()}, s.now())
		return err
	}
	s.list.Store(l)
	s.loadedAt.Store(s.now().Unix())
	s.count("reload_ok")
	s.log.Printf("allowlist reloaded: sequence %d, %d entries", l.Seq, len(l.Entries))
	return s.audit.Write(Record{Event: "allowlist_load", Outcome: "loaded", Seq: l.Seq, Detail: fmt.Sprintf("%d entries", len(l.Entries))}, s.now())
}

// Watch polls the allowlist file until ctx ends and reloads it when its content changes.
func (s *Server) Watch(ctx context.Context) {
	if s.set.reload == 0 {
		return
	}
	t := time.NewTicker(s.set.reload)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = s.Reload()
		}
	}
}

// Sequence is the sequence number of the allowlist in force.
func (s *Server) Sequence() int64 { return s.list.Load().Seq }

func (s *Server) count(k string) { s.cmu.Lock(); s.counters[k]++; s.cmu.Unlock() }

func (s *Server) countRule(code string) { s.cmu.Lock(); s.rules[code]++; s.cmu.Unlock() }

// Status is what the broker says about the allowlist in force (GET /status on the health listener). No key, no evidence.
type Status struct {
	AllowlistSeq   int64          `json:"allowlist_seq"`
	SignedAt       int64          `json:"signed_at"`
	LoadedAt       int64          `json:"loaded_at"`
	Entries        int            `json:"entries"`
	Allowing       int            `json:"allowing_now"`
	OutsideWindow  int            `json:"outside_window"`
	Revoked        int            `json:"revoked"`
	ReloadRefusals int            `json:"reload_refusals"`
	RefusalsByRule map[string]int `json:"refusals_by_rule"`
	Simulation     bool           `json:"simulation_build"`
	EntriesInForce []StatusEntry  `json:"entries_in_force"`
}

// StatusEntry is one entry of the list in force.
type StatusEntry struct {
	Party       string `json:"party"`
	Measurement string `json:"measurement"`
	Version     string `json:"version,omitempty"`
	State       string `json:"state"` // allowing, revoked, not_yet_valid, expired
	NotBefore   int64  `json:"not_before"`
	NotAfter    int64  `json:"not_after,omitempty"`
}

func entryState(e attest.AllowEntry, now time.Time) string {
	switch {
	case e.Revoked():
		return "revoked"
	case now.Before(e.NotBefore):
		return "not_yet_valid"
	case !e.NotAfter.IsZero() && now.After(e.NotAfter):
		return "expired"
	}
	return "allowing"
}

// Status reports the list in force and the refusal counters.
func (s *Server) Status() Status {
	l, now := s.list.Load(), s.now()
	a, o, r := l.Counts(now)
	st := Status{AllowlistSeq: l.Seq, SignedAt: l.SignedAt, LoadedAt: s.loadedAt.Load(), Entries: len(l.Entries), Allowing: a, OutsideWindow: o, Revoked: r,
		RefusalsByRule: map[string]int{}, Simulation: Simulation}
	for _, e := range l.Entries {
		se := StatusEntry{Party: e.Party, Measurement: e.Measurement, Version: e.Version, State: entryState(e, now), NotBefore: e.NotBefore.Unix()}
		if !e.NotAfter.IsZero() {
			se.NotAfter = e.NotAfter.Unix()
		}
		st.EntriesInForce = append(st.EntriesInForce, se)
	}
	s.cmu.Lock()
	defer s.cmu.Unlock()
	st.ReloadRefusals = s.counters["reload_refused"]
	for k, v := range s.rules {
		st.RefusalsByRule[k] = v
	}
	return st
}

// Handler is the mutual-TLS API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/challenge", s.handleChallenge)
	mux.HandleFunc("POST /v1/release", func(w http.ResponseWriter, r *http.Request) { s.handleKeys(w, r, attest.PurposeUnseal) })
	mux.HandleFunc("POST /v1/newkey", func(w http.ResponseWriter, r *http.Request) { s.handleKeys(w, r, attest.PurposeCreate) })
	return mux
}

// HealthHandler serves /healthz (the allowlist is loaded and the token answers) and /metrics (counters, no data). It carries no secret and no
// key, so it may listen in plain HTTP on a local address for pod probes.
func (s *Server) HealthHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		if s.list.Load() == nil || s.keys.Ready() != nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		st := s.Status() // takes cmu itself: before the lock below
		s.cmu.Lock()
		defer s.cmu.Unlock()
		for k, v := range s.counters {
			fmt.Fprintf(w, "qv_attest_broker_events_total{event=%q} %d\n", k, v)
		}
		fmt.Fprintf(w, "qv_attest_broker_allowlist_sequence %d\n", st.AllowlistSeq)
		fmt.Fprintf(w, "qv_attest_broker_allowlist_signed_at_seconds %d\n", st.SignedAt)
		fmt.Fprintf(w, "qv_attest_broker_allowlist_loaded_at_seconds %d\n", st.LoadedAt)
		for _, c := range []struct {
			state string
			n     int
		}{{"allowing", st.Allowing}, {"outside_window", st.OutsideWindow}, {"revoked", st.Revoked}} {
			fmt.Fprintf(w, "qv_attest_broker_allowlist_entries{state=%q} %d\n", c.state, c.n)
		}
		// One series per (party, version, measurement, state): which release is allowed for which party, and in what state. Entries that share all four
		// (the same release listed twice, e.g. a renewed window, or two measurements that share the shown prefix) are one series whose value is their count:
		// the same name and labels twice in one scrape is invalid exposition. Overlapping entries stay legal (the upgrade overlap needs them).
		type series struct{ party, version, measurement, state string }
		counts, order := map[series]int{}, []series{}
		for _, e := range st.EntriesInForce {
			k := series{e.Party, e.Version, shortHex(e.Measurement), e.State}
			if counts[k]++; counts[k] == 1 {
				order = append(order, k)
			}
		}
		for _, k := range order {
			fmt.Fprintf(w, "qv_attest_broker_allowlist_entry{party=%q,version=%q,measurement=%q,state=%q} %d\n", k.party, k.version, k.measurement, k.state, counts[k])
		}
		for k, v := range s.rules {
			fmt.Fprintf(w, "qv_attest_broker_refusals_total{rule=%q} %d\n", k, v)
		}
		s.writeCertMetrics(w)
	})
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, _ *http.Request) { reply(w, http.StatusOK, s.Status()) })
	return mux
}

// Serve listens on cfg.Listen (mutual TLS 1.3, pinned callers) until ctx ends.
func (s *Server) Serve(ctx context.Context) error {
	tc, err := s.cfg.tlsConfig(s.set)
	if err != nil {
		return err
	}
	s.leafEnd.Store(leafNotAfter(tc))
	srv := &http.Server{Addr: s.cfg.Listen, Handler: s.Handler(), TLSConfig: tc, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second}
	errc := make(chan error, 2)
	go func() { errc <- srv.ListenAndServeTLS("", "") }()
	var hs *http.Server
	if s.cfg.HealthListen != "" {
		hs = &http.Server{Addr: s.cfg.HealthListen, Handler: s.HealthHandler(), ReadHeaderTimeout: 5 * time.Second}
		go func() { errc <- hs.ListenAndServe() }()
	}
	select {
	case <-ctx.Done():
	case err = <-errc:
	}
	sh, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if hs != nil {
		hs.Shutdown(sh)
	}
	srv.Shutdown(sh)
	return err
}

// tlsConfigForTest builds the listener config (tests start their own listener).
func (s *Server) tlsConfigForTest() (*tls.Config, error) { return s.cfg.tlsConfig(s.set) }

// caller identifies the TLS client: its key pin and the party that pin belongs to.
func (s *Server) caller(r *http.Request) (pin [32]byte, party string, ok bool) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return pin, "", false
	}
	pin = sha256.Sum256(r.TLS.PeerCertificates[0].RawSubjectPublicKeyInfo)
	party, ok = s.set.pins[pin]
	return pin, party, ok
}

func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	pin, party, ok := s.caller(r)
	if !ok {
		reply(w, http.StatusForbidden, attest.ErrorResponse{Error: "unknown_caller"})
		return
	}
	now := s.now()
	if !s.limit.allow(party, now) {
		s.count("rate_limited")
		_ = s.audit.Write(Record{Event: "challenge", Party: party, CallerPin: hex.EncodeToString(pin[:]), Outcome: "refused", Rule: "rate_limited"}, now)
		reply(w, http.StatusTooManyRequests, attest.ErrorResponse{Error: "rate_limited"})
		return
	}
	nonce, exp, err := s.nonces.issue(pin, now)
	if err != nil {
		s.count("challenge_busy")
		reply(w, http.StatusServiceUnavailable, attest.ErrorResponse{Error: "busy"})
		return
	}
	reply(w, http.StatusOK, attest.ChallengeResponse{Nonce: nonce, ExpiresAt: exp})
}

// refusal is a failed rule: code goes to the caller and the audit log, detail only to the log.
type refusal struct{ code, detail string }

func (e *refusal) Error() string { return e.code + ": " + e.detail }

func refuse(code, format string, a ...any) *refusal { return &refusal{code, fmt.Sprintf(format, a...)} }

func (s *Server) handleKeys(w http.ResponseWriter, r *http.Request, purpose string) {
	event := "release"
	if purpose == attest.PurposeCreate {
		event = "newkey"
	}
	pin, party, ok := s.caller(r)
	if !ok {
		reply(w, http.StatusForbidden, attest.ErrorResponse{Error: "unknown_caller"})
		return
	}
	now := s.now()
	rec := Record{Event: event, Party: party, CallerPin: hex.EncodeToString(pin[:]), Outcome: "refused"}
	done := func(status int, ref *refusal) {
		if ref != nil {
			rec.Rule, rec.Detail = ref.code, ref.detail
			s.count(event + "_refused")
			s.countRule(ref.code)
			if err := s.audit.Write(rec, now); err != nil {
				s.log.Printf("audit write failed: %v", err)
			}
			reply(w, status, attest.ErrorResponse{Error: ref.code})
		}
	}
	if !s.limit.allow(party, now) {
		done(http.StatusTooManyRequests, refuse("rate_limited", "party %s exceeded its rate", party))
		return
	}
	var req attest.ReleaseRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		done(http.StatusBadRequest, refuse("bad_request", "%v", err))
		return
	}
	rec.Nonce, rec.CtxParty, rec.Keyset, rec.Generations = hexs(req.Nonce), req.Context.Party, req.Context.Keyset, req.Context.Generations
	keys, ref := s.release(&rec, req, pin, party, purpose, now)
	if ref != nil {
		done(http.StatusForbidden, ref)
		return
	}
	rec.Outcome = "released"
	if err := s.audit.Write(rec, now); err != nil { // no key leaves without a record
		s.log.Printf("audit write failed, refusing: %v", err)
		s.count(event + "_refused")
		reply(w, http.StatusInternalServerError, attest.ErrorResponse{Error: "audit_failed"})
		return
	}
	s.count(event + "_ok")
	reply(w, http.StatusOK, attest.ReleaseResponse{Keys: keys})
}

// release runs every rule in order and returns the keys, each encrypted to the evidence's key, or the first failed rule.
func (s *Server) release(rec *Record, req attest.ReleaseRequest, pin [32]byte, party, purpose string, now time.Time) ([]attest.ReleasedKey, *refusal) {
	c := req.Context
	switch {
	case c.Validate() != nil:
		return nil, refuse("bad_request", "context: %v", c.Validate())
	case c.Purpose != purpose:
		return nil, refuse("bad_request", "purpose %q on the %s call", c.Purpose, purpose)
	case purpose == attest.PurposeUnseal && len(req.Blobs) != len(c.Generations):
		return nil, refuse("bad_request", "%d blobs for %d generations", len(req.Blobs), len(c.Generations))
	case purpose == attest.PurposeCreate && len(req.Blobs) != 0:
		return nil, refuse("bad_request", "newkey takes no blobs")
	case len(req.Nonce) == 0 || len(req.Evidence) == 0:
		return nil, refuse("bad_request", "nonce and evidence are required")
	case c.Party != party:
		return nil, refuse("caller_not_party", "caller key belongs to party %s, the request is for %s", party, c.Party)
	}
	if err := s.nonces.consume(req.Nonce, pin, now); err != nil {
		return nil, refuse("nonce:"+err.Error(), "challenge refused")
	}
	claims, err := s.verifier.Verify(req.Evidence, attest.Expect{Nonce: req.Nonce, UserData: c.UserData(req.Blobs, pin)}, now)
	if err != nil {
		return nil, refuse("verify:"+string(attest.RuleOf(err)), "%v", err)
	}
	rec.Measurement = claims.Measurement()
	if err := attest.CheckAllowlist(claims, c.Party, s.list.Load().Entries, now); err != nil {
		return nil, refuse("allowlist:"+string(attest.ReasonOf(err)), "%v", err)
	}
	if _, err := attest.ParseReleasePublicKey(claims.PublicKey); err != nil {
		return nil, refuse("bad_public_key", "%v", err)
	}
	out := make([]attest.ReleasedKey, 0, len(c.Generations))
	for i, g := range c.Generations {
		var key, blob []byte
		if purpose == attest.PurposeUnseal {
			key, err = s.keys.Unwrap(c.Party, c.Keyset, g, req.Blobs[i])
		} else {
			key, blob, err = s.keys.NewDataKey(c.Party, c.Keyset, g)
		}
		if err != nil {
			wipe(key)
			return nil, refuse("hsm_failed", "generation %d: %v", g, err)
		}
		sealed, err := attest.SealTo(claims.PublicKey, attest.ResponseAAD(c.UserData(req.Blobs, pin), req.Nonce, g), key)
		wipe(key)
		if err != nil {
			return nil, refuse("seal_failed", "%v", err)
		}
		out = append(out, attest.ReleasedKey{Generation: g, Blob: blob, Sealed: sealed})
	}
	return out, nil
}

// shortHex is the first 12 hex characters: enough to tell measurements apart in a metric label.
func shortHex(h string) string {
	h = strings.ToLower(h) // the list accepts either case; one release is one series
	if len(h) > 12 {
		return h[:12]
	}
	return h
}
