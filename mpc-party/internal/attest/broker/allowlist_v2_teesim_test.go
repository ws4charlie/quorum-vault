//go:build teesim

package broker

import (
	"context"
	"encoding/hex"
	"io"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/mpc-party/internal/attest"
)

// A revoked entry stops key release at the next request, beats an overlapping active entry, and a list without an end date works.
func TestRevokedEntryWinsAndNoEndDateWorks(t *testing.T) {
	r := newRig(t, rigOpts{})
	now := r.clk.Now()
	mA := hex.EncodeToString(r.meas["A"])
	e := r.enclave("A")
	blobs, _ := e.newKeys(ctxOf("A", "k", attest.PurposeCreate, 1))
	rel := func() error {
		_, err := e.cl.Release(context.Background(), e.prepare(ctxOf("A", "k", attest.PurposeUnseal, 1), blobs, nil))
		return err
	}
	open := attest.AllowEntry{Party: "A", Measurement: mA, NotBefore: now.Add(-time.Hour), Version: "v1.0.0"} // no end
	b := attest.AllowEntry{Party: "B", Measurement: hex.EncodeToString(r.meas["B"]), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	r.writeList([]attest.AllowEntry{open, b}, 2, 2)
	if err := r.srv.Reload(); err != nil {
		t.Fatal(err)
	}
	r.clk.Advance(10 * time.Hour) // B's window has ended (the mock CA lives 24 h): an entry without an end still allows
	if err := rel(); err != nil {
		t.Fatalf("entry without an end after 10 h: %v", err)
	}
	st := r.srv.Status()
	if st.AllowlistSeq != 2 || st.Allowing != 1 || st.OutsideWindow != 1 {
		t.Fatalf("status %+v", st)
	}
	revoked := attest.AllowEntry{Party: "A", Measurement: mA, NotBefore: now, Version: "v1.0.0", Status: attest.StatusRevoked}
	r.writeList([]attest.AllowEntry{open, revoked, b}, 2, 3) // the active entry is still in the list: the revocation wins
	if err := r.srv.Reload(); err != nil {
		t.Fatal(err)
	}
	wantRefusal(t, rel(), "allowlist:revoked")
	if rec := r.lastRecord(); rec.Rule != "allowlist:revoked" || rec.Measurement != mA {
		t.Fatalf("audit: %+v", rec)
	}
	if st := r.srv.Status(); st.Revoked != 1 || st.RefusalsByRule["allowlist:revoked"] != 1 {
		t.Fatalf("status %+v", st)
	}
}

// An older list that was valid once is refused at a restart too: the floor comes from the audit log.
func TestOldListIsRefusedAtRestart(t *testing.T) {
	r := newRig(t, rigOpts{noStart: true})
	srv, err := Open(r.cfg, Options{Now: r.clk.Now}) // list sequence 1
	if err != nil {
		t.Fatal(err)
	}
	now := r.clk.Now()
	old, _ := readFile(r.cfg.AllowlistFile)
	entries := []attest.AllowEntry{{Party: "A", Measurement: hex.EncodeToString(r.meas["A"]), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}}
	r.writeList(entries, 2, 5)
	if err := srv.Reload(); err != nil || srv.Sequence() != 5 {
		t.Fatalf("reload: %v", err)
	}
	srv.Close()
	// the host puts the old signed list back while the broker is down
	writeFile(t, r.cfg.AllowlistFile, old)
	if s, err := Open(r.cfg, Options{Now: r.clk.Now}); err == nil {
		s.Close()
		t.Fatal("the broker started on an older list")
	} else if !strings.Contains(err.Error(), "older") {
		t.Fatalf("error does not say why: %v", err)
	}
	// the same sequence again (a plain restart) and a higher one start
	r.writeList(entries, 2, 5)
	s, err := Open(r.cfg, Options{Now: r.clk.Now})
	if err != nil {
		t.Fatalf("restart on the list in force: %v", err)
	}
	s.Close()
	r.writeList(entries, 2, 6)
	if s, err = Open(r.cfg, Options{Now: r.clk.Now}); err != nil || s.Sequence() != 6 {
		t.Fatalf("restart on a newer list: %v", err)
	}
	s.Close()
}

// The version in force and the refusals are in /status and /metrics.
func TestStatusAndMetrics(t *testing.T) {
	r := newRig(t, rigOpts{})
	now := r.clk.Now()
	r.writeList([]attest.AllowEntry{{Party: "A", Measurement: hex.EncodeToString(r.meas["A"]), NotBefore: now.Add(-time.Hour), Version: "v2.0.0"}}, 2, 7)
	_ = r.srv.Reload()
	_ = r.srv.Reload() // identical content: no-op
	writeFile(t, r.cfg.AllowlistFile, []byte("{garbage"))
	_ = r.srv.Reload()
	rec := httptest.NewRecorder()
	r.srv.HealthHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body, _ := io.ReadAll(rec.Result().Body)
	for _, want := range []string{
		"qv_attest_broker_allowlist_sequence 7",
		`qv_attest_broker_allowlist_entries{state="allowing"} 1`,
		`qv_attest_broker_allowlist_entry{party="A",version="v2.0.0",measurement="` + hex.EncodeToString(r.meas["A"])[:12] + `",state="allowing"} 1`,
		`qv_attest_broker_events_total{event="reload_refused"} 1`,
		"qv_attest_broker_allowlist_loaded_at_seconds",
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("metrics lack %q:\n%s", want, body)
		}
	}
	rec = httptest.NewRecorder()
	r.srv.HealthHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/status", nil))
	sb, _ := io.ReadAll(rec.Result().Body)
	if !strings.Contains(string(sb), `"allowlist_seq":7`) || !strings.Contains(string(sb), `"version":"v2.0.0"`) || !strings.Contains(string(sb), `"reload_refusals":1`) {
		t.Errorf("status: %s", sb)
	}
}

func readFile(p string) ([]byte, error) { return os.ReadFile(p) }

func writeFile(t *testing.T, p string, b []byte) {
	t.Helper()
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
}
