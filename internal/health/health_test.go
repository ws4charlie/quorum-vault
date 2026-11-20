package health

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func get(t *testing.T, h http.Handler, method, path string) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	b, _ := io.ReadAll(rec.Result().Body)
	return rec.Code, string(b)
}

func TestLiveAlwaysReadyOnlyWhenStartedAndChecksPass(t *testing.T) {
	p := New(nil)
	h := p.Handler()
	if c, body := get(t, h, "GET", "/livez"); c != 200 || strings.TrimSpace(body) != "ok" {
		t.Fatalf("livez before start: %d %q", c, body)
	}
	if c, _ := get(t, h, "GET", "/readyz"); c != 503 {
		t.Fatalf("readyz before SetReady: %d, want 503", c)
	}
	var dbErr error
	p.Check("database", func(context.Context) error { return dbErr })
	p.SetReady(true)
	if c, _ := get(t, h, "GET", "/readyz"); c != 200 {
		t.Fatalf("readyz ready: %d", c)
	}
	dbErr = errors.New("connection refused to db.internal:5432 as user qv_core")
	c, body := get(t, h, "GET", "/readyz")
	if c != 503 {
		t.Fatalf("readyz with a failing check: %d, want 503", c)
	}
	if strings.Contains(body, "db.internal") || strings.Contains(body, "qv_core") || strings.Contains(body, "database") {
		t.Fatalf("the answer must carry no detail, got %q", body)
	}
	if c, _ := get(t, h, "GET", "/livez"); c != 200 {
		t.Fatalf("a failing dependency must not fail liveness: %d", c)
	}
	dbErr = nil
	p.SetReady(false) // stopping
	if c, _ := get(t, h, "GET", "/readyz"); c != 503 {
		t.Fatalf("readyz while stopping: %d, want 503", c)
	}
}

func TestOnlyTheTwoRoutesAndOnlyReads(t *testing.T) {
	p := New(nil)
	p.SetReady(true)
	h := p.Handler()
	for _, path := range []string{"/", "/metrics", "/debug/pprof/", "/healthz", "/readyz/x", "/livez/"} {
		if c, _ := get(t, h, "GET", path); c != 404 {
			t.Errorf("GET %s = %d, want 404", path, c)
		}
	}
	for _, m := range []string{"POST", "PUT", "DELETE"} {
		if c, _ := get(t, h, m, "/livez"); c != 405 {
			t.Errorf("%s /livez = %d, want 405", m, c)
		}
	}
	if c, body := get(t, h, "HEAD", "/readyz"); c != 200 || body != "" {
		t.Errorf("HEAD /readyz = %d %q", c, body)
	}
}

func TestHungCheckIsBounded(t *testing.T) {
	p := New(nil)
	p.SetReady(true)
	p.Check("slow", func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() })
	start := time.Now()
	if err := p.Ready(context.Background()); err == nil {
		t.Fatal("a check that times out must fail readiness")
	}
	if d := time.Since(start); d > CheckTimeout+time.Second {
		t.Fatalf("took %s", d)
	}
}

func TestServeMarksNotReadyWhenContextEnds(t *testing.T) {
	p := New(nil)
	p.SetReady(true)
	ctx, cancel := context.WithCancel(context.Background())
	stop, err := p.Serve(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	cancel()
	deadline := time.Now().Add(2 * time.Second)
	for p.Ready(context.Background()) == nil {
		if time.Now().After(deadline) {
			t.Fatal("still ready after the context ended")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if stop, err := p.Serve(context.Background(), ""); err != nil || stop == nil {
		t.Fatal("an empty address must be a no-op")
	}
}
