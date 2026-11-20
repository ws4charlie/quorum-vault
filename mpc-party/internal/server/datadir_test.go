package server_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/mpc-party/internal/server"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/testenv"
)

// Two parties on one data directory (two pods on one volume): the second refuses to start with a clear message; once the first has stopped,
// a new one starts. A party on another directory is not affected.
func TestSecondPartyOnTheSameDataDirRefusesToStart(t *testing.T) {
	env := testenv.NewEnv(t)
	cfg := env.Config(t, "A", testenv.FreeAddr(t), testenv.FreeAddr(t), "")
	opts := func() server.Options {
		return server.Options{Config: cfg, Authorizer: server.DenyAll{}, Store: testenv.Store(t, cfg)}
	}
	first, err := server.New(opts())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.New(opts()); err == nil {
		t.Fatal("a second party was created on the same data directory")
	} else if !strings.Contains(err.Error(), "in use by another mpc-party process") {
		t.Fatalf("unclear message: %v", err)
	}
	other := *cfg
	other.DataDir = cfg.DataDir + "-other"
	o, err := server.New(server.Options{Config: &other, Authorizer: server.DenyAll{}, Store: testenv.Store(t, &other)})
	if err != nil {
		t.Fatalf("another directory must not be affected: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	o.Shutdown(ctx)
	first.Shutdown(ctx)
	again, err := server.New(opts())
	if err != nil {
		t.Fatalf("after the first one stopped: %v", err)
	}
	again.Shutdown(ctx)
}
