package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/gateway"
)

func TestLikeSignsTheSameRouteChangeMinutesLater(t *testing.T) {
	dir := t.TempDir()
	key := func(n string) string {
		_, priv, _ := ed25519.GenerateKey(nil)
		p := filepath.Join(dir, n+".key")
		os.WriteFile(p, []byte(hex.EncodeToString(priv.Seed())), 0o600)
		return p
	}
	t0 := time.Unix(1_800_000_000, 0)
	sign := func(now time.Time, args ...string) (string, error) {
		var o, e bytes.Buffer
		err := signTo(args, &o, &e, func() time.Time { return now })
		return e.String(), err
	}
	a, b := filepath.Join(dir, "a.json"), filepath.Join(dir, "b.json")
	if _, err := sign(t0, "-actor", "alice", "-key", key("alice"), "-pair", "A+C", "-seq", "5", "-out", a); err != nil {
		t.Fatal(err)
	}
	said, err := sign(t0.Add(6*time.Minute), "-actor", "bob", "-key", key("bob"), "-like", a, "-out", b)
	if err != nil || !strings.Contains(said, "pair A+C, sequence 5") || !strings.Contains(said, "6m0s ago") {
		t.Fatalf("%v\n%s", err, said)
	}
	load := func(p string) gateway.RouteChange {
		c, err := readChange(p)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	if _, err := gateway.MergeRoute(load(a), load(b)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]string{{"-pair", "B+C"}, {"-seq", "6"}, {"-signed-at", "1"}} {
		if _, err := sign(t0, append([]string{"-actor", "bob", "-key", key("bob"), "-like", a}, bad...)...); err == nil || !strings.Contains(err.Error(), "disagrees") {
			t.Errorf("%v: %v", bad, err)
		}
	}
	if _, err := sign(t0, "-actor", "alice", "-key", key("alice"), "-like", a); err == nil {
		t.Error("same approver twice accepted")
	}
}
