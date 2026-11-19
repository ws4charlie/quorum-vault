package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runCLI(t *testing.T, args ...string) (string, int) {
	t.Helper()
	var out, errw bytes.Buffer
	code := run(args, &out, &errw)
	return out.String() + errw.String(), code
}

// The operator workflow: keygen for two operators, a list is drafted, signed by one (not enough), then by both, and `show` says which.
func TestAllowlistToolFlow(t *testing.T) {
	dir := t.TempDir()
	p := func(n string) string { return filepath.Join(dir, n) }
	ops := map[string]any{}
	for _, n := range []string{"alice", "bob"} {
		if out, code := runCLI(t, "allowlist", "keygen", "-key", p(n+".key"), "-pub", p(n+".pub")); code != 0 {
			t.Fatalf("keygen: %s", out)
		}
		pub, _ := os.ReadFile(p(n + ".pub"))
		ops[n] = map[string]string{"public_key": strings.TrimSpace(string(pub))}
	}
	if _, code := runCLI(t, "allowlist", "keygen", "-key", p("alice.key")); code == 0 {
		t.Fatal("keygen overwrote an existing key")
	}
	cfg, _ := json.Marshal(map[string]any{"operators": map[string]any{"keys": ops, "min_operators": 2}})
	os.WriteFile(p("broker.json"), cfg, 0o600)

	m := strings.Repeat("ab", 48)
	if out, code := runCLI(t, "allowlist", "new", "-seq", "1", "-out", p("list.json"), "-entry", "A,"+m+",2026-01-01T00:00:00Z,2027-01-01T00:00:00Z"); code != 0 {
		t.Fatalf("new: %s", out)
	}
	if out, code := runCLI(t, "allowlist", "show", "-in", p("list.json"), "-operators", p("broker.json")); code == 0 || !strings.Contains(out, "NOT VALID") {
		t.Fatalf("an unsigned list shows as valid: %s", out)
	}
	if out, code := runCLI(t, "allowlist", "sign", "-in", p("list.json"), "-key", p("alice.key"), "-operator", "alice"); code != 0 || !strings.Contains(out, m) {
		t.Fatalf("sign must show what it signs: %s", out)
	}
	if out, code := runCLI(t, "allowlist", "show", "-in", p("list.json"), "-operators", p("broker.json")); code == 0 || !strings.Contains(out, "1 valid signatures") {
		t.Fatalf("one signature of two needed: %s", out)
	}
	runCLI(t, "allowlist", "sign", "-in", p("list.json"), "-key", p("bob.key"), "-operator", "bob")
	if out, code := runCLI(t, "allowlist", "show", "-in", p("list.json"), "-operators", p("broker.json")); code != 0 || !strings.Contains(out, "valid: signed by alice, bob") {
		t.Fatalf("two signatures: %s", out)
	}
	// editing an entry after signing breaks the signatures
	b, _ := os.ReadFile(p("list.json"))
	os.WriteFile(p("list.json"), []byte(strings.Replace(string(b), "2027-01-01", "2030-01-01", 1)), 0o644)
	if out, code := runCLI(t, "allowlist", "show", "-in", p("list.json"), "-operators", p("broker.json")); code == 0 {
		t.Fatalf("an edited list still verifies: %s", out)
	}
	// a key file other users can read is refused
	os.Chmod(p("bob.key"), 0o644)
	if _, code := runCLI(t, "allowlist", "sign", "-in", p("list.json"), "-key", p("bob.key"), "-operator", "bob"); code == 0 {
		t.Fatal("signed with a world-readable key")
	}
}

func TestUsage(t *testing.T) {
	if _, code := runCLI(t); code != 2 {
		t.Fatal("no arguments must print usage")
	}
	if _, code := runCLI(t, "serve", "-config", "/nonexistent"); code == 0 {
		t.Fatal("serve started without a config")
	}
}
