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

// Upgrade and revoke through the tool: add copies the list with the next sequence and no signatures; sign -against prints what changes; expire
// sets valid-until; revoke adds a revocation that stays in the list.
func TestAllowlistEditTools(t *testing.T) {
	dir := t.TempDir()
	p := func(n string) string { return filepath.Join(dir, n) }
	v1, v2 := strings.Repeat("a1", 48), strings.Repeat("b2", 48)
	if out, code := runCLI(t, "allowlist", "new", "-seq", "4", "-out", p("l4.json"), "-entry", "A,"+v1+",2026-01-01T00:00:00Z,,v1.0.0"); code != 0 {
		t.Fatalf("new without an end: %s", out)
	}
	if b, _ := os.ReadFile(p("l4.json")); strings.Contains(string(b), "not_after") || !strings.Contains(string(b), "v1.0.0") {
		t.Fatalf("new: %s", b)
	}
	if out, code := runCLI(t, "allowlist", "add", "-in", p("l4.json"), "-out", p("l5.json"), "-party", "A", "-measurement", strings.ToUpper(v2), "-version", "v1.1.0", "-not-before", "2026-02-01T00:00:00Z"); code != 0 || !strings.Contains(out, "sequence 5, 2 entries, 0 signatures") {
		t.Fatalf("add: %s", out)
	}
	if out, code := runCLI(t, "allowlist", "add", "-in", p("l5.json"), "-out", p("x.json"), "-party", "A", "-measurement", v2); code == 0 {
		t.Fatalf("add of an existing measurement: %s", out)
	}
	if out, code := runCLI(t, "allowlist", "expire", "-in", p("l5.json"), "-out", p("l6.json"), "-party", "A", "-measurement", v1, "-not-after", "2026-03-01T00:00:00Z"); code != 0 {
		t.Fatalf("expire: %s", out)
	}
	if out, code := runCLI(t, "allowlist", "expire", "-in", p("l5.json"), "-out", p("x.json"), "-party", "A", "-measurement", "cc", "-not-after", "2026-03-01T00:00:00Z"); code == 0 {
		t.Fatalf("expire of an unknown measurement: %s", out)
	}
	if out, code := runCLI(t, "allowlist", "revoke", "-in", p("l6.json"), "-out", p("l7.json"), "-party", "A", "-measurement", v1); code != 0 || !strings.Contains(out, "sequence 7, 3 entries") {
		t.Fatalf("revoke: %s", out)
	}
	if out, code := runCLI(t, "allowlist", "revoke", "-in", p("l7.json"), "-out", p("x.json"), "-party", "A", "-measurement", v1); code == 0 {
		t.Fatalf("revoke twice: %s", out)
	}
	// the operator sees the difference to the list in force before signing
	runCLI(t, "allowlist", "keygen", "-key", p("k.key"))
	out, code := runCLI(t, "allowlist", "sign", "-in", p("l7.json"), "-key", p("k.key"), "-operator", "alice", "-against", p("l4.json"), "-out", p("l7s.json"))
	if code != 0 || !strings.Contains(out, "against sequence 4") || !strings.Contains(out, "+ A "+v2) || !strings.Contains(out, "revoked") || !strings.Contains(out, "~ A "+v1) {
		t.Fatalf("sign -against: %s", out)
	}
	// an older list than the one given with -against is flagged
	if out, _ := runCLI(t, "allowlist", "show", "-in", p("l4.json"), "-against", p("l7.json")); !strings.Contains(out, "WARNING") {
		t.Fatalf("no warning for an older list: %s", out)
	}
}

// The tool refuses to read, show, sign or edit a file it cannot parse strictly (a misspelled not_after must not become "no end" in a list that gets signed).
func TestToolRefusesUnknownFields(t *testing.T) {
	dir := t.TempDir()
	p := func(n string) string { return filepath.Join(dir, n) }
	m := strings.Repeat("a1", 48)
	if out, code := runCLI(t, "allowlist", "new", "-seq", "1", "-out", p("ok.json"), "-entry", "A,"+m+",2026-01-01T00:00:00Z,2026-06-01T00:00:00Z"); code != 0 {
		t.Fatalf("new: %s", out)
	}
	good, _ := os.ReadFile(p("ok.json"))
	bad := strings.Replace(string(good), `"not_after"`, `"not_atfer"`, 1)
	if bad == string(good) {
		t.Fatal("test file has no not_after to misspell")
	}
	os.WriteFile(p("bad.json"), []byte(bad), 0o600)
	runCLI(t, "allowlist", "keygen", "-key", p("k.key"))
	for name, args := range map[string][]string{
		"show":   {"allowlist", "show", "-in", p("bad.json")},
		"sign":   {"allowlist", "sign", "-in", p("bad.json"), "-key", p("k.key"), "-operator", "alice", "-out", p("s.json")},
		"revoke": {"allowlist", "revoke", "-in", p("bad.json"), "-out", p("r.json"), "-party", "A", "-measurement", m},
		"touch":  {"allowlist", "touch", "-in", p("bad.json"), "-out", p("t.json")},
	} {
		if out, code := runCLI(t, args...); code == 0 {
			t.Errorf("%s accepted a file with an unknown field: %s", name, out)
		}
	}
	if _, err := os.Stat(p("s.json")); err == nil {
		t.Error("a signed copy of the bad file was written")
	}
}

// A Nitro image enters the list with its further PCRs (nitro-cli build-enclave prints them); they are in the file, in what the operators sign, and a
// malformed one is refused at once.
func TestAllowlistAddNitroPCRs(t *testing.T) {
	dir := t.TempDir()
	p := func(n string) string { return filepath.Join(dir, n) }
	if out, code := runCLI(t, "allowlist", "new", "-seq", "1", "-out", p("l1.json"), "-entry", "A,"+strings.Repeat("ab", 48)+",2026-01-01T00:00:00Z,"); code != 0 {
		t.Fatalf("new: %s", out)
	}
	m, p1, p2 := strings.Repeat("cd", 48), strings.Repeat("11", 48), strings.Repeat("2f", 48)
	out, code := runCLI(t, "allowlist", "add", "-in", p("l1.json"), "-out", p("l2.json"), "-party", "A", "-measurement", m, "-version", "v2",
		"-pcr", "1="+p1, "-pcr", "2="+strings.ToUpper(p2))
	if code != 0 {
		t.Fatalf("add: %s", out)
	}
	b, _ := os.ReadFile(p("l2.json"))
	if !strings.Contains(string(b), `"pcrs"`) || !strings.Contains(string(b), p2) || strings.Contains(string(b), strings.ToUpper(p2)) {
		t.Fatalf("the PCRs are not in the file in lower case: %s", b)
	}
	for _, bad := range []string{"1", "0=" + p1, "3=zz", "2=" + p1[:90]} {
		if _, code := runCLI(t, "allowlist", "add", "-in", p("l1.json"), "-out", p("x.json"), "-party", "A", "-measurement", m, "-pcr", bad); code == 0 {
			t.Fatalf("-pcr %q accepted", bad)
		}
	}
}
