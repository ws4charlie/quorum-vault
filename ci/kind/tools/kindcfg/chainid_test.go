package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The lane's EVM chain id is decided in one place, ci/kind/lib.sh (default 84532, Base Sepolia): the anvil manifest takes it from there (install.sh fills it in), and no
// file of the lane carries a chain id of its own. anvil runs with Ethereum fee rules (--network ethereum): on a Base chain id it would charge an L1 fee no receipt shows.
func TestKindChainIDDecidedInLibOnly(t *testing.T) {
	root, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	// lib.sh, sourced as the lane's scripts do, with nothing set by the caller: the default
	cmd := exec.Command("bash", "-c", `. ci/kind/lib.sh >/dev/null && printf %s "$QV_KIND_CHAIN_ID" && sed "s/@QV_KIND_CHAIN_ID@/$QV_KIND_CHAIN_ID/g" ci/kind/deps/chains.yaml | grep -c -- "--chain-id $QV_KIND_CHAIN_ID --network ethereum\""`)
	cmd.Dir = root
	cmd.Env = withoutEnv("QV_KIND_CHAIN_ID")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sourcing lib.sh and rendering chains.yaml: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "845321" { // the id, then one anvil line with it in the rendered manifest
		t.Fatalf("lib.sh default and rendered anvil: got %q, want id 84532 and one '--chain-id 84532 --network ethereum' line (anvil hides Base's L1 fee, docs/limits.md)", got)
	}
	// no other copy of a chain id in the lane's files
	literal := regexp.MustCompile(`11155111|84532|--chain-id [0-9]|chain_id"?: ?[0-9]|ChainID: big\.NewInt\([0-9]`)
	for _, dir := range []string{"ci/kind", "loadtest/kind"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() && d.Name() == ".work" {
				return filepath.SkipDir
			}
			if d.IsDir() || strings.HasSuffix(p, "_test.go") || p == filepath.Join(root, "ci/kind/lib.sh") {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			for i, line := range strings.Split(string(b), "\n") {
				if literal.MatchString(line) {
					t.Errorf("%s:%d carries its own chain id (ci/kind/lib.sh decides it): %s", strings.TrimPrefix(p, root+"/"), i+1, strings.TrimSpace(line))
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestLaneChainIDFromEnv(t *testing.T) {
	t.Setenv("QV_KIND_CHAIN_ID", "84532")
	if id, err := laneChainID(); err != nil || id != 84532 {
		t.Fatalf("84532: got %d, %v", id, err)
	}
	for _, v := range []string{"", "0", "abc", "-1", "84532 ", "18446744073709551615"} {
		t.Setenv("QV_KIND_CHAIN_ID", v)
		if id, err := laneChainID(); err == nil {
			t.Errorf("QV_KIND_CHAIN_ID=%q: got %d, want an error (no default outside lib.sh)", v, id)
		}
	}
}

func withoutEnv(name string) []string {
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, name+"=") {
			env = append(env, kv)
		}
	}
	return env
}
