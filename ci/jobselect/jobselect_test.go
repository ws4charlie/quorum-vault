package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// ---- helpers -----------------------------------------------------------------------------------------------------------------------------------------

const z40 = "0000000000000000000000000000000000000000"

func rec(status byte, path string) string {
	switch status {
	case 'A':
		return fmt.Sprintf(":000000 100644 %s %s A\x00%s\x00", z40, z40, path)
	case 'D':
		return fmt.Sprintf(":100644 000000 %s %s D\x00%s\x00", z40, z40, path)
	}
	return fmt.Sprintf(":100644 100644 %s %s M\x00%s\x00", z40, z40, path)
}

// runOf turns the selector's answer into the set of jobs that run (nil: all of them).
func runOf(t *testing.T, w *world, out string) set {
	t.Helper()
	if strings.HasPrefix(out, "all ") {
		return nil
	}
	if !strings.HasPrefix(out, "skip") {
		t.Fatalf("unexpected answer %q", out)
	}
	skip := set{}
	for _, j := range strings.Fields(strings.TrimPrefix(out, "skip")) {
		skip[j] = true
	}
	run := set{}
	for _, j := range w.cfg.jobs {
		if !skip[j.id] {
			run[j.id] = true
		}
	}
	return run
}

func names(s set) string {
	if s == nil {
		return "ALL"
	}
	return strings.Join(sorted(s), " ")
}

func write(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func thisRepo(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Skip("not in a git checkout")
	}
	return strings.TrimSpace(string(out))
}

// ---- a scratch repository: every rule of the decision, with a small graph ----------------------------------------------------------------------------

const scratchJobs = `module .
mains-exclude tools/
nobuild test
job test .:./...
job e2e-y .:./e2e/y/... @mains
job e2e-z .:./e2e/z/... @mains
job lib-only .:./lib/...
`

const scratchCI = `name: ci
on: pull_request
jobs:
  changes:
    runs-on: x
  build:
    runs-on: x
  test:
    needs: changes
    if: ${{ contains(needs.changes.outputs.skip_jobs, ',test,') }}
  e2e-y:
    needs: [changes, build]
    if: ${{ !contains(needs.changes.outputs.skip_jobs, ',e2e-y,') }}
  e2e-z:
    needs: [changes, build]
    if: ${{ !contains(needs.changes.outputs.skip_jobs, ',e2e-z,') }}
    steps:
      - run: make tool-target
  lib-only:
    needs: [changes, build]
    if: ${{ !contains(needs.changes.outputs.skip_jobs, ',lib-only,') }}
`

func scratch(t *testing.T, exceptions string, extra map[string]string) string {
	t.Helper()
	real := thisRepo(t)
	root := t.TempDir()
	files := map[string]string{
		"go.mod":                     "module example.test/s\n\ngo 1.21\n",
		"cmd/app/main.go":            "package main\n\nimport (\n\t_ \"example.test/s/internal/a\"\n\t_ \"example.test/s/internal/tagged\"\n)\n\nfunc main() {}\n",
		"internal/a/a.go":            "package a\n",
		"internal/a/testdata/gen.go": "package gen\n",
		"internal/b/b.go":            "package b\n",
		"internal/c/c.go":            "package c\n",
		"internal/d/d.go":            "package d\n",
		"internal/d/d_other.go":      "//go:build windows\n\npackage d\n",
		"internal/onlytest/x.go":     "package onlytest\n",
		"internal/tagged/t.go":       "package tagged\n",
		"internal/tagged/t_dev.go":   "//go:build devauth\n\npackage tagged\n\nimport _ \"example.test/s/internal/c\"\n",
		"e2e/y/y_test.go":            "package y\n\nimport (\n\t\"path/filepath\"\n\t\"testing\"\n\n\t_ \"example.test/s/internal/b\"\n)\n\nfunc TestY(t *testing.T) { _ = filepath.Join(\"..\", \"..\", \"data\", \"x.json\") } // reads data/\n",
		"e2e/z/z_test.go":            "package z\n\nimport \"testing\"\n\nfunc TestZ(t *testing.T) {}\n",
		"lib/l.go":                   "package lib\n",
		"lib/l_test.go":              "package lib\n",
		"tools/tool/main.go":         "package main\n\nfunc main() {}\n",
		"tools/data.yaml":            "x: 1\n",
		"data/x.json":                "{}\n",
		"docs/a.md":                  "doc\n",
		"Makefile":                   "DATA := data/x.json\n\ntool-target:\n\tgo run ./tools/tool\n\nother:\n\techo data/x.json\n",
		".github/workflows/ci.yml":   scratchCI,
		"ci/jobs":                    scratchJobs,
		"ci/job-rules":               "tools/*\ndata/*\n",
		"ci/job-rules-exceptions":    exceptions,
		"ci/job-readers":             "",
	}
	for k, v := range extra {
		files[k] = v
	}
	for rel, body := range files {
		write(t, root, rel, body)
	}
	for _, f := range []string{"classify.sh", "skip-allowlist", "skip-module-exceptions"} {
		b, err := os.ReadFile(filepath.Join(real, "ci", f))
		if err != nil {
			t.Fatal(err)
		}
		write(t, root, "ci/"+f, string(b))
	}
	if err := os.Chmod(filepath.Join(root, "ci", "classify.sh"), 0o755); err != nil {
		t.Fatal(err)
	}
	git(t, root, "init", "-q")
	git(t, root, "add", "-A")
	return root
}

const okExceptions = "data/\tMakefile\t1\tDATA := data/x.json\t-\tused by no target\n"

func TestMain(m *testing.M) {
	logw = io.Discard
	os.Exit(m.Run())
}

func TestDecisionsInAScratchRepository(t *testing.T) {
	root := scratch(t, okExceptions, nil)
	w, err := load(root)
	if err != nil {
		t.Fatal(err)
	}
	mk := func(js ...string) set {
		s := set{}
		for _, j := range js {
			s[j] = true
		}
		return s
	}
	const ALL = "ALL"
	cases := []struct {
		desc string
		raw  string
		want any // set or ALL
	}{
		{"a test file: only the jobs that test its package", rec('M', "e2e/y/y_test.go"), mk("test", "e2e-y")},
		{"a package only a test imports: the jobs that test that test", rec('M', "internal/b/b.go"), mk("test", "e2e-y")},
		{"a package a main imports: every @mains job", rec('M', "internal/a/a.go"), mk("test", "e2e-y", "e2e-z")},
		{"a package imported only under -tags devauth: the union of the tag sets", rec('M', "internal/c/c.go"), mk("test", "e2e-y", "e2e-z")},
		{"a file of another platform: all", rec('M', "internal/d/d_other.go"), ALL},
		{"a test file of lib", rec('M', "lib/l_test.go"), mk("test", "lib-only")},
		{"a package nobody imports: only test (and no image)", rec('M', "internal/onlytest/x.go"), mk("test")},
		{"a .go file under testdata: all (data)", rec('M', "internal/a/testdata/gen.go"), ALL},
		{"a new file in a new directory that is not a package: all", rec('A', "newpkg/x.go"), ALL},
		{"a deleted file of a package that remains", rec('D', "lib/gone.go"), mk("test", "lib-only")},
		{"a deleted test file of a package that remains", rec('D', "lib/gone_test.go"), mk("test", "lib-only")},
		{"a deleted file whose directory is gone: all", rec('D', "gone/x.go"), ALL},
		{"a rule tree: its packages and the Makefile recipe ci.yml's e2e-z calls", rec('M', "tools/data.yaml"), mk("test", "e2e-z")},
		{"a Go file in a rule tree: its package and the tree's readers", rec('M', "tools/tool/main.go"), mk("test", "e2e-z")},
		{"a rule tree read by a test (the Go join form) and a reviewed Makefile line", rec('M', "data/x.json"), mk("test", "e2e-y")},
		{"docs on the allowlist: nothing", rec('M', "docs/a.md"), mk()},
		{"docs with a test file", rec('M', "docs/a.md") + rec('M', "e2e/z/z_test.go"), mk("test", "e2e-z")},
		{"two files: the union", rec('M', "e2e/y/y_test.go") + rec('M', "lib/l.go"), mk("test", "e2e-y", "lib-only")},
		{"an unknown path: all", rec('M', "newdir/x.txt"), ALL},
		{"one unknown path among known ones: all", rec('M', "lib/l.go") + rec('A', "newdir/x.txt"), ALL},
		{"go.mod: all", rec('M', "go.mod"), ALL},
		{"go.sum: all", rec('M', "go.sum"), ALL},
		{"a workflow: all", rec('M', ".github/workflows/ci.yml"), ALL},
		{"the selector's table: all", rec('M', "ci/jobs"), ALL},
		{"the selector itself: all", rec('M', "ci/jobselect/main.go"), ALL},
		{"the Makefile: all", rec('M', "Makefile"), ALL},
		{"an ignored .go file name: all", rec('A', "lib/_x.go"), ALL},
		{"empty change list: all", "", ALL},
		{"a mode change: all", fmt.Sprintf(":100644 100755 %s %s M\x00lib/l.go\x00", z40, z40), ALL},
		{"a symlink: all", fmt.Sprintf(":000000 120000 %s %s A\x00lib/link.go\x00", z40, z40), ALL},
		{"a submodule: all", fmt.Sprintf(":000000 160000 %s %s A\x00lib/sub\x00", z40, z40), ALL},
		{"a rename record: all", fmt.Sprintf(":100644 100644 %s %s R100\x00lib/l.go\x00lib/m.go\x00", z40, z40), ALL},
		{"a truncated record: all", rec('M', "lib/l.go") + ":100644", ALL},
		{"an odd path: all", rec('M', "lib/../go.mod"), ALL},
		{"an executable script kept executable is a plain change", fmt.Sprintf(":100755 100755 %s %s M\x00tools/run.sh\x00", z40, z40), mk("test", "e2e-z")},
	}
	for _, c := range cases {
		out := selectJobs(root, []byte(c.raw))
		got := runOf(t, w, out)
		switch want := c.want.(type) {
		case string:
			if got != nil {
				t.Errorf("%s: want all, got %s (%q)", c.desc, names(got), out)
			}
		case set:
			if got == nil || names(got) != names(want) {
				t.Errorf("%s: want %s, got %s (%q)", c.desc, names(want), names(got), out)
			}
		}
	}
	// the build job is never in the list (it starts with `changes` and always runs)
	for _, f := range []string{"internal/onlytest/x.go", "lib/l.go", "docs/a.md"} {
		if out := selectJobs(root, []byte(rec('M', f))); strings.Contains(out, "build") {
			t.Errorf("%s: the build job is never skipped: %q", f, out)
		}
	}
	// more than maxFiles
	var many strings.Builder
	for i := 0; i <= maxFiles; i++ {
		many.WriteString(rec('M', fmt.Sprintf("lib/f%d.go", i)))
	}
	if out := selectJobs(root, []byte(many.String())); !strings.HasPrefix(out, "all ") {
		t.Errorf("%d files: want all, got %q", maxFiles+1, out)
	}
}

func TestAlwaysJobsAndPathReaders(t *testing.T) {
	// `always test`: a change test's packages do not compile (a rule tree no Go package reads) still runs test
	root := scratch(t, okExceptions, map[string]string{"ci/jobs": strings.Replace(scratchJobs, "nobuild test\n", "nobuild test\nalways test\n", 1)})
	w, err := load(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := runOf(t, w, selectJobs(root, []byte(rec('M', "tools/data.yaml")))); names(got) != "e2e-z test" {
		t.Errorf("always: got %s", names(got))
	}
	// a reviewed reader by path: a file matching its globs adds the reader's jobs (here a test of lib reads data/ by a relative path)
	extra := map[string]string{
		"lib/r_test.go":  "package lib\n\nimport \"os\"\n\nvar _, _ = os.ReadFile(\"../data/x.json\")\n",
		"ci/job-readers": "lib/r_test.go\t1\tdata/*\treads data\n",
	}
	root = scratch(t, okExceptions, extra)
	w, _ = load(root)
	if got := runOf(t, w, selectJobs(root, []byte(rec('M', "data/x.json")))); names(got) != "e2e-y lib-only test" {
		t.Errorf("a reader by path adds its jobs: got %s", names(got))
	}
	// an unlisted reader by path, or a wrong count, fails check
	for desc, readers := range map[string]string{"unlisted": "", "wrong count": "lib/r_test.go\t2\tdata/*\tx\n"} {
		extra["ci/job-readers"] = readers
		root = scratch(t, okExceptions, extra)
		if p := check(root); !hasProblem(p, "lib/r_test.go") {
			t.Errorf("%s reader: check must name lib/r_test.go: %v", desc, p)
		}
	}
}

func hasProblem(ps []string, sub string) bool {
	for _, p := range ps {
		if strings.Contains(p, sub) {
			return true
		}
	}
	return false
}

func TestReadersThatAreNotReviewedRunEverything(t *testing.T) {
	cases := []struct {
		desc, exceptions string
		extra            map[string]string
	}{
		{"no exception for a Makefile variable line", "", nil},
		{"the exception counts two lines, there is one", "data/\tMakefile\t2\tDATA := data/x.json\t-\tx\n", nil},
		{"the exception's text no longer matches", "data/\tMakefile\t1\tDATA := data/y.json\t-\tx\n", nil},
		{"a script names the tree", okExceptions, map[string]string{"scripts/run.sh": "#!/bin/sh\ncat data/x.json\n"}},
		{"a compose file mounts the tree", okExceptions, map[string]string{"docker-compose.yml": "services:\n  a:\n    volumes:\n      - ./data:/d\n"}},
		{"a Go file in a directory that is not a package names the tree", okExceptions, map[string]string{"internal/a/testdata/r.go": "package r\nvar p = \"data/x.json\"\n"}},
	}
	for _, c := range cases {
		root := scratch(t, c.exceptions, c.extra)
		w, err := load(root)
		if err != nil {
			t.Fatalf("%s: %v", c.desc, err)
		}
		out := selectJobs(root, []byte(rec('M', "data/x.json")))
		if got := runOf(t, w, out); got != nil {
			t.Errorf("%s: want all, got %s (%q)", c.desc, names(got), out)
		}
	}
	// a reader in a Go comment, in a Go message, or in another workflow is not a reader (control)
	root := scratch(t, okExceptions, map[string]string{
		"lib/c.go":                    "package lib\n\n// see data/x.json\nvar _ = 1 // data/x.json\n",
		".github/workflows/other.yml": "on: push\njobs:\n  a:\n    steps:\n      - run: cat data/x.json\n",
	})
	w, err := load(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := runOf(t, w, selectJobs(root, []byte(rec('M', "data/x.json")))); names(got) != "e2e-y test" {
		t.Errorf("comments and another workflow are not readers: got %s", names(got))
	}
	// a Go string that names the tree is a reader: its package's jobs are added
	root = scratch(t, okExceptions, map[string]string{"lib/c.go": "package lib\n\nvar P = \"data/x.json\"\n"})
	w, _ = load(root)
	if got := runOf(t, w, selectJobs(root, []byte(rec('M', "data/x.json")))); names(got) != "e2e-y lib-only test" {
		t.Errorf("a Go reader adds the jobs that compile it: got %s", names(got))
	}
}

func TestBrokenConfigurationRunsEverything(t *testing.T) {
	cases := map[string]map[string]string{
		"no ci/jobs":                             {"ci/jobs": ""},
		"a job with a root that matches nothing": {"ci/jobs": scratchJobs + "job x .:./nothing/...\n"},
		"an unknown directive":                   {"ci/jobs": scratchJobs + "frobnicate\n"},
		"a bad rule":                             {"ci/job-rules": "tools\n"},
		"a rule over all of ci":                  {"ci/job-rules": "ci/*\n"},
		"an exception for an unknown job":        {"ci/job-rules-exceptions": "data/\tMakefile\t1\tDATA\tnope\tx\n"},
		// go list reads only the package clause and the imports: a broken import block is an error (a broken body does not change the graph; the
		// test job fails on it)
		"a broken import block": {"lib/l.go": "package lib\n\nimport (\n\t\"example.test/s/internal/a\"\n"},
	}
	for desc, extra := range cases {
		root := scratch(t, okExceptions, extra)
		if out := selectJobs(root, []byte(rec('M', "lib/l_test.go"))); !strings.HasPrefix(out, "all ") {
			t.Errorf("%s: want all, got %q", desc, out)
		}
	}
}

// ---- small pieces --------------------------------------------------------------------------------------------------------------------------------------

func TestGlobStar(t *testing.T) {
	for _, c := range []struct {
		g, s string
		want bool
	}{
		{"docs/*.md", "docs/a.md", true}, {"docs/*.md", "docs/x/y.md", true}, {"docs/*.md", "docs/a.go", false},
		{"README.md", "README.md", true}, {"README.md", "x/README.md", false}, {"ci/helm/*", "ci/helm/a/b", true},
		{"a*b*c", "abc", true}, {"a*b*c", "ac", false}, {"*", "x", true},
	} {
		if got := globStar(c.g, c.s); got != c.want {
			t.Errorf("globStar(%q, %q) = %v", c.g, c.s, got)
		}
	}
}

func TestCodeOf(t *testing.T) {
	for in, want := range map[string]string{
		`x := "a//b" // c`:     `x := "a//b" `,
		"x := `a//b` // c":     "x := `a//b` ",
		`x := '/' // c`:        `x := '/' `,
		`s := "q\"//" // c`:    `s := "q\"//" `,
		`u := "http://x/data"`: `u := "http://x/data"`,
	} {
		if got := codeOf("a.go", in); got != want {
			t.Errorf("codeOf(%q) = %q, want %q", in, got, want)
		}
	}
	if got := codeOf("a.sh", "echo // x"); got != "echo // x" {
		t.Errorf("non-Go lines are kept: %q", got)
	}
}

func TestParseRawRejectsWhatItDoesNotUnderstand(t *testing.T) {
	for _, raw := range []string{"", "x", rec('M', "a") + "y", ":100644 100644 x y M\x00a\x00", ":100644 100644 " + z40 + " " + z40 + " MM\x00a\x00", rec('M', "a\nb"), rec('M', "/abs"), rec('M', "a//b"), rec('M', "./a")} {
		if _, err := parseRaw([]byte(raw)); err == nil {
			t.Errorf("parseRaw(%q): want an error", raw)
		}
	}
	cs, err := parseRaw([]byte(rec('M', "a/b.go") + rec('D', "c") + rec('A', "d")))
	if err != nil || len(cs) != 3 || cs[1].status != 'D' {
		t.Fatalf("parseRaw: %v %v", cs, err)
	}
}

// ---- THIS repository: the mapping of example paths to jobs (the human's acceptance test) ---------------------------------------------------------------

func TestMappingOfThisRepository(t *testing.T) {
	root := thisRepo(t)
	w, err := load(root)
	if err != nil {
		t.Fatal(err)
	}
	all := w.cfg.allJobs()
	pick := func(pred func(string) bool) set {
		s := set{}
		for j := range all {
			if pred(j) {
				s[j] = true
			}
		}
		return s
	}
	pre := func(p string) func(string) bool { return func(j string) bool { return strings.HasPrefix(j, p) } }
	btc, sol, mpcParty := pick(pre("e2e-btc-")), pick(pre("e2e-sol-")), pick(pre("mpc-party-"))
	custody := pick(pre("e2e-evm-"))
	e2e := pick(pre("e2e-"))
	union := func(ss ...set) set {
		u := set{}
		for _, s := range ss {
			u.add(s)
		}
		return u
	}
	one := func(j string) set { return set{j: true} }
	firstFile := func(dir, suffix string, test bool) string {
		ents, err := os.ReadDir(filepath.Join(root, dir))
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, e := range ents {
			n := e.Name()
			if strings.HasSuffix(n, suffix) && strings.HasSuffix(n, "_test.go") == test {
				names = append(names, n)
			}
		}
		sort.Strings(names)
		if len(names) == 0 {
			t.Fatalf("no %s file in %s", suffix, dir)
		}
		return dir + "/" + names[0]
	}
	type tc struct {
		path    string
		exact   set // the exact job set, or nil
		must    set // jobs that must run
		mustNot set // jobs that must not run
		all     bool
	}
	cases := []tc{
		// documentation and charts on the allowlist: nothing
		{path: "docs/architecture.md", exact: set{}},
		{path: "deploy/helm/qv-business/values.yaml", exact: set{}},
		// the e2e tests of one chain: that chain's jobs and test
		// (checks: monitoring/metrics_test.go reads every .go file of the repository, ci/job-readers)
		{path: firstFile("e2e/btc", ".go", true), exact: union(btc, one("test"), one("checks"))},
		{path: firstFile("e2e/sol", ".go", true), exact: union(sol, one("test"), one("checks"))},
		{path: firstFile("e2e/solsign", ".go", true), exact: union(one("e2e-sol-4"), one("test"), one("checks"))},
		{path: firstFile("e2e/custody", ".go", true), exact: union(custody, one("test"), one("checks"))},
		{path: firstFile("e2e/mpcsign", ".go", true), exact: union(one("e2e-evm-4"), one("test"), one("checks"))},
		// code every binary links: every job of the root module's binaries, none of the mpc-party module's own jobs
		{path: firstFile("internal/custody", ".go", false), must: union(e2e, one("test")), mustNot: mpcParty},
		{path: firstFile("internal/chain/btc", ".go", false), must: union(btc, sol, custody, one("test")), mustNot: mpcParty},
		// the mpc-party module: its jobs and every e2e job (they build mpc-party), and test (internal/gatecred's test walks mpc-party/)
		{path: firstFile("mpc-party/internal/server", ".go", false), must: union(mpcParty, e2e, one("checks"), one("test"))},
		// trees of ci/job-rules: no e2e group
		{path: "ci/kind/kind.yaml", exact: one("test")},
		{path: "ci/kind/charts.sh", exact: one("test")},
		{path: "ci/kind/tools/mkbucket/main.go", exact: union(one("test"), one("checks"))},
		{path: "deploy/helm/qv-certs/catalog.json", exact: one("test")},
		{path: "deploy/helm/qv-monitoring/values.yaml", exact: one("test")},
		{path: "loadtest/scenarios/smoke.json", must: union(one("e2e-evm-4"), one("test")), mustNot: union(btc, sol, mpcParty)},
		{path: "loadtest/README.md", must: one("test"), mustNot: union(btc, sol, mpcParty)},
		{path: "monitoring/worker.rules.yml", must: union(one("checks"), one("test")), mustNot: union(btc, sol, custody)},
		// anything not modelled: every job
		{path: "newdir/x.txt", all: true},
		{path: "go.mod", all: true},
		{path: "mpc-party/go.sum", all: true},
		{path: ".github/workflows/ci.yml", all: true},
		{path: ".github/actions/mpc-env/action.yml", all: true},
		{path: "ci/jobs", all: true},
		{path: "ci/run-in-image.sh", all: true},
		{path: "Makefile", all: true},
		{path: "docker-compose.yml", all: true},
		{path: "scripts/pki.sh", all: true},
		{path: "migrations/001_init.sql", all: true},
		{path: "mpc-party/cbmpc.pin", all: true},
		{path: "deploy/postgres/x.conf", all: true},
		{path: "internal/chain/evm/testdata/Token.abi.json", all: true},
		{path: "web/approval/app.js", all: true},
	}
	for _, c := range cases {
		d := w.decide(change{oldMode: "100644", newMode: "100644", status: 'M', path: c.path})
		switch {
		case c.all:
			if !d.all {
				t.Errorf("%s: want ALL, got %s (%s)", c.path, names(d.jobs), d.why)
			}
			continue
		case d.all:
			t.Errorf("%s: want a narrowed set, got ALL (%s)", c.path, d.why)
			continue
		}
		if c.exact != nil && names(d.jobs) != names(c.exact) {
			t.Errorf("%s: want exactly %s, got %s (%s)", c.path, names(c.exact), names(d.jobs), d.why)
		}
		for j := range c.must {
			if !d.jobs[j] {
				t.Errorf("%s: %s must run (%s)", c.path, j, d.why)
			}
		}
		for j := range c.mustNot {
			if d.jobs[j] {
				t.Errorf("%s: %s should not run (%s)", c.path, j, d.why)
			}
		}
	}
}

func TestCheckOfThisRepository(t *testing.T) {
	if p := check(thisRepo(t)); len(p) > 0 {
		t.Errorf("jobselect check:\n%s", strings.Join(p, "\n"))
	}
}
