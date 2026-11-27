package main

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"path"
	"regexp"
	"strings"
)

// world is everything a decision needs, loaded once.
type world struct {
	root       string
	cfg        *config
	g          *graph
	rules      []rule
	exceptions []*exception
	allow      allowlist
	tracked    []string
	modules    map[string]bool // every directory with a tracked go.mod
	closures   map[string]set  // job -> packages it compiles
	tests      map[string]set  // job -> packages it tests (its roots)
	derived    map[string]*decision
	classify   func(change) bool
	makeJobs   map[string]set
}

func load(root string) (*world, error) {
	w := &world{root: root, closures: map[string]set{}, tests: map[string]set{}, derived: map[string]*decision{}, modules: map[string]bool{}}
	b, err := readFile(root, "ci/jobs")
	if err != nil {
		return nil, err
	}
	if w.cfg, err = parseJobs(b); err != nil {
		return nil, err
	}
	if b, err = readFile(root, "ci/job-rules"); err != nil {
		return nil, err
	}
	if w.rules, err = parseRules(b); err != nil {
		return nil, err
	}
	if b, err = readFile(root, "ci/job-rules-exceptions"); err != nil {
		return nil, err
	}
	if w.exceptions, err = parseExceptions(b, w.cfg); err != nil {
		return nil, err
	}
	if b, err = readFile(root, "ci/skip-allowlist"); err != nil {
		return nil, err
	}
	w.allow = parseAllowlist(b)
	out, err := exec.Command("git", "-C", root, "ls-files", "-z").Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-files: %v", err)
	}
	for _, f := range strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00") {
		if f == "" {
			continue
		}
		w.tracked = append(w.tracked, f)
		if path.Base(f) == "go.mod" {
			w.modules[path.Dir(f)] = true
		}
	}
	if w.g, err = loadGraph(root, w.cfg.modules); err != nil {
		return nil, err
	}
	mains := w.g.mains(w.cfg)
	for _, j := range w.cfg.jobs {
		var roots []*pkg
		for _, r := range j.roots {
			ps := w.g.resolve(r)
			if len(ps) == 0 {
				return nil, fmt.Errorf("ci/jobs: job %s: %s:%s matches no package", j.id, r.module, r.pattern)
			}
			roots = append(roots, ps...)
		}
		t := set{}
		for _, p := range roots {
			t[p.path] = true
		}
		w.tests[j.id] = t
		var built []*pkg
		if j.mains {
			built = mains
		}
		w.closures[j.id] = w.g.closure(roots, built)
	}
	w.classify = func(c change) bool { return classifySkip(root, c) }
	return w, nil
}

// decision: the jobs one changed file can affect, or all of them.
type decision struct {
	all  bool
	jobs set
	why  string
}

func all(why string) decision { return decision{all: true, why: why} }

func (w *world) jobsCompiling(p *pkg) set {
	s := set{}
	for j, c := range w.closures {
		if c[p.path] {
			s[j] = true
		}
	}
	return s
}

func (w *world) jobsTesting(p *pkg) set {
	s := set{}
	for j, t := range w.tests {
		if t[p.path] {
			s[j] = true
		}
	}
	return s
}

// nearestModule: the directory of the nearest tracked go.mod above a path ("." for the root), or "" when there is none.
func (w *world) nearestModule(p string) string {
	d := path.Dir(p)
	for {
		if w.modules[d] {
			return d
		}
		if d == "." || d == "/" {
			return ""
		}
		d = path.Dir(d)
	}
}

func (w *world) ruleOf(p string) *rule {
	for i := range w.rules {
		if strings.HasPrefix(p, w.rules[i].dir) {
			return &w.rules[i]
		}
	}
	return nil
}

// decide is the rule for one changed file. Order matters: the first step that applies decides.
func (w *world) decide(c change) decision {
	p := c.path
	base := path.Base(p)
	// 1. a file no job reads (ci/skip-allowlist, decided by ci/classify.sh with its extension and module checks)
	if w.classify(c) {
		return decision{jobs: set{}, why: "on ci/skip-allowlist: no job reads it"}
	}
	// 2. what every job depends on: modules, the workflows and actions, the CI machinery (this selector, the image, the scripts the jobs run)
	switch {
	case base == "go.mod" || base == "go.sum" || strings.HasPrefix(base, "go.work"):
		return all("a module file")
	case strings.HasPrefix(p, ".github/"):
		return all("a workflow or action")
	case strings.HasPrefix(p, "ci/") && w.ruleOf(p) == nil:
		return all("CI machinery")
	}
	r := w.ruleOf(p)
	// 3. Go source: the package graph
	if strings.HasSuffix(p, ".go") {
		d := w.goFile(c)
		if d.all || r == nil {
			return d
		}
		rd := w.derive(r)
		if rd.all {
			return all(d.why + "; and " + rd.why)
		}
		d.jobs.add(rd.jobs)
		d.why += "; and it is in " + r.dir + " (" + rd.why + ")"
		return d
	}
	// 4. a tree of ci/job-rules: the jobs that read it
	if r != nil {
		d := w.derive(r)
		return *d
	}
	return all("not a Go file, not on ci/skip-allowlist, not in a tree of ci/job-rules")
}

// goFile: the jobs of a .go file, from the package graph.
func (w *world) goFile(c change) decision {
	p := c.path
	base := path.Base(p)
	if strings.HasPrefix(base, "_") || strings.HasPrefix(base, ".") {
		return all("a .go file go ignores (it may be data)")
	}
	for _, seg := range strings.Split(path.Dir(p), "/") {
		if seg == "testdata" || seg == "vendor" || strings.HasPrefix(seg, "_") || strings.HasPrefix(seg, ".") {
			return all("a .go file in a directory go ignores (testdata: it may be data)")
		}
	}
	m := w.nearestModule(p)
	if m == "" || !contains(w.cfg.modules, m) {
		return all("a .go file of a module ci/jobs does not list")
	}
	pk := w.g.byDir[path.Dir(p)]
	if pk == nil {
		return all("its directory is not a package of the build (go list)")
	}
	kind := pk.files[base]
	switch {
	case kind == "" && c.status != 'D':
		return all("go list does not know this file")
	case kind == "ignored":
		return all("excluded by build constraints from every configuration CI compiles (another platform or tag)")
	case kind == "test" || kind == "" && strings.HasSuffix(base, "_test.go"):
		return decision{jobs: w.jobsTesting(pk), why: "test file of " + pk.dir + ": the jobs that test it"}
	default:
		return decision{jobs: w.jobsCompiling(pk), why: "package " + pk.dir + ": the jobs that compile it"}
	}
}

// change is one record of `git diff --raw -z --no-renames --no-abbrev`.
type change struct {
	oldMode, newMode string
	status           byte
	path             string
}

const maxFiles = 1000

var objectID = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)

// parseRaw: only plain adds, modifies and deletes of regular files (mode 100644 or 100755, unchanged) are understood; anything else is an error (all).
func parseRaw(raw []byte) ([]change, error) {
	if len(raw) == 0 {
		return nil, errors.New("no changed files")
	}
	fields := bytes.Split(raw, []byte{0})
	if len(fields[len(fields)-1]) != 0 {
		return nil, errors.New("truncated change list")
	}
	fields = fields[:len(fields)-1]
	if len(fields)%2 != 0 {
		return nil, errors.New("truncated change list")
	}
	var out []change
	for i := 0; i < len(fields); i += 2 {
		meta, p := string(fields[i]), string(fields[i+1])
		if !strings.HasPrefix(meta, ":") {
			return nil, errors.New("unparsable change list")
		}
		f := strings.Fields(meta[1:])
		if len(f) != 5 || len(f[4]) != 1 || !objectID.MatchString(f[2]) || !objectID.MatchString(f[3]) {
			return nil, errors.New("unparsable change list")
		}
		c := change{oldMode: f[0], newMode: f[1], status: f[4][0], path: p}
		reg := func(m string) bool { return m == "100644" || m == "100755" }
		switch {
		case c.status == 'A' && c.oldMode == "000000" && reg(c.newMode):
		case c.status == 'M' && reg(c.oldMode) && c.oldMode == c.newMode:
		case c.status == 'D' && reg(c.oldMode) && c.newMode == "000000":
		default:
			return nil, fmt.Errorf("not a plain add, modify or delete of a regular file (%c %s %s): %s", c.status, c.oldMode, c.newMode, p)
		}
		if p == "" || strings.HasPrefix(p, "/") || strings.Contains(p, "//") || strings.ContainsAny(p, "\\") || strings.IndexFunc(p, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 ||
			strings.Contains("/"+p+"/", "/../") || strings.Contains("/"+p+"/", "/./") {
			return nil, fmt.Errorf("odd path %q", p)
		}
		out = append(out, c)
		if len(out) > maxFiles {
			return nil, fmt.Errorf("more than %d files", maxFiles)
		}
	}
	return out, nil
}
