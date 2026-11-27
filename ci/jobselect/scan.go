package main

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
)

// machinery: files that only the `changes` job runs (they name trees as test data or as rules). They are never readers for a heavy job; a change to any
// of them runs everything anyway (decide, step 2: ci/ outside a rule tree).
func isMachinery(p string) bool {
	return strings.HasPrefix(p, "ci/jobselect/") || p == "ci/jobs" || strings.HasPrefix(p, "ci/job-rules") || strings.HasPrefix(p, "ci/changes") ||
		p == "ci/classify.sh" || strings.HasPrefix(p, "ci/skip-") || p == "ci/final.sh" || p == "ci/e2e-groups-check.sh" || p == "ci/job-readers" ||
		strings.HasPrefix(p, "ci/tracked-files")
}

// isCode: a file that can open, run or embed another file. Data (Markdown, JSON, SQL, plain YAML outside .github and compose files) is not a reader.
func isCode(p string) bool {
	b := path.Base(p)
	switch {
	case strings.HasSuffix(b, ".go"), strings.HasSuffix(b, ".sh"), strings.HasSuffix(b, ".bash"), strings.HasSuffix(b, ".py"),
		strings.HasSuffix(b, ".js"), strings.HasSuffix(b, ".mjs"), strings.HasSuffix(b, ".mk"), b == "Makefile",
		strings.Contains(b, "Dockerfile"), strings.HasPrefix(b, "docker-compose"), strings.HasPrefix(b, "compose") && (strings.HasSuffix(b, ".yml") || strings.HasSuffix(b, ".yaml")),
		strings.HasPrefix(p, ".github/"), b == "go.mod":
		return true
	}
	return false
}

// needles: the ways a file names the tree dir (e.g. "loadtest/" or "ci/kind/"): the path itself, and the Go join form "ci", "kind"; for a top-level
// tree also its name as a Go string literal ("loadtest"). A deeper tree's last segment alone ("kind") is not a needle: it is a common word, and a relative
// join from the parent directory would be in ci/ or deploy/, whose files outside the rule trees run every job anyway (decide, step 2) or are themselves
// found by the path needle.
func needles(dir string) []*regexp.Regexp {
	d := strings.TrimSuffix(dir, "/")
	segs := strings.Split(d, "/")
	q := regexp.QuoteMeta
	ns := []*regexp.Regexp{regexp.MustCompile(`(^|[^A-Za-z0-9_.-])` + q(d) + `([^A-Za-z0-9_-]|$)`)}
	if len(segs) > 1 {
		var parts []string
		for _, s := range segs {
			parts = append(parts, `"`+q(s)+`"`)
		}
		ns = append(ns, regexp.MustCompile(strings.Join(parts, `\s*,\s*`)))
	} else {
		ns = append(ns, regexp.MustCompile(`"`+q(d)+`"`))
	}
	return ns
}

// codeOf: the line without a trailing Go comment (// outside a string literal), so that a remark in a comment does not count as a reader.
func codeOf(file, line string) string {
	if !strings.HasSuffix(file, ".go") {
		return line
	}
	var q rune
	prev := rune(0)
	for i, c := range line {
		switch {
		case q != 0:
			if c == q && (prev != '\\' || q == '`') {
				q = 0
			}
		case c == '"' || c == '`' || c == '\'':
			q = c
		case c == '/' && prev == '/':
			return line[:i-1]
		}
		if prev == '\\' && c == '\\' {
			prev = 0
			continue
		}
		prev = c
	}
	return line
}

// commentOnly: a line that names something without running it. //go:embed is not a comment; //go:generate is (CI never runs go generate: check).
func commentOnly(file, line string) bool {
	t := strings.TrimSpace(line)
	if strings.HasSuffix(file, ".go") {
		if strings.HasPrefix(t, "//go:embed") {
			return false
		}
		return strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*")
	}
	return strings.HasPrefix(t, "#")
}

// hit: a line of a file outside the tree that names it.
type hit struct {
	file string
	line int
	text string
}

func (w *world) readersOf(r *rule) ([]hit, error) {
	ns := needles(r.dir)
	var hits []hit
	for _, f := range w.tracked {
		if strings.HasPrefix(f, r.dir) || !isCode(f) || isMachinery(f) || w.allow.match(f) || strings.HasSuffix(f, ".md") {
			continue
		}
		b, err := readFile(w.root, f)
		if err != nil {
			return nil, fmt.Errorf("read %s: %v", f, err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			if commentOnly(f, line) {
				continue
			}
			code := codeOf(f, line)
			for _, n := range ns {
				if n.MatchString(code) {
					hits = append(hits, hit{file: f, line: i + 1, text: strings.TrimSpace(line)})
					break
				}
			}
		}
	}
	return hits, nil
}

// derive: the jobs that read a tree of ci/job-rules. Cached. All when a non-Go reader is not a reviewed exception, or an exception does not match the
// tree exactly as reviewed (count and text), or a Go reader is not in a package.
func (w *world) derive(r *rule) *decision {
	if d := w.derived[r.dir]; d != nil {
		return d
	}
	d := w.deriveUncached(r)
	w.derived[r.dir] = &d
	return &d
}

func (w *world) deriveUncached(r *rule) decision {
	jobs := set{}
	var why []string
	// Go packages inside the tree, or above it in the same module (they may embed or open its files relative to themselves)
	for _, p := range w.g.pkgs {
		if strings.HasPrefix(p.dir+"/", r.dir) || strings.HasPrefix(r.dir, p.dir+"/") {
			jobs.add(w.jobsCompiling(p))
			why = append(why, "package "+p.dir)
		}
	}
	hits, err := w.readersOf(r)
	if err != nil {
		return all(err.Error())
	}
	used := map[*exception]int{}
	for _, h := range hits {
		if strings.HasSuffix(h.file, ".go") {
			pk := w.g.byDir[path.Dir(h.file)]
			if pk == nil {
				return all(fmt.Sprintf("%s:%d names %s, and its directory is not a package", h.file, h.line, r.dir))
			}
			switch pk.files[path.Base(h.file)] {
			case "test":
				jobs.add(w.jobsTesting(pk))
			case "go":
				jobs.add(w.jobsCompiling(pk))
			default:
				return all(fmt.Sprintf("%s:%d names %s, and go list does not compile it", h.file, h.line, r.dir))
			}
			why = append(why, "read by "+h.file)
			continue
		}
		// the workflow and the Makefile map to jobs by themselves: a line of ci.yml belongs to its job, a recipe line of the Makefile to the jobs that call
		// its target; another workflow is not a job of ci.yml at all
		if js, ok := w.autoReader(h); ok {
			jobs.add(js)
			why = append(why, "read by "+h.file)
			continue
		}
		var e *exception
		for _, x := range w.exceptions {
			if x.tree == r.dir && x.file == h.file && (x.text == "*" || strings.Contains(h.text, x.text)) && used[x] < x.count {
				e = x
				break
			}
		}
		if e == nil {
			return all(fmt.Sprintf("%s:%d names %s and is not a reviewed line of ci/job-rules-exceptions: %s", h.file, h.line, r.dir, oneLine(h.text)))
		}
		used[e]++
		jobs.add(e.jobs)
	}
	for _, x := range w.exceptions {
		if x.tree == r.dir && used[x] != x.count {
			return all(fmt.Sprintf("ci/job-rules-exceptions line %d (%s in %s): reviewed for %d line(s), found %d: review the file again", x.line, x.file, r.dir, x.count, used[x]))
		}
	}
	sort.Strings(why)
	if len(why) > 6 {
		why = append(why[:6], fmt.Sprintf("and %d more", len(why)-6))
	}
	return decision{jobs: jobs, why: "tree " + r.dir + " is read by: " + strings.Join(why, ", ")}
}

// autoReader: the jobs of a reader line in a file whose structure says which jobs run it. ok=false: no such structure (a reviewed exception is needed).
func (w *world) autoReader(h hit) (set, bool) {
	switch {
	case h.file == ".github/workflows/ci.yml":
		job := w.ciJobAt(h.line)
		switch {
		case job == "changes":
			return set{}, true // the decision job itself (its tests name trees as data)
		case w.cfg.isJob(job):
			return set{job: true}, true
		}
		return nil, false
	case strings.HasPrefix(h.file, ".github/workflows/") && !strings.Contains(h.file[len(".github/workflows/"):], "/"):
		return set{}, true // another workflow: not a job of ci.yml (it has its own triggers)
	case h.file == "Makefile":
		t := w.makeTargetAt(h.line)
		if t == "" {
			return nil, false // a variable or a rule header: which recipe uses it is not known here
		}
		return w.makeCallers()[t], true
	}
	return nil, false
}

// ciJobAt: the ci.yml job whose block holds a line ("" when none).
func (w *world) ciJobAt(line int) string {
	b, err := readFile(w.root, ".github/workflows/ci.yml")
	if err != nil {
		return ""
	}
	key := regexp.MustCompile(`^  ([A-Za-z0-9_-]+):\s*(#.*)?$`)
	cur, in := "", false
	for i, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "jobs:") {
			in = true
		} else if in {
			if m := key.FindStringSubmatch(l); m != nil {
				cur = m[1]
			} else if l != "" && !strings.HasPrefix(l, " ") && !strings.HasPrefix(l, "#") {
				in, cur = false, ""
			}
		}
		if i+1 == line {
			return cur
		}
	}
	return ""
}

var makeRule = regexp.MustCompile(`^([A-Za-z0-9_.-]+)\s*:([^=]|$)`)

// makeTargetAt: the target whose recipe holds a Makefile line ("" for a line outside a recipe).
func (w *world) makeTargetAt(line int) string {
	b, err := readFile(w.root, "Makefile")
	if err != nil {
		return ""
	}
	cur := ""
	for i, l := range strings.Split(string(b), "\n") {
		switch {
		case strings.HasPrefix(l, "\t"):
		case makeRule.MatchString(l):
			cur = makeRule.FindStringSubmatch(l)[1]
			if i+1 == line {
				return "" // the header itself (its prerequisites)
			}
		case strings.TrimSpace(l) == "" || strings.HasPrefix(strings.TrimSpace(l), "#"):
		default:
			cur = ""
		}
		if i+1 == line {
			if strings.HasPrefix(l, "\t") {
				return cur
			}
			return ""
		}
	}
	return ""
}

// makeCallers: for every Makefile target, the ci.yml jobs that run it (`make T` in the job, or a target they run that calls `$(MAKE) T`, `make T`, or has T
// as a prerequisite).
func (w *world) makeCallers() map[string]set {
	if w.makeJobs != nil {
		return w.makeJobs
	}
	out := map[string]set{}
	mk, _ := readFile(w.root, "Makefile")
	y, _ := readFile(w.root, ".github/workflows/ci.yml")
	calls := map[string]set{} // target -> targets it runs
	cur := ""
	callRe := regexp.MustCompile(`(?:\$\(MAKE\)|\bmake)\s+(?:-[A-Za-z]+\s+)*([A-Za-z0-9_.-]+)`)
	for _, l := range strings.Split(string(mk), "\n") {
		if m := makeRule.FindStringSubmatch(l); m != nil && !strings.HasPrefix(l, "\t") {
			cur = m[1]
			if calls[cur] == nil {
				calls[cur] = set{}
			}
			pre := strings.SplitN(l, ":", 2)[1]
			pre, _, _ = strings.Cut(pre, "#")
			for _, p := range strings.Fields(pre) {
				calls[cur][p] = true
			}
			continue
		}
		if strings.HasPrefix(l, "\t") && cur != "" {
			for _, m := range callRe.FindAllStringSubmatch(l, -1) {
				calls[cur][m[1]] = true
			}
		}
	}
	for job, blk := range workflowJobs(string(y)) {
		for _, m := range callRe.FindAllStringSubmatch(blk, -1) {
			var visit func(t string)
			visit = func(t string) {
				if out[t] == nil {
					out[t] = set{}
				}
				if out[t][job] {
					return
				}
				out[t][job] = true
				for c := range calls[t] {
					visit(c)
				}
			}
			visit(m[1])
		}
	}
	w.makeJobs = out
	return out
}
