package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// config is ci/jobs.
type config struct {
	modules      []string
	mainsExclude []string
	noBuild      set
	always       set
	jobs         []jobSpec
}

type jobSpec struct {
	id    string
	roots []rootSpec
	mains bool // @mains
}

type rootSpec struct{ module, pattern string }

func (c *config) isJob(id string) bool {
	for _, j := range c.jobs {
		if j.id == id {
			return true
		}
	}
	return false
}

func (c *config) allJobs() set {
	s := set{}
	for _, j := range c.jobs {
		s[j.id] = true
	}
	return s
}

var jobID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

func parseJobs(b []byte) (*config, error) {
	c := &config{noBuild: set{}, always: set{}}
	seen := set{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		bad := func(why string) error { return fmt.Errorf("ci/jobs line %d: %s: %q", n, why, line) }
		switch f[0] {
		case "module":
			if len(f) != 2 {
				return nil, bad("module <dir>")
			}
			c.modules = append(c.modules, filepath.ToSlash(filepath.Clean(f[1])))
		case "mains-exclude":
			if len(f) != 2 || !strings.HasSuffix(f[1], "/") {
				return nil, bad("mains-exclude <dir/>")
			}
			c.mainsExclude = append(c.mainsExclude, f[1])
		case "nobuild", "always":
			if len(f) != 2 {
				return nil, bad(f[0] + " <job>")
			}
			if f[0] == "nobuild" {
				c.noBuild[f[1]] = true
			} else {
				c.always[f[1]] = true
			}
		case "job":
			if len(f) < 3 || !jobID.MatchString(f[1]) {
				return nil, bad("job <id> <root>...")
			}
			if seen[f[1]] {
				return nil, bad("job listed twice")
			}
			seen[f[1]] = true
			j := jobSpec{id: f[1]}
			for _, r := range f[2:] {
				if r == "@mains" {
					j.mains = true
					continue
				}
				m, p, ok := strings.Cut(r, ":")
				body := strings.TrimSuffix(strings.TrimSuffix(strings.TrimPrefix(p, "./"), "..."), "/")
				if !ok || !strings.HasPrefix(p, "./") || strings.Contains(body, "..") || strings.ContainsAny(body, "*? ") {
					return nil, bad("root must be <module>:./<pattern> or @mains")
				}
				j.roots = append(j.roots, rootSpec{module: filepath.ToSlash(filepath.Clean(m)), pattern: p})
			}
			c.jobs = append(c.jobs, j)
		default:
			return nil, bad("unknown directive")
		}
	}
	if len(c.modules) == 0 || len(c.jobs) == 0 {
		return nil, fmt.Errorf("ci/jobs: no module or no job")
	}
	for _, s := range []set{c.noBuild, c.always} {
		for j := range s {
			if !seen[j] {
				return nil, fmt.Errorf("ci/jobs: nobuild/always %s: no such job", j)
			}
		}
	}
	for _, j := range c.jobs {
		for _, r := range j.roots {
			if !contains(c.modules, r.module) {
				return nil, fmt.Errorf("ci/jobs: job %s: module %s is not a `module` line", j.id, r.module)
			}
		}
	}
	return c, nil
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// rule is a line of ci/job-rules: a tree whose non-Go files affect only the jobs that read it.
type rule struct {
	glob string // as written, e.g. ci/kind/*
	dir  string // the tree, e.g. ci/kind/
}

func parseRules(b []byte) ([]rule, error) {
	var rs []rule
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.ContainsAny(line, " \t?[") || !strings.HasSuffix(line, "/*") || strings.Count(line, "*") != 1 ||
			strings.HasPrefix(line, "/") || strings.Contains(line, "..") || strings.HasPrefix(line, ".github/") || line == "ci/*" {
			return nil, fmt.Errorf("ci/job-rules: %q: one tree per line, <dir>/*", line)
		}
		rs = append(rs, rule{glob: line, dir: strings.TrimSuffix(line, "*")})
	}
	return rs, nil
}

// exception is a reviewed non-Go reader of a rule's tree (ci/job-rules-exceptions):
// <tree/><TAB><file><TAB><number of lines><TAB><text of the lines, or *><TAB><jobs, comma-separated, or -><TAB><reason>
type exception struct {
	tree, file, text string
	count            int
	jobs             set
	line             int
}

func parseExceptions(b []byte, c *config) ([]*exception, error) {
	var es []*exception
	sc := bufio.NewScanner(bytes.NewReader(b))
	n := 0
	for sc.Scan() {
		n++
		line := sc.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 6 || f[5] == "" || f[3] == "" || !strings.HasSuffix(f[0], "/") {
			return nil, fmt.Errorf("ci/job-rules-exceptions line %d: want <tree/> <file> <count> <text|*> <jobs|-> <reason>, tab-separated", n)
		}
		cnt, err := strconv.Atoi(f[2])
		if err != nil || cnt < 1 {
			return nil, fmt.Errorf("ci/job-rules-exceptions line %d: bad count %q", n, f[2])
		}
		e := &exception{tree: f[0], file: f[1], count: cnt, text: f[3], jobs: set{}, line: n}
		if f[4] != "-" {
			for _, j := range strings.Split(f[4], ",") {
				if !c.isJob(j) {
					return nil, fmt.Errorf("ci/job-rules-exceptions line %d: unknown job %q", n, j)
				}
				e.jobs[j] = true
			}
		}
		es = append(es, e)
	}
	return es, nil
}

// allowlist is ci/skip-allowlist (only to know which files are not readers: ci/classify.sh decides the skips themselves).
// Only `*` is a wildcard, and it matches `/` too (a bash case pattern).
type allowlist []string

func parseAllowlist(b []byte) allowlist {
	var a allowlist
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) == 2 && !strings.ContainsAny(f[1], "?[\\") {
			a = append(a, f[1])
		}
	}
	return a
}

func (a allowlist) match(p string) bool {
	for _, g := range a {
		if globStar(g, p) {
			return true
		}
	}
	return false
}

// globStar matches a pattern whose only wildcard is * (any run of characters, / included).
func globStar(g, s string) bool {
	parts := strings.Split(g, "*")
	if len(parts) == 1 {
		return g == s
	}
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	for i, p := range parts[1:] {
		if i == len(parts)-2 {
			return strings.HasSuffix(s, p) && len(s) >= len(p)
		}
		k := strings.Index(s, p)
		if k < 0 {
			return false
		}
		s = s[k+len(p):]
	}
	return true
}

// classifySkip asks ci/classify.sh whether ONE changed file is a file no job reads (the docs and chart allowlist with its extension and module checks).
func classifySkip(root string, c change) bool {
	var rec bytes.Buffer
	z := strings.Repeat("0", 40)
	fmt.Fprintf(&rec, ":%s %s %s %s %c\x00%s\x00", c.oldMode, c.newMode, z, z, c.status, c.path)
	cmd := exec.Command(filepath.Join(root, "ci", "classify.sh"))
	cmd.Stdin = &rec
	out, err := cmd.Output()
	return err == nil && strings.HasPrefix(string(out), "skip ") && strings.Count(string(out), "\n") == 1
}

func readFile(root, rel string) ([]byte, error) {
	return os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
}

// reader is a reviewed Go file that reads files by a path relative to ".." or to the repository root (ci/job-readers): a search for tree names cannot see
// what such a path reaches, so the file is listed with what it reads. <file><TAB><number of lines><TAB><paths it reads: comma-separated globs (* crosses
// /), or -><TAB><reason>. A changed file matching one of the globs adds the jobs of the reader (a _test.go file: the jobs that test its package).
type reader struct {
	file  string
	count int
	globs []string
	line  int
}

func parseReaders(b []byte) ([]*reader, error) {
	var rs []*reader
	for n, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 4 || f[3] == "" || f[2] == "" {
			return nil, fmt.Errorf("ci/job-readers line %d: want <file> <count> <globs|-> <reason>, tab-separated", n+1)
		}
		cnt, err := strconv.Atoi(f[1])
		if err != nil || cnt < 1 {
			return nil, fmt.Errorf("ci/job-readers line %d: bad count %q", n+1, f[1])
		}
		r := &reader{file: f[0], count: cnt, line: n + 1}
		if f[2] != "-" {
			r.globs = strings.Split(f[2], ",")
		}
		rs = append(rs, r)
	}
	return rs, nil
}
