package main

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
)

// check is the guard that keeps ci/jobs, ci/job-rules, ci/job-rules-exceptions and ci.yml true. It runs in the `changes` job on every run; a problem
// fails that job, and then every job runs.
func check(root string) []string {
	w, err := load(root)
	if err != nil {
		return []string{err.Error()}
	}
	var p []string
	add := func(format string, a ...any) { p = append(p, fmt.Sprintf(format, a...)) }

	// 1. ci.yml: the jobs are those of ci/jobs, each one's condition names its own id, and the heavy ones need the image.
	b, err := readFile(root, ".github/workflows/ci.yml")
	if err != nil {
		return append(p, err.Error())
	}
	blocks := workflowJobs(string(b))
	ids := set{}
	for id := range blocks {
		ids[id] = true
	}
	want := w.cfg.allJobs()
	want["changes"], want["image"] = true, true
	for id := range ids {
		if !want[id] {
			add("ci.yml has a job %q that ci/jobs does not list (add it, with the packages it tests)", id)
		}
	}
	for id := range want {
		if !ids[id] {
			add("ci/jobs lists %q, which is not a job of ci.yml", id)
		}
	}
	cond := regexp.MustCompile(`contains\(needs\.changes\.outputs\.skip_jobs, ',([a-z0-9-]+),'\)`)
	for _, j := range w.cfg.jobs {
		blk, ok := blocks[j.id]
		if !ok {
			continue
		}
		var named []string
		for _, m := range cond.FindAllStringSubmatch(blk, -1) {
			named = append(named, m[1])
		}
		if len(named) == 0 {
			add("ci.yml job %s has no condition contains(needs.changes.outputs.skip_jobs, ',%s,') (without it, it runs always: safe, but it was forgotten?)", j.id, j.id)
		}
		for _, n := range named {
			if n != j.id {
				add("ci.yml job %s is skipped by the decision of another job (%s): a copy-paste slip", j.id, n)
			}
		}
		needs := needsOf(blk)
		if !needs["changes"] {
			add("ci.yml job %s does not need `changes`", j.id)
		}
		if !w.cfg.noImage[j.id] && !needs["image"] {
			add("ci.yml job %s does not need `image` (ci/jobs: only noimage jobs may run without it)", j.id)
		}
	}
	if !strings.Contains(blocks["image"], "contains(needs.changes.outputs.skip_jobs, ',image,')") {
		add("ci.yml job image: its condition must name ',image,' (skipped only when no job that needs it runs)")
	}

	// 2. every tree excluded from @mains is a tree of ci/job-rules (its readers, including a `go build` by path, are found there)
	for _, x := range w.cfg.mainsExclude {
		ok := false
		for _, r := range w.rules {
			if strings.HasPrefix(x, r.dir) {
				ok = true
			}
		}
		if !ok {
			add("ci/jobs: mains-exclude %s is not inside a tree of ci/job-rules", x)
		}
	}

	// 3. rules: each matches a tracked file, each derives without an unexplained reader; every exception is used exactly as reviewed
	for i := range w.rules {
		r := &w.rules[i]
		n := 0
		for _, f := range w.tracked {
			if strings.HasPrefix(f, r.dir) {
				n++
			}
		}
		if n == 0 {
			add("ci/job-rules: %s matches no tracked file (a tree that is not in the repository cannot be proven)", r.glob)
		}
		if d := w.derive(r); d.all {
			add("ci/job-rules: %s: %s", r.glob, d.why)
		}
	}
	for _, x := range w.exceptions {
		found := false
		for _, r := range w.rules {
			if r.dir == x.tree {
				found = true
			}
		}
		if !found {
			add("ci/job-rules-exceptions line %d: %s is not a tree of ci/job-rules", x.line, x.tree)
		}
	}

	// 4. build tags: every tag a tracked .go file uses is modelled (tagSets) or known not to be set by CI
	tagWord := regexp.MustCompile(`[A-Za-z0-9_.]+`)
	for _, f := range w.tracked {
		if !strings.HasSuffix(f, ".go") || w.allow.match(f) {
			continue
		}
		b, err := readFile(root, f)
		if err != nil {
			add("read %s: %v", f, err)
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			if !strings.HasPrefix(line, "//go:build ") {
				continue
			}
			for _, t := range tagWord.FindAllString(strings.TrimPrefix(line, "//go:build "), -1) {
				if !knownTags[t] && !strings.HasPrefix(t, "go1.") {
					add("%s: build tag %q is not modelled (ci/jobselect/graph.go tagSets, knownTags): a file only some CI build compiles could be missed", f, t)
				}
			}
		}
	}

	// 5. the mpc-party module jobs model only that module: nothing in it may build or name a package of the root module (an import path of it, or a
	// relative path that climbs out of mpc-party/)
	rootPath := regexp.MustCompile(`quorum-vault/(cmd|internal|e2e|loadtest|monitoring|migrations|deploy)/`)
	climb := regexp.MustCompile(`(\.\./)+|("\.\."\s*,\s*)+`)
	for _, f := range w.tracked {
		if !strings.HasPrefix(f, "mpc-party/") || !isCode(f) {
			continue
		}
		depth := strings.Count(f, "/") - 1 // directories below mpc-party/
		b, _ := readFile(root, f)
		for i, line := range strings.Split(string(b), "\n") {
			if commentOnly(f, line) {
				continue
			}
			code := codeOf(f, line)
			out := rootPath.MatchString(code)
			for _, m := range climb.FindAllString(code, -1) {
				if strings.Count(m, "..") > depth {
					out = true
				}
			}
			if out {
				add("%s:%d reaches outside mpc-party/ (the root module); the mpc-party jobs in ci/jobs do not model that: %s", f, i+1, strings.TrimSpace(line))
			}
		}
	}

	// 6. a job without @mains must not build a binary with `go build`/`go run` from a package that is not a whole module it tests
	goBuild := regexp.MustCompile(`"go",\s*"(build|run|install)"|exec\.Command(Context)?\((ctx,\s*)?"go"`)
	for _, j := range w.cfg.jobs {
		if j.mains {
			continue
		}
		whole := set{}
		for _, r := range j.roots {
			if r.pattern == "./..." {
				whole[r.module] = true
			}
		}
		for pp := range w.tests[j.id] {
			pk := w.g.pkgs[pp]
			if whole[pk.module] {
				continue
			}
			for f := range pk.files {
				b, _ := readFile(root, path.Join(pk.dir, f))
				if goBuild.Match(b) {
					add("job %s has no @mains, but %s runs the go command (it may build a binary): give the job @mains", j.id, path.Join(pk.dir, f))
				}
			}
		}
	}

	// 7. CI never runs go generate (//go:generate lines are not readers)
	for _, f := range []string{".github/workflows/ci.yml", "Makefile"} {
		b, _ := readFile(root, f)
		if strings.Contains(string(b), "go generate") {
			add("%s runs go generate: //go:generate lines would be readers (ci/jobselect/scan.go commentOnly)", f)
		}
	}
	sort.Strings(p)
	return p
}

// workflowJobs splits ci.yml into its jobs (two-space indented keys under `jobs:`), each with its text.
func workflowJobs(y string) map[string]string {
	out := map[string]string{}
	in := false
	cur := ""
	key := regexp.MustCompile(`^  ([A-Za-z0-9_-]+):\s*(#.*)?$`)
	for _, line := range strings.Split(y, "\n") {
		if strings.HasPrefix(line, "jobs:") {
			in = true
			continue
		}
		if !in {
			continue
		}
		if line != "" && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "#") {
			break
		}
		if m := key.FindStringSubmatch(line); m != nil {
			cur = m[1]
			out[cur] = ""
			continue
		}
		if cur != "" {
			out[cur] += line + "\n"
		}
	}
	return out
}

func needsOf(blk string) set {
	s := set{}
	for _, line := range strings.Split(blk, "\n") {
		t := strings.TrimSpace(line)
		if !strings.HasPrefix(t, "needs:") || !strings.HasPrefix(line, "    needs:") {
			continue
		}
		v := strings.Trim(strings.TrimSpace(strings.TrimPrefix(t, "needs:")), "[]")
		for _, n := range strings.Split(v, ",") {
			if n = strings.TrimSpace(n); n != "" {
				s[n] = true
			}
		}
	}
	return s
}
