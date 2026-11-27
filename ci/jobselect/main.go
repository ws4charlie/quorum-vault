// Command jobselect decides which jobs of .github/workflows/ci.yml a pull request can affect, so that the others may be skipped.
//
// The human's rule, which every decision here serves: never skip a job a change can affect; running too much is fine, missing a run is not. So every
// doubt, error or unknown path selects every job, and only a proof (the package graph from `go list`, or a reviewed tree of ci/job-rules) narrows it.
//
//	go run ./ci/jobselect select < <(git diff --raw -z --no-renames --no-abbrev <base> HEAD)   prints "skip <job>..." or "all <reason>"
//	go run ./ci/jobselect explain <path>...                                                  the jobs of each path, and why
//	go run ./ci/jobselect check                                                              the guard: ci/jobs, ci/job-rules and ci.yml agree
//	go run ./ci/jobselect readers                                                            the evidence: every reader of every tree of ci/job-rules
//
// It reads ci/jobs (the packages each job tests), ci/job-rules and ci/job-rules-exceptions (non-Go trees), ci/skip-allowlist through ci/classify.sh
// (files no job reads). Standard library only, so that it runs without downloading a module (go list runs offline: GOPROXY=off).
package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: jobselect select|explain <path>...|check")
		os.Exit(2)
	}
	root, err := repoRoot()
	if err != nil {
		fail(os.Args[1], err)
	}
	switch os.Args[1] {
	case "select":
		in, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Println("all cannot read the change list")
			return
		}
		fmt.Println(selectJobs(root, in))
	case "explain":
		w, err := load(root)
		if err != nil {
			fail("explain", err)
		}
		for _, p := range os.Args[2:] {
			d := w.decide(change{path: p, status: 'M'})
			if d.all {
				fmt.Printf("%s: ALL (%s)\n", p, d.why)
				continue
			}
			fmt.Printf("%s: %s (%s)\n", p, strings.Join(sorted(d.jobs), " "), d.why)
		}
	case "readers": // the evidence for ci/job-rules: every line outside each tree that names it
		w, err := load(root)
		if err != nil {
			fail("readers", err)
		}
		for i := range w.rules {
			r := &w.rules[i]
			hits, err := w.readersOf(r)
			if err != nil {
				fail("readers", err)
			}
			d := w.derive(r)
			if d.all {
				fmt.Printf("== %s: ALL (%s)\n", r.glob, d.why)
			} else {
				fmt.Printf("== %s: %s\n", r.glob, strings.Join(sorted(d.jobs), " "))
			}
			for _, h := range hits {
				fmt.Printf("   %s:%d: %s\n", h.file, h.line, oneLine(h.text))
			}
		}
	case "why": // why <job> <package dir>: the import chain from the job's roots to the package
		w, err := load(root)
		if err != nil || len(os.Args) != 4 {
			fail("why", fmt.Errorf("usage: why <job> <package dir> (%v)", err))
		}
		fmt.Println(w.why(os.Args[2], os.Args[3]))
	case "check":
		problems := check(root)
		for _, p := range problems {
			fmt.Println("jobselect check:", p)
		}
		if len(problems) > 0 {
			fmt.Println("jobselect check: FAILED. ci/jobs, ci/job-rules, ci/job-rules-exceptions and .github/workflows/ci.yml must agree (CONTRIBUTING.md, \"Which jobs run\").")
			os.Exit(1)
		}
		fmt.Println("jobselect check: ok")
	default:
		fmt.Fprintln(os.Stderr, "usage: jobselect select|explain <path>...|check")
		os.Exit(2)
	}
}

func fail(what string, err error) {
	if what == "select" {
		fmt.Println("all " + oneLine(err.Error()))
		os.Exit(0)
	}
	fmt.Fprintf(os.Stderr, "jobselect %s: %v\n", what, err)
	os.Exit(1)
}

// selectJobs is the whole decision for one change list: "skip <job>..." (the jobs no changed file can affect, possibly none) or "all <reason>". It never
// fails: every error is "all <reason>". The reasons per file go to stderr (the job's log).
func selectJobs(root string, raw []byte) (out string) {
	defer func() {
		if r := recover(); r != nil {
			out = "all the selector panicked: " + oneLine(fmt.Sprint(r))
		}
	}()
	changes, err := parseRaw(raw)
	if err != nil {
		return "all " + oneLine(err.Error())
	}
	w, err := load(root)
	if err != nil {
		return "all " + oneLine(err.Error())
	}
	run := set{}
	for _, c := range changes {
		d := w.decide(c)
		if d.all {
			return "all " + oneLine(c.path+": "+d.why)
		}
		for j := range d.jobs {
			if !w.cfg.isJob(j) {
				return "all " + oneLine("internal: unknown job "+j)
			}
			run[j] = true
		}
		fmt.Fprintf(logw, "%s: %s (%s)\n", c.path, strings.Join(sorted(d.jobs), " "), d.why)
	}
	// the answer is the jobs NOT to run; the image job is skipped only when every job that needs it is
	skip := set{}
	image := false
	for _, j := range w.cfg.jobs {
		if !run[j.id] {
			skip[j.id] = true
		} else if !w.cfg.noImage[j.id] {
			image = true
		}
	}
	if !image {
		skip["image"] = true
	}
	fmt.Fprintf(logw, "run: %s\n", strings.Join(sorted(run), " "))
	return strings.TrimSpace("skip " + strings.Join(sorted(skip), " "))
}

func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
}

// logw receives the reason for every changed file (the job's log). Tests silence it.
var logw io.Writer = os.Stderr

type set map[string]bool

func (s set) add(o set) {
	for k := range o {
		s[k] = true
	}
}

func sorted(s set) []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func repoRoot() (string, error) {
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", fmt.Errorf("not in a git checkout: %v", err)
	}
	return strings.TrimSpace(string(out)), nil
}
