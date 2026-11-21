package monitoring

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// ruleMetrics returns every metric name the rules of this directory read (not the names the rules record themselves), by file. It reads the `expr:` and `record:` keys
// as text (single-line values and `|` or `>` blocks), so the root module needs no YAML library.
func ruleMetrics(t *testing.T) map[string][]string {
	t.Helper()
	files, _ := filepath.Glob("*.rules.yml")
	name := regexp.MustCompile(`\bqv_[a-z0-9_]+(:[a-z0-9_:]+)?`)
	exprKey := regexp.MustCompile(`^(\s*)(?:-\s+)?expr:\s*(.*)$`)
	recKey := regexp.MustCompile(`^\s*(?:-\s+)?record:\s*(\S+)`)
	out := map[string][]string{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(string(b), "\n")
		recorded := map[string]bool{}
		var exprs []string
		for i := 0; i < len(lines); i++ {
			l := lines[i]
			if strings.HasPrefix(strings.TrimSpace(l), "#") {
				continue
			}
			if m := recKey.FindStringSubmatch(l); m != nil {
				recorded[m[1]] = true
			}
			if m := exprKey.FindStringSubmatch(l); m != nil {
				v := strings.TrimSpace(m[2])
				if v == "|" || v == ">" || v == "|-" || v == ">-" {
					indent := len(m[1])
					for i+1 < len(lines) && (strings.TrimSpace(lines[i+1]) == "" || len(lines[i+1])-len(strings.TrimLeft(lines[i+1], " ")) > indent) {
						i++
						v += "\n" + lines[i]
					}
				}
				exprs = append(exprs, v)
			}
		}
		seen := map[string]bool{}
		for _, e := range exprs {
			for _, m := range name.FindAllString(e, -1) {
				if strings.Contains(m, ":") || recorded[m] || seen[m] {
					continue
				}
				seen[m] = true
				out[m] = append(out[m], f)
			}
		}
	}
	return out
}

// emitted reads every Go source of the repository that is not a test (the main module, mpc-party and the others) and tells which of the names occur in it.
func emitted(t *testing.T, names []string) map[string]bool {
	t.Helper()
	found := map[string]bool{}
	err := filepath.WalkDir("..", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".deps", "node_modules", ".claude", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		s := codeOnly(string(b))
		for _, n := range names {
			if found[n] {
				continue
			}
			// a histogram is read as name_bucket, name_sum and name_count; the program spells the base name
			for _, cand := range []string{n, strings.TrimSuffix(n, "_bucket"), strings.TrimSuffix(n, "_sum"), strings.TrimSuffix(n, "_count")} {
				if strings.Contains(s, cand) {
					found[n] = true
					break
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

// codeOnly drops the lines that are only a comment: a metric that a comment mentions and no code writes is not emitted.
func codeOnly(src string) string {
	var b strings.Builder
	for _, l := range strings.Split(src, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "//") {
			continue
		}
		b.WriteString(l)
		b.WriteByte('\n')
	}
	return b.String()
}

// pendingMetrics reads pending-metrics.txt: the metrics a rule reads that no program emits yet.
func pendingMetrics(t *testing.T) map[string]bool {
	t.Helper()
	f, err := os.Open("pending-metrics.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		out[strings.Fields(l)[0]] = true
	}
	return out
}

// A rule that reads a metric no program writes never fires and nobody notices. Every metric of every rule must be emitted by some program, or be listed as pending
// (with the exact specification in the report of the task that adds it).
func TestEveryRuleMetricIsEmitted(t *testing.T) {
	used := ruleMetrics(t)
	if len(used) < 10 {
		t.Fatalf("only %d metric names found in the rules: the extraction is broken", len(used))
	}
	var names []string
	for n := range used {
		names = append(names, n)
	}
	sort.Strings(names)
	found := emitted(t, names)
	pending := pendingMetrics(t)
	for _, n := range names {
		switch {
		case !found[n] && !pending[n]:
			t.Errorf("%s (read by %v) is emitted by no program and is not in pending-metrics.txt", n, used[n])
		case found[n] && pending[n]:
			t.Errorf("%s is listed as pending but a program emits it now: delete the line from pending-metrics.txt", n)
		}
	}
	for n := range pending {
		if _, ok := used[n]; !ok {
			t.Errorf("pending-metrics.txt lists %s, which no rule reads", n)
		}
	}
}

// The check itself: a made-up name is reported as unknown, an existing one as emitted.
func TestEmittedFindsMetricNames(t *testing.T) {
	f := emitted(t, []string{"qv_mpc_party_sealer_ready", "qv_no_such_metric_anywhere_xyz"})
	if !f["qv_mpc_party_sealer_ready"] || f["qv_no_such_metric_anywhere_xyz"] {
		t.Fatalf("emitted: %v", f)
	}
}

// Comments do not count as emitting, and a histogram's _bucket line is found by its base name.
func TestEmittedIgnoresCommentsAndFindsHistogramBase(t *testing.T) {
	if got := codeOnly("// qv_x_total\nvar a = 1 // qv_y\n\t// qv_z"); strings.Contains(got, "qv_x_total") || strings.Contains(got, "qv_z") || !strings.Contains(got, "qv_y") {
		t.Fatalf("codeOnly: %q", got)
	}
	f := emitted(t, []string{"qv_worker_activity_schedule_to_start_latency_seconds_bucket", "qv_worker_no_such_latency_seconds_bucket"})
	if !f["qv_worker_activity_schedule_to_start_latency_seconds_bucket"] || f["qv_worker_no_such_latency_seconds_bucket"] {
		t.Fatalf("emitted: %v", f)
	}
}
