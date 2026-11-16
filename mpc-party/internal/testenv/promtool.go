package testenv

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// Promtool lets a test evaluate the repository's Prometheus rules (monitoring/) against counters a test produced. It uses $PROMTOOL, a promtool on the
// PATH, or the Prometheus image pinned in docker-compose.yml when it is already pulled; otherwise the test skips (it never downloads anything; `make
// test-monitoring` pulls the image).
type Promtool struct {
	run func(dir string, args ...string) (string, error)
}

func repoRoot() string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(f), "..", "..", ".."))
}

func NewPromtool(t testing.TB) *Promtool {
	t.Helper()
	local := func(bin string) *Promtool {
		return &Promtool{func(dir string, args ...string) (string, error) {
			c := exec.Command(bin, args...)
			c.Dir = dir
			out, err := c.CombinedOutput()
			return string(out), err
		}}
	}
	if p := os.Getenv("PROMTOOL"); p != "" {
		return local(p)
	}
	if p, err := exec.LookPath("promtool"); err == nil {
		return local(p)
	}
	if _, err := exec.LookPath("docker"); err == nil {
		if b, err := os.ReadFile(filepath.Join(repoRoot(), "docker-compose.yml")); err == nil {
			if m := regexp.MustCompile(`(?m)^\s*image:\s*(prom/prometheus:\S+)\s*$`).FindSubmatch(b); m != nil {
				img := string(m[1])
				if exec.Command("docker", "image", "inspect", img).Run() == nil {
					return &Promtool{func(dir string, args ...string) (string, error) {
						a := append([]string{"run", "--rm", "-v", dir + ":/work:ro", "-w", "/work", "--entrypoint", "promtool", img}, args...)
						out, err := exec.Command("docker", a...).CombinedOutput()
						return string(out), err
					}}
				}
			}
		}
	}
	t.Skip("promtool not available (no $PROMTOOL, none on the PATH, pinned Prometheus image not pulled): run `make test-monitoring` once")
	return nil
}

// TestRules runs `promtool test rules` on fixture (a unit-test file) against the repository's file monitoring/<rules>, in a private directory.
func (p *Promtool) TestRules(t testing.TB, rules, fixture string) {
	t.Helper()
	dir := t.TempDir()
	b, err := os.ReadFile(filepath.Join(repoRoot(), "monitoring", rules))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, rules), b, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "fixture.test.yml"), []byte(fixture), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := p.run(dir, "test", "rules", "fixture.test.yml"); err != nil {
		t.Fatalf("promtool test rules failed: %v\n%s\n--- fixture ---\n%s", err, out, fixture)
	}
}

// CounterFixture builds a promtool test: every non-zero series of the given Prometheus text (counters that started at 0 and reached their value
// after 10 minutes) as one input series each, and the expectation that the alert `alert` fires, at 15 minutes, for exactly the label sets wantAlerts
// (each written as `peer="B",kind="CRYPTOGRAPHIC",severity="page"`; none: the alert must not fire). rulesFile is the rules file to load.
func CounterFixture(rulesFile, alert string, metrics []string, wantAlerts []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "rule_files: [%s]\nevaluation_interval: 1m\ntests:\n  - interval: 1m\n    input_series:\n", rulesFile)
	n := 0
	for _, text := range metrics {
		for _, line := range strings.Split(text, "\n") {
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			i := strings.LastIndex(line, " ")
			series, val := line[:i], strings.TrimSpace(line[i+1:])
			if val == "0" || strings.HasPrefix(series, "qv_mpc_party_info") {
				continue
			}
			fmt.Fprintf(&b, "      - series: '%s'\n        values: '0x10 %sx30'\n", series, val)
			n++
		}
	}
	if n == 0 { // promtool needs a series; one that never fires anything
		fmt.Fprintf(&b, "      - series: 'qv_mpc_unused{}'\n        values: '0x40'\n")
	}
	fmt.Fprintf(&b, "    promql_expr_test:\n      - expr: ALERTS{alertname=%q, alertstate=\"firing\"}\n        eval_time: 15m\n", alert)
	if len(wantAlerts) == 0 {
		b.WriteString("        exp_samples: []\n")
		return b.String()
	}
	b.WriteString("        exp_samples:\n")
	for _, w := range wantAlerts {
		fmt.Fprintf(&b, "          - {labels: 'ALERTS{alertname=\"%s\",alertstate=\"firing\",%s}', value: 1}\n", alert, w)
	}
	return b.String()
}
