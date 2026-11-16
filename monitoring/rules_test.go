// Package monitoring tests the Prometheus rules in this directory with promtool: `check rules`, `check config`, and the unit tests in
// *.rules.test.yml. promtool comes from $PROMTOOL, the PATH, or the pinned Prometheus image when it is already pulled (`make test-monitoring`
// pulls it); without any of them the tests skip, they never download anything.
package monitoring

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// promtool returns a function that runs promtool with arguments in this directory, or skips the test.
func promtool(t *testing.T) func(args ...string) (string, error) {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	local := func(bin string) func(args ...string) (string, error) {
		return func(args ...string) (string, error) {
			c := exec.Command(bin, args...)
			c.Dir = dir
			out, err := c.CombinedOutput()
			return string(out), err
		}
	}
	if p := os.Getenv("PROMTOOL"); p != "" {
		return local(p)
	}
	if p, err := exec.LookPath("promtool"); err == nil {
		return local(p)
	}
	if _, err := exec.LookPath("docker"); err == nil {
		img := composeImage(t)
		if exec.Command("docker", "image", "inspect", img).Run() == nil {
			return func(args ...string) (string, error) {
				a := append([]string{"run", "--rm", "-v", dir + ":/work:ro", "-w", "/work", "--entrypoint", "promtool", img}, args...)
				out, err := exec.Command("docker", a...).CombinedOutput()
				return string(out), err
			}
		}
	}
	t.Skip("promtool not available (no $PROMTOOL, none on the PATH, pinned Prometheus image not pulled): run `make test-monitoring`")
	return nil
}

// composeImage is the Prometheus image the compose file pins: one place for the version.
func composeImage(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^\s*image:\s*(prom/prometheus:\S+)\s*$`).FindSubmatch(b)
	if m == nil {
		t.Fatal("docker-compose.yml pins no prom/prometheus image")
	}
	return string(m[1])
}

func TestRuleFilesPassPromtoolCheck(t *testing.T) {
	run := promtool(t)
	rules, _ := filepath.Glob("*.rules.yml")
	if len(rules) < 2 {
		t.Fatalf("rule files: %v", rules)
	}
	if out, err := run(append([]string{"check", "rules"}, rules...)...); err != nil {
		t.Fatalf("promtool check rules: %v\n%s", err, out)
	}
}

func TestPrometheusConfigPassesPromtoolCheck(t *testing.T) {
	run := promtool(t)
	if out, err := run("check", "config", "prometheus.yml"); err != nil {
		t.Fatalf("promtool check config: %v\n%s", err, out)
	}
}

// The unit tests of the rules: thresholds, windows, `for`, the suppression of a party the health checks already route away from.
func TestRulesUnitTestsPassPromtool(t *testing.T) {
	run := promtool(t)
	tests, _ := filepath.Glob("*.rules.test.yml")
	if len(tests) == 0 {
		t.Fatal("no rule unit tests")
	}
	if out, err := run(append([]string{"test", "rules"}, tests...)...); err != nil {
		t.Fatalf("promtool test rules: %v\n%s", err, out)
	}
}

// Every threshold of the blame rules is one number in one place, and every alert reads it from there.
func TestBlameThresholdsLiveInOnePlace(t *testing.T) {
	b, err := os.ReadFile("mpc-blame.rules.yml")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, name := range []string{"cryptographic_1h", "availability_5m", "refused_1h", "other_1h"} {
		if !strings.Contains(s, "labels: {name: "+name+"}") {
			t.Errorf("threshold %s is not defined", name)
		}
		if !strings.Contains(s, `qv_mpc_blame:threshold{name="`+name+`"}`) {
			t.Errorf("no alert reads threshold %s", name)
		}
	}
}
