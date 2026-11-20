package helmcheck

import (
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// A ConfigMap name is "<base>-<10 hex of the content>", and the base is cut BEFORE the hash is added. Cutting the whole name afterwards (the first version) lost the hash when the
// release name was long, so a change of content kept the same name; on an immutable ConfigMap the upgrade then fails. Release names may be up to 53 characters.
func TestConfigMapNameKeepsItsHashWithALongReleaseName(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		if os.Getenv("CI") == "" {
			t.Skip("helm not on PATH")
		}
		t.Fatal(err)
	}
	rel := strings.Repeat("r", 53)
	hash := regexp.MustCompile(`-[0-9a-f]{10}$`)
	cases := []struct {
		name   string
		chart  string
		args   []string
		change []string
	}{
		{"qv-business", "qv-business", []string{"-f", "../../deploy/helm/qv-business/values-kind.yaml"}, []string{"--set", "oidc.audience=another"}},
		{"qv-signing-core", "qv-signing-core", []string{"-f", "signing-core-ci.yaml", "-f", "../../deploy/helm/qv-signing-core/values-kind.yaml"}, []string{"--set", "kafka.brokers=other.example.test:9092"}},
		{"qv-party", "qv-party", []string{"--set", "role=B", "-f", "ci-party-values.yaml", "-f", "ci-party-digests.yaml", "-f", "../../deploy/helm/qv-party/values-kind.yaml"}, []string{"--set", "limits.recvTimeoutMs=777"}},
	}
	names := func(chart string, args []string) map[string]bool {
		out, err := exec.Command("helm", append([]string{"template", rel, "../../deploy/helm/" + chart, "-n", "n"}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", chart, err, out)
		}
		m := map[string]bool{}
		for _, x := range regexp.MustCompile(`(?m)^kind: ConfigMap\nmetadata:\n  name: (\S+)`).FindAllStringSubmatch(string(out), -1) {
			m[x[1]] = true
		}
		return m
	}
	for _, c := range cases {
		before := names(c.chart, c.args)
		after := names(c.chart, append(append([]string{}, c.args...), c.change...))
		if len(before) == 0 {
			t.Fatalf("%s: no ConfigMaps rendered", c.name)
		}
		for n := range before {
			if len(n) > 63 || !hash.MatchString(n) {
				t.Errorf("%s: ConfigMap %q is longer than 63 or has lost its hash", c.name, n)
			}
		}
		same := 0
		for n := range after {
			if before[n] {
				same++
			}
		}
		if same == len(after) {
			t.Errorf("%s: a changed value left every ConfigMap name as it was (the hash is cut off)", c.name)
		}
	}
}
