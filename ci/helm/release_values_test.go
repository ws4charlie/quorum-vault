package helmcheck

// Checks for the manual release procedure (docs/runbooks/release.md): the version rule of deploy/images/release-gate.sh, the release set (no development or
// simulated image), and deploy/images/manifest-values.py, which turns a release manifest into chart values. The generated values must render with each chart that
// runs our images, and must replace the digests the chart tests use. Digests here are made up. Needs python3, bash and helm on PATH.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func imagesDir() string { return filepath.Join("..", "..", "deploy", "images") }

// releaseSet returns name -> zone of qv_release_images (images.sh), the images a release publishes.
func releaseSet(t *testing.T) map[string]string {
	t.Helper()
	out, err := exec.Command("bash", "-c", `cd "$1" && . ./images.sh && qv_release_images`, "bash", imagesDir()).CombinedOutput()
	if err != nil {
		t.Fatalf("images.sh: %v\n%s", err, out)
	}
	set := map[string]string{}
	for _, l := range strings.Fields(string(out)) {
		p := strings.Split(l, ":")
		set[p[0]] = p[1]
	}
	if len(set) < 12 {
		t.Fatalf("release set has %d images, want at least 12: %v", len(set), set)
	}
	return set
}

func TestReleaseSetHasNoDev(t *testing.T) {
	for n := range releaseSet(t) {
		if regexp.MustCompile(`-dev($|-)|tee-?sim|softhsm`).MatchString(n) {
			t.Errorf("release set holds %q: development and simulated images are never published", n)
		}
	}
}

func TestVersionRule(t *testing.T) {
	ok := []string{"v0.0.1", "v1.2.3", "v10.20.30", "v1.2.3-rc.1", "v1.0.0-rc.12"}
	bad := []string{"", "1.2.3", "latest", "main", "v1", "v1.2", "v1.2.3.4", "v01.2.3", "v1.2.03", "v1.2.3-rc", "v1.2.3-rc.0", "v1.2.3-rc.01", "v1.2.3-beta.1", "v1.2.3+build", "V1.2.3", "v1.2.3 ", "v1.2.3-rc.1-x", "v-1.2.3"}
	run := func(v string) error {
		return exec.Command(filepath.Join(imagesDir(), "release-gate.sh"), "--check-version", v).Run()
	}
	for _, v := range ok {
		if err := run(v); err != nil {
			t.Errorf("version %q must be accepted: %v", v, err)
		}
	}
	for _, v := range bad {
		if err := run(v); err == nil {
			t.Errorf("version %q must be refused", v)
		}
	}
}

// The gate refuses a branch run and an untagged run before it asks GitHub anything.
func TestGateRefusesNonTag(t *testing.T) {
	for _, c := range []struct{ typ, name string }{{"branch", "main"}, {"branch", "v1.2.3"}, {"tag", "latest"}, {"tag", "v1.2"}} {
		cmd := exec.Command(filepath.Join(imagesDir(), "release-gate.sh"))
		cmd.Env = append(os.Environ(), "GITHUB_REF_TYPE="+c.typ, "GITHUB_REF_NAME="+c.name, "GITHUB_SHA=0123456789012345678901234567890123456789", "GITHUB_REPOSITORY=o/r")
		var eb bytes.Buffer
		cmd.Stderr = &eb
		if err := cmd.Run(); err == nil || !strings.Contains(eb.String(), "REFUSED") {
			t.Errorf("gate for %s %q: want a refusal, got err=%v stderr=%q", c.typ, c.name, err, eb.String())
		}
	}
}

type relManifest map[string]any

// fakeManifest is what publish.sh writes, with made-up digests: image name n gets the digest made of the hex digit (index+1) repeated.
func fakeManifest(t *testing.T, mutate func(relManifest)) (string, map[string]string) {
	t.Helper()
	set := releaseSet(t)
	names := make([]string, 0, len(set))
	for n := range set {
		names = append(names, n)
	}
	sortStrings(names)
	digests := map[string]string{}
	imgs := map[string]any{}
	for i, n := range names {
		d := "sha256:" + strings.Repeat(string("abcdef123456789"[i%15]), 63) + string("0123456789abcdef"[i%16])
		digests[n] = d
		imgs[n] = map[string]any{"repository": "ghcr.io/ws4charlie/quorum-vault/" + n, "digest": d, "zone": set[n]}
	}
	m := relManifest{"schema": 1, "version": "v1.2.3", "dryRun": false,
		"source": map[string]any{"commit": strings.Repeat("c", 40), "repository": "https://github.com/ws4charlie/quorum-vault"},
		"signer": map[string]any{"identity": "https://github.com/ws4charlie/quorum-vault/.github/workflows/images.yml@refs/tags/v1.2.3", "issuer": "https://token.actions.githubusercontent.com"},
		"images": imgs}
	if mutate != nil {
		mutate(m)
	}
	b, _ := json.MarshalIndent(m, "", "  ")
	p := filepath.Join(t.TempDir(), "release-v1.2.3.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p, digests
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func mvRun(args ...string) (string, string, error) {
	cmd := exec.Command("python3", append([]string{"-I", filepath.Join(imagesDir(), "manifest-values.py")}, args...)...)
	var ob, eb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &ob, &eb
	err := cmd.Run()
	return ob.String(), eb.String(), err
}

func TestManifestValuesRefusals(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(relManifest)
		args   []string
		want   string
	}{
		{"dry run", func(m relManifest) { m["dryRun"] = true }, nil, "dry run"},
		{"release candidate", func(m relManifest) { m["version"] = "v1.2.3-rc.1" }, nil, "release candidate"},
		{"bad version", func(m relManifest) { m["version"] = "latest" }, nil, "not vMAJOR"},
		{"unknown schema", func(m relManifest) { m["schema"] = 2 }, nil, "schema"},
		{"missing image", func(m relManifest) { delete(m["images"].(map[string]any), "qv-gateway") }, nil, "qv-gateway"},
		{"all-zero digest", func(m relManifest) {
			m["images"].(map[string]any)["qv-core"].(map[string]any)["digest"] = "sha256:" + strings.Repeat("0", 64)
		}, nil, "not a real sha256 digest"},
		{"tag instead of digest", func(m relManifest) { m["images"].(map[string]any)["qv-core"].(map[string]any)["digest"] = "v1.2.3" }, nil, "not a real sha256 digest"},
		{"short digest", func(m relManifest) { m["images"].(map[string]any)["qv-core"].(map[string]any)["digest"] = "sha256:abc" }, nil, "not a real sha256 digest"},
	}
	for _, c := range cases {
		p, _ := fakeManifest(t, c.mutate)
		ch := "qv-business"
		if c.name == "missing image" {
			ch = "qv-signing-core" // qv-gateway is its image
		}
		_, eb, err := mvRun(append([]string{p, "--chart", ch}, c.args...)...)
		if err == nil || !strings.Contains(eb, c.want) {
			t.Errorf("%s (%s): want refusal containing %q, got err=%v stderr=%q", c.name, ch, c.want, err, eb)
		}
	}
	// a release candidate is accepted for staging with the flag
	p, _ := fakeManifest(t, func(m relManifest) { m["version"] = "v1.2.3-rc.1" })
	if _, eb, err := mvRun(p, "--chart", "qv-party", "--allow-rc"); err != nil {
		t.Errorf("--allow-rc: %v %s", err, eb)
	}
}

// helmRender renders one chart with the given -f files and --set arguments and returns the manifests.
func helmRender(t *testing.T, chart string, args ...string) string {
	t.Helper()
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Fatalf("helm not found on PATH: %v", err)
	}
	cmd := exec.Command(helm, append([]string{"template", "rel", filepath.Join("..", "..", "deploy", "helm", chart), "--namespace", "qv"}, args...)...)
	var ob, eb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &ob, &eb
	if err := cmd.Run(); err != nil {
		t.Fatalf("helm template %s: %v\n%s", chart, err, eb.String())
	}
	return ob.String()
}

// TestManifestValuesRenderWithCharts: the generated file, applied LAST over the chart's own values and the made-up test inputs, puts exactly the manifest's
// digests into every image of every chart that runs our images, and nothing else.
func TestManifestValuesRenderWithCharts(t *testing.T) {
	p, digests := fakeManifest(t, nil)
	dir := t.TempDir()
	out, eb, err := mvRun(p, "--all", "--out-dir", dir)
	if err != nil {
		t.Fatalf("manifest-values --all: %v\n%s", err, eb)
	}
	if n := len(strings.Fields(out)); n != 3 {
		t.Fatalf("want 3 files, got %d: %q", n, out)
	}
	chartDir := func(c string) string { return filepath.Join("..", "..", "deploy", "helm", c) }
	type tc struct {
		chart string
		args  []string
		keys  map[string]string // values key -> image name
	}
	cases := []tc{
		{"qv-business", []string{"-f", filepath.Join(chartDir("qv-business"), "values.yaml"), "--set", "approval.enabled=true", "-f", filepath.Join(dir, "images-qv-business.yaml")},
			map[string]string{"core": "qv-core", "worker": "qv-worker", "relay": "qv-relay", "archiver": "qv-anchor-archiver", "migrate": "qv-migrate", "approval": "qv-approval-web"}},
		{"qv-signing-core", []string{"-f", "signing-core-ci.yaml", "--set", "signedSettings.job.enabled=true", "--set", "signedSettings.job.configMap=x", "--set-json", `signedSettings.job.files=["a.json"]`, "-f", filepath.Join(dir, "images-qv-signing-core.yaml")},
			map[string]string{"gateway": "qv-gateway", "tools": "qv-tools-signing"}},
	}
	for _, role := range []string{"A", "B", "C"} {
		keys := map[string]string{"party": "mpc-party", "cosigner": "qv-cosigner"}
		if role == "A" {
			delete(keys, "cosigner") // party A authorizes by pinned caller: no cosigner container
		}
		cases = append(cases, tc{"qv-party", []string{"--set", "role=" + role, "-f", filepath.Join(chartDir("qv-party"), "values.yaml"), "-f", "ci-party-values.yaml", "-f", filepath.Join(dir, "images-qv-party.yaml")}, keys})
	}
	for _, c := range cases {
		rendered := helmRender(t, c.chart, c.args...)
		for key, name := range c.keys {
			want := fmt.Sprintf("ghcr.io/ws4charlie/quorum-vault/%s@%s", name, digests[name])
			if !strings.Contains(rendered, want) {
				t.Errorf("%s: images.%s: rendered output lacks %s", c.chart, key, want)
			}
		}
		// every image of ours the chart renders carries a manifest digest: the chart tests' own made-up digests are gone
		mine := map[string]bool{}
		for _, d := range digests {
			mine[d] = true
		}
		for _, m := range regexp.MustCompile(`ghcr\.io/ws4charlie/quorum-vault/[a-z-]+@(sha256:[0-9a-f]{64})`).FindAllStringSubmatch(rendered, -1) {
			if !mine[m[1]] {
				t.Errorf("%s: %s is not a digest of the manifest: the generated file did not replace a test input", c.chart, m[0])
			}
		}
	}
}

// With --registry the digests stay and only the repository changes (a mirror inside a cluster that cannot reach the public registry).
func TestManifestValuesMirror(t *testing.T) {
	p, digests := fakeManifest(t, nil)
	out, eb, err := mvRun(p, "--chart", "qv-party", "--registry", "registry.internal:5000/qv/")
	if err != nil {
		t.Fatalf("%v\n%s", err, eb)
	}
	for _, n := range []string{"mpc-party", "qv-cosigner"} {
		if !strings.Contains(out, "registry.internal:5000/qv/"+n+",") || !strings.Contains(out, digests[n]) {
			t.Errorf("mirror output wrong for %s:\n%s", n, out)
		}
	}
	if strings.Contains(out, "ghcr.io") {
		t.Errorf("mirror output still names ghcr.io:\n%s", out)
	}
}
