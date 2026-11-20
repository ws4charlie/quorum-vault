package helmcheck

import (
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// The three service charts take the trust bundle of qv-certs (an immutable ConfigMap, `qv-trust-<zone>-<hash>`) as the CA file of their certificate volumes, instead of the ca.crt that
// cert-manager puts into the Secret. Set, every certificate volume that has a CA is a projected volume: the Secret contributes tls.crt and tls.key, the bundle contributes ca.crt.
// Not set, nothing changes. (The pinned gateway-party certificate has no CA file in use and the public ingress certificate is not the zone's: both stay plain Secrets.)
func TestServiceChartsTakeTheTrustBundleAsCA(t *testing.T) {
	const biz, sig = "qv-trust-business-0123456789", "qv-trust-signing-abcdef0123"
	both := []string{"--set", "tls.trust.business=" + biz, "--set", "tls.trust.signing=" + sig}
	businessText := func(extra ...string) string {
		if _, err := exec.LookPath("helm"); err != nil {
			if os.Getenv("CI") == "" {
				t.Skip("helm not on PATH")
			}
			t.Fatal(err)
		}
		args := append([]string{"template", "r", "../../deploy/helm/qv-business", "-n", "n", "-f", "../../deploy/helm/qv-business/values-kind.yaml"}, extra...)
		out, err := exec.Command("helm", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("qv-business: %v\n%s", err, out)
		}
		return string(out)
	}
	party := func(extra ...string) string {
		s, err := partyRender(true, "B", extra...)
		if err != nil {
			if os.Getenv("CI") == "" && strings.Contains(err.Error(), "not found on PATH") {
				t.Skip(err)
			}
			t.Fatal(err)
		}
		return s
	}
	secretCert := regexp.MustCompile(`(?m)^\s+secretName: (\S+-tls)\s*$`)
	cases := []struct {
		name    string
		with    string
		without string
		plain   []string // the certificate Secrets that stay plain volumes
		min     int      // projected volumes at least
		bundles []string
	}{
		{"qv-business", businessText(both...), businessText(), []string{"qv-public-tls"}, 5, []string{biz}},
		{"qv-signing-core", scText(t, true, both...), scText(t, true), []string{"qv-signing-gateway-party-tls"}, 2, []string{biz, sig}},
		{"qv-party", party(both...), party(), nil, 4, []string{biz, sig}},
	}
	for _, c := range cases {
		if strings.Contains(c.without, "qv-trust-") {
			t.Errorf("%s: without a trust name the render mentions a trust bundle", c.name)
		}
		if n := strings.Count(c.with, "projected:"); n < c.min {
			t.Errorf("%s: %d projected certificate volumes, want at least %d", c.name, n, c.min)
		}
		for _, b := range c.bundles {
			if !strings.Contains(c.with, "name: "+b) {
				t.Errorf("%s: the bundle %s is not mounted", c.name, b)
			}
		}
		plain := map[string]bool{}
		for _, p := range c.plain {
			plain[p] = true
		}
		for _, m := range secretCert.FindAllStringSubmatch(c.with, -1) {
			if !plain[m[1]] {
				t.Errorf("%s: certificate Secret %s is still a plain volume (its ca.crt would be the CA)", c.name, m[1])
			}
		}
		if !strings.Contains(c.with, "items: [{ key: tls.crt, path: tls.crt }, { key: tls.key, path: tls.key }]") && !strings.Contains(c.with, "key: tls.crt") {
			t.Errorf("%s: the projected Secret does not name its keys", c.name)
		}
	}
}
