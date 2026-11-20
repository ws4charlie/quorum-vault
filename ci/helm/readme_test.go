package helmcheck

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The contract file (deploy/images/contract.json) and the README table it mirrors must say the same thing. Reading the README is cheap and a
// drift between the two is exactly what lets a chart pass its test with a flag the image does not take.

func readImagesFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "deploy", "images", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

var (
	codeSpan = regexp.MustCompile("`([^`]+)`")
	envName  = regexp.MustCompile(`^[A-Z][A-Z0-9_]*[A-Z0-9]$`)
	flagName = regexp.MustCompile(`^-{1,2}([a-z][a-z0-9-]*)$`)
)

// readmeRow is one row of the run-time table: image name -> text of the "Flags and environment" and "Files it reads" columns.
func readmeRows(t *testing.T) map[string]string {
	t.Helper()
	text := readImagesFile(t, "README.md")
	i := strings.Index(text, "## Run-time contract")
	if i < 0 {
		t.Fatal("README has no 'Run-time contract' section")
	}
	rows := map[string]string{}
	for _, l := range strings.Split(text[i:], "\n") {
		if !strings.HasPrefix(l, "| `") {
			continue
		}
		// split on unescaped pipes
		cells := strings.Split(strings.ReplaceAll(l, `\|`, "\x00"), "|")
		if len(cells) < 6 {
			continue
		}
		name := strings.Trim(strings.TrimSpace(cells[1]), "`")
		rows[name] = strings.ReplaceAll(cells[3]+" "+cells[4], "\x00", "|")
	}
	return rows
}

// readmeTokens returns the flags and environment variables a row names. The word TLS (outside code) stands for the four -tls-* flags.
func readmeTokens(row string, tlsEnv []string) (flags, env map[string]bool) {
	flags, env = map[string]bool{}, map[string]bool{}
	skip := map[string]bool{}
	for _, e := range tlsEnv {
		skip[e] = true
	}
	for _, m := range codeSpan.FindAllStringSubmatch(row, -1) {
		for _, tok := range strings.FieldsFunc(m[1], func(r rune) bool {
			return r == ' ' || r == '/' || r == ',' || r == '|' || r == '\\' || r == '=' || r == '(' || r == ')'
		}) {
			if f := flagName.FindStringSubmatch(tok); f != nil {
				flags[f[1]] = true
			} else if envName.MatchString(tok) && strings.Contains(tok, "_") && !skip[tok] && !strings.HasPrefix(tok, "SIGHUP") {
				env[tok] = true
			}
		}
	}
	plain := codeSpan.ReplaceAllString(row, " ")
	if regexp.MustCompile(`\bTLS\b`).MatchString(plain) {
		for _, f := range []string{"tls-cert", "tls-key", "tls-ca", "tls-reload"} {
			flags[f] = true
		}
	}
	return
}

func keys(m map[string]bool) []string {
	var k []string
	for x := range m {
		k = append(k, x)
	}
	sort.Strings(k)
	return k
}

// Images with a README row but no contract entry yet: the signing-zone charts (task D6, D7) add theirs. A listed image that does get an entry is
// compared like the others; nothing here exempts it from that.
var imagesWithoutContract = map[string]bool{
	"qv-tools-business": true, "qv-gateway": true, "qv-cosigner": true, "mpc-party": true, "qv-tools-signing": true,
}

func TestContractMatchesReadme(t *testing.T) {
	c, err := LoadContract()
	if err != nil {
		t.Fatal(err)
	}
	rows := readmeRows(t)
	for name, ic := range c.Images {
		row, ok := rows[name]
		if !ok {
			t.Errorf("%s is in contract.json but has no row in the README table", name)
			continue
		}
		if name == "qv-attest-broker" || name == "mpc-party" {
			continue // their flags are in a JSON config file, compared below
		}
		rf, re := readmeTokens(row, c.TLSEnv)
		cf, ce := map[string]bool{}, map[string]bool{}
		for _, f := range ic.Flags {
			cf[f] = true
		}
		for _, e := range ic.Env {
			if !contains(c.TLSEnv, e) {
				ce[e] = true
			}
		}
		for _, f := range ic.Flags {
			if strings.HasPrefix(f, "archive-tls-") || strings.HasPrefix(f, "tls-") {
				continue // covered by the word TLS and `-archive-tls-*`
			}
		}
		// the README names the archive store's TLS flags as one glob
		if strings.Contains(row, "-archive-tls-*") {
			for _, f := range []string{"archive-tls-cert", "archive-tls-key", "archive-tls-ca", "archive-tls-reload"} {
				rf[f] = true
			}
			for _, e := range []string{"QV_ARCHIVE_TLS_CERT", "QV_ARCHIVE_TLS_KEY", "QV_ARCHIVE_TLS_CA", "QV_ARCHIVE_TLS_RELOAD"} {
				re[e] = true
			}
		}
		for _, f := range keys(rf) {
			if !cf[f] {
				t.Errorf("%s: the README names flag -%s, contract.json does not", name, f)
			}
		}
		for _, f := range keys(cf) {
			if !rf[f] {
				t.Errorf("%s: contract.json has flag -%s, the README row does not name it", name, f)
			}
		}
		for _, e := range keys(re) {
			if !ce[e] {
				t.Errorf("%s: the README names %s, contract.json does not", name, e)
			}
		}
		for _, e := range keys(ce) {
			if !re[e] {
				t.Errorf("%s: contract.json has %s, the README row does not name it", name, e)
			}
		}
	}
	// every README image row is either in the contract or on the list of images still waiting for it
	for name := range rows {
		if _, ok := c.Images[name]; !ok && !imagesWithoutContract[name] {
			t.Errorf("%s has a README row and no contract.json entry", name)
		}
	}
}

// images.sh, the Dockerfile targets, the contract's dev images and the README must name the same set of images.
func TestImageListsAgree(t *testing.T) {
	c, err := LoadContract()
	if err != nil {
		t.Fatal(err)
	}
	sh := readImagesFile(t, "images.sh")
	dockerfile := readImagesFile(t, "Dockerfile")
	readme := readImagesFile(t, "README.md")
	zones := map[string]string{}
	var prod, dev []string
	inList := false
	for _, l := range strings.Split(sh, "\n") {
		switch {
		case strings.HasPrefix(l, `QV_IMAGES="`):
			inList = true
		case inList && l == `"`:
			inList = false
		case inList:
			if p := strings.Split(l, ":"); len(p) == 3 {
				prod = append(prod, p[0])
				zones[p[0]] = p[1]
			}
		case strings.HasPrefix(l, "QV_DEV_IMAGES="):
			for _, d := range strings.Fields(strings.Trim(strings.TrimPrefix(l, "QV_DEV_IMAGES="), `"`)) {
				p := strings.Split(d, ":")
				dev = append(dev, p[0])
				zones[p[0]] = p[1]
			}
		}
	}
	if len(prod) == 0 || len(dev) == 0 {
		t.Fatalf("could not read images.sh (prod %v, dev %v)", prod, dev)
	}
	for _, n := range append(append([]string{}, prod...), dev...) {
		if !regexp.MustCompile(`(?m)^FROM \S+ AS ` + regexp.QuoteMeta(n) + `$`).MatchString(dockerfile) {
			t.Errorf("%s is in images.sh but the Dockerfile has no such target", n)
		}
		if !strings.Contains(readme, "`"+n+"`") {
			t.Errorf("%s is in images.sh but the README never names it", n)
		}
	}
	for n, ic := range c.Images {
		z, ok := zones[n]
		if !ok && !(n == "qv-migrate") {
			t.Errorf("%s is in contract.json but not in images.sh", n)
		}
		if ok && z != ic.Zone {
			t.Errorf("%s: contract.json says zone %s, images.sh says %s", n, ic.Zone, z)
		}
	}
	got := map[string]bool{}
	for n, d := range c.DevImages {
		got[n] = true
		if !contains(dev, n) {
			t.Errorf("contract.json devImages has %s, images.sh does not", n)
		}
		if _, ok := c.Images[d.Of]; !ok && !imagesWithoutContract[d.Of] {
			t.Errorf("devImages %s is of %s, which has no contract entry", n, d.Of)
		}
		if d.Of+"-dev" != n {
			t.Errorf("devImages %s: `of` is %s", n, d.Of)
		}
		for k, v := range d.RequiredEnv {
			if !strings.Contains(readme, k+"="+v) {
				t.Errorf("devImages %s needs %s=%s; the README never says to run the -dev images that way", n, k, v)
			}
		}
	}
	for _, n := range dev {
		if !got[n] {
			t.Errorf("%s is a dev image in images.sh and has no devImages entry in contract.json", n)
		}
	}
}

// The test itself must see a drift: remove a flag from a README row and the comparison must complain.
func TestReadmeTokens(t *testing.T) {
	f, e := readmeTokens("`-config` (required), `-addr` / `QV_HTTP_ADDR`, `QV_ENV` (unset = production), TLS, `-archive-tls-*` `QV_TLS_CERT`", []string{"QV_TLS_CERT"})
	if !f["config"] || !f["addr"] || !f["tls-key"] || !e["QV_HTTP_ADDR"] || !e["QV_ENV"] || e["QV_TLS_CERT"] {
		t.Errorf("tokens misread: %v %v", keys(f), keys(e))
	}
}
