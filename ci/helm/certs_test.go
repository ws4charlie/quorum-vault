package helmcheck

// Checks of deploy/helm/qv-certs: every catalog identity is rendered once, in the clusters the catalog names, and nowhere else; no key material; pinned
// identities keep their key; the zones stay apart. Each check is a function over parsed manifests, and a test shows it fails on a bad one.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

var certClusters = []string{"business", "signing-core", "party-b", "party-c", "broker"}

type catEntry struct {
	Name       string   `json:"name"`
	Zone       string   `json:"zone"`
	URI        string   `json:"uri"`
	Clusters   []string `json:"clusters"`
	Pinned     bool     `json:"pinned"`
	Operator   bool     `json:"operator"`
	SecretName string   `json:"secretName"`
}

func certChart() string { return filepath.Join("..", "..", "deploy", "helm", "qv-certs") }

func loadCatalog(t testing.TB) []catEntry {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(certChart(), "catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	var c struct{ Entries []catEntry }
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	if len(c.Entries) == 0 {
		t.Fatal("empty catalog.json")
	}
	return c.Entries
}

// testCAPEM makes a CA certificate for the trust-bundle tests at run time: nothing like it is kept in the repository.
func testCAPEM(t testing.TB) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func renderCerts(t testing.TB, values string, extra ...string) ([]Obj, error) {
	t.Helper()
	helm, err := exec.LookPath("helm")
	if err != nil {
		if os.Getenv("CI") == "" {
			t.Skip("helm not on PATH")
		}
		t.Fatal(err)
	}
	args := []string{"template", "qv-certs", certChart(), "--namespace", "qv", "-f", filepath.Join(certChart(), values)}
	if values == "values.yaml" {
		args = append(args, "-f", "certs-ci-values.yaml")
	}
	args = append(args, extra...)
	out, err := exec.Command(helm, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%v\n%s", err, out)
	}
	objs, err := Parse(string(out))
	if err != nil {
		t.Fatal(err)
	}
	return objs, nil
}

func mustRender(t testing.TB, values string, extra ...string) []Obj {
	t.Helper()
	objs, err := renderCerts(t, values, extra...)
	if err != nil {
		t.Fatal(err)
	}
	return objs
}

type certSpec struct {
	SecretName string   `yaml:"secretName"`
	CN         string   `yaml:"commonName"`
	URIs       []string `yaml:"uris"`
	IsCA       bool     `yaml:"isCA"`
	PrivateKey struct {
		Rotation string `yaml:"rotationPolicy"`
	} `yaml:"privateKey"`
	IssuerRef struct {
		Name string `yaml:"name"`
		Kind string `yaml:"kind"`
	} `yaml:"issuerRef"`
	Duration    string `yaml:"duration"`
	RenewBefore string `yaml:"renewBefore"`
}

func certSpecOf(o Obj) certSpec {
	var s certSpec
	_ = o.Spec.Decode(&s)
	return s
}

// leafCerts are the identity Certificates (not the kind CA certificates).
func leafCerts(objs []Obj) []Obj {
	var out []Obj
	for _, o := range objs {
		if o.Kind == "Certificate" && !certSpecOf(o).IsCA {
			out = append(out, o)
		}
	}
	return out
}

func issuersOf(objs []Obj) []Obj {
	var out []Obj
	for _, o := range objs {
		if o.Kind == "Issuer" {
			out = append(out, o)
		}
	}
	return out
}

// checkCatalog: the Certificates rendered for a cluster are exactly the catalog entries naming it (operator entries only when asked), each once, with the
// catalog's name, URI and Secret name.
func checkCatalog(objs []Obj, cat []catEntry, cluster string, operators bool) []string {
	var bad []string
	got := map[string]int{}
	for _, o := range leafCerts(objs) {
		s := certSpecOf(o)
		if len(s.URIs) != 1 {
			bad = append(bad, fmt.Sprintf("%s: want exactly one URI, got %v", o.Metadata.Name, s.URIs))
			continue
		}
		got[s.URIs[0]]++
		var e *catEntry
		for i := range cat {
			if cat[i].URI == s.URIs[0] {
				e = &cat[i]
			}
		}
		switch {
		case e == nil:
			bad = append(bad, fmt.Sprintf("%s: %s is not in the catalog", o.Metadata.Name, s.URIs[0]))
		case s.SecretName != e.SecretName:
			bad = append(bad, fmt.Sprintf("%s: secret %s, catalog says %s", e.Name, s.SecretName, e.SecretName))
		case s.CN != e.Name:
			bad = append(bad, fmt.Sprintf("%s: commonName %s must be the service name", e.Name, s.CN))
		}
	}
	for _, e := range cat {
		want := 0
		if (cluster == "all" || hasStr(e.Clusters, cluster)) && (operators || !e.Operator) {
			want = 1
		}
		if got[e.URI] != want {
			bad = append(bad, fmt.Sprintf("cluster %s: %s rendered %d times, want %d", cluster, e.URI, got[e.URI], want))
		}
	}
	return bad
}

func hasStr(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func TestCertsEveryCatalogEntryIsRenderedInItsClusters(t *testing.T) {
	cat := loadCatalog(t)
	for _, c := range certClusters {
		t.Run(c, func(t *testing.T) {
			objs := mustRender(t, "values.yaml", "--set", "cluster="+c)
			for _, m := range checkCatalog(objs, cat, c, false) {
				t.Error(m)
			}
		})
	}
	t.Run("kind", func(t *testing.T) {
		for _, m := range checkCatalog(mustRender(t, "values-kind.yaml"), cat, "all", true) {
			t.Error(m)
		}
	})
	t.Run("operators on", func(t *testing.T) {
		objs := mustRender(t, "values.yaml", "--set", "cluster=business", "--set", "operatorCertificates=true")
		for _, m := range checkCatalog(objs, cat, "business", true) {
			t.Error(m)
		}
	})
	// every entry is rendered in at least one cluster of a production install (operators aside), so none can be forgotten by the chart
	seen := map[string]bool{}
	for _, c := range certClusters {
		for _, o := range leafCerts(mustRender(t, "values.yaml", "--set", "cluster="+c)) {
			seen[certSpecOf(o).URIs[0]] = true
		}
	}
	for _, e := range cat {
		if !e.Operator && !seen[e.URI] {
			t.Errorf("%s is in no cluster's render", e.URI)
		}
	}
}

func TestCertsCheckCatchesDrift(t *testing.T) {
	cat := loadCatalog(t)
	objs := mustRender(t, "values.yaml", "--set", "cluster=business")
	// a catalog entry the chart does not render
	if m := checkCatalog(objs, append(cat[:len(cat):len(cat)], catEntry{Name: "newsvc", Zone: "business", URI: "spiffe://quorumvault/business/newsvc", Clusters: []string{"business"}, SecretName: "qv-newsvc-tls"}), "business", false); len(m) == 0 {
		t.Error("a catalog entry missing from the chart was not caught")
	}
	// an entry the catalog does not have
	var short []catEntry
	for _, e := range cat {
		if e.Name != "worker" {
			short = append(short, e)
		}
	}
	if m := checkCatalog(objs, short, "business", false); len(m) == 0 {
		t.Error("a certificate that is not in the catalog was not caught")
	}
	// an entry in the wrong cluster
	moved := append([]catEntry(nil), cat...)
	for i := range moved {
		if moved[i].Name == "core" {
			moved[i].Clusters = []string{"party-b"}
		}
	}
	if m := checkCatalog(objs, moved, "business", false); len(m) == 0 {
		t.Error("an entry in the wrong cluster was not caught")
	}
}

// checkNoKeyMaterial: no Secret at all, no private key text, and PEM only in the public trust-bundle ConfigMaps.
func checkNoKeyMaterial(objs []Obj) []string {
	var bad []string
	for _, o := range objs {
		id := o.Kind + "/" + o.Metadata.Name
		switch {
		case o.Kind == "Secret":
			bad = append(bad, id+": a Secret is rendered (certificates are made by cert-manager, never by the chart)")
		case strings.Contains(o.Raw, "PRIVATE KEY"):
			bad = append(bad, id+": private key text")
		case strings.Contains(o.Raw, "-----BEGIN") && !(o.Kind == "ConfigMap" && strings.HasPrefix(o.Metadata.Name, "qv-trust-")):
			bad = append(bad, id+": PEM outside a trust bundle")
		}
	}
	return bad
}

func TestCertsNoKeyMaterialRendered(t *testing.T) {
	pemFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(pemFile, []byte(testCAPEM(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range certClusters {
		objs := mustRender(t, "values.yaml", "--set", "cluster="+c, "--set-file", "trust.business="+pemFile, "--set-file", "trust.signing="+pemFile)
		for _, m := range checkNoKeyMaterial(objs) {
			t.Errorf("%s: %s", c, m)
		}
	}
	for _, m := range checkNoKeyMaterial(mustRender(t, "values-kind.yaml")) {
		t.Errorf("kind: %s", m)
	}
	// the chart takes a bundle with a key in it as an error, and the check sees a PEM that sits anywhere else
	if _, err := renderCerts(t, "values.yaml", "--set", "cluster=business", "--set", "trust.business=-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\nAA\n-----END PRIVATE KEY-----"); err == nil {
		t.Error("a trust bundle with a private key was accepted")
	}
	bad, _ := Parse("kind: ConfigMap\nmetadata: {name: other}\ndata: {x: '-----BEGIN CERTIFICATE-----'}\n---\nkind: Secret\nmetadata: {name: s}\n")
	if len(checkNoKeyMaterial(bad)) != 2 {
		t.Error("checkNoKeyMaterial missed a PEM in a ConfigMap or a Secret")
	}
}

// checkPinned: a Certificate rotates its key (Always) unless the catalog pins it, and then it never does.
func checkPinned(objs []Obj, cat []catEntry) []string {
	var bad []string
	for _, o := range leafCerts(objs) {
		s := certSpecOf(o)
		for _, e := range cat {
			if e.URI != s.URIs[0] {
				continue
			}
			want := "Always"
			if e.Pinned {
				want = "Never"
			}
			if s.PrivateKey.Rotation != want {
				bad = append(bad, fmt.Sprintf("%s: rotationPolicy %q, want %s", e.Name, s.PrivateKey.Rotation, want))
			}
		}
	}
	return bad
}

func TestCertsPinnedIdentitiesNeverRotateKeys(t *testing.T) {
	cat := loadCatalog(t)
	pinned := 0
	for _, c := range append(append([]string(nil), certClusters...), "all") {
		var objs []Obj
		if c == "all" {
			objs = mustRender(t, "values-kind.yaml")
		} else {
			objs = mustRender(t, "values.yaml", "--set", "cluster="+c)
		}
		for _, m := range checkPinned(objs, cat) {
			t.Errorf("%s: %s", c, m)
		}
		for _, o := range leafCerts(objs) {
			for _, e := range cat {
				if e.URI == certSpecOf(o).URIs[0] && e.Pinned {
					pinned++
				}
			}
		}
	}
	if pinned == 0 {
		t.Fatal("no pinned certificate was rendered")
	}
	// the check fails when a pinned certificate is allowed to rotate
	objs := mustRender(t, "values.yaml", "--set", "cluster=party-b")
	for i := range objs {
		if objs[i].Kind == "Certificate" && strings.Contains(objs[i].Raw, "mpc-party-b") {
			objs[i].Spec = mustNode(t, strings.ReplaceAll(certNodeText(t, objs[i].Spec), "rotationPolicy: Never", "rotationPolicy: Always"))
		}
	}
	if len(checkPinned(objs, cat)) == 0 {
		t.Error("a pinned certificate with rotationPolicy Always was not caught")
	}
}

func certNodeText(t testing.TB, n yaml.Node) string {
	t.Helper()
	b, err := yaml.Marshal(&n)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func mustNode(t testing.TB, s string) yaml.Node {
	t.Helper()
	var n yaml.Node
	if err := yaml.Unmarshal([]byte(s), &n); err != nil {
		t.Fatal(err)
	}
	return *n.Content[0]
}

// checkZones: the business cluster has no signing-zone issuer or certificate and the reverse; in a signing cluster the business authority signs link
// certificates only (names ending -link), through its restricted issuer.
func checkZones(objs []Obj, cluster string) []string {
	var bad []string
	for _, i := range issuersOf(objs) {
		n := i.Metadata.Name
		switch {
		case cluster == "business" && n != "qv-business":
			bad = append(bad, "business cluster has issuer "+n)
		case cluster != "business" && n != "qv-signing" && n != "qv-business-link":
			bad = append(bad, cluster+" has issuer "+n)
		}
	}
	for _, o := range leafCerts(objs) {
		s := certSpecOf(o)
		uri := s.URIs[0]
		switch {
		case cluster == "business" && (strings.Contains(uri, "/signing/") || s.IssuerRef.Name != "qv-business"):
			bad = append(bad, "business cluster: "+uri+" signed by "+s.IssuerRef.Name)
		case cluster != "business" && strings.Contains(uri, "/business/") && !(strings.HasSuffix(uri, "-link") && s.IssuerRef.Name == "qv-business-link"):
			bad = append(bad, cluster+": business-zone name "+uri+" that is not a link, or not signed by the link issuer")
		case cluster != "business" && strings.Contains(uri, "/signing/") && s.IssuerRef.Name != "qv-signing":
			bad = append(bad, cluster+": "+uri+" signed by "+s.IssuerRef.Name)
		case s.IssuerRef.Kind != "Issuer":
			bad = append(bad, uri+": issuer kind "+s.IssuerRef.Kind+" (a namespaced Issuer is the limit of one cluster's namespace)")
		}
	}
	return bad
}

func TestCertsZonesStayApart(t *testing.T) {
	links := map[string][]string{}
	for _, c := range certClusters {
		objs := mustRender(t, "values.yaml", "--set", "cluster="+c)
		for _, m := range checkZones(objs, c) {
			t.Error(m)
		}
		for _, o := range leafCerts(objs) {
			if s := certSpecOf(o); s.IssuerRef.Name == "qv-business-link" {
				links[c] = append(links[c], s.URIs[0])
			}
		}
	}
	// the link certificates by cluster: the gateway's in signing-core, the cosigner's in parties B and C, none elsewhere
	want := map[string][]string{
		"signing-core": {"spiffe://quorumvault/business/gateway-link"},
		"party-b":      {"spiffe://quorumvault/business/cosigner-link"},
		"party-c":      {"spiffe://quorumvault/business/cosigner-link"},
	}
	for _, c := range certClusters {
		sort.Strings(links[c])
		if strings.Join(links[c], ",") != strings.Join(want[c], ",") {
			t.Errorf("%s: link certificates %v, want %v", c, links[c], want[c])
		}
	}
	// the broker and the business cluster have no link issuer at all
	for _, c := range []string{"business", "broker"} {
		for _, i := range issuersOf(mustRender(t, "values.yaml", "--set", "cluster="+c)) {
			if i.Metadata.Name == "qv-business-link" {
				t.Errorf("%s has a link issuer", c)
			}
		}
	}
	// the checks fail on a mixed-up render
	sc := mustRender(t, "values.yaml", "--set", "cluster=signing-core")
	if len(checkZones(sc, "business")) == 0 {
		t.Error("a signing render passed as a business cluster")
	}
	if len(checkZones(mustRender(t, "values.yaml", "--set", "cluster=business"), "party-b")) == 0 {
		t.Error("a business render passed as a signing cluster")
	}
}

func TestCertsProductionHoldsNoCA(t *testing.T) {
	for _, c := range certClusters {
		objs := mustRender(t, "values.yaml", "--set", "cluster="+c)
		for _, o := range objs {
			if o.Kind == "Certificate" && certSpecOf(o).IsCA {
				t.Errorf("%s: CA certificate %s in a production render", c, o.Metadata.Name)
			}
			if o.Kind == "Issuer" && (strings.Contains(o.Raw, "selfSigned") || strings.Contains(o.Raw, "\n  ca:")) {
				t.Errorf("%s: issuer %s is not a Vault issuer", c, o.Metadata.Name)
			}
			if o.Kind == "Issuer" && !strings.Contains(o.Raw, "vault:") {
				t.Errorf("%s: issuer %s has no vault section", c, o.Metadata.Name)
			}
		}
	}
	// kind makes the authorities at install time: two CA certificates and two CA issuers, and no key is in the repository
	objs := mustRender(t, "values-kind.yaml")
	cas := 0
	for _, o := range objs {
		if o.Kind == "Certificate" && certSpecOf(o).IsCA {
			cas++
		}
	}
	if cas != 2 {
		t.Errorf("kind renders %d CA certificates, want 2 (business and signing)", cas)
	}
	for _, f := range []string{"values.yaml", "values-kind.yaml", "certs-ci-values.yaml"} {
		p := filepath.Join(certChart(), f)
		if f == "certs-ci-values.yaml" {
			p = f
		}
		b, _ := os.ReadFile(p)
		if strings.Contains(string(b), "-----BEGIN") {
			t.Errorf("%s holds PEM text", f)
		}
	}
}

func TestCertsRefusals(t *testing.T) {
	for name, args := range map[string][]string{
		"no cluster":                 {"--set", "cluster="},
		"unknown cluster":            {"--set", "cluster=party-d"},
		"all with vault":             {"--set", "cluster=all"},
		"vault without a server":     {"--set", "cluster=business", "--set", "issuers.vault.business.server="},
		"http vault":                 {"--set", "cluster=business", "--set", "issuers.vault.business.server=http://vault:8200"},
		"empty trust":                {"--set", "cluster=business", "--set", "trust.allowEmpty=false"},
		"trust is not a certificate": {"--set", "cluster=business", "--set", "trust.allowEmpty=false", "--set", "trust.business=hello"},
		"a lifetime without a unit":  {"--set", "cluster=business", "--set", "duration.default=72"},
	} {
		if _, err := renderCerts(t, "values.yaml", args...); err == nil {
			t.Errorf("%s: the chart rendered", name)
		}
	}
}

// The trust bundle of a zone is a ConfigMap of that zone with the CA certificate from values, in exactly the clusters that hold that zone's identities.
func TestCertsTrustBundles(t *testing.T) {
	pemFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(pemFile, []byte(testCAPEM(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"business": {"qv-trust-business"}, "broker": {"qv-trust-signing"},
		"signing-core": {"qv-trust-business", "qv-trust-signing"}, "party-b": {"qv-trust-business", "qv-trust-signing"}, "party-c": {"qv-trust-business", "qv-trust-signing"},
	}
	for c, w := range want {
		var got []string
		for _, o := range mustRender(t, "values.yaml", "--set", "cluster="+c, "--set-file", "trust.business="+pemFile, "--set-file", "trust.signing="+pemFile) {
			if o.Kind == "ConfigMap" {
				got = append(got, o.Metadata.Name)
				if s, _ := o.Data["ca.crt"].(string); !strings.HasPrefix(s, "-----BEGIN CERTIFICATE-----") {
					t.Errorf("%s: %s has no ca.crt", c, o.Metadata.Name)
				}
			}
		}
		sort.Strings(got)
		if strings.Join(got, ",") != strings.Join(w, ",") {
			t.Errorf("%s: trust bundles %v, want %v", c, got, w)
		}
	}
}

// The business chart refers to certificate Secrets by name: every one it asks for in production must be a Secret this chart makes in the business cluster.
func TestCertsSecretNamesMatchTheBusinessChart(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "deploy", "helm", "qv-business", "values.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		TLS map[string]any `yaml:"tls"`
	}
	if err := yaml.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	made := map[string]bool{}
	for _, o := range leafCerts(mustRender(t, "values.yaml", "--set", "cluster=business")) {
		made[certSpecOf(o).SecretName] = true
	}
	n := 0
	for k, x := range v.TLS {
		m, ok := x.(map[string]any)
		if !ok {
			continue
		}
		name, _ := m["secretName"].(string)
		n++
		if !made[name] {
			t.Errorf("qv-business tls.%s wants Secret %q, which qv-certs does not make in the business cluster", k, name)
		}
	}
	if n < 5 {
		t.Errorf("read only %d secret names from the business chart", n)
	}
}

// Lifetimes: renewal must start before expiry for every identity, and pinned identities live longer than the 30-day pin alert.
func TestCertsLifetimes(t *testing.T) {
	for _, o := range leafCerts(mustRender(t, "values-kind.yaml")) {
		s := certSpecOf(o)
		d, err1 := time.ParseDuration(s.Duration)
		r, err2 := time.ParseDuration(s.RenewBefore)
		if err1 != nil || err2 != nil || r >= d {
			t.Errorf("%s: duration %q renewBefore %q", o.Metadata.Name, s.Duration, s.RenewBefore)
		}
		if s.PrivateKey.Rotation == "Never" && d < 90*24*time.Hour {
			t.Errorf("%s: a pinned identity with a lifetime of %s", o.Metadata.Name, d)
		}
	}
}

// kind runs one cluster with four namespaces, and all of them must issue under the SAME authority. With issuers.ca.existing the chart makes no CA of its own: it
// renders only the issuers that read the Secrets the kind setup copied into the namespace. Without the switch a signing namespace would invent a second signing CA.
func TestCertsExistingCAMakesNoAuthority(t *testing.T) {
	for _, c := range []string{"business", "signing-core", "party-b", "party-c"} {
		own := mustRender(t, "values-kind.yaml", "--set", "cluster="+c)
		shared := mustRender(t, "values-kind.yaml", "--set", "cluster="+c, "--set", "issuers.ca.existing=true")
		ownCAs, sharedCAs, selfSigned, caIssuers := 0, 0, 0, map[string]string{}
		for _, o := range own {
			if o.Kind == "Certificate" && certSpecOf(o).IsCA {
				ownCAs++
			}
		}
		for _, o := range shared {
			if o.Kind == "Certificate" && certSpecOf(o).IsCA {
				sharedCAs++
			}
			if o.Kind == "Issuer" && strings.Contains(o.Raw, "selfSigned") {
				selfSigned++
			}
			if o.Kind == "Issuer" && strings.Contains(o.Raw, "secretName:") {
				caIssuers[o.Metadata.Name] = o.Raw
			}
		}
		if ownCAs == 0 {
			t.Errorf("%s: without the switch kind makes no CA (the test would prove nothing)", c)
		}
		if sharedCAs != 0 || selfSigned != 0 {
			t.Errorf("%s: with issuers.ca.existing the chart still makes %d CA certificates and %d self-signed issuers", c, sharedCAs, selfSigned)
		}
		if _, ok := caIssuers["qv-signing"]; c != "business" && !ok {
			t.Errorf("%s: no CA issuer reads the signing Secret", c)
		}
		if _, ok := caIssuers["qv-business"]; c == "business" && !ok {
			t.Errorf("%s: no CA issuer reads the business Secret", c)
		}
	}
	// production never holds a CA, with or without the switch
	for _, o := range mustRender(t, "values.yaml", "--set", "cluster=business", "--set", "issuers.ca.existing=true") {
		if o.Kind == "Issuer" && !strings.Contains(o.Raw, "vault:") {
			t.Errorf("issuer %s is not a Vault issuer", o.Metadata.Name)
		}
	}
}

// The party and signing-core charts name their certificate Secrets by default; every name ending in -tls must be one qv-certs makes in the cluster that holds the chart
// (found by the kind lane: the party chart asked for `mpc-party-c-tls`, qv-certs makes `qv-signing-mpc-party-c-tls`, and no pod started).
func TestCertsSecretNamesMatchThePartyAndSigningCoreCharts(t *testing.T) {
	re := regexp.MustCompile(`(?m)secretName: "?([a-z0-9-]+-tls)"?`)
	check := func(what, text, cluster string) {
		made := map[string]bool{}
		for _, o := range leafCerts(mustRender(t, "values.yaml", "--set", "cluster="+cluster)) {
			made[certSpecOf(o).SecretName] = true
		}
		found := re.FindAllStringSubmatch(text, -1)
		if len(found) < 1 {
			t.Fatalf("%s: found only %d certificate Secret names", what, len(found))
		}
		for _, m := range found {
			if !made[m[1]] {
				t.Errorf("%s asks for Secret %q, which qv-certs does not make in cluster %s", what, m[1], cluster)
			}
		}
	}
	for role, cluster := range map[string]string{"A": "signing-core", "B": "party-b", "C": "party-c"} {
		text, err := partyRender(true, role)
		if err != nil {
			t.Fatal(err)
		}
		check("qv-party "+role, text, cluster)
	}
	check("qv-signing-core", scText(t, true), "signing-core")
}
