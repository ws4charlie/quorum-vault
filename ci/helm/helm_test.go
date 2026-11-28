package helmcheck

import (
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

var valuesFiles = []struct {
	file          string
	requireDigest bool
	enableLogin   bool
}{
	{"values.yaml", true, false},
	{"values-kind.yaml", false, true},
}

func render(t *testing.T, file string, extra ...string) []Obj {
	t.Helper()
	text, err := Render(file, extra...)
	if err != nil {
		if os.Getenv("CI") == "" && strings.Contains(err.Error(), "not found on PATH") {
			t.Skip(err)
		}
		t.Fatal(err)
	}
	objs, err := Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	return objs
}

func opts(digest bool) PolicyOptions {
	return PolicyOptions{RequireDigest: digest, CorePort: 8443, ApprovalPort: 8090, LinkPorts: []int{5432, 9092}}
}

// kindCoreEnv is the one policy finding kind tolerates: QV_ENV=dev in qv-core's ConfigMap (core.env: dev), because the kind smoke logs in with
// the dev realm's test clients and a production core refuses them (internal/auth E2EClients). As qv-party and the broker tolerate their
// QV_ENV=dev in kind. Production values never set it (TestCoreEnvOnlyOutsideProduction).
var kindCoreEnv = regexp.MustCompile(`^ConfigMap/qv-core-env-[0-9a-f]+\[QV_ENV\]: a development switch is set$`)

// policyFindings is CheckPolicy and CheckMigration on a render of valuesFile, less the kind exception kindCoreEnv.
func policyFindings(objs []Obj, valuesFile string, requireDigest, enableLogin bool) []string {
	var out []string
	for _, m := range append(CheckPolicy(objs, opts(requireDigest)), CheckMigration(objs, enableLogin)...) {
		if valuesFile == "values-kind.yaml" && kindCoreEnv.MatchString(m) {
			continue
		}
		out = append(out, m)
	}
	return out
}

func TestPolicyPasses(t *testing.T) {
	for _, vf := range valuesFiles {
		t.Run(vf.file, func(t *testing.T) {
			objs := render(t, vf.file)
			for _, m := range policyFindings(objs, vf.file, vf.requireDigest, vf.enableLogin) {
				t.Error(m)
			}
		})
	}
}

// core.env: production renders no QV_ENV anywhere and refuses core.env with digests; kind renders QV_ENV=dev in qv-core's ConfigMap only;
// the kind exception covers that one finding and nothing else.
func TestCoreEnvOnlyOutsideProduction(t *testing.T) {
	prod, err := Render("values.yaml")
	if err != nil {
		t.Skip(err)
	}
	if strings.Contains(prod, "QV_ENV") {
		t.Error("the production render sets QV_ENV")
	}
	for _, v := range []string{"dev", "test"} {
		if _, err := Render("values.yaml", "--set", "core.env="+v); err == nil || !strings.Contains(err.Error(), "core.env") {
			t.Errorf("production values with core.env=%s rendered: %v", v, err)
		}
	}
	if _, err := Render("values-kind.yaml", "--set", "core.env=staging"); err == nil {
		t.Error("core.env=staging rendered")
	}
	var found []string
	for _, o := range render(t, "values-kind.yaml") {
		if o.Kind == "ConfigMap" && o.Data["QV_ENV"] != nil {
			found = append(found, o.Metadata.Name)
			if !strings.HasPrefix(o.Metadata.Name, "qv-core-env-") || o.Data["QV_ENV"] != "dev" {
				t.Errorf("kind: QV_ENV=%v in %s (only qv-core's ConfigMap may set it, to dev)", o.Data["QV_ENV"], o.Metadata.Name)
			}
		}
	}
	if len(found) != 1 {
		t.Errorf("kind: want QV_ENV in exactly qv-core's ConfigMap, got %v", found)
	}
	for _, m := range []string{
		"ConfigMap/qv-worker-env-0123abcd[QV_ENV]: a development switch is set",
		"ConfigMap/qv-core-env-0123abcd[QV_ALLOW_PLAINTEXT]: a development switch is set",
		"Deployment/qv-core/qv-core: development switch QV_ENV",
	} {
		if kindCoreEnv.MatchString(m) {
			t.Errorf("the kind exception also hides %q", m)
		}
	}
}

func TestContractPasses(t *testing.T) {
	c, err := LoadContract()
	if err != nil {
		t.Fatal(err)
	}
	for _, vf := range valuesFiles {
		t.Run(vf.file, func(t *testing.T) {
			objs := render(t, vf.file)
			if len(Workloads(objs)) < 5 {
				t.Fatalf("only %d workloads rendered", len(Workloads(objs)))
			}
			for _, m := range CheckContract(objs, c) {
				t.Error(m)
			}
		})
	}
}

// The checks are worth only what they catch: each case breaks the rendered manifest in one way and wants that violation (and only a violation of that kind).
func TestPolicyCatches(t *testing.T) {
	text, err := Render("values.yaml")
	if err != nil {
		t.Skip(err)
	}
	cases := []struct{ name, from, to, want string }{
		{"root filesystem writable", "readOnlyRootFilesystem: true", "readOnlyRootFilesystem: false", "readOnlyRootFilesystem is not true"},
		{"runs as root", "runAsNonRoot: true", "runAsNonRoot: false", "runAsNonRoot is not true"},
		{"capability added", `drop: ["ALL"]`, `drop: ["ALL"]` + "\n              add: [NET_ADMIN]", "capabilities added"},
		{"host network", "hostNetwork: false", "hostNetwork: true", "hostNetwork"},
		{"privilege escalation", "allowPrivilegeEscalation: false", "allowPrivilegeEscalation: true", "allowPrivilegeEscalation is not false"},
		{"bare tag in production", "qv-core@sha256:1111111111111111111111111111111111111111111111111111111111111111", "qv-core:latest", "not referenced by digest"},
		{"no memory limit", "              memory: 1Gi\n", "", "memory request and limit"},
		{"service token mounted", "automountServiceAccountToken: false\n      hostNetwork: false", "automountServiceAccountToken: true\n      hostNetwork: false", "automountServiceAccountToken true"},
		{"password in a ConfigMap", `QV_TEMPORAL_ADDR: "temporal-gate:7233"`, `QV_TEMPORAL_ADDR: "temporal-gate:7233"` + "\n  QV_DB_PASSWORD: \"hunter2\"", "secret-named key"},
		{"password in the DSN", "postgres://qv_core@", "postgres://qv_core:hunter2@", "password inside a URL"},
		{"dev switch", `QV_TEMPORAL_ADDR: "temporal-gate:7233"`, `QV_TEMPORAL_ADDR: "temporal-gate:7233"` + "\n  QV_ALLOW_PLAINTEXT: \"1\"", "development switch"},
		{"default deny removed", "policyTypes: [Ingress, Egress]", "policyTypes: [Egress]", "no default-deny"},
		{"public NodePort", "type: ClusterIP", "type: NodePort", "Service type"},
		{"Secret rendered", "kind: ServiceAccount", "kind: Secret", "must not render a Secret"},
		{"PEM in output", `QV_TEMPORAL_ADDR: "temporal-gate:7233"`, `QV_TEMPORAL_ADDR: "temporal-gate:7233"` + "\n  TLS_PEM: \"-----BEGIN PRIVATE KEY-----\"", "PEM block"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(text, tc.from) {
				t.Fatalf("test is stale: %q not in the rendered chart", tc.from)
			}
			objs, err := Parse(strings.ReplaceAll(text, tc.from, tc.to))
			if err != nil {
				t.Fatal(err)
			}
			if !anyContains(CheckPolicy(objs, opts(true)), tc.want) {
				t.Errorf("no violation containing %q", tc.want)
			}
		})
	}
}

func TestExternalIngressIsOnlyTheTwoLinks(t *testing.T) {
	objs := render(t, "values.yaml", "--set", "network.signingLink.from[0].ipBlock.cidr=10.9.0.0/16")
	if m := CheckPolicy(objs, opts(true)); len(m) > 0 {
		t.Fatalf("a configured signing link must pass: %v", m)
	}
	links := 0
	for _, o := range objs {
		if o.Kind == "NetworkPolicy" && o.Metadata.Annotations["quorumvault.io/ingress-purpose"] == "signing-link" {
			links++
		}
	}
	if links != 2 {
		t.Errorf("want 2 signing-link policies (Postgres, Kafka), got %d", links)
	}
	// an extra rule: any address may reach Postgres on 5432 without the link annotation, or the link opens another port
	text, _ := Render("values.yaml", "--set", "network.signingLink.from[0].ipBlock.cidr=10.9.0.0/16")
	bad := strings.Replace(text, "quorumvault.io/ingress-purpose: signing-link", "quorumvault.io/ingress-purpose: nothing", 1)
	o2, _ := Parse(bad)
	if !anyContains(CheckPolicy(o2, opts(true)), "neither the ingress controller nor the signing link") {
		t.Error("an unlabelled ingress from outside was not caught")
	}
	bad = strings.Replace(text, "ports: [{ port: 5432, protocol: TCP }]\n---\napiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: qv-signing-link-kafka", "ports: [{ port: 22, protocol: TCP }]\n---\napiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: qv-signing-link-kafka", 1)
	if bad != text {
		o3, _ := Parse(bad)
		if !anyContains(CheckPolicy(o3, opts(true)), "the signing link opens port 22") {
			t.Error("a link that opens another port was not caught")
		}
	}
}

func TestContractCatches(t *testing.T) {
	c, err := LoadContract()
	if err != nil {
		t.Fatal(err)
	}
	text, err := Render("values.yaml")
	if err != nil {
		t.Skip(err)
	}
	cases := []struct{ name, from, to, want string }{
		{"unknown flag", `args: ["-config", "/etc/qv/custody/config.json"]`, `args: ["-config", "/etc/qv/custody/config.json", "-skip-checks"]`, "flag -skip-checks is not in the contract"},
		{"missing required flag", `args: ["-config", "/etc/qv/custody/config.json"]`, `args: []`, "required flag -config is missing"},
		{"wrong port", `QV_HTTP_ADDR: "0.0.0.0:8443"`, `QV_HTTP_ADDR: "0.0.0.0:9443"`, "does not match containerPort"},
		{"wrong role", "postgres://qv_core@", "postgres://qv_worker@", "the role of this service is"},
		{"unknown env", `QV_TEMPORAL_ADDR: "temporal-gate:7233"`, `QV_TEMPORAL_ADDR: "temporal-gate:7233"` + "\n  QV_SURPRISE: \"1\"", "QV_SURPRISE is not in the contract"},
		{"file without a mount", "mountPath: /etc/qv/tls", "mountPath: /etc/qv/other", "no volume is mounted over it"},
		{"mount outside the contract", "mountPath: /etc/qv/tls", "mountPath: /srv/tls", "outside the contract's directories"},
		{"command overridden", "          args: [\"-config\"", "          command: [\"/bin/sh\"]\n          args: [\"-config\"", "sets command"},
		{"migrate in the wrong zone", "-zone\n            - business", "-zone\n            - signing", "-zone signing"},
		{"enable-login in the migrate step", "            - -zone\n            - business\n          env:", "            - -zone\n            - business\n            - \"-enable-login\"\n          env:", "belongs only in the container"},
		{"metrics reachable", `QV_HTTP_ADDR: "0.0.0.0:8443"`, `QV_HTTP_ADDR: "0.0.0.0:8443"` + "\n  QV_CORE_METRICS_LISTEN: \"0.0.0.0:9101\"", "not a loopback address"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(text, tc.from) {
				t.Fatalf("test is stale: %q not in the rendered chart", tc.from)
			}
			objs, err := Parse(strings.Replace(text, tc.from, tc.to, 1))
			if err != nil {
				t.Fatal(err)
			}
			if !anyContains(CheckContract(objs, c), tc.want) {
				t.Errorf("no drift containing %q; got %v", tc.want, CheckContract(objs, c))
			}
		})
	}
}

func TestMigrationOrderCaught(t *testing.T) {
	text, err := Render("values-kind.yaml")
	if err != nil {
		t.Skip(err)
	}
	bad := strings.Replace(text, `helm.sh/hook-weight: "-4"`, `helm.sh/hook-weight: "-9"`, 1)
	objs, _ := Parse(bad)
	if !anyContains(CheckMigration(objs, true), "must run after") {
		t.Error("login before migrate was not caught")
	}
	bad = strings.ReplaceAll(text, "helm.sh/hook: pre-install,pre-upgrade", "helm.sh/hook: post-install")
	objs, _ = Parse(bad)
	if !anyContains(CheckMigration(objs, true), "want pre-install,pre-upgrade") {
		t.Error("a post hook was not caught")
	}
}

func TestPlaceholderDigestRefused(t *testing.T) {
	zero := "sha256:" + strings.Repeat("0", 64)
	_, err := Render("values.yaml", "--set", "images.core.digest="+zero)
	if err == nil || !strings.Contains(err.Error(), "all-zero placeholder") {
		t.Errorf("an all-zero digest must fail the render, got %v", err)
	}
	if _, err := Render("values.yaml", "--set", "images.core.digest=", "--set", "images.core.tag="); err == nil {
		t.Error("an image without digest or tag must be refused")
	}
	// the shipped production values themselves must not render: their digests are placeholders
	helm, _ := exec.LookPath("helm")
	if helm != "" {
		if out, err := exec.Command(helm, "template", "qv", ChartDir(), "-f", ChartDir()+"/values.yaml").CombinedOutput(); err == nil {
			t.Errorf("values.yaml rendered with placeholder digests:\n%s", out[:200])
		}
	}
}

func TestNoCustodyConfigInChart(t *testing.T) {
	for _, vf := range valuesFiles {
		for _, o := range render(t, vf.file) {
			if o.Kind == "ConfigMap" {
				if _, ok := o.Data["config.json"]; ok {
					t.Errorf("%s renders a custody config", o.Metadata.Name)
				}
			}
			if pod, ok := o.Pod(); ok && len(pod.InitContainers) > 0 {
				t.Errorf("%s has init containers", o.Metadata.Name)
			}
		}
	}
}

func anyContains(l []string, s string) bool {
	for _, x := range l {
		if strings.Contains(x, s) {
			return true
		}
	}
	return false
}

// Every component probes the health listener of PR #97 (plain http, /readyz for start-up and readiness, /livez for liveness), and the listener is switched on by the
// same value that points the probe at it: the probe port is the port in QV_HEALTH_LISTEN. A TCP probe on core's TLS port (the old default) made every probe a failed
// TLS handshake in the log, and the other three components had no probe at all.
func TestProbesUseTheHealthListener(t *testing.T) {
	comps := []string{"core", "worker", "relay", "archiver"}
	for _, vf := range valuesFiles {
		objs := render(t, vf.file)
		for _, c := range comps {
			var dep, env *Obj
			for i, o := range objs {
				if o.Component() == c && o.Kind == "Deployment" {
					dep = &objs[i]
				}
				if o.Kind == "ConfigMap" && strings.Contains(o.Metadata.Name, "-"+c+"-env-") {
					env = &objs[i]
				}
			}
			if dep == nil || env == nil {
				t.Fatalf("%s: %s: no Deployment or env ConfigMap", vf.file, c)
			}
			listen, _ := env.Data["QV_HEALTH_LISTEN"].(string)
			if listen != "0.0.0.0:9100" {
				t.Errorf("%s: %s: QV_HEALTH_LISTEN = %q, want 0.0.0.0:9100", vf.file, c, listen)
			}
			for _, want := range []string{"path: /readyz, port: 9100", "path: /livez, port: 9100"} {
				if !strings.Contains(dep.Raw, want) {
					t.Errorf("%s: %s: no probe %q", vf.file, c, want)
				}
			}
			if strings.Contains(dep.Raw, "tcpSocket") {
				t.Errorf("%s: %s: a TCP probe", vf.file, c)
			}
		}
		// a component with probes off opens no health listener (nothing would use it)
		off := render(t, vf.file, "--set", "worker.probes.mode=none")
		for _, o := range off {
			if o.Kind == "ConfigMap" && strings.Contains(o.Metadata.Name, "-worker-env-") {
				if _, ok := o.Data["QV_HEALTH_LISTEN"]; ok {
					t.Errorf("%s: probes.mode=none still sets QV_HEALTH_LISTEN", vf.file)
				}
			}
			if o.Kind == "Deployment" && o.Component() == "worker" && strings.Contains(o.Raw, "Probe") {
				t.Errorf("%s: probes.mode=none still renders a probe", vf.file)
			}
		}
	}
}

// The migration job is a pre-install hook: on a first install nothing else of the chart exists yet. So every network rule it needs must be a hook too, on BOTH sides:
// its own egress, and the ingress of the database pods it connects to. Without the second, a database that is already isolated (default deny, or any operator policy)
// refuses the job and the first install hangs (found by the kind lane).
func TestMigrationHookHasBothNetworkRules(t *testing.T) {
	for _, vf := range valuesFiles {
		var egress, ingress bool
		for _, o := range render(t, vf.file) {
			if o.Kind != "NetworkPolicy" || !strings.Contains(o.Raw, "helm.sh/hook: pre-install") {
				continue
			}
			if strings.HasSuffix(o.Metadata.Name, "-migrate-egress") {
				egress = true
			}
			if strings.HasSuffix(o.Metadata.Name, "-migrate-postgres-in") && strings.Contains(o.Raw, "component: migrate") && strings.Contains(o.Raw, "port: 5432") {
				ingress = true
			}
		}
		if !egress || !ingress {
			t.Errorf("%s: hook policies: migrate egress %v, postgres ingress for the job %v", vf.file, egress, ingress)
		}
	}
	// the rule is part of the dependency policies: with them off, the chart renders none of them
	for _, o := range render(t, "values-kind.yaml", "--set", "network.dependencyPolicies.enabled=false") {
		if strings.HasSuffix(o.Metadata.Name, "-migrate-postgres-in") {
			t.Errorf("dependencyPolicies off still renders %s", o.Metadata.Name)
		}
	}
}

// The policy chart's rule, as the signing-core and party charts already keep it: every ConfigMap is immutable and its name carries a hash of its content, so a change of
// content is a new object and a new pod template (a rollout), never an edit in place. Each Deployment reads the ConfigMap that exists in the render.
func TestConfigMapsAreImmutableAndHashed(t *testing.T) {
	hashed := regexp.MustCompile(`-[0-9a-f]{10}$`)
	names := func(objs []Obj) map[string]string {
		m := map[string]string{}
		for _, o := range objs {
			if o.Kind != "ConfigMap" {
				continue
			}
			if !strings.Contains(o.Raw, "immutable: true") {
				t.Errorf("ConfigMap %s is not immutable", o.Metadata.Name)
			}
			if !hashed.MatchString(o.Metadata.Name) {
				t.Errorf("ConfigMap %s has no content hash in its name", o.Metadata.Name)
			}
			m[o.Metadata.Name] = o.Raw
		}
		return m
	}
	for _, vf := range valuesFiles {
		before := render(t, vf.file, "--set", "approval.enabled=true", "--set", "ingress.public.host=a.example.test", "--set", "approval.ingress.host=b.example.test")
		cms := names(before)
		if len(cms) < 5 {
			t.Errorf("%s: only %d ConfigMaps", vf.file, len(cms))
		}
		for _, o := range before {
			if pod, ok := o.Pod(); ok {
				for _, ref := range regexp.MustCompile(`configMapRef:\s*\{?\s*\n?\s*name: (\S+?)\s*\}?\n`).FindAllStringSubmatch(o.Raw, -1) {
					if _, ok := cms[strings.Trim(ref[1], `"{} `)]; !ok {
						t.Errorf("%s/%s reads ConfigMap %q, which the chart does not render", vf.file, o.Metadata.Name, ref[1])
					}
				}
				_ = pod
			}
		}
		// a content change renames the core's ConfigMap and the Deployment follows it (new pod template, so a rollout)
		after := render(t, vf.file, "--set", "oidc.audience=another-audience")
		var nb, na string
		for n := range cms {
			if strings.Contains(n, "-core-env-") {
				nb = n
			}
		}
		for n := range names(after) {
			if strings.Contains(n, "-core-env-") {
				na = n
			}
		}
		if nb == "" || na == "" || nb == na {
			t.Errorf("%s: a changed value did not rename the core ConfigMap (%q -> %q)", vf.file, nb, na)
		}
		for _, o := range after {
			if o.Kind == "Deployment" && o.Component() == "core" && !strings.Contains(o.Raw, na) {
				t.Errorf("%s: core's Deployment does not read %s", vf.file, na)
			}
		}
	}
}

// AgentGate's certificate name joins the core's service allow-list only when the chart says so.
func TestAgentGateJoinsTheAllowListOnlyWhenOn(t *testing.T) {
	allow := func(objs []Obj) string {
		for _, o := range objs {
			if o.Kind == "ConfigMap" && strings.Contains(o.Metadata.Name, "-core-env-") {
				m := regexp.MustCompile(`QV_CORE_SERVICE_ALLOW: "?([^"\n]*)"?`).FindStringSubmatch(o.Raw)
				if m != nil {
					return m[1]
				}
			}
		}
		t.Fatal("no QV_CORE_SERVICE_ALLOW in the core's ConfigMap")
		return ""
	}
	for _, vf := range valuesFiles {
		if a := allow(render(t, vf.file)); strings.Contains(a, "agentgate") {
			t.Errorf("%s: off by default, but the allow-list is %q", vf.file, a)
		}
		if a := allow(render(t, vf.file, "--set", "agentgate.enabled=true")); !strings.HasSuffix(a, ",business/agentgate") {
			t.Errorf("%s: on, but the allow-list is %q", vf.file, a)
		}
	}
}
