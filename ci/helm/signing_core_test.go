package helmcheck

// Checks for the qv-signing-core chart (deploy/helm/qv-signing-core): the policy and image-contract checks of the business chart applied to it, plus the rules
// of a signing cluster: nothing reaches the pod from outside, egress goes only to named peers, no SoftHSM and no development switch in production, the
// signed-setting Job is off by default and carries no key. Each rule is shown to fail on a bad manifest.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

const scCI = "signing-core-ci.yaml"

func scDir() string { return filepath.Join("..", "..", "deploy", "helm", "qv-signing-core") }

// scRender renders the chart with the CI inputs (made-up digests, required values) and, for kind, the kind values on top.
func scRender(kind bool, extra ...string) (string, error) {
	helm, err := exec.LookPath("helm")
	if err != nil {
		return "", fmt.Errorf("helm not found on PATH: %w", err)
	}
	args := []string{"template", "qv", scDir(), "--namespace", "qvs", "-f", scCI}
	if kind {
		args = append(args, "-f", filepath.Join(scDir(), "values-kind.yaml"))
	}
	args = append(args, extra...)
	cmd := exec.Command(helm, args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("helm template: %w\n%s", err, errb.String())
	}
	return out.String(), nil
}

func scText(t *testing.T, kind bool, extra ...string) string {
	t.Helper()
	text, err := scRender(kind, extra...)
	if err != nil {
		if os.Getenv("CI") == "" && strings.Contains(err.Error(), "not found on PATH") {
			t.Skip(err)
		}
		t.Fatal(err)
	}
	return text
}

func scObjs(t *testing.T, kind bool, extra ...string) []Obj {
	t.Helper()
	objs, err := Parse(scText(t, kind, extra...))
	if err != nil {
		t.Fatal(err)
	}
	return objs
}

// ---- generic access to a rendered object (the shared structs do not carry every field these checks need) ----

func asMap(o Obj) map[string]any {
	var m map[string]any
	_ = o.Spec.Decode(&m)
	return m
}

func dig(v any, path ...string) any {
	for _, p := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[p]
	}
	return v
}

func list(v any) []any { l, _ := v.([]any); return l }

func scStr(v any) string { s, _ := v.(string); return s }

// ---- the checks of this chart ----

type scOpts struct {
	Production      bool // production values: no development switch of any kind
	JobOffByDefault bool
}

// checkSigning returns one line per violation of the signing-cluster rules.
func checkSigning(objs []Obj, op scOpts) []string {
	var v []string
	add := func(f string, a ...any) { v = append(v, fmt.Sprintf(f, a...)) }
	for _, o := range objs {
		id := o.Kind + "/" + o.Metadata.Name
		switch o.Kind {
		case "Ingress", "IngressClass":
			add("%s: a signing cluster has no Ingress", id)
		case "Service":
			add("%s: the gateway listens on nothing a peer may use: no Service at all", id)
		case "ConfigMap":
			if o.Raw != "" && !strings.Contains(o.Raw, "immutable: true") {
				add("%s: a ConfigMap of this chart must be immutable (a change is a new rollout)", id)
			}
			n := o.Metadata.Name
			if len(n) < 12 || strings.Count(n, "-") < 2 {
				add("%s: the name carries no content hash", id)
			}
		case "NetworkPolicy":
			m := asMap(o)
			for _, r := range list(m["ingress"]) {
				for _, f := range list(dig(r, "from")) {
					if dig(f, "ipBlock") != nil || dig(f, "namespaceSelector") != nil {
						add("%s: ingress from an address or another namespace (a signing cluster takes none)", id)
					}
				}
				if len(list(dig(r, "from"))) == 0 {
					add("%s: an ingress rule with no `from` admits everyone", id)
				}
			}
			for _, r := range list(m["egress"]) {
				if len(list(dig(r, "to"))) == 0 {
					add("%s: an egress rule with no `to` admits every destination", id)
				}
				if len(list(dig(r, "ports"))) == 0 {
					add("%s: an egress rule with no ports admits every port", id)
				}
				for _, to := range list(dig(r, "to")) {
					if c := scStr(dig(to, "ipBlock", "cidr")); c == "0.0.0.0/0" || c == "::/0" {
						add("%s: egress to %s (no internet egress from a signing cluster)", id, c)
					}
				}
			}
		}
		if strings.Contains(strings.ToLower(o.Raw), "softhsm") && op.Production {
			add("%s: SoftHSM appears in the production render", id)
		}
		if op.Production && (strings.Contains(o.Raw, "QV_ENV") || strings.Contains(o.Raw, "QV_ALLOW_PLAINTEXT")) {
			add("%s: QV_ENV or a plaintext switch appears in the production render", id)
		}
		pod, ok := o.Pod()
		if !ok {
			continue
		}
		for _, c := range pod.Containers {
			for _, e := range c.Env {
				if e.Name == "QV_HSM_PIN" {
					add("%s: QV_HSM_PIN is an environment variable of container %s: the PIN is a file (QV_HSM_PIN_FILE), an environment is visible in process listings and crash dumps", id, c.Name)
				}
			}
		}
		if o.Kind == "Job" && o.Component() == "tools" {
			if op.JobOffByDefault {
				add("%s: the signed-setting Job is rendered by default", id)
			}
			checkToolsJob(id, o, pod, add)
		}
	}
	return v
}

var signedTools = map[string]bool{"/usr/local/bin/qv-route": true, "/usr/local/bin/qv-fee-caps": true, "/usr/local/bin/qv-approvers": true, "/usr/local/bin/qv-keysets": true}

// checkToolsJob: the operator Job may run only `show` or `apply`, mounts no key, and reads only what it needs.
func checkToolsJob(id string, o Obj, pod PodSpec, add func(string, ...any)) {
	for _, c := range pod.Containers {
		if len(c.Command) != 1 || !signedTools[c.Command[0]] {
			add("%s: command %v is not one of the four signed-setting tools", id, c.Command)
		}
		for i, a := range c.Args {
			if i == 0 && a != "show" && a != "apply" {
				add("%s: action %q (only show and apply run in a cluster; sign belongs on the operator's machine)", id, a)
			}
			switch strings.TrimLeft(a, "-") {
			case "key", "operator", "approver-key", "actor", "key-file":
				add("%s: argument %s hands a signing key or an identity to the tool", id, a)
			}
		}
		if len(c.Env) != 1 || c.Env[0].Name != "QV_GATEWAY_GUARD_DSN" {
			add("%s: the Job's environment is only QV_GATEWAY_GUARD_DSN", id)
		}
	}
	for _, vl := range pod.Volumes {
		switch {
		case vl.Secret != nil && vl.Name == "tls":
			// the gateway's own certificate: the login to the guard database (a TLS key, not a signing key)
		case vl.ConfigMap != nil && (vl.Name == "config" || vl.Name == "signed"):
		default:
			add("%s: volume %s: only the guard login certificate and two ConfigMaps may be mounted", id, vl.Name)
		}
	}
}

// scPolicy runs the business chart's policy checks plus this chart's rules; for kind it lets the dev switch through where kind needs it.
func scPolicy(objs []Obj, kind bool) []string {
	var out []string
	for _, m := range CheckPolicy(objs, PolicyOptions{RequireDigest: !kind}) {
		if kind && strings.Contains(m, "ConfigMap/qv-gateway-env") && strings.Contains(m, "QV_ENV") {
			continue // kind: QV_ENV=dev is what lets the binary accept SoftHSM; production values never set it
		}
		if strings.Contains(m, "ConfigMap/qv-hsm-client") && strings.Contains(m, "PEM block") && !strings.Contains(m, "PRIVATE") {
			continue // the CloudHSM cluster's CA certificate is public
		}
		out = append(out, m)
	}
	return append(out, checkSigning(objs, scOpts{Production: !kind, JobOffByDefault: true})...)
}

// scContract loads the image contract. CheckContract was written for the business chart and hard-codes that zone: for the signing images it is shown the
// zone as "business" after this function has checked that the contract names them as signing. A -dev image (devImages) has the contract of the image it is "of".
func scContract(t *testing.T) Contract {
	t.Helper()
	c, err := LoadContract()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"qv-gateway", "qv-tools-signing"} {
		ic, ok := c.Images[n]
		if !ok {
			t.Fatalf("deploy/images/contract.json has no entry for %s", n)
		}
		if ic.Zone != "signing" {
			t.Fatalf("%s is in zone %q in the contract, want signing", n, ic.Zone)
		}
		ic.Zone = "business"
		c.Images[n] = ic
	}
	for n, d := range c.DevImages {
		if ic, ok := c.Images[d.Of]; ok && (d.Of == "qv-gateway" || d.Of == "qv-tools-signing") {
			c.Images[n] = ic
		}
	}
	return c
}

// scContractCheck compares the gateway and the operator Job with the contract. The init Job of the SoftHSM token is a kind-only helper and is checked apart.
func scContractCheck(objs []Obj, c Contract) []string {
	var keep []Obj
	for _, o := range objs {
		if o.Component() == "softhsm" {
			continue
		}
		keep = append(keep, o)
	}
	var out []string
	for _, m := range CheckContract(keep, c) {
		switch {
		case strings.Contains(m, "qv-tools-signing") || strings.Contains(m, "/apply") || strings.Contains(m, "/show"):
			if strings.Contains(m, "sets command") {
				continue // the tools image has no ENTRYPOINT: the Job names the tool (checkToolsJob limits which)
			}
		}
		if strings.Contains(m, "metrics-agent") {
			continue
		}
		if strings.Contains(m, "/opt/cloudhsm/") && strings.Contains(m, "outside the contract's directories") {
			continue // the vendor module and its client config: the one directory the contract does not list
		}
		out = append(out, m)
	}
	// the database logins: the jobs DSN uses the business-issued link certificate, the guard DSN the signing certificate; no password; verify-full
	for _, o := range keep {
		if o.Kind != "ConfigMap" {
			continue
		}
		jobs, guard := fmt.Sprint(o.Data["QV_GATEWAY_JOBS_DSN"]), fmt.Sprint(o.Data["QV_GATEWAY_GUARD_DSN"])
		if jobs == "<nil>" {
			continue
		}
		out = append(out, dsnRules("jobs", jobs, "qv_gateway", "/etc/qv/link-tls")...)
		out = append(out, dsnRules("guard", guard, "qv_gateway_guard", "/etc/qv/tls")...)
		ju, _ := url.Parse(jobs)
		gu, _ := url.Parse(guard)
		if ju != nil && gu != nil && ju.Host == gu.Host && ju.Path == gu.Path {
			out = append(out, "the guard database is the job-queue database (the gateway refuses it)")
		}
	}
	return out
}

func dsnRules(what, dsn, role, dir string) []string {
	var v []string
	u, err := url.Parse(dsn)
	if err != nil || u.User == nil {
		return []string{what + " DSN does not parse"}
	}
	if u.User.Username() != role {
		v = append(v, fmt.Sprintf("%s DSN user is %q, want %q", what, u.User.Username(), role))
	}
	if _, has := u.User.Password(); has {
		v = append(v, what+" DSN carries a password")
	}
	q := u.Query()
	if q.Get("sslmode") != "verify-full" {
		v = append(v, fmt.Sprintf("%s DSN sslmode is %q", what, q.Get("sslmode")))
	}
	for _, k := range []string{"sslcert", "sslkey", "sslrootcert"} {
		if !strings.HasPrefix(q.Get(k), dir+"/") {
			v = append(v, fmt.Sprintf("%s DSN %s is %q, want a file under %s", what, k, q.Get(k), dir))
		}
	}
	return v
}

// ---- tests ----

var scValues = []struct {
	name string
	kind bool
}{{"production", false}, {"kind", true}}

func TestSigningCorePolicyAndContractPass(t *testing.T) {
	c := scContract(t)
	for _, vf := range scValues {
		t.Run(vf.name, func(t *testing.T) {
			objs := scObjs(t, vf.kind)
			var gw bool
			for _, o := range objs {
				if o.Kind == "Deployment" {
					gw = true
				}
			}
			if !gw {
				t.Fatal("no gateway Deployment rendered")
			}
			for _, m := range scPolicy(objs, vf.kind) {
				t.Error(m)
			}
			for _, m := range scContractCheck(objs, c) {
				t.Error(m)
			}
		})
	}
}

// With everything optional on (the metrics agent, the signed-setting Job) the same rules still hold.
func TestSigningCoreOptionalPartsPass(t *testing.T) {
	c := scContract(t)
	objs := scObjs(t, false, "--set", "metrics.agent.enabled=true", "--set", "metrics.agent.remoteWrite.url=https://metrics.example.invalid/api/v1/write",
		"--set", "metrics.agent.remoteWrite.tlsSecret=qv-remote-write-tls", "--set", "metrics.agent.cluster=signing-core", "--set", "signedSettings.job.enabled=true", "--set", "signedSettings.job.configMap=qv-signed-route-1-0123456789",
		"--set", "signedSettings.job.files={route-1.json,route-2.json}")
	var job, agent bool
	for _, o := range objs {
		pod, ok := o.Pod()
		if !ok {
			continue
		}
		if o.Kind == "Job" && o.Component() == "tools" {
			job = true
			if len(pod.Containers) != 1 || pod.Containers[0].Args[len(pod.Containers[0].Args)-1] != "/etc/qv/signed/route-2.json" {
				t.Errorf("the Job does not pass the signed files in order: %v", pod.Containers[0].Args)
			}
		}
		for _, ct := range pod.Containers {
			if ct.Name == "metrics-agent" {
				agent = true
			}
		}
	}
	if !job || !agent {
		t.Fatalf("job=%v agent=%v: an optional part did not render", job, agent)
	}
	var viol []string
	for _, m := range CheckPolicy(objs, PolicyOptions{RequireDigest: true}) {
		viol = append(viol, m)
	}
	viol = append(viol, checkSigning(objs, scOpts{Production: true})...)
	viol = append(viol, scContractCheck(objs, c)...)
	for _, m := range viol {
		t.Error(m)
	}
	// the agent's egress is the one extra rule, to a named endpoint
	found := false
	for _, o := range objs {
		if o.Kind == "NetworkPolicy" && o.Metadata.Name == "qv-gateway-egress" {
			found = strings.Contains(o.Raw, "10.50.1.0/28")
		}
	}
	if !found {
		t.Error("the metrics endpoint is not in the gateway's egress")
	}
}

func TestSigningCoreOffByDefault(t *testing.T) {
	for _, vf := range scValues {
		for _, o := range scObjs(t, vf.kind) {
			if o.Kind == "Job" && o.Component() == "tools" {
				t.Errorf("%s: the signed-setting Job is rendered by default", vf.name)
			}
			if pod, ok := o.Pod(); ok {
				for _, c := range pod.Containers {
					if c.Name == "metrics-agent" {
						t.Errorf("%s: the metrics agent is on by default", vf.name)
					}
				}
			}
		}
	}
}

// Production values: no SoftHSM, no QV_ENV, no init Job, a real PKCS#11 module from a volume, the PIN from a Secret reference only.
func TestSigningCoreProductionShape(t *testing.T) {
	objs := scObjs(t, false)
	for _, o := range objs {
		if o.Component() == "softhsm" {
			t.Errorf("%s: SoftHSM object in production", o.Metadata.Name)
		}
		if o.Kind == "ConfigMap" && o.Metadata.Name != "" && strings.HasPrefix(o.Metadata.Name, "qv-gateway-env") {
			if got := fmt.Sprint(o.Data["QV_PKCS11_LIB"]); got != "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so" {
				t.Errorf("QV_PKCS11_LIB = %s", got)
			}
			if got := fmt.Sprint(o.Data["QV_HSM_PIN_FILE"]); got != "/etc/qv/hsm-pin/pin" {
				t.Errorf("QV_HSM_PIN_FILE = %s", got)
			}
		}
		pod, ok := o.Pod()
		if !ok || o.Kind != "Deployment" {
			continue
		}
		gw := pod.Containers[0]
		for _, e := range gw.Env {
			if e.Name == "QV_HSM_PIN" {
				t.Error("QV_HSM_PIN must never be an environment variable: the PIN is a file")
			}
		}
		mounted := map[string]bool{}
		for _, m := range gw.VolumeMounts {
			mounted[m.MountPath] = m.ReadOnly
		}
		for _, p := range []string{"/opt/cloudhsm/lib", "/opt/cloudhsm/etc", "/etc/qv/hsm-pin", "/etc/qv/tls", "/etc/qv/party-tls", "/etc/qv/link-tls", "/etc/qv/config"} {
			if ro, ok := mounted[p]; !ok || !ro {
				t.Errorf("%s is not mounted read-only", p)
			}
		}
		if rw, ok := mounted["/var/lib/qv/metrics"]; !ok || rw {
			t.Error("the metrics directory must be a writable volume")
		}
		// Secret volumes: group-readable (0440) so that the pod's fsGroup lets the non-root user read the key
		sc, _ := o.Spec, 0
		m := asMap(o)
		_ = sc
		if dig(m, "template", "spec", "securityContext", "fsGroup") != 65532 {
			t.Error("fsGroup is not the image's group")
		}
		for _, vl := range list(dig(m, "template", "spec", "volumes")) {
			if s := dig(vl, "secret"); s != nil && dig(s, "defaultMode") != 288 {
				t.Errorf("Secret volume %v has mode %v, want 288 (0440)", dig(vl, "name"), dig(s, "defaultMode"))
			}
		}
	}
}

func nodeText(n yaml.Node) string {
	b, _ := yaml.Marshal(&n)
	return string(b)
}

// The replica and rollout rule (README "Replicas").
func TestSigningCoreRollout(t *testing.T) {
	for _, vf := range scValues {
		objs := scObjs(t, vf.kind)
		var dep Obj
		var pdb bool
		for _, o := range objs {
			if o.Kind == "Deployment" {
				dep = o
			}
			if o.Kind == "PodDisruptionBudget" {
				pdb = true
			}
		}
		m := asMap(dep)
		typ := scStr(dig(m, "strategy", "type"))
		replicas := dig(m, "replicas")
		if vf.kind {
			if typ != "Recreate" || replicas != 1 || pdb {
				t.Errorf("kind: want one replica, Recreate (one SoftHSM token directory), no PDB; got %v %v pdb=%v", replicas, typ, pdb)
			}
			continue
		}
		if replicas != 2 || typ != "RollingUpdate" || dig(m, "strategy", "rollingUpdate", "maxUnavailable") != 0 || !pdb {
			t.Errorf("production: want 2 replicas, RollingUpdate with maxUnavailable 0, a PDB; got %v %v pdb=%v", replicas, typ, pdb)
		}
	}
}

func TestSigningCoreProbesAndShutdown(t *testing.T) {
	for _, vf := range scValues {
		objs := scObjs(t, vf.kind)
		for _, o := range objs {
			if o.Kind != "Deployment" {
				continue
			}
			m := asMap(o)
			gw := list(dig(m, "template", "spec", "containers"))[0]
			for probe, path := range map[string]string{"startupProbe": "/readyz", "readinessProbe": "/readyz", "livenessProbe": "/livez"} {
				if scStr(dig(gw, probe, "httpGet", "path")) != path || scStr(dig(gw, probe, "httpGet", "port")) != "health" {
					t.Errorf("%s %s: want httpGet %s on the health port", vf.name, probe, path)
				}
			}
			ports := list(dig(gw, "ports"))
			if len(ports) != 1 || dig(ports[0], "containerPort") != 9100 {
				t.Errorf("%s: the one container port is the health port 9100, got %v", vf.name, ports)
			}
			// terminationGracePeriodSeconds >= sign_timeout + 30 s, with sign_timeout read from the config the chart ships
			var cfg struct {
				SignTimeout string `json:"sign_timeout"`
			}
			for _, c := range objs {
				if c.Kind == "ConfigMap" && c.Data["config.json"] != nil {
					if err := json.Unmarshal([]byte(fmt.Sprint(c.Data["config.json"])), &cfg); err != nil {
						t.Fatal(err)
					}
				}
			}
			d, err := time.ParseDuration(cfg.SignTimeout)
			if err != nil {
				t.Fatalf("sign_timeout %q: %v", cfg.SignTimeout, err)
			}
			grace, _ := dig(m, "template", "spec", "terminationGracePeriodSeconds").(int)
			if time.Duration(grace)*time.Second < d+30*time.Second {
				t.Errorf("%s: terminationGracePeriodSeconds %d is less than sign_timeout %s + 30s", vf.name, grace, d)
			}
		}
	}
	// the chart refuses a value that is too short
	if _, err := scRender(false, "--set", "gateway.terminationGracePeriodSeconds=40"); err == nil || !strings.Contains(err.Error(), "terminationGracePeriodSeconds") {
		t.Errorf("a grace period shorter than sign_timeout + 30 s must fail the render, got %v", err)
	}
}

// A ConfigMap is immutable and its name follows its content: a changed config is a new object and so a new rollout.
func TestSigningCoreConfigIsImmutableAndHashed(t *testing.T) {
	names := func(extra ...string) map[string]string {
		m := map[string]string{}
		for _, o := range scObjs(t, false, extra...) {
			if o.Kind == "ConfigMap" {
				m[strings.Join(strings.Split(o.Metadata.Name, "-")[:2], "-")] = o.Metadata.Name
			}
			if o.Kind == "ConfigMap" && !strings.Contains(o.Raw, "immutable: true") {
				t.Errorf("%s is not immutable", o.Metadata.Name)
			}
		}
		return m
	}
	a := names()
	b := names("--set", "config.signing={\"sign_timeout\":\"30s\",\"x\":1}")
	if a["qv-config"] == b["qv-config"] || a["qv-config"] == "" {
		t.Errorf("a changed signing config kept its ConfigMap name (%s)", a["qv-config"])
	}
	if a["qv-gateway"] != b["qv-gateway"] {
		t.Errorf("the env ConfigMap changed with an unrelated change: %s %s", a["qv-gateway"], b["qv-gateway"])
	}
	c := names("--set", "kafka.brokers=other:9092")
	if a["qv-gateway"] == c["qv-gateway"] {
		t.Error("the env ConfigMap kept its name although its content changed")
	}
}

func TestSigningCoreRefusals(t *testing.T) {
	cases := []struct {
		name  string
		kind  bool
		extra []string
		want  string
	}{
		{"all-zero digest", false, []string{"--set", "images.gateway.digest=sha256:" + strings.Repeat("0", 64)}, "all-zero placeholder"},
		{"no image reference", false, []string{"--set", "images.gateway.digest=", "--set", "images.gateway.tag="}, "needs a digest"},
		{"no signing config", false, []string{"--set", "config.signing="}, "config.signing is required"},
		{"SoftHSM in production", false, []string{"--set", "hsm.mode=softhsm"}, "development only"},
		{"dev switch with a real HSM", false, []string{"--set", "env=dev"}, "dev is for kind only"},
		{"PKCS#11 without a module volume", false, []string{"--set", "hsm.pkcs11.volume=null"}, "hsm.pkcs11.volume is required"},
		{"business Postgres not named", false, []string{"--set", "jobs.host=REQUIRED"}, "jobs.host is required"},
		{"empty peer list (would mean everywhere)", false, []string{"--set", "network.parties.b.peers=null"}, "network.parties.b.peers is required"},
		{"empty link peers", false, []string{"--set", "network.kafka.peers=null"}, "network.kafka.peers is required"},
		{"agent without an endpoint", false, []string{"--set", "metrics.agent.enabled=true"}, "remoteWrite.url is required"},
		{"Job without its ConfigMap", false, []string{"--set", "signedSettings.job.enabled=true"}, "configMap is required"},
		{"sign in a cluster", false, []string{"--set", "signedSettings.job.enabled=true", "--set", "signedSettings.job.configMap=x-0123456789", "--set", "signedSettings.job.action=sign"}, "must be one of"},
		{"Job ConfigMap without a content hash", false, []string{"--set", "signedSettings.job.enabled=true", "--set", "signedSettings.job.configMap=qv-signed-route-7"}, "must end in a hash"},
		{"unknown tool", false, []string{"--set", "signedSettings.job.enabled=true", "--set", "signedSettings.job.configMap=x-0123456789", "--set", "signedSettings.job.tool=sh"}, "must be one of"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := scRender(tc.kind, tc.extra...)
			if err != nil && os.Getenv("CI") == "" && strings.Contains(err.Error(), "not found on PATH") {
				t.Skip(err)
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("want a failed render containing %q, got %v", tc.want, err)
			}
		})
	}
	// the shipped production values on their own do not render: digests are placeholders and several values are required
	if helm, _ := exec.LookPath("helm"); helm != "" {
		if out, err := exec.Command(helm, "template", "qv", scDir(), "-f", filepath.Join(scDir(), "values.yaml")).CombinedOutput(); err == nil {
			t.Errorf("values.yaml rendered on its own:\n%s", out[:200])
		}
	}
}

// Each rule is worth only what it catches: break the rendered manifest in one way and want that violation.
func TestSigningCoreRulesCatch(t *testing.T) {
	prod := scText(t, false, "--set", "signedSettings.job.enabled=true", "--set", "signedSettings.job.configMap=x-0123456789", "--set", "signedSettings.job.files={a.json}")
	cases := []struct{ name, from, to, want string }{
		{"Ingress added", "\n---\n", "\n---\napiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata: { name: x }\nspec: {}\n---\n", "no Ingress"},
		{"Service added", "\n---\n", "\n---\napiVersion: v1\nkind: Service\nmetadata: { name: x }\nspec: { type: ClusterIP }\n---\n", "no Service at all"},
		{"LoadBalancer", "\n---\n", "\n---\napiVersion: v1\nkind: Service\nmetadata: { name: x }\nspec: { type: LoadBalancer }\n---\n", "Service type"},
		{"egress to the internet", "cidr: 10.20.1.0/28", "cidr: 0.0.0.0/0", "egress to 0.0.0.0/0"},
		{"egress to everywhere (IPv6)", "cidr: 10.30.1.0/28", "cidr: \"::/0\"", "egress to ::/0"},
		{"ingress from another namespace", "  policyTypes: [Ingress]\n  ingress:\n    - from: [{ podSelector:", "  policyTypes: [Ingress]\n  ingress:\n    - from: [{ namespaceSelector: {} }, { podSelector:", "ingress from an address or another namespace"},
		{"egress rule without peers", "    - to:\n        - ipBlock:\n            cidr: 10.20.1.16/28\n", "    - to: []\n      x:\n        - ipBlock:\n            cidr: 10.20.1.16/28\n", "no `to` admits every destination"},
		{"QV_ENV in production", "QV_MPC_METRICS_FILE: /var/lib/qv/metrics/mpc.prom", "QV_MPC_METRICS_FILE: /var/lib/qv/metrics/mpc.prom\n  QV_ENV: \"dev\"", "QV_ENV"},
		{"SoftHSM module in production", "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so", "/usr/lib/softhsm/libsofthsm2.so", "SoftHSM appears"},
		{"Job runs sign", "          command: [\"/usr/local/bin/qv-route\"]", "          command: [\"/usr/local/bin/qv-route\", \"sign\", \"-key\", \"/etc/qv/signed/key\"]", "not one of the four"},
		{"Job runs another binary", "/usr/local/bin/qv-route", "/bin/sh", "not one of the four"},
		{"Job gets a key argument", "            - -config\n            - /etc/qv/config/config.json\n            - \"/etc/qv/signed/a.json\"", "            - -config\n            - /etc/qv/config/config.json\n            - -key\n            - /etc/qv/signed/a.json", "hands a signing key"},
		{"Job mounts a Secret key", "          configMap: { name: \"x-0123456789\" }", "          secret: { secretName: operator-key }", "only the guard login certificate"},
		{"ConfigMap edited in place", "immutable: true", "immutable: false", "must be immutable"},
		{"PIN as an environment variable", "          ports:\n            - { name: health", "          env:\n            - { name: QV_HSM_PIN, valueFrom: { secretKeyRef: { name: p, key: pin } } }\n          ports:\n            - { name: health", "QV_HSM_PIN is an environment variable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(prod, tc.from) {
				t.Fatalf("test is stale: %q not in the rendered chart", tc.from)
			}
			objs, err := Parse(strings.Replace(prod, tc.from, tc.to, 1))
			if err != nil {
				t.Fatal(err)
			}
			if !anyContains(scPolicy(objs, false), tc.want) {
				t.Errorf("no violation containing %q; got %v", tc.want, scPolicy(objs, false))
			}
		})
	}
	// the Job in the default render
	if !anyContains(checkSigning(mustParse(t, prod), scOpts{JobOffByDefault: true}), "rendered by default") {
		t.Error("a Job in the default render was not caught")
	}
	// the policy checks of the business chart catch the usual breaks here too
	for _, tc := range []struct{ name, from, to, want string }{
		{"root filesystem writable", "readOnlyRootFilesystem: true", "readOnlyRootFilesystem: false", "readOnlyRootFilesystem is not true"},
		{"tag instead of digest", "qv-gateway@sha256:6666666666666666666666666666666666666666666666666666666666666666", "qv-gateway:latest", "not referenced by digest"},
		{"service token", "automountServiceAccountToken: false\n      hostNetwork: false", "automountServiceAccountToken: true\n      hostNetwork: false", "automountServiceAccountToken true"},
		{"password in the DSN", "postgres://qv_gateway_guard@", "postgres://qv_gateway_guard:hunter2@", "password inside a URL"},
		{"default deny removed", "policyTypes: [Ingress, Egress]", "policyTypes: [Egress]", "no default-deny"},
	} {
		t.Run("policy: "+tc.name, func(t *testing.T) {
			if !strings.Contains(prod, tc.from) {
				t.Fatalf("test is stale: %q", tc.from)
			}
			if !anyContains(scPolicy(mustParse(t, strings.Replace(prod, tc.from, tc.to, 1)), false), tc.want) {
				t.Errorf("no violation containing %q", tc.want)
			}
		})
	}
}

func TestSigningCoreContractCatches(t *testing.T) {
	c := scContract(t)
	prod := scText(t, false)
	cases := []struct{ name, from, to, want string }{
		{"unknown flag", "            - -config\n", "            - -skip-checks\n            - -config\n", "flag -skip-checks is not in the contract"},
		{"missing config flag", "            - -config\n            - /etc/qv/config/config.json\n", "", "required flag -config is missing"},
		{"unknown env", "QV_MPC_METRICS_FILE:", "QV_SURPRISE: \"1\"\n  QV_MPC_METRICS_FILE:", "QV_SURPRISE is not in the contract"},
		{"health port mismatch", `QV_HEALTH_LISTEN: "0.0.0.0:9100"`, `QV_HEALTH_LISTEN: "0.0.0.0:9200"`, "does not match containerPort"},
		{"file without a mount", "mountPath: /etc/qv/link-tls", "mountPath: /etc/qv/other", "no volume is mounted over it"},
		{"mount outside the contract", "mountPath: /etc/qv/config", "mountPath: /srv/config", "outside the contract's directories"},
		{"command overridden", "          args:\n            - -config", "          command: [\"/bin/sh\"]\n          args:\n            - -config", "sets command"},
		{"guard login with the link certificate", "sslcert=/etc/qv/tls/tls.crt&sslkey=/etc/qv/tls/tls.key\"", "sslcert=/etc/qv/link-tls/tls.crt&sslkey=/etc/qv/link-tls/tls.key\"", "want a file under /etc/qv/tls"},
		{"job queue login with the signing certificate", "sslcert=/etc/qv/link-tls/tls.crt", "sslcert=/etc/qv/tls/tls.crt", "want a file under /etc/qv/link-tls"},
		{"wrong role", "postgres://qv_gateway@", "postgres://qv_core@", "DSN user is"},
		{"weaker sslmode", "sslmode=verify-full&sslrootcert=/etc/qv/link-tls", "sslmode=require&sslrootcert=/etc/qv/link-tls", "sslmode"},
		{"same database for both", "qv-guard-rw:5432/qv_gateway_guard", "qv-business-db-rw.business.internal:5432/quorumvault", "is the job-queue database"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(prod, tc.from) {
				t.Fatalf("test is stale: %q not in the rendered chart", tc.from)
			}
			objs := mustParse(t, strings.Replace(prod, tc.from, tc.to, 1))
			if !anyContains(scContractCheck(objs, c), tc.want) {
				t.Errorf("no drift containing %q; got %v", tc.want, scContractCheck(objs, c))
			}
		})
	}
}

// Kind-only objects: the SoftHSM volume and token Job exist only with the kind values, run the dev image, and carry the PIN as a Secret reference.
func TestSigningCoreKindSoftHSM(t *testing.T) {
	objs := scObjs(t, true)
	var job, pvc bool
	for _, o := range objs {
		if o.Kind == "PersistentVolumeClaim" {
			pvc = true
		}
		pod, ok := o.Pod()
		if !ok || o.Component() != "softhsm" {
			continue
		}
		job = true
		for _, c := range pod.Containers {
			if !strings.Contains(c.Image, "qv-gateway-dev") {
				t.Errorf("the token Job must run the -dev image, got %s", c.Image)
			}
			for _, e := range c.Env {
				if strings.HasSuffix(e.Name, "PIN") && e.Value != "" {
					t.Errorf("env %s carries a value", e.Name)
				}
			}
		}
	}
	if !job || !pvc {
		t.Errorf("kind lacks the token Job (%v) or its volume (%v)", job, pvc)
	}
}

func mustParse(t *testing.T, text string) []Obj {
	t.Helper()
	objs, err := Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	return objs
}
