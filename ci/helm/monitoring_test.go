package helmcheck

// Checks for deploy/helm/qv-monitoring and for the metrics parts of the other charts (task D10), without a cluster:
//   - the rules reach the cluster as PrometheusRule objects generated from monitoring/ (drift test);
//   - one chart per cluster kind: a signing-cluster render holds no scrape object and no inbound rule, whatever is switched on;
//   - the metrics agent sidecar (qv-signing-core, qv-party): pod hardening, no extra mounts, one image pinned in the contract, egress only to the named endpoint;
//   - the business chart: metrics Services and one ingress rule that admits the monitoring namespace only.
// The test that every metric of every rule is emitted by some program is in monitoring/metrics_test.go (it needs the Go sources, which that module sees).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	monDir      = "../../deploy/helm/qv-monitoring"
	monRulesSrc = "../../monitoring"
)

// monHelm renders a chart; it skips when helm is missing outside CI.
func monHelm(t *testing.T, chart string, args ...string) []Obj {
	t.Helper()
	helm, err := exec.LookPath("helm")
	if err != nil {
		if os.Getenv("CI") == "" {
			t.Skip("helm not found on PATH")
		}
		t.Fatal(err)
	}
	a := append([]string{"template", "qv", chart, "--namespace", "qv"}, args...)
	var out, errb bytes.Buffer
	c := exec.Command(helm, a...)
	c.Stdout, c.Stderr = &out, &errb
	if err := c.Run(); err != nil {
		t.Fatalf("helm template %s: %v\n%s", chart, err, errb.String())
	}
	objs, err := Parse(out.String())
	if err != nil {
		t.Fatal(err)
	}
	return objs
}

// monHelmFails renders a chart that must be refused and returns helm's message.
func monHelmFails(t *testing.T, chart string, args ...string) string {
	t.Helper()
	helm, err := exec.LookPath("helm")
	if err != nil {
		if os.Getenv("CI") == "" {
			t.Skip("helm not found on PATH")
		}
		t.Fatal(err)
	}
	a := append([]string{"template", "qv", chart, "--namespace", "qv"}, args...)
	var errb bytes.Buffer
	c := exec.Command(helm, a...)
	c.Stderr = &errb
	if c.Run() == nil {
		t.Fatalf("helm template %s %v rendered; it must be refused", chart, args)
	}
	return errb.String()
}

// ---- renders of the charts that run in signing clusters ----

type monRender struct {
	name string
	objs []Obj
}

const monAgentURL = "https://metrics.example.invalid/api/v1/write"

// monSigningRenders renders qv-signing-core and qv-party (A, B, C), production and kind values, with the agent off and on.
func monSigningRenders(t *testing.T, agent bool) []monRender {
	t.Helper()
	var out []monRender
	for _, kind := range []bool{false, true} {
		kn := map[bool]string{false: "production", true: "kind"}[kind]
		// signing-core
		args := []string{"-f", scCI}
		if kind {
			args = append(args, "-f", "../../deploy/helm/qv-signing-core/values-kind.yaml")
		}
		if agent {
			args = append(args, "--set", "metrics.agent.enabled=true", "--set", "metrics.agent.remoteWrite.url="+monAgentURL, "--set", "metrics.agent.remoteWrite.tlsSecret=qv-remote-write-tls",
				"--set", "metrics.agent.cluster=signing-core")
		}
		out = append(out, monRender{"signing-core/" + kn + agentSuffix(agent), monHelm(t, "../../deploy/helm/qv-signing-core", args...)})
		// parties
		for _, role := range []string{"A", "B", "C"} {
			args := []string{"--set", "role=" + role, "-f", "ci-party-values.yaml"}
			if kind {
				args = append(args, "-f", "../../deploy/helm/qv-party/values-kind.yaml")
			} else {
				args = append(args, "-f", "ci-party-digests.yaml")
			}
			if agent {
				args = append(args, "--set", "metrics.agent.enabled=true", "--set", "metrics.agent.remoteWrite.url="+monAgentURL, "--set", "metrics.agent.remoteWrite.tlsSecret=qv-remote-write-tls",
					"--set", "network.metricsRemoteWrite.to[0].ipBlock.cidr=10.9.0.0/28", "--set", "metrics.agent.cluster=party-"+strings.ToLower(role))
			}
			out = append(out, monRender{"party-" + role + "/" + kn + agentSuffix(agent), monHelm(t, "../../deploy/helm/qv-party", args...)})
		}
	}
	return out
}

func agentSuffix(on bool) string {
	if on {
		return "+agent"
	}
	return ""
}

// monScrapeKinds are the objects that make something scrape, or evaluate rules, in a cluster.
var monScrapeKinds = map[string]bool{"ServiceMonitor": true, "PodMonitor": true, "ScrapeConfig": true, "Probe": true, "PrometheusRule": true, "Prometheus": true, "PrometheusAgent": true, "AlertmanagerConfig": true}

// monMetricsPorts are the loopback ports the processes of a signing pod publish metrics on, and the agent's own server port. No rule may let anything in on them.
var monMetricsPorts = map[int]bool{9102: true, 9104: true, 12345: true, 9100: false}

func ingressPorts(o Obj) (rules int, ports []int) {
	var s npSpec
	if err := o.Spec.Decode(&s); err != nil {
		return 0, nil
	}
	for _, r := range s.Ingress {
		rules++
		for _, p := range r.Ports {
			ports = append(ports, p.Port)
		}
	}
	return rules, ports
}

// No signing-cluster render holds a scrape object, a metrics Service or a rule that lets anything reach a metrics port.
func TestSigningClustersHaveNoInboundMetricsPath(t *testing.T) {
	for _, agent := range []bool{false, true} {
		for _, r := range monSigningRenders(t, agent) {
			t.Run(r.name, func(t *testing.T) {
				for _, v := range checkNoInboundMetrics(r.objs) {
					t.Error(v)
				}
			})
		}
	}
}

func checkNoInboundMetrics(objs []Obj) []string {
	var v []string
	for _, o := range objs {
		id := o.Kind + "/" + o.Metadata.Name
		if monScrapeKinds[o.Kind] {
			v = append(v, id+": a scrape or rule object in a signing cluster")
		}
		if o.Kind == "NetworkPolicy" {
			n, ports := ingressPorts(o)
			for _, p := range ports {
				if monMetricsPorts[p] {
					v = append(v, fmt.Sprintf("%s: ingress on metrics port %d", id, p))
				}
			}
			// signing-core takes nothing in at all
			if strings.HasPrefix(o.Metadata.Labels["app.kubernetes.io/name"], "qv-signing") && n > 0 {
				v = append(v, id+": an ingress rule in the signing-core chart")
			}
			if strings.Contains(o.Raw, "metrics-scrape") {
				v = append(v, id+": a metrics-scrape rule in a signing cluster")
			}
		}
		if o.Kind == "Service" {
			var s struct {
				Ports []struct {
					Name       string `yaml:"name"`
					Port       int    `yaml:"port"`
					TargetPort any    `yaml:"targetPort"`
				} `yaml:"ports"`
			}
			_ = o.Spec.Decode(&s)
			for _, p := range s.Ports {
				if monMetricsPorts[p.Port] || strings.Contains(strings.ToLower(p.Name), "metrics") || fmt.Sprint(p.TargetPort) == "metrics" {
					v = append(v, fmt.Sprintf("%s: a Service exposes a metrics port (%s/%d)", id, p.Name, p.Port))
				}
			}
		}
		if pod, ok := o.Pod(); ok {
			for _, c := range containers(pod) {
				for _, p := range c.Ports {
					if monMetricsPorts[p.ContainerPort] {
						v = append(v, fmt.Sprintf("%s/%s: declares metrics port %d", id, c.Name, p.ContainerPort))
					}
				}
				for _, e := range c.Env {
					if strings.HasSuffix(e.Name, "METRICS_LISTEN") && !strings.HasPrefix(e.Value, "127.0.0.1:") {
						v = append(v, fmt.Sprintf("%s/%s: %s=%s is not loopback", id, c.Name, e.Name, e.Value))
					}
				}
			}
		}
	}
	return v
}

// The check fails on a bad render: a ServiceMonitor, an ingress on 9102, a metrics Service.
func TestNoInboundMetricsCheckFails(t *testing.T) {
	bad := `
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata: { name: x }
spec: {}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: y }
spec:
  podSelector: {}
  policyTypes: [Ingress]
  ingress:
    - from: [{ namespaceSelector: {} }]
      ports: [{ port: 9102, protocol: TCP }]
---
apiVersion: v1
kind: Service
metadata: { name: z }
spec:
  ports: [{ name: metrics, port: 9104 }]
`
	objs, err := Parse(bad)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(checkNoInboundMetrics(objs), "\n")
	for _, want := range []string{"scrape or rule object", "ingress on metrics port 9102", "a Service exposes a metrics port"} {
		if !strings.Contains(got, want) {
			t.Errorf("no violation %q in:\n%s", want, got)
		}
	}
}

// The agent is off by default and does not exist then: no container, no volume, no egress rule for it.
func TestAgentOffByDefault(t *testing.T) {
	for _, r := range monSigningRenders(t, false) {
		for _, o := range r.objs {
			if pod, ok := o.Pod(); ok {
				for _, c := range pod.Containers {
					if c.Name == "metrics-agent" {
						t.Errorf("%s: the agent is on by default", r.name)
					}
				}
			}
			if o.Kind == "NetworkPolicy" && strings.Contains(o.Metadata.Name, "metrics") {
				t.Errorf("%s: %s: a metrics policy without the agent", r.name, o.Metadata.Name)
			}
		}
	}
}

// ---- the agent sidecar ----

func monContract(t *testing.T) (repo, digest string) {
	t.Helper()
	b, err := os.ReadFile("../../deploy/images/contract.json")
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		External map[string]struct {
			Repository string `json:"repository"`
			Digest     string `json:"digest"`
		} `json:"externalImages"`
	}
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	a := c.External["alloy"]
	if a.Repository == "" || !digestRe.MatchString(a.Repository+"@"+a.Digest) || strings.Trim(strings.TrimPrefix(a.Digest, "sha256:"), "0") == "" {
		t.Fatalf("contract.json externalImages.alloy has no real repository and digest: %+v", a)
	}
	return a.Repository, a.Digest
}

func TestAgentImageIsPinnedInTheContract(t *testing.T) {
	repo, dig := monContract(t)
	for _, r := range monSigningRenders(t, true) {
		var found bool
		for _, o := range r.objs {
			if pod, ok := o.Pod(); ok {
				for _, c := range pod.Containers {
					if c.Name == "metrics-agent" {
						found = true
						if want := repo + "@" + dig; c.Image != want {
							t.Errorf("%s: agent image %s, the contract pins %s", r.name, c.Image, want)
						}
					}
				}
			}
		}
		if !found { // every signing render has the agent when it is on (signing-core: the gateway; party: the StatefulSet)
			t.Errorf("%s: no metrics-agent container with the agent on", r.name)
		}
	}
}

func TestAgentSidecarIsHardenedAndOutwardOnly(t *testing.T) {
	for _, r := range monSigningRenders(t, true) {
		t.Run(r.name, func(t *testing.T) {
			var agent *Container
			var pod PodSpec
			for _, o := range r.objs {
				if p, ok := o.Pod(); ok {
					for i := range p.Containers {
						if p.Containers[i].Name == "metrics-agent" {
							agent, pod = &p.Containers[i], p
						}
					}
				}
			}
			if agent == nil {
				t.Fatal("no metrics-agent container")
			}
			sc := agent.SecurityContext
			switch {
			case sc == nil:
				t.Fatal("no securityContext")
			case sc.RunAsNonRoot == nil || !*sc.RunAsNonRoot, sc.RunAsUser == nil || *sc.RunAsUser != wantUser:
				t.Error("not runAsNonRoot as uid 65532")
			case sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem:
				t.Error("root filesystem is writable")
			case sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation:
				t.Error("privilege escalation allowed")
			case sc.Privileged != nil && *sc.Privileged:
				t.Error("privileged")
			case sc.Capabilities == nil || len(sc.Capabilities.Add) != 0 || len(sc.Capabilities.Drop) != 1 || sc.Capabilities.Drop[0] != "ALL":
				t.Error("capabilities: must drop ALL and add none")
			case sc.SeccompProfile == nil || sc.SeccompProfile.Type != "RuntimeDefault":
				t.Error("no RuntimeDefault seccomp profile")
			}
			if len(agent.Ports) != 0 {
				t.Errorf("the agent declares container ports %v", agent.Ports)
			}
			if len(agent.Resources.Limits) == 0 || len(agent.Resources.Requests) == 0 {
				t.Error("no requests and limits")
			}
			if strings.Contains(strings.Join(agent.Args, " "), "0.0.0.0") || !strings.Contains(strings.Join(agent.Args, " "), "--server.http.listen-addr=127.0.0.1:") {
				t.Errorf("the agent's own server is not on loopback: %v", agent.Args)
			}
			// what it may see: its config, its own scratch, the client certificate; the gateway's metrics files read-only. Never data, the cosigner socket, a PIN, the HSM or other certificates.
			vols := map[string]Volume{}
			for _, v := range pod.Volumes {
				vols[v.Name] = v
			}
			allowed := map[string]bool{"agent-config": true, "agent-data": true, "remote-write": true, "metrics": true}
			for _, m := range agent.VolumeMounts {
				if !allowed[m.Name] {
					t.Errorf("the agent mounts %s (%s)", m.Name, m.MountPath)
				}
				if m.Name == "metrics" && !m.ReadOnly {
					t.Error("the agent mounts the gateway's metrics directory writable")
				}
				if v := vols[m.Name]; (v.Secret != nil || v.ConfigMap != nil) && !m.ReadOnly {
					t.Errorf("the agent mounts %s writable", m.Name)
				}
			}
			if rw, ok := vols["remote-write"]; !ok || rw.Secret == nil || rw.Secret.SecretName != "qv-remote-write-tls" {
				t.Errorf("the client certificate is not the Secret named by metrics.agent.remoteWrite.tlsSecret: %+v", rw)
			}
			// no environment at all: no token, no password
			if len(agent.Env) != 0 || len(agent.EnvFrom) != 0 {
				t.Error("the agent has environment variables")
			}
			if pod.AutomountServiceAccountToken == nil || *pod.AutomountServiceAccountToken {
				t.Error("the pod mounts a service account token")
			}
		})
	}
}

// The agent's config: it writes outward with a client certificate and carries no secret.
func TestAgentConfigUsesAClientCertificate(t *testing.T) {
	for _, r := range monSigningRenders(t, true) {
		var cfg string
		for _, o := range r.objs {
			if o.Kind == "ConfigMap" {
				if s, ok := o.Data["config.alloy"].(string); ok {
					cfg = s
				}
			}
		}
		if cfg == "" {
			t.Errorf("%s: no agent config", r.name)
			continue
		}
		for _, want := range []string{`url = "` + monAgentURL + `"`, `cert_file = "/etc/qv/remote-write/tls.crt"`, `key_file  = "/etc/qv/remote-write/tls.key"`, `ca_file   = "/etc/qv/remote-write/ca.crt"`, `qv_cluster`} {
			if !strings.Contains(cfg, want) {
				t.Errorf("%s: agent config lacks %q", r.name, want)
			}
		}
		for _, bad := range []string{"bearer_token", "password", "basic_auth", "authorization"} {
			if strings.Contains(cfg, bad) {
				t.Errorf("%s: agent config contains %q: the credential is the client certificate", r.name, bad)
			}
		}
		switch {
		case strings.HasPrefix(r.name, "signing-core"):
			if !strings.Contains(cfg, `directory = "/var/lib/qv/metrics"`) || strings.Contains(cfg, "127.0.0.1:9") {
				t.Errorf("%s: the gateway agent must read the textfile directory only", r.name)
			}
		case strings.HasPrefix(r.name, "party-"):
			if !strings.Contains(cfg, `"127.0.0.1:9102"`) {
				t.Errorf("%s: the party agent does not scrape the party's loopback port", r.name)
			}
			wantCos := !strings.HasPrefix(r.name, "party-A")
			if strings.Contains(cfg, `"127.0.0.1:9104"`) != wantCos {
				t.Errorf("%s: cosigner scrape present = %v, want %v", r.name, !wantCos, wantCos)
			}
		}
	}
}

// Egress: with the agent on there is one rule for it, to the endpoint you name and one port; nothing else is added to the pod's egress.
func TestAgentEgressIsOnlyTheEndpoint(t *testing.T) {
	base := map[string]int{}
	for _, r := range monSigningRenders(t, false) {
		base[strings.TrimSuffix(r.name, "")] = egressRuleCount(r.objs)
	}
	for _, r := range monSigningRenders(t, true) {
		t.Run(r.name, func(t *testing.T) {
			off := base[strings.TrimSuffix(r.name, "+agent")]
			if got := egressRuleCount(r.objs); got != off+1 {
				t.Errorf("the agent adds %d egress rules, want exactly 1", got-off)
			}
			var hit int
			for _, o := range r.objs {
				if o.Kind != "NetworkPolicy" {
					continue
				}
				var s struct {
					Egress []struct {
						To []struct {
							IPBlock *struct {
								CIDR string `yaml:"cidr"`
							} `yaml:"ipBlock"`
							NamespaceSelector *yaml.Node `yaml:"namespaceSelector"`
							PodSelector       *yaml.Node `yaml:"podSelector"`
						} `yaml:"to"`
						Ports []npPort `yaml:"ports"`
					} `yaml:"egress"`
				}
				_ = o.Spec.Decode(&s)
				for _, e := range s.Egress {
					for _, to := range e.To {
						if to.IPBlock != nil && (to.IPBlock.CIDR == "10.50.1.0/28" || to.IPBlock.CIDR == "10.9.0.0/28") {
							hit++
							if len(e.Ports) != 1 || e.Ports[0].Port != 443 || len(e.To) != 1 {
								t.Errorf("%s: the endpoint rule is not one peer and port 443: %+v", o.Metadata.Name, e)
							}
						}
					}
				}
			}
			if hit != 1 {
				t.Errorf("the endpoint is named in %d egress rules, want 1", hit)
			}
		})
	}
}

func egressRuleCount(objs []Obj) int {
	n := 0
	for _, o := range objs {
		if o.Kind != "NetworkPolicy" {
			continue
		}
		var s struct {
			Egress []yaml.Node `yaml:"egress"`
		}
		_ = o.Spec.Decode(&s)
		n += len(s.Egress)
	}
	return n
}

// Switching the agent on without its settings is refused: no empty peer list (which would mean "everywhere"), no missing certificate.
func TestAgentWithoutSettingsIsRefused(t *testing.T) {
	base := []string{"--set", "role=B", "-f", "ci-party-values.yaml", "-f", "ci-party-digests.yaml", "--set", "metrics.agent.enabled=true", "--set", "metrics.agent.cluster=party-b"}
	cases := []struct {
		name string
		more []string
		want string
	}{
		{"no endpoint peers", []string{"--set", "metrics.agent.remoteWrite.url=" + monAgentURL, "--set", "metrics.agent.remoteWrite.tlsSecret=s"}, "network.metricsRemoteWrite.to is required"},
		{"no certificate", []string{"--set", "metrics.agent.remoteWrite.url=" + monAgentURL, "--set", "network.metricsRemoteWrite.to[0].ipBlock.cidr=10.9.0.0/28"}, "tlsSecret is required"},
		{"no cluster name", []string{"--set", "metrics.agent.cluster=", "--set", "metrics.agent.remoteWrite.url=" + monAgentURL, "--set", "metrics.agent.remoteWrite.tlsSecret=s", "--set", "network.metricsRemoteWrite.to[0].ipBlock.cidr=10.9.0.0/28"}, "metrics.agent.cluster is required"},
		{"no url", []string{"--set", "metrics.agent.remoteWrite.tlsSecret=s", "--set", "network.metricsRemoteWrite.to[0].ipBlock.cidr=10.9.0.0/28"}, "remoteWrite.url is required"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if msg := monHelmFails(t, "../../deploy/helm/qv-party", append(append([]string{}, base...), c.more...)...); !strings.Contains(msg, c.want) {
				t.Errorf("refused, but not for %q: %s", c.want, msg)
			}
		})
	}
	if msg := monHelmFails(t, "../../deploy/helm/qv-signing-core", "-f", scCI, "--set", "metrics.agent.enabled=true", "--set", "metrics.agent.cluster=signing-core", "--set", "metrics.agent.remoteWrite.url="+monAgentURL); !strings.Contains(msg, "tlsSecret is required") {
		t.Errorf("signing-core without a certificate: %s", msg)
	}
	if msg := monHelmFails(t, "../../deploy/helm/qv-signing-core", "-f", scCI, "--set", "metrics.agent.enabled=true", "--set", "metrics.agent.remoteWrite.url="+monAgentURL, "--set", "metrics.agent.remoteWrite.tlsSecret=s"); !strings.Contains(msg, "metrics.agent.cluster is required") {
		t.Errorf("signing-core without a cluster name: %s", msg)
	}
}

// Both charts point at the image the contract pins.
func TestChartValuesPinTheContractImage(t *testing.T) {
	repo, dig := monContract(t)
	for _, f := range []string{"../../deploy/helm/qv-signing-core/values.yaml", "../../deploy/helm/qv-party/values.yaml"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var v struct {
			Images map[string]struct {
				Repository string `yaml:"repository"`
				Digest     string `yaml:"digest"`
			} `yaml:"images"`
		}
		if err := yaml.Unmarshal(b, &v); err != nil {
			t.Fatal(err)
		}
		if a := v.Images["agent"]; a.Repository != repo || a.Digest != dig {
			t.Errorf("%s: images.agent is %+v, the contract pins %s@%s", f, a, repo, dig)
		}
	}
}

// ---- the rules ----

// The chart's copies of the rule files are the files of monitoring/, byte for byte, and no other file is there.
func TestRuleCopiesMatchMonitoring(t *testing.T) {
	src, _ := filepath.Glob(filepath.Join(monRulesSrc, "*.rules.yml"))
	dst, _ := filepath.Glob(filepath.Join(monDir, "rules", "*"))
	if len(src) < 7 {
		t.Fatalf("source rule files: %v", src)
	}
	have := map[string]bool{}
	for _, d := range dst {
		have[filepath.Base(d)] = true
	}
	for _, s := range src {
		b, _ := os.ReadFile(s)
		d, err := os.ReadFile(filepath.Join(monDir, "rules", filepath.Base(s)))
		switch {
		case err != nil:
			t.Errorf("%s has no copy in the chart: run ci/helm/sync-monitoring-rules.sh", filepath.Base(s))
		case !bytes.Equal(b, d):
			t.Errorf("%s differs from its copy in the chart: run ci/helm/sync-monitoring-rules.sh", filepath.Base(s))
		}
		delete(have, filepath.Base(s))
	}
	for extra := range have {
		t.Errorf("the chart has rules/%s, which monitoring/ does not: run ci/helm/sync-monitoring-rules.sh", extra)
	}
}

type monRuleFile struct {
	Groups []struct {
		Name  string `yaml:"name"`
		Rules []struct {
			Alert  string            `yaml:"alert"`
			Record string            `yaml:"record"`
			Expr   string            `yaml:"expr"`
			For    string            `yaml:"for"`
			Labels map[string]string `yaml:"labels"`
		} `yaml:"rules"`
	} `yaml:"groups"`
}

// The central render holds one PrometheusRule per file, with every group, alert, expression, `for` and label of the source.
func TestPrometheusRulesAreGeneratedFromMonitoring(t *testing.T) {
	objs := monHelm(t, monDir, "--set", "clusterKind=central")
	src, _ := filepath.Glob(filepath.Join(monRulesSrc, "*.rules.yml"))
	want := map[string]monRuleFile{}
	for _, s := range src {
		b, _ := os.ReadFile(s)
		var f monRuleFile
		if err := yaml.Unmarshal(b, &f); err != nil {
			t.Fatal(err)
		}
		want["qv-"+strings.TrimSuffix(filepath.Base(s), ".rules.yml")] = f
	}
	got := 0
	for _, o := range objs {
		if o.Kind != "PrometheusRule" {
			continue
		}
		got++
		w, ok := want[o.Metadata.Name]
		if !ok {
			t.Errorf("PrometheusRule/%s has no source file", o.Metadata.Name)
			continue
		}
		var s monRuleFile
		if err := o.Spec.Decode(&s); err != nil {
			t.Fatal(err)
		}
		gj, _ := json.Marshal(s)
		wj, _ := json.Marshal(w)
		if string(gj) != string(wj) {
			t.Errorf("PrometheusRule/%s differs from monitoring/", o.Metadata.Name)
		}
		if !strings.HasPrefix(o.Metadata.Annotations["quorumvault.io/generated-from"], "monitoring/") {
			t.Errorf("PrometheusRule/%s does not say where it comes from", o.Metadata.Name)
		}
	}
	if got != len(want) {
		t.Errorf("%d PrometheusRule objects, %d rule files", got, len(want))
	}
	// the new alerts of this task are in the cluster
	names := map[string]bool{}
	for _, f := range want {
		for _, g := range f.Groups {
			for _, r := range g.Rules {
				names[r.Alert] = true
			}
		}
	}
	for _, a := range []string{"QVAttestBrokerRefusals", "QVAttestBrokerReloadRefused", "QVAttestBrokerCertExpiringSoon", "QVMpcPartySealerNotReady", "QVMpcPartyAllowlistRefused", "QVDrainRefused"} {
		if !names[a] {
			t.Errorf("alert %s is missing from monitoring/", a)
		}
	}
}

// One chart per cluster kind: what each renders.
func TestMonitoringChartPerClusterKind(t *testing.T) {
	kinds := func(objs []Obj) []string {
		m := map[string]bool{}
		for _, o := range objs {
			m[o.Kind] = true
		}
		var k []string
		for x := range m {
			k = append(k, x)
		}
		sort.Strings(k)
		return k
	}
	central := kinds(monHelm(t, monDir, "--set", "clusterKind=central", "--set", "alertmanager.enabled=true"))
	if strings.Join(central, ",") != "AlertmanagerConfig,PrometheusRule" {
		t.Errorf("central renders %v", central)
	}
	business := monHelm(t, monDir, "--set", "clusterKind=business", "--set", "alertmanager.enabled=true")
	if k := kinds(business); strings.Join(k, ",") != "ServiceMonitor" {
		t.Errorf("business renders %v (rules and routing are central, scrape objects only here)", k)
	}
	if n := len(business); n != 3 {
		t.Errorf("business renders %d ServiceMonitors, want core, relay, archiver", n)
	}
	// a signing cluster gets nothing, whatever is switched on
	signing := monHelm(t, monDir, "--set", "clusterKind=signing", "--set", "alertmanager.enabled=true", "--set", "rules.enabled=true", "--set", "serviceMonitors.enabled=true")
	if len(signing) != 0 {
		t.Errorf("signing renders %v", kinds(signing))
	}
	if msg := monHelmFails(t, monDir, "--set", "clusterKind=elsewhere"); !strings.Contains(msg, "clusterKind") {
		t.Errorf("unknown cluster kind: %s", msg)
	}
}

// The Alertmanager example: a party's alerts go to that party's operators; the receivers name Secrets and nothing else.
func TestAlertmanagerRoutingExample(t *testing.T) {
	objs := monHelm(t, monDir, "--set", "clusterKind=central", "--set", "alertmanager.enabled=true")
	var am *Obj
	for i := range objs {
		if objs[i].Kind == "AlertmanagerConfig" {
			am = &objs[i]
		}
	}
	if am == nil {
		t.Fatal("no AlertmanagerConfig")
	}
	var s struct {
		Route struct {
			Receiver string `yaml:"receiver"`
			Routes   []struct {
				Receiver string                                    `yaml:"receiver"`
				Matchers []struct{ Name, Value, MatchType string } `yaml:"matchers"`
			} `yaml:"routes"`
		} `yaml:"route"`
		Receivers []struct {
			Name           string `yaml:"name"`
			WebhookConfigs []struct {
				URL       string                      `yaml:"url"`
				URLSecret *struct{ Name, Key string } `yaml:"urlSecret"`
			} `yaml:"webhookConfigs"`
		} `yaml:"receivers"`
	}
	if err := am.Spec.Decode(&s); err != nil {
		t.Fatal(err)
	}
	recv := map[string]bool{}
	for _, r := range s.Receivers {
		recv[r.Name] = true
		for _, w := range r.WebhookConfigs {
			if w.URL != "" || w.URLSecret == nil || w.URLSecret.Name == "" {
				t.Errorf("receiver %s: a URL in values, or no Secret reference", r.Name)
			}
		}
	}
	if !recv[s.Route.Receiver] {
		t.Errorf("default receiver %q is not defined", s.Route.Receiver)
	}
	parties := map[string]string{}
	for _, r := range s.Route.Routes {
		if !recv[r.Receiver] {
			t.Errorf("route to undefined receiver %q", r.Receiver)
		}
		if len(r.Matchers) != 1 || r.Matchers[0].Name != "party" {
			t.Errorf("a party route must match the party label only: %+v", r.Matchers)
			continue
		}
		parties[r.Matchers[0].Value] = r.Receiver
	}
	for _, p := range []string{"A", "B", "C"} {
		if parties[p] == "" || parties[p] == s.Route.Receiver {
			t.Errorf("party %s has no receiver of its own", p)
		}
	}
	if pemRe.MatchString(am.Raw) || secretJSON.MatchString(am.Raw) || urlCreds.MatchString(am.Raw) {
		t.Error("the routing example holds something that looks like a credential")
	}
}

// ---- the business chart ----

var monBusiness = []string{"-f", "../../deploy/helm/qv-business/values.yaml", "-f", "ci-digests.yaml"}

func monBusinessObjs(t *testing.T, extra ...string) []Obj {
	return monHelm(t, "../../deploy/helm/qv-business", append(append([]string{}, monBusiness...), extra...)...)
}

// Off by default: no metrics Service, no switch, no extra flag.
func TestBusinessMetricsOffByDefault(t *testing.T) {
	for _, o := range monBusinessObjs(t) {
		if o.Kind == "Service" && strings.HasSuffix(o.Metadata.Name, "-metrics") || o.Metadata.Annotations["quorumvault.io/ingress-purpose"] == "metrics-scrape" {
			t.Errorf("%s/%s exists with metrics off", o.Kind, o.Metadata.Name)
		}
		if strings.Contains(o.Raw, "QV_METRICS_ALLOW_NON_LOOPBACK") || strings.Contains(o.Raw, "-metrics-listen") {
			t.Errorf("%s/%s binds metrics beyond loopback with metrics off", o.Kind, o.Metadata.Name)
		}
	}
}

// On: core, relay and archiver get a Service; one policy lets the monitoring namespace reach the metrics port; the policy and contract tests still pass; the ServiceMonitors select exactly these Services.
func TestBusinessMetricsReachOnlyTheMonitoringNamespace(t *testing.T) {
	objs := monBusinessObjs(t, "--set", "metrics.enabled=true")
	svc := map[string]Obj{}
	var scrape []Obj
	for _, o := range objs {
		if o.Kind == "Service" && strings.HasSuffix(o.Metadata.Name, "-metrics") {
			svc[o.Component()] = o
		}
		if o.Metadata.Annotations["quorumvault.io/ingress-purpose"] == "metrics-scrape" {
			scrape = append(scrape, o)
		}
	}
	if len(svc) != 3 || svc["core"].Kind == "" || svc["relay"].Kind == "" || svc["archiver"].Kind == "" || svc["worker"].Kind != "" {
		t.Fatalf("metrics Services: %v (want core, relay, archiver; the worker has no metrics port)", monKeys(svc))
	}
	if len(scrape) != 1 {
		t.Fatalf("%d metrics-scrape policies, want 1", len(scrape))
	}
	var np struct {
		PodSelector struct {
			MatchExpressions []struct {
				Key    string   `yaml:"key"`
				Values []string `yaml:"values"`
			} `yaml:"matchExpressions"`
		} `yaml:"podSelector"`
		PolicyTypes []string `yaml:"policyTypes"`
		Ingress     []struct {
			From []struct {
				NamespaceSelector struct {
					MatchLabels map[string]string `yaml:"matchLabels"`
				} `yaml:"namespaceSelector"`
				PodSelector *yaml.Node `yaml:"podSelector"`
				IPBlock     *yaml.Node `yaml:"ipBlock"`
			} `yaml:"from"`
			Ports []npPort `yaml:"ports"`
		} `yaml:"ingress"`
	}
	if err := scrape[0].Spec.Decode(&np); err != nil {
		t.Fatal(err)
	}
	if len(np.Ingress) != 1 || len(np.Ingress[0].From) != 1 || len(np.Ingress[0].Ports) != 1 || np.Ingress[0].Ports[0].Port != 9102 {
		t.Fatalf("the scrape rule is not one peer and the one metrics port: %+v", np.Ingress)
	}
	f := np.Ingress[0].From[0]
	if f.IPBlock != nil || f.PodSelector != nil || f.NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"] != "monitoring" {
		t.Errorf("the scrape rule admits something other than the monitoring namespace: %+v", f)
	}
	if len(np.PolicyTypes) != 1 || np.PolicyTypes[0] != "Ingress" {
		t.Errorf("policy types %v", np.PolicyTypes)
	}
	for _, e := range np.PodSelector.MatchExpressions {
		if e.Key == "app.kubernetes.io/component" && strings.Contains(strings.Join(e.Values, ","), "worker") {
			t.Error("the scrape rule selects the worker")
		}
	}
	// the policy test and the image contract accept the render
	opt := PolicyOptions{RequireDigest: true, CorePort: 8443, ApprovalPort: 8090, LinkPorts: []int{5432, 9092}}
	for _, m := range CheckPolicy(objs, opt) {
		t.Error(m)
	}
	c, err := LoadContract()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range CheckContract(objs, c) {
		t.Error(m)
	}
	// the ServiceMonitors of the business kind select exactly these Services
	mons := monHelm(t, monDir, "--set", "clusterKind=business")
	for _, m := range mons {
		var s struct {
			NamespaceSelector struct {
				MatchNames []string `yaml:"matchNames"`
			} `yaml:"namespaceSelector"`
			Selector struct {
				MatchLabels map[string]string `yaml:"matchLabels"`
			} `yaml:"selector"`
			Endpoints []struct {
				Port   string `yaml:"port"`
				Scheme string `yaml:"scheme"`
			} `yaml:"endpoints"`
		}
		_ = m.Spec.Decode(&s)
		comp := s.Selector.MatchLabels["app.kubernetes.io/component"]
		sv, ok := svc[comp]
		if !ok {
			t.Errorf("ServiceMonitor/%s selects component %q, which has no metrics Service", m.Metadata.Name, comp)
			continue
		}
		for k, v := range s.Selector.MatchLabels {
			if sv.Metadata.Labels[k] != v {
				t.Errorf("ServiceMonitor/%s: label %s=%s is not on Service/%s", m.Metadata.Name, k, v, sv.Metadata.Name)
			}
		}
		if len(s.NamespaceSelector.MatchNames) != 1 || s.NamespaceSelector.MatchNames[0] != "qv" {
			t.Errorf("ServiceMonitor/%s namespace %v, the release runs in qv", m.Metadata.Name, s.NamespaceSelector.MatchNames)
		}
		var sp struct {
			Ports []struct{ Name string } `yaml:"ports"`
		}
		_ = sv.Spec.Decode(&sp)
		if len(s.Endpoints) != 1 || len(sp.Ports) != 1 || s.Endpoints[0].Port != sp.Ports[0].Name {
			t.Errorf("ServiceMonitor/%s endpoint %+v does not match the Service's port %+v", m.Metadata.Name, s.Endpoints, sp.Ports)
		}
	}
}

func monKeys(m map[string]Obj) []string {
	var k []string
	for x := range m {
		k = append(k, x)
	}
	sort.Strings(k)
	return k
}

// monitoring-check.sh must stop when kubeconform rejects a render that is not empty (an earlier `validate ... || echo` turned that failure into success). A fake kubeconform that always fails
// stands in for the real one: the script has to exit non-zero at the first validation and must not reach the end; with one that succeeds it has to get through.
func TestMonitoringCheckStopsOnFailedValidation(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed")
	}
	run := func(exit int) (string, error) {
		bin := t.TempDir()
		fake := fmt.Sprintf("#!/bin/sh\necho \"fake kubeconform $*\" >&2\nexit %d\n", exit)
		if err := os.WriteFile(filepath.Join(bin, "kubeconform"), []byte(fake), 0o755); err != nil {
			t.Fatal(err)
		}
		c := exec.Command("bash", "monitoring-check.sh")
		c.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
		out, err := c.CombinedOutput()
		return string(out), err
	}
	out, err := run(1)
	if err == nil {
		t.Fatalf("a failed kubeconform did not stop monitoring-check.sh:\n%s", out)
	}
	if strings.Contains(out, "qv-business with metrics on") {
		t.Fatalf("the script went on after the first failed validation:\n%s", out)
	}
	if out, err := run(0); err != nil {
		t.Fatalf("with a passing kubeconform the script failed: %v\n%s", err, out)
	}
}

// ---- identity of the series an agent sends ----

var extLabelsRe = regexp.MustCompile(`(?s)external_labels\s*=\s*\{(.*?)\}`)
var extPairRe = regexp.MustCompile(`(\w+)\s*=\s*"([^"]*)"`)

// agentLabels is the external label set of the agent configuration in a render.
func agentLabels(t *testing.T, name string, objs []Obj) map[string]string {
	t.Helper()
	for _, o := range objs {
		if o.Kind != "ConfigMap" {
			continue
		}
		cfg, ok := o.Data["config.alloy"].(string)
		if !ok {
			continue
		}
		m := extLabelsRe.FindStringSubmatch(cfg)
		if m == nil {
			t.Fatalf("%s: the agent has no external_labels", name)
		}
		out := map[string]string{}
		for _, p := range extPairRe.FindAllStringSubmatch(m[1], -1) {
			out[p[1]] = p[2]
		}
		return out
	}
	t.Fatalf("%s: no agent config", name)
	return nil
}

// Every series an agent sends says which party and which cluster it came from: B's cosigner and C's must differ (same metric names, same zone), and the label the Alertmanager example routes on is the
// one the agents set.
func TestAgentSeriesCarryPartyAndCluster(t *testing.T) {
	got := map[string]map[string]string{}
	for _, r := range monSigningRenders(t, true) {
		if !strings.Contains(r.name, "production") {
			continue
		}
		l := agentLabels(t, r.name, r.objs)
		got[strings.SplitN(r.name, "/", 2)[0]] = l
		if l["qv_cluster"] == "" {
			t.Errorf("%s: no qv_cluster label: %v", r.name, l)
		}
		if strings.HasPrefix(r.name, "party-") {
			if want := strings.TrimPrefix(strings.SplitN(r.name, "/", 2)[0], "party-"); l["party"] != want {
				t.Errorf("%s: party label %q, want %q", r.name, l["party"], want)
			}
		} else if _, has := l["party"]; has {
			t.Errorf("%s: the gateway is no party: %v", r.name, l)
		}
	}
	for _, k := range []string{"signing-core", "party-A", "party-B", "party-C"} {
		if got[k] == nil {
			t.Fatalf("no labels for %s (have %v)", k, got)
		}
	}
	for _, p := range [][2]string{{"party-B", "party-C"}, {"party-A", "party-B"}, {"party-B", "signing-core"}} {
		a, b := got[p[0]], got[p[1]]
		if a["party"] == b["party"] && a["qv_cluster"] == b["qv_cluster"] {
			t.Errorf("%s and %s cannot be told apart: %v %v", p[0], p[1], a, b)
		}
	}
	// the user cannot overwrite the identity with externalLabels
	objs := monHelm(t, "../../deploy/helm/qv-party", "--set", "role=B", "-f", "ci-party-values.yaml", "-f", "ci-party-digests.yaml", "--set", "metrics.agent.enabled=true",
		"--set", "metrics.agent.remoteWrite.url="+monAgentURL, "--set", "metrics.agent.remoteWrite.tlsSecret=s", "--set", "metrics.agent.cluster=party-b",
		"--set", "network.metricsRemoteWrite.to[0].ipBlock.cidr=10.9.0.0/28", "--set", "metrics.agent.externalLabels.party=C", "--set", "metrics.agent.externalLabels.site=berlin")
	l := agentLabels(t, "override", objs)
	if l["party"] != "B" || l["site"] != "berlin" {
		t.Errorf("externalLabels overrode the identity or was dropped: %v", l)
	}
	// the Alertmanager example routes on exactly these party values
	am := monHelm(t, monDir, "--set", "clusterKind=central", "--set", "alertmanager.enabled=true")
	routed := map[string]bool{}
	for _, o := range am {
		if o.Kind != "AlertmanagerConfig" {
			continue
		}
		var s struct {
			Route struct {
				Routes []struct {
					Matchers []struct{ Name, Value string } `yaml:"matchers"`
				} `yaml:"routes"`
			} `yaml:"route"`
		}
		if err := o.Spec.Decode(&s); err != nil {
			t.Fatal(err)
		}
		for _, r := range s.Route.Routes {
			for _, m := range r.Matchers {
				if m.Name == "party" {
					routed[m.Value] = true
				}
			}
		}
	}
	for _, p := range []string{"A", "B", "C"} {
		if !routed[p] || got["party-"+p]["party"] != p {
			t.Errorf("party %s: routed=%v, agent label=%q", p, routed[p], got["party-"+p]["party"])
		}
	}
}
