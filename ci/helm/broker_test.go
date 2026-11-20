package helmcheck

// Checks for deploy/helm/qv-attest-broker (task Broker-chart): the shared policy and image contract, plus the rules of this chart only: one pod and one writer, the broker
// reachable by its own party and nothing else, nothing leaving but DNS (and a network HSM), the allowlist as an immutable hashed ConfigMap, no SoftHSM and no simulation in
// production, the PIN and the keys only from Secret files. Each rule has a test that breaks a rendered manifest, or a value, and wants the violation.

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

func brokerChartDir() string { return filepath.Join("..", "..", "deploy", "helm", "qv-attest-broker") }

// brokerRender renders the chart. Production: values.yaml + made-up pins, keys and allowlist + a made-up digest. Kind (tee-sim): the same without the digest, then values-kind.yaml.
func brokerRender(kind bool, extra ...string) (string, error) {
	helm, err := exec.LookPath("helm")
	if err != nil {
		return "", fmt.Errorf("helm not found on PATH: %w", err)
	}
	d := brokerChartDir()
	args := []string{"template", "qv-attest-b", d, "--namespace", "qv", "-f", filepath.Join(d, "values.yaml"), "-f", "ci-broker-values.yaml"}
	if kind {
		args = append(args, "-f", filepath.Join(d, "values-kind.yaml"))
	} else {
		args = append(args, "-f", "ci-broker-digests.yaml")
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

func brokerObjs(t *testing.T, kind bool, extra ...string) ([]Obj, string) {
	t.Helper()
	text, err := brokerRender(kind, extra...)
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
	return objs, text
}

// blankTokenLabel: the PKCS#11 token LABEL in a config is a name, not a credential, but the shared "secret-looking JSON field" rule matches the key `token`.
func blankTokenLabel(objs []Obj, file string) []Obj {
	var out []Obj
	for _, o := range objs {
		if s, ok := o.Data[file]; ok && o.Kind == "ConfigMap" {
			data := map[string]any{}
			for k, x := range o.Data {
				data[k] = x
			}
			data[file] = tokenLabelRe.ReplaceAllString(fmt.Sprint(s), `"token": ""`)
			o.Data = data
		}
		out = append(out, o)
	}
	return out
}

func brokerPolicy(objs []Obj, kind bool) []string {
	var v []string
	for _, m := range CheckPolicy(blankTokenLabel(objs, "broker.json"), PolicyOptions{RequireDigest: !kind}) {
		if kind && strings.Contains(m, "development switch QV_ENV") {
			continue // kind: QV_ENV=dev is what lets the broker use SoftHSM
		}
		v = append(v, m)
	}
	return v
}

func brokerConfigOf(objs []Obj) (map[string]any, string) {
	for _, o := range partyFind(objs, "ConfigMap") {
		if s, ok := o.Data["broker.json"]; ok {
			var c map[string]any
			if err := json.Unmarshal([]byte(fmt.Sprint(s)), &c); err != nil {
				return nil, "broker.json does not parse: " + err.Error()
			}
			return c, ""
		}
	}
	return nil, "no ConfigMap holds broker.json"
}

var hashedName = regexp.MustCompile(`-[0-9a-f]{10}$`)

// checkBroker returns one line per violation of the rules of this chart.
func checkBroker(objs []Obj, kind bool) []string {
	var v []string
	add := func(f string, a ...any) { v = append(v, fmt.Sprintf(f, a...)) }

	// --- one StatefulSet, one pod, one volume
	sets := partyFind(objs, "StatefulSet")
	if len(sets) != 1 {
		add("want exactly one StatefulSet, got %d", len(sets))
		return v
	}
	for _, o := range objs {
		if o.Kind == "Deployment" || o.Kind == "DaemonSet" || o.Kind == "ReplicaSet" || o.Kind == "Ingress" {
			add("%s/%s: the broker runs as one StatefulSet and is never published through an Ingress", o.Kind, o.Metadata.Name)
		}
	}
	var sts partySTS
	if err := sets[0].Spec.Decode(&sts); err != nil {
		add("StatefulSet spec: %v", err)
		return v
	}
	pod, _ := sets[0].Pod()
	if sts.Replicas == nil || *sts.Replicas != 1 {
		add("replicas is not exactly 1: the broker is a single writer (nonces in memory, one audit chain)")
	}
	if sts.UpdateStrategy.Type != "RollingUpdate" || sts.PodManagementPolicy != "OrderedReady" {
		add("the update must stop the old pod before the new one starts (RollingUpdate on one replica, OrderedReady)")
	}
	if sts.RetentionPolicy.WhenDeleted != "Retain" || sts.RetentionPolicy.WhenScaled != "Retain" {
		add("the audit volume must be retained when the StatefulSet is deleted or scaled")
	}
	if len(sts.VolumeClaimTemplates) != 1 || sts.VolumeClaimTemplates[0].Metadata.Name != "data" {
		add("want one volumeClaimTemplate named data")
	} else if !kind && strings.Join(sts.VolumeClaimTemplates[0].Spec.AccessModes, ",") != "ReadWriteOncePod" {
		add("production data volume must be ReadWriteOncePod, got %v", sts.VolumeClaimTemplates[0].Spec.AccessModes)
	}
	var main *Container
	for i := range pod.Containers {
		if pod.Containers[i].Name == "qv-attest-broker" {
			main = &pod.Containers[i]
		}
	}
	if len(pod.Containers) != 1 || main == nil {
		add("the pod must be exactly the broker container (no sidecar sees the PIN or the wrapping keys)")
		return v
	}
	if strings.Join(main.Args, " ") != "serve -config /etc/qv/config/broker.json" {
		add("broker args are %v, want serve -config /etc/qv/config/broker.json", main.Args)
	}
	if pod.AutomountServiceAccountToken == nil || *pod.AutomountServiceAccountToken {
		add("automountServiceAccountToken must be false")
	}

	// --- the config
	cfg, bad := brokerConfigOf(objs)
	if bad != "" {
		add("%s", bad)
		return v
	}
	parties, _ := cfg["parties"].(map[string]any)
	if len(parties) != 1 {
		add("the broker lists %d parties, want exactly one: a broker that releases the keys of several parties is one place where 2-of-3 falls", len(parties))
	}
	for p, e := range parties {
		if len(strList(dig(e, "caller_pins"))) == 0 {
			add("party %s has no caller_pins", p)
		}
		for _, pin := range strList(dig(e, "caller_pins")) {
			if !hex64.MatchString(pin) {
				add("party %s: caller pin %q is not 64 lowercase hex", p, pin)
			}
		}
	}
	if _, ok := cfg["allow_debug"]; ok {
		add("allow_debug is in the config: debug-mode evidence must never be accepted by a deployed broker")
	}
	if str(dig(cfg, "operators", "min_operators")) == "" || str(dig(cfg, "operators", "min_operators")) == "0" {
		add("operators.min_operators is missing or zero")
	}
	pin := str(dig(cfg, "pkcs11", "pin_file"))
	lib := str(dig(cfg, "pkcs11", "lib"))
	for name, p := range map[string]string{"tls_cert": str(cfg["tls_cert"]), "tls_key": str(cfg["tls_key"]), "trust_roots": str(cfg["trust_roots"]), "allowlist_file": str(cfg["allowlist_file"]), "pkcs11.pin_file": pin} {
		if !strings.HasPrefix(p, "/etc/qv/") && !strings.HasPrefix(p, "/run/qv/") {
			add("%s %q is not under /etc/qv or /run/qv", name, p)
		}
	}
	if !strings.HasPrefix(str(cfg["audit_log"]), "/var/lib/qv/broker/") {
		add("audit_log %q is not on the data volume /var/lib/qv/broker", cfg["audit_log"])
	}
	if str(cfg["audit_log"]) == "" || str(cfg["allowlist_file"]) == "" {
		add("audit_log and allowlist_file are required")
	}

	// --- production: no SoftHSM, no simulation, no development switch; kind: SoftHSM only through the init container
	var env = map[string]string{}
	for _, e := range main.Env {
		env[e.Name] = e.Value
		if e.ValueFrom.Kind != 0 {
			add("environment variable %s comes from a Secret or field: the PIN is a file, never an environment variable", e.Name)
		}
	}
	vols := map[string]bool{}
	for _, vl := range pod.Volumes {
		vols[vl.Name] = true
	}
	if kind {
		if env["QV_ENV"] != "dev" {
			add("kind: QV_ENV must be dev (SoftHSM)")
		}
		if !strings.HasPrefix(lib, "/usr/lib/softhsm/") {
			add("kind: pkcs11.lib %q is not the SoftHSM module", lib)
		}
		if pin != "/run/qv/pin/pin" {
			add("kind: the broker reads the staged 0400 PIN copy, got %q", pin)
		}
		if partyFindInit(pod, "softhsm-init") == nil {
			add("kind: no softhsm-init container (the token and the staged PIN)")
		}
	} else {
		if _, ok := env["QV_ENV"]; ok {
			add("production sets QV_ENV: the production broker has no development switch")
		}
		if len(pod.InitContainers) != 0 || vols["softhsm-conf"] || vols["hsm-so-pin"] || vols["pin-staged"] {
			add("production has SoftHSM parts (init container or volumes)")
		}
		if !strings.HasPrefix(lib, "/etc/qv/hsm/") || !vols["hsm-module"] {
			add("production pkcs11.lib %q must lie under /etc/qv/hsm/ on the hsm-module volume", lib)
		}
		if pin != "/etc/qv/hsm-pin/pin" {
			add("production pin_file is %q", pin)
		}
		if strings.Contains(sets[0].Raw, "softhsm") || strings.Contains(sets[0].Raw, "SOFTHSM") {
			add("production StatefulSet mentions SoftHSM")
		}
		if !digestRe.MatchString(main.Image) {
			add("production image %q is not referenced by digest", main.Image)
		}
	}

	// --- the allowlist: an immutable ConfigMap whose name carries its content hash, mounted as the file the config names
	cms := map[string]Obj{}
	for _, o := range partyFind(objs, "ConfigMap") {
		cms[o.Metadata.Name] = o
		if !strings.Contains(o.Raw, "immutable: true") {
			add("ConfigMap %s is not immutable", o.Metadata.Name)
		}
		if !hashedName.MatchString(o.Metadata.Name) {
			add("ConfigMap %s has no content hash in its name", o.Metadata.Name)
		}
	}
	allow := ""
	for _, vl := range pod.Volumes {
		if vl.Name == "allowlist" && vl.ConfigMap != nil {
			allow = vl.ConfigMap.Name
		}
	}
	if o, ok := cms[allow]; !ok || o.Data["allowlist.json"] == nil {
		add("the allowlist volume does not name a rendered ConfigMap with allowlist.json")
	} else if !strings.HasPrefix(str(cfg["allowlist_file"]), "/etc/qv/allowlist/") {
		add("allowlist_file %q is not on the allowlist mount", cfg["allowlist_file"])
	}

	// --- network: default deny; in = this party on the mutual-TLS port (and a named scraper on the health port); out = DNS and a network HSM
	deny := false
	for _, o := range partyFind(objs, "NetworkPolicy") {
		m := asMap(o)
		types := strList(dig(m, "policyTypes"))
		sel, _ := dig(m, "podSelector").(map[string]any)
		if len(sel) == 0 && strings.Join(types, ",") == "Ingress,Egress" && len(list(m["ingress"])) == 0 && len(list(m["egress"])) == 0 {
			deny = true
		}
		for _, eg := range list(m["egress"]) {
			for _, p := range list(dig(eg, "ports")) {
				port := str(dig(p, "port"))
				if port != "53" && port != "2223" {
					add("NetworkPolicy %s: egress to port %s: the broker dials nothing but DNS and its HSM", o.Metadata.Name, port)
				}
			}
			if len(list(dig(eg, "to"))) == 0 {
				add("NetworkPolicy %s: an egress rule without a destination means everyone", o.Metadata.Name)
			}
		}
		for _, in := range list(m["ingress"]) {
			if len(list(dig(in, "from"))) == 0 {
				add("NetworkPolicy %s: an ingress rule without a source means everyone", o.Metadata.Name)
			}
			for _, p := range list(dig(in, "ports")) {
				port := str(dig(p, "port"))
				if port != "8443" && port != "8444" {
					add("NetworkPolicy %s: ingress on port %s", o.Metadata.Name, port)
				}
				if port == "8443" && o.Metadata.Annotations["quorumvault.io/ingress-purpose"] != "attest-broker-party" {
					add("NetworkPolicy %s: the mutual-TLS port is opened without the party-ingress purpose", o.Metadata.Name)
				}
			}
		}
	}
	if !deny {
		add("no default-deny NetworkPolicy")
	}

	// --- service: the mutual-TLS port only
	for _, o := range partyFind(objs, "Service") {
		m := asMap(o)
		if ps := list(dig(m, "ports")); len(ps) != 1 || str(dig(ps[0], "port")) != "8443" {
			add("Service %s publishes %d ports: only the mutual-TLS port 8443 (the health port is not published)", o.Metadata.Name, len(ps))
		}
	}

	// --- one PodDisruptionBudget, a drain waits for the operator
	pdbs := partyFind(objs, "PodDisruptionBudget")
	if len(pdbs) != 1 {
		add("want one PodDisruptionBudget, got %d", len(pdbs))
	} else if got := str(dig(asMap(pdbs[0]), "maxUnavailable")); !kind && got != "0" {
		add("production PodDisruptionBudget maxUnavailable is %s: a drain must wait for the operator (0)", got)
	}
	return v
}

func brokerContractOK(objs []Obj) []string {
	c, err := LoadContract()
	if err != nil {
		return []string{err.Error()}
	}
	return partyContract(objs, c)
}

func TestBrokerPolicyContractAndChecksPass(t *testing.T) {
	for _, kind := range []bool{false, true} {
		name := map[bool]string{false: "production", true: "kind"}[kind]
		t.Run(name, func(t *testing.T) {
			objs, _ := brokerObjs(t, kind)
			for _, m := range brokerPolicy(objs, kind) {
				t.Error("policy: " + m)
			}
			for _, m := range checkBroker(objs, kind) {
				t.Error(m)
			}
			if kind { // the token-making init container is a shell in the dev image, not the entrypoint: the contract is checked on the broker container
				objs = partyDropInit(objs)
			}
			for _, m := range brokerContractOK(objs) {
				t.Error("contract: " + m)
			}
		})
	}
}

// Every rule above has to be able to fail: each case breaks one rendered manifest and wants the violation.
func TestBrokerChecksCatch(t *testing.T) {
	cases := []struct {
		name, from, to, want string
		kind                 bool
	}{
		{"second replica", "  replicas: 1\n  serviceName", "  replicas: 2\n  serviceName", "replicas is not exactly 1", false},
		{"no default deny", "  podSelector: {}\n  policyTypes: [Ingress, Egress]", "  podSelector: {}\n  policyTypes: [Ingress]", "no default-deny", false},
		{"egress to the internet", "- { port: 2223, protocol: TCP }", "- { port: 443, protocol: TCP }", "dials nothing but DNS", false},
		{"ingress on a strange port", "ports: [{ port: 8443, protocol: TCP }]", "ports: [{ port: 22, protocol: TCP }]", "ingress on port 22", false},
		{"a drain that does not wait", "  maxUnavailable: 0", "  maxUnavailable: 1", "a drain must wait", false},
		{"Service publishes the health port", "    - { name: mtls, port: 8443, targetPort: mtls, protocol: TCP }", "    - { name: mtls, port: 8443, targetPort: mtls, protocol: TCP }\n    - { name: health, port: 8444, targetPort: health, protocol: TCP }", "publishes 2 ports", false},
		{"allow_debug in the config", `"audit_log": "/var/lib/qv/broker/audit.log",`, `"allow_debug": true, "audit_log": "/var/lib/qv/broker/audit.log",`, "allow_debug", false},
		{"audit log off the volume", `"audit_log": "/var/lib/qv/broker/audit.log"`, `"audit_log": "/tmp/audit.log"`, "audit_log", false},
		{"production sets QV_ENV", "          args: [\"serve\", \"-config\", \"/etc/qv/config/broker.json\"]\n", "          args: [\"serve\", \"-config\", \"/etc/qv/config/broker.json\"]\n          env:\n            - { name: QV_ENV, value: dev }\n", "no development switch", false},
		{"mutable ConfigMap", "immutable: true\ndata:\n  allowlist.json", "data:\n  allowlist.json", "is not immutable", false},
		{"PIN from a Secret env var", "          args: [\"serve\", \"-config\", \"/etc/qv/config/broker.json\"]\n", "          args: [\"serve\", \"-config\", \"/etc/qv/config/broker.json\"]\n          env:\n            - name: QV_BROKER_PIN\n              valueFrom: { secretKeyRef: { name: x, key: pin } }\n", "never an environment variable", false},
		{"kind without the init container", "        - name: softhsm-init", "        - name: other-init", "no softhsm-init", true},
	}
	cache := map[bool]string{}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			text, ok := cache[c.kind]
			if !ok {
				_, tx := brokerObjs(t, c.kind)
				cache[c.kind], text = tx, tx
			}
			if !strings.Contains(text, c.from) {
				t.Fatalf("test is stale: %q not in the rendered chart", c.from)
			}
			objs, err := Parse(strings.Replace(text, c.from, c.to, 1))
			if err != nil {
				t.Fatal(err)
			}
			got := append(checkBroker(objs, c.kind), brokerPolicy(objs, c.kind)...)
			for _, m := range got {
				if strings.Contains(m, c.want) {
					return
				}
			}
			t.Errorf("want a violation containing %q, got %v", c.want, got)
		})
	}
}

// The chart refuses what the schema or a guard rules out, before anything is rendered.
func TestBrokerRefusals(t *testing.T) {
	if _, err := brokerRender(false); err != nil && strings.Contains(err.Error(), "not found on PATH") {
		t.Skip(err)
	}
	cases := []struct {
		name  string
		kind  bool
		extra []string
		want  string
	}{
		{"two replicas", false, []string{"--set", "replicas=2"}, "value must be 1"},
		{"no role", false, []string{"--set", "party.role="}, "party.role is required"},
		{"unknown role", false, []string{"--set", "party.role=D"}, "must be one of"},
		{"no caller pins", false, []string{"--set", "party.callerPins=null"}, "party.callerPins is required"},
		{"a malformed pin", false, []string{"--set", "party.callerPins={xyz}"}, "does not match"},
		{"all-zero digest", false, []string{"--set", "images.broker.digest=sha256:" + strings.Repeat("0", 64)}, "all-zero placeholder"},
		{"a tag in production", false, []string{"--set", "images.broker.digest=", "--set", "images.broker.tag=latest"}, "images.broker.digest is required in production"},
		{"no digest, no tag", false, []string{"--set", "images.broker.digest="}, "images.broker.digest is required in production"},
		{"kind without digest and tag", true, []string{"--set", "images.broker.tag="}, "needs a digest"},
		{"SoftHSM in production", false, []string{"--set", "hsm.softhsm.enabled=true"}, "hsm.softhsm.enabled is for env dev or test only"},
		{"SoftHSM with env dev and a digest image", false, []string{"--set", "hsm.softhsm.enabled=true", "--set", "env=dev"}, "digest"},
		{"simulation in production", false, []string{"--set", "simulation=true"}, "simulation"},
		{"simulation with a digest image", false, []string{"--set", "simulation=true", "--set", "env=test"}, "simulation needs the tee-sim image referenced by tag"},
		{"env dev with a digest", false, []string{"--set", "env=dev"}, "env dev or test with an image referenced by digest"},
		{"an unknown env", false, []string{"--set", "env=staging"}, "must be one of"},
		{"no PKCS#11 module", false, []string{"--set", "hsm.module.path="}, "hsm.module.path is required"},
		{"module outside the volume", false, []string{"--set", "hsm.module.path=/usr/lib/x.so"}, "must lie under /etc/qv/hsm/"},
		{"fewer operators than needed", false, []string{"--set", "operators.minOperators=5"}, "at least operators.minOperators"},
		{"a malformed operator key", false, []string{"--set", "operators.keys.dave=xyz"}, "does not match"},
		{"no evidence root", false, []string{"--set", "trustRoots.configMap="}, "trustRoots.configMap is required"},
		{"an evidence root ConfigMap without a hash", false, []string{"--set", "trustRoots.configMap=qv-attest-evidence-root"}, "10-hex content hash"},
		{"no allowlist", false, []string{"--set", "allowlist.file="}, "allowlist.file is required"},
		{"an allowlist that is not JSON", false, []string{"--set", "allowlist.file=not json"}, "does not parse"},
		{"a list without a sequence", false, listArg(`{"entries":[],"signatures":[]}`), "seq must be a number"},
		{"a list for another party", false, listArg(`{"seq":2,"entries":[{"party":"A","measurement":"11","not_before":"2026-01-01T00:00:00Z"}],"signatures":[]}`), "one list per broker"},
		{"a misspelled not_after", false, listArg(`{"seq":2,"entries":[{"party":"B","measurement":"11","not_before":"2026-01-01T00:00:00Z","not_atfer":"2027-01-01T00:00:00Z"}],"signatures":[]}`), "unknown field"},
		{"a status that is neither active nor revoked", false, listArg(`{"seq":2,"entries":[{"party":"B","measurement":"11","not_before":"2026-01-01T00:00:00Z","status":"revokd"}],"signatures":[]}`), "not active or revoked"},
		{"nobody may reach it", false, []string{"--set", "network.partyIngress.from=null"}, "network.partyIngress.from is required"},
		{"load balancer without annotations", false, []string{"--set", "service.type=LoadBalancer"}, "internal-load-balancer annotations"},
		{"load balancer without source ranges", false, []string{"--set", "service.type=LoadBalancer", "--set", "service.annotations.service\\.beta\\.kubernetes\\.io/aws-load-balancer-internal=true"}, "sourceRanges"},
		{"NodePort", false, []string{"--set", "service.type=NodePort"}, "must be one of"},
		{"root", false, []string{"--set", "runAsUser=0"}, "value must be 65532"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := brokerRender(c.kind, c.extra...)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("want a refusal containing %q, got %v", c.want, err)
			}
		})
	}
}

// A new allowlist is a new ConfigMap (a new name, so a rollout), the config likewise; an unchanged value leaves the names alone. With a 53-character release name the hash must survive.
func TestBrokerConfigMapNamesFollowTheirContent(t *testing.T) {
	names := func(extra ...string) map[string]bool {
		_, text := brokerObjs(t, false, extra...)
		m := map[string]bool{}
		for _, x := range regexp.MustCompile(`(?m)^kind: ConfigMap\nmetadata:\n  name: (\S+)`).FindAllStringSubmatch(text, -1) {
			m[x[1]] = true
		}
		return m
	}
	base := names()
	if len(base) != 2 {
		t.Fatalf("want two ConfigMaps (config, allowlist), got %v", base)
	}
	if again := names(); fmt.Sprint(again) != fmt.Sprint(base) {
		t.Errorf("the same values gave other names: %v and %v", base, again)
	}
	f := filepath.Join(t.TempDir(), "list.yaml")
	if err := os.WriteFile(f, []byte("allowlist:\n  file: '{\"seq\":2,\"entries\":[],\"signatures\":[]}'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	newList := names("-f", f)
	same := 0
	for n := range newList {
		if base[n] {
			same++
		}
	}
	if same != 1 {
		t.Errorf("a new allowlist must change exactly the allowlist ConfigMap's name (the config stays): %d names unchanged", same)
	}
	for n := range base {
		if len(n) > 63 {
			t.Errorf("ConfigMap name %q is longer than 63", n)
		}
	}
}

// The simulated broker in kind: the tee-sim image by tag, QV_ENV=dev, and a render that production values cannot reach.
func TestBrokerKindIsTheSimulation(t *testing.T) {
	_, text := brokerObjs(t, true)
	if !strings.Contains(text, "qv-image/qv-attest-broker-teesim:local") {
		t.Error("kind values must run the tee-sim broker image by tag")
	}
	_, prod := brokerObjs(t, false)
	for _, s := range []string{"teesim", "softhsm", "SOFTHSM", "QV_ENV"} {
		if strings.Contains(prod, s) {
			t.Errorf("the production render mentions %q", s)
		}
	}
}

// listArg passes a list as the value of allowlist.file (a JSON string: --set would split it at the commas).
func listArg(list string) []string {
	b, _ := json.Marshal(list)
	return []string{"--set-json", "allowlist.file=" + string(b)}
}
