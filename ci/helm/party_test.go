package helmcheck

// Checks for deploy/helm/qv-party: the shared policy and contract checks applied to the party chart for roles A, B and C (production and kind values), plus the
// rules that belong to this chart only: one replica, one volume, the shared socket, no SoftHSM in production, no Ingress, PIN and keys only from Secrets, what a
// role renders and what it must not. Each check also has a test that breaks a rendered manifest and wants the violation.
//
// Everything here is local to this file (names start with party); the helpers it shares with the business tests are Parse, Render's neighbours in manifests.go,
// CheckPolicy and CheckContract.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

var partyRoles = []string{"A", "B", "C"}

var partyEnvs = []struct {
	name string
	kind bool
}{{"production", false}, {"kind", true}}

func partyChartDir() string { return filepath.Join("..", "..", "deploy", "helm", "qv-party") }

// partyRender renders the chart for one role. Production: values.yaml + made-up pins and addresses + made-up digests. Kind: the same without digests, then
// values-kind.yaml (last, so its SoftHSM settings win over the made-up vendor module).
func partyRender(kind bool, role string, extra ...string) (string, error) {
	helm, err := exec.LookPath("helm")
	if err != nil {
		return "", fmt.Errorf("helm not found on PATH: %w", err)
	}
	d := partyChartDir()
	rel := "qv-party-" + strings.ToLower(role)
	if role == "" {
		rel = "qv-party-x"
	}
	args := []string{"template", rel, d, "--namespace", "qv", "--set", "role=" + role,
		"-f", filepath.Join(d, "values.yaml"), "-f", "ci-party-values.yaml"}
	if kind {
		args = append(args, "-f", filepath.Join(d, "values-kind.yaml"))
	} else {
		args = append(args, "-f", "ci-party-digests.yaml")
	}
	args = append(args, extra...)
	args = append(args, strings.Fields(os.Getenv("QV_HELM_ARGS"))...)
	cmd := exec.Command(helm, args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("helm template: %w\n%s", err, errb.String())
	}
	return out.String(), nil
}

func partyObjs(t *testing.T, kind bool, role string, extra ...string) ([]Obj, string) {
	t.Helper()
	text, err := partyRender(kind, role, extra...)
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

// ---------------------------------------------------------------------------------------------------------------------------------------------------------
// Shared checks, applied to the party chart

func partyPolicyOptions(kind bool) PolicyOptions { return PolicyOptions{RequireDigest: !kind} }

// partyPolicy runs the shared policy. The one thing it must tolerate in kind is the development switch QV_ENV=dev that lets the party use SoftHSM; production gets none.
var tokenLabelRe = regexp.MustCompile(`"token":\s*"[^"]*"`)

// The PKCS#11 token LABEL in party.json is a name, not a credential, but the shared "secret-looking JSON field" rule matches the key `token`. It is blanked for that rule only.
func partyPolicy(objs []Obj, kind bool) []string {
	var cleaned []Obj
	for _, o := range objs {
		for _, f := range []string{"party.json", "party-pkcs11.json"} { // the second is the migration's -from config (attested mode, phase migrate)
			if s, ok := o.Data[f]; ok && o.Kind == "ConfigMap" {
				data := map[string]any{}
				for k, x := range o.Data {
					data[k] = x
				}
				data[f] = tokenLabelRe.ReplaceAllString(fmt.Sprint(s), `"token": ""`)
				o.Data = data
			}
		}
		cleaned = append(cleaned, o)
	}
	objs = cleaned
	var v []string
	for _, m := range CheckPolicy(objs, partyPolicyOptions(kind)) {
		if kind && strings.Contains(m, "development switch QV_ENV") {
			continue
		}
		v = append(v, m)
	}
	return v
}

// partyContract runs the shared image contract. The contract was written for the business chart: its zone test is replaced here by one that wants the SIGNING zone,
// and the token-making init container of kind (a shell and softhsm2-util in the -dev image: not the image's entrypoint) is checked by partySoftHSMInit instead.
func partyContract(objs []Obj, c Contract) []string {
	sims := map[string]DevImage{}
	for n, d := range c.DevImages {
		sims[n] = d
	}
	for n, d := range c.SimImages {
		sims[n] = d
	}
	for n, d := range sims { // a -dev (or tee-sim) image is the same binary: it is checked against its production image's entry
		if ic, ok := c.Images[d.Of]; ok {
			ic.Env = append(append([]string{}, ic.Env...), "QV_ENV", "SOFTHSM2_CONF")
			ic.PathEnv = append(append([]string{}, ic.PathEnv...), "SOFTHSM2_CONF")
			c.Images[n] = ic
		}
	}
	signing := map[string]bool{}
	for k, ic := range c.Images {
		signing[k] = ic.Zone == "signing"
		ic.Zone = "business"
		c.Images[k] = ic
	}
	var v []string
	for _, o := range Workloads(objs) {
		pod, _ := o.Pod()
		for _, ct := range containers(pod) {
			if m := imageName.FindStringSubmatch(ct.Image); m != nil && !signing[m[1]] {
				v = append(v, fmt.Sprintf("%s/%s/%s: image %q is not a signing-zone image of the contract", o.Kind, o.Metadata.Name, ct.Name, ct.Image))
			}
		}
	}
	return append(v, CheckContract(partyDropInit(objs), c)...)
}

// partyDropInit removes the initContainers of every workload (the kind-only token step) and declares the `data` volume that a StatefulSet's volumeClaimTemplate creates
// (the contract check wants every mounted volume declared).
func partyDropInit(objs []Obj) []Obj {
	var out []Obj
	for _, o := range objs {
		var m map[string]any
		if err := o.Spec.Decode(&m); err == nil {
			if tpl, ok := m["template"].(map[string]any); ok {
				if sp, ok := tpl["spec"].(map[string]any); ok {
					delete(sp, "initContainers")
					if o.Kind == "StatefulSet" {
						vols, _ := sp["volumes"].([]any)
						sp["volumes"] = append(vols, map[string]any{"name": "data", "persistentVolumeClaim": map[string]any{"claimName": "data"}})
					}
					var n yaml.Node
					if err := n.Encode(m); err == nil {
						o.Spec = n
					}
				}
			}
		}
		out = append(out, o)
	}
	return out
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------------
// Chart-specific checks

type partySTS struct {
	Replicas            *int   `yaml:"replicas"`
	PodManagementPolicy string `yaml:"podManagementPolicy"`
	ServiceName         string `yaml:"serviceName"`
	UpdateStrategy      struct {
		Type          string `yaml:"type"`
		RollingUpdate struct {
			MaxUnavailable any `yaml:"maxUnavailable"`
		} `yaml:"rollingUpdate"`
	} `yaml:"updateStrategy"`
	RetentionPolicy struct {
		WhenDeleted string `yaml:"whenDeleted"`
		WhenScaled  string `yaml:"whenScaled"`
	} `yaml:"persistentVolumeClaimRetentionPolicy"`
	Template struct {
		Spec struct {
			TerminationGracePeriodSeconds int `yaml:"terminationGracePeriodSeconds"`
			Volumes                       []struct {
				Name     string `yaml:"name"`
				HostPath *struct {
					Path string `yaml:"path"`
				} `yaml:"hostPath"`
				EmptyDir *struct {
					Medium string `yaml:"medium"`
				} `yaml:"emptyDir"`
				Secret *struct {
					SecretName string `yaml:"secretName"`
				} `yaml:"secret"`
				ConfigMap *struct {
					Name string `yaml:"name"`
				} `yaml:"configMap"`
				PVC *struct {
					ClaimName string `yaml:"claimName"`
				} `yaml:"persistentVolumeClaim"`
			} `yaml:"volumes"`
		} `yaml:"spec"`
	} `yaml:"template"`
	VolumeClaimTemplates []struct {
		Metadata struct {
			Name string `yaml:"name"`
		} `yaml:"metadata"`
		Spec struct {
			AccessModes []string `yaml:"accessModes"`
		} `yaml:"spec"`
	} `yaml:"volumeClaimTemplates"`
}

func partyFind(objs []Obj, kind string) []Obj {
	var r []Obj
	for _, o := range objs {
		if o.Kind == kind {
			r = append(r, o)
		}
	}
	return r
}

func partyConfigOf(objs []Obj) (map[string]any, string) {
	for _, o := range partyFind(objs, "ConfigMap") {
		if s, ok := o.Data["party.json"]; ok {
			var c map[string]any
			if err := json.Unmarshal([]byte(fmt.Sprint(s)), &c); err != nil {
				return nil, "party.json does not parse: " + err.Error()
			}
			return c, ""
		}
	}
	return nil, "no ConfigMap holds party.json"
}

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func strList(v any) []string {
	var r []string
	if l, ok := v.([]any); ok {
		for _, x := range l {
			r = append(r, fmt.Sprint(x))
		}
	}
	return r
}

func str(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}

func portOf(addr string) int {
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return 0
	}
	p, _ := strconv.Atoi(addr[i+1:])
	return p
}

// checkPartyConfig mirrors mpc-party/internal/server/config.go: unknown fields are an error, and the same role rules. (The test cannot import that module; it is internal.)
func checkPartyConfig(role string, c map[string]any) []string {
	var v []string
	add := func(f string, a ...any) { v = append(v, "party.json: "+fmt.Sprintf(f, a...)) }
	known := map[string]bool{"role": true, "caller_listen": true, "peer_listen": true, "peer_address": true, "cert_file": true, "key_file": true, "peer_pins": true, "caller_pins": true,
		"peer_c_address": true, "peer_c_pins": true, "peer_a_pins": true, "peer_b_pins": true, "data_dir": true, "metrics_listen": true, "admin_keys": true, "admin_max_age_seconds": true, "admin_threshold": true, "admin_allow_v1": true, "admin_max_validity_seconds": true, "admin_domain": true,
		"sealer": true, "authorizer": true, "limits": true}
	for k := range c {
		if !known[k] {
			add("unknown field %q (the binary refuses unknown fields)", k)
		}
	}
	has := func(k string) bool { return str(c[k]) != "" || len(strList(c[k])) > 0 }
	if str(c["role"]) != role {
		add("role is %q, the release is %q", str(c["role"]), role)
	}
	switch role {
	case "A":
		if !has("peer_address") || !has("peer_pins") {
			add("role A needs peer_address and peer_pins")
		}
		if has("peer_listen") {
			add("peer_listen is only for roles B and C")
		}
	case "B", "C":
		if !has("peer_listen") {
			add("peer_listen is required for role %s", role)
		}
		if has("peer_address") {
			add("peer_address is only for role A")
		}
	}
	if role == "C" {
		if has("peer_c_address") || has("peer_c_pins") || has("peer_pins") {
			add("party C dials nobody: no peer_address, peer_c_* or peer_pins")
		}
		if !has("peer_a_pins") || !has("peer_b_pins") {
			add("role C needs peer_a_pins and peer_b_pins")
		}
		for _, a := range strList(c["peer_a_pins"]) {
			for _, b := range strList(c["peer_b_pins"]) {
				if a == b {
					add("peer_a_pins and peer_b_pins share a certificate")
				}
			}
		}
	} else {
		if has("peer_a_pins") || has("peer_b_pins") {
			add("peer_a_pins and peer_b_pins are only for role C")
		}
		if has("peer_c_address") != has("peer_c_pins") {
			add("peer_c_address and peer_c_pins go together")
		}
		if !has("peer_c_address") {
			add("roles A and B dial C: peer_c_address and peer_c_pins are required in this deployment")
		}
		if !has("peer_pins") {
			add("peer_pins is required")
		}
	}
	for _, k := range []string{"caller_listen", "cert_file", "key_file", "data_dir"} {
		if !has(k) {
			add("%s is required", k)
		}
	}
	if !has("caller_pins") || !has("admin_keys") {
		add("caller_pins and admin_keys are required")
	}
	for _, k := range []string{"peer_pins", "caller_pins", "peer_c_pins", "peer_a_pins", "peer_b_pins", "admin_keys"} {
		for _, p := range strList(c[k]) {
			if !hex64.MatchString(p) {
				add("%s: %q is not 64 lowercase hex characters", k, p)
			}
		}
	}
	if has("peer_listen") && str(c["peer_listen"]) == str(c["caller_listen"]) {
		add("peer_listen and caller_listen must be different listeners")
	}
	if m := str(c["metrics_listen"]); m != "" && !strings.HasPrefix(m, "127.0.0.1:") {
		add("metrics_listen %q is not loopback (a signing cluster takes no inbound scrape)", m)
	}
	sealer, _ := c["sealer"].(map[string]any)
	auth, _ := c["authorizer"].(map[string]any)
	for k := range sealer {
		if !map[string]bool{"type": true, "token": true, "lib": true, "pin_env": true, "pin_file": true, "key_file": true}[k] {
			add("sealer: unknown field %q", k)
		}
	}
	if str(sealer["type"]) == "pkcs11" {
		if str(sealer["pin_file"]) == "" || str(sealer["pin_env"]) != "" {
			add("sealer: the PIN comes from pin_file, never pin_env")
		}
		if str(sealer["token"]) == "" || str(sealer["lib"]) == "" {
			add("sealer: token and lib are required")
		}
	}
	if str(sealer["type"]) == "insecure-static-key-for-tests" || str(auth["type"]) == "dev-allow-all" || str(auth["type"]) == "deny-all" {
		add("sealer or authorizer type is a test type")
	}
	for k := range auth {
		if !map[string]bool{"type": true, "socket": true, "timeout_ms": true, "cosigner_pins": true, "accept_risk": true}[k] {
			add("authorizer: unknown field %q", k)
		}
	}
	switch role {
	case "A":
		if str(auth["type"]) != "pinned-caller" {
			add("role A: authorizer is %q, want pinned-caller (its pinned caller, the gateway, decides)", str(auth["type"]))
		}
	default:
		if str(auth["type"]) != "cosigner" || str(auth["socket"]) != "/run/qv/cosigner.sock" || len(strList(auth["cosigner_pins"])) == 0 {
			add("role %s: authorizer must be cosigner on /run/qv/cosigner.sock with cosigner_pins", role)
		}
		for _, p := range strList(auth["cosigner_pins"]) {
			if !hex64.MatchString(p) {
				add("authorizer.cosigner_pins: %q is not 64 lowercase hex characters", p)
			}
		}
	}
	lim, _ := c["limits"].(map[string]any)
	for k := range lim {
		if !map[string]bool{"recv_timeout_ms": true, "keygen_recv_timeout_ms": true, "session_timeout_ms": true, "max_peer_sessions": true, "max_frame_bytes": true,
			"sessions_per_sec_key": true, "max_intent_bytes": true, "shutdown_grace_ms": true, "replay_cache_size": true}[k] {
			add("limits: unknown field %q", k)
		}
	}
	return v
}

type partyMount struct {
	container, volume, path string
	readOnly                bool
}

// checkParty is everything this chart promises about one render.
func checkParty(objs []Obj, role string, kind bool) []string {
	var v []string
	add := func(f string, a ...any) { v = append(v, fmt.Sprintf(f, a...)) }
	cos := role != "A"

	// --- one StatefulSet, one pod, one volume, no overlap
	sets := partyFind(objs, "StatefulSet")
	if len(sets) != 1 {
		add("want exactly one StatefulSet, got %d", len(sets))
		return v
	}
	for _, o := range objs {
		if o.Kind == "Deployment" || o.Kind == "DaemonSet" || o.Kind == "ReplicaSet" {
			add("%s/%s: a party runs only as a StatefulSet", o.Kind, o.Metadata.Name)
		}
	}
	var sts partySTS
	if err := sets[0].Spec.Decode(&sts); err != nil {
		add("StatefulSet spec: %v", err)
		return v
	}
	pod, _ := sets[0].Pod()
	if sts.Replicas == nil || *sts.Replicas != 1 {
		add("StatefulSet replicas is not exactly 1")
	}
	if sts.UpdateStrategy.Type != "RollingUpdate" {
		add("updateStrategy is %q: only RollingUpdate (stop the old pod, then start the new) never runs two pods of one party", sts.UpdateStrategy.Type)
	}
	if sts.UpdateStrategy.RollingUpdate.MaxUnavailable != nil {
		add("updateStrategy sets maxUnavailable (a surge of pods is not allowed)")
	}
	if sts.PodManagementPolicy != "OrderedReady" {
		add("podManagementPolicy is %q, want OrderedReady", sts.PodManagementPolicy)
	}
	if sts.RetentionPolicy.WhenDeleted != "Retain" || sts.RetentionPolicy.WhenScaled != "Retain" {
		add("persistentVolumeClaimRetentionPolicy must retain the data volume (whenDeleted and whenScaled Retain)")
	}
	if len(sts.VolumeClaimTemplates) != 1 || sts.VolumeClaimTemplates[0].Metadata.Name != "data" {
		add("want exactly one volumeClaimTemplate named data")
	} else if !kind && fmt.Sprint(sts.VolumeClaimTemplates[0].Spec.AccessModes) != "[ReadWriteOncePod]" {
		add("production data volume access mode is %v, want [ReadWriteOncePod] (one pod can mount it, ever)", sts.VolumeClaimTemplates[0].Spec.AccessModes)
	}
	cfg, msg := partyConfigOf(objs)
	if msg != "" {
		add("%s", msg)
		return v
	}
	grace := 10
	if lim, ok := cfg["limits"].(map[string]any); ok {
		if g, ok := lim["shutdown_grace_ms"].(float64); ok {
			grace = int(g) / 1000
		}
	}
	if sts.Template.Spec.TerminationGracePeriodSeconds < grace+20 {
		add("terminationGracePeriodSeconds %d is below shutdown_grace_ms/1000 + 20 (%d)", sts.Template.Spec.TerminationGracePeriodSeconds, grace+20)
	}

	// --- containers and mounts
	var names []string
	mounts := map[string][]partyMount{} // volume -> mounts
	byName := map[string]Container{}
	for _, c := range pod.Containers {
		names = append(names, c.Name)
		byName[c.Name] = c
		for _, m := range c.VolumeMounts {
			mounts[m.Name] = append(mounts[m.Name], partyMount{c.Name, m.Name, m.MountPath, m.ReadOnly})
		}
	}
	wantNames := "mpc-party"
	if cos {
		wantNames = "mpc-party,qv-cosigner"
	}
	if strings.Join(names, ",") != wantNames {
		add("containers are [%s], want [%s]", strings.Join(names, ","), wantNames)
	}
	for _, vl := range sts.Template.Spec.Volumes {
		if vl.HostPath != nil {
			add("volume %s is a hostPath", vl.Name)
		}
		if vl.EmptyDir != nil {
			var who []string
			for _, m := range mounts[vl.Name] {
				who = append(who, m.container)
			}
			sort.Strings(who)
			if !cos {
				add("role A has an emptyDir (%s): it has no cosigner, so no socket", vl.Name)
			} else if vl.Name != "socket" || vl.EmptyDir.Medium != "Memory" || strings.Join(who, ",") != "mpc-party,qv-cosigner" {
				add("emptyDir %s (medium %q) is mounted by [%s]: only the socket volume, in memory, shared by exactly mpc-party and qv-cosigner", vl.Name, vl.EmptyDir.Medium, strings.Join(who, ","))
			}
		}
	}
	if cos {
		found := false
		for _, vl := range sts.Template.Spec.Volumes {
			if vl.Name == "socket" && vl.EmptyDir != nil {
				found = true
			}
		}
		if !found {
			add("no socket emptyDir for the cosigner")
		}
	}
	// the data volume belongs to the party container alone
	for _, m := range mounts["data"] {
		if m.container != "mpc-party" {
			add("the data volume is mounted by %s", m.container)
		}
	}
	// keys: the party's key only in the party container, each cosigner secret only in the cosigner; nothing else mounts a Secret
	secretOwner := map[string]string{"party-tls": "mpc-party", "hsm-pin": "mpc-party", "hsm-so-pin": "softhsm-init", "cosigner-tls": "qv-cosigner", "cosigner-link-tls": "qv-cosigner", "cosigner-socket-tls": "qv-cosigner"}
	secrets := map[string]string{}
	for _, vl := range sts.Template.Spec.Volumes {
		if vl.Secret != nil {
			secrets[vl.Name] = vl.Secret.SecretName
			if _, ok := secretOwner[vl.Name]; !ok {
				add("Secret volume %s is not one the chart knows", vl.Name)
			}
		}
	}
	for vol, ms := range mounts {
		if owner, ok := secretOwner[vol]; ok {
			for _, m := range ms {
				if m.container != owner {
					add("Secret volume %s is mounted in %s, only %s may hold it", vol, m.container, owner)
				}
			}
		}
	}
	if cos {
		if secrets["party-tls"] == "" || secrets["cosigner-tls"] == "" || secrets["cosigner-socket-tls"] == "" || secrets["cosigner-link-tls"] == "" {
			add("a role %s pod needs the party, cosigner, cosigner-socket and cosigner-link certificate Secrets", role)
		}
	} else {
		for _, n := range []string{"cosigner-tls", "cosigner-link-tls", "cosigner-socket-tls", "cosigner-config"} {
			if _, ok := mountsOrVolume(sts, n); ok {
				add("role A has the cosigner volume %s", n)
			}
		}
	}
	// files named in the config sit on the right mounts
	under := func(container, path string) (string, bool) {
		for _, m := range byName[container].VolumeMounts {
			if path == m.MountPath || strings.HasPrefix(path, strings.TrimSuffix(m.MountPath, "/")+"/") {
				return m.Name, true
			}
		}
		return "", false
	}
	needVolume := func(field, path, want string) {
		if vol, ok := under("mpc-party", path); !ok || (want != "" && vol != want) {
			add("party.json %s=%s is not on the %s volume of the mpc-party container (on %q)", field, path, want, vol)
		}
	}
	needVolume("cert_file", str(cfg["cert_file"]), "party-tls")
	needVolume("key_file", str(cfg["key_file"]), "party-tls")
	needVolume("data_dir", str(cfg["data_dir"]), "data")
	if s, ok := cfg["sealer"].(map[string]any); ok && str(s["type"]) == "pkcs11" {
		needVolume("sealer.pin_file", str(s["pin_file"]), "hsm-pin")
		if kind {
			if vol, ok := under("mpc-party", str(s["lib"])); ok {
				add("kind: the SoftHSM module should be the image's own file, found on volume %s", vol)
			}
		} else {
			needVolume("sealer.lib", str(s["lib"]), "hsm-module")
		}
	}
	if cos {
		a, _ := cfg["authorizer"].(map[string]any)
		needVolume("authorizer.socket", str(a["socket"]), "socket")
	}
	// the config the container reads is the one rendered, by an immutable ConfigMap whose name carries a hash
	args := strings.Join(byName["mpc-party"].Args, " ")
	if args != "-config /etc/qv/config/party.json" {
		add("mpc-party args are %q", args)
	}
	for _, o := range partyFind(objs, "ConfigMap") {
		if !strings.Contains(o.Raw, "immutable: true") {
			add("ConfigMap/%s is not immutable", o.Metadata.Name)
		}
		if !regexp.MustCompile(`-[0-9a-f]{10}$`).MatchString(o.Metadata.Name) {
			add("ConfigMap/%s: the name does not end in a content hash", o.Metadata.Name)
		}
	}
	v = append(v, checkPartyConfig(role, cfg)...)

	// --- ports: services, probes, policies agree with the config
	cp := portOf(str(cfg["caller_listen"]))
	pp := portOf(str(cfg["peer_listen"]))
	if role == "A" {
		pp = portOf(str(cfg["peer_address"])) // A dials: the peer port is where B and C listen
	}
	svcs := map[string]Obj{}
	for _, o := range partyFind(objs, "Service") {
		svcs[strings.TrimPrefix(o.Metadata.Name, "qv-party-"+strings.ToLower(role))] = o
	}
	servicePort := func(o Obj) int {
		var s struct {
			Ports []struct {
				TargetPort int `yaml:"targetPort"`
			} `yaml:"ports"`
		}
		_ = o.Spec.Decode(&s)
		if len(s.Ports) != 1 {
			return -1
		}
		return s.Ports[0].TargetPort
	}
	if s, ok := svcs["-caller"]; !ok || servicePort(s) != cp {
		add("no caller Service on the caller_listen port %d", cp)
	}
	if cos {
		if s, ok := svcs["-peer"]; !ok || servicePort(s) != pp {
			add("no peer Service on the peer_listen port %d", pp)
		}
	} else if _, ok := svcs["-peer"]; ok {
		add("role A has a peer Service (it dials, it does not listen)")
	}
	allowed := map[int]bool{cp: true}
	if cos {
		allowed[pp] = true
	}
	for _, c := range pod.Containers {
		for _, p := range []*struct{}{} {
			_ = p
		}
		_ = c
	}
	if hp := portsOfEnv(byName["mpc-party"], "QV_HEALTH_LISTEN"); hp == 0 || allowed[hp] {
		add("mpc-party health listener port %d is missing or collides with a service port", hp)
	}
	if !strings.Contains(sets[0].Raw, "path: /readyz") || !strings.Contains(sets[0].Raw, "path: /livez") {
		add("probes: want httpGet /readyz and /livez on the health listener")
	}
	for _, o := range partyFind(objs, "NetworkPolicy") {
		v = append(v, checkPartyPolicy(o, role, cp, pp)...)
	}
	// --- no way in from outside
	for _, o := range objs {
		switch o.Kind {
		case "Ingress", "HTTPRoute", "TCPRoute", "Gateway", "Route", "IngressRoute":
			add("%s/%s: a party has no Ingress or Gateway: its ports are reached through private endpoints", o.Kind, o.Metadata.Name)
		case "Service":
			var s struct {
				Type  string `yaml:"type"`
				Ports []struct {
					NodePort int `yaml:"nodePort"`
				} `yaml:"ports"`
			}
			_ = o.Spec.Decode(&s)
			if s.Type == "NodePort" || s.Type == "ExternalName" {
				add("Service/%s: type %s", o.Metadata.Name, s.Type)
			}
			if s.Type == "LoadBalancer" {
				if o.Metadata.Annotations["quorumvault.io/endpoint"] != "private" || !privateLB(o.Metadata.Annotations) {
					add("Service/%s: a LoadBalancer without an internal-load-balancer annotation", o.Metadata.Name)
				}
				if !strings.Contains(o.Raw, "loadBalancerSourceRanges") {
					add("Service/%s: a LoadBalancer without loadBalancerSourceRanges", o.Metadata.Name)
				}
			}
		}
	}
	// --- PIN and keys: only from Secrets
	for _, c := range pod.Containers {
		for _, e := range c.Env {
			up := strings.ToUpper(e.Name)
			if strings.Contains(up, "PIN") && !strings.HasSuffix(up, "_PINS") || strings.Contains(up, "PASSWORD") {
				add("%s: environment variable %s: the PIN is a file from a Secret", c.Name, e.Name)
			}
			if len(e.ValueFrom.Content) > 0 {
				add("%s: environment variable %s comes from valueFrom: secrets are files", c.Name, e.Name)
			}
		}
		if len(c.EnvFrom) > 0 {
			add("%s: envFrom", c.Name)
		}
	}
	if sealer, ok := cfg["sealer"].(map[string]any); ok && str(sealer["type"]) == "pkcs11" {
		if secrets["hsm-pin"] == "" {
			add("the PIN volume is not a Secret")
		}
		if _, ok := sealer["pin"]; ok {
			add("sealer.pin: the PIN is in the config")
		}
	}
	// --- what a role must not render
	if cos {
		for _, bad := range []string{"peer_address", "pinned-caller", "QV_GATEWAY_GUARD_DSN", "-gateway-guard-dsn", "-jobs-dsn", "QV_GATEWAY_JOBS_DSN"} {
			if role == "B" || role == "C" {
				if strings.Contains(sets[0].Raw, bad) || bad != "peer_address" && bad != "pinned-caller" && strings.Contains(fmt.Sprint(cfg), bad) {
					add("a role %s render contains the gateway-side setting %s", role, bad)
				}
			}
		}
		if strings.Contains(fmt.Sprint(cfg), "peer_address") || strings.Contains(fmt.Sprint(cfg["authorizer"]), "pinned-caller") {
			add("a role %s config has an A-only setting", role)
		}
	} else {
		for _, o := range objs {
			if strings.Contains(strings.ToLower(o.Raw), "cosigner") {
				add("%s/%s: role A runs no cosigner but the render mentions one", o.Kind, o.Metadata.Name)
			}
		}
	}
	// --- softhsm and development switches
	soft := partyFindInit(pod, "softhsm-init")
	if kind {
		if role != "" && soft == nil {
			add("kind: no softhsm-init container to make the token")
		}
		v = append(v, partySoftHSMInit(pod, byName["mpc-party"], cfg)...)
	} else {
		if soft != nil {
			add("production render has the SoftHSM init container")
		}
		for _, o := range objs {
			low := strings.ToLower(o.Raw)
			if strings.Contains(low, "softhsm") || strings.Contains(o.Raw, "QV_ENV") || regexp.MustCompile(`-dev(@|:|")`).MatchString(o.Raw) {
				add("%s/%s: SoftHSM, QV_ENV or a -dev image in a production render", o.Kind, o.Metadata.Name)
			}
		}
	}
	return v
}

func mountsOrVolume(s partySTS, name string) (int, bool) {
	for i, vl := range s.Template.Spec.Volumes {
		if vl.Name == name {
			return i, true
		}
	}
	return 0, false
}

func partyFindInit(p PodSpec, name string) *Container {
	for i := range p.InitContainers {
		if p.InitContainers[i].Name == name {
			return &p.InitContainers[i]
		}
	}
	return nil
}

func portsOfEnv(c Container, name string) int {
	for _, e := range c.Env {
		if e.Name == name {
			return portOf(e.Value)
		}
	}
	return 0
}

var privateLBKeys = []string{"service.beta.kubernetes.io/aws-load-balancer-internal", "service.beta.kubernetes.io/aws-load-balancer-scheme", "networking.gke.io/load-balancer-type",
	"service.beta.kubernetes.io/azure-load-balancer-internal", "service.beta.kubernetes.io/openstack-internal-load-balancer"}

func privateLB(a map[string]string) bool {
	for _, k := range privateLBKeys {
		if val, ok := a[k]; ok && val != "false" && val != "internet-facing" && val != "External" {
			return true
		}
	}
	return false
}

// partySoftHSMInit: the kind-only token step runs the same image (by tag, -dev), as the same user, mounts no socket and no certificate, and its environment is the development switch.
func partySoftHSMInit(pod PodSpec, party Container, cfg map[string]any) []string {
	var v []string
	c := partyFindInit(pod, "softhsm-init")
	if c == nil {
		return v
	}
	if c.Image != party.Image || !strings.Contains(c.Image, "-dev:") {
		v = append(v, fmt.Sprintf("softhsm-init image %q must be the party's -dev image referenced by tag", c.Image))
	}
	for _, m := range c.VolumeMounts {
		if m.Name == "socket" || strings.Contains(m.Name, "tls") {
			v = append(v, "softhsm-init mounts "+m.Name)
		}
	}
	env := ""
	for _, e := range party.Env {
		env += e.Name + "=" + e.Value + " "
	}
	if !strings.Contains(env, "QV_ENV=dev") {
		v = append(v, "kind: the party container does not set QV_ENV=dev, SoftHSM would be refused")
	}
	return v
}

type npPeer struct {
	IPBlock *struct {
		CIDR string `yaml:"cidr"`
	} `yaml:"ipBlock"`
	NamespaceSelector *yaml.Node `yaml:"namespaceSelector"`
	PodSelector       *struct {
		MatchLabels map[string]string `yaml:"matchLabels"`
	} `yaml:"podSelector"`
}
type npPort struct {
	Port int `yaml:"port"`
}
type npFull struct {
	PodSelector struct {
		MatchLabels      map[string]string `yaml:"matchLabels"`
		MatchExpressions []any             `yaml:"matchExpressions"`
	} `yaml:"podSelector"`
	PolicyTypes []string `yaml:"policyTypes"`
	Ingress     []struct {
		From  []npPeer `yaml:"from"`
		Ports []npPort `yaml:"ports"`
	} `yaml:"ingress"`
	Egress []struct {
		To    []npPeer `yaml:"to"`
		Ports []npPort `yaml:"ports"`
	} `yaml:"egress"`
}

func checkPartyPolicy(o Obj, role string, cp, pp int) []string {
	var v []string
	id := "NetworkPolicy/" + o.Metadata.Name
	add := func(f string, a ...any) { v = append(v, id+": "+fmt.Sprintf(f, a...)) }
	var s npFull
	if err := o.Spec.Decode(&s); err != nil {
		return []string{id + ": " + err.Error()}
	}
	allSelected := len(s.PodSelector.MatchLabels) == 0 && len(s.PodSelector.MatchExpressions) == 0
	for _, r := range s.Ingress {
		if allSelected {
			add("an ingress rule on the policy that selects every pod")
		}
		if len(r.From) == 0 {
			add("an ingress rule with no `from` (means everyone)")
		}
		for _, p := range r.Ports {
			switch {
			case p.Port == cp:
			case p.Port == pp && role != "A":
			default:
				add("ingress on port %d: only the caller port %d (and the peer port %d for B and C)", p.Port, cp, pp)
			}
		}
		purpose := o.Metadata.Annotations["quorumvault.io/ingress-purpose"]
		for _, p := range r.Ports {
			if p.Port == pp && role != "A" && purpose != "party-peer" || p.Port == cp && purpose != "party-caller" {
				add("port %d with purpose %q", p.Port, purpose)
			}
		}
		if purpose == "party-peer" {
			for _, f := range r.From {
				if f.PodSelector != nil && f.IPBlock == nil && len(f.PodSelector.MatchLabels) == 0 {
					add("peer ingress from every pod")
				}
				if f.PodSelector != nil && f.PodSelector.MatchLabels["quorumvault.io/party-operator"] != "" {
					add("the operators' pod reaches the peer port")
				}
			}
		}
		for _, f := range r.From {
			if f.IPBlock != nil && (f.IPBlock.CIDR == "0.0.0.0/0" || f.IPBlock.CIDR == "::/0") {
				add("ingress from the whole internet (%s)", f.IPBlock.CIDR)
			}
		}
	}
	for _, r := range s.Egress {
		if len(r.To) == 0 {
			add("an egress rule with no `to` (means everyone)")
		}
		for _, t := range r.To {
			if t.IPBlock != nil && (t.IPBlock.CIDR == "0.0.0.0/0" || t.IPBlock.CIDR == "::/0") {
				add("egress to the whole internet (%s)", t.IPBlock.CIDR)
			}
			if t.IPBlock == nil && t.NamespaceSelector == nil && t.PodSelector == nil {
				add("an egress peer that selects nothing")
			}
		}
		for _, p := range r.Ports {
			switch p.Port {
			case 53, 5432, 9092, 2223, cp:
			case pp:
				if role == "C" {
					add("egress to a peer port: party C dials nobody")
				}
			default:
				add("egress on port %d is not one of DNS, peers, database, Kafka, the HSM, the caller port", p.Port)
			}
		}
		if len(r.Ports) == 0 {
			add("an egress rule without ports")
		}
	}
	if role == "A" && (strings.Contains(o.Metadata.Name, "guard-database") || strings.Contains(o.Metadata.Name, "kafka")) {
		add("party A has no database and no Kafka link (its guard is the gateway's)")
	}
	return v
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------------
// Tests

func TestPartyPolicyAndChecksPass(t *testing.T) {
	for _, e := range partyEnvs {
		for _, role := range partyRoles {
			t.Run(e.name+"/"+role, func(t *testing.T) {
				objs, _ := partyObjs(t, e.kind, role)
				for _, m := range partyPolicy(objs, e.kind) {
					t.Error("policy: " + m)
				}
				for _, m := range checkParty(objs, role, e.kind) {
					t.Error(m)
				}
			})
		}
	}
}

func TestPartyContractPasses(t *testing.T) {
	c, err := LoadContract()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range partyEnvs {
		for _, role := range partyRoles {
			t.Run(e.name+"/"+role, func(t *testing.T) {
				objs, _ := partyObjs(t, e.kind, role)
				cc, _ := LoadContract()
				for _, m := range partyContract(objs, cc) {
					t.Error(m)
				}
				_ = c
			})
		}
	}
}

// The checks are worth only what they catch: each case breaks one rendered manifest in one way and wants that violation.
func TestPartyChecksCatch(t *testing.T) {
	type tc struct {
		name, role string
		kind       bool
		from, to   string // text replaced in the render
		want       string
		policy     bool // the shared policy catches it (otherwise checkParty does)
	}
	cases := []tc{
		{"second replica", "B", false, "replicas: 1\n  serviceName", "replicas: 2\n  serviceName", "replicas is not exactly 1", false},
		{"no replica count", "A", false, "replicas: 1\n  serviceName", "serviceName", "replicas is not exactly 1", false},
		{"OnDelete update", "B", false, "type: RollingUpdate", "type: OnDelete", "only RollingUpdate", false},
		{"surge update", "B", false, "rollingUpdate: { partition: 0 }", "rollingUpdate: { partition: 0, maxUnavailable: 1 }", "maxUnavailable", false},
		{"Parallel pod management", "B", false, "podManagementPolicy: OrderedReady", "podManagementPolicy: Parallel", "want OrderedReady", false},
		{"data volume deleted with the set", "B", false, "whenDeleted: Retain", "whenDeleted: Delete", "retain the data volume", false},
		{"shared data volume mode", "B", false, "accessModes: [\"ReadWriteOncePod\"]", "accessModes: [\"ReadWriteMany\"]", "ReadWriteOncePod", false},
		{"short stop bound", "B", false, "terminationGracePeriodSeconds: 30", "terminationGracePeriodSeconds: 5", "terminationGracePeriodSeconds", false},
		{"socket on disk", "B", false, "emptyDir: { medium: Memory, sizeLimit: 1Mi }", "emptyDir: {}", "in memory", false},
		{"party key in the cosigner", "B", false, "            - { name: cosigner-config, mountPath: /etc/qv/cosigner, readOnly: true }", "            - { name: cosigner-config, mountPath: /etc/qv/cosigner, readOnly: true }\n            - { name: party-tls, mountPath: /etc/qv/party-tls, readOnly: true }", "only mpc-party may hold it", false},
		{"cosigner socket key in the party", "C", false, "            - { name: data, mountPath: /var/lib/qv/party }", "            - { name: data, mountPath: /var/lib/qv/party }\n            - { name: cosigner-socket-tls, mountPath: /etc/qv/socket-tls, readOnly: true }", "only qv-cosigner may hold it", false},
		{"cosigner mounts the share", "B", false, "            - { name: socket, mountPath: /run/qv }\n      volumes:", "            - { name: socket, mountPath: /run/qv }\n            - { name: data, mountPath: /var/lib/qv/party }\n      volumes:", "the data volume is mounted by qv-cosigner", false},
		{"a Deployment", "A", false, "kind: StatefulSet", "kind: Deployment", "want exactly one StatefulSet", false},
		{"hostPath", "A", false, "        - name: config\n", "        - name: scratch\n          hostPath: { path: /var/run }\n        - name: config\n", "hostPath", false},
		{"SoftHSM word in production", "A", false, "name: qv-party-a-config-", "name: softhsm-qv-party-a-config-", "SoftHSM, QV_ENV or a -dev image", false},
		{"QV_ENV in production", "B", false, `- { name: QV_HEALTH_LISTEN, value: "0.0.0.0:9100" }`, `- { name: QV_HEALTH_LISTEN, value: "0.0.0.0:9100" }` + "\n            - { name: QV_ENV, value: dev }", "development switch QV_ENV", true},
		{"-dev image in production", "A", false, "mpc-party@sha256", "mpc-party-dev@sha256", "SoftHSM, QV_ENV or a -dev image", false},
		{"PIN in the environment", "A", false, `- { name: QV_HEALTH_LISTEN, value: "0.0.0.0:9100" }`, `- { name: QV_HEALTH_LISTEN, value: "0.0.0.0:9100" }` + "\n            - { name: QV_PARTY_PIN, value: \"1234\" }", "carries a secret value inline", true},
		{"PIN from a Secret env", "A", false, `- { name: QV_HEALTH_LISTEN, value: "0.0.0.0:9100" }`, `- { name: QV_HEALTH_LISTEN, value: "0.0.0.0:9100" }` + "\n            - { name: HSM_PIN, valueFrom: { secretKeyRef: { name: x, key: y } } }", "the PIN is a file from a Secret", false},
		{"PIN in the config", "A", false, `"pin_file": "/etc/qv/hsm-pin/pin"`, `"pin": "1234"`, "unknown field", false},
		{"PIN in an environment variable of the config", "A", false, `"pin_file": "/etc/qv/hsm-pin/pin"`, `"pin_env": "QV_PARTY_PIN"`, "never pin_env", false},
		{"PIN file not on the Secret", "A", false, `"pin_file": "/etc/qv/hsm-pin/pin"`, `"pin_file": "/tmp/pin"`, "sealer.pin_file", false},
		{"unknown config field", "A", false, `"role": "A"`, `"role": "A",` + "\n    \"skip_checks\": true", "unknown field", false},
		{"role mismatch", "B", false, `"role": "B"`, `"role": "A"`, "the release is", false},
		{"gateway setting in B", "B", false, `"role": "B"`, `"role": "B",` + "\n    \"peer_address\": \"x:1\"", "peer_address is only for role A", false},
		{"pinned-caller in C", "C", false, `"type": "cosigner"`, `"type": "pinned-caller"`, "authorizer must be cosigner", false},
		{"test authorizer", "B", false, `"type": "cosigner"`, `"type": "deny-all"`, "authorizer must be cosigner", false},
		{"bad pin", "A", false, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "BBBB", "64 lowercase hex", false},
		{"metrics on the pod IP", "B", false, `"metrics_listen": "127.0.0.1:9102"`, `"metrics_listen": "0.0.0.0:9102"`, "not loopback", false},
		{"an Ingress", "B", false, "kind: ServiceAccount", "kind: Ingress", "no Ingress or Gateway", false},
		{"NodePort", "B", false, "  type: ClusterIP\n  selector:", "  type: NodePort\n  selector:", "NodePort", false},
		{"public load balancer", "B", false, "  type: ClusterIP\n  selector:", "  type: LoadBalancer\n  selector:", "LoadBalancer without", false},
		{"egress to the internet", "B", false, "cidr: 10.40.1.0/24", "cidr: 0.0.0.0/0", "egress to the whole internet", false},
		{"ingress from the internet", "B", false, "cidr: 10.30.0.0/24", "cidr: 0.0.0.0/0", "ingress from the whole internet", false},
		{"ingress on the health port", "B", false, "ports: [{ port: 7003, protocol: TCP }]", "ports: [{ port: 9100, protocol: TCP }]", "ingress on port 9100", false},
		{"party C dials", "C", false, "  policyTypes: [Egress]\n  egress:\n    - to:\n        - ipBlock:\n            cidr: 10.40.1.0/24", "  policyTypes: [Egress]\n  egress:\n    - to:\n        - ipBlock:\n            cidr: 10.40.1.0/24\n      ports: [{ port: 7003 }]\n    - to:\n        - ipBlock:\n            cidr: 10.40.1.0/24", "party C dials nobody", false},
		{"A has a guard database", "A", false, "name: qv-party-a-operator-egress", "name: qv-party-a-guard-database-egress", "no database and no Kafka", false},
		{"A mentions a cosigner", "A", false, "name: qv-party-a-dns", "name: qv-party-a-cosigner-dns", "role A runs no cosigner", false},
		{"default deny removed", "B", false, "policyTypes: [Ingress, Egress]\n", "policyTypes: [Ingress]\n", "no default-deny", true},
		{"writable root", "B", false, "readOnlyRootFilesystem: true", "readOnlyRootFilesystem: false", "readOnlyRootFilesystem is not true", true},
		{"capability added", "B", false, `drop: ["ALL"]`, `drop: ["ALL"]` + "\n              add: [IPC_LOCK]", "capabilities added", true},
		{"bare tag in production", "B", false, "mpc-party@sha256:3333333333333333333333333333333333333333333333333333333333333333", "mpc-party:latest", "not referenced by digest", true},
		{"service token mounted", "B", false, "automountServiceAccountToken: false\n      enableServiceLinks", "automountServiceAccountToken: true\n      enableServiceLinks", "automountServiceAccountToken true", true},
		{"PEM in output", "B", false, `"metrics_listen": "127.0.0.1:9102"`, `"metrics_listen": "127.0.0.1:9102",` + "\n    \"x\": \"-----BEGIN PRIVATE KEY-----\"", "PEM block", true},
		{"no softhsm-init in kind", "A", true, "        - name: softhsm-init", "        - name: other-init", "no softhsm-init container", false},
		{"kind without QV_ENV", "A", true, "            - { name: QV_ENV, value: \"dev\" }\n            - { name: SOFTHSM2_CONF, value: /etc/qv/softhsm/softhsm2.conf }\n          startupProbe", "            - { name: SOFTHSM2_CONF, value: /etc/qv/softhsm/softhsm2.conf }\n          startupProbe", "does not set QV_ENV=dev", false},
	}
	cache := map[string]string{}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			key := fmt.Sprint(c.kind, c.role)
			text, ok := cache[key]
			if !ok {
				var err error
				if text, err = partyRender(c.kind, c.role); err != nil {
					t.Skip(err)
				}
				cache[key] = text
			}
			if !strings.Contains(text, c.from) {
				t.Fatalf("test is stale: %q not in the rendered chart", c.from)
			}
			objs, err := Parse(strings.Replace(text, c.from, c.to, 1))
			if err != nil {
				t.Fatal(err)
			}
			got := checkParty(objs, c.role, c.kind)
			if c.policy {
				got = partyPolicy(objs, c.kind)
			}
			if !anyContains(got, c.want) {
				t.Errorf("no violation containing %q; got %v", c.want, got)
			}
		})
	}
}

func TestPartyContractCatches(t *testing.T) {
	text, err := partyRender(false, "B")
	if err != nil {
		t.Skip(err)
	}
	cases := []struct{ name, from, to, want string }{
		{"unknown flag", `- -audit-source`, `- -skip-checks` + "\n            - -audit-source", "flag -skip-checks is not in the contract"},
		{"missing socket flag", "            - -socket\n            - /run/qv/cosigner.sock\n", "", "required flag -socket is missing"},
		{"command overridden", "          args: [\"-config\", \"/etc/qv/config/party.json\"]", "          command: [\"/bin/sh\"]\n          args: [\"-config\", \"/etc/qv/config/party.json\"]", "sets command"},
		{"unknown env", `- { name: QV_HEALTH_LISTEN, value: "0.0.0.0:9100" }`, `- { name: QV_HEALTH_LISTEN, value: "0.0.0.0:9100" }` + "\n            - { name: QV_SURPRISE, value: \"1\" }", "QV_SURPRISE is not in the contract"},
		{"plain text switch", `- { name: QV_HEALTH_LISTEN, value: "0.0.0.0:9100" }`, `- { name: QV_HEALTH_LISTEN, value: "0.0.0.0:9100" }` + "\n            - { name: QV_ALLOW_PLAINTEXT, value: \"1\" }", "must never be set"},
		{"cosigner metrics reachable", `value: "127.0.0.1:9104"`, `value: "0.0.0.0:9104"`, "not a loopback address"},
		{"file without a mount", "mountPath: /etc/qv/socket-tls", "mountPath: /etc/qv/other-tls", "no volume is mounted over it"},
		{"mount outside the contract", "mountPath: /etc/qv/link-tls", "mountPath: /srv/link-tls", "outside the contract's directories"},
		{"business image in a party", "qv-cosigner@sha256:4444444444444444444444444444444444444444444444444444444444444444", "qv-core@sha256:4444444444444444444444444444444444444444444444444444444444444444", "not a signing-zone image"},
		{"image not in the contract", "qv-cosigner@sha256:4444444444444444444444444444444444444444444444444444444444444444", "qv-sidecar@sha256:4444444444444444444444444444444444444444444444444444444444444444", "not in deploy/images/contract.json"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !strings.Contains(text, c.from) {
				t.Fatalf("test is stale: %q not in the rendered chart", c.from)
			}
			objs, err := Parse(strings.Replace(text, c.from, c.to, 1))
			if err != nil {
				t.Fatal(err)
			}
			cc, _ := LoadContract()
			if got := partyContract(objs, cc); !anyContains(got, c.want) {
				t.Errorf("no drift containing %q; got %v", c.want, got)
			}
		})
	}
}

// The chart refuses what the schema or a guard rules out, before anything is rendered.
func TestPartyRefusals(t *testing.T) {
	if _, err := partyRender(false, "A"); err != nil && strings.Contains(err.Error(), "not found on PATH") {
		t.Skip(err)
	}
	cases := []struct {
		name  string
		kind  bool
		role  string
		extra []string
		want  string
	}{
		{"two replicas", false, "A", []string{"--set", "replicas=2"}, "value must be 1"},
		{"zero replicas", false, "A", []string{"--set", "replicas=0"}, "value must be 1"},
		{"unknown role", false, "D", nil, "must be one of"},
		{"no role", false, "", nil, "role is required"},
		{"all-zero digest", false, "A", []string{"--set", "images.party.digest=sha256:" + strings.Repeat("0", 64)}, "all-zero placeholder"},
		{"no digest, no tag", false, "A", []string{"--set", "images.party.digest="}, "needs a digest"},
		{"SoftHSM with a digest image", false, "A", []string{"--set", "hsm.softhsm.enabled=true"}, "SoftHSM is never used with an image referenced by digest"},
		{"attested sealer without a broker", false, "A", []string{"--set", "sealer.type=attested"}, "attested.broker.url is required"},
		{"the former attestBroker switch", false, "A", []string{"--set", "attestBroker.enabled=true"}, "additional properties 'attestBroker' not allowed"},
		{"no PKCS#11 module", false, "A", []string{"--set", "hsm.module.path="}, "hsm.module.path is required"},
		{"module outside the volume", false, "A", []string{"--set", "hsm.module.path=/usr/lib/x.so"}, "must lie under /etc/qv/hsm/"},
		{"load balancer without annotations", false, "B", []string{"--set", "service.peer.type=LoadBalancer"}, "internal-load-balancer annotations"},
		{"load balancer without source ranges", false, "B", []string{"--set", "service.peer.type=LoadBalancer", "--set", "service.peer.annotations.service\\.beta\\.kubernetes\\.io/aws-load-balancer-internal=true"}, "sourceRanges"},
		{"NodePort", false, "B", []string{"--set", "service.peer.type=NodePort"}, "must be one of"},
		{"no operator keys", false, "A", []string{"--set", "adminKeys=null"}, "adminKeys is required"},
		{"threshold above the keys", false, "A", []string{"--set", "adminThreshold=2"}, "adminThreshold cannot be more than the number of adminKeys"},
		{"no caller pins", false, "A", []string{"--set", "callerPins=null"}, "callerPins is required"},
		{"A without B's endpoint", false, "A", []string{"--set", "peers.b.address="}, "peers.b.address is required"},
		{"B without the cosigner config", false, "B", []string{"--set", "cosigner.config=null"}, "cosigner.config is required"},
		{"B without cosigner pins", false, "B", []string{"--set", "cosigner.socketPins=null"}, "cosigner.socketPins is required"},
		{"C without B's pins", false, "C", []string{"--set", "peers.b.pins=null"}, "peers.a.pins and peers.b.pins"},
		{"a malformed pin", false, "A", []string{"--set", "callerPins={xyz}"}, "does not match"},
		{"root", false, "A", []string{"--set", "runAsUser=0"}, "value must be 65532"},
		{"backup job without a volume", false, "A", []string{"--set", "backup.job.enabled=true", "--set", "backup.outputClaim=", "--set", "backup.job.keysetId=k", "--set", "backup.job.outputFile=f"}, "backup.outputClaim is required"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := partyRender(c.kind, c.role, c.extra...)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("want a refusal containing %q, got %v", c.want, err)
			}
		})
	}
}

// What the chart's production defaults contain: no SoftHSM, no development image, no credential-looking values, no Ingress.
func TestPartyProductionValues(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(partyChartDir(), "values.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Images map[string]struct {
			Repository string `yaml:"repository"`
			Tag        string `yaml:"tag"`
		} `yaml:"images"`
		HSM struct {
			SoftHSM struct {
				Enabled bool `yaml:"enabled"`
			} `yaml:"softhsm"`
			Module struct {
				Path string `yaml:"path"`
			} `yaml:"module"`
		} `yaml:"hsm"`
		Sealer      struct{ Type string } `yaml:"sealer"`
		Replicas    int                   `yaml:"replicas"`
		Persistence struct {
			AccessModes []string `yaml:"accessModes"`
		} `yaml:"persistence"`
		Service struct {
			Caller struct{ Type string } `yaml:"caller"`
			Peer   struct{ Type string } `yaml:"peer"`
		} `yaml:"service"`
	}
	if err := yaml.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if v.HSM.SoftHSM.Enabled {
		t.Error("values.yaml enables SoftHSM")
	}
	for k, i := range v.Images {
		if strings.HasSuffix(i.Repository, "-dev") || i.Tag != "" {
			t.Errorf("values.yaml images.%s is a development image or a tag: %s:%s", k, i.Repository, i.Tag)
		}
	}
	var code []string
	for _, l := range strings.Split(string(raw), "\n") {
		if i := strings.Index(l, " #"); i >= 0 {
			l = l[:i]
		}
		if !strings.HasPrefix(strings.TrimSpace(l), "#") {
			code = append(code, l)
		}
	}
	nc := strings.Join(code, "\n")
	if strings.Contains(strings.ToLower(nc), "softhsm2.conf") || strings.Contains(nc, "QV_ENV") || strings.Contains(strings.ToLower(nc), "libsofthsm") {
		t.Error("values.yaml carries SoftHSM or QV_ENV settings")
	}
	if v.Replicas != 1 || v.Sealer.Type != "pkcs11" || fmt.Sprint(v.Persistence.AccessModes) != "[ReadWriteOncePod]" || v.Service.Caller.Type != "ClusterIP" || v.Service.Peer.Type != "ClusterIP" {
		t.Errorf("production defaults: replicas %d, sealer %s, access modes %v, services %s/%s", v.Replicas, v.Sealer.Type, v.Persistence.AccessModes, v.Service.Caller.Type, v.Service.Peer.Type)
	}
	// the defaults must not render: the digests are placeholders
	if helm, err := exec.LookPath("helm"); err == nil {
		if out, err := exec.Command(helm, "template", "qv-party-a", partyChartDir(), "--set", "role=A", "-f", "ci-party-values.yaml").CombinedOutput(); err == nil {
			t.Errorf("values.yaml rendered with placeholder digests:\n%.200s", out)
		}
	}
	// the kind values are the only place SoftHSM and a -dev image may be named
	kind, err := os.ReadFile(filepath.Join(partyChartDir(), "values-kind.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(kind), "-dev") || !strings.Contains(string(kind), "softhsm") {
		t.Error("values-kind.yaml no longer shows the -dev image and SoftHSM: is the kind lane still testing the same chart?")
	}
}

// Roles render what they need and nothing else.
func TestPartyRoleShapes(t *testing.T) {
	want := map[string]struct{ containers, services, configMaps int }{
		"A": {1, 2, 1}, // party; headless + caller; party config
		"B": {2, 3, 2}, // party, cosigner; headless + caller + peer; party + cosigner config
		"C": {2, 3, 2},
	}
	for role, w := range want {
		t.Run(role, func(t *testing.T) {
			objs, _ := partyObjs(t, false, role)
			pod, _ := partyFind(objs, "StatefulSet")[0].Pod()
			if len(pod.Containers) != w.containers || len(partyFind(objs, "Service")) != w.services || len(partyFind(objs, "ConfigMap")) != w.configMaps {
				t.Errorf("role %s renders %d containers, %d services, %d ConfigMaps; want %d, %d, %d", role, len(pod.Containers), len(partyFind(objs, "Service")), len(partyFind(objs, "ConfigMap")), w.containers, w.services, w.configMaps)
			}
			if len(partyFind(objs, "Secret")) != 0 || len(partyFind(objs, "Job")) != 0 {
				t.Error("a Secret or a Job is rendered by default")
			}
		})
	}
}

// A role-B render carries nothing that belongs to the gateway or to party A.
func TestPartyRoleBHasNoGatewayOnlySettings(t *testing.T) {
	for _, role := range []string{"B", "C"} {
		objs, text := partyObjs(t, false, role)
		for _, bad := range []string{"peer_address", "pinned-caller", "GATEWAY_GUARD_DSN", "gateway-guard-dsn", "jobs-dsn", "mpc-metrics-file", "worker-id"} {
			if strings.Contains(text, bad) {
				t.Errorf("role %s render contains %q", role, bad)
			}
		}
		if cfg, _ := partyConfigOf(objs); len(strList(cfg["peer_pins"])) == 0 && role == "B" {
			t.Error("B lost its peer pins")
		}
	}
}

// The optional pieces: the backup Job and the output volume render safely, and only when asked.
func TestPartyBackupJob(t *testing.T) {
	args := []string{"--set", "backup.job.enabled=true", "--set", "backup.job.keysetId=ks1", "--set", "backup.job.outputFile=ks1-g1-B.backup", "--set", "backup.job.recoveryPublicConfigMap=recovery-public"}
	for _, e := range partyEnvs {
		objs, text := partyObjs(t, e.kind, "B", args...)
		jobs := partyFind(objs, "Job")
		if len(jobs) != 1 {
			t.Fatalf("%s: want 1 Job, got %d", e.name, len(jobs))
		}
		for _, m := range partyPolicy(objs, e.kind) {
			t.Error(e.name + " policy: " + m)
		}
		pod, _ := jobs[0].Pod()
		c := pod.Containers[0]
		if strings.Join(c.Args[:2], " ") != "backup export" || strings.Contains(text, "recovery.private") || strings.Contains(strings.ToLower(text), "admin-key") {
			t.Errorf("%s: the Job is not a plain `backup export` with the recovery PUBLIC key: %v", e.name, c.Args)
		}
		for _, vol := range pod.Volumes {
			if vol.Secret != nil && vol.Name != "hsm-pin" {
				t.Errorf("%s: the Job mounts the Secret %s", e.name, vol.Name)
			}
		}
		if e.kind == false && jobs[0].Metadata.Labels["app.kubernetes.io/component"] != "party-backup" {
			t.Error("the backup Job pod must not carry the party's selector labels (a Service would route to it)")
		}
	}
}

// The operator Job (`qv-party-admin`, one call): off by default, refuses missing pieces, holds no signing key, carries the operator label and not the
// party's selector labels, mounts only the caller certificate and the signed file, and passes the policies.
func TestPartyOperatorJob(t *testing.T) {
	base := []string{"--set", "operator.job.enabled=true", "--set", "operator.job.command=refresh", "--set", "operator.job.keysetId=hot-0",
		"--set", "operator.job.authConfigMap=refresh-auth", "--set", "operator.job.callerCertSecret=operator-caller",
		"--set", "operator.job.partyPin=" + strings.Repeat("ab", 32)}
	for _, role := range []string{"A", "B", "C"} {
		for _, e := range partyEnvs {
			objs, text := partyObjs(t, e.kind, role, base...)
			jobs := partyFind(objs, "Job")
			if len(jobs) != 1 {
				t.Fatalf("%s %s: want 1 Job, got %d", role, e.name, len(jobs))
			}
			for _, m := range partyPolicy(objs, e.kind) {
				t.Error(role + " " + e.name + " policy: " + m)
			}
			pod, _ := jobs[0].Pod()
			c := pod.Containers[0]
			args := strings.Join(c.Args, " ")
			for _, want := range []string{"refresh -auth /etc/qv/admin/auth.json", "-party " + role + "=qv-party-" + strings.ToLower(role) + "-caller:7001@" + strings.Repeat("ab", 32), "-cert /etc/qv/caller/tls.crt", "-window 300s", "-threshold 1", "-max-validity 3600s", "-admin-key " + strings.Repeat("1", 64)} {
				if !strings.Contains(args, want) {
					t.Errorf("%s %s: args lack %q: %s", role, e.name, want, args)
				}
			}
			if !strings.Contains(c.Image, "qv-tools-signing") || len(c.Command) != 1 || c.Command[0] != "/usr/local/bin/qv-party-admin" {
				t.Errorf("%s %s: image %s command %v", role, e.name, c.Image, c.Command)
			}
			if strings.Contains(strings.ToLower(text), "admin.key") || strings.Contains(args, "-key /etc/qv/admin") {
				t.Errorf("%s %s: the Job refers to an operator signing key", role, e.name)
			}
			secrets := 0
			for _, vol := range pod.Volumes {
				if vol.Secret != nil {
					secrets++
					if vol.Secret.SecretName != "operator-caller" {
						t.Errorf("%s %s: the Job mounts the Secret %s", role, e.name, vol.Secret.SecretName)
					}
				}
			}
			if secrets != 1 {
				t.Errorf("%s %s: want exactly the caller certificate Secret, got %d", role, e.name, secrets)
			}
			var tpl struct {
				Template struct {
					Metadata Meta `yaml:"metadata"`
				} `yaml:"template"`
			}
			if err := jobs[0].Spec.Decode(&tpl); err != nil {
				t.Fatal(err)
			}
			l := tpl.Template.Metadata.Labels
			if l["quorumvault.io/party-operator"] != "true" || l["app.kubernetes.io/component"] == "party" {
				t.Errorf("%s %s: pod labels %v: want the operator label and not the party's", role, e.name, l)
			}
			if pod.AutomountServiceAccountToken == nil || *pod.AutomountServiceAccountToken {
				t.Errorf("%s %s: the Job mounts a service account token", role, e.name)
			}
		}
	}
	// a DKG carries its scheme; status needs no file
	objs, _ := partyObjs(t, false, "A", "--set", "operator.job.enabled=true", "--set", "operator.job.command=dkg", "--set", "operator.job.keysetId=k", "--set", "operator.job.scheme=ecdsa-2of3",
		"--set", "operator.job.authConfigMap=a", "--set", "operator.job.callerCertSecret=s", "--set", "operator.job.partyPin="+strings.Repeat("cd", 32))
	pod, _ := partyFind(objs, "Job")[0].Pod()
	if a := strings.Join(pod.Containers[0].Args, " "); !strings.Contains(a, "dkg -auth") || !strings.Contains(a, "-scheme ecdsa-2of3") || strings.Contains(a, "-curve") {
		t.Errorf("dkg args: %s", a)
	}
	objs, _ = partyObjs(t, false, "B", "--set", "operator.job.enabled=true", "--set", "operator.job.command=status", "--set", "operator.job.callerCertSecret=s", "--set", "operator.job.partyPin="+strings.Repeat("cd", 32))
	pod, _ = partyFind(objs, "Job")[0].Pod()
	if a := strings.Join(pod.Containers[0].Args, " "); strings.Contains(a, "-auth") || len(pod.Volumes) != 1 {
		t.Errorf("status args: %s, volumes %d", a, len(pod.Volumes))
	}
	// off by default
	for _, e := range partyEnvs {
		if objs, _ := partyObjs(t, e.kind, "A"); len(partyFind(objs, "Job")) != 0 {
			t.Errorf("%s: a Job renders by default", e.name)
		}
	}
	// refusals
	with := func(drop string, extra ...string) []string {
		var out []string
		for i := 0; i < len(base); i += 2 {
			if !strings.Contains(base[i+1], drop) {
				out = append(out, base[i], base[i+1])
			}
		}
		return append(out, extra...)
	}
	for _, c := range []struct {
		name string
		args []string
		want string
	}{
		{"no command", with("command", "--set", "operator.job.command="), "operator.job.command must be"},
		{"no auth file", with("authConfigMap"), "operator.job.authConfigMap is required"},
		{"no certificate", with("callerCertSecret"), "operator.job.callerCertSecret is required"},
		{"no pin", with("partyPin"), "operator.job.partyPin is required"},
		{"bad pin", with("partyPin", "--set", "operator.job.partyPin=XYZ"), "64 lowercase hex"},
		{"no keyset", with("keysetId"), "operator.job.keysetId is required"},
		{"bad scheme", with("command", "--set", "operator.job.command=dkg", "--set", "operator.job.scheme=rsa"), "operator.job.scheme must be"},
	} {
		if _, err := partyRender(false, "A", c.args...); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err %v, want %q", c.name, err, c.want)
		}
	}
}

// The Job's arguments are parsed by the real qv-party-admin's flag definitions (the binary is built and asked with -h), so the chart and the
// tool cannot drift; and every command that acts on a keyset passes the expected one (the tool refuses a file for another keyset).
func TestPartyOperatorJobFlagsMatchTheTool(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go not found")
	}
	bin := filepath.Join(t.TempDir(), "qv-party-admin")
	build := exec.Command("go", "build", "-o", bin, "./cmd/qv-party-admin")
	build.Dir = filepath.Join(partyChartDir(), "..", "..", "..", "mpc-party")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build qv-party-admin: %v\n%s", err, out)
	}
	known := func(cmd string) map[string]bool {
		out, _ := exec.Command(bin, cmd, "-h").CombinedOutput() // exits 1 after printing the flags
		m := map[string]bool{}
		for _, l := range strings.Split(string(out), "\n") {
			if f := strings.Fields(l); len(f) > 0 && strings.HasPrefix(f[0], "-") {
				m[strings.TrimPrefix(f[0], "-")] = true
			}
		}
		if len(m) < 4 {
			t.Fatalf("%s -h printed no flags:\n%s", cmd, out)
		}
		return m
	}
	pin := strings.Repeat("ab", 32)
	for _, cmd := range []string{"dkg", "refresh", "unfreeze", "status"} {
		args := []string{"--set", "operator.job.enabled=true", "--set", "operator.job.command=" + cmd, "--set", "operator.job.keysetId=hot-0",
			"--set", "operator.job.authConfigMap=a", "--set", "operator.job.callerCertSecret=s", "--set", "operator.job.partyPin=" + pin}
		objs, _ := partyObjs(t, false, "A", args...)
		pod, _ := partyFind(objs, "Job")[0].Pod()
		a := pod.Containers[0].Args
		if a[0] != cmd {
			t.Fatalf("%s: first argument %q", cmd, a[0])
		}
		ks := known(cmd)
		sawKeyset := false
		for i := 1; i < len(a); i++ {
			if !strings.HasPrefix(a[i], "-") {
				continue
			}
			name := strings.TrimPrefix(a[i], "-")
			if !ks[name] {
				t.Errorf("%s: the Job passes -%s, which `qv-party-admin %s` does not define", cmd, name, cmd)
			}
			if name == "keyset" {
				sawKeyset = true
				if a[i+1] != "hot-0" {
					t.Errorf("%s: -keyset is %q", cmd, a[i+1])
				}
			}
		}
		if !sawKeyset {
			t.Errorf("%s: the Job does not pass -keyset: a file for another keyset would be accepted", cmd)
		}
	}
}
