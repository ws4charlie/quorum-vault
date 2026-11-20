package helmcheck

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const wantUser = 65532

// PolicyOptions: RequireDigest is set for the production values (a bare tag is refused there), not for kind.
type PolicyOptions struct {
	RequireDigest bool
	CorePort      int
	LinkPorts     []int // the only ports the signing link may open: Postgres and Kafka
}

var (
	digestRe   = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)
	pemRe      = regexp.MustCompile(`-----BEGIN [A-Z ]*(PRIVATE KEY|CERTIFICATE)-----`)
	secretJSON = regexp.MustCompile(`(?i)"(rpc_user|rpc_password|password|passwd|secret|secret_key|api_key|apikey|private_key|pin|token)"\s*:\s*"[^"]`)
	urlCreds   = regexp.MustCompile(`://[^/@\s"]*:[^/@\s"]+@`)
	rpcKeyURL  = regexp.MustCompile(`(?i)"rpc_url"\s*:\s*"[^"]*(@|[?&](key|token|apikey|api_key)=|/v[0-9]/[A-Za-z0-9_-]{16,})`)
	secretName = regexp.MustCompile(`(?i)(PASSWORD|SECRET|TOKEN|_PIN$|PRIVATE|ACCESS_KEY)`)
	devEnv     = map[string]bool{"QV_ALLOW_PLAINTEXT": true, "QV_DEV_ACTOR_HEADER": true, "QV_OIDC_TEST_JWKS": true}
)

func containers(p PodSpec) []Container {
	return append(append([]Container{}, p.InitContainers...), p.Containers...)
}

// CheckPolicy returns one line per violation. Empty = the manifests pass.
func CheckPolicy(objs []Obj, opt PolicyOptions) []string {
	var v []string
	add := func(f string, a ...any) { v = append(v, fmt.Sprintf(f, a...)) }
	hasDeny := false
	for _, o := range objs {
		id := o.Kind + "/" + o.Metadata.Name
		// no Secret object, no key material anywhere in the output
		if o.Kind == "Secret" {
			add("%s: the chart must not render a Secret (certificates come from cert-manager, credentials from the operator)", id)
		}
		if pemRe.MatchString(o.Raw) {
			add("%s: a PEM block is in the rendered output", id)
		}
		switch o.Kind {
		case "ConfigMap":
			keys := make([]string, 0, len(o.Data))
			for k := range o.Data {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				s := fmt.Sprint(o.Data[k])
				if secretJSON.MatchString(s) {
					add("%s[%s]: secret-looking JSON field with a value", id, k)
				}
				if rpcKeyURL.MatchString(s) {
					add("%s[%s]: rpc_url carries credentials or a key; it belongs in the overlay Secret", id, k)
				}
				if urlCreds.MatchString(s) || strings.Contains(strings.ToLower(s), "password=") {
					add("%s[%s]: a password inside a URL or DSN", id, k)
				}
				if secretName.MatchString(k) && !strings.HasSuffix(k, "_FILE") && s != "" {
					add("%s[%s]: a secret-named key holds a value (use a Secret volume and a *_FILE path)", id, k)
				}
				if k == "QV_ENV" && (s == "dev" || s == "test") || devEnv[k] {
					add("%s[%s]: a development switch is set", id, k)
				}
			}
		case "Service":
			var s struct {
				Type string `yaml:"type"`
			}
			_ = o.Spec.Decode(&s)
			if s.Type != "" && s.Type != "ClusterIP" && !(s.Type == "LoadBalancer" && o.Metadata.Annotations["quorumvault.io/endpoint"] == "private") { // a party's private endpoint (qv-party, party_test.go checks it)
				add("%s: Service type %s (only ClusterIP; the way in is the Ingress)", id, s.Type)
			}
		case "NetworkPolicy":
			checkNetworkPolicy(o, opt, &hasDeny, add)
		}
		pod, ok := o.Pod()
		if !ok {
			continue
		}
		if pod.HostNetwork || pod.HostPID || pod.HostIPC {
			add("%s: hostNetwork/hostPID/hostIPC", id)
		}
		if pod.AutomountServiceAccountToken == nil {
			add("%s: automountServiceAccountToken must be set explicitly", id)
		} else if *pod.AutomountServiceAccountToken && o.Component() != "archiver" {
			add("%s: automountServiceAccountToken true (only the archiver's workload identity may)", id)
		}
		for _, c := range containers(pod) {
			cid := id + "/" + c.Name
			sc := c.SecurityContext
			if sc == nil {
				add("%s: no securityContext", cid)
				continue
			}
			nonRoot := (sc.RunAsNonRoot != nil && *sc.RunAsNonRoot) || (pod.SecurityContext != nil && pod.SecurityContext.RunAsNonRoot != nil && *pod.SecurityContext.RunAsNonRoot)
			if !nonRoot {
				add("%s: runAsNonRoot is not true", cid)
			}
			uid := sc.RunAsUser
			if uid == nil && pod.SecurityContext != nil {
				uid = pod.SecurityContext.RunAsUser
			}
			if uid == nil || *uid != wantUser {
				add("%s: runAsUser is not the image's %d", cid, wantUser)
			}
			if sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem {
				add("%s: readOnlyRootFilesystem is not true", cid)
			}
			if sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
				add("%s: allowPrivilegeEscalation is not false", cid)
			}
			if sc.Privileged != nil && *sc.Privileged {
				add("%s: privileged", cid)
			}
			if sc.Capabilities == nil || len(sc.Capabilities.Add) > 0 {
				add("%s: capabilities added or not dropped", cid)
			} else if !contains(sc.Capabilities.Drop, "ALL") {
				add("%s: capabilities.drop must be ALL", cid)
			}
			seccomp := sc.SeccompProfile
			if seccomp == nil && pod.SecurityContext != nil {
				seccomp = pod.SecurityContext.SeccompProfile
			}
			if seccomp == nil || seccomp.Type != "RuntimeDefault" {
				add("%s: seccompProfile is not RuntimeDefault", cid)
			}
			for _, r := range []string{"cpu", "memory"} {
				if c.Resources.Requests[r] == "" || c.Resources.Limits[r] == "" {
					add("%s: %s request and limit are both required", cid, r)
				}
			}
			if opt.RequireDigest && !digestRe.MatchString(c.Image) {
				add("%s: image %q is not referenced by digest", cid, c.Image)
			}
			for _, e := range c.Env {
				if devEnv[e.Name] || (e.Name == "QV_ENV" && (e.Value == "dev" || e.Value == "test")) {
					add("%s: development switch %s", cid, e.Name)
				}
				if secretName.MatchString(e.Name) && e.Value != "" && !strings.HasSuffix(e.Name, "_FILE") {
					add("%s: env %s carries a secret value inline", cid, e.Name)
				}
				if urlCreds.MatchString(e.Value) || strings.Contains(strings.ToLower(e.Value), "password=") {
					add("%s: env %s holds a password in a URL", cid, e.Name)
				}
			}
		}
	}
	if !hasDeny {
		add("no default-deny NetworkPolicy (empty podSelector, Ingress and Egress, no rules)")
	}
	return v
}

type npSpec struct {
	PodSelector struct {
		MatchLabels      map[string]string `yaml:"matchLabels"`
		MatchExpressions []any             `yaml:"matchExpressions"`
	} `yaml:"podSelector"`
	PolicyTypes []string `yaml:"policyTypes"`
	Ingress     []struct {
		From []struct {
			IPBlock           *yaml.Node `yaml:"ipBlock"`
			NamespaceSelector *yaml.Node `yaml:"namespaceSelector"`
			PodSelector       *yaml.Node `yaml:"podSelector"`
		} `yaml:"from"`
		Ports []struct {
			Port int `yaml:"port"`
		} `yaml:"ports"`
	} `yaml:"ingress"`
	Egress []yaml.Node `yaml:"egress"`
}

func checkNetworkPolicy(o Obj, opt PolicyOptions, hasDeny *bool, add func(string, ...any)) {
	id := o.Kind + "/" + o.Metadata.Name
	var s npSpec
	if err := o.Spec.Decode(&s); err != nil {
		add("%s: unreadable: %v", id, err)
		return
	}
	if len(s.PodSelector.MatchLabels) == 0 && len(s.PodSelector.MatchExpressions) == 0 && contains(s.PolicyTypes, "Ingress") && contains(s.PolicyTypes, "Egress") && len(s.Ingress) == 0 && len(s.Egress) == 0 {
		*hasDeny = true
	}
	purpose := o.Metadata.Annotations["quorumvault.io/ingress-purpose"]
	for _, r := range s.Ingress {
		external := false
		for _, f := range r.From {
			// a peer that names a namespace or an address is not "this namespace's pods"
			if f.IPBlock != nil || f.NamespaceSelector != nil {
				external = true
			}
		}
		if !external {
			continue
		}
		switch purpose {
		case "ingress-controller":
			if s.PodSelector.MatchLabels["app.kubernetes.io/component"] != "core" {
				add("%s: the ingress controller may reach only the core", id)
			}
			for _, p := range r.Ports {
				if p.Port != opt.CorePort {
					add("%s: ingress from outside on port %d (only the core port %d)", id, p.Port, opt.CorePort)
				}
			}
		case "signing-link":
			if s.PodSelector.MatchLabels["app.kubernetes.io/part-of"] == "quorum-vault" {
				add("%s: the signing link must end at a dependency (Postgres, Kafka), not at a QuorumVault workload", id)
			}
			for _, p := range r.Ports {
				if !containsInt(opt.LinkPorts, p.Port) {
					add("%s: the signing link opens port %d (only %v)", id, p.Port, opt.LinkPorts)
				}
			}
			if len(r.Ports) == 0 {
				add("%s: the signing link must name its ports", id)
			}
		case "party-caller", "party-peer": // qv-party: its own test (party_test.go) checks the ports and who may come
		default:
			add("%s: ingress from outside the namespace that is neither the ingress controller nor the signing link", id)
		}
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
func containsInt(l []int, n int) bool {
	for _, x := range l {
		if x == n {
			return true
		}
	}
	return false
}

// CheckMigration: the migration hooks exist, run before install and upgrade, in the right order, and no service workload is a hook.
func CheckMigration(objs []Obj, enableLogin bool) []string {
	var v []string
	add := func(f string, a ...any) { v = append(v, fmt.Sprintf(f, a...)) }
	weights := map[string]int{}
	for _, o := range objs {
		h := o.Metadata.Annotations["helm.sh/hook"]
		if o.Kind == "Deployment" && h != "" {
			add("%s: a service Deployment is a hook", o.Metadata.Name)
		}
		if o.Kind != "Job" {
			continue
		}
		if h != "pre-install,pre-upgrade" {
			add("Job/%s: hook is %q, want pre-install,pre-upgrade", o.Metadata.Name, h)
		}
		w, err := strconv.Atoi(o.Metadata.Annotations["helm.sh/hook-weight"])
		if err != nil {
			add("Job/%s: no hook weight", o.Metadata.Name)
		}
		pod, _ := o.Pod()
		for _, c := range pod.Containers {
			weights[c.Name] = w
		}
	}
	m, okm := weights["migrate"]
	if !okm {
		add("no migrate Job")
	}
	if enableLogin {
		l, okl := weights["enable-login"]
		if !okl {
			add("no enable-login Job")
		} else if okm && !(m < l) {
			add("the enable-login Job (weight %d) must run after the migrate Job (weight %d)", l, m)
		}
	}
	return v
}
