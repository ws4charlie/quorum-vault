package helmcheck

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

type selector struct {
	MatchLabels      map[string]string `yaml:"matchLabels"`
	MatchExpressions []struct {
		Key      string   `yaml:"key"`
		Operator string   `yaml:"operator"`
		Values   []string `yaml:"values"`
	} `yaml:"matchExpressions"`
}

// matches reports whether the selector selects a pod with these labels (empty selector = every pod).
func (s selector) matches(labels map[string]string) bool {
	for k, v := range s.MatchLabels {
		if labels[k] != v {
			return false
		}
	}
	for _, e := range s.MatchExpressions {
		v, has := labels[e.Key]
		switch e.Operator {
		case "In":
			if !has || !contains(e.Values, v) {
				return false
			}
		case "NotIn":
			if has && contains(e.Values, v) {
				return false
			}
		case "Exists":
			if !has {
				return false
			}
		case "DoesNotExist":
			if has {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// CheckApproval checks the optional approval page (qv-approval-web) in the rendered chart: when it is off nothing of it exists and the core lists no
// approval origin; when it is on, it has its own origin (not the core's), the core's -approval-origins is that origin exactly, the page's /config.json
// points at the core's public origin, nothing selects its pods for egress (it makes no connection), and only the ingress controller reaches its port.
func CheckApproval(objs []Obj, approvalPort int) []string {
	var v []string
	add := func(f string, a ...any) { v = append(v, fmt.Sprintf(f, a...)) }
	var dep *Obj
	var coreHosts, approvalHosts []string
	data := map[string]map[string]any{}
	for i, o := range objs {
		if o.Kind == "Deployment" && o.Component() == "approval" {
			dep = &objs[i]
		}
		if o.Kind == "ConfigMap" {
			data[o.Metadata.Name] = o.Data
		}
		if o.Kind == "Ingress" {
			var s struct {
				Rules []struct {
					Host string `yaml:"host"`
				} `yaml:"rules"`
			}
			_ = o.Spec.Decode(&s)
			for _, r := range s.Rules {
				switch o.Component() {
				case "core":
					coreHosts = append(coreHosts, strings.ToLower(r.Host))
				case "approval":
					approvalHosts = append(approvalHosts, strings.ToLower(r.Host))
				}
			}
		}
	}
	coreOrigins := ""
	for _, d := range data {
		if s, ok := d["QV_APPROVAL_ORIGINS"]; ok {
			coreOrigins = fmt.Sprint(s)
		}
	}
	if dep == nil {
		if coreOrigins != "" {
			add("the core lists approval origins %q but no approval page is deployed", coreOrigins)
		}
		if len(approvalHosts) > 0 {
			add("an approval Ingress without an approval Deployment")
		}
		return v
	}
	pod, _ := dep.Pod()
	if len(approvalHosts) != 1 {
		add("the approval page needs exactly one Ingress host, has %v", approvalHosts)
	} else {
		h := approvalHosts[0]
		if contains(coreHosts, h) {
			add("the approval page's host %s is also a core host: it must be a different origin", h)
		}
		if coreOrigins != "https://"+h {
			add("the core's -approval-origins is %q, the approval Ingress is https://%s: they must be the same value", coreOrigins, h)
		}
	}
	for _, c := range pod.Containers {
		var cfg map[string]any
		for _, ef := range c.EnvFrom {
			if ef.ConfigMapRef != nil {
				cfg = data[ef.ConfigMapRef.Name]
			}
		}
		if api := fmt.Sprint(cfg["QV_APPROVAL_API"]); !contains(prefixed("https://", coreHosts), strings.ToLower(api)) {
			add("the page's api %q is not the core's public origin (hosts %v)", api, coreHosts)
		}
	}
	if len(pod.Volumes) > 0 {
		add("the approval page mounts a volume (it holds no state and no secret)")
	}
	labels := dep.Metadata.Labels
	hasIngress := false
	for _, o := range objs {
		if o.Kind != "NetworkPolicy" {
			continue
		}
		var s struct {
			PodSelector selector    `yaml:"podSelector"`
			PolicyTypes []string    `yaml:"policyTypes"`
			Egress      []yaml.Node `yaml:"egress"`
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
		}
		if err := o.Spec.Decode(&s); err != nil || !s.PodSelector.matches(labels) {
			continue
		}
		id := "NetworkPolicy/" + o.Metadata.Name
		if len(s.Egress) > 0 {
			add("%s lets the approval page open connections (egress rules select its pods)", id)
		}
		if o.Metadata.Annotations["quorumvault.io/ingress-purpose"] == "ingress-controller" && len(s.Ingress) > 0 {
			hasIngress = true
		}
		for _, r := range s.Ingress {
			for _, f := range r.From {
				if f.IPBlock != nil || f.PodSelector != nil {
					add("%s admits something other than the ingress controller's namespace to the approval page", id)
				}
			}
			if len(r.From) == 0 {
				add("%s admits everyone to the approval page (a rule without `from`)", id)
			}
			for _, p := range r.Ports {
				if p.Port != approvalPort {
					add("%s opens port %d of the approval page (only %d)", id, p.Port, approvalPort)
				}
			}
			if len(r.Ports) == 0 {
				add("%s opens every port of the approval page", id)
			}
		}
	}
	if !hasIngress {
		add("no NetworkPolicy admits the ingress controller to the approval page")
	}
	return v
}

func prefixed(p string, l []string) []string {
	var out []string
	for _, x := range l {
		out = append(out, p+x)
	}
	return out
}
