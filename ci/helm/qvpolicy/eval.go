package qvpolicy

// An offline evaluator for the qv-policy chart (deploy/policy/qv-policy): it reads the rendered ValidatingAdmissionPolicies and bindings and applies them to
// manifests, with the CEL engine the API server uses (github.com/google/cel-go, pinned in go.mod) and, for Pod Security `restricted`, the API server's own checks
// (k8s.io/pod-security-admission, pinned). No cluster is involved.
//
// What it does NOT reproduce (the kind lane's live tests cover these, see deploy/policy/qv-policy/README.md): the API server's type checking of the
// expressions against the resource schemas, the CEL cost budget, the Kubernetes CEL extension libraries (the chart uses the standard functions and the
// strings extension only, which the compile step enforces), admission order and defaulting beyond what podFromWorkload mimics.

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	psaapi "k8s.io/pod-security-admission/api"
	"k8s.io/pod-security-admission/policy"
)

type Map = map[string]any

// ParseDocs splits a multi-document YAML stream into generic objects.
func ParseDocs(text string) ([]Map, error) {
	dec := yaml.NewDecoder(strings.NewReader(text))
	var out []Map
	for {
		var m Map
		if err := dec.Decode(&m); err != nil {
			if err.Error() == "EOF" {
				return out, nil
			}
			return nil, err
		}
		if len(m) > 0 {
			out = append(out, m)
		}
	}
}

// HelmTemplate renders a chart and returns the objects.
func HelmTemplate(chart, release, ns string, args ...string) ([]Map, error) {
	a := append([]string{"template", release, chart, "--namespace", ns}, args...)
	cmd := exec.Command("helm", a...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("helm template %s: %v\n%s", chart, err, stderr.String())
	}
	return ParseDocs(string(out))
}

func qstr(m Map, path ...string) string {
	var cur any = m
	for _, p := range path {
		mm, ok := cur.(Map)
		if !ok {
			return ""
		}
		cur = mm[p]
	}
	s, _ := cur.(string)
	return s
}

func qsub(m Map, path ...string) Map {
	var cur any = m
	for _, p := range path {
		mm, ok := cur.(Map)
		if !ok {
			return nil
		}
		cur = mm[p]
	}
	mm, _ := cur.(Map)
	return mm
}

func qstrs(v any) []string {
	var out []string
	l, _ := v.([]any)
	for _, x := range l {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// DeepCopy copies a generic object without changing number types.
func DeepCopy(v any) any {
	switch t := v.(type) {
	case Map:
		o := make(Map, len(t))
		for k, x := range t {
			o[k] = DeepCopy(x)
		}
		return o
	case []any:
		o := make([]any, len(t))
		for i, x := range t {
			o[i] = DeepCopy(x)
		}
		return o
	}
	return v
}

// PodFromWorkload builds the Pod the API server would see for a workload's pod template: the template's metadata and spec, the namespace, and the
// ServiceAccount admission plugin's work (the default ServiceAccount, and the projected token volume unless the pod or its ServiceAccount opts out).
// Returns nil for objects that carry no pod template.
func PodFromWorkload(o Map, ns string, all []Map) Map {
	var tpl Map
	switch qstr(o, "kind") {
	case "Deployment", "StatefulSet", "ReplicaSet", "DaemonSet", "Job":
		tpl = qsub(o, "spec", "template")
	case "CronJob":
		tpl = qsub(o, "spec", "jobTemplate", "spec", "template")
	}
	if tpl == nil {
		return nil
	}
	meta, _ := DeepCopy(tpl["metadata"]).(Map)
	if meta == nil {
		meta = Map{}
	}
	meta["namespace"] = ns
	if meta["name"] == nil {
		meta["name"] = qstr(o, "metadata", "name") + "-0"
	}
	spec := DeepCopy(tpl["spec"]).(Map)
	if spec["serviceAccountName"] == nil {
		spec["serviceAccountName"] = "default"
	}
	mount := true
	if v, ok := spec["automountServiceAccountToken"].(bool); ok {
		mount = v
	} else {
		for _, sa := range all {
			if qstr(sa, "kind") == "ServiceAccount" && qstr(sa, "metadata", "name") == spec["serviceAccountName"] {
				if v, ok := sa["automountServiceAccountToken"].(bool); ok && !v {
					mount = false
				}
			}
		}
	}
	if mount {
		vols, _ := spec["volumes"].([]any)
		vols = append(vols, Map{"name": "kube-api-access-x1y2z", "projected": Map{"sources": []any{Map{"serviceAccountToken": Map{"path": "token", "expirationSeconds": 3607}}}}})
		spec["volumes"] = vols
	}
	return Map{"apiVersion": "v1", "kind": "Pod", "metadata": meta, "spec": spec}
}

// PSAViolations evaluates a Pod against Pod Security `restricted` at the pinned version and returns one line per failed check.
func PSAViolations(pod Map, version string) ([]string, error) {
	var maj, min int
	if _, err := fmt.Sscanf(version, "v%d.%d", &maj, &min); err != nil {
		return nil, fmt.Errorf("bad version %q", version)
	}
	b, err := json.Marshal(pod)
	if err != nil {
		return nil, err
	}
	var p corev1.Pod
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	ev, err := policy.NewEvaluator(policy.DefaultChecks())
	if err != nil {
		return nil, err
	}
	var out []string
	for _, r := range ev.EvaluatePod(psaapi.LevelVersion{Level: psaapi.LevelRestricted, Version: psaapi.MajorMinorVersion(maj, min)}, &metav1.ObjectMeta{Name: p.Name}, &p.Spec) {
		if !r.Allowed {
			out = append(out, r.ForbiddenReason+": "+r.ForbiddenDetail)
		}
	}
	return out, nil
}

// Policy is one rendered ValidatingAdmissionPolicy with its binding.
type Policy struct {
	Name          string
	FailurePolicy string
	Rules         []Map
	Conditions    []NamedExpr
	Variables     []NamedExpr
	Validations   []Validation
	Actions       []string
	NSLabels      map[string]string // the binding's namespaceSelector.matchLabels
	HasBinding    bool
}

type NamedExpr struct{ Name, Expr string }
type Validation struct{ Expr, Message, Reason string }

// PolicySet is the policies of one render, in name order.
type PolicySet struct {
	Policies []*Policy
	env      *cel.Env
}

// LoadPolicies reads the VAPs and bindings out of rendered objects.
func LoadPolicies(objs []Map) (*PolicySet, error) {
	env, err := cel.NewEnv(ext.Strings(), cel.Variable("object", cel.DynType), cel.Variable("oldObject", cel.DynType), cel.Variable("request", cel.DynType), cel.Variable("variables", cel.DynType))
	if err != nil {
		return nil, err
	}
	ps := &PolicySet{env: env}
	by := map[string]*Policy{}
	for _, o := range objs {
		if qstr(o, "kind") != "ValidatingAdmissionPolicy" {
			continue
		}
		p := &Policy{Name: qstr(o, "metadata", "name"), FailurePolicy: qstr(o, "spec", "failurePolicy")}
		for _, r := range anyList(qsub(o, "spec", "matchConstraints")["resourceRules"]) {
			p.Rules = append(p.Rules, r.(Map))
		}
		for _, c := range anyList(qsub(o, "spec")["matchConditions"]) {
			p.Conditions = append(p.Conditions, NamedExpr{qstr(c.(Map), "name"), qstr(c.(Map), "expression")})
		}
		for _, c := range anyList(qsub(o, "spec")["variables"]) {
			p.Variables = append(p.Variables, NamedExpr{qstr(c.(Map), "name"), qstr(c.(Map), "expression")})
		}
		for _, c := range anyList(qsub(o, "spec")["validations"]) {
			p.Validations = append(p.Validations, Validation{qstr(c.(Map), "expression"), qstr(c.(Map), "message"), qstr(c.(Map), "reason")})
		}
		by[p.Name] = p
		ps.Policies = append(ps.Policies, p)
	}
	for _, o := range objs {
		if qstr(o, "kind") != "ValidatingAdmissionPolicyBinding" {
			continue
		}
		p := by[qstr(o, "spec", "policyName")]
		if p == nil {
			return nil, fmt.Errorf("binding %s names the unknown policy %s", qstr(o, "metadata", "name"), qstr(o, "spec", "policyName"))
		}
		p.HasBinding = true
		p.Actions = qstrs(qsub(o, "spec")["validationActions"])
		p.NSLabels = map[string]string{}
		for k, v := range qsub(o, "spec", "matchResources", "namespaceSelector", "matchLabels") {
			p.NSLabels[k], _ = v.(string)
		}
	}
	sort.Slice(ps.Policies, func(i, j int) bool { return ps.Policies[i].Name < ps.Policies[j].Name })
	// Every expression must compile: a typo is a test failure, not a policy that silently never matches.
	for _, p := range ps.Policies {
		for _, e := range p.exprs() {
			if _, iss := env.Compile(e); iss.Err() != nil {
				return nil, fmt.Errorf("policy %s: expression does not compile: %v\n%s", p.Name, iss.Err(), e)
			}
		}
	}
	return ps, nil
}

func anyList(v any) []any { l, _ := v.([]any); return l }

func (p *Policy) exprs() []string {
	var e []string
	for _, c := range p.Conditions {
		e = append(e, c.Expr)
	}
	for _, c := range p.Variables {
		e = append(e, c.Expr)
	}
	for _, c := range p.Validations {
		e = append(e, c.Expr)
	}
	return e
}

// Request is what the API server hands to admission.
type Request struct {
	Group, Resource, Subresource, Operation string
	Name, Namespace                         string
	Object, OldObject                       Map
	User                                    string
	Groups                                  []string
}

// Denial is one failed validation.
type Denial struct{ Policy, Message string }

func (d Denial) String() string { return d.Policy + ": " + d.Message }

func ruleMatches(r Map, q Request) bool {
	has := func(key, v string) bool {
		for _, s := range qstrs(r[key]) {
			if s == v || s == "*" {
				return true
			}
		}
		return false
	}
	res := q.Resource
	if q.Subresource != "" {
		res += "/" + q.Subresource
	}
	return has("apiGroups", q.Group) && has("operations", q.Operation) && has("resources", res)
}

// Admit evaluates every policy that applies to the request. nsLabels are the labels of the request's namespace. A policy in Warn mode (no Deny action) never denies.
func (ps *PolicySet) Admit(q Request, nsLabels map[string]string) ([]Denial, error) {
	var out []Denial
	for _, p := range ps.Policies {
		if !p.HasBinding {
			continue
		}
		deny := false
		for _, a := range p.Actions {
			deny = deny || a == "Deny"
		}
		if !deny {
			continue
		}
		ok := true
		for k, v := range p.NSLabels {
			if nsLabels[k] != v {
				ok = false
			}
		}
		if !ok {
			continue
		}
		matched := false
		for _, r := range p.Rules {
			matched = matched || ruleMatches(r, q)
		}
		if !matched {
			continue
		}
		act := Map{"object": nilIfEmpty(q.Object), "oldObject": nilIfEmpty(q.OldObject), "request": Map{
			"operation": q.Operation, "name": q.Name, "namespace": q.Namespace, "subResource": q.Subresource,
			"userInfo": Map{"username": q.User, "groups": toAny(q.Groups)},
		}, "variables": Map{}}
		skip := false
		for _, c := range p.Conditions {
			v, err := ps.eval(c.Expr, act)
			if err != nil {
				return nil, fmt.Errorf("%s: matchCondition %s: %w", p.Name, c.Name, err)
			}
			if !v {
				skip = true
			}
		}
		if skip {
			continue
		}
		vars := Map{}
		for _, c := range p.Variables {
			val, err := ps.evalAny(c.Expr, act)
			if err != nil {
				return nil, fmt.Errorf("%s: variable %s: %w", p.Name, c.Name, err)
			}
			vars[c.Name] = val
			act["variables"] = vars
		}
		for _, v := range p.Validations {
			okv, err := ps.eval(v.Expr, act)
			if err != nil {
				// failurePolicy Fail: an expression that cannot be evaluated refuses the request.
				out = append(out, Denial{p.Name, "evaluation error (failurePolicy " + p.FailurePolicy + "): " + err.Error()})
				continue
			}
			if !okv {
				out = append(out, Denial{p.Name, v.Message})
			}
		}
	}
	return out, nil
}

func nilIfEmpty(m Map) any {
	if m == nil {
		return nil
	}
	return m
}

func toAny(s []string) []any {
	o := make([]any, len(s))
	for i, x := range s {
		o[i] = x
	}
	return o
}

func (ps *PolicySet) evalAny(expr string, act Map) (any, error) {
	ast, iss := ps.env.Compile(expr)
	if iss.Err() != nil {
		return nil, iss.Err()
	}
	prg, err := ps.env.Program(ast)
	if err != nil {
		return nil, err
	}
	out, _, err := prg.Eval(act)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (ps *PolicySet) eval(expr string, act Map) (bool, error) {
	v, err := ps.evalAny(expr, act)
	if err != nil {
		return false, err
	}
	b, ok := v.(interface{ Value() any })
	if !ok {
		return false, fmt.Errorf("expression gave no value")
	}
	r, ok := b.Value().(bool)
	if !ok {
		return false, fmt.Errorf("expression is not boolean: %v", b.Value())
	}
	return r, nil
}
