package qvpolicy

// Structure checks that need no evaluator: what the chart refuses to render, the namespace labels, the Kyverno signature policy and the RBAC roles.

import (
	"os/exec"
	"strings"
	"testing"
)

func helmOut(args ...string) (string, error) {
	out, err := exec.Command("helm", append([]string{"template", "qvp", policyDir}, args...)...).CombinedOutput()
	return string(out), err
}

var base = []string{"--set", "clusterKind=signing-core", "--set", "namespaces={qvs}", "--set", "registry=" + registry, "--set", "configWriters.users={" + writer + "}"}

func with(extra ...string) []string { return append(append([]string{}, base...), extra...) }

func TestChartRefuses(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("no helm")
	}
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no clusterKind", []string{"--set", "namespaces={a}", "--set", "registry=r.io/x"}, "clusterKind"},
		{"no namespaces", []string{"--set", "clusterKind=business", "--set", "registry=r.io/x"}, "namespaces"},
		{"no registry", []string{"--set", "clusterKind=business", "--set", "namespaces={a}"}, "registry"},
		{"party with two namespaces", []string{"--set", "clusterKind=party", "--set", "namespaces={a,b}", "--set", "registry=r.io/x", "--set", "configWriters.users={u}"}, "exactly one namespace"},
		{"production without signatures", with("--set", "signature.enabled=false"), "signature.enabled"},
		{"production without digests", with("--set", "requireDigest=false"), "requireDigest"},
		{"production in Warn mode", with("--set", "enforcement=Warn"), "enforcement"},
		{"signing cluster without config writers", []string{"--set", "clusterKind=party", "--set", "namespaces={a}", "--set", "registry=r.io/x"}, "configWriters"},
		{"key mode without key", with("--set", "signature.mode=key"), "publicKey"},
		{"unknown kind", with("--set", "clusterKind=other"), "clusterKind"},
		{"weaker Pod Security", with("--set", "pss.level=baseline"), "pss"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, err := helmOut(c.args...)
			if err == nil {
				t.Fatalf("rendered, want a refusal mentioning %q", c.want)
			}
			if !strings.Contains(out, c.want) {
				t.Errorf("refused, but not for %q:\n%s", c.want, out)
			}
		})
	}
}

func TestNamespacesAndKyverno(t *testing.T) {
	objs, _ := policies(t, "signing-core", "qvs")
	var ns, kyv []Map
	for _, o := range objs {
		switch qstr(o, "kind") {
		case "Namespace":
			ns = append(ns, o)
		case "ClusterPolicy":
			kyv = append(kyv, o)
		}
	}
	if len(ns) != 1 {
		t.Fatalf("want one Namespace, got %d", len(ns))
	}
	l := qsub(ns[0], "metadata", "labels")
	for k, v := range map[string]string{"pod-security.kubernetes.io/enforce": "restricted", "pod-security.kubernetes.io/enforce-version": "v1.31", "quorumvault.io/policy": "enforced"} {
		if l[k] != v {
			t.Errorf("namespace label %s = %v, want %s", k, l[k], v)
		}
	}
	if qstr(ns[0], "metadata", "annotations", "helm.sh/resource-policy") != "keep" {
		t.Error("namespaces must survive helm uninstall")
	}
	if len(kyv) != 1 {
		t.Fatalf("want one Kyverno ClusterPolicy in production, got %d", len(kyv))
	}
	sp := qsub(kyv[0], "spec")
	if sp["validationFailureAction"] != "Enforce" || sp["failurePolicy"] != "Fail" {
		t.Errorf("signature policy must Enforce and fail closed: %v %v", sp["validationFailureAction"], sp["failurePolicy"])
	}
	rules := anyList(sp["rules"])
	if len(rules) != 1 {
		t.Fatalf("Kyverno runs exactly one rule, got %d", len(rules))
	}
	if _, ok := rules[0].(Map)["mutate"]; ok {
		t.Error("Kyverno must not mutate")
	}
	vi := anyList(rules[0].(Map)["verifyImages"])[0].(Map)
	if vi["required"] != true || vi["verifyDigest"] != true || vi["mutateDigest"] != false {
		t.Errorf("verifyImages flags wrong: %v", vi)
	}
	if refs := qstrs(vi["imageReferences"]); len(refs) != 1 || refs[0] != registry+"/*" {
		t.Errorf("imageReferences = %v", refs)
	}
	kl := qsub(anyList(qsub(anyList(vi["attestors"])[0].(Map))["entries"])[0].(Map), "keyless")
	if kl["issuer"] != "https://token.actions.githubusercontent.com" || !strings.Contains(kl["subjectRegExp"].(string), "images\\.yml") {
		t.Errorf("keyless identity is not the images.yml publish workflow: %v", kl)
	}
	res := anyList(qsub(rules[0].(Map), "match")["any"])[0].(Map)["resources"].(Map)
	if qsub(res, "namespaceSelector", "matchLabels")["quorumvault.io/policy"] != "enforced" {
		t.Error("the signature rule must select our labelled namespaces only")
	}
	// off in kind
	kobjs, _ := policies(t, "signing-core", "qvs", "-f", policyDir+"/values-kind.yaml", "--set", "registry=qv-image")
	for _, o := range kobjs {
		if qstr(o, "kind") == "ClusterPolicy" {
			t.Error("kind values must not render the signature policy")
		}
	}
	// key mode
	out, err := helmOut(with("--set", "signature.mode=key", "--set-string", "signature.key.publicKey=-----BEGIN PUBLIC KEY-----\\nabc\\n-----END PUBLIC KEY-----")...)
	if err != nil || !strings.Contains(out, "publicKeys") {
		t.Errorf("key mode did not render: %v\n%s", err, out)
	}
}

func TestRBAC(t *testing.T) {
	check := func(t *testing.T, objs []Map, wantBreakGlassBindings int) {
		bg := 0
		for _, o := range objs {
			switch qstr(o, "kind") {
			case "ClusterRoleBinding":
				t.Errorf("no ClusterRoleBinding may be rendered: %s", qstr(o, "metadata", "name"))
			case "ClusterRole":
				for _, r := range anyList(o["rules"]) {
					rm := r.(Map)
					for _, res := range qstrs(rm["resources"]) {
						if res == "secrets" || res == "*" || strings.HasPrefix(res, "secrets/") {
							t.Errorf("%s grants %s", qstr(o, "metadata", "name"), res)
						}
					}
					for _, vb := range qstrs(rm["verbs"]) {
						if vb == "*" || vb == "impersonate" || vb == "escalate" || vb == "bind" {
							t.Errorf("%s grants verb %s", qstr(o, "metadata", "name"), vb)
						}
					}
					if qstrs(rm["apiGroups"])[0] == "rbac.authorization.k8s.io" {
						t.Errorf("%s touches RBAC", qstr(o, "metadata", "name"))
					}
				}
				if qstr(o, "metadata", "name") == "qv-read-only" {
					for _, r := range anyList(o["rules"]) {
						for _, vb := range qstrs(r.(Map)["verbs"]) {
							if vb != "get" && vb != "list" && vb != "watch" {
								t.Errorf("read-only role has verb %s", vb)
							}
						}
						for _, res := range qstrs(r.(Map)["resources"]) {
							if strings.Contains(res, "exec") || strings.Contains(res, "attach") || strings.Contains(res, "portforward") {
								t.Errorf("read-only role reaches %s", res)
							}
						}
					}
				}
			case "RoleBinding":
				if qstr(o, "metadata", "namespace") == "" {
					t.Errorf("RoleBinding without a namespace")
				}
				if qstr(o, "roleRef", "name") == "qv-break-glass" {
					bg++
				}
			}
		}
		if bg != wantBreakGlassBindings {
			t.Errorf("break-glass bindings = %d, want %d", bg, wantBreakGlassBindings)
		}
	}
	t.Run("default: break-glass bound to nobody", func(t *testing.T) {
		objs, _ := policies(t, "signing-core", "qvs")
		check(t, objs, 0)
	})
	t.Run("with subjects: one RoleBinding per namespace, never cluster-wide", func(t *testing.T) {
		objs, _ := policies(t, "party", "pb", "--set-json", `breakGlass.subjects=[{"apiGroup":"rbac.authorization.k8s.io","kind":"Group","name":"qv:break-glass"}]`)
		check(t, objs, 1)
	})
	t.Run("two namespaces get two bindings", func(t *testing.T) {
		args := with("--set", "namespaces={qvs,qvg}", "--set-json", `breakGlass.subjects=[{"apiGroup":"rbac.authorization.k8s.io","kind":"Group","name":"qv:break-glass"}]`)
		out, err := helmOut(args...)
		if err != nil {
			t.Fatal(out)
		}
		objs, _ := ParseDocs(out)
		check(t, objs, 2)
	})
}
