package helmcheck

import (
	"strings"
	"testing"
)

var approvalOn = []string{"--set", "approval.enabled=true"}

func TestApprovalOffByDefault(t *testing.T) {
	for _, vf := range valuesFiles {
		objs := render(t, vf.file)
		for _, o := range objs {
			if o.Component() == "approval" || strings.Contains(o.Raw, "qv-approval-web") || strings.Contains(o.Raw, "QV_APPROVAL_ORIGINS") {
				t.Errorf("%s: %s/%s renders with approval.enabled=false", vf.file, o.Kind, o.Metadata.Name)
			}
		}
		if m := CheckApproval(objs, 8090); len(m) > 0 {
			t.Errorf("%s: %v", vf.file, m)
		}
	}
}

func TestApprovalOnPassesEveryCheck(t *testing.T) {
	c, err := LoadContract()
	if err != nil {
		t.Fatal(err)
	}
	for _, vf := range valuesFiles {
		t.Run(vf.file, func(t *testing.T) {
			objs := render(t, vf.file, approvalOn...)
			for _, m := range append(CheckPolicy(objs, opts(vf.requireDigest)), CheckMigration(objs, vf.enableLogin)...) {
				t.Error(m)
			}
			for _, m := range CheckContract(objs, c) {
				t.Error(m)
			}
			for _, m := range CheckApproval(objs, 8090) {
				t.Error(m)
			}
			n := 0
			for _, o := range objs {
				if o.Kind == "Deployment" && o.Component() == "approval" {
					n++
					want := "replicas: 2"
					if vf.file == "values-kind.yaml" {
						want = "replicas: 1"
					}
					if !strings.Contains(o.Raw, want) {
						t.Errorf("%s: want %s", vf.file, want)
					}
				}
			}
			if n != 1 {
				t.Errorf("want one approval Deployment, got %d", n)
			}
		})
	}
}

func TestApprovalOriginComesFromOneValue(t *testing.T) {
	objs := render(t, "values.yaml", "--set", "approval.enabled=true", "--set", "approval.ingress.host=pages.qv.example.invalid", "--set", "ingress.public.host=api.qv.example.invalid")
	if m := CheckApproval(objs, 8090); len(m) > 0 {
		t.Fatal(m)
	}
	found := false
	for _, o := range objs {
		if v, ok := o.Data["QV_APPROVAL_ORIGINS"]; ok {
			found = true
			if v != "https://pages.qv.example.invalid" {
				t.Errorf("core origins = %v", v)
			}
		}
		if v, ok := o.Data["QV_APPROVAL_API"]; ok && v != "https://api.qv.example.invalid" {
			t.Errorf("page api = %v", v)
		}
	}
	if !found {
		t.Error("the core has no QV_APPROVAL_ORIGINS")
	}
}

func TestApprovalSameHostRefused(t *testing.T) {
	for name, args := range map[string][]string{
		"the core's public host":    {"--set", "approval.ingress.host=custody.example.invalid"},
		"the same host, other case": {"--set", "approval.ingress.host=Custody.Example.Invalid"},
		"the passthrough host":      {"--set", "ingress.passthrough.enabled=true", "--set", "approval.ingress.host=custody-internal.example.invalid"},
		"no public ingress to call": {"--set", "ingress.public.enabled=false"},
		"an empty host":             {"--set", "approval.ingress.host="},
	} {
		_, err := Render("values.yaml", append(append([]string{}, approvalOn...), args...)...)
		if err == nil {
			t.Errorf("%s: the render must fail", name)
		}
	}
}

// Each case breaks the rendered approval page in one way and wants that violation.
func TestApprovalCatches(t *testing.T) {
	text, err := Render("values.yaml", approvalOn...)
	if err != nil {
		t.Skip(err)
	}
	cases := []struct{ name, from, to, want string }{
		{"origins differ", `QV_APPROVAL_ORIGINS: "https://approval.example.invalid"`, `QV_APPROVAL_ORIGINS: "https://other.example.invalid"`, "must be the same value"},
		{"origins forgotten", `QV_APPROVAL_ORIGINS: "https://approval.example.invalid"`, `QV_UNRELATED: "1"`, "must be the same value"},
		{"page on the core's host", `- host: "approval.example.invalid"`, `- host: "custody.example.invalid"`, "different origin"},
		{"page calls another api", `QV_APPROVAL_API: "https://custody.example.invalid"`, `QV_APPROVAL_API: "https://elsewhere.example.invalid"`, "not the core's public origin"},
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
			if !anyContains(CheckApproval(objs, 8090), tc.want) {
				t.Errorf("no violation containing %q; got %v", tc.want, CheckApproval(objs, 8090))
			}
		})
	}
	// network: append policies that a careless edit could add
	extra := map[string]string{
		"egress to anywhere": `---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: bad-egress }
spec:
  podSelector: { matchLabels: { app.kubernetes.io/component: approval } }
  policyTypes: [Egress]
  egress: [{ to: [{ ipBlock: { cidr: 0.0.0.0/0 } }] }]
`,
		"egress through the DNS rule": `---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: bad-dns }
spec:
  podSelector: { matchLabels: { app.kubernetes.io/instance: qv } }
  policyTypes: [Egress]
  egress: [{ ports: [{ port: 53, protocol: UDP }] }]
`,
		"every pod of the namespace may reach it": `---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: bad-ingress }
spec:
  podSelector: { matchLabels: { app.kubernetes.io/component: approval } }
  policyTypes: [Ingress]
  ingress: [{ from: [{ podSelector: {} }], ports: [{ port: 8090, protocol: TCP }] }]
`,
		"another port": `---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: bad-port }
spec:
  podSelector: { matchLabels: { app.kubernetes.io/component: approval } }
  policyTypes: [Ingress]
  ingress: [{ from: [{ namespaceSelector: {} }], ports: [{ port: 22, protocol: TCP }] }]
`,
	}
	want := map[string]string{
		"egress to anywhere": "open connections", "egress through the DNS rule": "open connections",
		"every pod of the namespace may reach it": "something other than the ingress controller", "another port": "opens port 22",
	}
	for name, doc := range extra {
		t.Run(name, func(t *testing.T) {
			objs, err := Parse(text + doc)
			if err != nil {
				t.Fatal(err)
			}
			if !anyContains(CheckApproval(objs, 8090), want[name]) {
				t.Errorf("no violation containing %q; got %v", want[name], CheckApproval(objs, 8090))
			}
		})
	}
	// the chart's own DNS rule must not select the approval pods (this is the check above, on the real render)
	objs, _ := Parse(text)
	for _, o := range objs {
		if o.Kind == "NetworkPolicy" && strings.HasSuffix(o.Metadata.Name, "allow-dns") && !strings.Contains(o.Raw, "NotIn") {
			t.Error("the DNS policy does not exclude the approval page")
		}
	}
	// and without the chart's ingress rule nobody may reach it, which the check also wants stated
	noIngress := strings.Replace(text, "quorumvault.io/ingress-purpose: ingress-controller\nspec:\n  podSelector:\n    matchLabels:\n      app.kubernetes.io/name: qv\n      app.kubernetes.io/instance: qv\n      app.kubernetes.io/component: approval", "x: y\nspec:\n  podSelector:\n    matchLabels:\n      app.kubernetes.io/name: qv\n      app.kubernetes.io/instance: qv\n      app.kubernetes.io/component: approval", 1)
	if noIngress != text {
		o2, _ := Parse(noIngress)
		if !anyContains(CheckApproval(o2, 8090), "no NetworkPolicy admits the ingress controller") {
			t.Error("a missing ingress rule was not caught")
		}
	}
	// the policy check: the ingress controller may reach the approval port only
	bad := strings.Replace(text, "ports: [{ port: 8090, protocol: TCP }]", "ports: [{ port: 8443, protocol: TCP }]", 1)
	o3, _ := Parse(bad)
	if !anyContains(CheckPolicy(o3, opts(true)), "ingress from outside on port 8443 (only port 8090)") {
		t.Errorf("an ingress-controller rule on another port was not caught: %v", CheckPolicy(o3, opts(true)))
	}
}

func TestApprovalContractCatches(t *testing.T) {
	c, err := LoadContract()
	if err != nil {
		t.Fatal(err)
	}
	text, err := Render("values.yaml", approvalOn...)
	if err != nil {
		t.Skip(err)
	}
	cases := []struct{ name, from, to, want string }{
		{"wrong port", `QV_APPROVAL_LISTEN: "0.0.0.0:8090"`, `QV_APPROVAL_LISTEN: "0.0.0.0:9000"`, "does not match containerPort"},
		{"unknown env", `QV_APPROVAL_DIR: /srv/approval`, `QV_APPROVAL_DIR: /srv/approval` + "\n  QV_SURPRISE: \"1\"", "QV_SURPRISE is not in the contract"},
		{"no issuer", `QV_OIDC_ISSUER: "https://idp.example.invalid/realms/qv"` + "\n  QV_APPROVAL_CLIENT_ID", "QV_UNUSED: \"x\"\n  QV_APPROVAL_CLIENT_ID", "none of [issuer QV_OIDC_ISSUER] is set"},
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
