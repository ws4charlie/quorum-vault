package qvpolicy

// Tests for deploy/policy/qv-policy without a cluster: the rendered policies are evaluated against (a) the real production renders of the four application
// charts, which must pass every rule, and (b) one manifest per rule that must be denied, with the reason checked. A last check fails if a rule has no denied example.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const (
	root      = "../../.."
	policyDir = root + "/deploy/policy/qv-policy"
	registry  = "ghcr.io/ws4charlie/quorum-vault"
	writer    = "system:serviceaccount:flux-system:kustomize-controller"
	breakGl   = "qv:break-glass"
)

var enforced = map[string]string{"quorumvault.io/policy": "enforced"}

// render runs helm template for one of our charts and returns objects.
func render(t testing.TB, chart, ns string, args ...string) []Map {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not on PATH (CI installs it)")
	}
	objs, err := HelmTemplate(chart, "qv", ns, args...)
	if err != nil {
		t.Fatal(err)
	}
	return objs
}

func policies(t testing.TB, kind, ns string, extra ...string) ([]Map, *PolicySet) {
	t.Helper()
	args := append([]string{"--set", "clusterKind=" + kind, "--set", "namespaces={" + ns + "}", "--set", "registry=" + registry, "--set", "configWriters.users={" + writer + "}"}, extra...)
	objs := render(t, policyDir, "kube-system", args...)
	ps, err := LoadPolicies(objs)
	if err != nil {
		t.Fatal(err)
	}
	return objs, ps
}

// workload inputs: the same values the chart check scripts use (ci/helm/*-check.sh).
type input struct {
	name, chart, ns string
	args            []string
}

func inputs(kind bool) (business, signing, partyA, partyB, partyC input) {
	c := func(n string) string { return root + "/deploy/helm/" + n }
	ci := root + "/ci/helm/"
	if !kind {
		business = input{"qv-business", c("qv-business"), "qv", []string{"-f", c("qv-business") + "/values.yaml", "-f", ci + "ci-digests.yaml", "--set", "approval.enabled=true"}}
		signing = input{"qv-signing-core", c("qv-signing-core"), "qvs", []string{"-f", ci + "signing-core-ci.yaml"}}
		pv := func(role string) []string {
			return []string{"--set", "role=" + role, "-f", c("qv-party") + "/values.yaml", "-f", ci + "ci-party-values.yaml", "-f", ci + "ci-party-digests.yaml"}
		}
		partyA = input{"qv-party A", c("qv-party"), "qvs", pv("A")}
		partyB = input{"qv-party B", c("qv-party"), "qv", pv("B")}
		partyC = input{"qv-party C", c("qv-party"), "qv", pv("C")}
		return
	}
	business = input{"qv-business kind", c("qv-business"), "qv", []string{"-f", c("qv-business") + "/values-kind.yaml"}}
	signing = input{"qv-signing-core kind", c("qv-signing-core"), "qvs", []string{"-f", ci + "signing-core-ci.yaml", "-f", c("qv-signing-core") + "/values-kind.yaml"}}
	pv := func(role string) []string {
		return []string{"--set", "role=" + role, "-f", c("qv-party") + "/values.yaml", "-f", ci + "ci-party-values.yaml", "-f", c("qv-party") + "/values-kind.yaml"}
	}
	partyA = input{"qv-party A kind", c("qv-party"), "qvs", pv("A")}
	partyB = input{"qv-party B kind", c("qv-party"), "qv", pv("B")}
	partyC = input{"qv-party C kind", c("qv-party"), "qv", pv("C")}
	return
}

// admitAll applies the policies to everything an application chart renders: its pods (made from the pod templates), Services, Ingresses and ConfigMaps. It
// returns the denials and the number of pods checked. Pod Security restricted is evaluated on every pod too (the namespace labels say so).
func admitAll(t testing.TB, ps *PolicySet, in input, psaVersion string) (denials []string, pods int) {
	t.Helper()
	objs := render(t, in.chart, in.ns, in.args...)
	for _, o := range objs {
		kind := qstr(o, "kind")
		name := qstr(o, "metadata", "name")
		var reqs []Request
		if pod := PodFromWorkload(o, in.ns, objs); pod != nil {
			pods++
			if v, err := PSAViolations(pod, psaVersion); err != nil {
				t.Fatal(err)
			} else {
				for _, m := range v {
					denials = append(denials, fmt.Sprintf("%s/%s: Pod Security restricted: %s", kind, name, m))
				}
			}
			reqs = append(reqs, Request{Group: "", Resource: "pods", Operation: "CREATE", Object: pod, Namespace: in.ns})
		}
		switch kind {
		case "Service":
			reqs = append(reqs, Request{Resource: "services", Operation: "CREATE", Object: o, Namespace: in.ns})
		case "Ingress":
			reqs = append(reqs, Request{Group: "networking.k8s.io", Resource: "ingresses", Operation: "CREATE", Object: o, Namespace: in.ns})
		case "ConfigMap":
			reqs = append(reqs, Request{Resource: "configmaps", Operation: "CREATE", Object: o, Namespace: in.ns, Name: name, User: writer})
		}
		for _, q := range reqs {
			ds, err := ps.Admit(q, enforced)
			if err != nil {
				t.Fatal(err)
			}
			for _, d := range ds {
				denials = append(denials, fmt.Sprintf("%s/%s: %s", kind, name, d))
			}
		}
	}
	return
}

// Every application chart, rendered with production values, passes every rule of its cluster kind.
func TestProductionRendersPass(t *testing.T) {
	biz, sc, pa, pb, pc := inputs(false)
	cases := []struct {
		kind, ns string
		charts   []input
		minPods  int
	}{
		{"business", "qv", []input{biz}, 6},
		{"signing-core", "qvs", []input{sc, pa}, 2},
		{"party", "qv", []input{pb}, 1},
		{"party", "qv", []input{pc}, 1},
	}
	for _, c := range cases {
		for _, in := range c.charts {
			t.Run(c.kind+"/"+in.name, func(t *testing.T) {
				_, ps := policies(t, c.kind, c.ns)
				d, n := admitAll(t, ps, in, "v1.31")
				for _, x := range d {
					t.Errorf("denied: %s", x)
				}
				if n < 1 {
					t.Errorf("no pod found in the render: the test would pass on nothing")
				}
			})
		}
	}
}

// A party Service of type LoadBalancer is admitted with the private-endpoint annotation the chart sets.
func TestPartyPrivateLoadBalancerPasses(t *testing.T) {
	_, _, _, pb, _ := inputs(false)
	args := append(append([]string{}, pb.args...), "--set", "service.caller.type=LoadBalancer", "--set", "service.peer.type=LoadBalancer",
		"--set", "service.caller.sourceRanges={10.0.0.0/8}", "--set", "service.peer.sourceRanges={10.0.0.0/8}",
		"--set-json", `service.caller.annotations={"service.beta.kubernetes.io/aws-load-balancer-scheme":"internal","service.beta.kubernetes.io/aws-load-balancer-type":"external"}`,
		"--set-json", `service.peer.annotations={"service.beta.kubernetes.io/aws-load-balancer-scheme":"internal","service.beta.kubernetes.io/aws-load-balancer-type":"external"}`)
	pb.args = args
	_, ps := policies(t, "party", "qv")
	d, _ := admitAll(t, ps, pb, "v1.31")
	for _, x := range d {
		t.Errorf("denied: %s", x)
	}
	lb := 0
	for _, o := range render(t, pb.chart, pb.ns, pb.args...) {
		if qstr(o, "kind") == "Service" && qstr(o, "spec", "type") == "LoadBalancer" {
			lb++
		}
	}
	if lb != 2 {
		t.Fatalf("expected two LoadBalancer Services in the render, got %d", lb)
	}
}

// The kind renders pass the kind policy set (same rules, kind's relaxations only), and the production policy set refuses them for the right reasons.
func TestKindRenders(t *testing.T) {
	biz, sc, pa, pb, pc := inputs(true)
	for _, c := range []struct {
		kind, ns string
		in       input
	}{{"business", "qv", biz}, {"signing-core", "qvs", sc}, {"signing-core", "qvs", pa}, {"party", "qv", pb}, {"party", "qv", pc}} {
		t.Run(c.in.name, func(t *testing.T) {
			_, kps := policies(t, c.kind, c.ns, "-f", policyDir+"/values-kind.yaml", "--set", "registry=qv-image")
			d, n := admitAll(t, kps, c.in, "v1.31")
			for _, x := range d {
				t.Errorf("kind policy denied: %s", x)
			}
			if n < 1 {
				t.Fatal("no pod")
			}
		})
	}
	// production policies against kind output: SoftHSM, -dev images, tags, QV_ENV=dev must be refused
	_, pps := policies(t, "signing-core", "qvs")
	d, _ := admitAll(t, pps, sc, "v1.31")
	all := strings.Join(d, "\n")
	for _, want := range []string{"development switches", "images must be referenced by digest"} {
		if !strings.Contains(all, want) {
			t.Errorf("the production policies did not refuse the kind signing-core render for %q; denials:\n%s", want, all)
		}
	}
	_, ppps := policies(t, "party", "qv")
	d, _ = admitAll(t, ppps, pb, "v1.31")
	all = strings.Join(d, "\n")
	for _, want := range []string{"a development image (-dev)", "development switches", "images must be referenced by digest"} {
		if !strings.Contains(all, want) {
			t.Errorf("the production policies did not refuse the kind party render for %q; denials:\n%s", want, all)
		}
	}
}

// ---- denied examples -------------------------------------------------------------------------------------------------------------------------------

func cont(spec Map, i int) Map { return spec["containers"].([]any)[i].(Map) }
func scOf(c Map) Map {
	s, _ := c["securityContext"].(Map)
	if s == nil {
		s = Map{}
		c["securityContext"] = s
	}
	return s
}
func volumes(spec Map, v Map) { spec["volumes"] = append(spec["volumes"].([]any), v) }

func pod(t testing.TB, in input, kind string) Map {
	t.Helper()
	objs := render(t, in.chart, in.ns, in.args...)
	for _, o := range objs {
		if qstr(o, "kind") == kind {
			return PodFromWorkload(o, in.ns, objs)
		}
	}
	t.Fatalf("no %s in %s", kind, in.name)
	return nil
}

const (
	awsScheme = "service.beta.kubernetes.io/aws-load-balancer-scheme"
	awsType   = "service.beta.kubernetes.io/aws-load-balancer-type"
)

func TestDeniedExamples(t *testing.T) {
	_, sc, _, _, _ := inputs(false)
	_, ps := policies(t, "signing-core", "qvs")
	good := pod(t, sc, "Deployment")
	covered := map[string]bool{}

	admit := func(t *testing.T, q Request) []Denial {
		t.Helper()
		if q.Namespace == "" {
			q.Namespace = "qvs"
		}
		ds, err := ps.Admit(q, enforced)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range ds {
			covered[d.String()] = true
		}
		return ds
	}
	wantDenied := func(t *testing.T, q Request, msg string) {
		t.Helper()
		ds := admit(t, q)
		for _, d := range ds {
			if strings.Contains(d.Message, msg) {
				return
			}
		}
		t.Errorf("not denied for %q; denials: %v", msg, ds)
	}
	wantAdmitted := func(t *testing.T, q Request) {
		t.Helper()
		if ds := admit(t, q); len(ds) != 0 {
			t.Errorf("denied: %v", ds)
		}
	}
	podReq := func(p Map) Request { return Request{Resource: "pods", Operation: "CREATE", Object: p} }

	t.Run("baseline gateway pod is admitted", func(t *testing.T) { wantAdmitted(t, podReq(good)) })

	mutate := func(f func(spec Map)) Map {
		p := DeepCopy(good).(Map)
		f(p["spec"].(Map))
		return p
	}
	podCases := []struct {
		name string
		f    func(spec Map)
		msg  string
	}{
		{"hostNetwork", func(s Map) { s["hostNetwork"] = true }, "hostNetwork, hostPID and hostIPC"},
		{"hostPID", func(s Map) { s["hostPID"] = true }, "hostNetwork, hostPID and hostIPC"},
		{"hostIPC", func(s Map) { s["hostIPC"] = true }, "hostNetwork, hostPID and hostIPC"},
		{"hostPath", func(s Map) { volumes(s, Map{"name": "h", "hostPath": Map{"path": "/"}}) }, "hostPath volumes"},
		{"privileged", func(s Map) { scOf(cont(s, 0))["privileged"] = true }, "privileged containers"},
		{"added capability", func(s Map) { scOf(cont(s, 0))["capabilities"] = Map{"drop": []any{"ALL"}, "add": []any{"NET_ADMIN"}} }, "added Linux capabilities"},
		{"root user", func(s Map) { scOf(cont(s, 0))["runAsUser"] = 0 }, "non-root"},
		{"runAsNonRoot false", func(s Map) { scOf(cont(s, 0))["runAsNonRoot"] = false }, "non-root"},
		{"runAsNonRoot unset", func(s Map) {
			delete(scOf(cont(s, 0)), "runAsNonRoot")
			delete(s["securityContext"].(Map), "runAsNonRoot")
		}, "non-root"},
		{"pod runAsUser 0", func(s Map) {
			delete(scOf(cont(s, 0)), "runAsUser")
			s["securityContext"].(Map)["runAsUser"] = 0
		}, "non-root"},
		{"privilege escalation", func(s Map) { scOf(cont(s, 0))["allowPrivilegeEscalation"] = true }, "allowPrivilegeEscalation"},
		{"foreign registry", func(s Map) { cont(s, 0)["image"] = "docker.io/evil/gateway@sha256:" + strings.Repeat("a", 64) }, "images must come from " + registry},
		{"registry prefix trick", func(s Map) { cont(s, 0)["image"] = registry + ".evil.io/gateway@sha256:" + strings.Repeat("a", 64) }, "images must come from " + registry},
		{"tag instead of digest", func(s Map) { cont(s, 0)["image"] = registry + "/qv-gateway:latest" }, "by digest"},
		{"dev image", func(s Map) { cont(s, 0)["image"] = registry + "/qv-gateway-dev@sha256:" + strings.Repeat("a", 64) }, "development image"},
		{"QV_ENV dev", func(s Map) { cont(s, 0)["env"] = []any{Map{"name": "QV_ENV", "value": "dev"}} }, "development switches"},
		{"QV_ENV test", func(s Map) { cont(s, 0)["env"] = []any{Map{"name": "QV_ENV", "value": "test"}} }, "development switches"},
		{"SOFTHSM2_CONF", func(s Map) { cont(s, 0)["env"] = []any{Map{"name": "SOFTHSM2_CONF", "value": "/x"}} }, "development switches"},
		{"SoftHSM module path", func(s Map) {
			cont(s, 0)["env"] = []any{Map{"name": "QV_PKCS11_LIB", "value": "/usr/lib/softhsm/libsofthsm2.so"}}
		}, "development switches"},
		{"QV_ALLOW_PLAINTEXT", func(s Map) { cont(s, 0)["env"] = []any{Map{"name": "QV_ALLOW_PLAINTEXT", "value": "1"}} }, "development switches"},
		{"QV_ENV mixed-case dev", func(s Map) { cont(s, 0)["env"] = []any{Map{"name": "QV_ENV", "value": " Dev "}} }, "development switches"},
		{"QV_ENV TEST upper-case", func(s Map) { cont(s, 0)["env"] = []any{Map{"name": "QV_ENV", "value": "TEST"}} }, "development switches"},
		{"QV_ENV unknown spelling", func(s Map) { cont(s, 0)["env"] = []any{Map{"name": "QV_ENV", "value": "develop"}} }, "development switches"},
		{"QV_ENV from a Secret", func(s Map) {
			cont(s, 0)["env"] = []any{Map{"name": "QV_ENV", "valueFrom": Map{"secretKeyRef": Map{"name": "s", "key": "k"}}}}
		}, "development switches"},
		{"QV_PKCS11_LIB from a ConfigMap", func(s Map) {
			cont(s, 0)["env"] = []any{Map{"name": "QV_PKCS11_LIB", "valueFrom": Map{"configMapKeyRef": Map{"name": "x-0123456789", "key": "k"}}}}
		}, "development switches"},
		{"QV_DEV_ACTOR_HEADER", func(s Map) { cont(s, 0)["env"] = []any{Map{"name": "QV_DEV_ACTOR_HEADER", "value": "1"}} }, "development switches"},
		{"QV_OIDC_TEST_JWKS", func(s Map) { cont(s, 0)["env"] = []any{Map{"name": "QV_OIDC_TEST_JWKS", "value": "/x"}} }, "development switches"},
		{"QV_FAILPOINT", func(s Map) { cont(s, 0)["env"] = []any{Map{"name": "QV_FAILPOINT", "value": "a.b"}} }, "development switches"},
		{"envFrom a Secret", func(s Map) { cont(s, 0)["envFrom"] = []any{Map{"secretRef": Map{"name": "s"}}} }, "envFrom may only name"},
		{"envFrom with a prefix", func(s Map) {
			cont(s, 0)["envFrom"] = []any{Map{"prefix": "QV_", "configMapRef": Map{"name": "gateway-env-0123456789"}}}
		}, "envFrom may only name"},
		{"envFrom a ConfigMap off the allowlist", func(s Map) {
			cont(s, 0)["envFrom"] = []any{Map{"configMapRef": Map{"name": "evil-0123456789"}}}
		}, "envFrom may only name"},
		{"dev flag in args", func(s Map) { cont(s, 0)["args"] = []any{"-dev-actor-header"} }, "development flag"},
		{"dev flag with value in command", func(s Map) { cont(s, 0)["command"] = []any{"/qv-core", "--oidc-test-jwks=/x"} }, "development flag"},
		{"mutable ConfigMap volume", func(s Map) { volumes(s, Map{"name": "m", "configMap": Map{"name": "gateway-config"}}) }, "ConfigMaps whose name ends in a 10-character content hash"},
		{"mutable ConfigMap envFrom", func(s Map) { cont(s, 0)["envFrom"] = []any{Map{"configMapRef": Map{"name": "gateway-env"}}} }, "ConfigMaps whose name ends in a 10-character content hash"},
		{"mutable ConfigMap key ref", func(s Map) {
			cont(s, 0)["env"] = []any{Map{"name": "X", "valueFrom": Map{"configMapKeyRef": Map{"name": "gateway-env", "key": "k"}}}}
		}, "ConfigMaps whose name ends in a 10-character content hash"},
		{"token mounted (automount true)", func(s Map) { s["automountServiceAccountToken"] = true }, "no ServiceAccount token"},
		{"token mounted (automount unset)", func(s Map) { delete(s, "automountServiceAccountToken") }, "no ServiceAccount token"},
		{"projected token volume", func(s Map) {
			volumes(s, Map{"name": "tok", "projected": Map{"sources": []any{Map{"serviceAccountToken": Map{"path": "t"}}}}})
		}, "no ServiceAccount token"},
		{"init container too", func(s Map) {
			s["initContainers"] = []any{Map{"name": "i", "image": "docker.io/x/y@sha256:" + strings.Repeat("a", 64), "securityContext": Map{"runAsNonRoot": true, "allowPrivilegeEscalation": false}}}
		}, "images must come from"},
	}
	for _, c := range podCases {
		t.Run("pod/"+c.name, func(t *testing.T) { wantDenied(t, podReq(mutate(c.f)), c.msg) })
	}
	t.Run("pod/ephemeral debug container without securityContext", func(t *testing.T) {
		p := mutate(func(s Map) {
			s["ephemeralContainers"] = []any{Map{"name": "debug", "image": "busybox:1.36"}}
		})
		q := Request{Resource: "pods", Subresource: "ephemeralcontainers", Operation: "UPDATE", Object: p}
		wantDenied(t, q, "images must come from")
		wantDenied(t, q, "allowPrivilegeEscalation")
	})
	t.Run("pod/token allowed for a listed ServiceAccount", func(t *testing.T) {
		_, ps2 := policies(t, "signing-core", "qvs", "--set", "serviceAccountTokenAllowed={reader}")
		p := mutate(func(s Map) { s["automountServiceAccountToken"] = true; s["serviceAccountName"] = "reader" })
		if ds, _ := ps2.Admit(podReq(p), enforced); len(ds) != 0 {
			t.Errorf("a listed ServiceAccount must be admitted: %v", ds)
		}
	})
	t.Run("pod/outside our namespaces nothing applies", func(t *testing.T) {
		p := mutate(func(s Map) { s["hostNetwork"] = true })
		if ds, _ := ps.Admit(podReq(p), map[string]string{}); len(ds) != 0 {
			t.Errorf("an unlabelled namespace must not be governed: %v", ds)
		}
	})

	// Services
	svc := func(typ string, ann Map, extra Map) Request {
		o := Map{"apiVersion": "v1", "kind": "Service", "metadata": Map{"name": "s"}, "spec": Map{"type": typ}}
		if ann != nil {
			o["metadata"].(Map)["annotations"] = ann
		}
		for k, v := range extra {
			o["spec"].(Map)[k] = v
		}
		return Request{Resource: "services", Operation: "CREATE", Object: o}
	}
	t.Run("service/NodePort", func(t *testing.T) { wantDenied(t, svc("NodePort", nil, nil), "NodePort") })
	t.Run("service/LoadBalancer without annotation", func(t *testing.T) { wantDenied(t, svc("LoadBalancer", nil, nil), "private") })
	t.Run("service/LoadBalancer public annotation", func(t *testing.T) {
		wantDenied(t, svc("LoadBalancer", Map{"quorumvault.io/endpoint": "public"}, nil), "private")
	})
	t.Run("service/LoadBalancer only our own annotation is not internal", func(t *testing.T) {
		wantDenied(t, svc("LoadBalancer", Map{"quorumvault.io/endpoint": "private"}, nil), "internal-load-balancer annotations")
	})
	t.Run("service/LoadBalancer scheme internal without type external (in-tree provider ignores it)", func(t *testing.T) {
		wantDenied(t, svc("LoadBalancer", Map{"quorumvault.io/endpoint": "private", awsScheme: "internal"}, nil), "internal-load-balancer annotations")
	})
	t.Run("service/LoadBalancer scheme internet-facing", func(t *testing.T) {
		wantDenied(t, svc("LoadBalancer", Map{"quorumvault.io/endpoint": "private", awsScheme: "internet-facing", awsType: "external"}, nil), "internal-load-balancer annotations")
	})
	t.Run("service/LoadBalancer internal but not marked private", func(t *testing.T) {
		wantDenied(t, svc("LoadBalancer", Map{awsScheme: "internal", awsType: "external"}, nil), "internal-load-balancer annotations")
	})
	t.Run("service/LoadBalancer internal", func(t *testing.T) {
		wantAdmitted(t, svc("LoadBalancer", Map{"quorumvault.io/endpoint": "private", awsScheme: "internal", awsType: "external"}, nil))
	})
	t.Run("service/LoadBalancer refused when no cloud annotations are configured", func(t *testing.T) {
		_, nps := policies(t, "signing-core", "qvs", "--set-json", "loadBalancer.internalAnnotations=[]")
		ds, _ := nps.Admit(svc("LoadBalancer", Map{"quorumvault.io/endpoint": "private", awsScheme: "internal", awsType: "external"}, nil), enforced)
		if len(ds) == 0 {
			t.Errorf("with loadBalancer.internalAnnotations empty every LoadBalancer must be refused")
		}
	})
	t.Run("service/ClusterIP", func(t *testing.T) { wantAdmitted(t, svc("ClusterIP", nil, nil)) })
	t.Run("service/externalIPs", func(t *testing.T) {
		wantDenied(t, svc("ClusterIP", nil, Map{"externalIPs": []any{"1.2.3.4"}}), "externalIPs")
	})

	// Ingress: refused in a signing cluster, admitted in the business cluster
	ing := Request{Group: "networking.k8s.io", Resource: "ingresses", Operation: "CREATE", Object: Map{"kind": "Ingress", "metadata": Map{"name": "i"}}}
	t.Run("ingress/signing cluster", func(t *testing.T) { wantDenied(t, ing, "no Ingress") })
	for _, r := range []string{"gateways", "gatewayclasses", "httproutes", "grpcroutes", "tcproutes", "tlsroutes", "udproutes", "backendtlspolicies", "referencegrants"} {
		t.Run("ingress/gateway api "+r, func(t *testing.T) {
			wantDenied(t, Request{Group: "gateway.networking.k8s.io", Resource: r, Operation: "CREATE", Object: Map{"metadata": Map{"name": "i"}}}, "no Ingress")
		})
	}
	t.Run("ingress/business cluster", func(t *testing.T) {
		_, bps := policies(t, "business", "qv")
		if ds, _ := bps.Admit(ing, enforced); len(ds) != 0 {
			t.Errorf("the business cluster takes an Ingress: %v", ds)
		}
		for _, p := range bps.Policies {
			if p.Name == "qv-no-ingress" || p.Name == "qv-no-exec" {
				t.Errorf("the business cluster must not carry %s", p.Name)
			}
		}
	})

	// ConfigMaps
	cm := func(name string, immutable bool, data Map, op, user string, groups ...string) Request {
		o := Map{"apiVersion": "v1", "kind": "ConfigMap", "metadata": Map{"name": name}, "data": data}
		if immutable {
			o["immutable"] = true
		}
		return Request{Resource: "configmaps", Operation: op, Name: name, Object: o, OldObject: o, User: user, Groups: groups}
	}
	t.Run("configmap/not immutable", func(t *testing.T) {
		wantDenied(t, cm("x-0123456789", false, Map{"a": "b"}, "CREATE", writer), "must be immutable")
	})
	t.Run("configmap/immutable by the writer", func(t *testing.T) {
		wantAdmitted(t, cm("x-0123456789", true, Map{"a": "b"}, "CREATE", writer))
	})
	t.Run("configmap/QV_ENV dev", func(t *testing.T) {
		wantDenied(t, cm("x-0123456789", true, Map{"QV_ENV": "dev"}, "CREATE", writer), "development switches")
	})
	t.Run("configmap/SoftHSM module path in a config", func(t *testing.T) {
		wantDenied(t, cm("x-0123456789", true, Map{"party.json": `{"pkcs11":{"module":"/usr/lib/softhsm/libsofthsm2.so"}}`}, "CREATE", writer), "development switches")
	})
	t.Run("configmap/QV_ENV spelled Dev with spaces", func(t *testing.T) {
		wantDenied(t, cm("x-0123456789", true, Map{"QV_ENV": " DEV\n"}, "CREATE", writer), "development switches")
	})
	t.Run("configmap/QV_ENV unknown spelling", func(t *testing.T) {
		wantDenied(t, cm("x-0123456789", true, Map{"QV_ENV": "staging"}, "CREATE", writer), "development switches")
	})
	t.Run("configmap/QV_ENV production spellings admitted", func(t *testing.T) {
		for _, v := range []string{"", "production", " Production ", "PROD"} {
			wantAdmitted(t, cm("x-0123456789", true, Map{"QV_ENV": v}, "CREATE", writer))
		}
	})
	t.Run("configmap/QV_FAILPOINT key", func(t *testing.T) {
		wantDenied(t, cm("x-0123456789", true, Map{"QV_FAILPOINT": "a.b"}, "CREATE", writer), "development switches")
	})
	t.Run("pod/QV_ENV production spellings admitted", func(t *testing.T) {
		for _, v := range []string{"", "Production", " prod "} {
			wantAdmitted(t, podReq(mutate(func(s Map) { cont(s, 0)["env"] = []any{Map{"name": "QV_ENV", "value": v}} })))
		}
	})
	t.Run("configmap/dev switch key", func(t *testing.T) {
		wantDenied(t, cm("x-0123456789", true, Map{"QV_OIDC_TEST_JWKS": "{}"}, "CREATE", writer), "development switches")
	})
	for _, op := range []string{"CREATE", "UPDATE", "DELETE"} {
		t.Run("configmap/"+op+" by an administrator who is not the GitOps identity", func(t *testing.T) {
			wantDenied(t, cm("x-0123456789", true, Map{"a": "b"}, op, "alice", "system:masters"), "GitOps identity")
		})
	}
	t.Run("configmap/the control plane's root CA ConfigMap is exempt", func(t *testing.T) {
		wantAdmitted(t, cm("kube-root-ca.crt", false, Map{"ca.crt": "x"}, "UPDATE", "system:serviceaccount:kube-system:root-ca-cert-publisher"))
	})
	t.Run("configmap/writer group", func(t *testing.T) {
		_, gps := policies(t, "signing-core", "qvs", "--set", "configWriters.groups={gitops}")
		if ds, _ := gps.Admit(cm("x-0123456789", true, Map{"a": "b"}, "DELETE", "bob", "gitops"), enforced); len(ds) != 0 {
			t.Errorf("a member of a writer group must be admitted: %v", ds)
		}
	})

	// exec, attach, port-forward, debug containers
	for _, c := range []struct{ res, sub, op string }{{"pods", "exec", "CONNECT"}, {"pods", "attach", "CONNECT"}, {"pods", "portforward", "CONNECT"}, {"pods", "ephemeralcontainers", "UPDATE"}} {
		obj := Map{"kind": "PodExecOptions"}
		if c.sub == "ephemeralcontainers" {
			obj = good // the object of that subresource is the Pod
		}
		q := Request{Resource: c.res, Subresource: c.sub, Operation: c.op, Name: "qv-gateway-0", Object: obj, User: "alice", Groups: []string{"qv:readers", "system:authenticated"}}
		t.Run("exec/"+c.sub+" denied for others", func(t *testing.T) { wantDenied(t, q, "break-glass group only") })
		t.Run("exec/"+c.sub+" denied for system:masters", func(t *testing.T) {
			q2 := q
			q2.Groups = []string{"system:masters"}
			wantDenied(t, q2, "break-glass group only")
		})
		t.Run("exec/"+c.sub+" admitted for the break-glass group", func(t *testing.T) {
			q2 := q
			q2.Groups = []string{breakGl}
			if c.sub == "ephemeralcontainers" { // the new debug container must itself satisfy the pod rules
				return
			}
			wantAdmitted(t, q2)
		})
	}

	// Every validation of the signing-core production set has at least one denied example above.
	t.Cleanup(func() {
		var missing []string
		for _, p := range ps.Policies {
			for _, v := range p.Validations {
				if v.Expr == "" {
					continue
				}
				if !covered[p.Name+": "+v.Message] {
					missing = append(missing, p.Name+": "+v.Message)
				}
			}
		}
		sort.Strings(missing)
		if len(missing) > 0 && !t.Failed() {
			t.Errorf("rules without a denied example:\n  %s", strings.Join(missing, "\n  "))
		}
	})
}

// Every optional object our charts can render is checked too: the certificate chart's trust bundles (all cluster kinds), the signing-core chart's signed-setting
// Job, and the party chart's backup Job. A rule that rejects what our own charts or documented procedures need would break an install; a chart that breaks a rule
// is a hole. Both are caught here.
func TestOptionalObjectsPass(t *testing.T) {
	_, sc, pa, pb, _ := inputs(false)
	pemFile := filepath.Join(t.TempDir(), "ca.pem") // a placeholder certificate text: the chart only checks the PEM frame, nothing here is a secret
	if err := os.WriteFile(pemFile, []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	certs := func(cluster string) input {
		return input{"qv-certs " + cluster, root + "/deploy/helm/qv-certs", "qv", []string{"-f", root + "/deploy/helm/qv-certs/values.yaml", "-f", root + "/ci/helm/certs-ci-values.yaml",
			"--set", "cluster=" + cluster, "--set-file", "trust.business=" + pemFile, "--set-file", "trust.signing=" + pemFile}}
	}
	job := sc
	job.name = "qv-signing-core with the signed-setting Job"
	job.args = append(append([]string{}, sc.args...), "--set", "signedSettings.job.enabled=true", "--set", "signedSettings.job.configMap=qv-signed-route-7-0123456789",
		"--set", "signedSettings.job.revision=7", "--set", "signedSettings.job.files={route-1.json}")
	backup := func(in input, name string) input {
		in.name = name
		in.args = append(append([]string{}, in.args...), "--set", "backup.job.enabled=true", "--set", "backup.job.keysetId=ks-1", "--set", "backup.job.outputFile=ks-1.backup",
			"--set", "backup.job.recoveryPublicConfigMap=recovery-public-0123456789")
		return in
	}
	cases := []struct {
		kind, ns string
		in       input
		minPods  int
		must     string // an object kind the render must contain, so a case cannot pass on nothing
	}{
		{"business", "qv", certs("business"), 0, "ConfigMap"},
		{"signing-core", "qv", certs("signing-core"), 0, "ConfigMap"},
		{"party", "qv", certs("party-b"), 0, "ConfigMap"},
		{"party", "qv", certs("party-c"), 0, "ConfigMap"},
		{"broker", "qv", certs("broker"), 0, "ConfigMap"},
		{"signing-core", "qvs", job, 2, "Job"},
		{"signing-core", "qvs", backup(pa, "qv-party A with the backup Job"), 2, "Job"},
		{"party", "qv", backup(pb, "qv-party B with the backup Job"), 2, "Job"},
	}
	for _, c := range cases {
		t.Run(c.kind+"/"+c.in.name, func(t *testing.T) {
			_, ps := policies(t, c.kind, c.ns)
			d, n := admitAll(t, ps, c.in, "v1.31")
			for _, x := range d {
				t.Errorf("denied: %s", x)
			}
			if n < c.minPods {
				t.Errorf("only %d pods in the render, want at least %d", n, c.minPods)
			}
			found := false
			for _, o := range render(t, c.in.chart, c.in.ns, c.in.args...) {
				if qstr(o, "kind") == c.must {
					found = true
				}
			}
			if !found {
				t.Errorf("the render has no %s: the case would pass on nothing", c.must)
			}
		})
	}
}
