package qvpolicy

// The cluster policies against the charts of task Broker-chart: the production render of qv-attest-broker must pass every rule of the cluster kind `broker`; the tee-sim
// (kind) renders of the broker and of an attested party pass the kind policies and are refused by the production ones, for the right reasons.

import (
	"strings"
	"testing"
)

func brokerInput(kind bool) input {
	c := root + "/deploy/helm/qv-attest-broker"
	ci := root + "/ci/helm/"
	if kind {
		return input{"qv-attest-broker kind", c, "qv", []string{"-f", c + "/values.yaml", "-f", ci + "ci-broker-values.yaml", "-f", c + "/values-kind.yaml"}}
	}
	return input{"qv-attest-broker", c, "qv", []string{"-f", c + "/values.yaml", "-f", ci + "ci-broker-values.yaml", "-f", ci + "ci-broker-digests.yaml"}}
}

func attestedPartyInput(role string) input {
	c := root + "/deploy/helm/qv-party"
	ci := root + "/ci/helm/"
	return input{"qv-party " + role + " attested (tee-sim)", c, "qv", []string{"--set", "role=" + role, "-f", c + "/values.yaml", "-f", ci + "ci-party-values.yaml", "-f", c + "/values-kind.yaml", "-f", c + "/values-kind-teesim.yaml", "-f", ci + "ci-party-attested.yaml"}}
}

func TestBrokerProductionRenderPasses(t *testing.T) {
	_, ps := policies(t, "broker", "qv")
	d, n := admitAll(t, ps, brokerInput(false), "v1.31")
	for _, x := range d {
		t.Errorf("denied: %s", x)
	}
	if n != 1 {
		t.Errorf("want exactly one pod (the broker), got %d: the test would pass on nothing", n)
	}
}

func TestBrokerAndAttestedPartyKindRenders(t *testing.T) {
	for _, c := range []struct {
		kind string
		in   input
	}{{"broker", brokerInput(true)}, {"party", attestedPartyInput("B")}, {"party", attestedPartyInput("C")}} {
		t.Run(c.in.name, func(t *testing.T) {
			_, kps := policies(t, c.kind, "qv", "-f", policyDir+"/values-kind.yaml", "--set", "registry=qv-image")
			d, n := admitAll(t, kps, c.in, "v1.31")
			for _, x := range d {
				t.Errorf("kind policy denied: %s", x)
			}
			if n < 1 {
				t.Fatal("no pod")
			}
			// the production policies must refuse the simulation for the right reasons
			_, pps := policies(t, c.kind, "qv")
			d, _ = admitAll(t, pps, c.in, "v1.31")
			all := strings.Join(d, "\n")
			for _, want := range []string{"development switches", "images must be referenced by digest"} {
				if !strings.Contains(all, want) {
					t.Errorf("the production policies did not refuse the tee-sim render for %q; denials:\n%s", want, all)
				}
			}
		})
	}
}
