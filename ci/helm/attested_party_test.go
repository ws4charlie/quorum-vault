package helmcheck

// Checks for the attested mode of deploy/helm/qv-party (task Broker-chart): sealer.type attested, the SIMULATED enclave (tee-sim image, env dev or test). What a party in this mode must
// not mount (no HSM PIN, no PKCS#11 module, no TLS key Secret), what the config says, the two phases that run while the party does not (enrol and migrate), and every refusal.
// The production values cannot render an attested party at all today (there is no production attester): a test says so.

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// attestedRender renders the chart in attested mode, the way the kind lane does: production values, made-up pins, kind values, the tee-sim values, the made-up broker.
func attestedRender(role string, extra ...string) (string, error) {
	helm, err := exec.LookPath("helm")
	if err != nil {
		return "", fmt.Errorf("helm not found on PATH: %w", err)
	}
	d := partyChartDir()
	args := []string{"template", "qv-party-" + strings.ToLower(role), d, "--namespace", "qv", "--set", "role=" + role,
		"-f", filepath.Join(d, "values.yaml"), "-f", "ci-party-values.yaml", "-f", filepath.Join(d, "values-kind.yaml"), "-f", filepath.Join(d, "values-kind-teesim.yaml"), "-f", "ci-party-attested.yaml"}
	out, err := exec.Command(helm, append(args, extra...)...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("helm template: %w\n%s", err, out)
	}
	return string(out), nil
}

func attestedObjs(t *testing.T, role string, extra ...string) []Obj {
	t.Helper()
	text, err := attestedRender(role, extra...)
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
	return objs
}

func configIn(objs []Obj, file string) map[string]any {
	for _, o := range partyFind(objs, "ConfigMap") {
		if s, ok := o.Data[file]; ok {
			var c map[string]any
			if err := json.Unmarshal([]byte(fmt.Sprint(s)), &c); err != nil {
				return nil
			}
			return c
		}
	}
	return nil
}

func volNames(p PodSpec) []string {
	var n []string
	for _, v := range p.Volumes {
		n = append(n, v.Name)
	}
	sort.Strings(n)
	return n
}

func hasAny(l []string, want ...string) string {
	for _, w := range want {
		for _, x := range l {
			if x == w {
				return w
			}
		}
	}
	return ""
}

// checkAttestedRun: what the running party of an attested release must and must not have.
func checkAttestedRun(objs []Obj, role string) []string {
	var v []string
	add := func(f string, a ...any) { v = append(v, fmt.Sprintf(f, a...)) }
	sets := partyFind(objs, "StatefulSet")
	if len(sets) != 1 {
		return []string{fmt.Sprintf("want one StatefulSet, got %d", len(sets))}
	}
	pod, _ := sets[0].Pod()
	vols := volNames(pod)
	// replaced by the mode: no HSM, no PIN, no PKCS#11 module, no SoftHSM token, and (sealed TLS) no TLS key in a Secret
	if x := hasAny(vols, "hsm-pin", "hsm-so-pin", "hsm-module", "softhsm-conf", "party-tls"); x != "" {
		add("an attested party mounts the volume %q, which the mode replaces", x)
	}
	if len(pod.InitContainers) != 0 {
		add("an attested party has an init container (the SoftHSM token maker belongs to the pkcs11 sealer)")
	}
	for _, want := range []string{"broker-link", "attester-ca", "data", "config"} {
		found := false
		for _, x := range append(vols, "data") { // data is a volumeClaimTemplate, not in volumes
			if x == want {
				found = true
			}
		}
		if !found {
			add("an attested party lacks the volume %q", want)
		}
	}
	for _, ct := range pod.Containers {
		for _, m := range ct.VolumeMounts {
			if strings.HasPrefix(m.MountPath, "/etc/qv/hsm") || m.MountPath == "/etc/qv/party-tls" || m.MountPath == "/etc/qv/softhsm" {
				add("container %s mounts %s: an attested party reads no HSM PIN or module, and holds its TLS key sealed", ct.Name, m.MountPath)
			}
		}
		if ct.Name == "mpc-party" {
			env := map[string]string{}
			for _, e := range ct.Env {
				env[e.Name] = e.Value
			}
			if env["QV_ENV"] != "dev" && env["QV_ENV"] != "test" {
				add("the simulated attester needs QV_ENV dev or test, got %q", env["QV_ENV"])
			}
			if _, ok := env["SOFTHSM2_CONF"]; ok {
				add("SOFTHSM2_CONF is set on an attested party")
			}
			if !strings.Contains(ct.Image, "teesim") || strings.Contains(ct.Image, "@sha256:") {
				add("the simulated attester runs only in the tee-sim image referenced by tag, got %q", ct.Image)
			}
		}
	}
	c := configIn(objs, "party.json")
	if c == nil {
		return append(v, "no party.json")
	}
	if c["tls_sealed"] != true {
		add("config: tls_sealed is not true")
	}
	for _, k := range []string{"cert_file", "key_file"} {
		if _, ok := c[k]; ok {
			add("config: %s is set with a sealed TLS key", k)
		}
	}
	sl, _ := c["sealer"].(map[string]any)
	if str(sl["type"]) != "attested" {
		add("config: sealer.type is %q", sl["type"])
	}
	if !strings.HasPrefix(str(sl["broker_url"]), "https://") || len(strList(sl["broker_pins"])) == 0 {
		add("config: sealer.broker_url must be https and sealer.broker_pins set")
	}
	for _, k := range []string{"pin_file", "lib", "token"} {
		if _, ok := sl[k]; ok {
			add("config: sealer.%s is the PKCS#11 sealer's", k)
		}
	}
	if str(dig(sl, "attester", "type")) != "mock" || str(dig(sl, "attester", "ca_dir")) != "/etc/qv/attester-ca" {
		add("config: attester is %v", sl["attester"])
	}
	if str(sl["broker_cert_file"]) != "/etc/qv/broker-link/tls.crt" || str(sl["broker_key_file"]) != "/etc/qv/broker-link/tls.key" {
		add("config: the broker link must use its own certificate (a sealed key cannot open the link that releases the keys)")
	}
	// outward to the broker only
	got := false
	for _, o := range partyFind(objs, "NetworkPolicy") {
		if strings.HasSuffix(o.Metadata.Name, "-broker-egress") {
			got = true
		}
		if strings.HasSuffix(o.Metadata.Name, "-hsm-egress") {
			add("an attested party has an HSM egress rule")
		}
	}
	if !got {
		add("no broker egress NetworkPolicy")
	}
	return v
}

func TestAttestedPartyPassesPolicyContractAndChecks(t *testing.T) {
	c, err := LoadContract()
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range partyRoles {
		t.Run(role, func(t *testing.T) {
			objs := attestedObjs(t, role)
			for _, m := range partyPolicy(objs, true) {
				t.Error("policy: " + m)
			}
			for _, m := range checkAttestedRun(objs, role) {
				t.Error(m)
			}
			cc, _ := LoadContract()
			for _, m := range partyContract(objs, cc) {
				t.Error("contract: " + m)
			}
			_ = c
		})
	}
}

func TestAttestedChecksCatch(t *testing.T) {
	cases := []struct{ name, from, to, want string }{
		{"a PIN volume mounted", "        - name: config\n          configMap", "        - name: hsm-pin\n          secret: { secretName: x }\n        - name: config\n          configMap", "which the mode replaces"},
		{"the TLS key Secret mounted", "        - name: config\n          configMap", "        - name: party-tls\n          secret: { secretName: x }\n        - name: config\n          configMap", "which the mode replaces"},
		{"no QV_ENV", `            - { name: QV_ENV, value: "dev" }` + "\n", "", "needs QV_ENV dev or test"},
		{"a digest image", `qv-image/mpc-party-teesim:local`, `qv-image/mpc-party-teesim@sha256:` + strings.Repeat("7", 64), "tee-sim image referenced by tag"},
		{"a cert_file with a sealed key", `"tls_sealed": true`, `"cert_file": "/x", "tls_sealed": true`, "cert_file is set"},
		{"no broker egress", "-broker-egress", "-other-egress", "no broker egress"},
		{"PIN path in the sealer", `"type": "attested"`, `"pin_file": "/etc/qv/hsm-pin/pin", "type": "attested"`, "PKCS#11 sealer's"},
	}
	text, err := attestedRender("B")
	if err != nil {
		t.Skip(err)
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
			for _, m := range checkAttestedRun(objs, "B") {
				if strings.Contains(m, c.want) {
					return
				}
			}
			t.Errorf("want a violation containing %q", c.want)
		})
	}
}

// Enrolment: first install only, as a phase that renders the Job and the data volume and no StatefulSet.
func TestAttestedEnrolPhase(t *testing.T) {
	for _, role := range partyRoles {
		t.Run(role, func(t *testing.T) {
			objs := attestedObjs(t, role, "--set", "attested.phase=enrol", "--set", "attested.stopPartyAck=true")
			if n := len(partyFind(objs, "StatefulSet")); n != 0 {
				t.Fatalf("the enrol phase must render no StatefulSet (the volume has one user), got %d", n)
			}
			jobs := partyFind(objs, "Job")
			if len(jobs) != 1 {
				t.Fatalf("want one Job, got %d", len(jobs))
			}
			pod, _ := jobs[0].Pod()
			ct := pod.Containers[0]
			if strings.Join(ct.Args, " ") != "tls-init -config /etc/qv/enrol/enroll.json" {
				t.Errorf("Job args %v", ct.Args)
			}
			if x := hasAny(volNames(pod), "hsm-pin", "hsm-module", "party-tls", "config"); x != "" {
				t.Errorf("the enrolment Job mounts %q: it needs the broker link, the TEST CA, its own config and the data volume only", x)
			}
			// the enrolment config: role, data_dir, tls_sealed, sealer; nothing that depends on the other parties' pins
			ec := configIn(objs, "enroll.json")
			keys := []string{}
			for k := range ec {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			if strings.Join(keys, ",") != "data_dir,role,sealer,tls_sealed" {
				t.Errorf("enroll.json holds %v", keys)
			}
			if configIn(objs, "party.json") != nil {
				t.Error("the enrol phase renders party.json: the pins of the peers do not exist yet")
			}
			// the data volume, kept by Helm, under the name the StatefulSet's claim template will use
			pvcs := partyFind(objs, "PersistentVolumeClaim")
			if len(pvcs) != 1 || pvcs[0].Metadata.Name != "data-qv-party-"+strings.ToLower(role)+"-0" || pvcs[0].Metadata.Annotations["helm.sh/resource-policy"] != "keep" {
				t.Errorf("want one kept PVC data-qv-party-%s-0, got %+v", strings.ToLower(role), pvcs)
			}
			for _, m := range partyPolicy(objs, true) {
				t.Error("policy: " + m)
			}
			cc, _ := LoadContract()
			for _, m := range partyContract(objs, cc) {
				t.Error("contract: " + m)
			}
		})
	}
}

// The enrolment config is a different file than the running one: another measurement, so the allowlist can hold the one without the other.
func TestAttestedEnrolConfigDiffersFromTheRunningConfig(t *testing.T) {
	run := attestedObjs(t, "B")
	enrol := attestedObjs(t, "B", "--set", "attested.phase=enrol", "--set", "attested.stopPartyAck=true")
	var a, b string
	for _, o := range partyFind(run, "ConfigMap") {
		if s, ok := o.Data["party.json"]; ok {
			a = fmt.Sprint(s)
		}
	}
	for _, o := range partyFind(enrol, "ConfigMap") {
		if s, ok := o.Data["enroll.json"]; ok {
			b = fmt.Sprint(s)
		}
	}
	if a == "" || b == "" || a == b {
		t.Fatalf("the two configs must exist and differ")
	}
	// the sealer block is the same text in both: what the party proves is the same, only the file (and so the measurement) differs
	ra, rb := configIn(run, "party.json")["sealer"], configIn(enrol, "enroll.json")["sealer"]
	ja, _ := json.Marshal(ra)
	jb, _ := json.Marshal(rb)
	if string(ja) != string(jb) {
		t.Errorf("sealer blocks differ:\n%s\n%s", ja, jb)
	}
}

// Migration from the PKCS#11 sealer: a phase with the Job and both configs, the running config as -to.
func TestAttestedMigratePhase(t *testing.T) {
	extra := []string{"--set", "attested.phase=migrate", "--set", "attested.stopPartyAck=true", "--set", "attested.tlsSealed=false", "--set", "hsm.softhsm.enabled=true"}
	for _, role := range partyRoles {
		t.Run(role, func(t *testing.T) {
			objs := attestedObjs(t, role, extra...)
			if n := len(partyFind(objs, "StatefulSet")); n != 0 {
				t.Fatalf("the migrate phase must render no StatefulSet, got %d", n)
			}
			jobs := partyFind(objs, "Job")
			if len(jobs) != 1 {
				t.Fatalf("want one Job, got %d", len(jobs))
			}
			pod, _ := jobs[0].Pod()
			if got := strings.Join(pod.Containers[0].Args, " "); got != "migrate-seal -from /etc/qv/config-from/party-pkcs11.json -to /etc/qv/config/party.json" {
				t.Errorf("Job args %v", got)
			}
			from, to := configIn(objs, "party-pkcs11.json"), configIn(objs, "party.json")
			if from == nil || to == nil {
				t.Fatal("both configs must be rendered")
			}
			if str(dig(from, "sealer", "type")) != "pkcs11" || str(dig(to, "sealer", "type")) != "attested" {
				t.Errorf("-from must be the pkcs11 config and -to the attested one")
			}
			if str(from["data_dir"]) != str(to["data_dir"]) || str(from["role"]) != str(to["role"]) {
				t.Error("-from and -to must be the same party and data_dir")
			}
			if str(to["cert_file"]) == "" || to["tls_sealed"] != nil {
				t.Errorf("the migrated party keeps its certificate (pin unchanged): cert_file %q tls_sealed %v", to["cert_file"], to["tls_sealed"])
			}
			// -to is the config the party will run with: the same ConfigMap the later release mounts
			cm := ""
			for _, v := range pod.Volumes {
				if v.Name == "config" && v.ConfigMap != nil {
					cm = v.ConfigMap.Name
				}
			}
			runCM := ""
			for _, o := range partyFind(attestedObjs(t, role, "--set", "attested.tlsSealed=false"), "ConfigMap") {
				if _, ok := o.Data["party.json"]; ok {
					runCM = o.Metadata.Name
				}
			}
			if cm == "" || cm != runCM {
				t.Errorf("-to mounts %q, the running party will mount %q: the attester would measure another file", cm, runCM)
			}
			for _, m := range partyPolicy(objs, true) {
				t.Error("policy: " + m)
			}
			cc, _ := LoadContract() // the Job's two flags are the migrate command's, not the long-running party's
			ic := cc.Images["mpc-party"]
			ic.Flags = append(append([]string{}, ic.Flags...), "from", "to")
			ic.RequiredFlags = nil // migrate-seal takes -from and -to, not -config
			cc.Images["mpc-party"] = ic
			for _, m := range partyContract(objs, cc) {
				t.Error("contract: " + m)
			}
		})
	}
}

func TestAttestedRefusals(t *testing.T) {
	if _, err := attestedRender("B"); err != nil && strings.Contains(err.Error(), "not found on PATH") {
		t.Skip(err)
	}
	cases := []struct {
		name  string
		role  string
		extra []string
		want  string
	}{
		{"no broker URL", "B", []string{"--set", "attested.broker.url="}, "attested.broker.url is required"},
		{"a plain http broker", "B", []string{"--set", "attested.broker.url=http://b:8443"}, "must start with https://"},
		{"no broker pins", "B", []string{"--set", "attested.broker.pins=null"}, "attested.broker.pins is required"},
		{"a malformed broker pin", "B", []string{"--set", "attested.broker.pins={xyz}"}, "does not match"},
		{"no attester", "B", []string{"--set", "attested.attester.type="}, "attested.attester.type is required"},
		{"a production attester that does not exist", "B", []string{"--set", "attested.attester.type=nitro"}, "only mock exists"},
		{"the simulated attester in production", "B", []string{"--set", "env="}, "env dev or test only"},
		{"an unknown env", "B", []string{"--set", "env=staging"}, "must be one of"},
		{"the simulated attester with a digest image", "B", []string{"--set", "images.party.digest=sha256:" + strings.Repeat("7", 64)}, "env dev or test with an image referenced by digest"},
		{"no TEST CA Secret", "B", []string{"--set", "attested.attester.mock.caSecret="}, "caSecret is required"},
		{"no broker egress rule", "B", []string{"--set", "network.broker.to=null"}, "network.broker.to is required"},
		{"SoftHSM in the running attested party", "B", []string{"--set", "hsm.softhsm.enabled=true"}, "only for the one-time migration"},
		{"a backup Job in attested mode", "B", []string{"--set", "backup.job.enabled=true", "--set", "backup.job.keysetId=k", "--set", "backup.job.outputFile=f", "--set", "backup.job.recoveryPublicConfigMap=r"}, "backup.job.enabled is not supported"},
		{"an unknown phase", "B", []string{"--set", "attested.phase=other"}, "must be one of"},
		{"enrol without the acknowledgement", "B", []string{"--set", "attested.phase=enrol"}, "stopPartyAck"},
		{"migrate without the acknowledgement", "B", []string{"--set", "attested.phase=migrate", "--set", "attested.tlsSealed=false"}, "stopPartyAck"},
		{"enrol without a sealed TLS key", "B", []string{"--set", "attested.phase=enrol", "--set", "attested.stopPartyAck=true", "--set", "attested.tlsSealed=false"}, "needs attested.tlsSealed"},
		{"migrate with a sealed TLS key", "B", []string{"--set", "attested.phase=migrate", "--set", "attested.stopPartyAck=true", "--set", "hsm.softhsm.enabled=true"}, "runs with attested.tlsSealed=false"},
		{"migrate without the PKCS#11 module", "B", []string{"--set", "attested.phase=migrate", "--set", "attested.stopPartyAck=true", "--set", "attested.tlsSealed=false", "--set", "hsm.module.path="}, "needs hsm.module.path"},
		{"an enrol name that is no DNS label", "B", []string{"--set", "attested.enrol.name=Not_Valid"}, "does not match"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := attestedRender(c.role, c.extra...)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("want a refusal containing %q, got %v", c.want, err)
			}
		})
	}
}

// With the production values (digests, env empty) an attested party does not render, whatever else is set: there is no production attester yet.
func TestAttestedProductionIsRefused(t *testing.T) {
	_, err := partyRender(false, "B", "--set", "sealer.type=attested", "--set", "attested.broker.url=https://b:8443", "--set", "attested.broker.pins={"+strings.Repeat("9", 64)+"}",
		"--set", "attested.attester.type=mock", "--set", "attested.attester.mock.caSecret=x", "--set", "network.broker.to[0].ipBlock.cidr=10.0.0.0/24")
	if err == nil || !strings.Contains(err.Error(), "env dev or test only") {
		t.Errorf("an attested party with production values must be refused, got %v", err)
	}
	_, err = partyRender(false, "B", "--set", "sealer.type=attested", "--set", "attested.broker.url=https://b:8443", "--set", "attested.broker.pins={"+strings.Repeat("9", 64)+"}", "--set", "network.broker.to[0].ipBlock.cidr=10.0.0.0/24")
	if err == nil || !strings.Contains(err.Error(), "attested.attester.type is required") {
		t.Errorf("without an attester it must be refused, got %v", err)
	}
}

// The default (pkcs11) render is untouched by the attested mode: no attested objects, no broker rule, the HSM PIN and module as before.
func TestPkcs11RenderHasNoAttestedParts(t *testing.T) {
	_, text := partyObjs(t, false, "B")
	for _, s := range []string{"broker-link", "attester-ca", "tls_sealed", "broker_url", "enrol", "party-pkcs11.json"} {
		if strings.Contains(text, s) {
			t.Errorf("the pkcs11 render mentions %q", s)
		}
	}
	for _, s := range []string{"hsm-pin", "hsm-module", "party-tls", `"cert_file"`} {
		if !strings.Contains(text, s) {
			t.Errorf("the pkcs11 render lacks %q", s)
		}
	}
}
