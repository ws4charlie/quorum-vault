package helmcheck

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The operator Job for the keys that protect the parties (K7a): a change of the admin set, a change of the recovery-key registry, the recovery status,
// and the live check of the usual files after the admin set was changed. The arguments are parsed by the real tool's flag definitions.
func TestPartyOperatorJobPartyKeys(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go not found")
	}
	bin := filepath.Join(t.TempDir(), "qv-party-admin")
	build := exec.Command("go", "build", "-o", bin, "./cmd/qv-party-admin")
	build.Dir = filepath.Join(partyChartDir(), "..", "..", "..", "mpc-party")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build qv-party-admin: %v\n%s", err, out)
	}
	known := func(words ...string) map[string]bool {
		out, _ := exec.Command(bin, append(words, "-h")...).CombinedOutput()
		m := map[string]bool{}
		for _, l := range strings.Split(string(out), "\n") {
			if f := strings.Fields(l); len(f) > 0 && strings.HasPrefix(f[0], "-") {
				m[strings.TrimPrefix(f[0], "-")] = true
			}
		}
		if len(m) < 4 {
			t.Fatalf("%v -h printed no flags:\n%s", words, out)
		}
		return m
	}
	pin := strings.Repeat("ab", 32)
	job := func(cmd string, extra ...string) []string {
		a := []string{"--set", "operator.job.enabled=true", "--set", "operator.job.command=" + cmd, "--set", "operator.job.callerCertSecret=s", "--set", "operator.job.partyPin=" + pin}
		if cmd != "status" && cmd != "recovery-status" {
			a = append(a, "--set", "operator.job.authConfigMap=a")
		}
		return append(a, extra...)
	}
	for _, c := range []struct {
		cmd    string
		words  []string // what the tool is asked for flags with
		first  []string // the first arguments of the Job
		auth   bool
		policy bool // the static policy flags (-threshold, -admin-key ...) are passed
	}{
		{"admin-set", []string{"admin-set", "send"}, []string{"admin-set", "send"}, true, false},
		{"recovery-key", []string{"recovery-key", "send"}, []string{"recovery-key", "send"}, true, false},
		{"recovery-status", []string{"recovery-key", "status"}, []string{"recovery-key", "status"}, false, false},
	} {
		objs, _ := partyObjs(t, false, "A", job(c.cmd, "--set", "operator.job.keysetId=ignored")...)
		jobs := partyFind(objs, "Job")
		if len(jobs) != 1 {
			t.Fatalf("%s: want 1 Job, got %d", c.cmd, len(jobs))
		}
		pod, _ := jobs[0].Pod()
		a := pod.Containers[0].Args
		if len(a) < 2 || a[0] != c.first[0] || a[1] != c.first[1] {
			t.Fatalf("%s: arguments start %v, want %v", c.cmd, a[:min(2, len(a))], c.first)
		}
		ks := known(c.words...)
		for i := 2; i < len(a); i++ {
			if !strings.HasPrefix(a[i], "-") {
				continue
			}
			name := strings.TrimPrefix(a[i], "-")
			if !ks[name] {
				t.Errorf("%s: the Job passes -%s, which `qv-party-admin %s` does not define", c.cmd, name, strings.Join(c.words, " "))
			}
			if name == "threshold" || name == "admin-key" || name == "live" {
				t.Errorf("%s: the Job passes the policy flag -%s: these commands ask the parties for the admin set they hold", c.cmd, name)
			}
			if name == "keyset" && c.cmd != "recovery-status" {
				t.Errorf("%s: the Job passes -keyset, which names no keyset here", c.cmd)
			}
		}
		if got := strings.Contains(strings.Join(a, " "), "-auth /etc/qv/admin/auth.json"); got != c.auth {
			t.Errorf("%s: -auth passed: %v, want %v", c.cmd, got, c.auth)
		}
	}
	// admin-set and recovery-key need the signed file, like the other signed commands; recovery-status does not
	if _, err := partyRender(false, "A", job("admin-set", "--set", "operator.job.authConfigMap=")...); err == nil {
		t.Error("an admin-set Job without its request file rendered")
	}
	// after the admin set was changed the usual files are checked against the live set: -live instead of the configured keys
	objs, _ := partyObjs(t, false, "A", job("refresh", "--set", "operator.job.keysetId=hot-0", "--set", "operator.job.live=true")...)
	pod, _ := partyFind(objs, "Job")[0].Pod()
	args := strings.Join(pod.Containers[0].Args, " ")
	if !strings.Contains(args, "-live") || strings.Contains(args, "-admin-key") || strings.Contains(args, "-threshold") {
		t.Errorf("live refresh Job: %s", args)
	}
	if !known("refresh")["live"] {
		t.Error("qv-party-admin refresh does not define -live")
	}
}
