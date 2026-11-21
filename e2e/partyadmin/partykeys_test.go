package partyadmin_test

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/e2e/mpcstack"
)

// The keys that protect the parties (K7a), through the operator tool: a change of the admin set, with a party down and finished afterwards, and the
// replacement of the recovery key, tracked by `recovery-key status` until it is complete.

// signBy has the given key files sign the request file in turn.
func (r *rig) signBy(file string, keys ...string) {
	r.t.Helper()
	for _, k := range keys {
		if out, err := r.run("sign", "-key", k, "-in", file); err != nil {
			r.t.Fatalf("sign: %v\n%s", err, out)
		}
	}
}

func (r *rig) mpcParty(args ...string) (string, error) {
	r.t.Helper()
	cmd := exec.Command(bin.MPCParty, args...)
	cmd.Env = append(append(os.Environ(), mpcstack.SoftHSMEnv()...), "QV_ENV=test") // SoftHSM is refused in production
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (r *rig) tool(args ...string) (string, error) {
	return r.run(append(args, r.callers...)...)
}

func TestAdminSetThroughTheTool(t *testing.T) {
	r := newRig(t, mpcstack.Opts{})
	r.mustSend("dkg", "k1", "-scheme", "ecdsa-2of3")
	if out, err := r.status(); err != nil || !strings.Contains(out, "admin set: version 0, 2 of 3 keys") {
		t.Fatalf("status: %v\n%s", err, out)
	}
	// a fourth admin's key
	nk := filepath.Join(r.dir, "admin-new.key")
	_ = os.WriteFile(nk, []byte(strings.Repeat("7", 64)), 0o600)
	pubOut, err := r.run("pubkey", "-key", nk)
	if err != nil {
		t.Fatalf("pubkey: %v\n%s", err, pubOut)
	}
	newPub := strings.TrimSpace(pubOut)
	oldPub := r.s.Admins.PublicHex()

	// admin 1 leaves, the new admin joins: the request is made against what the parties hold, and the current quorum signs it
	req := filepath.Join(r.dir, "set-1.json")
	out, err := r.tool("admin-set", "request", "-add", newPub, "-remove", oldPub[1], "-out", req)
	if err != nil || !strings.Contains(out, "admin set version 1") {
		t.Fatalf("request: %v\n%s", err, out)
	}
	if out, err := r.run("verify", "-in", req, "-admin-key", oldPub[0], "-admin-key", oldPub[1], "-admin-key", oldPub[2], "-threshold", "2"); err == nil || !strings.Contains(out, "signature") {
		t.Fatalf("verify of an unsigned request: %v\n%s", err, out)
	}
	// unsigned, or signed by one admin: the tool refuses before any call
	if out, err := r.tool("admin-set", "send", "-auth", req); err == nil || !strings.Contains(out, "sign it first") {
		t.Fatalf("send unsigned: %v\n%s", err, out)
	}
	r.signBy(req, r.opKeys[0])
	if out, err := r.tool("admin-set", "send", "-auth", req); err == nil || !strings.Contains(out, "would be refused by every party") || !strings.Contains(out, "nothing was sent") {
		t.Fatalf("send with one signature: %v\n%s", err, out)
	}
	r.signBy(req, r.opKeys[2])

	// party C is down while the change is made
	r.s.C.Kill()
	out, err = r.tool("admin-set", "send", "-auth", req)
	if err == nil || !strings.Contains(out, "party A: applied") || !strings.Contains(out, "party B: applied") || !strings.Contains(out, "party C: UNREACHABLE") || !strings.Contains(out, "did not take the change") {
		t.Fatalf("send with C down: %v\n%s", err, out)
	}
	// it comes back on the old set, and the status says so
	r.s.RestartC()
	st, err := r.status()
	if err == nil || !strings.Contains(st, "THE PARTIES DISAGREE") || !strings.Contains(st, "party C is at version 0") || !strings.Contains(st, "admin-set request -finish") {
		t.Fatalf("status with C behind: %v\n%s", err, st)
	}
	// a request for the next change is refused until the last one is finished
	if out, err := r.tool("admin-set", "request", "-threshold", "3"); err == nil || !strings.Contains(out, "finish the earlier change first") {
		t.Fatalf("request while C is behind: %v\n%s", err, out)
	}
	// finish: the same set, signed by the set C still has (and by the new one)
	fin := filepath.Join(r.dir, "set-1-finish.json")
	if out, err := r.tool("admin-set", "request", "-finish", "-out", fin); err != nil || !strings.Contains(out, "admin set version 1") {
		t.Fatalf("request -finish: %v\n%s", err, out)
	}
	r.signBy(fin, r.opKeys[0], r.opKeys[2])
	out, err = r.tool("admin-set", "send", "-auth", fin)
	if err != nil || !strings.Contains(out, "party A: already had it") || !strings.Contains(out, "party C: applied") || !strings.Contains(out, "OK admin-set: all 3 parties are on the same state") {
		t.Fatalf("finish: %v\n%s", err, out)
	}
	if st, err := r.status(); err != nil || strings.Count(st, "admin set: version 1, 2 of 3 keys") != 3 {
		t.Fatalf("status after: %v\n%s", err, st)
	}

	// the usual files are now checked against the live set: the admin who left is refused before anything is sent, the others are not
	left := r.request("refresh", "k1", []int{1, 0})
	if out, err := r.run(append(append([]string{"refresh", "-auth", left, "-live"}, r.callers...), "-keyset", "k1")...); err == nil || !strings.Contains(out, "not a configured admin key") || !strings.Contains(out, "nothing was sent") {
		t.Fatalf("a refresh signed by the admin who left: %v\n%s", err, out)
	}
	stay := r.request("refresh", "k1", []int{0, 2})
	if out, err := r.run(append(append([]string{"refresh", "-auth", stay, "-live"}, r.callers...), "-keyset", "k1")...); err != nil || !strings.Contains(out, "OK refresh: keyset k1 generation 2") {
		t.Fatalf("a refresh by the admins who stay: %v\n%s", err, out)
	}
	// the one the parties' configuration still lists (admin 1) cannot sign for a party that has the new set; a replay of the first request is "already"
	if out, err := r.tool("admin-set", "send", "-auth", req); err != nil || strings.Count(out, "already had it") != 3 {
		t.Fatalf("replay: %v\n%s", err, out)
	}
}

func TestRecoveryKeyReplacementThroughTheTool(t *testing.T) {
	r := newRig(t, mpcstack.Opts{})
	r.mustSend("dkg", "k1", "-scheme", "ecdsa-2of3")
	gen := func(name string) (priv, pub string) {
		priv, pub = filepath.Join(r.dir, name+".private"), filepath.Join(r.dir, name+".public")
		if out, err := r.mpcParty("backup", "gen-recovery-key", "-private", priv, "-public", pub); err != nil {
			t.Fatalf("gen-recovery-key: %v\n%s", err, out)
		}
		return
	}
	_, oldPub := gen("old")
	_, newPub := gen("new")
	change := func(pub string, extra ...string) string {
		t.Helper()
		f := filepath.Join(r.dir, fmt.Sprintf("rk-%d.json", time.Now().UnixNano()))
		if out, err := r.tool(append([]string{"recovery-key", "request", "-current-public", pub, "-out", f}, extra...)...); err != nil {
			t.Fatalf("recovery-key request: %v\n%s", err, out)
		}
		r.signBy(f, r.opKeys[0], r.opKeys[2])
		out, err := r.tool("recovery-key", "send", "-auth", f)
		if err != nil || !strings.Contains(out, "OK recovery-key: all 3 parties are on the same state") {
			t.Fatalf("recovery-key send: %v\n%s", err, out)
		}
		return f
	}
	export := func(role, pub, tag string) (string, error) {
		return r.mpcParty("backup", "export", "-config", filepath.Join(r.s.Dir, "party-"+role+".json"), "-keyset", "k1", "-recovery-public", pub, "-out", filepath.Join(r.dir, "k1-"+tag+"-"+role+".bk"))
	}
	exportAll := func(pub, tag string) {
		t.Helper()
		for _, role := range []string{"A", "B", "C"} {
			if out, err := export(role, pub, tag); err != nil || !strings.Contains(out, "VERIFIED") {
				t.Fatalf("export on %s: %v\n%s", role, err, out)
			}
		}
	}
	status := func() (string, error) { return r.tool("recovery-key", "status") }

	// nothing registered: the status says so and is not complete
	if out, err := status(); err == nil || !strings.Contains(out, "none registered") {
		t.Fatalf("status before: %v\n%s", err, out)
	}
	change(oldPub)
	if out, err := status(); err == nil || !strings.Contains(out, "NONE") || !strings.Contains(out, "next:") {
		t.Fatalf("status with no backups: %v\n%s", err, out)
	}
	exportAll(oldPub, "old")
	if out, err := status(); err != nil || !strings.Contains(out, "COMPLETE") {
		t.Fatalf("status with every backup under the registered key: %v\n%s", err, out)
	}
	// replace: new key current, old retired (the default)
	change(newPub)
	out, err := status()
	if err == nil || strings.Count(out, "RETIRED") != 3 || !strings.Contains(out, "mpc-party backup export") || strings.Contains(out, "useless") || !strings.Contains(out, "not complete") {
		t.Fatalf("status after the registry change: %v\n%s", err, out)
	}
	for _, role := range []string{"A", "B", "C"} {
		if out, err := export(role, oldPub, "late-"+role); err == nil || !strings.Contains(out, "RETIRED") {
			t.Fatalf("export under the retired key on %s: %v\n%s", role, err, out)
		}
	}
	// the refresh makes every old backup dead; the status calls them stale until the new ones are made
	r.mustSend("refresh", "k1", "-live")
	if out, err := status(); err == nil || strings.Count(out, "STALE") != 3 {
		t.Fatalf("status after the refresh: %v\n%s", err, out)
	}
	exportAll(newPub, "new")
	if out, err := status(); err != nil || !strings.Contains(out, "COMPLETE: all 3 parties") {
		t.Fatalf("status at the end: %v\n%s", err, out)
	}
	// a check of one party is a local check and never says COMPLETE
	one, err := r.run("recovery-key", "status", "-party", "B="+r.s.CallerB+"@"+r.s.CertB.Pin, "-cert", r.callers[len(r.callers)-3], "-key", r.callers[len(r.callers)-1])
	if err != nil || !strings.Contains(one, "LOCAL CHECK ONLY") || strings.Contains(one, "COMPLETE:") {
		t.Fatalf("status of one party: %v\n%s", err, one)
	}
	// the registry the offline machine restores with
	reg := filepath.Join(r.dir, "registry.json")
	if out, err := r.tool("recovery-key", "registry", "-out", reg); err != nil || !strings.Contains(out, "registry version 2") {
		t.Fatalf("registry: %v\n%s", err, out)
	}
	raw, _ := os.ReadFile(reg)
	var d struct {
		Version uint64
		Current string
		Retired []string
	}
	if json.Unmarshal(raw, &d) != nil || d.Version != 2 || len(d.Retired) != 1 || d.Current == "" {
		t.Fatalf("registry file: %s", raw)
	}
}

// A party that lost its volume is restored with its share AND the two public records the others hold: after an admin-set change and a recovery-key
// change it must not come back on the bootstrap admins with no registry. The records come from the surviving parties, and only when they agree.
func TestRestoreBringsBackTheRecords(t *testing.T) {
	r := newRig(t, mpcstack.Opts{})
	r.mustSend("dkg", "k1", "-scheme", "ecdsa-2of3")
	gen := func(name string) (priv, pub string) {
		priv, pub = filepath.Join(r.dir, name+".private"), filepath.Join(r.dir, name+".public")
		if out, err := r.mpcParty("backup", "gen-recovery-key", "-private", priv, "-public", pub); err != nil {
			t.Fatalf("gen-recovery-key: %v\n%s", err, out)
		}
		return
	}
	_, oldPub := gen("old")
	newPriv, newPub := gen("new")
	send := func(file string, group string) {
		t.Helper()
		r.signBy(file, r.opKeys[0], r.opKeys[2])
		if out, err := r.tool(group, "send", "-auth", file); err != nil {
			t.Fatalf("%s send: %v\n%s", group, err, out)
		}
	}
	// the admin set changes (admin 1 leaves, a new admin joins) and the registry moves from the old key to the new one
	nk := filepath.Join(r.dir, "admin-new.key")
	_ = os.WriteFile(nk, []byte(strings.Repeat("9", 64)), 0o600)
	pubOut, _ := r.run("pubkey", "-key", nk)
	req := filepath.Join(r.dir, "set-1.json")
	if out, err := r.tool("admin-set", "request", "-add", strings.TrimSpace(pubOut), "-remove", r.s.Admins.PublicHex()[1], "-out", req); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	send(req, "admin-set")
	for i, pub := range []string{oldPub, newPub} {
		f := filepath.Join(r.dir, fmt.Sprintf("rk-%d.json", i))
		if out, err := r.tool("recovery-key", "request", "-current-public", pub, "-out", f); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		send(f, "recovery-key")
	}
	cfgC := filepath.Join(r.s.Dir, "party-C.json")
	bk := filepath.Join(r.dir, "k1-C.bk")
	if out, err := r.mpcParty("backup", "export", "-config", cfgC, "-keyset", "k1", "-recovery-public", newPub, "-out", bk); err != nil {
		t.Fatalf("export: %v\n%s", err, out)
	}
	// party C loses its volume
	r.s.C.Kill()
	if err := os.RemoveAll(filepath.Join(r.s.Dir, "data-C")); err != nil {
		t.Fatal(err)
	}
	// without the records, restore refuses; -no-records is the explicit "never changed" and leaves C on the bootstrap admins
	if out, err := r.mpcParty("backup", "restore", "-config", cfgC, "-recovery-private", newPriv, "-file", bk); err == nil || !strings.Contains(out, "-records FILE") {
		t.Fatalf("restore without -records: %v\n%s", err, out)
	}
	// the records need at least two surviving parties, and they must be reachable and agree
	rec := filepath.Join(r.dir, "records.json")
	if out, err := r.run("records", "export", "-party", "A="+r.s.CallerA+"@"+r.s.CertA.Pin, "-cert", r.callers[len(r.callers)-3], "-key", r.callers[len(r.callers)-1], "-out", rec); err == nil || !strings.Contains(out, "at least two") {
		t.Fatalf("export from one party: %v\n%s", err, out)
	}
	two := []string{"-party", "A=" + r.s.CallerA + "@" + r.s.CertA.Pin, "-party", "B=" + r.s.CallerB + "@" + r.s.CertB.Pin, "-cert", r.callers[len(r.callers)-3], "-key", r.callers[len(r.callers)-1]}
	if out, err := r.run(append([]string{"records", "export", "-out", rec}, two...)...); err != nil || !strings.Contains(out, "admin set version 1") || !strings.Contains(out, "registry version 2") {
		t.Fatalf("records export: %v\n%s", err, out)
	}
	// an edited file is refused
	raw, _ := os.ReadFile(rec)
	bad := filepath.Join(r.dir, "records-edited.json")
	_ = os.WriteFile(bad, []byte(strings.Replace(string(raw), `"threshold": 2`, `"threshold": 1`, 1)), 0o644)
	if out, err := r.mpcParty("backup", "restore", "-config", cfgC, "-recovery-private", newPriv, "-file", bk, "-records", bad); err == nil || !strings.Contains(out, "does not match its hash") {
		t.Fatalf("restore with an edited records file: %v\n%s", err, out)
	}
	if out, err := r.mpcParty("backup", "restore", "-config", cfgC, "-recovery-private", newPriv, "-file", bk, "-records", rec); err != nil || !strings.Contains(out, "admin set (version 1)") {
		t.Fatalf("restore: %v\n%s", err, out)
	}
	r.s.RestartC()
	st, err := r.status()
	if err != nil || strings.Count(st, "admin set: version 1, 2 of 3 keys") != 3 || strings.Count(st, "recovery keys: registry version 2") != 3 {
		t.Fatalf("status after the restore: %v\n%s", err, st)
	}
	// the restored party takes what the current admins sign, and refuses an export under the retired key
	stay := r.request("refresh", "k1", []int{0, 2})
	if out, err := r.run(append(append([]string{"refresh", "-auth", stay, "-live"}, r.callers...), "-keyset", "k1")...); err != nil || !strings.Contains(out, "OK refresh") {
		t.Fatalf("a refresh by the current admins after the restore: %v\n%s", err, out)
	}
	if out, err := r.mpcParty("backup", "export", "-config", cfgC, "-keyset", "k1", "-recovery-public", oldPub, "-out", filepath.Join(r.dir, "late.bk")); err == nil || !strings.Contains(out, "RETIRED") {
		t.Fatalf("the restored party exported under the retired key: %v\n%s", err, out)
	}
}

// A registry change made while a party was down is finished with `recovery-key request -finish`, also when the first file expired: no dead end.
func TestRecoveryKeyChangeFinishedAfterAPartyWasDown(t *testing.T) {
	r := newRig(t, mpcstack.Opts{})
	gen := func(name string) string {
		pub := filepath.Join(r.dir, name+".public")
		if out, err := r.mpcParty("backup", "gen-recovery-key", "-private", filepath.Join(r.dir, name+".private"), "-public", pub); err != nil {
			t.Fatalf("gen-recovery-key: %v\n%s", err, out)
		}
		return pub
	}
	oldPub, newPub := gen("old"), gen("new")
	signSend := func(file string) (string, error) {
		r.signBy(file, r.opKeys[0], r.opKeys[2])
		return r.tool("recovery-key", "send", "-auth", file)
	}
	f1 := filepath.Join(r.dir, "rk1.json")
	if out, err := r.tool("recovery-key", "request", "-current-public", oldPub, "-out", f1); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if out, err := signSend(f1); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	// C is down while the key is replaced
	f2 := filepath.Join(r.dir, "rk2.json")
	if out, err := r.tool("recovery-key", "request", "-current-public", newPub, "-out", f2); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	r.s.C.Kill()
	if out, err := signSend(f2); err == nil || !strings.Contains(out, "party C: UNREACHABLE") {
		t.Fatalf("send with C down: %v\n%s", err, out)
	}
	time.Sleep(2 * time.Second) // the party's start is later than the file's issue time (both are whole seconds)
	r.s.RestartC()
	// the original file is dead for C (issued before its restart); a new change is refused until this one is finished
	if out, err := r.tool("recovery-key", "send", "-auth", f2); err == nil || !strings.Contains(out, "party C") {
		t.Fatalf("resending the original file: %v\n%s", err, out)
	}
	if out, err := r.tool("recovery-key", "request", "-current-public", oldPub, "-out", filepath.Join(r.dir, "x.json")); err == nil || !strings.Contains(out, "recovery-key request -finish") {
		t.Fatalf("a new change while C is behind: %v\n%s", err, out)
	}
	// a finish request that expires before it is sent is a dead end only until the next -finish
	f3 := filepath.Join(r.dir, "rk3.json")
	if out, err := r.tool("recovery-key", "request", "-finish", "-valid-for", "2s", "-out", f3); err != nil {
		t.Fatalf("request -finish: %v\n%s", err, out)
	}
	r.signBy(f3, r.opKeys[0], r.opKeys[2])
	time.Sleep(3 * time.Second)
	if out, err := r.tool("recovery-key", "send", "-auth", f3); err == nil || !strings.Contains(out, "refused by every party") && !strings.Contains(out, "expired") {
		t.Fatalf("an expired finish request: %v\n%s", err, out)
	}
	f4 := filepath.Join(r.dir, "rk4.json")
	if out, err := r.tool("recovery-key", "request", "-finish", "-out", f4); err != nil {
		t.Fatalf("second -finish: %v\n%s", err, out)
	}
	out, err := signSend(f4)
	if err != nil || !strings.Contains(out, "party A: already had it") || !strings.Contains(out, "party C: applied") || !strings.Contains(out, "all 3 parties are on the same state") {
		t.Fatalf("finish: %v\n%s", err, out)
	}
}
