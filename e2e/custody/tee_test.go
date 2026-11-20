package custody_test

import (
	"bytes"
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

// SIMULATED ENCLAVE. These tests run the whole signing path (gateway, parties A, B and C, cosigners, anvil) with every party on the attested sealer,
// its own broker (a real process, its own SoftHSM token, a signed allowlist) and its TLS key sealed (e2e/mpcstack/tee.go). The evidence is a mock
// Nitro document signed by a test CA: it proves our code binds keys to a measurement, not that any hardware isolates anything. The lane runs them
// with QV_CUSTODY_SIGNER=mpc QV_CUSTODY_TEE=sim (make test-e2e-tee-sim); every other mpc test also runs in that mode by the same two variables.
// What simulation cannot prove is the real-hardware checklist in docs/runbooks/tee-broker.md.

func requireTEE(t *testing.T) {
	t.Helper()
	requireMPC(t)
	if !teeMode() {
		t.Skip("QV_CUSTODY_TEE != sim (simulated enclave run mode)")
	}
	t.Log("SIMULATED ENCLAVE: mock attester, test CA, SoftHSM brokers")
}

const (
	readyLine  = "attested sealer: data keys released"
	alertLine  = "ALERT attested sealer: the broker refused to release the data keys because this party's measurement is not allowlisted"
	releaseOK  = `"event":"release"`
	releasedOK = `"outcome":"released"`
	refusedOn  = `"outcome":"refused"`
)

// notServing is true when the party answers no Health call (not ready: its TLS key is sealed and its data keys are not released).
func notServing(s *system, role string) bool {
	h, err := s.mpc.HealthOf(role)
	if err != nil {
		return true
	}
	for _, k := range h.Keysets {
		if !k.Resolved {
			return true
		}
	}
	return false
}

func (s *system) teeWaitNotServing(role string) {
	s.t.Helper()
	s.waitFor(60*time.Second, "party "+role+" to refuse to serve", func() bool { return notServing(s, role) })
}

func (s *system) pay(n int, customer, tag string) {
	s.t.Helper()
	for i := 0; i < n; i++ {
		id, dest := s.startPayment(customer, fmt.Sprintf("%s-%d", tag, i))
		s.mustPayOnce(id, dest, 150*time.Second)
	}
}

func dirHasPrivateKey(t *testing.T, dir string) (string, bool) {
	t.Helper()
	var found string
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || found != "" {
			return nil
		}
		if b, _ := os.ReadFile(p); bytes.Contains(b, []byte("PRIVATE KEY")) {
			found = p
		}
		return nil
	})
	return found, found != ""
}

// The happy path: a withdrawal is signed through the real gateway while all three parties run the attested sealer; at rest nothing is in the clear.
func TestTEESimWithdrawalOnAttestedSealer(t *testing.T) {
	requireTEE(t)
	s, _ := funded(t, opts{}, "c-tee", 20)
	mpc := s.mpc
	tee := mpc.TEE()
	s.pay(3, "c-tee", "tee-ok")
	for _, r := range []string{"A", "B", "C"} {
		p := mpc.Party(r)
		if !strings.Contains(p.Output(), mpcstack.SimulationMarkerText) {
			t.Errorf("party %s does not announce that it is a simulation", r)
		}
		if p.CountLog(readyLine) == 0 {
			t.Errorf("party %s never reported its data keys released", r)
		}
		if tee.AuditLines(r, releaseOK, releasedOK) == 0 {
			t.Errorf("broker %s has no released record for party %s", r, r)
		}
		if tee.AuditLines(r, `"measurement":"`+tee.MeasurementOf(r)+`"`) == 0 {
			t.Errorf("broker %s never saw the measurement of party %s's binary and config", r, r)
		}
		// at rest: the TLS key and the shares are sealed, nothing is in the clear
		if f, bad := dirHasPrivateKey(t, mpc.DataDir(r)); bad {
			t.Errorf("party %s: %s holds a private key in the clear", r, f)
		}
		if _, err := os.Stat(filepath.Join(mpc.DataDir(r), "tls-key.sealed.json")); err != nil {
			t.Errorf("party %s: no sealed TLS key: %v", r, err)
		}
		if c := readFile(mpc.ConfigPath(r)); strings.Contains(c, "\"cert_file\"") || strings.Contains(c, "\"key_file\"") {
			t.Errorf("party %s: the config names a TLS key file", r)
		}
	}
	plainPartyRefusesAttested(t, mpc.ConfigPath("A"))
	s.finish()
}

// DKG (a new data key is made at the broker), refresh (a new generation, a new key) and the restart of one party (it attests again, its keys are
// released again, it signs again).
func TestTEESimDKGRefreshAndRestartOfOneParty(t *testing.T) {
	requireTEE(t)
	s, _ := funded(t, opts{}, "c-tee2", 20)
	mpc := s.mpc
	tee := mpc.TEE()
	before := tee.AuditLines("A", `"event":"newkey"`, releasedOK)
	sh := mpc.Derive(7)
	if sh.KeyID == "" {
		t.Fatal("no keyset")
	}
	if after := tee.AuditLines("A", `"event":"newkey"`, releasedOK); after <= before {
		t.Fatalf("DKG made no new data key at broker A (%d before, %d after)", before, after)
	}
	if err := mpc.Refresh(); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	s.pay(2, "c-tee2", "tee-refresh")
	// restart B: it proves itself again
	rel := tee.AuditLines("B", releaseOK, releasedOK)
	ready := mpc.B.CountLog(readyLine)
	mpc.B.Kill()
	mpc.B.Start(t)
	mpc.WaitReady(120 * time.Second)
	if tee.AuditLines("B", releaseOK, releasedOK) <= rel || mpc.B.CountLog(readyLine) <= ready {
		t.Fatal("B restarted without attesting and getting its keys released again")
	}
	s.pay(2, "c-tee2", "tee-restart")
	s.finish()
}

// One byte of the binary, or of the config, and the broker refuses; the party does not serve; the other two keep signing.
func TestTEESimWrongBinaryOrConfigIsRefused(t *testing.T) {
	requireTEE(t)
	s, _ := funded(t, opts{}, "c-tee3", 20)
	mpc := s.mpc
	tee := mpc.TEE()
	dir := t.TempDir()

	// one more byte at the end of the binary (it still runs: the party must be stopped by the broker, not by a broken file)
	raw, err := os.ReadFile(mpcBin.MPCParty)
	if err != nil {
		t.Fatal(err)
	}
	modBin := filepath.Join(dir, "mpc-party") // the same base name: the harness's environment is chosen by it
	if err := os.WriteFile(modBin, append(raw, 0), 0o755); err != nil {
		t.Fatal(err)
	}
	// one more byte of the config (a trailing newline: still valid JSON)
	cfg := readFile(mpc.ConfigPath("C"))
	modCfg := filepath.Join(dir, "party-C.modified.json")
	if err := os.WriteFile(modCfg, []byte(cfg+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if tee.Measure(modBin, mpc.ConfigPath("B")) == tee.MeasurementOf("B") || tee.Measure(mpcBin.MPCParty, modCfg) == tee.MeasurementOf("C") {
		t.Fatal("the measurement did not change")
	}

	for _, c := range []struct{ role, bin, cfg, what string }{
		{"B", modBin, "", "one byte of the binary"},
		{"C", "", modCfg, "one byte of the config"},
	} {
		refused := tee.AuditLines(c.role, refusedOn, `"rule":"allowlist:`)
		alerts := mpc.Party(c.role).CountLog(alertLine)
		p := tee.RestartPartyWith(c.role, c.bin, c.cfg)
		s.waitFor(60*time.Second, "broker "+c.role+" to refuse ("+c.what+")", func() bool {
			return tee.AuditLines(c.role, refusedOn, `"rule":"allowlist:`) > refused
		})
		s.waitFor(30*time.Second, "party "+c.role+" to raise the ALERT", func() bool { return p.CountLog(alertLine) > alerts })
		s.teeWaitNotServing(c.role)
		if tee.AuditLines(c.role, `"measurement":"`+tee.Measure(orDefault(c.bin, mpcBin.MPCParty), orDefault(c.cfg, mpc.ConfigPath(c.role)))+`"`, releasedOK) != 0 {
			t.Fatalf("%s: keys were released to the modified image", c.what)
		}
		// 2-of-3: the other two keep signing
		s.pay(2, "c-tee3", "tee-bad-"+c.role)
		// the original image comes back and is served
		tee.RestartPartyWith(c.role, "", "")
		mpc.WaitReady(120 * time.Second)
		t.Logf("%s: refused, not serving, two parties kept signing; original image back and ready", c.what)
	}
	s.pay(1, "c-tee3", "tee-bad-after")
	s.finish()
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

// Debug-mode evidence (all-zero PCRs) is refused by the verifier.
func TestTEESimDebugEvidenceIsRefused(t *testing.T) {
	requireTEE(t)
	s, _ := funded(t, opts{}, "c-tee4", 20)
	mpc := s.mpc
	tee := mpc.TEE()
	// the same config with attester.debug = true: a different file, so its measurement differs too; the verifier refuses before the allowlist is asked
	cfg := readFile(mpc.ConfigPath("C"))
	if !strings.Contains(cfg, `"type": "mock"`) {
		t.Fatal("unexpected config shape")
	}
	mod := strings.Replace(cfg, `"type": "mock"`, `"type": "mock",
   "debug": true`, 1)
	modCfg := filepath.Join(t.TempDir(), "party-C.debug.json")
	if err := os.WriteFile(modCfg, []byte(mod), 0o600); err != nil {
		t.Fatal(err)
	}
	refused := tee.AuditLines("C", refusedOn, `"rule":"verify:`)
	tee.RestartPartyWith("C", "", modCfg)
	s.waitFor(60*time.Second, "broker C to refuse debug evidence", func() bool { return tee.AuditLines("C", refusedOn, `"rule":"verify:`) > refused })
	s.teeWaitNotServing("C")
	s.pay(2, "c-tee4", "tee-debug")
	tee.RestartPartyWith("C", "", "")
	mpc.WaitReady(120 * time.Second)
	s.finish()
}

// An allowlist entry is revoked. The running party keeps its keys (they are in its memory; the broker has no way to take them back) and keeps
// signing: that is what the design says and what the runbook documents. At its next start it is refused: not ready, ALERT, and the other two
// keep signing 2-of-3. When the entry is back the party recovers without a restart.
func TestTEESimRevokedEntryWhileRunningAndAtRestart(t *testing.T) {
	requireTEE(t)
	s, _ := funded(t, opts{}, "c-tee5", 20)
	mpc := s.mpc
	tee := mpc.TEE()

	tee.Revoke("A")
	s.pay(2, "c-tee5", "tee-rev-run") // A still holds its keys
	if !mpc.A.Running() || notServing(s, "A") {
		t.Fatal("revoking an entry stopped a running party; the design says it keeps its keys until restart")
	}
	t.Log("revoked while running: party A keeps its keys and signs (documented: revocation takes effect at the next start)")

	mpc.A.Kill()
	alerts, readyBefore := mpc.A.CountLog(alertLine), mpc.A.CountLog(readyLine)
	mpc.A.Start(t)
	s.waitFor(60*time.Second, "party A to raise the allowlist ALERT", func() bool { return mpc.A.CountLog(alertLine) > alerts })
	s.teeWaitNotServing("A")
	if mpc.A.CountLog(readyLine) != readyBefore {
		t.Fatal("A reported ready after the revocation")
	}
	s.pay(3, "c-tee5", "tee-rev-restart") // B and C sign (A is the first coordinator: the gateway falls back to B)

	tee.Allow("A")
	mpc.WaitReady(180 * time.Second) // the gate retries; no restart needed
	s.pay(1, "c-tee5", "tee-rev-back")
	s.finish()
}

// A data directory rolled back to an older copy: the party does not serve that keyset (it is on an older generation than the others); the others sign.
func TestTEESimRolledBackDataDirectory(t *testing.T) {
	requireTEE(t)
	s, _ := funded(t, opts{}, "c-tee6", 20)
	mpc := s.mpc
	snap := filepath.Join(t.TempDir(), "data-A-old")
	mpc.A.Kill()
	if out, err := exec.Command("cp", "-a", mpc.DataDir("A"), snap).CombinedOutput(); err != nil {
		t.Fatalf("snapshot: %v\n%s", err, out)
	}
	mpc.A.Start(t)
	mpc.WaitReady(120 * time.Second)
	if err := mpc.RefreshKeyset("hot-0"); err != nil { // generation 2 everywhere
		t.Fatal(err)
	}
	s.pay(1, "c-tee6", "tee-rb-before")

	mpc.A.Kill()
	if out, err := exec.Command("rm", "-rf", mpc.DataDir("A")).CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if out, err := exec.Command("cp", "-a", snap, mpc.DataDir("A")).CombinedOutput(); err != nil {
		t.Fatalf("restore: %v\n%s", err, out)
	}
	mpc.A.Start(t)
	s.waitFor(90*time.Second, "party A to refuse the rolled-back keyset", func() bool {
		return strings.Contains(mpc.A.Output(), "stale restore") || strings.Contains(mpc.B.Output(), "stale restore") || strings.Contains(mpc.C.Output(), "stale restore")
	})
	s.waitFor(30*time.Second, "the rolled-back keyset to be unresolved on A", func() bool { return notServing(s, "A") })
	s.pay(2, "c-tee6", "tee-rb-after") // B and C sign
	s.finish()
}

// The broker is down when a party starts: it stays not ready (no fallback to another sealer), the others sign, and it comes up when the broker does.
func TestTEESimBrokerDownAtStart(t *testing.T) {
	requireTEE(t)
	s, _ := funded(t, opts{}, "c-tee7", 20)
	mpc := s.mpc
	tee := mpc.TEE()
	mpc.B.Kill()
	tee.StopBroker("B")
	ready := mpc.B.CountLog(readyLine)
	mpc.B.Start(t)
	s.waitFor(60*time.Second, "party B to say its broker is unreachable", func() bool { return mpc.B.CountLog("the broker is unreachable") > 0 })
	s.teeWaitNotServing("B")
	s.pay(2, "c-tee7", "tee-bd")
	tee.StartBroker("B")
	mpc.WaitReady(180 * time.Second)
	if mpc.B.CountLog(readyLine) <= ready {
		t.Fatal("B is ready without having got its keys")
	}
	s.pay(1, "c-tee7", "tee-bd-back")
	s.finish()
}

// The simulation binary is a different file from the production one and carries the marker; the production one has no mock.
func TestTEESimBinariesAreDistinctAndMarked(t *testing.T) {
	requireTEE(t)
	plain, err := mpcstack.Build(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pb, _ := os.ReadFile(plain.MPCParty)
	tb, _ := os.ReadFile(mpcBin.MPCParty)
	if bytes.Equal(pb, tb) {
		t.Fatal("the tee-sim party binary is the production binary")
	}
	if !bytes.Contains(tb, []byte(mpcstack.SimulationMarkerText)) {
		t.Fatal("the tee-sim party binary has no simulation marker")
	}
	if bytes.Contains(pb, []byte(mpcstack.SimulationMarkerText)) || bytes.Contains(pb, []byte("QV mock Nitro root")) {
		t.Fatal("the production party binary contains the simulation")
	}
}

// plainPartyRefusesAttested starts a PRODUCTION party binary on a tee-sim config: it must refuse (it has no attester and never falls back).
func plainPartyRefusesAttested(t *testing.T, cfgPath string) {
	t.Helper()
	plain, err := mpcstack.Build(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any // a copy with its own data directory: the running party holds the lock of its own
	if err := json.Unmarshal([]byte(readFile(cfgPath)), &cfg); err != nil {
		t.Fatal(err)
	}
	cfg["data_dir"] = filepath.Join(t.TempDir(), "data")
	raw, _ := json.Marshal(cfg)
	copyPath := filepath.Join(t.TempDir(), "party.json")
	if err := os.WriteFile(copyPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(plain.MPCParty, "-config", copyPath)
	cmd.Env = append(os.Environ(), "QV_ENV=test")
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "this build contains no attester") {
		t.Fatalf("a production party with sealer.type attested did not refuse: %v\n%s", err, out)
	}
}

// ROLLING UPGRADE (SIMULATED enclave; docs/runbooks/tee-broker.md, "Upgrade a party release"). A new release is a new measurement: here the
// party binary with one more byte (it runs the same code; a real release differs more, see the runbook on wire compatibility). The operators add
// the new measurement for every party (overlap), then the parties are restarted one at a time on the new build. Every step signs: with one
// party down the other two sign 2-of-3, and with the three on mixed builds all three are allowed. A party's data directory, written under the old
// build, opens under the new one: the broker releases the key by party, keyset and generation, not by measurement. At the end the old
// measurement gets a valid-until: the old build is refused, the new one is served. Then the rollback and the bad release.
func TestTEESimRollingUpgradeKeepsSigning(t *testing.T) {
	requireTEE(t)
	s, _ := funded(t, opts{}, "c-tee6", 40)
	mpc := s.mpc
	tee := mpc.TEE()
	roles := []string{"A", "B", "C"}
	s.pay(1, "c-tee6", "up-before")

	// the new release: another file, another measurement per party (the configs are unchanged)
	raw, err := os.ReadFile(mpcBin.MPCParty)
	if err != nil {
		t.Fatal(err)
	}
	newBin := filepath.Join(t.TempDir(), "mpc-party") // the harness's environment is chosen by the base name
	if err := os.WriteFile(newBin, append(raw, 0), 0o755); err != nil {
		t.Fatal(err)
	}
	oldM, newM := map[string]string{}, map[string]string{}
	for _, r := range roles {
		oldM[r] = tee.MeasurementOf(r)
		newM[r] = tee.Measure(newBin, mpc.ConfigPath(r))
		if oldM[r] == newM[r] {
			t.Fatal("the new build has the old measurement")
		}
	}
	// The release recipe computes, from the binary that actually runs (the tee-sim build, not the production image's: that one has no attester) and the
	// party's own config, the value the broker sees: the allowlist entry made by the documented script is the one the running party presents.
	if py, err := exec.LookPath("python3"); err == nil {
		script := filepath.Join(mpcstack.RepoRoot(), "deploy", "images", "measure-release.py")
		for _, r := range roles {
			out, err := exec.Command(py, "-I", script, "binary", "--binary", mpcBin.MPCParty, "--config", mpc.ConfigPath(r)).Output()
			if err != nil || strings.TrimSpace(string(out)) != oldM[r] {
				t.Fatalf("measure-release.py for party %s: %q, %v; the running party has %s", r, out, err, oldM[r])
			}
		}
	} else {
		t.Log("python3 not found: the measure-release.py cross-check is skipped")
	}

	// before the new measurement is on the list, the new build is refused (and nothing is released to it)
	refused := tee.AuditLines("B", refusedOn, `"rule":"allowlist:measurement_not_allowed"`)
	tee.RestartPartyWith("B", newBin, "")
	s.waitFor(60*time.Second, "broker B to refuse the unlisted release", func() bool {
		return tee.AuditLines("B", refusedOn, `"rule":"allowlist:measurement_not_allowed"`) > refused
	})
	s.teeWaitNotServing("B")
	s.pay(1, "c-tee6", "up-unlisted") // A and C sign
	tee.RestartPartyWith("B", "", "")
	mpc.WaitReady(120 * time.Second)

	// step 1: add the new measurement (overlap). The operator sees the difference before signing.
	diff := tee.AllowRelease(newM, "v2.0.0")
	if !strings.Contains(diff, "+ A "+newM["A"]) || !strings.Contains(diff, `version "v2.0.0"`) {
		t.Fatalf("the tool did not show the added entry before signing:\n%s", diff)
	}
	s.pay(1, "c-tee6", "up-overlap") // nothing changed for the running parties

	// step 2: one party at a time. While it restarts, the other two sign; when it is back, all three sign on mixed builds.
	for i, r := range roles {
		rel := tee.AuditLines(r, releaseOK, releasedOK, `"measurement":"`+newM[r]+`"`)
		tee.RestartPartyWith(r, newBin, "")
		s.pay(1, "c-tee6", fmt.Sprintf("up-%s-restarting", r)) // 2-of-3: the party that restarts may still be starting
		mpc.WaitReady(120 * time.Second)                       // reconciled and serving: its sealed state opened under the new build
		if tee.AuditLines(r, releaseOK, releasedOK, `"measurement":"`+newM[r]+`"`) <= rel {
			t.Fatalf("party %s is ready but the broker never released its keys to the new measurement", r)
		}
		s.pay(2, "c-tee6", fmt.Sprintf("up-%s-new-%d", r, i)) // mixed builds: i+1 parties on the new one
	}

	// step 3: valid-until on the old measurement. The old build is refused from then on; the new one stays.
	tee.SetValidUntil(oldM, time.Now().Add(-time.Minute))
	refused = tee.AuditLines("C", refusedOn, `"rule":"allowlist:expired"`)
	tee.RestartPartyWith("C", "", "") // the old build
	s.waitFor(60*time.Second, "broker C to refuse the expired old build", func() bool { return tee.AuditLines("C", refusedOn, `"rule":"allowlist:expired"`) > refused })
	s.teeWaitNotServing("C")
	s.pay(1, "c-tee6", "up-old-refused")
	tee.RestartPartyWith("C", newBin, "")
	mpc.WaitReady(120 * time.Second)
	s.pay(1, "c-tee6", "up-done")

	// rollback inside the window: a downgrade needs the old measurement on the list again (the operators move valid-until), nothing else.
	tee.SetValidUntil(oldM, time.Now().Add(time.Hour))
	tee.RestartPartyWith("B", "", "")
	mpc.WaitReady(120 * time.Second)
	s.pay(2, "c-tee6", "up-rollback") // B on the old build with data written by the new one: opens, signs

	// a bad release: the new measurement is revoked for party A. The running A keeps its keys (they are in memory); at its restart it is refused with
	// the reason "revoked"; the data directory is untouched; the others sign. The old build comes back for A.
	tee.RevokeRelease(map[string]string{"A": newM["A"]})
	s.pay(1, "c-tee6", "up-revoked-running")
	if !mpc.A.Running() || notServing(s, "A") {
		t.Fatal("revoking stopped the running party; its keys are in memory until restart (documented limit)")
	}
	refused = tee.AuditLines("A", refusedOn, `"rule":"allowlist:revoked"`)
	tee.RestartPartyWith("A", newBin, "")
	s.waitFor(60*time.Second, "broker A to refuse the revoked release", func() bool { return tee.AuditLines("A", refusedOn, `"rule":"allowlist:revoked"`) > refused })
	s.teeWaitNotServing("A")
	s.pay(2, "c-tee6", "up-revoked-restart") // B and C
	tee.RestartPartyWith("A", "", "")
	mpc.WaitReady(120 * time.Second)
	s.pay(1, "c-tee6", "up-after-revoke")
	if f, bad := dirHasPrivateKey(t, mpc.DataDir("A")); bad {
		t.Fatalf("a private key in the clear after the upgrade: %s", f)
	}
	s.finish()
}
