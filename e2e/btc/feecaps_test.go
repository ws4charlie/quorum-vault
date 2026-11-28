package btce2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
)

// Signed fee-cap changes end to end (docs/runbooks/btc-fee-caps.md): approvers sign with `qv-fee-caps sign`, an operator applies with `qv-fee-caps apply` to the
// core and the zone's two guard databases, `show` and `metrics` read them back; real mpc-party, gateway, cosigner and workflows, bitcoind, and the proxy that makes the
// node refuse low fees. No service is restarted in any of these tests.

const (
	workerAlert  = "ALERT: the zone refused a withdrawal built under other fee caps than its own"
	gatewayAlert = "ALERT: the zone refused a transaction built under other fee caps than its own"
)

func feeCapsSystem(t *testing.T, o opts) *system {
	t.Helper()
	o.withdraw = true
	if o.feeCaps == nil {
		o.feeCaps = &feeCapsOpts{}
	}
	return newSystem(t, o)
}

// A send stuck at the fee cap is raised past it: the node wants more than the cap allows, the system stops at the cap with one ALERT; the approvers raise max_fee_rate
// with signatures, the change is applied to the core and both zone databases while everything runs, and the next bump pays more than the old cap, up to the new one, and
// confirms. Booked once, Reconcile clean, no process restarted.
func TestFeeCapsRaiseBumpsAStuckSendBeyondTheOldCap(t *testing.T) {
	px := newFeeProxy(t)
	s := feeCapsSystem(t, opts{proxy: px, fallbackRate: 1, stuckAfter: "2s", maxFeeRate: 4})
	procs := []*proc{s.core, s.worker, s.gateway}
	s.wantCaps(everywhere, 100_000, 4, 0)
	w, dest := s.stuckWithdrawal(px)
	f0 := s.firstFee(px) // the size at 1 sat/vB
	oldCap := 4 * f0
	px.setMin(f0 * 11 / 2) // 5.5 x f0: refuses 5 x f0 and below, takes 6 x f0
	s.waitFor(120*time.Second, "the ALERT at the old cap", func() bool { return s.workerLogCount("cannot be replaced") >= 1 })
	s.holds(10*time.Second, "waiting at the cap: nothing voided, one ALERT", func() bool {
		return s.getWd(w.ID).Status == "broadcast" && s.workerLogCount("cannot be replaced") == 1
	})
	for _, o := range px.offered() {
		if o.Fee > oldCap {
			t.Fatalf("a fee of %d is above the cap of %d before the change", o.Fee, oldCap)
		}
	}
	before := len(px.offered())

	// Two approvers sign the raise to 8 sat/vB; max_tx_fee_sats stays; sequence 1.
	files := s.signedBy(100_000, 8, 1, "alice", "bob")
	out, err := s.applyCaps(everywhere, files...)
	if err != nil {
		t.Fatalf("apply: %v\n%s", err, out)
	}
	if strings.Count(out, "applied") != 3 || strings.Contains(out, "FAILED") {
		t.Fatalf("apply output:\n%s", out)
	}
	s.wantCaps(everywhere, 100_000, 8, 1)

	s.waitFor(180*time.Second, "the node takes a replacement above the old cap", func() bool {
		for _, o := range px.offered() {
			if o.Verdict == "taken" && o.Fee > oldCap {
				return true
			}
		}
		return false
	})
	newCap := 8 * f0
	for i, o := range px.offered() {
		if o.Fee > newCap {
			t.Fatalf("a fee of %d is above the new cap of %d", o.Fee, newCap)
		}
		if i >= before && o.Verdict == "taken" && o.Fee <= oldCap {
			t.Fatalf("the node took %d after the raise, not above the old cap %d", o.Fee, oldCap)
		}
	}
	strictlyAbove(t, px.offered())
	s.node.mine(2, "")
	s.waitWd(w.ID, "confirmed", 60*time.Second)
	taken := px.feesWith("taken")
	last := taken[len(taken)-1]
	if last <= oldCap {
		t.Fatalf("the confirmed transaction paid %d, not above the old cap %d", last, oldCap)
	}
	if got := s.withdrawalFee(w.ID); got != last {
		t.Fatalf("booked fee %d, the confirmed transaction paid %d", got, last)
	}
	if got := s.received(dest, 1); got != 10_000_000 {
		t.Fatalf("received %d", got)
	}
	if got := s.hotPosted().Int64(); got != -100_000_000+10_000_000+last {
		t.Fatalf("hot mirror %d", got)
	}
	for _, p := range procs {
		if !alive(p) {
			t.Fatalf("%s stopped: the change must not need a restart", p.name)
		}
	}
	if n := s.workerLogCount(workerAlert); n != 0 {
		t.Fatalf("%d fee-cap sequence ALERTs for a change applied to every database before any build used it", n)
	}
	s.ledgerOK()
	s.reconcileClean()
}

// The window: the zone has the change and the core does not. A withdrawal requested in between does not fail: it keeps its hold, one ALERT
// is raised for it, and it goes out under the new caps as soon as the other side has the change. show says the databases differ, the divergence metric is 1, and it is 0
// again after.
func TestFeeCapsApplyWindowWaitsThenSendsUnderTheNewCaps(t *testing.T) {
	s := feeCapsSystem(t, opts{stuckAfter: "10m"})
	procs := []*proc{s.core, s.worker, s.gateway}
	s.fundHot(100_000_000)
	s.deposit("c1", 30_000_000)
	m := s.metrics(everywhere)
	if m["qv_btc_fee_caps_diverged"] != 0 || m["qv_btc_fee_caps_seq{core}"] != 0 || m["qv_btc_fee_cap_max_fee_rate_sat_vb{gateway}"] != 50 || m["qv_btc_fee_cap_max_tx_fee_sats{cosigner-b}"] != 100_000 {
		t.Fatalf("metrics at the start: %v", m)
	}

	// 1. The zone first.
	files := s.signedBy(150_000, 60, 1, "alice", "carol")
	s.mustApply(zoneOnly, files...)
	rows, out := s.showCaps(everywhere)
	if rows["core"].seq != 0 || rows["gateway"].seq != 1 || rows["cosigner-b"].seq != 1 || rows["gateway"].rate != 60 || !strings.Contains(out, "WARNING: the databases are on different sequence numbers") {
		t.Fatalf("show during the window:\n%s", out)
	}
	m = s.metrics(everywhere)
	if m["qv_btc_fee_caps_diverged"] != 1 || m["qv_btc_fee_caps_seq{core}"] != 0 || m["qv_btc_fee_caps_seq{gateway}"] != 1 || m["qv_btc_fee_caps_seq{cosigner-b}"] != 1 {
		t.Fatalf("metrics during the window: %v", m)
	}
	dest := s.node.fresh()
	w1 := s.withdraw("ini", "w1", "c1", dest, 10_000_000)
	s.waitFor(90*time.Second, "the ALERT for the waiting withdrawal", func() bool { return s.workerLogCount(workerAlert) >= 1 && fileContains(s.gateway.log, gatewayAlert) })
	s.holds(8*time.Second, "w1 waits: not sent, not failed", func() bool {
		st := s.getWd(w1.ID).Status
		return st != "broadcast" && st != "confirmed" && st != "failed"
	})
	// finish the apply: the zone databases already have the change (skipped), the core takes it (a command always names a zone database: the approvers in force come from there)
	s.mustApply(everywhere, files...)
	s.wantCaps(everywhere, 150_000, 60, 1)
	if m = s.metrics(everywhere); m["qv_btc_fee_caps_diverged"] != 0 {
		t.Fatalf("metrics after the window: %v", m)
	}
	s.waitWd(w1.ID, "broadcast", 90*time.Second)
	s.node.mine(2, "")
	s.waitWd(w1.ID, "confirmed", 60*time.Second)
	if n := s.workerLogCount(workerAlert); n != 1 {
		t.Fatalf("%d ALERTs for the withdrawal that waited, want one", n)
	}
	if got := s.received(dest, 1); got != 10_000_000 {
		t.Fatalf("received %d", got)
	}

	// The other order, the core on a change the zone does not have, can no longer be made by the tool (it writes the core only after every zone database
	// accepted the change); a row forged in the core's database makes it, see TestFeeCapsForgedCoreRowIsRefusedByTheZone.
	if got := s.received(dest, 1); got != 10_000_000 {
		t.Fatalf("received %d", got)
	}
	for _, p := range procs {
		if !alive(p) {
			t.Fatalf("%s stopped", p.name)
		}
	}
	s.ledgerOK()
	s.reconcileClean()
}

// Refused changes leave everything as it was: no row in any database, the same caps and sequence number in show and metrics, nothing in the audit trail of the fee
// caps. The same file applied twice is not an error and adds nothing.
func TestFeeCapsRefusedChangesLeaveEverythingAsItWas(t *testing.T) {
	s := feeCapsSystem(t, opts{})
	s.wantCaps(everywhere, 100_000, 50, 0)
	check := func(why string) {
		t.Helper()
		s.wantCaps(everywhere, 100_000, 50, 0)
		if rows := s.capRows(); rows[0] != 0 || rows[1] != 0 || rows[2] != 0 {
			t.Fatalf("%s: rows left in the databases: %v", why, rows)
		}
		if m := s.metrics(everywhere); m["qv_btc_fee_caps_diverged"] != 0 || m["qv_btc_fee_caps_seq{core}"] != 0 || m["qv_btc_fee_caps_ignored_rows{gateway}"] != 0 {
			t.Fatalf("%s: metrics: %v", why, m)
		}
	}
	refused := func(why, want string, files ...string) {
		t.Helper()
		out, err := s.applyCaps(everywhere, files...)
		if err == nil {
			t.Fatalf("%s: apply succeeded:\n%s", why, out)
		}
		if !strings.Contains(out, want) {
			t.Fatalf("%s: the refusal does not say %q:\n%s", why, want, out)
		}
		if strings.Contains(out, "applied: max_tx_fee_sats") {
			t.Fatalf("%s: something was applied:\n%s", why, out)
		}
		check(why)
	}

	refused("unsigned", "0 valid signatures", s.stripSignatures(s.signCaps("alice", 150_000, 80, 1)))
	refused("one approver of two", "1 valid signatures of distinct, enabled approvers, 2 needed", s.signCaps("alice", 150_000, 80, 1))
	a1 := s.signCaps("alice", 150_000, 80, 1)
	refused("one person twice", "1 valid signatures", a1, a1)
	// Signed for 80, edited to 90 afterwards: the signatures do not cover it.
	a := s.signCaps("alice", 150_000, 80, 1)
	b := s.cosignCaps("bob", a)
	tampered := s.tamper(a, b, 90)
	refused("edited after signing", "valid signatures", tampered)
	refused("above the zone's bounds", "outside the zone's bounds", s.signedBy(fcMaxTx, fcMaxRate+1, 1, "alice", "bob")...)
	refused("below the zone's bounds", "outside the zone's bounds", s.signedBy(fcMinTx-1, 1, 1, "alice", "bob")...)
	refused("breaks the cap consistency rule", "is below max_fee_rate", s.signedBy(50_000, 200, 1, "alice", "bob")...)
	// Not an approver: a name the zone does not know, and a known name signed with another key, count for nothing.
	m := s.signedAs("mallory", 150_000, 80, 1)
	refused("an actor the zone does not know", "valid signatures", m, s.cosignCaps("bob", m))
	fa := s.signedAs("alice", 150_000, 80, 1)
	refused("an approver's name with another key", "valid signatures", fa, s.cosignCaps("bob", fa))

	// A change that is fine: applied once; the same file again changes nothing; another change with the same or a lower sequence number is refused.
	good := s.signedBy(150_000, 80, 1, "alice", "bob")
	s.mustApply(everywhere, good...)
	s.wantCaps(everywhere, 150_000, 80, 1)
	s.mustApply(everywhere, good...)
	if rows := s.capRows(); rows[0] != 1 || rows[1] != 1 || rows[2] != 1 {
		t.Fatalf("the same change applied twice: rows %v", rows)
	}
	for _, seq := range []int64{1, 0} {
		files := s.signedBy(150_000, 90, max(seq, 1), "alice", "carol")
		if seq == 0 { // the tool will not sign sequence 0; a hand-made file with it is refused all the same
			files = []string{s.withSeq(files[0], files[1], 0)}
		}
		out, err := s.applyCaps(everywhere, files...)
		if err == nil || !(strings.Contains(out, "is not higher than the current") || strings.Contains(out, "sequence number of at least 1")) {
			t.Fatalf("a replayed sequence number %d: %v\n%s", seq, err, out)
		}
		s.wantCaps(everywhere, 150_000, 80, 1)
		if rows := s.capRows(); rows[0] != 1 || rows[1] != 1 || rows[2] != 1 {
			t.Fatalf("a replayed sequence number %d left rows: %v", seq, rows)
		}
	}
	// A partial failure is reported and finished by running the same command again: here the core is behind (a change applied to the zone alone).
	two := s.signedBy(150_000, 85, 2, "alice", "bob")
	s.mustApply(zoneOnly, two...)
	out, _ := s.applyCaps(everywhere, two...)
	if strings.Count(out, "applied") != 3 {
		t.Fatalf("finishing the change:\n%s", out)
	}
	s.wantCaps(everywhere, 150_000, 85, 2)
}

// revokeApprover revokes an approver of the zone with operator signatures: two operators sign, `qv-approvers apply` puts it into both guard databases.
func (s *system) revokeApprover(name string, seq int) {
	s.t.Helper()
	var files []string
	at := fmt.Sprint(time.Now().Unix()) // one signing time for both operators: two separate runs can fall in different seconds
	for _, op := range []string{"op1", "op2"} {
		out := filepath.Join(s.dir, fmt.Sprintf("revoke-%s-%s.json", name, op))
		if o, err := s.tool("qv-approvers", "sign", "-operator", op, "-key", s.keyFile(op, s.ops[op]), "-seq", fmt.Sprint(seq), "-signed-at", at, "-action", "revoke", "-name", name, "-out", out); err != nil {
			s.t.Fatalf("qv-approvers sign: %v\n%s", err, o)
		}
		files = append(files, out)
	}
	args := append([]string{"apply", "-config", s.gwPath}, s.dbArgs(zoneOnly)...)
	if o, err := s.tool("qv-approvers", append(args, files...)...); err != nil {
		s.t.Fatalf("qv-approvers apply: %v\n%s", err, o)
	}
}

// The approver registry (operator-signed revocations) decides who counts, and the core keeps no approver list of its own: `qv-fee-caps` reads the approvers in force
// from the zone databases. An approver is revoked, then:
//   - a change signed by that approver is refused at the pre-check with a message that names the approvers in force, to every database and to the core alone
//     (the core alone is refused too: there is no zone to ask), and nothing is written anywhere;
//   - revoking an approver whose signature carried the change in force makes the zone ignore that change (it falls back to the config's caps, sequence 0) while the
//     core's row stays: the core reads its own rows by shape. That is a mismatch, shown by `show` and the metrics, and it ends with one new change signed by the
//     approvers who are left, applied to all databases (sequence 3 here is higher than the core's 1);
//   - the new set passes end to end.
//
// Nothing is voided and nothing is signed in the meantime.
func TestFeeCapsRevokedApproverIsRefusedAtThePreCheck(t *testing.T) {
	s := feeCapsSystem(t, opts{stuckAfter: "10m", feeCaps: &feeCapsOpts{operators: 3}})
	procs := []*proc{s.core, s.worker, s.gateway}
	s.fundHot(100_000_000)
	s.deposit("c1", 30_000_000)

	// A change signed by alice and bob is in force everywhere (sequence 1, 60 sat/vB).
	s.mustApply(everywhere, s.signedBy(150_000, 60, 1, "alice", "bob")...)
	s.wantCaps(everywhere, 150_000, 60, 1)

	// Bob is revoked in the zone. The change he signed no longer has two approvers behind it there: the zone ignores it, the core does not.
	s.revokeApprover("bob", 1)
	rows, out := s.showCaps(everywhere)
	if rows["core"] != (capsRow{150_000, 60, 1}) || rows["gateway"] != (capsRow{100_000, 50, 0}) || rows["cosigner-b"] != (capsRow{100_000, 50, 0}) ||
		!strings.Contains(out, "carry no valid approver signatures and are ignored") || !strings.Contains(out, "WARNING: the databases are on different sequence numbers") {
		t.Fatalf("show after the revocation:\n%s", out)
	}
	if m := s.metrics(everywhere); m["qv_btc_fee_caps_diverged"] != 1 || m["qv_btc_fee_caps_ignored_rows{gateway}"] != 1 || m["qv_btc_fee_caps_ignored_rows{core}"] != 0 {
		t.Fatalf("metrics after the revocation: %v", m)
	}
	dest := s.node.fresh()
	w := s.withdraw("ini", "w1", "c1", dest, 10_000_000)
	s.waitFor(90*time.Second, "the ALERT for the waiting withdrawal", func() bool { return s.workerLogCount(workerAlert) >= 1 })
	waits := func(what string) {
		t.Helper()
		s.holds(6*time.Second, what, func() bool {
			st := s.getWd(w.ID).Status
			return st != "broadcast" && st != "confirmed" && st != "failed"
		})
	}
	waits("the withdrawal waits while the core is on the change the zone ignores")

	// A new change signed by the revoked approver and alice. To every database: refused before anything is written.
	bad := s.signedBy(150_000, 70, 2, "alice", "bob")
	out, err := s.applyCaps(everywhere, bad...)
	if err == nil || !strings.Contains(out, "change refused by") || strings.Contains(out, "applied: max_tx_fee_sats") {
		t.Fatalf("a change signed by a revoked approver, applied everywhere: %v\n%s", err, out)
	}
	if rows := s.capRows(); rows[0] != 1 || rows[1] != 1 || rows[2] != 1 {
		t.Fatalf("rows after the refused change: %v", rows)
	}
	// To the core alone: refused too. The core keeps no approver list and there is no zone database to ask, so nothing is applied.
	if out, err := s.applyCaps(coreOnly, bad...); err == nil || !strings.Contains(out, "at least one zone database") {
		t.Fatalf("the core alone: %v\n%s", err, out)
	}
	// The pre-check names who is in force.
	if out, err := s.applyCaps(zoneOnly, bad...); err == nil || !strings.Contains(out, "approvers in force there:") || strings.Contains(out, "bob,") {
		t.Fatalf("the zone databases took a change signed by a revoked approver, or the message does not say who is in force: %v\n%s", err, out)
	}
	if rows := s.capRows(); rows[0] != 1 || rows[1] != 1 || rows[2] != 1 {
		t.Fatalf("rows after the refused changes: %v", rows)
	}
	waits("the withdrawal still waits: the core is on sequence 1, the zone on 0")

	// The way out: the approvers who are left sign a new change; the zone takes it (3 is higher than its 0), the core too.
	s.mustApply(everywhere, s.signedBy(150_000, 80, 3, "alice", "carol")...)
	s.wantCaps(everywhere, 150_000, 80, 3)
	if m := s.metrics(everywhere); m["qv_btc_fee_caps_diverged"] != 0 {
		t.Fatalf("metrics after the new change: %v", m)
	}
	s.waitWd(w.ID, "broadcast", 90*time.Second)
	s.node.mine(2, "")
	s.waitWd(w.ID, "confirmed", 60*time.Second)
	if got := s.received(dest, 1); got != 10_000_000 {
		t.Fatalf("received %d", got)
	}
	for _, p := range procs {
		if !alive(p) {
			t.Fatalf("%s stopped", p.name)
		}
	}
	s.ledgerOK()
	s.reconcileClean()
}

// Two approvers on two machines never sign in the same second. Bob signs the change alice signed a few seconds earlier, with -like, and the pair applies;
// signing the same values again later without -like gives a different signing time and is refused as two different changes.
func TestFeeCapsApproversSignSecondsApart(t *testing.T) {
	s := feeCapsSystem(t, opts{})
	a := s.signCaps("alice", 150_000, 80, 1)
	time.Sleep(3 * time.Second)
	b := s.cosignCaps("bob", a)
	s.mustApply(everywhere, a, b)
	s.wantCaps(everywhere, 150_000, 80, 1)

	// The mistake -like prevents: the values typed again, a few seconds later.
	a2 := s.signCaps("alice", 160_000, 80, 2)
	time.Sleep(2 * time.Second)
	b2 := s.signCaps("bob", 160_000, 80, 2)
	out, err := s.applyCaps(everywhere, a2, b2)
	if err == nil || !strings.Contains(out, "the signatures are over different changes") {
		t.Fatalf("two signing times: %v\n%s", err, out)
	}
	s.wantCaps(everywhere, 150_000, 80, 1)
}

// An approver enrolled by a signed registry change counts at once: a fee-cap change signed by that new approver passes the pre-check and applies everywhere,
// though the core's configuration never heard of the name (it has no approver list; the old static list refused this change early).
func TestFeeCapsEnrolledApproverCounts(t *testing.T) {
	s := feeCapsSystem(t, opts{feeCaps: &feeCapsOpts{operators: 3}})
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	var files []string
	at := fmt.Sprint(time.Now().Unix()) // one signing time for both operators: two separate runs can fall in different seconds
	for _, op := range []string{"op1", "op2"} {
		out := filepath.Join(s.dir, "enrol-dave-"+op+".json")
		if o, err := s.tool("qv-approvers", "sign", "-operator", op, "-key", s.keyFile(op, s.ops[op]), "-seq", "1", "-signed-at", at, "-action", "enrol", "-name", "dave",
			"-public-key", hex.EncodeToString(pub), "-out", out); err != nil {
			t.Fatalf("qv-approvers sign: %v\n%s", err, o)
		}
		files = append(files, out)
	}
	args := append([]string{"apply", "-config", s.gwPath}, s.dbArgs(zoneOnly)...)
	if o, err := s.tool("qv-approvers", append(args, files...)...); err != nil {
		t.Fatalf("qv-approvers apply: %v\n%s", err, o)
	}
	s.approv["dave"] = priv
	s.mustApply(everywhere, s.signedBy(150_000, 60, 1, "alice", "dave")...)
	s.wantCaps(everywhere, 150_000, 60, 1)
}

// A row forged in the core's database (no valid signature, caps far above the zone's) is a hint the core follows and the zone never does: the withdrawal built
// under it is refused by the zone with the zone's reason in the worker's log, nothing is broadcast, and the withdrawal waits (and is parked after the hold,
// TestFeeCapsRefusalThatNeverClearsIsParkedWithTheZonesReason). A real signed change with a higher sequence number, applied everywhere, ends the wait.
func TestFeeCapsForgedCoreRowIsRefusedByTheZone(t *testing.T) {
	s := feeCapsSystem(t, opts{stuckAfter: "10m", feeCaps: &feeCapsOpts{}})
	s.fundHot(100_000_000)
	s.deposit("c1", 30_000_000)
	c, err := pgx.Connect(context.Background(), s.bizDSN)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exec(context.Background(), `INSERT INTO btc_fee_cap_changes (chain, seq, max_tx_fee_sats, max_fee_rate, signed_at, signatures) VALUES ($1, 7, 900000, 190, $2, '[{"actor":"mallory","signature":"00"}]')`, s.chain, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	c.Close(context.Background())
	rows, _ := s.showCaps(everywhere)
	if rows["core"].seq != 7 || rows["gateway"].seq != 0 {
		t.Fatalf("the core follows the forged row, the zone does not: %v", rows)
	}
	dest := s.node.fresh()
	w := s.withdraw("ini", "w1", "c1", dest, 10_000_000)
	s.waitFor(90*time.Second, "the zone's reason in the worker's log", func() bool { return s.workerLogCount("the zone's reason for refusing the withdrawal") >= 1 })
	if s.workerLogCount(btc.FeeCapsSeqNote) < 1 {
		t.Fatal("the worker's log does not carry the zone's refusal reason")
	}
	s.holds(6*time.Second, "the withdrawal is not sent under the forged caps", func() bool {
		st := s.getWd(w.ID).Status
		return st != "broadcast" && st != "confirmed" && st != "failed"
	})
	// the way out: one real change with a higher sequence number, to every database
	s.mustApply(everywhere, s.signedBy(150_000, 60, 8, "alice", "bob")...)
	s.waitWd(w.ID, "broadcast", 90*time.Second)
	s.node.mine(2, "")
	s.waitWd(w.ID, "confirmed", 60*time.Second)
	if got := s.received(dest, 1); got != 10_000_000 {
		t.Fatalf("received %d", got)
	}
}
