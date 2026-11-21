package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/mpc-party/api/admin"
	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

func genKeys(n int) []ed25519.PrivateKey {
	var l []ed25519.PrivateKey
	for range n {
		_, k, _ := ed25519.GenerateKey(rand.Reader)
		l = append(l, k)
	}
	return l
}

func rawPubs(ks []ed25519.PrivateKey) [][]byte {
	var l [][]byte
	for _, k := range ks {
		l = append(l, k.Public().(ed25519.PublicKey))
	}
	return l
}

// persistedRig is a verifier with a data directory, so the admin set is durable; restart builds a new one on the same directory.
type persistedRig struct {
	*v2rig
	dir string
	cfg *Config
}

func newPersistedRig(t *testing.T, threshold int) *persistedRig {
	t.Helper()
	r := &persistedRig{v2rig: newV2Rig(t, threshold), dir: t.TempDir()}
	r.cfg = r.v2rig.cfg
	r.v.persistOn(nil, r.dir)
	return r
}

func (r *persistedRig) restart(t *testing.T) {
	t.Helper()
	time.Sleep(1100 * time.Millisecond) // a request issued before the new process started is refused: let the clock move
	v, err := newAdminVerifier(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	v.persistOn(nil, r.dir)
	r.v2rig.v = v
}

func setBody(sn setSnap, keys []ed25519.PrivateKey, thr int) *pb.AdminSetRequest {
	return admin.AdminSetBody(sn.version+1, rawPubs(keys), thr, sn.hash)
}

func (r *persistedRig) snapNow(t *testing.T) setSnap {
	t.Helper()
	sn, err := r.v.snap()
	if err != nil {
		t.Fatal(err)
	}
	return sn
}

func TestAdminSetChangeNeedsBothQuorums(t *testing.T) {
	r := newPersistedRig(t, 2)
	nxt := genKeys(3)
	body := setBody(r.snapNow(t), nxt, 2)
	only := func(ks ...ed25519.PrivateKey) *pb.AdminAuth {
		return sign(t, admin.OpAdminSet, "", body, authOpt{}, ks...)
	}

	_, _, err := r.v.applySet(body, only(r.keys[0], r.keys[1]))
	wantRefused(t, "current quorum alone", err, "new admin set")
	_, _, err = r.v.applySet(body, only(nxt[0], nxt[1]))
	wantRefused(t, "new keys alone", err, "current admin set")
	_, _, err = r.v.applySet(body, only(r.keys[0], nxt[0], nxt[1]))
	wantRefused(t, "one current signer of two", err, "current admin set")
	_, _, err = r.v.applySet(body, only(r.keys[0], r.keys[1], nxt[0], nxt[1], genKeys(1)[0]))
	wantRefused(t, "a stranger among the signers", err, "not a configured")
	if sn := r.snapNow(t); sn.version != 0 || sn.fromState {
		t.Fatalf("a refused change must leave the set alone: %+v", sn)
	}
	out, sn, err := r.v.applySet(body, only(r.keys[0], r.keys[1], nxt[0], nxt[1]))
	if err != nil || out != pb.RecordOutcome_RECORD_OUTCOME_APPLIED || sn.version != 1 || !sn.fromState {
		t.Fatalf("both quorums: %v %v %+v", out, err, sn)
	}
}

func TestAdminSetChangeTakesEffectAndSurvivesRestart(t *testing.T) {
	r := newPersistedRig(t, 2)
	nxt := genKeys(3)
	body := setBody(r.snapNow(t), nxt, 2)
	if _, _, err := r.v.applySet(body, sign(t, admin.OpAdminSet, "", body, authOpt{}, r.keys[0], r.keys[1], nxt[0], nxt[1])); err != nil {
		t.Fatal(err)
	}
	refresh := admin.RefreshBody("k1")
	// now: the old keys are no admins, the new keys are
	if _, err := r.v.check("refresh", "k1", refresh, sign(t, "refresh", "k1", refresh, authOpt{}, r.keys[0], r.keys[1])); err == nil {
		t.Error("the old admin keys still sign")
	}
	if _, err := r.v.check("refresh", "k1", refresh, sign(t, "refresh", "k1", refresh, authOpt{}, nxt[0], nxt[1])); err != nil {
		t.Errorf("the new admin keys do not sign: %v", err)
	}
	// restart: the state is read back, the configuration's list (the old keys) is ignored
	r.restart(t)
	sn := r.snapNow(t)
	if sn.version != 1 || !sn.fromState || !sn.differs || sn.threshold != 2 || len(sn.keys) != 3 {
		t.Fatalf("after restart: %+v", sn)
	}
	st := r.v.setStatus()
	if st.Version != 1 || !st.ConfigDiffers || !st.FromState {
		t.Errorf("status: %v", st)
	}
	if _, err := r.v.check("refresh", "k2", admin.RefreshBody("k2"), sign(t, "refresh", "k2", admin.RefreshBody("k2"), authOpt{}, r.keys[0], r.keys[1])); err == nil {
		t.Error("the configuration's keys work after a restart: the state must win")
	}
	if _, err := r.v.check("refresh", "k2", admin.RefreshBody("k2"), sign(t, "refresh", "k2", admin.RefreshBody("k2"), authOpt{}, nxt[1], nxt[2])); err != nil {
		t.Errorf("new keys after restart: %v", err)
	}
}

func TestAdminSetVersionRules(t *testing.T) {
	r := newPersistedRig(t, 1)
	s0 := r.snapNow(t)
	k1 := genKeys(2)
	b1 := setBody(s0, k1, 1)
	a1 := sign(t, admin.OpAdminSet, "", b1, authOpt{}, r.keys[0], k1[0])
	if out, sn1, err := r.v.applySet(b1, a1); err != nil || out != pb.RecordOutcome_RECORD_OUTCOME_APPLIED {
		t.Fatalf("v1: %v %v", out, err)
	} else {
		// the same request again: already applied, with no signature looked at (a damaged one is fine too)
		if out, _, err := r.v.applySet(b1, &pb.AdminAuth{}); err != nil || out != pb.RecordOutcome_RECORD_OUTCOME_ALREADY {
			t.Errorf("repeat: %v %v", out, err)
		}
		k2 := genKeys(2)
		// a request for a step that was skipped
		gap := admin.AdminSetBody(3, rawPubs(k2), 1, sn1.hash)
		_, _, err := r.v.applySet(gap, sign(t, admin.OpAdminSet, "", gap, authOpt{}, k1[0], k2[0]))
		wantRefused(t, "skipped version", err, "apply the changes in between")
		// a request that replaces another set than this party has
		other := admin.AdminSetBody(2, rawPubs(k2), 1, s0.hash)
		_, _, err = r.v.applySet(other, sign(t, admin.OpAdminSet, "", other, authOpt{}, k1[0], k2[0]))
		wantRefused(t, "another predecessor", err, "replaces another admin set")
		// an old request with another content, signed by the set it replaced: stale, never replayed
		old := admin.AdminSetBody(1, rawPubs(k2), 1, s0.hash)
		_, _, err = r.v.applySet(old, sign(t, admin.OpAdminSet, "", old, authOpt{}, r.keys[0], k2[0]))
		wantRefused(t, "old version", err, "old (it cannot be replayed)")
		// no change
		same := admin.AdminSetBody(2, rawPubs(k1), 1, sn1.hash)
		_, _, err = r.v.applySet(same, sign(t, admin.OpAdminSet, "", same, authOpt{}, k1[0]))
		wantRefused(t, "no change", err, "nothing to change")
		// a good second step, signed by the SECOND set (the first one no longer signs)
		good := admin.AdminSetBody(2, rawPubs(k2), 2, sn1.hash)
		_, _, err = r.v.applySet(good, sign(t, admin.OpAdminSet, "", good, authOpt{}, r.keys[0], k2[0], k2[1]))
		wantRefused(t, "the replaced set signs", err, "not a configured")
		if out, sn2, err := r.v.applySet(good, sign(t, admin.OpAdminSet, "", good, authOpt{}, k1[0], k2[0], k2[1])); err != nil || sn2.version != 2 || out != pb.RecordOutcome_RECORD_OUTCOME_APPLIED {
			t.Errorf("second step: %v %v %v", out, sn2, err)
		}
	}
}

func TestAdminSetRefusals(t *testing.T) {
	r := newPersistedRig(t, 1)
	nxt := genKeys(1)
	s0 := r.snapNow(t)
	body := setBody(s0, nxt, 1)
	at := func(o authOpt) error {
		_, _, err := r.v.applySet(body, sign(t, admin.OpAdminSet, "", body, o, r.keys[0], nxt[0]))
		return err
	}
	wantRefused(t, "expired", at(authOpt{issued: time.Now().Add(-20 * time.Minute), expires: time.Now().Add(-10 * time.Minute)}), "expired")
	wantRefused(t, "another domain", at(authOpt{domain: "staging"}), "domain")
	wantRefused(t, "longer than the party allows", at(authOpt{expires: time.Now().Add(3 * time.Hour)}), "at most")
	wantRefused(t, "issued before the party started", at(authOpt{issued: r.v.start.Add(-time.Minute), expires: time.Now().Add(time.Minute)}), "before this party's start")
	// the v1 format cannot change the set
	_, _, err := r.v.applySet(body, &pb.AdminAuth{UnixSeconds: time.Now().Unix(), PublicKey: r.keys[0].Public().(ed25519.PublicKey), Signature: make([]byte, 64)})
	wantRefused(t, "v1", err, "v2 authorization")
	// content: no keys, a threshold above the keys
	bad := admin.AdminSetBody(1, nil, 1, s0.hash)
	_, _, err = r.v.applySet(bad, sign(t, admin.OpAdminSet, "", bad, authOpt{}, r.keys[0]))
	wantRefused(t, "empty set", err, "no keys")
	bad = admin.AdminSetBody(1, rawPubs(nxt), 2, s0.hash)
	_, _, err = r.v.applySet(bad, sign(t, admin.OpAdminSet, "", bad, authOpt{}, r.keys[0], nxt[0]))
	wantRefused(t, "threshold above the keys", err, "threshold")
	// a signature over one request does not carry to another body
	other := setBody(s0, genKeys(1), 1)
	a := sign(t, admin.OpAdminSet, "", other, authOpt{}, r.keys[0], nxt[0])
	_, _, err = r.v.applySet(body, a)
	wantRefused(t, "signature of another request", err, "does not verify")
}

// A durable set that cannot be read is no reason to fall back to the configuration: every admin request is refused until it is fixed.
func TestAdminSetUnreadableStateRefusesEverything(t *testing.T) {
	r := newPersistedRig(t, 1)
	nxt := genKeys(1)
	body := setBody(r.snapNow(t), nxt, 1)
	if _, _, err := r.v.applySet(body, sign(t, admin.OpAdminSet, "", body, authOpt{}, r.keys[0], nxt[0])); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{"garbage": "not json", "empty": "", "no keys": `{"v":1,"version":1,"threshold":1,"keys":[]}`, "bad key": `{"v":1,"version":1,"threshold":1,"keys":["zz"]}`} {
		if err := os.WriteFile(filepath.Join(r.dir, adminSetFile), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		r.restart(t)
		refresh := admin.RefreshBody("k")
		_, err := r.v.check("refresh", "k", refresh, sign(t, "refresh", "k", refresh, authOpt{}, r.keys[0])) // the CONFIGURED key
		wantRefused(t, name+": a configured key", err, "durable admin set")
		if st := r.v.setStatus(); st != nil {
			t.Errorf("%s: a status was reported from an unreadable state: %v", name, st)
		}
	}
	// deleting the file is the break-glass: the party is back on its bootstrap list at version 0
	if err := os.Remove(filepath.Join(r.dir, adminSetFile)); err != nil {
		t.Fatal(err)
	}
	r.restart(t)
	refresh := admin.RefreshBody("k")
	if _, err := r.v.check("refresh", "k", refresh, sign(t, "refresh", "k", refresh, authOpt{}, r.keys[0])); err != nil {
		t.Errorf("after the state was deleted the bootstrap list must work: %v", err)
	}
	if st := r.v.setStatus(); st.Version != 0 || st.FromState {
		t.Errorf("status after reset: %v", st)
	}
}

// Once the set was changed the old single-signature format is gone for good, whatever the configuration says.
func TestAdminSetEndsV1(t *testing.T) {
	r := newPersistedRig(t, 0) // threshold unset: v1 accepted
	if !r.v.v1Allowed() {
		t.Fatal("v1 is accepted before any change")
	}
	nxt := genKeys(1)
	body := setBody(r.snapNow(t), nxt, 1)
	if _, _, err := r.v.applySet(body, sign(t, admin.OpAdminSet, "", body, authOpt{}, r.keys[0], nxt[0])); err != nil {
		t.Fatal(err)
	}
	if r.v.v1Allowed() {
		t.Error("v1 is still accepted after a change of the set")
	}
	a := admin.Sign(nxt[0], "refresh", "k", time.Now())
	if _, err := r.v.check("refresh", "k", admin.RefreshBody("k"), a); err == nil || !strings.Contains(err.Error(), "v1") {
		t.Errorf("a v1 authorization by a new key: %v", err)
	}
}

func TestRecoveryRegistryRules(t *testing.T) {
	r := newPersistedRig(t, 1)
	dir := t.TempDir()
	rs := newRecoveryStore(nil, dir)
	f := func(c byte) string { return strings.Repeat(string([]byte{c}), 64) }
	verify := func(body *pb.RecoveryKeyRequest) func() ([][]byte, error) {
		return func() ([][]byte, error) {
			return r.v.authorizeRecord(admin.OpRecoveryKey, body, sign(t, admin.OpRecoveryKey, "", body, authOpt{}, r.keys[0]))
		}
	}
	lg := r.v.log
	h0 := admin.RecoveryHash("", nil)
	apply := func(body *pb.RecoveryKeyRequest) (pb.RecordOutcome, RecoveryRegistry, error) {
		return rs.apply(body, verify(body), lg)
	}
	// nothing registered: everything is allowed
	reg, _ := rs.get()
	if reg.Version != 0 || reg.Allows(f('a')) != nil {
		t.Fatalf("empty registry: %+v", reg)
	}
	// v1: register the key in use
	out, reg, err := apply(admin.RecoveryKeyBody(1, f('a'), nil, h0))
	if err != nil || out != pb.RecordOutcome_RECORD_OUTCOME_APPLIED || reg.Current != f('a') {
		t.Fatalf("register: %v %v %+v", out, err, reg)
	}
	if reg.Allows(f('b')) == nil || reg.Allows(f('a')) != nil {
		t.Error("only the current key is allowed")
	}
	// the same request again is "already" (no signature needed)
	if out, _, err := rs.apply(admin.RecoveryKeyBody(1, f('a'), nil, h0), func() ([][]byte, error) { t.Error("verified twice"); return nil, nil }, lg); err != nil || out != pb.RecordOutcome_RECORD_OUTCOME_ALREADY {
		t.Errorf("repeat: %v %v", out, err)
	}
	// replace: b current, a retired
	prev := reg.Hash()
	out, reg, err = apply(admin.RecoveryKeyBody(2, f('b'), []string{f('a')}, prev))
	if err != nil || out != pb.RecordOutcome_RECORD_OUTCOME_APPLIED || reg.Current != f('b') || !reg.IsRetired(f('a')) {
		t.Fatalf("replace: %v %v %+v", out, err, reg)
	}
	if err := reg.Allows(f('a')); err == nil || !strings.Contains(err.Error(), "RETIRED") {
		t.Errorf("a retired key: %v", err)
	}
	// a retired key never comes back
	_, _, err = apply(admin.RecoveryKeyBody(3, f('a'), nil, reg.Hash()))
	wantRefused(t, "retired key as current", err, "retired earlier")
	// stale, gap, other predecessor
	_, _, err = apply(admin.RecoveryKeyBody(2, f('c'), nil, prev))
	wantRefused(t, "old version", err, "old (it cannot be replayed)")
	_, _, err = apply(admin.RecoveryKeyBody(4, f('c'), nil, reg.Hash()))
	wantRefused(t, "gap", err, "in between")
	_, _, err = apply(admin.RecoveryKeyBody(3, f('c'), nil, prev))
	wantRefused(t, "predecessor", err, "another registry")
	// it survives a restart
	rs2 := newRecoveryStore(nil, dir)
	if got, err := rs2.get(); err != nil || got.Version != 2 || got.Current != f('b') || !got.IsRetired(f('a')) {
		t.Errorf("reload: %+v %v", got, err)
	}
	// an unreadable record is an error, never "no registry" (a party must not export under a retired key because its record is damaged)
	os.WriteFile(filepath.Join(dir, recoveryRegFile), []byte("junk"), 0o600)
	if _, err := newRecoveryStore(nil, dir).get(); err == nil {
		t.Error("a damaged registry was read as empty")
	}
	// unsigned or badly signed requests do not apply
	rs3 := newRecoveryStore(nil, t.TempDir())
	body := admin.RecoveryKeyBody(1, f('a'), nil, h0)
	_, _, err = rs3.apply(body, func() ([][]byte, error) {
		return r.v.authorizeRecord(admin.OpRecoveryKey, body, sign(t, admin.OpRecoveryKey, "", body, authOpt{}, genKeys(1)[0]))
	}, lg)
	wantRefused(t, "a stranger signs", err, "not a configured")
	if reg, _ := rs3.get(); reg.Version != 0 {
		t.Error("a refused registry change was applied")
	}
	_ = hex.EncodeToString
}
