package e2e

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

// The keys that protect the parties themselves (K7a): the admin set, rolled over by a request the current set signs, and the recovery key, replaced
// with signing going on. Real party processes, real SoftHSM sealing where the test needs it.

func newAdminKeys(n int) []ed25519.PrivateKey {
	var l []ed25519.PrivateKey
	for range n {
		_, k, _ := ed25519.GenerateKey(rand.Reader)
		l = append(l, k)
	}
	return l
}

func pubList(ks []ed25519.PrivateKey) [][]byte {
	var l [][]byte
	for _, k := range ks {
		l = append(l, k.Public().(ed25519.PublicKey))
	}
	return l
}

func pubHex(ks []ed25519.PrivateKey) []string {
	var l []string
	for _, k := range ks {
		l = append(l, hex.EncodeToString(k.Public().(ed25519.PublicKey)))
	}
	return l
}

func (cl *cluster3) adminSetOf(t *testing.T, role string) *pb.AdminSetStatus {
	t.Helper()
	h, err := cl.client[role].Health(ctx(t, 5*time.Second), &pb.HealthRequest{})
	must(t, err)
	if h.AdminSet == nil {
		t.Fatalf("party %s reports no admin set", role)
	}
	return h.AdminSet
}

// setChange is the request that makes `keys` (threshold thr) the admin set after the one party A reports now, signed by `signers`.
func (cl *cluster3) setChange(t *testing.T, cur *pb.AdminSetStatus, keys []ed25519.PrivateKey, thr int, signers ...ed25519.PrivateKey) *pb.AdminSetRequest {
	t.Helper()
	var prev [32]byte
	copy(prev[:], cur.SetHash)
	return cl.setChangeAt(t, cur.Version+1, prev, keys, thr, signers...)
}

func (cl *cluster3) setChangeAt(t *testing.T, version uint64, prev [32]byte, keys []ed25519.PrivateKey, thr int, signers ...ed25519.PrivateKey) *pb.AdminSetRequest {
	t.Helper()
	body := admin.AdminSetBody(version, pubList(keys), thr, prev)
	now := time.Now()
	a, err := admin.Authorize(admin.OpAdminSet, body, "", now, now.Add(10*time.Minute), signers...)
	must(t, err)
	body.Admin = a
	return body
}

func outcomes(t *testing.T, ms []*pb.RecordMember) map[string]pb.RecordOutcome {
	t.Helper()
	out := map[string]pb.RecordOutcome{}
	for _, m := range ms {
		out[m.Name] = m.Outcome
	}
	return out
}

func wantOutcomes(t *testing.T, what string, ms []*pb.RecordMember, want map[string]pb.RecordOutcome) {
	t.Helper()
	got := outcomes(t, ms)
	for r, w := range want {
		if got[r] != w {
			t.Fatalf("%s: party %s: %v, want %v (all: %v)", what, r, got[r], w, ms)
		}
	}
}

func (cl *cluster3) refreshBy(t *testing.T, id string, signers ...ed25519.PrivateKey) error {
	t.Helper()
	body := &pb.RefreshRequest{KeysetId: id}
	now := time.Now()
	a, err := admin.Authorize(admin.OpRefresh, body, "", now, now.Add(10*time.Minute), signers...)
	must(t, err)
	body.Admin = a
	_, err = cl.client["A"].Refresh(ctx(t, 60*time.Second), body)
	return err
}

// The admin set is changed by a request the CURRENT set signs (and the new set too), every party applies it itself, and a party that was down
// stays behind, visibly, and takes the same change when it is sent again.
func TestAdminSetRolloverWithAPartyDown(t *testing.T) {
	cl := newCluster3(t, nil)
	pub := cl.dkg(t, "k1")
	old := cl.env.AdminKeys
	nxt := newAdminKeys(3)
	for _, r := range []string{"A", "B", "C"} {
		if s := cl.adminSetOf(t, r); s.Version != 0 || s.FromState || s.Threshold != 2 || len(s.Keys) != 3 {
			t.Fatalf("party %s before: %v", r, s)
		}
	}
	cur := cl.adminSetOf(t, "A")

	// the change needs both quorums: the current one alone, and the new keys alone, are refused (by every party, nothing changes)
	for name, signers := range map[string][]ed25519.PrivateKey{"current set alone": {old[0], old[1]}, "new keys alone": {nxt[0], nxt[1]}, "one of each": {old[0], nxt[0]}} {
		resp, err := cl.client["A"].AdminSet(ctx(t, 30*time.Second), cl.setChange(t, cur, nxt, 2, signers...))
		must(t, err)
		wantOutcomes(t, name, resp.Members, map[string]pb.RecordOutcome{"A": pb.RecordOutcome_RECORD_OUTCOME_REFUSED, "B": pb.RecordOutcome_RECORD_OUTCOME_REFUSED, "C": pb.RecordOutcome_RECORD_OUTCOME_REFUSED})
	}
	if cl.adminSetOf(t, "A").Version != 0 {
		t.Fatal("a refused change was applied")
	}

	// C is down during the change
	cl.stop("C")
	both := []ed25519.PrivateKey{old[0], old[1], nxt[0], nxt[1]}
	resp, err := cl.client["A"].AdminSet(ctx(t, 60*time.Second), cl.setChange(t, cur, nxt, 2, both...))
	must(t, err)
	wantOutcomes(t, "C down", resp.Members, map[string]pb.RecordOutcome{"A": pb.RecordOutcome_RECORD_OUTCOME_APPLIED, "B": pb.RecordOutcome_RECORD_OUTCOME_APPLIED, "C": pb.RecordOutcome_RECORD_OUTCOME_UNREACHABLE})
	for _, r := range []string{"A", "B"} {
		if s := cl.adminSetOf(t, r); s.Version != 1 || !s.FromState || len(s.Keys) != 3 {
			t.Fatalf("party %s after: %v", r, s)
		}
	}

	// C comes back on the OLD set (version 0): the parties do not agree on who the admins are
	cl.start(t, "C")
	cl.waitReady(t)
	if s := cl.adminSetOf(t, "C"); s.Version != 0 {
		t.Fatalf("C: %v", s)
	}
	// so no admin call works: signed by the new keys, C refuses; signed by the old keys, A and B refuse. The keyset is left as it was.
	g0 := cl.waitConverged3(t, "k1", true)
	if err := cl.refreshBy(t, "k1", nxt[0], nxt[1]); err == nil {
		t.Fatal("a refresh signed by the new set went through while C still had the old set")
	}
	if err := cl.refreshBy(t, "k1", old[0], old[1]); err == nil || !strings.Contains(err.Error(), "not a configured admin key") {
		t.Fatalf("a refresh signed by the replaced set: %v", err)
	}
	if g := cl.waitConverged3(t, "k1", true); g != g0 {
		t.Fatalf("a refused refresh moved the keyset from generation %d to %d", g0, g)
	}

	// finish: the same change again (a new request: C restarted, so the first file is no use), signed by the set C still has and by the new keys
	resp, err = cl.client["A"].AdminSet(ctx(t, 60*time.Second), cl.setChange(t, cur, nxt, 2, both...))
	must(t, err)
	wantOutcomes(t, "finish", resp.Members, map[string]pb.RecordOutcome{"A": pb.RecordOutcome_RECORD_OUTCOME_ALREADY, "B": pb.RecordOutcome_RECORD_OUTCOME_ALREADY, "C": pb.RecordOutcome_RECORD_OUTCOME_APPLIED})
	for _, r := range []string{"A", "B", "C"} {
		if s := cl.adminSetOf(t, r); s.Version != 1 || !bytesEq(s.SetHash, cl.adminSetOf(t, "A").SetHash) {
			t.Fatalf("party %s after finishing: %v", r, s)
		}
	}
	// and now the new keys work on all three and the old ones on none
	if err := cl.refreshBy(t, "k1", old[0], old[1]); err == nil {
		t.Fatal("the replaced admin keys still work")
	}
	must(t, cl.refreshBy(t, "k1", nxt[1], nxt[2]))
	cl.waitConverged3(t, "k1", true)
	cl.sign(t, "A", "k1", "after-rollover", 5, pub)

	// the state is durable, and the configuration (which still lists the old keys) is ignored, loudly
	for _, r := range []string{"A", "B", "C"} {
		cl.restart(t, r)
		cl.waitReady(t)
	}
	for _, r := range []string{"A", "B", "C"} {
		if s := cl.adminSetOf(t, r); s.Version != 1 || !s.ConfigDiffers {
			t.Fatalf("party %s after restart: %v", r, s)
		}
		waitLogText(t, cl.procs[r].stderr, "the configuration is IGNORED", 5*time.Second)
	}
	cl.waitConverged3(t, "k1", true)
	must(t, cl.refreshBy(t, "k1", nxt[0], nxt[2]))

	// a replay of the change is "already"; an old request for another content is refused as stale, by every party
	resp, err = cl.client["A"].AdminSet(ctx(t, 30*time.Second), cl.setChange(t, cur, nxt, 2, both...))
	must(t, err)
	wantOutcomes(t, "replay", resp.Members, map[string]pb.RecordOutcome{"A": pb.RecordOutcome_RECORD_OUTCOME_ALREADY, "B": pb.RecordOutcome_RECORD_OUTCOME_ALREADY, "C": pb.RecordOutcome_RECORD_OUTCOME_ALREADY})
	other := newAdminKeys(2)
	resp, err = cl.client["A"].AdminSet(ctx(t, 30*time.Second), cl.setChange(t, cur, other, 1, old[0], old[1], other[0]))
	must(t, err)
	for _, m := range resp.Members {
		if m.Outcome != pb.RecordOutcome_RECORD_OUTCOME_REFUSED || !strings.Contains(m.Detail, "old (it cannot be replayed)") {
			t.Fatalf("a stale request: %v", m)
		}
	}
}

func bytesEq(a, b []byte) bool { return string(a) == string(b) }

// Break-glass: the admin keys are lost beyond the quorum. One party reset on its own gets nobody anything; all three reset under a new bootstrap list
// work again.
func TestAdminSetBreakGlassNeedsEveryParty(t *testing.T) {
	cl := newCluster3(t, nil)
	cl.dkg(t, "k1")
	old := cl.env.AdminKeys
	nxt := newAdminKeys(3)
	cur := cl.adminSetOf(t, "A")
	resp, err := cl.client["A"].AdminSet(ctx(t, 60*time.Second), cl.setChange(t, cur, nxt, 2, old[0], old[1], nxt[0], nxt[1]))
	must(t, err)
	wantOutcomes(t, "rollover", resp.Members, map[string]pb.RecordOutcome{"A": pb.RecordOutcome_RECORD_OUTCOME_APPLIED, "B": pb.RecordOutcome_RECORD_OUTCOME_APPLIED, "C": pb.RecordOutcome_RECORD_OUTCOME_APPLIED})

	// the admins lose their keys: nobody can sign for the set any more. Someone with access to ONE party's host resets that party only
	// (deletes its admin set and lists a bootstrap set of their own in its configuration).
	thief := newAdminKeys(3)
	reset := func(role string, keys []ed25519.PrivateKey) {
		t.Helper()
		cl.stop(role)
		if err := os.Remove(filepath.Join(cl.cfgs[role].DataDir, "admin-set.json")); err != nil {
			t.Fatal(err)
		}
		cl.cfgs[role].AdminKeys = pubHex(keys)
		cl.env.WriteConfig(t, cl.cfgs[role], strings.ToLower(role)+".json")
		cl.start(t, role)
		cl.waitReady(t)
	}
	reset("C", thief)
	if s := cl.adminSetOf(t, "C"); s.Version != 0 || s.FromState {
		t.Fatalf("C after its reset: %v", s)
	}
	// the thief's keys work on C, the others are on the new set: no admin call reaches all three with one set of signatures
	for name, keys := range map[string][]ed25519.PrivateKey{"the thief's keys": {thief[0], thief[1]}, "the admins' new keys": {nxt[0], nxt[1]}, "the replaced keys": {old[0], old[1]}} {
		if err := cl.refreshBy(t, "k1", keys...); err == nil {
			t.Fatalf("a refresh signed by %s went through with one party reset", name)
		}
	}
	// the status shows the disagreement
	if a, c := cl.adminSetOf(t, "A"), cl.adminSetOf(t, "C"); a.Version == c.Version || bytesEq(a.SetHash, c.SetHash) {
		t.Fatalf("a reset party must show: A %v, C %v", a, c)
	}
	// and a change of the set cannot be forced either: the thief's keys sign a change for C only if A and B see it too, and they refuse it
	resp, err = cl.client["A"].AdminSet(ctx(t, 60*time.Second), cl.setChangeAt(t, 1, [32]byte(admin.SetHash(pubList(thief), 2)), thief[:2], 1, thief[0], thief[1]))
	must(t, err)
	if o := outcomes(t, resp.Members); o["A"] != pb.RecordOutcome_RECORD_OUTCOME_REFUSED || o["B"] != pb.RecordOutcome_RECORD_OUTCOME_REFUSED {
		t.Fatalf("A and B took a change signed by keys they do not know: %v", resp.Members)
	}

	// the real break-glass: all three, under one new bootstrap list
	boot := newAdminKeys(3)
	for _, r := range []string{"A", "B", "C"} {
		cl.stop(r)
	}
	for _, r := range []string{"A", "B", "C"} {
		if err := os.Remove(filepath.Join(cl.cfgs[r].DataDir, "admin-set.json")); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		cl.cfgs[r].AdminKeys = pubHex(boot)
		cl.env.WriteConfig(t, cl.cfgs[r], strings.ToLower(r)+".json")
	}
	for _, r := range []string{"C", "B", "A"} {
		cl.start(t, r)
	}
	cl.waitReady(t)
	for _, r := range []string{"A", "B", "C"} {
		if s := cl.adminSetOf(t, r); s.Version != 0 || s.FromState || s.ConfigDiffers {
			t.Fatalf("party %s after break-glass: %v", r, s)
		}
	}
	cl.waitConverged3(t, "k1", true)
	must(t, cl.refreshBy(t, "k1", boot[0], boot[1]))
	if err := cl.refreshBy(t, "k1", old[0], old[1]); err == nil {
		t.Fatal("the replaced keys work after the break-glass")
	}
	_ = time.Second
}
