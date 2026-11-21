package admin

import (
	"crypto/ed25519"
	"fmt"
	"strings"
	"testing"
	"time"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

func pubs(ks []ed25519.PrivateKey) [][]byte {
	var l [][]byte
	for _, k := range ks {
		l = append(l, k.Public().(ed25519.PublicKey))
	}
	return l
}

func TestSetHashIgnoresOrderAndCoversThreshold(t *testing.T) {
	k := pubs(newKeys(3))
	a := SetHash([][]byte{k[0], k[1], k[2]}, 2)
	if a != SetHash([][]byte{k[2], k[0], k[1]}, 2) {
		t.Error("the order of the keys must not change the hash")
	}
	if a == SetHash(k, 3) || a == SetHash(k[:2], 2) {
		t.Error("the threshold and the key list are both part of the hash")
	}
}

func TestCheckAdminSet(t *testing.T) {
	k := pubs(newKeys(3))
	for name, c := range map[string]struct {
		keys [][]byte
		thr  int
		want string
	}{
		"ok":          {k, 2, ""},
		"empty":       {nil, 1, "no keys"},
		"threshold 0": {k, 0, "threshold"},
		"too high":    {k, 4, "threshold"},
		"duplicate":   {[][]byte{k[0], k[0]}, 1, "twice"},
		"short key":   {[][]byte{k[0][:5]}, 1, "bytes"},
	} {
		err := CheckAdminSet(c.keys, c.thr)
		if c.want == "" && err != nil || c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}

// The new set has to prove it can sign: signatures of the current quorum alone, or of the new keys alone, are not enough.
func TestSetRequestNeedsBothQuorums(t *testing.T) {
	cur, nxt := newKeys(3), newKeys(2)
	now := time.Now()
	pol := Policy{Keys: pubs(cur), Threshold: 2, MaxValidity: time.Hour, Skew: time.Minute}
	r, err := NewSetRequest("", 4, SetHash(pubs(cur), 2), pubs(cur), 2, pubs(nxt), 2, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(r Request, ks ...ed25519.PrivateKey) Request {
		for _, k := range ks {
			if err := r.Sign(k); err != nil {
				t.Fatal(err)
			}
		}
		return r
	}
	for name, c := range map[string]struct {
		signers []ed25519.PrivateKey
		want    string
	}{
		"both quorums":          {[]ed25519.PrivateKey{cur[0], cur[1], nxt[0], nxt[1]}, ""},
		"current quorum alone":  {[]ed25519.PrivateKey{cur[0], cur[1]}, "new admin set"},
		"new keys alone":        {[]ed25519.PrivateKey{nxt[0], nxt[1]}, "current admin set"},
		"one current signer":    {[]ed25519.PrivateKey{cur[0], nxt[0], nxt[1]}, "current admin set"},
		"a stranger":            {[]ed25519.PrivateKey{cur[0], cur[1], nxt[0], nxt[1], newKeys(1)[0]}, "not a configured"},
		"a key in both counted": {[]ed25519.PrivateKey{cur[0], cur[1], nxt[0]}, "new admin set"},
	} {
		err := sign(r, c.signers...).Check(pol, now)
		if c.want == "" && err != nil || c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
	// a key that is in both sets counts for both
	both := []ed25519.PrivateKey{cur[0], cur[1]}
	r2, _ := NewSetRequest("", 4, SetHash(pubs(cur), 2), pubs(cur), 2, pubs(both), 2, now, time.Hour)
	if err := sign(r2, both...).Check(pol, now); err != nil {
		t.Errorf("two keys that stay in the set sign for both quorums: %v", err)
	}
	// the request names its step: version and predecessor are inside what is signed
	ch, err := r.SetChange()
	if err != nil || ch.SetVersion != 5 || string(ch.SetPrevHash) != string(func() []byte { h := SetHash(pubs(cur), 2); return h[:] }()) {
		t.Errorf("change: %v %v", ch, err)
	}
	// a v1 file or another operation is no admin-set request
	if _, err := (Request{Op: OpRefresh}).SetChange(); err == nil {
		t.Error("SetChange of another operation")
	}
}

func TestRecoveryRecordBounds(t *testing.T) {
	var many []string
	for i := 0; i <= MaxRetiredPerRequest; i++ {
		many = append(many, fmt.Sprintf("%064x", i))
	}
	if err := CheckRecoveryRecord("", many); err == nil {
		t.Error("more fingerprints than one request may retire")
	}
	if err := CheckRecoveryRecord("", many[:MaxRetiredPerRequest]); err != nil {
		t.Error(err)
	}
}

func TestRecoveryRequest(t *testing.T) {
	f1, f2 := strings.Repeat("a", 64), strings.Repeat("b", 64)
	if _, err := NewRecoveryRequest("", 0, RecoveryHash("", nil), f1, []string{f1}, time.Now(), time.Hour); err == nil {
		t.Error("a key cannot be current and retired at once")
	}
	if _, err := NewRecoveryRequest("", 0, RecoveryHash("", nil), "zz", nil, time.Now(), time.Hour); err == nil {
		t.Error("a fingerprint is 64 hex")
	}
	r, err := NewRecoveryRequest("", 1, RecoveryHash(f1, nil), f2, []string{f1}, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ch, err := r.RecoveryChange()
	if err != nil || ch.RkVersion != 2 || ch.RkCurrent != f2 || len(ch.RkRetire) != 1 {
		t.Errorf("%v %v", ch, err)
	}
	k := newKeys(1)[0]
	if err := r.Sign(k); err != nil {
		t.Fatal(err)
	}
	back, err := ParseRequest(r.JSON())
	if err != nil {
		t.Fatal(err)
	}
	if err := back.Check(Policy{Keys: pubs([]ed25519.PrivateKey{k}), Threshold: 1, MaxValidity: time.Hour, Skew: time.Minute}, time.Now()); err != nil {
		t.Error(err)
	}
	var _ = pb.Op_OP_RECOVERY_KEY
}

// 17 of 17 replaced by 17 other keys needs 34 signatures and one request carries 32: the request is refused when it is made (and by the party).
func TestSetStepNeverNeedsMoreThanARequestCarries(t *testing.T) {
	cur, other := pubs(newKeys(17)), pubs(newKeys(17))
	if n := MinSetSigners(cur, 17, other, 17); n != 34 {
		t.Fatalf("disjoint 17 and 17: %d", n)
	}
	if err := CheckSetStep(cur, 17, other, 17); err == nil || !strings.Contains(err.Error(), "at most 32") {
		t.Fatalf("34 signatures: %v", err)
	}
	if _, err := NewSetRequest("", 0, [32]byte{}, cur, 17, other, 17, time.Now(), time.Hour); err == nil {
		t.Error("the tool built a request that can never pass")
	}
	// keeping keys makes it possible: 17 shared keys need 17 signatures
	if err := CheckSetStep(cur, 17, append(append([][]byte{}, cur...), other...), 17); err != nil {
		t.Error(err)
	}
	// 16 of 16 replaced entirely needs exactly 32
	c16, o16 := pubs(newKeys(16)), pubs(newKeys(16))
	if err := CheckSetStep(c16, 16, o16, 16); err != nil {
		t.Errorf("32 is allowed: %v", err)
	}
}
