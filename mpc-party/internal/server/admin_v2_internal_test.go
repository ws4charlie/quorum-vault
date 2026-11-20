package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ws4charlie/quorum-vault/mpc-party/api/admin"
	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

type v2rig struct {
	v    *adminVerifier
	keys []ed25519.PrivateKey
	cfg  *Config
}

func newV2Rig(t *testing.T, threshold int, mut ...func(*Config)) *v2rig {
	t.Helper()
	r := &v2rig{}
	r.cfg = &Config{AdminMaxAgeSeconds: 300, AdminThreshold: threshold}
	for range 3 {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		r.keys = append(r.keys, priv)
		r.cfg.AdminKeys = append(r.cfg.AdminKeys, hex.EncodeToString(pub))
	}
	for _, m := range mut {
		m(r.cfg)
	}
	var err error
	if r.v, err = newAdminVerifier(r.cfg); err != nil {
		t.Fatal(err)
	}
	return r
}

type authOpt struct {
	domain  string
	issued  time.Time
	expires time.Time
	nonce   []byte
}

// sign makes a v2 authorization for (op, keyset) over body with the given keys, issued now (+ delta).
func sign(t *testing.T, op, keyset string, body proto.Message, o authOpt, keys ...ed25519.PrivateKey) *pb.AdminAuth {
	t.Helper()
	if o.issued.IsZero() {
		o.issued = time.Now().Add(time.Second)
	}
	if o.expires.IsZero() {
		o.expires = o.issued.Add(10 * time.Minute)
	}
	if o.nonce == nil {
		o.nonce = make([]byte, admin.NonceSize)
		rand.Read(o.nonce)
	}
	h, err := admin.BodyHash(op, body)
	if err != nil {
		t.Fatal(err)
	}
	msg := admin.Message2(op, keyset, o.domain, h, o.issued.Unix(), o.expires.Unix(), o.nonce)
	a := &pb.AdminAuthV2{Domain: o.domain, IssuedUnix: o.issued.Unix(), ExpiresUnix: o.expires.Unix(), Nonce: o.nonce}
	for _, k := range keys {
		a.Signatures = append(a.Signatures, &pb.AdminSignature{PublicKey: k.Public().(ed25519.PublicKey), Signature: ed25519.Sign(k, msg)})
	}
	return &pb.AdminAuth{V2: a}
}

func wantRefused(t *testing.T, what string, err error, contains string) {
	t.Helper()
	if err == nil {
		t.Errorf("%s: accepted", what)
	} else if !strings.Contains(err.Error(), contains) {
		t.Errorf("%s: refused for another reason: %v (want %q)", what, err, contains)
	}
}

func TestAdminV2AcceptsAQuorumAndRefusesTheRest(t *testing.T) {
	r := newV2Rig(t, 2)
	k := r.keys
	body := admin.DKGBody("ks", pb.Scheme_SCHEME_ECDSA_2OF3, 0)
	good := func() *pb.AdminAuth { return sign(t, "dkg", "ks", body, authOpt{}, k[0], k[2]) }

	if key, err := r.v.check("dkg", "ks", body, good()); err != nil || strings.Count(key, ",") != 1 {
		t.Fatalf("2 of 3 refused or not reported: %q %v", key, err)
	}

	// a changed request field: signed for one scheme, sent with another
	wantRefused(t, "changed scheme", errOf(r.v.check("dkg", "ks", admin.DKGBody("ks", pb.Scheme_SCHEME_ED25519_2OF3, 0), good())), "does not verify")
	wantRefused(t, "changed curve (hd)", errOf(r.v.check("dkg", "ks", admin.DKGBody("ks", pb.Scheme_SCHEME_UNSPECIFIED, pb.Curve_CURVE_ED25519),
		sign(t, "dkg", "ks", admin.DKGBody("ks", pb.Scheme_SCHEME_UNSPECIFIED, pb.Curve_CURVE_SECP256K1), authOpt{}, k[0], k[1]))), "does not verify")
	// another keyset, another operation
	wantRefused(t, "another keyset", errOf(r.v.check("dkg", "other", admin.DKGBody("other", pb.Scheme_SCHEME_ECDSA_2OF3, 0), good())), "does not verify")
	wantRefused(t, "another operation", errOf(r.v.check("refresh", "ks", admin.RefreshBody("ks"), sign(t, "dkg", "ks", admin.RefreshBody("ks"), authOpt{}, k[0], k[1]))), "does not verify")
	// the deployment
	wantRefused(t, "another domain", errOf(r.v.check("dkg", "ks", body, sign(t, "dkg", "ks", body, authOpt{domain: "staging"}, k[0], k[1]))), "domain")
	// the quorum
	wantRefused(t, "one signer of two", errOf(r.v.check("dkg", "ks", body, sign(t, "dkg", "ks", body, authOpt{}, k[1]))), "1 signature(s), 2 needed")
	wantRefused(t, "the same key twice", errOf(r.v.check("dkg", "ks", body, sign(t, "dkg", "ks", body, authOpt{}, k[1], k[1]))), "twice")
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	wantRefused(t, "an unknown key beside enough good ones", errOf(r.v.check("dkg", "ks", body, sign(t, "dkg", "ks", body, authOpt{}, k[0], k[1], stranger))), "not a configured admin key")
	wantRefused(t, "only unknown keys", errOf(r.v.check("dkg", "ks", body, sign(t, "dkg", "ks", body, authOpt{}, stranger, stranger))), "twice")
	// a forged signature next to good ones spoils the whole authorization
	bad := sign(t, "dkg", "ks", body, authOpt{}, k[0], k[1])
	bad.V2.Signatures[1].Signature[0] ^= 1
	wantRefused(t, "a damaged signature", errOf(r.v.check("dkg", "ks", body, bad)), "does not verify")
	// time
	now := time.Now()
	wantRefused(t, "expired", errOf(r.v.check("dkg", "ks", body, sign(t, "dkg", "ks", body, authOpt{issued: now.Add(-20 * time.Minute), expires: now.Add(-10 * time.Minute)}, k[0], k[1]))), "expired")
	wantRefused(t, "valid for longer than the party allows", errOf(r.v.check("dkg", "ks", body, sign(t, "dkg", "ks", body, authOpt{issued: now.Add(time.Second), expires: now.Add(3 * time.Hour)}, k[0], k[1]))), "at most")
	wantRefused(t, "issued in the future", errOf(r.v.check("dkg", "ks", body, sign(t, "dkg", "ks", body, authOpt{issued: now.Add(time.Hour), expires: now.Add(90 * time.Minute)}, k[0], k[1]))), "future")
	wantRefused(t, "issued before the party started", errOf(r.v.check("dkg", "ks", body, sign(t, "dkg", "ks", body, authOpt{issued: now.Add(-time.Minute), expires: now.Add(30 * time.Minute)}, k[0], k[1]))), "before this party's start")
	// malformed
	wantRefused(t, "no signatures", errOf(r.v.check("dkg", "ks", body, &pb.AdminAuth{V2: &pb.AdminAuthV2{Nonce: make([]byte, admin.NonceSize)}})), "no signatures")
	wantRefused(t, "short nonce", errOf(r.v.check("dkg", "ks", body, sign(t, "dkg", "ks", body, authOpt{nonce: []byte("short")}, k[0], k[1]))), "nonce")
	wantRefused(t, "nothing", errOf(r.v.check("dkg", "ks", body, nil)), "missing")
	mixed := good()
	mixed.Signature = make([]byte, 64)
	wantRefused(t, "v1 and v2 fields together", errOf(r.v.check("dkg", "ks", body, mixed)), "both set")
}

func errOf(_ string, err error) error { return err }

// One authorization is used once: the same bytes again, the same message signed by another pair or in another order, all count as the same.
func TestAdminV2ReplayIsKeyedOnTheMessage(t *testing.T) {
	r := newV2Rig(t, 2)
	k := r.keys
	body := admin.RefreshBody("ks")
	nonce := make([]byte, admin.NonceSize)
	rand.Read(nonce)
	o := authOpt{nonce: nonce, issued: time.Now().Add(time.Second)}
	o.expires = o.issued.Add(10 * time.Minute)
	if _, err := r.v.check("refresh", "ks", body, sign(t, "refresh", "ks", body, o, k[0], k[1])); err != nil {
		t.Fatal(err)
	}
	wantRefused(t, "the same authorization again", errOf(r.v.check("refresh", "ks", body, sign(t, "refresh", "ks", body, o, k[0], k[1]))), "already used")
	wantRefused(t, "the same message, signers in another order", errOf(r.v.check("refresh", "ks", body, sign(t, "refresh", "ks", body, o, k[1], k[0]))), "already used")
	wantRefused(t, "the same message, a different pair", errOf(r.v.check("refresh", "ks", body, sign(t, "refresh", "ks", body, o, k[1], k[2]))), "already used")
	wantRefused(t, "the same message with a third signature added", errOf(r.v.check("refresh", "ks", body, sign(t, "refresh", "ks", body, o, k[2], k[1], k[0]))), "already used")
	// a reused nonce on another request is a different message
	other := admin.RefreshBody("ks2")
	if _, err := r.v.check("refresh", "ks2", other, sign(t, "refresh", "ks2", other, o, k[0], k[1])); err != nil {
		t.Fatalf("the same nonce on another request: %v", err)
	}
}

func TestAdminV2SeenSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	r := newV2Rig(t, 2)
	r.v.persistOn(nil, dir)
	body := admin.UnfreezeBody("ks")
	a := sign(t, "unfreeze", "ks", body, authOpt{}, r.keys[0], r.keys[1])
	if _, err := r.v.check("unfreeze", "ks", body, a); err != nil {
		t.Fatal(err)
	}
	// "crash" after the record, before the operation ran; a new process with the same files
	v2, err := newAdminVerifier(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	v2.persistOn(nil, dir)
	v2.start = time.Now().Add(-time.Hour) // the start-time rule alone would not catch it: only the file does
	wantRefused(t, "replay after a restart", errOf(v2.check("unfreeze", "ks", body, a)), "already used")
	// the record is pruned once the authorization has expired
	v2.now = func() time.Time { return time.Now().Add(time.Hour) }
	b := admin.UnfreezeBody("ks3")
	if _, err := v2.check("unfreeze", "ks3", b, sign(t, "unfreeze", "ks3", b, authOpt{issued: time.Now().Add(time.Hour), expires: time.Now().Add(time.Hour + 10*time.Minute)}, r.keys[0], r.keys[1])); err != nil {
		t.Fatal(err)
	}
	if len(v2.seen2) != 1 {
		t.Fatalf("expired record not pruned: %d entries", len(v2.seen2))
	}
}

func TestAdminV1OffOnceAThresholdIsSet(t *testing.T) {
	// no threshold: v1 still works (the roll-over starts here), counted
	r := newV2Rig(t, 0)
	pub := r.keys[0].Public().(ed25519.PublicKey)
	if len(pub) == 0 {
		t.Fatal()
	}
	a := admin.Sign(r.keys[0], "refresh", "ks", time.Now())
	if _, err := r.v.check("refresh", "ks", admin.RefreshBody("ks"), a); err != nil {
		t.Fatalf("v1 refused before a threshold is set: %v", err)
	}
	if r.v.v1Accepted.Load() != 1 {
		t.Error("a v1 acceptance was not counted")
	}
	// a v2 authorization with one signature works too when no threshold is set (threshold 1)
	body := admin.RefreshBody("ks")
	if _, err := r.v.check("refresh", "ks", body, sign(t, "refresh", "ks", body, authOpt{}, r.keys[2])); err != nil {
		t.Fatalf("v2 with threshold unset: %v", err)
	}

	// threshold set: v1 refused, nothing counted, and no fallback
	r2 := newV2Rig(t, 2)
	wantRefused(t, "v1 with a threshold set", errOf(r2.v.check("refresh", "ks", body, admin.Sign(r2.keys[0], "refresh", "ks", time.Now()))), "no longer accepts the v1")
	if r2.v.v1Accepted.Load() != 0 {
		t.Error("a refused v1 was counted")
	}
	// the explicit switch for the roll-over
	yes := true
	r3 := newV2Rig(t, 2, func(c *Config) { c.AdminAllowV1 = &yes })
	if _, err := r3.v.check("refresh", "ks", body, admin.Sign(r3.keys[0], "refresh", "ks", time.Now())); err != nil {
		t.Fatalf("v1 with admin_allow_v1: %v", err)
	}
	// and explicitly off with no threshold
	no := false
	r4 := newV2Rig(t, 0, func(c *Config) { c.AdminAllowV1 = &no })
	wantRefused(t, "v1 with admin_allow_v1 false", errOf(r4.v.check("refresh", "ks", body, admin.Sign(r4.keys[0], "refresh", "ks", time.Now()))), "no longer accepts the v1")
}

func TestAdminConfigChecks(t *testing.T) {
	r := newV2Rig(t, 4)
	if err := r.cfg.Validate(); err == nil || !strings.Contains(err.Error(), "admin_threshold") {
		t.Errorf("threshold above the number of keys: %v", err)
	}
	r = newV2Rig(t, 2, func(c *Config) { c.AdminKeys = append(c.AdminKeys, c.AdminKeys[0]) })
	if err := r.cfg.Validate(); err == nil || !strings.Contains(err.Error(), "listed twice") {
		t.Errorf("a key listed twice: %v", err)
	}
}
