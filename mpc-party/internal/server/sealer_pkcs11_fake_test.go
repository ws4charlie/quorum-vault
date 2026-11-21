package server

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/pkcs11"
)

// fakeHSM is an in-memory PKCS#11 module with the rules of one HSM family. It is not SoftHSM and not CloudHSM: it imposes the rules the sealer
// has to live with, so the whole contract runs in every CI job without a token store.
//
// CloudHSM rules (AWS CloudHSM Client SDK 5 documentation, see docs/runbooks/cloudhsm-sealer.md): the HSM makes the IV and ignores the one passed
// in, one AES-GCM call takes at most 16224 bytes, the login PIN is "user:password", sessions are read-write only.
type fakeHSM struct {
	mu sync.Mutex

	hsmIV         bool   // the HSM makes the IV
	maxData       int    // bytes per AES-GCM call, 0 = no limit
	pin           string // exact PIN accepted, "" = any
	rejectPrivate bool   // CKA_PRIVATE in a key template is refused
	badTagCode    uint   // code returned for a failed GCM check
	zeroIV        bool   // a broken HSM that returns an all-zero IV

	label    string
	keys     map[string]cipher.AEAD // by label
	handles  map[pkcs11.ObjectHandle]string
	byLabel  map[string]pkcs11.ObjectHandle
	nextObj  pkcs11.ObjectHandle
	findLbl  string
	attrs    map[string]map[uint]bool
	sessions map[pkcs11.SessionHandle]bool
	next     pkcs11.SessionHandle
	loggedIn bool

	throttle        int // the next N encrypt calls fail with CKR_FUNCTION_FAILED
	throttleDecInit int // the next N decrypt calls fail in C_DecryptInit with CKR_FUNCTION_FAILED
	calls           map[string]int
	logins          int
	maxGCMLen       int
}

func newFakeHSM(label string, cloud bool) *fakeHSM {
	f := &fakeHSM{label: label, keys: map[string]cipher.AEAD{}, handles: map[pkcs11.ObjectHandle]string{}, byLabel: map[string]pkcs11.ObjectHandle{}, nextObj: 0, attrs: map[string]map[uint]bool{}, sessions: map[pkcs11.SessionHandle]bool{}, next: 100,
		badTagCode: pkcs11.CKR_ENCRYPTED_DATA_INVALID, calls: map[string]int{}}
	if cloud {
		f.hsmIV, f.maxData, f.rejectPrivate, f.badTagCode = true, cloudhsmMaxData, true, pkcs11.CKR_FUNCTION_FAILED
	}
	return f
}

func (f *fakeHSM) GetInfo() (pkcs11.Info, error) {
	return pkcs11.Info{ManufacturerID: "Fake HSM Inc", LibraryDescription: "contract test double"}, nil
}
func (f *fakeHSM) GetSlotList(bool) ([]uint, error) { return []uint{7}, nil }
func (f *fakeHSM) GetTokenInfo(uint) (pkcs11.TokenInfo, error) {
	return pkcs11.TokenInfo{Label: f.label, ManufacturerID: "Fake HSM Inc", Model: "fake"}, nil
}

func (f *fakeHSM) OpenSession(_, flags uint) (pkcs11.SessionHandle, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.hsmIV && flags&pkcs11.CKF_RW_SESSION == 0 {
		return 0, pkcs11.Error(pkcs11.CKR_SESSION_READ_ONLY) // CloudHSM: no read-only sessions
	}
	f.next++
	f.sessions[f.next] = true
	return f.next, nil
}

func (f *fakeHSM) CloseSession(s pkcs11.SessionHandle) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.sessions, s)
	if len(f.sessions) == 0 {
		f.loggedIn = false // PKCS#11: the login ends with the last session
	}
	return nil
}

func (f *fakeHSM) Login(s pkcs11.SessionHandle, _ uint, pin string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logins++
	if !f.sessions[s] {
		return pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}
	if f.pin != "" && pin != f.pin {
		return pkcs11.Error(pkcs11.CKR_PIN_INCORRECT)
	}
	f.loggedIn = true
	return nil
}

// drop is the HSM going away: every session is invalid and the login is gone, as after a lost connection to the cluster.
func (f *fakeHSM) drop() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sessions = map[pkcs11.SessionHandle]bool{}
	f.loggedIn = false
}

func (f *fakeHSM) check(s pkcs11.SessionHandle) error {
	if !f.sessions[s] {
		return pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}
	if !f.loggedIn {
		return pkcs11.Error(pkcs11.CKR_USER_NOT_LOGGED_IN)
	}
	return nil
}

func (f *fakeHSM) FindObjectsInit(s pkcs11.SessionHandle, t []*pkcs11.Attribute) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls["find"]++
	f.findLbl = pkcs11WrapKeyLabel
	for _, a := range t {
		if a.Type == pkcs11.CKA_LABEL {
			f.findLbl = string(a.Value)
		}
	}
	return f.check(s)
}
func (f *fakeHSM) FindObjects(s pkcs11.SessionHandle, _ int) ([]pkcs11.ObjectHandle, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if h, ok := f.byLabel[f.findLbl]; ok {
		return []pkcs11.ObjectHandle{h}, false, nil
	}
	return nil, false, nil
}

func (f *fakeHSM) DestroyObject(s pkcs11.SessionHandle, h pkcs11.ObjectHandle) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.check(s); err != nil {
		return err
	}
	label, ok := f.handles[h]
	if !ok {
		return pkcs11.Error(pkcs11.CKR_OBJECT_HANDLE_INVALID)
	}
	delete(f.handles, h)
	delete(f.byLabel, label)
	delete(f.keys, label)
	delete(f.attrs, label)
	return nil
}

func (f *fakeHSM) keyOf(h pkcs11.ObjectHandle) cipher.AEAD     { return f.keys[f.handles[h]] }
func (f *fakeHSM) FindObjectsFinal(pkcs11.SessionHandle) error { return nil }

func (f *fakeHSM) GenerateKey(s pkcs11.SessionHandle, tmpl []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.check(s); err != nil {
		return 0, err
	}
	have := map[uint]bool{}
	label := pkcs11WrapKeyLabel
	for _, a := range tmpl {
		if a.Type == pkcs11.CKA_LABEL {
			label = string(a.Value)
		}
		if a.Type == pkcs11.CKA_PRIVATE && f.rejectPrivate {
			return 0, pkcs11.Error(pkcs11.CKR_ATTRIBUTE_TYPE_INVALID)
		}
		if len(a.Value) == 1 {
			have[a.Type] = a.Value[0] == 1
		}
	}
	f.attrs[label] = have
	k := make([]byte, 32)
	rand.Read(k)
	blk, _ := aes.NewCipher(k)
	g, _ := cipher.NewGCM(blk)
	f.keys[label] = g
	f.nextObj++
	f.handles[f.nextObj] = label
	f.byLabel[label] = f.nextObj
	return f.nextObj, nil
}

func (f *fakeHSM) GCMEncrypt(s pkcs11.SessionHandle, h pkcs11.ObjectHandle, iv, aad, pt []byte) ([]byte, []byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls["encrypt"]++
	if err := f.check(s); err != nil {
		return nil, nil, opErr("C_Encrypt", err)
	}
	if f.throttle > 0 {
		f.throttle--
		return nil, nil, opErr("C_Encrypt", pkcs11.Error(pkcs11.CKR_FUNCTION_FAILED))
	}
	if f.maxData > 0 && len(pt) > f.maxData {
		return nil, nil, opErr("C_Encrypt", pkcs11.Error(pkcs11.CKR_MECHANISM_INVALID))
	}
	used := iv
	if f.hsmIV {
		used = make([]byte, envelopeIVLen)
		if !f.zeroIV {
			rand.Read(used)
		}
	}
	return used, f.keyOf(h).Seal(nil, used, pt, aad), nil
}

func (f *fakeHSM) GCMDecrypt(s pkcs11.SessionHandle, h pkcs11.ObjectHandle, iv, aad, ct []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls["decrypt"]++
	if err := f.check(s); err != nil {
		return nil, opErr("C_Decrypt", err)
	}
	if f.throttleDecInit > 0 {
		f.throttleDecInit--
		return nil, opErr("C_DecryptInit", pkcs11.Error(pkcs11.CKR_FUNCTION_FAILED))
	}
	pt, err := f.keyOf(h).Open(nil, iv, ct, aad)
	if err != nil {
		return nil, opErr("C_Decrypt", pkcs11.Error(f.badTagCode))
	}
	return pt, nil
}

func fakeSealer(t *testing.T, f *fakeHSM, prof profile) *PKCS11Sealer {
	t.Helper()
	s, err := newPKCS11SealerOn(f, prof, "fake.so", f.label, "user:"+randHex(8))
	if err != nil {
		t.Fatal(err)
	}
	s.sleep = func(time.Duration) {}
	return s
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

type profileCase struct {
	name       string
	prof       profile
	newFake    func(label string) *fakeHSM
	reconnects bool
	chunked    bool
}

var profileCases = []profileCase{
	{"softhsm", softHSMProfile, func(l string) *fakeHSM { return newFakeHSM(l, false) }, false, false},
	{"cloudhsm", cloudHSMProfile, func(l string) *fakeHSM { return newFakeHSM(l, true) }, true, true},
}

// contractSealer is what a hardware run (sealer_pkcs11_cloudhsm_hw_test.go) and the fake run share: the sealer's whole contract that does
// not need to break the HSM.
func contractSealer(t *testing.T, s *PKCS11Sealer, other *PKCS11Sealer, reopen func() *PKCS11Sealer) {
	t.Helper()
	aad := []byte("qv-mpc-party|keyset|v2|A|ks|1|ecdsa")
	for _, n := range []int{0, 1, 100, cloudhsmChunk - 1, cloudhsmChunk, cloudhsmChunk + 1, 3*cloudhsmChunk + 17} {
		secret := make([]byte, n)
		rand.Read(secret)
		sealed, err := s.Seal(aad, secret)
		if err != nil {
			t.Fatalf("seal %d bytes: %v", n, err)
		}
		if n >= 16 && bytes.Contains(sealed, secret[:16]) {
			t.Fatalf("%d bytes: plaintext visible in the envelope", n)
		}
		got, err := s.Open(aad, sealed)
		if err != nil || !bytes.Equal(got, secret) {
			t.Fatalf("round trip %d bytes: %v", n, err)
		}
		// restart: a new sealer on the same token opens it
		if reopen != nil {
			got, err = reopen().Open(aad, sealed)
			if err != nil || !bytes.Equal(got, secret) {
				t.Fatalf("restart, %d bytes: %v", n, err)
			}
		}
	}
	sealed, err := s.Seal(aad, []byte("the share"))
	if err != nil {
		t.Fatal(err)
	}
	// Two seals of one value differ (a new IV each time).
	again, _ := s.Seal(aad, []byte("the share"))
	if bytes.Equal(sealed, again) {
		t.Error("two seals of the same value are identical: IV reused")
	}
	rejects := map[string]func() error{
		"other role":   func() error { _, e := s.Open([]byte("qv-mpc-party|keyset|v2|B|ks|1|ecdsa"), sealed); return e },
		"other keyset": func() error { _, e := s.Open([]byte("qv-mpc-party|keyset|v2|A|other|1|ecdsa"), sealed); return e },
		"no aad":       func() error { _, e := s.Open(nil, sealed); return e },
		"garbage":      func() error { _, e := s.Open(aad, []byte("not json")); return e },
		"unknown ver":  func() error { _, e := s.Open(aad, []byte(`{"v":9}`)); return e },
		"attested ver": func() error {
			_, e := s.Open(aad, []byte(`{"v":2,"iv":"AAAAAAAAAAAAAAAA","ct":"AAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`))
			return e
		},
		"empty": func() error { _, e := s.Open(aad, nil); return e },
		"tampered byte": func() error {
			x := bytes.Replace(sealed, []byte(`"ct":"`), []byte(`"ct":"A`), 1)
			_, e := s.Open(aad, x)
			return e
		},
	}
	if other != nil {
		rejects["other token's key"] = func() error { _, e := other.Open(aad, sealed); return e }
	}
	for name, f := range rejects {
		err := f()
		if err == nil {
			t.Errorf("%s: opened", name)
		} else if !errors.Is(err, ErrOpen) {
			t.Errorf("%s: want ErrOpen, got %T %v", name, err, err)
		}
	}
}

func TestSealerContractOnFake(t *testing.T) {
	for _, pc := range profileCases {
		t.Run(pc.name, func(t *testing.T) {
			f, o := pc.newFake("tok"), pc.newFake("tok")
			s := fakeSealer(t, f, pc.prof)
			contractSealer(t, s, fakeSealer(t, o, pc.prof), func() *PKCS11Sealer { return fakeSealer(t, f, pc.prof) })
			if f.hsmIV && f.calls["encrypt"] == 0 {
				t.Fatal("no encrypt calls")
			}
		})
	}
}

func TestSealerWrapKeyTemplate(t *testing.T) {
	for _, pc := range profileCases {
		f := pc.newFake("tok")
		fakeSealer(t, f, pc.prof)
		a := f.attrs[pkcs11WrapKeyLabel]
		if a[pkcs11.CKA_EXTRACTABLE] || !a[pkcs11.CKA_SENSITIVE] || !a[pkcs11.CKA_TOKEN] || !a[pkcs11.CKA_ENCRYPT] || !a[pkcs11.CKA_DECRYPT] {
			t.Errorf("%s: wrap key must be sensitive, non-extractable, persistent, encrypt+decrypt: %v", pc.name, a)
		}
	}
	// CloudHSM rules refuse CKA_PRIVATE: the softhsm profile would fail there, the cloudhsm profile does not use it.
	f := newFakeHSM("tok", true)
	if _, err := newPKCS11SealerOn(f, softHSMProfile, "fake.so", "tok", "x"); err == nil {
		t.Error("softhsm profile on CloudHSM rules: want an error")
	}
}

func TestEnvelopeV3Binding(t *testing.T) {
	f := newFakeHSM("tok", true)
	s := fakeSealer(t, f, cloudHSMProfile)
	aad := []byte("aad")
	secret := bytes.Repeat([]byte{7}, 2*cloudhsmChunk+5) // 3 parts
	sealed, err := s.Seal(aad, secret)
	if err != nil {
		t.Fatal(err)
	}
	var e envelopeHSM
	if err := json.Unmarshal(sealed, &e); err != nil || e.V != envelopeVersionHSM || e.P != ProviderCloudHSM || len(e.Parts) != 3 || len(e.ID) != envelopeIDLen || e.Len != len(secret) {
		t.Fatalf("envelope: %+v %v", e, err)
	}
	mut := map[string]func(e envelopeHSM) envelopeHSM{
		"swap parts":  func(e envelopeHSM) envelopeHSM { e.Parts[0], e.Parts[1] = e.Parts[1], e.Parts[0]; return e },
		"drop a part": func(e envelopeHSM) envelopeHSM { e.Parts = e.Parts[:2]; return e },
		"duplicate":   func(e envelopeHSM) envelopeHSM { e.Parts = append(e.Parts, e.Parts[2]); return e },
		"no parts":    func(e envelopeHSM) envelopeHSM { e.Parts = nil; return e },
		"truncate":    func(e envelopeHSM) envelopeHSM { e.Parts[2].CT = e.Parts[2].CT[:len(e.Parts[2].CT)-1]; return e },
		"other id":    func(e envelopeHSM) envelopeHSM { e.ID = bytes.Repeat([]byte{1}, envelopeIDLen); return e },
		"other len":   func(e envelopeHSM) envelopeHSM { e.Len++; return e },
		"short iv":    func(e envelopeHSM) envelopeHSM { e.Parts[0].IV = e.Parts[0].IV[:5]; return e },
	}
	for name, m := range mut {
		var c envelopeHSM
		json.Unmarshal(sealed, &c)
		b, _ := json.Marshal(m(c))
		if _, err := s.Open(aad, b); !errors.Is(err, ErrOpen) {
			t.Errorf("%s: want ErrOpen, got %v", name, err)
		}
	}
	// No call to the HSM exceeds its limit: the fake refuses larger ones.
}

// A blob sealed by the softhsm profile (v1) opens under the cloudhsm profile on a token with the same key, and the other way round (v3).
func TestEnvelopeCompatAcrossProfiles(t *testing.T) {
	f := newFakeHSM("tok", true) // the sealer stores the IV the module returns, so both profiles work on it
	f.rejectPrivate = false
	old := fakeSealer(t, f, softHSMProfile)
	cl := fakeSealer(t, f, cloudHSMProfile)
	aad := []byte("aad")
	v1, err := old.Seal(aad, []byte("secret"))
	if err != nil || !bytes.Contains(v1, []byte(`"v":1`)) {
		t.Fatalf("v1: %s %v", v1, err)
	}
	if pt, err := cl.Open(aad, v1); err != nil || string(pt) != "secret" {
		t.Fatalf("cloudhsm profile opens v1: %q %v", pt, err)
	}
	v3, err := cl.Seal(aad, []byte("secret"))
	if err != nil || !bytes.Contains(v3, []byte(`"v":3`)) {
		t.Fatalf("v3: %s %v", v3, err)
	}
	if pt, err := old.Open(aad, v3); err != nil || string(pt) != "secret" {
		t.Fatalf("softhsm profile opens v3: %q %v", pt, err)
	}
}

func TestReconnectAfterSessionLoss(t *testing.T) {
	for _, pc := range profileCases {
		t.Run(pc.name, func(t *testing.T) {
			f := pc.newFake("tok")
			s := fakeSealer(t, f, pc.prof)
			aad := []byte("aad")
			sealed, err := s.Seal(aad, []byte("x"))
			if err != nil {
				t.Fatal(err)
			}
			f.drop() // the HSM went away and came back: sessions and login are gone
			got, err := s.Open(aad, sealed)
			if pc.reconnects {
				if err != nil || string(got) != "x" {
					t.Fatalf("open after drop: %q %v", got, err)
				}
				if _, err := s.Seal(aad, []byte("y")); err != nil {
					t.Fatalf("seal after reconnect: %v", err)
				}
				return
			}
			var ue *UnavailableError
			if !errors.As(err, &ue) {
				t.Fatalf("softhsm profile after a lost session: want UnavailableError (as before), got %v", err)
			}
		})
	}
}

func TestThrottleIsRetriedThenUnavailable(t *testing.T) {
	f := newFakeHSM("tok", true)
	s := fakeSealer(t, f, cloudHSMProfile)
	f.throttle = 2
	if _, err := s.Seal([]byte("a"), []byte("x")); err != nil {
		t.Fatalf("two throttled calls must be retried: %v", err)
	}
	f.throttle = 3
	_, err := s.Seal([]byte("a"), []byte("x"))
	var ue *UnavailableError
	if !errors.As(err, &ue) {
		t.Fatalf("persistent throttling: want UnavailableError, got %v", err)
	}
	f.throttle = 0
	if _, err := s.Seal([]byte("a"), []byte("x")); err != nil {
		t.Fatalf("recovers: %v", err)
	}
}

// A tampered blob on CloudHSM may be reported as CKR_FUNCTION_FAILED: it must be ErrOpen, not an outage and not retried as a throttle.
func TestBadTagIsNotAnOutageOrRetried(t *testing.T) {
	f := newFakeHSM("tok", true)
	s := fakeSealer(t, f, cloudHSMProfile)
	sealed, _ := s.Seal([]byte("a"), []byte("x"))
	before := f.calls["decrypt"]
	if _, err := s.Open([]byte("b"), sealed); !errors.Is(err, ErrOpen) {
		t.Fatalf("want ErrOpen, got %v", err)
	}
	// the failed decrypt, then the probe's decrypt; a retry would add two more
	if n := f.calls["decrypt"] - before; n != 2 {
		t.Errorf("decrypt calls = %d, want 2 (no retry)", n)
	}
}

func TestHSMReturningZeroIVIsRefused(t *testing.T) {
	f := newFakeHSM("tok", true)
	f.zeroIV = true
	s := fakeSealer(t, f, cloudHSMProfile) // the key creation does not encrypt
	if _, err := s.Seal([]byte("a"), []byte("x")); err == nil {
		t.Fatal("sealed with an all-zero IV")
	}
}

func TestCloudHSMProfileInputs(t *testing.T) {
	dir := t.TempDir()
	pinFile := func(content string) string {
		p := filepath.Join(dir, randHex(4))
		if err := os.WriteFile(p, []byte(content), 0o400); err != nil {
			t.Fatal(err)
		}
		return p
	}
	secret := randHex(6)
	t.Setenv("QV_TEST_CLOUD_PIN", "user:"+secret)
	for name, tc := range map[string]struct {
		c    SealerConfig
		want string
	}{
		"pin from env":      {SealerConfig{Provider: "cloudhsm", Token: "t", PinEnv: "QV_TEST_CLOUD_PIN", Lib: "/nonexistent"}, "use pin_file"},
		"no colon":          {SealerConfig{Provider: "cloudhsm", Token: "t", PinFile: pinFile(secret), Lib: "/nonexistent"}, "user:password"},
		"empty password":    {SealerConfig{Provider: "cloudhsm", Token: "t", PinFile: pinFile("user:"), Lib: "/nonexistent"}, "user:password"},
		"empty user":        {SealerConfig{Provider: "CloudHSM", Token: "t", PinFile: pinFile(":" + secret), Lib: "/nonexistent"}, "user:password"},
		"good pin, no lib":  {SealerConfig{Provider: "cloudhsm", Token: "t", PinFile: pinFile("user:" + secret), Lib: "/nonexistent"}, "library"},
		"unknown provider":  {SealerConfig{Provider: "yubihsm", Token: "t", PinFile: pinFile("x")}, "unknown provider"},
		"softhsm env stays": {SealerConfig{Provider: "softhsm", Token: "t", PinEnv: "QV_TEST_CLOUD_PIN", Lib: "/nonexistent"}, "library"},
	} {
		_, err := NewPKCS11Sealer(tc.c)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want %q, got %v", name, tc.want, err)
		} else if strings.Contains(err.Error(), secret) {
			t.Errorf("%s: the password is in the error", name)
		}
	}
	// A wrong login on the HSM is an error that does not show the PIN.
	f := newFakeHSM("tok", true)
	f.pin = "user:" + secret
	_, err := newPKCS11SealerOn(f, cloudHSMProfile, "fake.so", "tok", "user:wrong-"+secret)
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Errorf("wrong login: %v", err)
	}
}

// CloudHSM presents one token whose label the operator does not choose: a lone token is used (with a warning); several tokens must match.
func TestCloudHSMLoneTokenFallback(t *testing.T) {
	f := newFakeHSM("cavium", true)
	if _, err := newPKCS11SealerOn(f, cloudHSMProfile, "fake.so", "qv-party-1", "user:pw"); err != nil {
		t.Fatalf("lone token: %v", err)
	}
	if _, err := newPKCS11SealerOn(f, softHSMProfile, "fake.so", "qv-party-1", "user:pw"); err == nil {
		t.Fatal("softhsm profile must require the label")
	}
}

// Parts of two seals with the same key, associated data, part count and length must not combine: every tag is valid, the whole was never sealed.
func TestEnvelopeV3PartsOfTwoSealsDoNotMix(t *testing.T) {
	f := newFakeHSM("tok", true)
	s := fakeSealer(t, f, cloudHSMProfile)
	aad := []byte("same aad")
	a := bytes.Repeat([]byte{1}, 2*cloudhsmChunk+5)
	b := bytes.Repeat([]byte{2}, 2*cloudhsmChunk+5)
	sa, _ := s.Seal(aad, a)
	sb, _ := s.Seal(aad, b)
	var ea, eb envelopeHSM
	json.Unmarshal(sa, &ea)
	json.Unmarshal(sb, &eb)
	for i := range ea.Parts {
		m := ea
		m.Parts = append([]envelopePart(nil), ea.Parts...)
		m.Parts[i] = eb.Parts[i]
		raw, _ := json.Marshal(m)
		if _, err := s.Open(aad, raw); !errors.Is(err, ErrOpen) {
			t.Errorf("part %d taken from another seal: want ErrOpen, got %v", i, err)
		}
	}
	// Also with b's header: still different ids per part.
	m := eb
	m.Parts = append([]envelopePart(nil), eb.Parts...)
	m.Parts[0] = ea.Parts[0]
	raw, _ := json.Marshal(m)
	if _, err := s.Open(aad, raw); !errors.Is(err, ErrOpen) {
		t.Errorf("mixed with b's header: %v", err)
	}
	if got, err := s.Open(aad, sa); err != nil || !bytes.Equal(got, a) {
		t.Fatalf("untouched seal: %v", err)
	}
}

// A throttle on C_DecryptInit is an HSM error: retried (cloudhsm), and UNAVAILABLE when it persists; never "bad data", even though the probe works.
func TestThrottledDecryptSetupIsNotBadData(t *testing.T) {
	f := newFakeHSM("tok", true)
	s := fakeSealer(t, f, cloudHSMProfile)
	sealed, err := s.Seal([]byte("a"), []byte("share"))
	if err != nil {
		t.Fatal(err)
	}
	f.throttleDecInit = 1
	if got, err := s.Open([]byte("a"), sealed); err != nil || string(got) != "share" {
		t.Fatalf("one throttled C_DecryptInit must be retried: %q %v", got, err)
	}
	f.throttleDecInit = 3
	_, err = s.Open([]byte("a"), sealed)
	var ue *UnavailableError
	if !errors.As(err, &ue) || errors.Is(err, ErrOpen) {
		t.Fatalf("persistent throttle: want UnavailableError, got %v", err)
	}
	// softhsm profile: no retry, but still not bad data.
	g := newFakeHSM("tok", false)
	o := fakeSealer(t, g, softHSMProfile)
	sg, _ := o.Seal([]byte("a"), []byte("share"))
	g.throttleDecInit = 1
	if _, err := o.Open([]byte("a"), sg); errors.Is(err, ErrOpen) {
		t.Fatalf("softhsm profile: throttled setup reported as bad data: %v", err)
	}
}
