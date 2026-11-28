package server

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/miekg/pkcs11"
)

// Envelope versions written and read by the PKCS#11 sealer. Version 2 belongs to the attested sealer (sealer_attested.go); do not reuse it.
//
//	v1: {"v":1,"iv":b64,"ct":b64}                     one AES-256-GCM call, IV made by this process (SoftHSM profile).
//	v3: {"v":3,"p":"cloudhsm","id","len","parts":[{"iv","ct"}…]}  one AES-256-GCM call per part of at most cloudhsmChunk bytes, IV made by
//	                                                   the HSM and read back from the call. Each part's associated data holds the caller's
//	                                                   data, the envelope's random id (16 bytes, fresh per seal), the part index, the part
//	                                                   count and the total plaintext length: parts cannot be mixed between seals, moved,
//	                                                   dropped, duplicated or cut.
//
// Either version may carry "k": the label of the wrap key it was sealed under, written only when it is not the default label (pkcs11WrapKeyLabel). An
// envelope without it is under the default key. The sealer opens an envelope under the key it names, whatever label the party writes new ones under
// (`sealer.wrap_key_label`), which is what lets a party move its shares to a new wrap key one file at a time (mpc-party reseal).
//
// Both profiles open both versions, so a data directory sealed under one profile still opens under the other when the token holds the same key.
const (
	pkcs11WrapKeyLabel = "qv-share-wrap"
	envelopeVersion    = 1
	envelopeVersionHSM = 3
	envelopeIVLen      = 12
	envelopeTagBits    = 128

	// cloudhsmMaxData is AWS's documented limit for one AES-GCM call (16224 bytes, no multipart); parts are cut well below it so the tag fits too.
	cloudhsmMaxData  = 16224
	cloudhsmChunk    = 16000
	envelopeIDLen    = 16
	maxEnvelopeParts = 4096
)

// ErrOpen: the envelope does not decrypt under this token and AAD (wrong token, wrong AAD, tampered bytes: GCM cannot tell).
var ErrOpen = errors.New("sealer: cannot open envelope")

type envelope struct {
	V  int    `json:"v"`
	K  string `json:"k,omitempty"` // label of the wrap key; absent: the default label (every envelope written before wrap keys could be replaced)
	IV []byte `json:"iv"`
	CT []byte `json:"ct"`
}

type envelopePart struct {
	IV []byte `json:"iv"`
	CT []byte `json:"ct"`
}

type envelopeHSM struct {
	V     int            `json:"v"`
	K     string         `json:"k,omitempty"` // label of the wrap key, as in envelope
	P     string         `json:"p"`
	ID    []byte         `json:"id"`  // random, one per seal: every part is bound to it, so parts of two seals cannot be mixed
	Len   int            `json:"len"` // total plaintext length, bound into every part
	Parts []envelopePart `json:"parts"`
}

// Provider names for SealerConfig.Provider.
const (
	ProviderSoftHSM  = "softhsm"
	ProviderCloudHSM = "cloudhsm"
)

// p11 is the part of PKCS#11 the sealer uses. *pkcs11.Ctx (through realP11) is the production implementation; tests pass a fake that
// imposes the rules of a particular HSM. GCM is one call here because on CloudHSM the HSM makes the IV and only the library's parameter
// block can carry it back.
type p11 interface {
	GetInfo() (pkcs11.Info, error)
	GetSlotList(tokenPresent bool) ([]uint, error)
	GetTokenInfo(slot uint) (pkcs11.TokenInfo, error)
	OpenSession(slot, flags uint) (pkcs11.SessionHandle, error)
	CloseSession(sess pkcs11.SessionHandle) error
	Login(sess pkcs11.SessionHandle, userType uint, pin string) error
	FindObjectsInit(sess pkcs11.SessionHandle, tmpl []*pkcs11.Attribute) error
	FindObjects(sess pkcs11.SessionHandle, max int) ([]pkcs11.ObjectHandle, bool, error)
	FindObjectsFinal(sess pkcs11.SessionHandle) error
	GenerateKey(sess pkcs11.SessionHandle, tmpl []*pkcs11.Attribute) (pkcs11.ObjectHandle, error)
	DestroyObject(sess pkcs11.SessionHandle, obj pkcs11.ObjectHandle) error
	// GCMEncrypt returns the IV the HSM used (the one passed in when the HSM takes it, the HSM's own when it makes it) and the ciphertext with tag.
	GCMEncrypt(sess pkcs11.SessionHandle, key pkcs11.ObjectHandle, iv, aad, plaintext []byte) (usedIV, ct []byte, err error)
	GCMDecrypt(sess pkcs11.SessionHandle, key pkcs11.ObjectHandle, iv, aad, ct []byte) ([]byte, error)
}

type realP11 struct{ *pkcs11.Ctx }

func (r realP11) GenerateKey(sess pkcs11.SessionHandle, tmpl []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	return r.Ctx.GenerateKey(sess, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)}, tmpl)
}

func (r realP11) GCMEncrypt(sess pkcs11.SessionHandle, key pkcs11.ObjectHandle, iv, aad, pt []byte) ([]byte, []byte, error) {
	params := pkcs11.NewGCMParams(iv, aad, envelopeTagBits)
	defer params.Free()
	if err := r.Ctx.EncryptInit(sess, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, params)}, key); err != nil {
		return nil, nil, opErr("C_EncryptInit", err)
	}
	ct, err := r.Ctx.Encrypt(sess, pt)
	if err != nil {
		return nil, nil, opErr("C_Encrypt", err)
	}
	// The IV is read after the call: CloudHSM overwrites the one passed in; SoftHSM leaves it as passed.
	used := params.IV()
	if len(used) != envelopeIVLen {
		return nil, nil, opErr("C_Encrypt", fmt.Errorf("the module returned an IV of %d bytes, want %d", len(used), envelopeIVLen))
	}
	return used, ct, nil
}

func (r realP11) GCMDecrypt(sess pkcs11.SessionHandle, key pkcs11.ObjectHandle, iv, aad, ct []byte) ([]byte, error) {
	params := pkcs11.NewGCMParams(iv, aad, envelopeTagBits)
	defer params.Free()
	if err := r.Ctx.DecryptInit(sess, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, params)}, key); err != nil {
		return nil, opErr("C_DecryptInit", err)
	}
	pt, err := r.Ctx.Decrypt(sess, ct)
	if err != nil {
		return nil, opErr("C_Decrypt", err)
	}
	return pt, nil
}

// hsmOpError is a failed PKCS#11 call, with the call's name. withSession turns it into an *UnavailableError at the end; until then it lets the
// retry logic look at the code.
type hsmOpError struct {
	op  string
	err error
}

func (e *hsmOpError) Error() string { return fmt.Sprintf("hsm: %s: %v", e.op, e.err) }
func (e *hsmOpError) Unwrap() error { return e.err }

func opErr(op string, err error) error { return &hsmOpError{op: op, err: err} }

// profile is everything that differs between PKCS#11 modules. One value per provider; the sealer has no `if provider` anywhere else.
type profile struct {
	name string
	// hsmMakesIV: the HSM chooses the IV of every AES-GCM encryption and returns it (CloudHSM). Otherwise this process makes it.
	hsmMakesIV bool
	// maxData: bytes per AES-GCM call (0 = no limit); chunk is the part size used when it applies.
	chunk int
	// envelope version written.
	writeVersion int
	// pin checks the shape of the PIN and may forbid the environment as its source. It never returns the PIN in an error.
	pin func(c SealerConfig, pin string) error
	// pinFromEnvAllowed: pin_env is accepted.
	pinFromEnvAllowed bool
	// keyTemplate: attributes of the wrap key.
	keyTemplate func(label string) []*pkcs11.Attribute
	// requireRW: sessions must be read-write (CloudHSM supports no read-only session). Always true for the sealer today; kept for the fake.
	// tokenByLabelOnly: a token whose label does not match is an error; otherwise a lone token is accepted with a warning.
	tokenByLabelOnly bool
	// attempts and backoff: how often one operation is tried when the session or the device fails; each retry opens a new login session.
	attempts int
	backoff  time.Duration
	// retryFunctionFailed: CKR_FUNCTION_FAILED on a call that does not decrypt is a throttle to retry (CloudHSM).
	retryFunctionFailed bool
}

func baseKeyTemplate(private bool, label string) []*pkcs11.Attribute {
	t := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY), pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32), pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true), pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false), // non-exportable
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true), pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
	}
	if private {
		t = append(t, pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true))
	}
	return t
}

var softHSMProfile = profile{
	name: ProviderSoftHSM, writeVersion: envelopeVersion, pinFromEnvAllowed: true, tokenByLabelOnly: true,
	pin:         func(SealerConfig, string) error { return nil },
	keyTemplate: func(l string) []*pkcs11.Attribute { return baseKeyTemplate(true, l) },
	attempts:    1,
}

// cloudHSMProfile follows AWS's CloudHSM Client SDK 5 PKCS#11 documentation (docs/runbooks/cloudhsm-sealer.md lists each source and what is
// unverified): HSM-made IV, 16224 bytes per AES-GCM call, login PIN "user:password", read-write sessions only, throttling answered with
// CKR_FUNCTION_FAILED, no CKA_PRIVATE in the template (not confirmed as supported).
var cloudHSMProfile = profile{
	name: ProviderCloudHSM, hsmMakesIV: true, chunk: cloudhsmChunk, writeVersion: envelopeVersionHSM,
	pinFromEnvAllowed: false,
	pin: func(c SealerConfig, pin string) error {
		u, p, ok := strings.Cut(pin, ":")
		if !ok || u == "" || p == "" {
			return errors.New(`sealer pkcs11 (cloudhsm): the PIN must be "user:password" (the crypto user's name, a colon, its password)`)
		}
		return nil
	},
	keyTemplate:         func(l string) []*pkcs11.Attribute { return baseKeyTemplate(false, l) },
	attempts:            3,
	backoff:             100 * time.Millisecond,
	retryFunctionFailed: true,
}

// profileFor maps the provider to its profile. "" is the SoftHSM profile, accepted only in development and tests (NewPKCS11Sealer refuses it in production).
func profileFor(provider string) (profile, error) {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "", ProviderSoftHSM:
		return softHSMProfile, nil
	case ProviderCloudHSM:
		return cloudHSMProfile, nil
	}
	return profile{}, fmt.Errorf("sealer pkcs11: unknown provider %q (have: %s, %s)", provider, ProviderSoftHSM, ProviderCloudHSM)
}

// PKCS11Sealer seals under an AES-256 key that lives in one party's PKCS#11 token (SoftHSM in dev, an HSM in production).
// Party A uses token qv-party-1 and party B qv-party-2 (scripts/setup-softhsm.sh), each with its own key.
type PKCS11Sealer struct {
	api   p11
	prof  profile
	slot  uint
	label string // the token's label
	wrap  string // the label of the wrap key new envelopes are sealed under
	pin   string // kept so a lost login can be redone (reconnect); never logged, never in an error

	mu    sync.Mutex // guards login
	login pkcs11.SessionHandle
	// sleep is time.Sleep; tests replace it.
	sleep func(time.Duration)
}

// NewPKCS11Sealer loads the module, finds the token by label, logs in and makes sure the wrap key exists. Any problem is an
// error: the process must not start without a working token.
func NewPKCS11Sealer(c SealerConfig) (*PKCS11Sealer, error) {
	if strings.TrimSpace(c.Provider) == "" && productionEnv() {
		// An empty provider means the SoftHSM profile (process-made IV, pin_env allowed): a real HSM must be named, never guessed.
		return nil, errors.New("sealer pkcs11: provider is required in production (QV_ENV unset, or not dev or test): cloudhsm, or softhsm for development")
	}
	prof, err := profileFor(c.Provider)
	if err != nil {
		return nil, err
	}
	if c.Token == "" {
		return nil, errors.New("sealer pkcs11: token (label) is required")
	}
	if c.PinEnv != "" && productionEnv() {
		// The rule the gateway has (internal/hsm/pin.go): an environment variable is readable by anything that can dump the process environment.
		return nil, fmt.Errorf("sealer pkcs11: pin_env is refused in production (QV_ENV unset, or not dev or test): the PIN comes from pin_file only")
	}
	if c.PinEnv != "" && !prof.pinFromEnvAllowed {
		return nil, fmt.Errorf("sealer pkcs11 (%s): pin_env is not accepted for this provider: the PIN holds a password; use pin_file", prof.name)
	}
	pin, err := ReadPIN(c.PinEnv, c.PinFile)
	if err != nil {
		return nil, err
	}
	if err := prof.pin(c, pin); err != nil {
		return nil, err
	}
	lib := c.Lib
	if lib == "" {
		lib = defaultPKCS11Lib()
	}
	if _, err := os.Stat(lib); err != nil {
		return nil, fmt.Errorf("sealer pkcs11: library %s: %w", lib, err)
	}
	ctx, err := sharedCtx(lib)
	if err != nil {
		return nil, err
	}
	return newPKCS11SealerLabel(realP11{ctx}, prof, lib, c.Token, pin, c.WrapKeyLabel)
}

// WrapKeyLabelRE is what a wrap key label may look like.
var wrapKeyLabelRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// newPKCS11SealerOn is NewPKCS11Sealer on an already loaded module (tests give a fake).
func newPKCS11SealerOn(api p11, prof profile, libPath, token, pin string) (*PKCS11Sealer, error) {
	return newPKCS11SealerLabel(api, prof, libPath, token, pin, "")
}

// newPKCS11SealerLabel is newPKCS11SealerOn with the label of the wrap key new envelopes are sealed under ("" = the default label).
func newPKCS11SealerLabel(api p11, prof profile, libPath, token, pin, wrap string) (*PKCS11Sealer, error) {
	if wrap == "" {
		wrap = pkcs11WrapKeyLabel
	}
	if !wrapKeyLabelRE.MatchString(wrap) {
		return nil, fmt.Errorf("sealer pkcs11: wrap_key_label %q: letters, digits, dot, dash and underscore, 1 to 64 characters", wrap)
	}
	var libInfo pkcs11.Info
	if info, err := api.GetInfo(); err == nil {
		libInfo = info
	}
	if err := refuseSoftHSM(libInfo, nil, libPath); err != nil { // before the PIN is sent anywhere
		return nil, err
	}
	slots, err := api.GetSlotList(true)
	if err != nil {
		return nil, fmt.Errorf("sealer pkcs11: C_GetSlotList: %w", err)
	}
	slot, found := uint(0), false
	for _, sl := range slots {
		if info, err := api.GetTokenInfo(sl); err == nil && strings.TrimRight(info.Label, " \x00") == token {
			slot, found = sl, true
			break
		}
	}
	if !found && !prof.tokenByLabelOnly && len(slots) == 1 {
		// CloudHSM presents the cluster as one token; its label is not one this party chooses (unverified, see the runbook). One cluster per party.
		slog.Default().Warn("sealer pkcs11: no token has the configured label; using the only token the module offers", "token", token, "provider", prof.name)
		slot, found = slots[0], true
	}
	if !found {
		return nil, fmt.Errorf("sealer pkcs11: token %q not found in %s (run scripts/setup-softhsm.sh, or check SOFTHSM2_CONF)", token, libPath)
	}
	if tok, err := api.GetTokenInfo(slot); err == nil {
		if err := refuseSoftHSM(libInfo, &tok, libPath); err != nil {
			return nil, err
		}
	}
	s := &PKCS11Sealer{api: api, prof: prof, slot: slot, label: token, wrap: wrap, pin: pin, sleep: time.Sleep}
	if err := s.relogin(); err != nil {
		return nil, err
	}
	if err := s.withSession(func(sess pkcs11.SessionHandle) error { _, err := s.ensureKey(sess, s.wrap); return err }); err != nil {
		return nil, fmt.Errorf("sealer pkcs11: wrap key: %w", err)
	}
	return s, nil
}

// relogin (re)opens the long-lived login session. The application stays logged in while any session is open, so this one is kept open for
// the life of the process; per-operation sessions ride on it. After a lost connection to the HSM it is the one to redo.
func (s *PKCS11Sealer) relogin() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.login != 0 {
		s.api.CloseSession(s.login) // the session may already be dead; the error says nothing useful
		s.login = 0
	}
	sess, err := s.api.OpenSession(s.slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return fmt.Errorf("sealer pkcs11: C_OpenSession on %q: %w", s.label, err)
	}
	if err := s.api.Login(sess, pkcs11.CKU_USER, s.pin); err != nil && !isCKR(err, pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
		s.api.CloseSession(sess)
		return fmt.Errorf("sealer pkcs11: login to token %q failed (wrong PIN?): %w", s.label, err)
	}
	s.login = sess
	return nil
}

// retryable says whether a failed operation is worth another try on a fresh login: the session or the device went away, or (CloudHSM) the
// HSM is throttling. A failed decrypt is never retried on FUNCTION_FAILED: that is also how a bad tag may look.
func (s *PKCS11Sealer) retryable(err error) bool {
	var he *hsmOpError
	if !errors.As(err, &he) {
		return false
	}
	if isDeviceError(he.err) {
		return true
	}
	return s.prof.retryFunctionFailed && he.op != "C_Decrypt" && isCKR(he.err, pkcs11.CKR_FUNCTION_FAILED)
}

func (s *PKCS11Sealer) withSession(f func(pkcs11.SessionHandle) error) error {
	attempts := s.prof.attempts
	if attempts < 1 {
		attempts = 1
	}
	var err error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			s.sleep(s.prof.backoff << (i - 1))
			if rerr := s.relogin(); rerr != nil {
				err = opErr("reconnect", rerr)
				continue
			}
		}
		err = s.withSessionOnce(f)
		if err == nil || !s.retryable(err) {
			break
		}
	}
	var he *hsmOpError
	if errors.As(err, &he) {
		return &UnavailableError{Msg: he.Error()}
	}
	return err
}

func (s *PKCS11Sealer) withSessionOnce(f func(pkcs11.SessionHandle) error) error {
	sess, err := s.api.OpenSession(s.slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return opErr(fmt.Sprintf("C_OpenSession on %q", s.label), err)
	}
	defer s.api.CloseSession(sess)
	return f(sess)
}

func (s *PKCS11Sealer) findKey(sess pkcs11.SessionHandle, label string) (pkcs11.ObjectHandle, bool, error) {
	tmpl := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY), pkcs11.NewAttribute(pkcs11.CKA_LABEL, label)}
	if err := s.api.FindObjectsInit(sess, tmpl); err != nil {
		return 0, false, opErr("C_FindObjectsInit", err)
	}
	hs, _, err := s.api.FindObjects(sess, 1)
	s.api.FindObjectsFinal(sess)
	if err != nil {
		return 0, false, opErr("C_FindObjects", err)
	}
	if len(hs) == 0 {
		return 0, false, nil
	}
	return hs[0], true, nil
}

var createKeyMu sync.Mutex

func (s *PKCS11Sealer) ensureKey(sess pkcs11.SessionHandle, label string) (pkcs11.ObjectHandle, error) {
	if h, ok, err := s.findKey(sess, label); err != nil || ok {
		return h, err
	}
	createKeyMu.Lock()
	defer createKeyMu.Unlock()
	if h, ok, err := s.findKey(sess, label); err != nil || ok {
		return h, err
	}
	h, err := s.api.GenerateKey(sess, s.prof.keyTemplate(label))
	if err != nil {
		return 0, opErr("C_GenerateKey "+label, err)
	}
	return h, nil
}

// WrapLabel is the label of the wrap key new envelopes are sealed under.
func (s *PKCS11Sealer) WrapLabel() string { return s.wrap }

// HasKey says whether the token holds a wrap key with this label.
func (s *PKCS11Sealer) HasKey(label string) (bool, error) {
	var ok bool
	err := s.withSession(func(sess pkcs11.SessionHandle) (e error) { _, ok, e = s.findKey(sess, label); return })
	return ok, err
}

// DestroyKey removes the wrap key with this label from the token. It refuses the key this sealer seals under; the caller (reseal.go) checks that nothing
// on disk is sealed under it before it asks.
func (s *PKCS11Sealer) DestroyKey(label string) error {
	if label == s.wrap {
		return fmt.Errorf("sealer pkcs11: %q is the key this sealer seals under", label)
	}
	return s.withSession(func(sess pkcs11.SessionHandle) error {
		h, ok, err := s.findKey(sess, label)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("sealer pkcs11: token %q has no wrap key %q", s.label, label)
		}
		if err := s.api.DestroyObject(sess, h); err != nil {
			return opErr("C_DestroyObject "+label, err)
		}
		return nil
	})
}

// envelopeKeyLabel is the label of the wrap key an envelope was sealed under ("" for what is not an envelope).
func envelopeKeyLabel(sealed []byte) string {
	var p struct {
		V int    `json:"v"`
		K string `json:"k"`
	}
	if json.Unmarshal(sealed, &p) != nil || (p.V != envelopeVersion && p.V != envelopeVersionHSM) {
		return ""
	}
	if p.K == "" {
		return pkcs11WrapKeyLabel
	}
	return p.K
}

// partAAD binds a part of a v3 envelope to its place: a part cannot be moved, dropped, duplicated or taken from another envelope.
func partAAD(aad, id []byte, i, n, total int) []byte {
	out := make([]byte, 0, len(aad)+48)
	out = append(out, aad...)
	out = append(out, 0, 'q', 'v', '-', 'p', 'a', 'r', 't')
	out = append(out, id...)
	out = binary.BigEndian.AppendUint32(out, uint32(i))
	out = binary.BigEndian.AppendUint32(out, uint32(n))
	return binary.BigEndian.AppendUint64(out, uint64(total))
}

func (s *PKCS11Sealer) encrypt(sess pkcs11.SessionHandle, key pkcs11.ObjectHandle, aad, pt []byte) (iv, ct []byte, err error) {
	var in []byte
	if !s.prof.hsmMakesIV {
		in = make([]byte, envelopeIVLen)
		if _, err := rand.Read(in); err != nil {
			return nil, nil, err
		}
	} else {
		in = make([]byte, envelopeIVLen) // the HSM overwrites it
	}
	iv, ct, err = s.api.GCMEncrypt(sess, key, in, aad, pt)
	if err != nil {
		return nil, nil, err
	}
	if s.prof.hsmMakesIV && allZero(iv) {
		return nil, nil, opErr("C_Encrypt", errors.New("the HSM returned an all-zero IV: refusing to use it"))
	}
	return iv, ct, nil
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// Seal implements Sealer.
func (s *PKCS11Sealer) Seal(aad, plaintext []byte) ([]byte, error) {
	var out []byte
	err := s.withSession(func(sess pkcs11.SessionHandle) error {
		key, err := s.ensureKey(sess, s.wrap)
		if err != nil {
			return err
		}
		k := ""
		if s.wrap != pkcs11WrapKeyLabel {
			k = s.wrap
		}
		if s.prof.writeVersion == envelopeVersion {
			iv, ct, err := s.encrypt(sess, key, aad, plaintext)
			if err != nil {
				return err
			}
			out, err = json.Marshal(envelope{V: envelopeVersion, K: k, IV: iv, CT: ct})
			return err
		}
		chunk := s.prof.chunk
		n := (len(plaintext) + chunk - 1) / chunk
		if n == 0 {
			n = 1
		}
		id := make([]byte, envelopeIDLen)
		if _, err := rand.Read(id); err != nil {
			return err
		}
		parts := make([]envelopePart, 0, n)
		for i := 0; i < n; i++ {
			lo, hi := i*chunk, min((i+1)*chunk, len(plaintext))
			iv, ct, err := s.encrypt(sess, key, partAAD(aad, id, i, n, len(plaintext)), plaintext[lo:hi])
			if err != nil {
				return err
			}
			parts = append(parts, envelopePart{IV: iv, CT: ct})
		}
		out, err = json.Marshal(envelopeHSM{V: envelopeVersionHSM, K: k, P: s.prof.name, ID: id, Len: len(plaintext), Parts: parts})
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// parseEnvelope reads v1 and v3; it returns the parts with the associated data each one was sealed under.
func parseEnvelope(aad, sealed []byte) (parts []envelopePart, aads [][]byte, err error) {
	var probe struct {
		V int `json:"v"`
	}
	if err := json.Unmarshal(sealed, &probe); err != nil {
		return nil, nil, fmt.Errorf("%w: bad envelope: %v", ErrOpen, err)
	}
	switch probe.V {
	case envelopeVersion:
		var e envelope
		if err := json.Unmarshal(sealed, &e); err != nil || len(e.IV) != envelopeIVLen || len(e.CT) < envelopeTagBits/8 {
			return nil, nil, fmt.Errorf("%w: bad envelope (v=%d iv=%d ct=%d)", ErrOpen, e.V, len(e.IV), len(e.CT))
		}
		return []envelopePart{{IV: e.IV, CT: e.CT}}, [][]byte{aad}, nil
	case envelopeVersionHSM:
		var e envelopeHSM
		if err := json.Unmarshal(sealed, &e); err != nil || len(e.Parts) == 0 || len(e.Parts) > maxEnvelopeParts || len(e.ID) != envelopeIDLen || e.Len < 0 {
			return nil, nil, fmt.Errorf("%w: bad envelope (v=%d)", ErrOpen, probe.V)
		}
		for i, p := range e.Parts {
			if len(p.IV) != envelopeIVLen || len(p.CT) < envelopeTagBits/8 {
				return nil, nil, fmt.Errorf("%w: bad envelope (v=3 part %d)", ErrOpen, i)
			}
			aads = append(aads, partAAD(aad, e.ID, i, len(e.Parts), e.Len))
		}
		return e.Parts, aads, nil
	}
	return nil, nil, fmt.Errorf("%w: bad envelope (v=%d)", ErrOpen, probe.V)
}

// Open implements Sealer. A decryption failure is ErrOpen (the blob or the AAD is wrong); anything wrong with the token
// itself is an *UnavailableError, so the service answers UNAVAILABLE instead of crashing.
func (s *PKCS11Sealer) Open(aad, sealed []byte) ([]byte, error) {
	parts, aads, err := parseEnvelope(aad, sealed)
	if err != nil {
		return nil, err
	}
	var pt []byte
	keyLabel := envelopeKeyLabel(sealed)
	err = s.withSession(func(sess pkcs11.SessionHandle) error {
		pt = pt[:0]
		key, ok, err := s.findKey(sess, keyLabel)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("%w: token %q has no %s key", ErrOpen, s.label, keyLabel)
		}
		for i, p := range parts {
			b, err := s.api.GCMDecrypt(sess, key, p.IV, aads[i], p.CT)
			if err != nil {
				// Only a failure of C_Decrypt itself can mean "bad data". Anything else (C_DecryptInit refused, session or device lost,
				// throttling) is an HSM error: it goes up as such so withSession can retry it or report UNAVAILABLE.
				var he *hsmOpError
				if !errors.As(err, &he) || he.op != "C_Decrypt" || isDeviceError(he.err) {
					return err
				}
				// Token implementations differ in the code they return for a failed GCM check (SoftHSM on macOS and Linux
				// differ). A decryption failure is "the blob is wrong" only if the token still works: prove it with a round trip.
				if perr := s.probe(sess, key); perr != nil {
					return opErr("C_Decrypt", fmt.Errorf("failed (%v) and the token failed a self-check: %v", err, perr))
				}
				return fmt.Errorf("%w: C_Decrypt on %q failed", ErrOpen, s.label)
			}
			pt = append(pt, b...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return pt, nil
}

// probe encrypts and decrypts a random value with the wrap key in the given session.
func (s *PKCS11Sealer) probe(sess pkcs11.SessionHandle, key pkcs11.ObjectHandle) error {
	val := make([]byte, 16)
	rand.Read(val)
	iv, ct, err := s.encrypt(sess, key, []byte("probe"), val)
	if err != nil {
		return err
	}
	pt, err := s.api.GCMDecrypt(sess, key, iv, []byte("probe"), ct)
	if err != nil {
		return err
	}
	if !bytesEqual(pt, val) {
		return errors.New("probe mismatch")
	}
	return nil
}

func bytesEqual(a, b []byte) bool { return string(a) == string(b) }

func isDeviceError(err error) bool {
	var pe pkcs11.Error
	if !errors.As(err, &pe) {
		return false
	}
	switch uint(pe) {
	case pkcs11.CKR_DEVICE_ERROR, pkcs11.CKR_DEVICE_MEMORY, pkcs11.CKR_DEVICE_REMOVED, pkcs11.CKR_TOKEN_NOT_PRESENT, pkcs11.CKR_TOKEN_NOT_RECOGNIZED,
		pkcs11.CKR_SESSION_CLOSED, pkcs11.CKR_SESSION_HANDLE_INVALID, pkcs11.CKR_USER_NOT_LOGGED_IN, pkcs11.CKR_CRYPTOKI_NOT_INITIALIZED:
		return true
	}
	return false
}

var _ Sealer = (*PKCS11Sealer)(nil)

// A process loads a PKCS#11 module once (C_Initialize may be called once per process); sealers for several tokens share it.
// It is finalized by the OS at exit.
var (
	ctxMu    sync.Mutex
	ctxByLib = map[string]*pkcs11.Ctx{}
)

func sharedCtx(lib string) (*pkcs11.Ctx, error) {
	ctxMu.Lock()
	defer ctxMu.Unlock()
	if c, ok := ctxByLib[lib]; ok {
		return c, nil
	}
	ctx := pkcs11.New(lib)
	if ctx == nil {
		return nil, fmt.Errorf("sealer pkcs11: cannot load library %s", lib)
	}
	if err := ctx.Initialize(); err != nil && !isCKR(err, pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
		ctx.Destroy()
		return nil, fmt.Errorf("sealer pkcs11: C_Initialize: %w", err)
	}
	ctxByLib[lib] = ctx
	return ctx, nil
}

func isCKR(err error, code uint) bool {
	var pe pkcs11.Error
	return errors.As(err, &pe) && uint(pe) == code
}
