package server

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/miekg/pkcs11"
)

// The envelope format is the one of internal/mpc/seal in the root module ({"v":1,"iv":b64,"ct":b64}, AES-256-GCM, 12-byte
// IV, 16-byte tag, the key lives in the token and cannot be extracted). This module may not import the root module, so the
// few lines are repeated here.
const (
	pkcs11WrapKeyLabel = "qv-share-wrap"
	envelopeVersion    = 1
	envelopeIVLen      = 12
	envelopeTagBits    = 128
)

// ErrOpen: the envelope does not decrypt under this token and AAD (wrong token, wrong AAD, tampered bytes: GCM cannot tell).
var ErrOpen = errors.New("sealer: cannot open envelope")

type envelope struct {
	V  int    `json:"v"`
	IV []byte `json:"iv"`
	CT []byte `json:"ct"`
}

// PKCS11Sealer seals under an AES-256 key that lives in one party's PKCS#11 token (SoftHSM in dev, an HSM in production).
// Party A uses token qv-party-1 and party B qv-party-2 (scripts/setup-softhsm.sh), each with its own key.
type PKCS11Sealer struct {
	ctx   *pkcs11.Ctx
	slot  uint
	label string
	mu    sync.Mutex
}

// ReadPIN takes the token PIN from an environment variable or from a file that only its owner can read (mode 0400/0600).
// It never comes from the JSON config.
func ReadPIN(env, file string) (string, error) {
	switch {
	case env != "" && file != "":
		return "", errors.New("sealer: set exactly one of pin_env and pin_file")
	case env != "":
		v := os.Getenv(env)
		if v == "" {
			return "", fmt.Errorf("sealer: environment variable %s (pin_env) is empty or unset", env)
		}
		return v, nil
	case file != "":
		fi, err := os.Stat(file)
		if err != nil {
			return "", fmt.Errorf("sealer: pin_file: %w", err)
		}
		if fi.Mode().Perm()&0o077 != 0 {
			return "", fmt.Errorf("sealer: pin_file %s has mode %v: group and others must have no access (chmod 0400)", file, fi.Mode().Perm())
		}
		b, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("sealer: pin_file: %w", err)
		}
		pin := strings.TrimRight(string(b), "\r\n")
		if pin == "" {
			return "", errors.New("sealer: pin_file is empty")
		}
		return pin, nil
	}
	return "", errors.New("sealer: pkcs11 needs pin_env or pin_file")
}

func defaultPKCS11Lib() string {
	if p := os.Getenv("QV_PKCS11_LIB"); p != "" {
		return p
	}
	var c []string
	if runtime.GOOS == "darwin" {
		c = []string{"/opt/homebrew/lib/softhsm/libsofthsm2.so", "/usr/local/lib/softhsm/libsofthsm2.so"}
	} else {
		c = []string{"/usr/lib/softhsm/libsofthsm2.so", "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so", "/usr/local/lib/softhsm/libsofthsm2.so"}
	}
	for _, p := range c {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return c[0]
}

// NewPKCS11Sealer loads the module, finds the token by label, logs in and makes sure the wrap key exists. Any problem is an
// error: the process must not start without a working token.
func NewPKCS11Sealer(c SealerConfig) (*PKCS11Sealer, error) {
	if c.Token == "" {
		return nil, errors.New("sealer pkcs11: token (label) is required")
	}
	pin, err := ReadPIN(c.PinEnv, c.PinFile)
	if err != nil {
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
	fail := func(format string, a ...any) (*PKCS11Sealer, error) { return nil, fmt.Errorf(format, a...) }
	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return fail("sealer pkcs11: C_GetSlotList: %w", err)
	}
	slot, found := uint(0), false
	for _, sl := range slots {
		if info, err := ctx.GetTokenInfo(sl); err == nil && strings.TrimRight(info.Label, " \x00") == c.Token {
			slot, found = sl, true
			break
		}
	}
	if !found {
		return fail("sealer pkcs11: token %q not found in %s (run scripts/setup-softhsm.sh, or check SOFTHSM2_CONF)", c.Token, lib)
	}
	s := &PKCS11Sealer{ctx: ctx, slot: slot, label: c.Token}
	login, err := ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return fail("sealer pkcs11: C_OpenSession on %q: %w", c.Token, err)
	}
	if err := ctx.Login(login, pkcs11.CKU_USER, pin); err != nil && !isCKR(err, pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
		ctx.CloseSession(login)
		return fail("sealer pkcs11: login to token %q failed (wrong PIN?): %w", c.Token, err)
	}
	// The login session stays open for the life of the process: the application stays logged in while any session is open.
	if err := s.withSession(func(sess pkcs11.SessionHandle) error { _, err := s.ensureKey(sess); return err }); err != nil {
		return fail("sealer pkcs11: wrap key: %w", err)
	}
	return s, nil
}

func (s *PKCS11Sealer) withSession(f func(pkcs11.SessionHandle) error) error {
	sess, err := s.ctx.OpenSession(s.slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return &UnavailableError{Msg: fmt.Sprintf("hsm: C_OpenSession on %q: %v", s.label, err)}
	}
	defer s.ctx.CloseSession(sess)
	return f(sess)
}

func (s *PKCS11Sealer) findKey(sess pkcs11.SessionHandle) (pkcs11.ObjectHandle, bool, error) {
	tmpl := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY), pkcs11.NewAttribute(pkcs11.CKA_LABEL, pkcs11WrapKeyLabel)}
	if err := s.ctx.FindObjectsInit(sess, tmpl); err != nil {
		return 0, false, &UnavailableError{Msg: fmt.Sprintf("hsm: C_FindObjectsInit: %v", err)}
	}
	hs, _, err := s.ctx.FindObjects(sess, 1)
	s.ctx.FindObjectsFinal(sess)
	if err != nil {
		return 0, false, &UnavailableError{Msg: fmt.Sprintf("hsm: C_FindObjects: %v", err)}
	}
	if len(hs) == 0 {
		return 0, false, nil
	}
	return hs[0], true, nil
}

var createKeyMu sync.Mutex

func (s *PKCS11Sealer) ensureKey(sess pkcs11.SessionHandle) (pkcs11.ObjectHandle, error) {
	if h, ok, err := s.findKey(sess); err != nil || ok {
		return h, err
	}
	createKeyMu.Lock()
	defer createKeyMu.Unlock()
	if h, ok, err := s.findKey(sess); err != nil || ok {
		return h, err
	}
	tmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY), pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32), pkcs11.NewAttribute(pkcs11.CKA_LABEL, pkcs11WrapKeyLabel),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true), pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true), pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false), // non-exportable
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true), pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
	}
	h, err := s.ctx.GenerateKey(sess, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)}, tmpl)
	if err != nil {
		return 0, fmt.Errorf("C_GenerateKey %s: %w", pkcs11WrapKeyLabel, err)
	}
	return h, nil
}

// Seal implements Sealer.
func (s *PKCS11Sealer) Seal(aad, plaintext []byte) ([]byte, error) {
	iv := make([]byte, envelopeIVLen)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	var ct []byte
	err := s.withSession(func(sess pkcs11.SessionHandle) error {
		key, err := s.ensureKey(sess)
		if err != nil {
			return err
		}
		params := pkcs11.NewGCMParams(iv, aad, envelopeTagBits)
		defer params.Free()
		if err := s.ctx.EncryptInit(sess, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, params)}, key); err != nil {
			return &UnavailableError{Msg: fmt.Sprintf("hsm: C_EncryptInit: %v", err)}
		}
		ct, err = s.ctx.Encrypt(sess, plaintext)
		if err != nil {
			return &UnavailableError{Msg: fmt.Sprintf("hsm: C_Encrypt: %v", err)}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope{V: envelopeVersion, IV: iv, CT: ct})
}

// Open implements Sealer. A decryption failure is ErrOpen (the blob or the AAD is wrong); anything wrong with the token
// itself is an *UnavailableError, so the service answers UNAVAILABLE instead of crashing.
func (s *PKCS11Sealer) Open(aad, sealed []byte) ([]byte, error) {
	var e envelope
	if err := json.Unmarshal(sealed, &e); err != nil {
		return nil, fmt.Errorf("%w: bad envelope: %v", ErrOpen, err)
	}
	if e.V != envelopeVersion || len(e.IV) != envelopeIVLen || len(e.CT) < envelopeTagBits/8 {
		return nil, fmt.Errorf("%w: bad envelope (v=%d iv=%d ct=%d)", ErrOpen, e.V, len(e.IV), len(e.CT))
	}
	var pt []byte
	err := s.withSession(func(sess pkcs11.SessionHandle) error {
		key, ok, err := s.findKey(sess)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("%w: token %q has no %s key", ErrOpen, s.label, pkcs11WrapKeyLabel)
		}
		params := pkcs11.NewGCMParams(e.IV, aad, envelopeTagBits)
		defer params.Free()
		if err := s.ctx.DecryptInit(sess, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, params)}, key); err != nil {
			return &UnavailableError{Msg: fmt.Sprintf("hsm: C_DecryptInit: %v", err)}
		}
		pt, err = s.ctx.Decrypt(sess, e.CT)
		if err != nil {
			if isDeviceError(err) {
				return &UnavailableError{Msg: fmt.Sprintf("hsm: C_Decrypt: %v", err)}
			}
			// Token implementations differ in the code they return for a failed GCM check (SoftHSM on macOS and Linux
			// differ). A decryption failure is "the blob is wrong" only if the token still works: prove it with a round trip.
			if perr := s.probe(sess, key); perr != nil {
				return &UnavailableError{Msg: fmt.Sprintf("hsm: C_Decrypt failed (%v) and the token failed a self-check: %v", err, perr)}
			}
			return fmt.Errorf("%w: C_Decrypt on %q failed", ErrOpen, s.label)
		}
		return nil
	})
	return pt, err
}

// probe encrypts and decrypts a random value with the wrap key in the given session.
func (s *PKCS11Sealer) probe(sess pkcs11.SessionHandle, key pkcs11.ObjectHandle) error {
	iv := make([]byte, envelopeIVLen)
	val := make([]byte, 16)
	rand.Read(iv)
	rand.Read(val)
	params := pkcs11.NewGCMParams(iv, []byte("probe"), envelopeTagBits)
	defer params.Free()
	if err := s.ctx.EncryptInit(sess, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, params)}, key); err != nil {
		return err
	}
	ct, err := s.ctx.Encrypt(sess, val)
	if err != nil {
		return err
	}
	params2 := pkcs11.NewGCMParams(iv, []byte("probe"), envelopeTagBits)
	defer params2.Free()
	if err := s.ctx.DecryptInit(sess, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, params2)}, key); err != nil {
		return err
	}
	pt, err := s.ctx.Decrypt(sess, ct)
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
