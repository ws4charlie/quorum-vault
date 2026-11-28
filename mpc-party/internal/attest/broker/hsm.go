package broker

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/miekg/pkcs11"
)

// KeyWrapper makes and opens wrapped data keys. The only implementation is the HSM; the interface is the seam a cloud KMS would plug into.
type KeyWrapper interface {
	// NewDataKey makes a random 32-byte key and returns it with its wrapped form, bound to party, keyset and generation.
	NewDataKey(party, keyset string, generation uint64) (key, blob []byte, err error)
	// Unwrap opens a blob made for exactly this party, keyset and generation.
	Unwrap(party, keyset string, generation uint64, blob []byte) ([]byte, error)
	// Ready reports whether the token answers.
	Ready() error
}

// PKCS11Config names the broker's own token. The PIN comes from the environment or from a file only its owner can read, never from JSON.
type PKCS11Config struct {
	Lib     string `json:"lib,omitempty"`
	Token   string `json:"token"`
	PinEnv  string `json:"pin_env,omitempty"`
	PinFile string `json:"pin_file,omitempty"`
}

const (
	wrapKeyPrefix = "qv-attest-wrap-" // + party: one non-extractable AES-256 key per party
	blobVersion   = 1
	blobIVLen     = 12
	blobTagBits   = 128
)

// HSM wraps and unwraps data keys under a per-party AES-256 key that lives in a PKCS#11 token and cannot be extracted: the broker process
// never holds a wrapping key. (A data key is in this process's memory for the moment between the HSM returning it and SealTo encrypting it to
// the enclave; that is the exposure docs/enclaves.md accepts for a broker, the same as AWS KMS has.) The session code is a copy of the minimum in
// internal/server/sealer_pkcs11.go (owned by another task, and that package links the whole party): same login model, same library lookup.
type HSM struct {
	ctx   *pkcs11.Ctx
	slot  uint
	label string
}

type blob struct {
	V     int    `json:"v"`
	Party string `json:"party"`
	IV    []byte `json:"iv"`
	CT    []byte `json:"ct"`
}

// ReadPIN takes the PIN from an environment variable or from a file that only its owner, or its owner and one group, can read: no access for others, and
// the group may read but not write or execute (0400, 0600, 0440, 0640). The group read bit is what kubelet gives a Secret volume under fsGroup, and the pod's
// group is the only group that sees it; the same rule as the party's own ReadPIN (internal/server/sealer_pkcs11.go).
func ReadPIN(env, file string) (string, error) {
	switch {
	case env != "" && file != "":
		return "", errors.New("hsm: set exactly one of pin_env and pin_file")
	case env != "":
		if v := os.Getenv(env); v != "" {
			return v, nil
		}
		return "", fmt.Errorf("hsm: environment variable %s (pin_env) is empty or unset", env)
	case file != "":
		fi, err := os.Stat(file)
		if err != nil {
			return "", fmt.Errorf("hsm: pin_file: %w", err)
		}
		if perm := fi.Mode().Perm(); perm&0o007 != 0 {
			return "", fmt.Errorf("hsm: pin_file %s has mode %04o: others must have no access (chmod 0400, or 0440 for a group-readable Secret volume)", file, uint32(perm))
		} else if perm&0o030 != 0 {
			return "", fmt.Errorf("hsm: pin_file %s has mode %04o: the group may read it (0440) but not write or execute it", file, uint32(perm))
		}
		b, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("hsm: pin_file: %w", err)
		}
		if pin := strings.TrimRight(string(b), "\r\n"); pin != "" {
			return pin, nil
		}
		return "", errors.New("hsm: pin_file is empty")
	}
	return "", errors.New("hsm: needs pin_env or pin_file")
}

func defaultLib() string {
	if p := os.Getenv("QV_PKCS11_LIB"); p != "" {
		return p
	}
	c := []string{"/usr/lib/softhsm/libsofthsm2.so", "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so", "/usr/local/lib/softhsm/libsofthsm2.so"}
	if runtime.GOOS == "darwin" {
		c = []string{"/opt/homebrew/lib/softhsm/libsofthsm2.so", "/usr/local/lib/softhsm/libsofthsm2.so"}
	}
	for _, p := range c {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return c[0]
}

var (
	ctxMu    sync.Mutex
	ctxByLib = map[string]*pkcs11.Ctx{}
	keyMu    sync.Mutex
)

func sharedCtx(lib string) (*pkcs11.Ctx, error) {
	ctxMu.Lock()
	defer ctxMu.Unlock()
	if c, ok := ctxByLib[lib]; ok {
		return c, nil
	}
	ctx := pkcs11.New(lib)
	if ctx == nil {
		return nil, fmt.Errorf("hsm: cannot load library %s", lib)
	}
	if err := ctx.Initialize(); err != nil && !isCKR(err, pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
		ctx.Destroy()
		return nil, fmt.Errorf("hsm: C_Initialize: %w", err)
	}
	ctxByLib[lib] = ctx
	return ctx, nil
}

func isCKR(err error, code uint) bool {
	var pe pkcs11.Error
	return errors.As(err, &pe) && uint(pe) == code
}

// OpenHSM loads the module, finds the token, logs in and makes sure every party has its wrapping key. Any problem is an error.
func OpenHSM(c PKCS11Config, parties []string) (*HSM, error) {
	if c.Token == "" {
		return nil, errors.New("hsm: token (label) is required")
	}
	pin, err := ReadPIN(c.PinEnv, c.PinFile)
	if err != nil {
		return nil, err
	}
	lib := c.Lib
	if lib == "" {
		lib = defaultLib()
	}
	if _, err := os.Stat(lib); err != nil {
		return nil, fmt.Errorf("hsm: library %s: %w", lib, err)
	}
	ctx, err := sharedCtx(lib)
	if err != nil {
		return nil, err
	}
	var libInfo pkcs11.Info
	if info, err := ctx.GetInfo(); err == nil {
		libInfo = info
	}
	if err := refuseSoftHSM(libInfo, nil, lib); err != nil { // before the PIN is sent anywhere
		return nil, err
	}
	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return nil, fmt.Errorf("hsm: C_GetSlotList: %w", err)
	}
	h := &HSM{ctx: ctx, label: c.Token}
	found := false
	for _, sl := range slots {
		if info, err := ctx.GetTokenInfo(sl); err == nil && strings.TrimRight(info.Label, " \x00") == c.Token {
			h.slot, found = sl, true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("hsm: token %q not found in %s (check SOFTHSM2_CONF)", c.Token, lib)
	}
	if tok, err := ctx.GetTokenInfo(h.slot); err == nil {
		if err := refuseSoftHSM(libInfo, &tok, lib); err != nil {
			return nil, err
		}
	}
	login, err := ctx.OpenSession(h.slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, fmt.Errorf("hsm: C_OpenSession on %q: %w", c.Token, err)
	}
	if err := ctx.Login(login, pkcs11.CKU_USER, pin); err != nil && !isCKR(err, pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
		ctx.CloseSession(login)
		return nil, fmt.Errorf("hsm: login to token %q failed (wrong PIN?): %w", c.Token, err)
	}
	// the login session stays open for the life of the process: the application stays logged in while any session is open
	for _, p := range parties {
		if err := h.session(func(s pkcs11.SessionHandle) error { _, err := h.ensureKey(s, p); return err }); err != nil {
			return nil, fmt.Errorf("hsm: wrapping key of party %q: %w", p, err)
		}
	}
	return h, nil
}

func (h *HSM) session(f func(pkcs11.SessionHandle) error) error {
	s, err := h.ctx.OpenSession(h.slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return fmt.Errorf("hsm: C_OpenSession on %q: %w", h.label, err)
	}
	defer h.ctx.CloseSession(s)
	return f(s)
}

func (h *HSM) findKey(s pkcs11.SessionHandle, party string) (pkcs11.ObjectHandle, bool, error) {
	tmpl := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY), pkcs11.NewAttribute(pkcs11.CKA_LABEL, wrapKeyPrefix+party)}
	if err := h.ctx.FindObjectsInit(s, tmpl); err != nil {
		return 0, false, fmt.Errorf("hsm: C_FindObjectsInit: %w", err)
	}
	hs, _, err := h.ctx.FindObjects(s, 1)
	h.ctx.FindObjectsFinal(s)
	if err != nil {
		return 0, false, fmt.Errorf("hsm: C_FindObjects: %w", err)
	}
	if len(hs) == 0 {
		return 0, false, nil
	}
	return hs[0], true, nil
}

func (h *HSM) ensureKey(s pkcs11.SessionHandle, party string) (pkcs11.ObjectHandle, error) {
	if k, ok, err := h.findKey(s, party); err != nil || ok {
		return k, err
	}
	keyMu.Lock()
	defer keyMu.Unlock()
	if k, ok, err := h.findKey(s, party); err != nil || ok {
		return k, err
	}
	tmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY), pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32), pkcs11.NewAttribute(pkcs11.CKA_LABEL, wrapKeyPrefix+party),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true), pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true), pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false), // never leaves the token
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true), pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
	}
	return h.ctx.GenerateKey(s, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)}, tmpl)
}

// wrapAAD binds a blob to its party, keyset and generation: a blob of one generation does not open as another, nor for another party.
func wrapAAD(party, keyset string, generation uint64) []byte {
	out := []byte("qv-attest-dek-v1\n")
	out = binary.BigEndian.AppendUint64(out, uint64(len(party)))
	out = append(out, party...)
	out = binary.BigEndian.AppendUint64(out, uint64(len(keyset)))
	out = append(out, keyset...)
	return binary.BigEndian.AppendUint64(out, generation)
}

// NewDataKey implements KeyWrapper. The key's bytes come from the token's random generator.
func (h *HSM) NewDataKey(party, keyset string, generation uint64) (key, wrapped []byte, err error) {
	err = h.session(func(s pkcs11.SessionHandle) error {
		wk, ok, err := h.findKey(s, party)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("hsm: no wrapping key for party %q", party)
		}
		if key, err = h.ctx.GenerateRandom(s, 32); err != nil || len(key) != 32 {
			return fmt.Errorf("hsm: C_GenerateRandom: %v", err)
		}
		iv := make([]byte, blobIVLen)
		if _, err := rand.Read(iv); err != nil {
			return err
		}
		params := pkcs11.NewGCMParams(iv, wrapAAD(party, keyset, generation), blobTagBits)
		defer params.Free()
		if err := h.ctx.EncryptInit(s, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, params)}, wk); err != nil {
			return fmt.Errorf("hsm: C_EncryptInit: %w", err)
		}
		ct, err := h.ctx.Encrypt(s, key)
		if err != nil {
			return fmt.Errorf("hsm: C_Encrypt: %w", err)
		}
		wrapped, err = json.Marshal(blob{V: blobVersion, Party: party, IV: iv, CT: ct})
		return err
	})
	if err != nil {
		wipe(key)
		return nil, nil, err
	}
	return key, wrapped, nil
}

// Unwrap implements KeyWrapper.
func (h *HSM) Unwrap(party, keyset string, generation uint64, wrapped []byte) ([]byte, error) {
	var b blob
	if err := json.Unmarshal(wrapped, &b); err != nil || b.V != blobVersion || b.Party != party || len(b.IV) != blobIVLen || len(b.CT) < blobTagBits/8 {
		return nil, errors.New("hsm: bad blob")
	}
	var pt []byte
	err := h.session(func(s pkcs11.SessionHandle) error {
		wk, ok, err := h.findKey(s, party)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("hsm: no wrapping key for party %q", party)
		}
		params := pkcs11.NewGCMParams(b.IV, wrapAAD(party, keyset, generation), blobTagBits)
		defer params.Free()
		if err := h.ctx.DecryptInit(s, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, params)}, wk); err != nil {
			return fmt.Errorf("hsm: C_DecryptInit: %w", err)
		}
		if pt, err = h.ctx.Decrypt(s, b.CT); err != nil {
			return errors.New("hsm: blob does not open under this party, keyset and generation")
		}
		return nil
	})
	return pt, err
}

// Ready implements KeyWrapper: a session can be opened.
func (h *HSM) Ready() error { return h.session(func(pkcs11.SessionHandle) error { return nil }) }

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// productionEnv: QV_ENV unset, or anything but dev or test, is production (the rule of the gateway and the party: a typo cannot loosen anything).
func productionEnv() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("QV_ENV"))) {
	case "dev", "test":
		return false
	}
	return true
}

// isSoftHSM says whether the module is SoftHSM, from what the module reports (library manufacturer or description, token manufacturer or model),
// not from its file name.
func isSoftHSM(lib pkcs11.Info, tok *pkcs11.TokenInfo) bool {
	has := func(s string) bool { return strings.Contains(strings.ToLower(s), "softhsm") }
	if has(lib.ManufacturerID) || has(lib.LibraryDescription) {
		return true
	}
	return tok != nil && (has(tok.ManufacturerID) || has(tok.Model))
}

// refuseSoftHSM: SoftHSM keeps the wrapping keys in files next to the broker, so in production (QV_ENV unset, or not dev or test) it stops the start.
func refuseSoftHSM(lib pkcs11.Info, tok *pkcs11.TokenInfo, libPath string) error {
	if productionEnv() && isSoftHSM(lib, tok) {
		return fmt.Errorf("hsm: %s is SoftHSM (reported by the module: manufacturer %q, description %q): refused in production, it is for development and tests only; use a real HSM, or set QV_ENV=dev on a development machine",
			libPath, strings.TrimSpace(lib.ManufacturerID), strings.TrimSpace(lib.LibraryDescription))
	}
	return nil
}
