// Package seal encrypts MPC key-share blobs under an AES-256 key that lives
// inside one party's PKCS#11 token and never leaves it.
//
// Each party token holds one secret key object labelled WrapKeyLabel
// (CKO_SECRET_KEY, CKK_AES, 32 bytes, CKA_TOKEN, CKA_SENSITIVE,
// !CKA_EXTRACTABLE). Seal runs CKM_AES_GCM inside the token with a random
// 12-byte IV and caller-chosen AAD, and returns a small JSON envelope
// {"v":1,"iv":b64,"ct":b64} (ct includes the 16-byte GCM tag). Without the
// token the envelope is useless; with a different token, a different AAD or a
// flipped bit, Open fails GCM authentication.
package seal

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/miekg/pkcs11"

	"github.com/ws4charlie/quorum-vault/internal/hsm"
)

// WrapKeyLabel is the CKA_LABEL of the per-token AES wrap key.
const WrapKeyLabel = "qv-share-wrap"

const (
	envelopeVersion = 1
	ivLen           = 12
	tagBits         = 128
)

// ErrOpen is returned (wrapped) when an envelope does not decrypt: wrong
// token, wrong AAD or tampered bytes. GCM cannot tell these apart.
var ErrOpen = errors.New("seal: cannot open envelope")

type envelope struct {
	V  int    `json:"v"`
	IV []byte `json:"iv"`
	CT []byte `json:"ct"`
}

// createMu serialises find-or-create of the wrap key within this process so
// two goroutines do not both generate one.
var createMu sync.Mutex

// EnsureKey returns the handle of the token's wrap key, generating it with
// CKM_AES_KEY_GEN on first use. The handle is only valid inside s's
// application, so callers use it within the same WithSession call.
func EnsureKey(p *pkcs11.Ctx, s pkcs11.SessionHandle) (pkcs11.ObjectHandle, error) {
	if h, ok, err := findKey(p, s); err != nil || ok {
		return h, err
	}
	createMu.Lock()
	defer createMu.Unlock()
	if h, ok, err := findKey(p, s); err != nil || ok {
		return h, err
	}
	tmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, WrapKeyLabel),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
	}
	h, err := p.GenerateKey(s, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)}, tmpl)
	if err != nil {
		return 0, fmt.Errorf("seal: C_GenerateKey %s: %w", WrapKeyLabel, err)
	}
	return h, nil
}

func findKey(p *pkcs11.Ctx, s pkcs11.SessionHandle) (pkcs11.ObjectHandle, bool, error) {
	tmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, WrapKeyLabel),
	}
	if err := p.FindObjectsInit(s, tmpl); err != nil {
		return 0, false, fmt.Errorf("seal: C_FindObjectsInit: %w", err)
	}
	hs, _, err := p.FindObjects(s, 1)
	if ferr := p.FindObjectsFinal(s); err == nil && ferr != nil {
		err = ferr
	}
	if err != nil {
		return 0, false, fmt.Errorf("seal: C_FindObjects: %w", err)
	}
	if len(hs) == 0 {
		return 0, false, nil
	}
	return hs[0], true, nil
}

// Seal encrypts plaintext under tok's wrap key with aad bound in, and returns
// the JSON envelope.
func Seal(ctx context.Context, tok *hsm.Token, plaintext, aad []byte) ([]byte, error) {
	iv := make([]byte, ivLen)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("seal: iv: %w", err)
	}
	var ct []byte
	err := tok.WithSession(ctx, func(p *pkcs11.Ctx, s pkcs11.SessionHandle) error {
		key, err := EnsureKey(p, s)
		if err != nil {
			return err
		}
		params := pkcs11.NewGCMParams(iv, aad, tagBits)
		defer params.Free()
		if err := p.EncryptInit(s, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, params)}, key); err != nil {
			return fmt.Errorf("seal: C_EncryptInit: %w", err)
		}
		ct, err = p.Encrypt(s, plaintext)
		if err != nil {
			return fmt.Errorf("seal: C_Encrypt: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope{V: envelopeVersion, IV: iv, CT: ct})
}

// Open decrypts an envelope produced by Seal with the same token and AAD.
func Open(ctx context.Context, tok *hsm.Token, env, aad []byte) ([]byte, error) {
	var e envelope
	if err := json.Unmarshal(env, &e); err != nil {
		return nil, fmt.Errorf("%w: bad envelope: %v", ErrOpen, err)
	}
	if e.V != envelopeVersion || len(e.IV) != ivLen || len(e.CT) < tagBits/8 {
		return nil, fmt.Errorf("%w: bad envelope (v=%d iv=%d ct=%d)", ErrOpen, e.V, len(e.IV), len(e.CT))
	}
	var pt []byte
	err := tok.WithSession(ctx, func(p *pkcs11.Ctx, s pkcs11.SessionHandle) error {
		key, ok, err := findKey(p, s)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("%w: token %q has no %s key", ErrOpen, tok.Label(), WrapKeyLabel)
		}
		params := pkcs11.NewGCMParams(e.IV, aad, tagBits)
		defer params.Free()
		if err := p.DecryptInit(s, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, params)}, key); err != nil {
			return fmt.Errorf("seal: C_DecryptInit: %w", err)
		}
		// A failed single-part C_Decrypt terminates the operation, so the
		// pooled session is clean afterwards.
		pt, err = p.Decrypt(s, e.CT)
		if err != nil {
			return fmt.Errorf("%w: C_Decrypt on %q: %v", ErrOpen, tok.Label(), err)
		}
		return nil
	})
	return pt, err
}

// WriteFile writes data to path with mode 0600 via a temp file + rename, so
// a crash never leaves a half-written envelope.
func WriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op after a successful rename
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
