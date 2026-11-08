// Package backup is the offline backup format of a party's keyset: PVE (publicly verifiable encryption) of the two secret
// scalars to a recovery key, plus the stripped keyset blob encrypted to the same recovery key.
//
// Why both: PVE carries only x mod q and k. For party A (ECDSA) the stripped blob still holds the Paillier private key and
// c_key, from which the exact share is recovered after a refresh, so it is as sensitive as the whole keyset and is encrypted
// too (hybrid: AES-256-GCM, key wrapped with RSA-OAEP to the recovery key). Anyone holding the recovery private key and BOTH
// parties' backups of one generation holds the whole signing key.
//
// The recovery PRIVATE key never exists on a party host: gen-recovery-key runs on an offline machine; export needs only
// the public key; restore runs offline.
package backup

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ws4charlie/quorum-vault/mpc-party/internal/cbmpc"
)

const (
	FileVersion = 1
	KeyVersion  = 1
	rsaBits     = 3072
)

// RecoveryPrivate / RecoveryPublic are the JSON key files.
type RecoveryPrivate struct {
	V          int    `json:"v"`
	Kind       string `json:"kind"`
	PVEEk      []byte `json:"pve_ek"`
	PVEDk      []byte `json:"pve_dk"`
	RSAPrivate []byte `json:"rsa_private_pkcs8"`
}

type RecoveryPublic struct {
	V           int    `json:"v"`
	Kind        string `json:"kind"`
	PVEEk       []byte `json:"pve_ek"`
	RSAPublic   []byte `json:"rsa_public_pkix"`
	Fingerprint string `json:"fingerprint"` // sha256 of the two public parts, hex
}

func fingerprint(pveEk, rsaPub []byte) string {
	h := sha256.New()
	h.Write([]byte("qv-recovery-key-v1"))
	h.Write(pveEk)
	h.Write(rsaPub)
	return hex.EncodeToString(h.Sum(nil))
}

// GenRecoveryKey makes a recovery key pair. Run it on an offline machine; store the private file under the cold ceremony.
func GenRecoveryKey() (priv, pub []byte, err error) {
	ek, dk, err := cbmpc.GeneratePVEKeys()
	if err != nil {
		return nil, nil, err
	}
	dkb, err := dk.Bytes()
	dk.Wipe()
	if err != nil {
		return nil, nil, err
	}
	defer cbmpc.WipeBytes(dkb)
	rk, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return nil, nil, err
	}
	pk8, err := x509.MarshalPKCS8PrivateKey(rk)
	if err != nil {
		return nil, nil, err
	}
	pkix, err := x509.MarshalPKIXPublicKey(&rk.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	priv, _ = json.MarshalIndent(RecoveryPrivate{V: KeyVersion, Kind: "qv-recovery-private", PVEEk: ek, PVEDk: dkb, RSAPrivate: pk8}, "", " ")
	pub, _ = json.MarshalIndent(RecoveryPublic{V: KeyVersion, Kind: "qv-recovery-public", PVEEk: ek, RSAPublic: pkix, Fingerprint: fingerprint(ek, pkix)}, "", " ")
	return priv, pub, nil
}

func parsePublic(b []byte) (*RecoveryPublic, *rsa.PublicKey, error) {
	var p RecoveryPublic
	if err := strictJSON(b, &p); err != nil {
		return nil, nil, fmt.Errorf("recovery public key file: %w", err)
	}
	if p.V != KeyVersion || p.Kind != "qv-recovery-public" || len(p.PVEEk) == 0 {
		return nil, nil, errors.New("recovery public key file: wrong kind or version")
	}
	if p.Fingerprint != fingerprint(p.PVEEk, p.RSAPublic) {
		return nil, nil, errors.New("recovery public key file: fingerprint does not match its contents (corrupted?)")
	}
	k, err := x509.ParsePKIXPublicKey(p.RSAPublic)
	if err != nil {
		return nil, nil, fmt.Errorf("recovery public key file: %w", err)
	}
	rk, ok := k.(*rsa.PublicKey)
	if !ok || rk.N.BitLen() < 3000 {
		return nil, nil, errors.New("recovery public key file: not an RSA-3072 key")
	}
	return &p, rk, nil
}

// Stripped is the encrypted stripped keyset blob.
type Stripped struct {
	WrappedKey []byte `json:"wrapped_key"`
	IV         []byte `json:"iv"`
	CT         []byte `json:"ct"`
}

// File is the versioned backup file of ONE party's keyset at ONE generation.
type File struct {
	V              int       `json:"v"`
	KeysetID       string    `json:"keyset_id"`
	Generation     uint64    `json:"generation"`
	Role           string    `json:"role"`             // "A" or "B" (2-party keysets), "A", "B" or "C" (2-of-3 keysets)
	Alg            string    `json:"alg"`              // "ecdsa" or "ed25519"
	Scheme         string    `json:"scheme,omitempty"` // "" = 2-party HD keyset; "ecdsa-2of3" = one member's share of a 2-of-3 keyset
	RootPublicKey  string    `json:"root_public_key"`
	CreatedAt      time.Time `json:"created_at"`
	RecoveryKeyFpr string    `json:"recovery_key_fingerprint"`
	PubX           string    `json:"pub_x"`
	PubK           string    `json:"pub_k"`
	PVE            []byte    `json:"pve"`
	Stripped       Stripped  `json:"stripped"`
}

// SchemeT2of3 is File.Scheme of a 2-of-3 threshold share.
const SchemeT2of3 = "ecdsa-2of3"

func (f *File) header() []byte {
	h := fmt.Sprintf("qv-backup-v%d|%s|%d|%s|%s|%s|%s", f.V, f.KeysetID, f.Generation, f.Role, f.Alg, f.RootPublicKey, f.RecoveryKeyFpr)
	if f.Scheme != "" {
		h += "|" + f.Scheme // 2-party headers stay exactly as they were
	}
	return []byte(h)
}

func (f *File) label() []byte {
	if f.Scheme == SchemeT2of3 {
		return cbmpc.TBackupLabel(f.KeysetID, memberOfRole(f.Role), f.Generation)
	}
	return cbmpc.BackupLabel(fmt.Sprintf("%s#%d", f.KeysetID, f.Generation), algOf(f.Alg), roleOf(f.Role))
}

func memberOfRole(r string) cbmpc.Member {
	switch r {
	case "B":
		return 1
	case "C":
		return 2
	}
	return 0
}

func algOf(s string) cbmpc.Alg {
	if s == "ed25519" {
		return cbmpc.Ed25519
	}
	return cbmpc.ECDSA
}

func roleOf(s string) cbmpc.Role {
	if s == "B" {
		return cbmpc.P2
	}
	return cbmpc.P1
}

func strictJSON(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

// Parse reads a backup file strictly.
func Parse(b []byte) (*File, error) {
	var f File
	if err := strictJSON(b, &f); err != nil {
		return nil, fmt.Errorf("backup file: %w", err)
	}
	if f.V != FileVersion {
		return nil, fmt.Errorf("backup file: version %d, this tool reads version %d", f.V, FileVersion)
	}
	if f.KeysetID == "" || f.Generation == 0 || (f.Role != "A" && f.Role != "B" && f.Role != "C") || (f.Alg != "ecdsa" && f.Alg != "ed25519") {
		return nil, errors.New("backup file: incomplete header")
	}
	switch f.Scheme {
	case "":
		if f.Role == "C" {
			return nil, errors.New("backup file: party C holds 2-of-3 keysets only")
		}
	case SchemeT2of3:
		if f.Alg != "ecdsa" || f.PubK != "" {
			return nil, errors.New("backup file: malformed 2-of-3 header")
		}
	default:
		return nil, fmt.Errorf("backup file: unknown scheme %q", f.Scheme)
	}
	return &f, nil
}

// Marshal renders the file.
func (f *File) Marshal() []byte { b, _ := json.MarshalIndent(f, "", " "); return b }

// SHA256 fingerprints the rendered file.
func (f *File) SHA256() string { h := sha256.Sum256(f.Marshal()); return hex.EncodeToString(h[:]) }

// Export builds the backup of keyset ks (generation gen of keyset id on party role) for the recovery public key.
func Export(ks *cbmpc.Keyset, id string, gen uint64, role string, recoveryPublic []byte) (*File, error) {
	pub, rsaPub, err := parsePublic(recoveryPublic)
	if err != nil {
		return nil, err
	}
	root, err := ks.RootPublicKey()
	if err != nil {
		return nil, err
	}
	f := &File{V: FileVersion, KeysetID: id, Generation: gen, Role: role, Alg: ks.Alg().String(), RootPublicKey: hex.EncodeToString(root),
		CreatedAt: time.Now().UTC(), RecoveryKeyFpr: pub.Fingerprint}
	sp, err := ks.Split()
	if err != nil {
		return nil, err
	}
	defer sp.Wipe()
	f.PubX, f.PubK = hex.EncodeToString(sp.PubX), hex.EncodeToString(sp.PubK)
	if f.PVE, err = sp.PVEExport(pub.PVEEk, f.label()); err != nil {
		return nil, err
	}
	stripped, err := sp.Stripped.Bytes()
	if err != nil {
		return nil, err
	}
	defer cbmpc.WipeBytes(stripped)
	aesKey := make([]byte, 32)
	rand.Read(aesKey)
	defer cbmpc.WipeBytes(aesKey)
	blk, _ := aes.NewCipher(aesKey)
	gcm, _ := cipher.NewGCM(blk)
	iv := make([]byte, gcm.NonceSize())
	rand.Read(iv)
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPub, aesKey, f.header())
	if err != nil {
		return nil, err
	}
	f.Stripped = Stripped{WrappedKey: wrapped, IV: iv, CT: gcm.Seal(nil, iv, stripped, f.header())}
	return f, nil
}

// ExportT builds the backup of one member's share of a 2-of-3 keyset. The PVE ciphertext carries the share scalar x_i; the
// "stripped" part is the share blob with the scalar wiped (public points, no secret), encrypted the same way for uniformity.
func ExportT(k *cbmpc.TKey, id string, gen uint64, role string, recoveryPublic []byte) (*File, error) {
	pub, rsaPub, err := parsePublic(recoveryPublic)
	if err != nil {
		return nil, err
	}
	f := &File{V: FileVersion, KeysetID: id, Generation: gen, Role: role, Alg: "ecdsa", Scheme: SchemeT2of3,
		RootPublicKey: hex.EncodeToString(k.PublicKey()), CreatedAt: time.Now().UTC(), RecoveryKeyFpr: pub.Fingerprint}
	sp, err := k.Split()
	if err != nil {
		return nil, err
	}
	defer sp.Wipe()
	f.PubX = hex.EncodeToString(sp.PubX)
	if f.PVE, err = sp.PVEExport(pub.PVEEk, f.label()); err != nil {
		return nil, err
	}
	aesKey := make([]byte, 32)
	rand.Read(aesKey)
	defer cbmpc.WipeBytes(aesKey)
	blk, _ := aes.NewCipher(aesKey)
	gcm, _ := cipher.NewGCM(blk)
	iv := make([]byte, gcm.NonceSize())
	rand.Read(iv)
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPub, aesKey, f.header())
	if err != nil {
		return nil, err
	}
	f.Stripped = Stripped{WrappedKey: wrapped, IV: iv, CT: gcm.Seal(nil, iv, sp.Public, f.header())}
	return f, nil
}

// Verify checks the backup with PUBLIC data only: header, recovery key fingerprint, and the PVE proof that the ciphertext
// encrypts scalars whose public points are pub_x and pub_k, bound to this keyset, generation, role and algorithm.
func Verify(f *File, recoveryPublic []byte) error {
	pub, _, err := parsePublic(recoveryPublic)
	if err != nil {
		return err
	}
	if f.RecoveryKeyFpr != pub.Fingerprint {
		return fmt.Errorf("backup was made for recovery key %s, not %s", f.RecoveryKeyFpr, pub.Fingerprint)
	}
	px, err1 := hex.DecodeString(f.PubX)
	pk, err2 := hex.DecodeString(f.PubK)
	if err1 != nil || err2 != nil {
		return errors.New("backup file: pub_x/pub_k are not hex")
	}
	if len(f.Stripped.WrappedKey) == 0 || len(f.Stripped.IV) != 12 || len(f.Stripped.CT) < 16 {
		return errors.New("backup file: the encrypted stripped blob is malformed")
	}
	if f.Scheme == SchemeT2of3 {
		if err := cbmpc.TPVEVerify(pub.PVEEk, f.PVE, f.label(), px); err != nil {
			return fmt.Errorf("backup file: the PVE ciphertext does not verify (tampered, or for another keyset, generation or member): %w", err)
		}
		return nil
	}
	if err := cbmpc.PVEVerify(algOf(f.Alg), pub.PVEEk, f.PVE, f.label(), px, pk); err != nil {
		return fmt.Errorf("backup file: the PVE ciphertext does not verify (tampered, or for another keyset, generation, role or algorithm): %w", err)
	}
	return nil
}

// RestoreT rebuilds one member's share of a 2-of-3 keyset. Offline: needs the recovery PRIVATE key file.
func RestoreT(f *File, recoveryPrivate []byte) (*cbmpc.TKey, error) {
	if f.Scheme != SchemeT2of3 {
		return nil, errors.New("this is not a 2-of-3 backup")
	}
	var priv RecoveryPrivate
	if err := strictJSON(recoveryPrivate, &priv); err != nil {
		return nil, fmt.Errorf("recovery private key file: %w", err)
	}
	if priv.V != KeyVersion || priv.Kind != "qv-recovery-private" {
		return nil, errors.New("recovery private key file: wrong kind or version")
	}
	rkAny, err := x509.ParsePKCS8PrivateKey(priv.RSAPrivate)
	if err != nil {
		return nil, fmt.Errorf("recovery private key file: %w", err)
	}
	rk, ok := rkAny.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("recovery private key file: not an RSA key")
	}
	pubDER, _ := x509.MarshalPKIXPublicKey(&rk.PublicKey)
	if fingerprint(priv.PVEEk, pubDER) != f.RecoveryKeyFpr {
		return nil, errors.New("this is not the recovery key the backup was made for (fingerprint differs)")
	}
	aesKey, err := rsa.DecryptOAEP(sha256.New(), nil, rk, f.Stripped.WrappedKey, f.header())
	if err != nil {
		return nil, errors.New("cannot unwrap the public blob key: wrong recovery key or a tampered backup")
	}
	defer cbmpc.WipeBytes(aesKey)
	blk, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, _ := cipher.NewGCM(blk)
	public, err := gcm.Open(nil, f.Stripped.IV, f.Stripped.CT, f.header())
	if err != nil {
		return nil, errors.New("the public blob does not decrypt: tampered backup or a header that was changed")
	}
	px, _ := hex.DecodeString(f.PubX)
	if err := cbmpc.TPVEVerify(priv.PVEEk, f.PVE, f.label(), px); err != nil {
		return nil, fmt.Errorf("the PVE ciphertext does not verify (tampered backup): %w", err)
	}
	dk := cbmpc.SecretFromBytes(priv.PVEDk)
	defer dk.Wipe()
	x, err := cbmpc.TRestoreScalar(dk, priv.PVEEk, f.PVE, f.label())
	if err != nil {
		return nil, fmt.Errorf("PVE restore failed (tampered backup or wrong recovery key): %w", err)
	}
	defer x.Wipe()
	k, err := cbmpc.TJoin(memberOfRole(f.Role), public, x, px)
	if err != nil {
		return nil, fmt.Errorf("the restored share does not match the recorded share point: %w", err)
	}
	if hex.EncodeToString(k.PublicKey()) != f.RootPublicKey {
		k.Wipe()
		return nil, errors.New("the restored share has another group public key than the backup header says")
	}
	return k, nil
}

// Restore rebuilds the keyset. Offline: needs the recovery PRIVATE key file. It checks that the result has the root public
// key recorded in the header.
func Restore(f *File, recoveryPrivate []byte) (*cbmpc.Keyset, error) {
	var priv RecoveryPrivate
	if err := strictJSON(recoveryPrivate, &priv); err != nil {
		return nil, fmt.Errorf("recovery private key file: %w", err)
	}
	if priv.V != KeyVersion || priv.Kind != "qv-recovery-private" {
		return nil, errors.New("recovery private key file: wrong kind or version")
	}
	rkAny, err := x509.ParsePKCS8PrivateKey(priv.RSAPrivate)
	if err != nil {
		return nil, fmt.Errorf("recovery private key file: %w", err)
	}
	rk, ok := rkAny.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("recovery private key file: not an RSA key")
	}
	pubDER, _ := x509.MarshalPKIXPublicKey(&rk.PublicKey)
	if fingerprint(priv.PVEEk, pubDER) != f.RecoveryKeyFpr {
		return nil, errors.New("this is not the recovery key the backup was made for (fingerprint differs)")
	}
	aesKey, err := rsa.DecryptOAEP(sha256.New(), nil, rk, f.Stripped.WrappedKey, f.header())
	if err != nil {
		return nil, errors.New("cannot unwrap the stripped blob key: wrong recovery key or a tampered backup")
	}
	defer cbmpc.WipeBytes(aesKey)
	blk, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, _ := cipher.NewGCM(blk)
	stripped, err := gcm.Open(nil, f.Stripped.IV, f.Stripped.CT, f.header())
	if err != nil {
		return nil, errors.New("the stripped blob does not decrypt: tampered backup or a header that was changed")
	}
	px, _ := hex.DecodeString(f.PubX)
	pk, _ := hex.DecodeString(f.PubK)
	alg := algOf(f.Alg)
	// Decrypting does not check the ciphertext: verify it first, with the public parts of the recovery key.
	if err := cbmpc.PVEVerify(alg, priv.PVEEk, f.PVE, f.label(), px, pk); err != nil {
		return nil, fmt.Errorf("the PVE ciphertext does not verify (tampered backup): %w", err)
	}
	sp, err := cbmpc.NewKeysetSplit(alg, roleOf(f.Role), stripped, px, pk) // wipes stripped
	if err != nil {
		return nil, err
	}
	defer sp.Wipe()
	dk := cbmpc.SecretFromBytes(priv.PVEDk)
	defer dk.Wipe()
	x, k, err := cbmpc.PVERestore(alg, dk, priv.PVEEk, f.PVE, f.label())
	if err != nil {
		return nil, fmt.Errorf("PVE restore failed (tampered backup or wrong recovery key): %w", err)
	}
	sp.X, sp.K = x, k
	ks, err := cbmpc.Join(sp)
	if err != nil {
		return nil, fmt.Errorf("the restored shares do not match the recorded public points: %w", err)
	}
	root, err := ks.RootPublicKey()
	if err != nil || hex.EncodeToString(root) != f.RootPublicKey {
		ks.Wipe()
		return nil, errors.New("the restored keyset has another root public key than the backup header says")
	}
	return ks, nil
}

var _ = base64.StdEncoding
