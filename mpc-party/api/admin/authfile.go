package admin

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

// The operations that carry an AdminAuth.
const (
	OpDKG      = "dkg"
	OpRefresh  = "refresh"
	OpUnfreeze = "unfreeze"
)

// DefaultMaxAge is the parties' default `admin_max_age_seconds`. The parties' own setting decides; this is what tools assume.
const DefaultMaxAge = 300 * time.Second

var keysetRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// File is the authorisation file an operator signs on their own machine and a sender carries to the parties: one operation on one keyset.
// The JSON form is the one `qv-keysets party-auth` writes and `qv-rekey dkg -admin-auth` reads.
type File struct {
	Op          string `json:"op"`
	Keyset      string `json:"keyset"`
	UnixSeconds int64  `json:"unix_seconds"`
	PublicKey   string `json:"public_key"` // hex, 32 bytes
	Signature   string `json:"signature"`  // hex, 64 bytes
}

// NewFile signs an authorisation file with an operator key.
func NewFile(priv ed25519.PrivateKey, op, keysetID string, now time.Time) (File, error) {
	if err := checkOpKeyset(op, keysetID); err != nil {
		return File{}, err
	}
	a := Sign(priv, op, keysetID, now)
	return File{Op: op, Keyset: keysetID, UnixSeconds: a.UnixSeconds, PublicKey: hex.EncodeToString(a.PublicKey), Signature: hex.EncodeToString(a.Signature)}, nil
}

func checkOpKeyset(op, keysetID string) error {
	switch op {
	case OpDKG, OpRefresh, OpUnfreeze:
	default:
		return fmt.Errorf("unknown operation %q: want dkg, refresh or unfreeze", op)
	}
	if !keysetRE.MatchString(keysetID) {
		return errors.New("the keyset ID must match [A-Za-z0-9._-]{1,64}")
	}
	return nil
}

// JSON is the file's text.
func (f File) JSON() []byte {
	j, _ := json.MarshalIndent(f, "", "  ")
	return append(j, '\n')
}

// ParseFile reads and checks an authorisation file: known operation, keyset ID, hex of the right length, and that the signature is a
// valid signature of the operator key over (operation, keyset, time). It does not look at the clock.
func ParseFile(raw []byte) (File, error) {
	var f File
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return f, fmt.Errorf("not an authorisation file: %w", err)
	}
	if err := checkOpKeyset(f.Op, f.Keyset); err != nil {
		return f, err
	}
	if _, err := f.Auth(); err != nil {
		return f, err
	}
	return f, nil
}

// ReadFile is ParseFile on a file.
func ReadFile(path string) (File, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return File{}, err
	}
	f, err := ParseFile(raw)
	if err != nil {
		return f, fmt.Errorf("%s: %w", path, err)
	}
	return f, nil
}

// Auth is the protobuf form the parties verify. It refuses a file whose signature does not verify (a damaged or edited file).
func (f File) Auth() (*pb.AdminAuth, error) {
	pub, err1 := hex.DecodeString(f.PublicKey)
	sig, err2 := hex.DecodeString(f.Signature)
	if err1 != nil || err2 != nil || len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return nil, errors.New("public_key and signature must be hex of 32 and 64 bytes")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), Message(f.Op, f.Keyset, f.UnixSeconds), sig) {
		return nil, fmt.Errorf("the signature does not match (%s, %s, %d): the file was changed or damaged", f.Op, f.Keyset, f.UnixSeconds)
	}
	return &pb.AdminAuth{UnixSeconds: f.UnixSeconds, PublicKey: pub, Signature: sig}, nil
}

// Age is how old the signature is at now (negative: signed in the future).
func (f File) Age(now time.Time) time.Duration { return now.Sub(time.Unix(f.UnixSeconds, 0)) }

// ReadKeyFile reads an operator's Ed25519 private key: hex of the 32-byte seed or the 64-byte key.
func ReadKeyFile(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	switch {
	case err != nil:
		return nil, errors.New("the key file must hold hex")
	case len(b) == ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(b), nil
	case len(b) == ed25519.PrivateKeySize:
		return ed25519.PrivateKey(b), nil
	}
	return nil, errors.New("the key must be a 32-byte seed or a 64-byte private key")
}
