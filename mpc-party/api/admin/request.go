package admin

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

// DefaultValidity is how long a new request stays valid for co-signing and sending. The parties' own upper limit (`admin_max_validity_seconds`) decides.
const DefaultValidity = time.Hour

// Request is the v2 authorization file. One operator creates it (NewRequest), each admin adds a signature offline (Sign) without changing a
// byte of what is signed, anyone checks it (Check), and a sender carries it to party A. `request` is the body the parties will receive, in
// readable form: a signer sees what they sign, and the hash is recomputed from it, never trusted.
type Request struct {
	Version     int             `json:"version"`
	Op          string          `json:"op"`
	Keyset      string          `json:"keyset"`
	Domain      string          `json:"domain"`
	Body        json.RawMessage `json:"request"`
	BodyHash    string          `json:"body_hash"` // hex; a check only, recomputed on reading
	IssuedUnix  int64           `json:"issued_unix"`
	ExpiresUnix int64           `json:"expires_unix"`
	Nonce       string          `json:"nonce"` // hex, 16 bytes
	Signatures  []FileSignature `json:"signatures"`
}

// FileSignature is one admin's signature.
type FileSignature struct {
	PublicKey string `json:"public_key"` // hex, 32 bytes
	Signature string `json:"signature"`  // hex, 64 bytes
}

// NewRequest makes an unsigned request for op on keyset. scheme and curve matter for dkg only. domain is the deployment name the parties
// are configured with (`admin_domain`), "" when they have none.
func NewRequest(op, keyset, domain string, scheme pb.Scheme, curve pb.Curve, now time.Time, validFor time.Duration) (Request, error) {
	if err := checkOpKeyset(op, keyset); err != nil {
		return Request{}, err
	}
	if validFor <= 0 {
		return Request{}, errors.New("the validity must be positive")
	}
	body, err := BodyOf(op, keyset, scheme, curve)
	if err != nil {
		return Request{}, err
	}
	hash, err := BodyHash(op, body)
	if err != nil {
		return Request{}, err
	}
	raw, err := protojson.MarshalOptions{EmitUnpopulated: true}.Marshal(body)
	if err != nil {
		return Request{}, err
	}
	var nonce [NonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return Request{}, err
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		return Request{}, err
	}
	return Request{Version: Version2, Op: op, Keyset: keyset, Domain: domain, Body: compact.Bytes(), BodyHash: hex.EncodeToString(hash[:]),
		IssuedUnix: now.Unix(), ExpiresUnix: now.Add(validFor).Unix(), Nonce: hex.EncodeToString(nonce[:])}, nil
}

// NewSetRequest makes an unsigned request for a change of the admin set: the party's current version, set hash, keys and threshold say which step it is
// (it refuses a change no request could carry, CheckSetStep).
func NewSetRequest(domain string, curVersion uint64, curHash [32]byte, curKeys [][]byte, curThreshold int, keys [][]byte, threshold int, now time.Time, validFor time.Duration) (Request, error) {
	if err := CheckAdminSet(keys, threshold); err != nil {
		return Request{}, err
	}
	if err := CheckSetStep(curKeys, curThreshold, keys, threshold); err != nil {
		return Request{}, err
	}
	return newRequestBody(OpAdminSet, domain, AdminSetBody(curVersion+1, keys, threshold, curHash), now, validFor)
}

// NewRecoveryRequest makes an unsigned request for a change of the recovery-key registry.
func NewRecoveryRequest(domain string, curVersion uint64, curHash [32]byte, current string, retire []string, now time.Time, validFor time.Duration) (Request, error) {
	if err := CheckRecoveryRecord(current, retire); err != nil {
		return Request{}, err
	}
	return newRequestBody(OpRecoveryKey, domain, RecoveryKeyBody(curVersion+1, current, retire, curHash), now, validFor)
}

func newRequestBody(op, domain string, body proto.Message, now time.Time, validFor time.Duration) (Request, error) {
	if validFor <= 0 {
		return Request{}, errors.New("the validity must be positive")
	}
	hash, err := BodyHash(op, body)
	if err != nil {
		return Request{}, err
	}
	raw, err := protojson.MarshalOptions{EmitUnpopulated: true}.Marshal(body)
	if err != nil {
		return Request{}, err
	}
	var nonce [NonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return Request{}, err
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		return Request{}, err
	}
	return Request{Version: Version2, Op: op, Keyset: "", Domain: domain, Body: compact.Bytes(), BodyHash: hex.EncodeToString(hash[:]),
		IssuedUnix: now.Unix(), ExpiresUnix: now.Add(validFor).Unix(), Nonce: hex.EncodeToString(nonce[:])}, nil
}

// SetChange reads the change an admin-set request asks for (an error for other operations).
func (r Request) SetChange() (*pb.AdminSetRequest, error) {
	m, _, err := r.body()
	if err != nil {
		return nil, err
	}
	x, ok := m.(*pb.AdminSetRequest)
	if !ok {
		return nil, errors.New("not an admin-set request")
	}
	return x, nil
}

// RecoveryChange reads the change a recovery-key request asks for (an error for other operations).
func (r Request) RecoveryChange() (*pb.RecoveryKeyRequest, error) {
	m, _, err := r.body()
	if err != nil {
		return nil, err
	}
	x, ok := m.(*pb.RecoveryKeyRequest)
	if !ok {
		return nil, errors.New("not a recovery-key request")
	}
	return x, nil
}

// body parses `request` into the message for the operation and returns it with its hash.
func (r Request) body() (proto.Message, [32]byte, error) {
	m, err := newBody(r.Op)
	if err != nil {
		return nil, [32]byte{}, err
	}
	if err := (protojson.UnmarshalOptions{}).Unmarshal(r.Body, m); err != nil {
		return nil, [32]byte{}, fmt.Errorf("request: %w", err)
	}
	if !equalKeyset(m, r.Keyset) {
		return nil, [32]byte{}, errors.New("the request names another keyset than the file does")
	}
	h, err := BodyHash(r.Op, m)
	return m, h, err
}

func equalKeyset(m proto.Message, keyset string) bool {
	switch x := m.(type) {
	case *pb.DKGRequest:
		return x.KeysetId == keyset
	case *pb.RefreshRequest:
		return x.KeysetId == keyset
	case *pb.UnfreezeRequest:
		return x.KeysetId == keyset
	case *pb.AdminSetRequest, *pb.RecoveryKeyRequest:
		return keyset == ""
	}
	return false
}

// DKGParams reads the scheme and curve a dkg request names (an error for other operations).
func (r Request) DKGParams() (pb.Scheme, pb.Curve, error) {
	m, _, err := r.body()
	if err != nil {
		return 0, 0, err
	}
	d, ok := m.(*pb.DKGRequest)
	if !ok {
		return 0, 0, errors.New("not a dkg request")
	}
	return d.Scheme, d.Curve, nil
}

// Message is the bytes every admin signs.
func (r Request) Message() ([]byte, error) {
	_, hash, err := r.body()
	if err != nil {
		return nil, err
	}
	nonce, err := hex.DecodeString(r.Nonce)
	if err != nil || len(nonce) != NonceSize {
		return nil, fmt.Errorf("the nonce must be %d bytes of hex", NonceSize)
	}
	return Message2(r.Op, r.Keyset, r.Domain, hash, r.IssuedUnix, r.ExpiresUnix, nonce), nil
}

// Sign adds the signature of priv. The signed bytes do not change; the same key twice is refused.
func (r *Request) Sign(priv ed25519.PrivateKey) error {
	msg, err := r.Message()
	if err != nil {
		return err
	}
	pub := hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	for _, s := range r.Signatures {
		if s.PublicKey == pub {
			return fmt.Errorf("key %s already signed this request", pub)
		}
	}
	r.Signatures = append(r.Signatures, FileSignature{PublicKey: pub, Signature: hex.EncodeToString(ed25519.Sign(priv, msg))})
	return nil
}

// JSON is the file's text.
func (r Request) JSON() []byte {
	j, _ := json.MarshalIndent(r, "", "  ")
	return append(j, '\n')
}

// FileVersion tells which format a file is: 2 for a v2 request, 1 for a v1 file, 0 when it is neither.
func FileVersion(raw []byte) int {
	var v struct {
		Version *int   `json:"version"`
		Op      string `json:"op"`
	}
	if json.Unmarshal(raw, &v) != nil {
		return 0
	}
	switch {
	case v.Version != nil && *v.Version == Version2:
		return 2
	case v.Version == nil && v.Op != "":
		return 1
	}
	return 0
}

// ParseRequest reads a v2 file strictly: known fields only, the body hash recomputed and equal to the one in the file, and every signature
// valid for the rebuilt message. It does not look at the clock or at who may sign.
func ParseRequest(raw []byte) (Request, error) {
	var r Request
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return r, fmt.Errorf("not a v2 authorization file: %w", err)
	}
	if r.Version != Version2 {
		return r, fmt.Errorf("version %d: this tool reads version %d", r.Version, Version2)
	}
	if err := checkOpKeyset(r.Op, r.Keyset); err != nil {
		return r, err
	}
	_, hash, err := r.body()
	if err != nil {
		return r, err
	}
	if r.BodyHash != hex.EncodeToString(hash[:]) {
		return r, errors.New("body_hash does not match the request: the file was edited")
	}
	if len(r.Signatures) > 0 {
		if _, err := r.auth2(hash); err != nil {
			return r, err
		}
	}
	return r, nil
}

func (r Request) auth2(hash [32]byte) (*pb.AdminAuthV2, error) {
	nonce, err := hex.DecodeString(r.Nonce)
	if err != nil {
		return nil, errors.New("the nonce is not hex")
	}
	a := &pb.AdminAuthV2{Domain: r.Domain, IssuedUnix: r.IssuedUnix, ExpiresUnix: r.ExpiresUnix, Nonce: nonce}
	for _, s := range r.Signatures {
		pub, e1 := hex.DecodeString(s.PublicKey)
		sig, e2 := hex.DecodeString(s.Signature)
		if e1 != nil || e2 != nil {
			return nil, errors.New("public_key and signature must be hex")
		}
		a.Signatures = append(a.Signatures, &pb.AdminSignature{PublicKey: pub, Signature: sig})
	}
	if _, err := Verify2(r.Op, r.Keyset, hash, a); err != nil {
		return nil, err
	}
	return a, nil
}

// Auth is the protobuf form the parties verify, from a file with at least one signature.
func (r Request) Auth() (*pb.AdminAuth, error) {
	_, hash, err := r.body()
	if err != nil {
		return nil, err
	}
	a, err := r.auth2(hash)
	if err != nil {
		return nil, err
	}
	return &pb.AdminAuth{V2: a}, nil
}

// Policy is what a party's configuration says an authorization needs. A sender or a reviewer can check a file against it before anything is sent.
type Policy struct {
	Keys        [][]byte      // the party's admin_keys
	Threshold   int           // admin_threshold (at least 1)
	MaxValidity time.Duration // admin_max_validity_seconds
	Skew        time.Duration // admin_max_age_seconds
	Domain      string        // admin_domain
}

// Check says whether a party with this policy would accept the file at now, as far as a file can tell: signatures valid, every signer a
// configured key, enough distinct signers, inside its validity, and the domain. A party's own replay memory and start time are not visible here.
func (r Request) Check(p Policy, now time.Time) error {
	a, err := r.Auth()
	if err != nil {
		return err
	}
	if r.Op == OpAdminSet {
		ch, err := r.SetChange()
		if err != nil {
			return err
		}
		if err := CheckAdminSet(ch.SetKeys, int(ch.SetThreshold)); err != nil {
			return err
		}
		if err := CheckAuth2(r.Op, r.Keyset, r.Domain, a.V2, UnionPolicy(p, ch.SetKeys), now); err != nil {
			return err
		}
		return CheckSetSignatures(a.V2, p, ch.SetKeys, int(ch.SetThreshold))
	}
	return CheckAuth2(r.Op, r.Keyset, r.Domain, a.V2, p, now)
}

// CheckAuth2 is the policy part of an authorization check, shared by the parties and the CLI (signatures are Verify2's).
func CheckAuth2(op, keyset, domain string, a *pb.AdminAuthV2, p Policy, now time.Time) error {
	if p.Threshold < 1 {
		p.Threshold = 1
	}
	if domain != p.Domain {
		return fmt.Errorf("domain %q: the parties are configured for %q", domain, p.Domain)
	}
	known := map[string]bool{}
	for _, k := range p.Keys {
		known[string(k)] = true
	}
	for _, s := range a.Signatures {
		if !known[string(s.PublicKey)] {
			return fmt.Errorf("key %x... is not a configured admin key", s.PublicKey[:4])
		}
	}
	if n := len(a.Signatures); n < p.Threshold { // distinct: Verify2 refuses a repeated key
		return fmt.Errorf("%d signature(s), %d needed (admin_threshold)", n, p.Threshold)
	}
	issued, expires := time.Unix(a.IssuedUnix, 0), time.Unix(a.ExpiresUnix, 0)
	switch {
	case now.After(expires):
		return fmt.Errorf("expired at %s (%s ago)", expires.UTC().Format(time.RFC3339), now.Sub(expires).Round(time.Second))
	case issued.After(now.Add(p.Skew)):
		return fmt.Errorf("issued in the future (%s ahead; the party tolerates %s)", issued.Sub(now).Round(time.Second), p.Skew)
	case !expires.After(issued):
		return errors.New("expires before it was issued")
	case expires.Sub(issued) > p.MaxValidity:
		return fmt.Errorf("valid for %s, the parties accept at most %s", expires.Sub(issued), p.MaxValidity)
	}
	return nil
}

// CheckBody says whether the request in the file is the one body describes (the call the sender is about to make). A sender that builds the call
// itself uses it so a file for another scheme or curve is refused before any party is contacted.
func (r Request) CheckBody(body proto.Message) error {
	want, err := BodyHash(r.Op, Canonical(body))
	if err != nil {
		return err
	}
	_, got, err := r.body()
	if err != nil {
		return err
	}
	if want != got {
		return fmt.Errorf("the request in the file (%s) is not the call this tool makes", r.Body)
	}
	return nil
}
