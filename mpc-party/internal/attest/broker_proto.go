package attest

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// Wire types and binding rules of the release broker (cmd/qv-attest-broker, package attest/broker). The party (task T3) and the broker share
// them, so both compute the same user_data and the same encryption context.

// Purposes of a broker call.
const (
	PurposeUnseal = "unseal" // release the data keys wrapped in the given blobs
	PurposeCreate = "create" // make new data keys, one per generation, and return each wrapped and sealed to the evidence key
)

// MaxGenerations bounds one request.
const MaxGenerations = 64

var partyRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)

// RequestContext says what a release is for. The evidence is bound to it (through user_data), so evidence cannot be reused for another
// party, keyset, generation list or purpose.
type RequestContext struct {
	Party       string   `json:"party"`       // the party role, as named in the allowlist and in the broker's config
	Keyset      string   `json:"keyset"`      // keyset id
	Generations []uint64 `json:"generations"` // one data key per generation, in the order of the blobs
	Purpose     string   `json:"purpose"`     // PurposeUnseal or PurposeCreate
}

// Validate checks the shape of the context.
func (c RequestContext) Validate() error {
	switch {
	case !partyRE.MatchString(c.Party):
		return errors.New("party must be 1-32 characters of A-Z a-z 0-9 _ -")
	case c.Keyset == "" || len(c.Keyset) > 128:
		return errors.New("keyset must be 1-128 characters")
	case len(c.Generations) == 0 || len(c.Generations) > MaxGenerations:
		return fmt.Errorf("generations must hold 1 to %d values", MaxGenerations)
	case c.Purpose != PurposeUnseal && c.Purpose != PurposeCreate:
		return fmt.Errorf("purpose %q is none of %s, %s", c.Purpose, PurposeUnseal, PurposeCreate)
	}
	seen := map[uint64]bool{}
	for _, g := range c.Generations {
		if seen[g] {
			return fmt.Errorf("generation %d appears twice", g)
		}
		seen[g] = true
	}
	return nil
}

// UserData is the value the evidence must carry in user_data: SHA-256 over a domain tag, the context, the digest of every blob and the
// caller's TLS public-key pin (SHA-256 of the SPKI, as every pinned link defines it). Binding the pin means evidence taken for one TLS
// connection is useless on another; binding the blobs means it cannot be used to open blobs the enclave did not name.
func (c RequestContext) UserData(blobs [][]byte, callerPin [32]byte) []byte {
	h := sha256.New()
	put := func(b []byte) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	put([]byte("qv-attest-userdata-v1"))
	body, _ := json.Marshal(c)
	put(body)
	for _, b := range blobs {
		d := sha256.Sum256(b)
		put(d[:])
	}
	put(callerPin[:])
	return h.Sum(nil)
}

// ResponseAAD is the authenticated context of one released key: it ties the ciphertext to this request (user_data), this challenge and one
// generation, so a response cannot be replayed into another request even for the same enclave key.
func ResponseAAD(userData, nonce []byte, generation uint64) []byte {
	out := []byte("qv-attest-release-v1\n")
	out = binary.BigEndian.AppendUint64(out, generation)
	out = binary.BigEndian.AppendUint64(out, uint64(len(userData)))
	out = append(out, userData...)
	return append(out, nonce...)
}

// ChallengeResponse is the answer of the challenge call: a fresh single-use nonce bound to the caller's pinned identity.
type ChallengeResponse struct {
	Nonce     []byte    `json:"nonce"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ReleaseRequest is the body of the release and newkey calls. Blobs hold one wrapped data key per generation (release) and are empty for
// newkey.
type ReleaseRequest struct {
	Nonce    []byte         `json:"nonce"`
	Evidence []byte         `json:"evidence"`
	Context  RequestContext `json:"context"`
	Blobs    [][]byte       `json:"blobs,omitempty"`
}

// ReleasedKey is one data key. Sealed is the key encrypted to the public key inside the evidence (OpenFrom); Blob is the wrapped form, set
// by newkey only, for the party to store next to its sealed shares.
type ReleasedKey struct {
	Generation uint64 `json:"generation"`
	Blob       []byte `json:"blob,omitempty"`
	Sealed     []byte `json:"sealed"`
}

// ReleaseResponse is the answer of release and newkey. No field holds a key in the clear.
type ReleaseResponse struct {
	Keys []ReleasedKey `json:"keys"`
}

// ErrorResponse is every refusal: Error is a short code, never a secret.
type ErrorResponse struct {
	Error string `json:"error"`
}
