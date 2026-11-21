package admin

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

// The two versioned records a party keeps beside its keysets, both changed only by an admin request every member verifies itself:
//   - the admin set: the Ed25519 keys that may sign admin requests and how many must (AdminSetRequest);
//   - the recovery-key registry: which recovery key the backups must be made under, and which are retired (RecoveryKeyRequest).
// A request names the version it creates (the member's version plus one) and the hash of the record it replaces, so it fits one step of one
// history: an old request cannot be replayed, a request cannot skip a step, and two members that applied different requests show different hashes.

// MaxAdminKeys bounds the size of an admin set.
const MaxAdminKeys = 64

var fingerprintRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// SetHash is the hash of an admin set: the threshold and the keys in sorted order. The version is not part of it (it is the request's).
func SetHash(keys [][]byte, threshold int) [32]byte {
	sorted := append([][]byte(nil), keys...)
	sort.Slice(sorted, func(i, j int) bool { return bytes.Compare(sorted[i], sorted[j]) < 0 })
	h := sha256.New()
	h.Write([]byte("qv-mpc-admin-set-v1\n"))
	var b [binary.MaxVarintLen64]byte
	h.Write(b[:binary.PutUvarint(b[:], uint64(threshold))])
	h.Write(b[:binary.PutUvarint(b[:], uint64(len(sorted)))])
	for _, k := range sorted {
		h.Write(k)
	}
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// RecoveryHash is the hash of a recovery-key registry (the current fingerprint, "" if none, and the retired ones in sorted order).
func RecoveryHash(current string, retired []string) [32]byte {
	sorted := append([]string(nil), retired...)
	sort.Strings(sorted)
	h := sha256.New()
	h.Write([]byte("qv-mpc-recovery-registry-v1\n"))
	put := func(s string) {
		var b [binary.MaxVarintLen64]byte
		h.Write(b[:binary.PutUvarint(b[:], uint64(len(s)))])
		h.Write([]byte(s))
	}
	put(current)
	var b [binary.MaxVarintLen64]byte
	h.Write(b[:binary.PutUvarint(b[:], uint64(len(sorted)))])
	for _, s := range sorted {
		put(s)
	}
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// AdminSetBody is the request body of a change of the admin set.
func AdminSetBody(version uint64, keys [][]byte, threshold int, prevHash [32]byte) *pb.AdminSetRequest {
	return &pb.AdminSetRequest{SetVersion: version, SetKeys: keys, SetThreshold: uint32(threshold), SetPrevHash: prevHash[:]}
}

// RecoveryKeyBody is the request body of a change of the recovery-key registry.
func RecoveryKeyBody(version uint64, current string, retire []string, prevHash [32]byte) *pb.RecoveryKeyRequest {
	return &pb.RecoveryKeyRequest{RkVersion: version, RkCurrent: current, RkRetire: retire, RkPrevHash: prevHash[:]}
}

// CheckAdminSet validates the content of a new admin set: 1 to MaxAdminKeys distinct 32-byte keys, a threshold from 1 to the number of keys
// and at most MaxSignatures.
func CheckAdminSet(keys [][]byte, threshold int) error {
	switch {
	case len(keys) == 0:
		return errors.New("the new admin set has no keys")
	case len(keys) > MaxAdminKeys:
		return fmt.Errorf("the new admin set has %d keys, at most %d", len(keys), MaxAdminKeys)
	case threshold < 1 || threshold > len(keys):
		return fmt.Errorf("threshold %d: it must be between 1 and the %d keys", threshold, len(keys))
	case threshold > MaxSignatures:
		return fmt.Errorf("threshold %d is more than the %d signatures one authorization may carry", threshold, MaxSignatures)
	}
	seen := map[string]bool{}
	for _, k := range keys {
		if len(k) != ed25519.PublicKeySize {
			return fmt.Errorf("an admin key must be %d bytes, got %d", ed25519.PublicKeySize, len(k))
		}
		if seen[string(k)] {
			return fmt.Errorf("key %x... is listed twice (a key counts once)", k[:4])
		}
		seen[string(k)] = true
	}
	return nil
}

// CheckRecoveryRecord validates the content of a registry change: a current fingerprint (or none) and retired fingerprints, all 64 hex, the
// current one not among the retired.
func CheckRecoveryRecord(current string, retire []string) error {
	if current != "" && !fingerprintRE.MatchString(current) {
		return fmt.Errorf("%q is not a recovery key fingerprint (64 hex characters)", current)
	}
	for _, f := range retire {
		if !fingerprintRE.MatchString(f) {
			return fmt.Errorf("%q is not a recovery key fingerprint (64 hex characters)", f)
		}
		if f == current {
			return errors.New("the current recovery key cannot be retired in the same request")
		}
	}
	return nil
}

// CheckSetSignatures is the policy part of a check of an admin-set request: the signers must be keys of the current set or of the new set (an
// unknown key spoils the whole authorization), at least the current threshold of them from the current set AND at least the new threshold from the
// new set (a key in both counts for both). The second condition keeps a typo in the new keys from locking the admins out: the new set has to
// prove it can sign. Verify2 has already checked the signatures; the time and domain rules are CheckAuth2's, called with the union of the keys.
func CheckSetSignatures(a *pb.AdminAuthV2, cur Policy, newKeys [][]byte, newThreshold int) error {
	curSet, newSet := map[string]bool{}, map[string]bool{}
	for _, k := range cur.Keys {
		curSet[string(k)] = true
	}
	for _, k := range newKeys {
		newSet[string(k)] = true
	}
	nCur, nNew := 0, 0
	for _, s := range a.Signatures {
		in := false
		if curSet[string(s.PublicKey)] {
			nCur++
			in = true
		}
		if newSet[string(s.PublicKey)] {
			nNew++
			in = true
		}
		if !in {
			return fmt.Errorf("key %x... is in neither the current admin set nor the new one", s.PublicKey[:4])
		}
	}
	if need := max(cur.Threshold, 1); nCur < need {
		return fmt.Errorf("%d signature(s) from the current admin set, %d needed (its admin_threshold)", nCur, need)
	}
	if nNew < newThreshold {
		return fmt.Errorf("%d signature(s) from the new admin set, %d needed (its threshold): the new keys must prove they can sign", nNew, newThreshold)
	}
	return nil
}

// UnionPolicy is cur with the new keys added and a threshold of one: what CheckAuth2 needs to check the time, the domain and the signer list of
// an admin-set request (the real thresholds are CheckSetSignatures').
func UnionPolicy(cur Policy, newKeys [][]byte) Policy {
	u := cur
	u.Threshold = 1
	u.Keys = append(append([][]byte(nil), cur.Keys...), newKeys...)
	return u
}

// RecoveryFingerprint reads the fingerprint of a recovery public key file (the JSON `mpc-party backup gen-recovery-key` writes): the SHA-256
// of the label and the two public parts. It is the same value the backup package computes and records in every backup; a test there keeps the two in
// step. Tools that must not link the cryptographic library (qv-party-admin) read it here.
func RecoveryFingerprint(publicKeyFile []byte) (string, error) {
	var p struct {
		V           int    `json:"v"`
		Kind        string `json:"kind"`
		PVEEk       []byte `json:"pve_ek"`
		RSAPublic   []byte `json:"rsa_public_pkix"`
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.Unmarshal(publicKeyFile, &p); err != nil || p.Kind != "qv-recovery-public" || len(p.PVEEk) == 0 {
		return "", errors.New("not a recovery public key file")
	}
	h := sha256.New()
	h.Write([]byte("qv-recovery-key-v1"))
	h.Write(p.PVEEk)
	h.Write(p.RSAPublic)
	got := hex.EncodeToString(h.Sum(nil))
	if p.Fingerprint != got {
		return "", errors.New("the fingerprint in the file does not match its contents (damaged?)")
	}
	return got, nil
}

// SetHashOf is the hash of the admin set an admin-set request creates.
func SetHashOf(r *pb.AdminSetRequest) []byte {
	h := SetHash(r.SetKeys, int(r.SetThreshold))
	return h[:]
}
