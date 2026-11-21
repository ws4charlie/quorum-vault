package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/ws4charlie/quorum-vault/mpc-party/api/admin"
	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

// The admin set: who may sign admin requests, and how many of them must. The configuration's `admin_keys` and `admin_threshold` are only the
// BOOTSTRAP set (version 0): the party uses them while it has no durable state. A change of the set is an admin request (op "admin-set") signed by the
// CURRENT set at the current threshold, and by the new set at its threshold (so a typo in the new keys cannot lock the admins out); every member
// verifies it against its own state and applies it to a durable record, admin-set.json beside the replay memory (sealed the same way). From then on the
// record wins and a different list in the configuration is ignored, loudly.
//
// A request creates version N+1 from the set whose hash it names, so it fits exactly one step of one history: an old request is stale, a request
// cannot skip a step, and members that applied different changes show different hashes in Health. Members apply independently: one that was down
// stays behind (Health says so) and takes the same change when it is sent again (see AdminSet in rollout.go).
//
// What this does not stop: whoever can edit the data directory can delete or roll back admin-set.json (sealing makes it unforgeable, not
// undeletable), which puts that one party back on the bootstrap list or on an older set. Every admin call needs ALL members that take part to accept
// the same signatures, so one party reset alone cannot act; resetting all of them is the break-glass of docs/runbooks/key-ceremony.md.

// adminSetFile is the durable admin set, in the data directory root (listed in the state table in sealer_local.go).
const adminSetFile = "admin-set.json"

type adminSetDoc struct {
	V           int      `json:"v"`
	Version     uint64   `json:"version"`
	Keys        []string `json:"keys"` // hex
	Threshold   int      `json:"threshold"`
	PrevHash    string   `json:"prev_hash"`    // hex: the set this one replaced
	AppliedUnix int64    `json:"applied_unix"` // when this party applied it
	SignedBy    []string `json:"signed_by"`    // hex keys that signed the change (for the audit trail)
}

// setSnap is the admin set in effect.
type setSnap struct {
	version   uint64
	keys      []ed25519.PublicKey
	threshold int
	hash      [32]byte
	fromState bool // durable state; false: the bootstrap list
	differs   bool // state exists and the configuration lists another set
}

func (s setSnap) rawKeys() [][]byte {
	out := make([][]byte, len(s.keys))
	for i, k := range s.keys {
		out[i] = k
	}
	return out
}

func newSnap(version uint64, keys []ed25519.PublicKey, threshold int) setSnap {
	sn := setSnap{version: version, keys: keys, threshold: threshold}
	sn.hash = admin.SetHash(sn.rawKeys(), threshold)
	return sn
}

func (v *adminVerifier) bootSnap() setSnap { return newSnap(0, v.keys, v.threshold) }

// snap is the set in effect: the durable one, else the bootstrap list. An unreadable durable set is an error, never "no state": falling back to the
// configuration would let a damaged or foreign file reset the admins.
func (v *adminVerifier) snap() (setSnap, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.ensure(); err != nil {
		return setSnap{}, err
	}
	return v.snapLocked(), nil
}

func (v *adminVerifier) snapLocked() setSnap {
	if v.cur != nil {
		return *v.cur
	}
	return v.bootSnap()
}

// v1Allowed: the old single-signature format needs the configuration's switch, and is never accepted once a change of the admin set was applied
// (the set is then a v2 matter: v1 signs no request body and no quorum).
func (v *adminVerifier) v1Allowed() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.ensure() != nil { // the state is read first: a party that has one must not take a v1 file as its first call after a restart
		return false
	}
	return v.allowV1 && v.cur == nil
}

// loadSet reads the durable set once (called under v.mu by ensure).
func (v *adminVerifier) loadSet() error {
	if v.setPath == "" || v.cur != nil {
		return nil
	}
	raw, err := os.ReadFile(v.setPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("admin set: %v", err)
	}
	if v.store != nil {
		if raw, err = v.store.openLocal(context.Background(), "admin-set", adminSetFile, raw); err != nil {
			return fmt.Errorf("the durable admin set (%s) cannot be opened, so no admin request is accepted (a party must not fall back to the configuration's list: restore the file, or run the break-glass procedure on every party): %v", v.setPath, err)
		}
	} else if isEnvelope(raw) {
		return fmt.Errorf("the durable admin set (%s) is sealed by the attested sealer and this party has another sealer", v.setPath)
	}
	var d adminSetDoc
	if err := json.Unmarshal(raw, &d); err != nil || d.V != 1 || d.Threshold < 1 {
		return fmt.Errorf("the durable admin set (%s) is not valid, so no admin request is accepted (restore the file, or run the break-glass procedure on every party)", v.setPath)
	}
	var keys []ed25519.PublicKey
	for _, k := range d.Keys {
		b, err := hex.DecodeString(k)
		if err != nil || len(b) != ed25519.PublicKeySize {
			return fmt.Errorf("the durable admin set (%s) holds a malformed key", v.setPath)
		}
		keys = append(keys, ed25519.PublicKey(b))
	}
	sn := newSnap(d.Version, keys, d.Threshold)
	if err := admin.CheckAdminSet(sn.rawKeys(), sn.threshold); err != nil {
		return fmt.Errorf("the durable admin set (%s) is not valid: %v", v.setPath, err)
	}
	sn.fromState = true
	sn.differs = sn.hash != v.cfgSet.hash
	v.cur = &sn
	if sn.differs {
		v.log.Warn("AUDIT admin set: this party has durable state (version "+fmt.Sprint(sn.version)+") and the admin_keys / admin_threshold of its configuration list ANOTHER set: the configuration is IGNORED (it is only the bootstrap list). Change the admin set with an admin-set request, not by editing the configuration",
			"version", sn.version, "state_hash", hex.EncodeToString(sn.hash[:]), "config_hash", hex.EncodeToString(v.cfgSet.hash[:]))
	}
	return nil
}

// saveSet writes the durable set (temp file, fsync, rename, fsync of the directory; sealed with the local key under the attested sealer).
func (v *adminVerifier) saveSet(sn setSnap, prev [32]byte, signers [][]byte) error {
	if v.setPath == "" {
		return nil
	}
	d := adminSetDoc{V: 1, Version: sn.version, Threshold: sn.threshold, PrevHash: hex.EncodeToString(prev[:]), AppliedUnix: v.now().Unix()}
	for _, k := range sn.keys {
		d.Keys = append(d.Keys, hex.EncodeToString(k))
	}
	sort.Strings(d.Keys)
	for _, k := range signers {
		d.SignedBy = append(d.SignedBy, hex.EncodeToString(k))
	}
	raw, _ := json.Marshal(d)
	if v.store != nil {
		var err error
		if raw, err = v.store.sealLocal(context.Background(), "admin-set", adminSetFile, raw); err != nil {
			return err
		}
	}
	return writeAtomic(v.setPath, raw)
}

// errSetStep marks a refusal that is about the version (stale, a gap, another predecessor): the request may still be right for another member, so the
// coordinator forwards it anyway. Any other refusal (signatures, keys, time, content) is the request's own fault.
var errSetStep = errors.New("version")

// applySet verifies a change of the admin set against this party's state and applies it. b is the request without its AdminAuth, in canonical
// form (admin.Canonical, or admin.BodyFromOpen on a follower). It returns APPLIED, or ALREADY when this party already has exactly this set at this
// version (no signature is looked at: nothing changes), or an error.
func (v *adminVerifier) applySet(b *pb.AdminSetRequest, a *pb.AdminAuth) (pb.RecordOutcome, setSnap, error) {
	newKeys := b.SetKeys
	thr := int(b.SetThreshold)
	if err := admin.CheckAdminSet(newKeys, thr); err != nil {
		return 0, setSnap{}, fmt.Errorf("%w: %v", errAdmin, err)
	}
	newHash := admin.SetHash(newKeys, thr)
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.ensure(); err != nil {
		return 0, setSnap{}, fmt.Errorf("%w: %v", errAdmin, err)
	}
	cur := v.snapLocked()
	switch {
	case b.SetVersion == cur.version && newHash == cur.hash:
		return pb.RecordOutcome_RECORD_OUTCOME_ALREADY, cur, nil
	case b.SetVersion <= cur.version:
		return 0, cur, fmt.Errorf("%w: %w: this party is at version %d: version %d is old (it cannot be replayed)", errAdmin, errSetStep, cur.version, b.SetVersion)
	case b.SetVersion != cur.version+1:
		return 0, cur, fmt.Errorf("%w: %w: this party is at version %d, so it can take version %d next, not %d: apply the changes in between first", errAdmin, errSetStep, cur.version, cur.version+1, b.SetVersion)
	case !bytes.Equal(b.SetPrevHash, cur.hash[:]):
		return 0, cur, fmt.Errorf("%w: %w: the request replaces another admin set (%x...) than this party has (%x...)", errAdmin, errSetStep, head(b.SetPrevHash), cur.hash[:4])
	case newHash == cur.hash:
		return 0, cur, fmt.Errorf("%w: the new admin set equals the current one: nothing to change", errAdmin)
	}
	if a.GetV2() == nil {
		return 0, cur, fmt.Errorf("%w: a change of the admin set needs a v2 authorization (the old v1 format signs no request body)", errAdmin)
	}
	if len(a.PublicKey)+len(a.Signature) != 0 || a.UnixSeconds != 0 {
		return 0, cur, fmt.Errorf("%w: v1 and v2 fields both set", errAdmin)
	}
	bodyHash, err := admin.BodyHash(admin.OpAdminSet, b)
	if err != nil {
		return 0, cur, fmt.Errorf("%w: %v", errAdmin, err)
	}
	sc, err := admin.Verify2(admin.OpAdminSet, "", bodyHash, a.V2)
	if err != nil {
		return 0, cur, fmt.Errorf("%w: %v", errAdmin, err)
	}
	pol := v.policyOf(cur)
	if err := admin.CheckAuth2(admin.OpAdminSet, "", a.V2.Domain, a.V2, admin.UnionPolicy(pol, newKeys), v.now()); err != nil {
		return 0, cur, fmt.Errorf("%w: %v", errAdmin, err)
	}
	if err := admin.CheckSetSignatures(a.V2, pol, newKeys, thr); err != nil {
		return 0, cur, fmt.Errorf("%w: %v", errAdmin, err)
	}
	if a.V2.IssuedUnix < v.start.Unix() {
		return 0, cur, fmt.Errorf("%w: issued at %d, before this party's start (%d): create and sign a new request", errAdmin, a.V2.IssuedUnix, v.start.Unix())
	}
	var keys []ed25519.PublicKey
	for _, k := range newKeys {
		keys = append(keys, ed25519.PublicKey(append([]byte(nil), k...)))
	}
	next := newSnap(cur.version+1, keys, thr)
	next.fromState = true
	if err := v.saveSet(next, cur.hash, sc.Signers); err != nil { // durable before it takes effect; on failure nothing changed
		return 0, cur, fmt.Errorf("%w: cannot record the new admin set: %v", errAdmin, err)
	}
	next.differs = next.hash != v.cfgSet.hash
	v.cur = &next
	v.log.Warn("AUDIT admin set changed", "version", next.version, "keys", len(keys), "threshold", thr, "set_hash", hex.EncodeToString(next.hash[:]),
		"signed_by", signerHexList(sc.Signers))
	return pb.RecordOutcome_RECORD_OUTCOME_APPLIED, next, nil
}

func head(b []byte) []byte {
	if len(b) > 4 {
		return b[:4]
	}
	return b
}

func signerHexList(ks [][]byte) string {
	s := ""
	for i, k := range ks {
		if i > 0 {
			s += ","
		}
		s += hex.EncodeToString(k)
	}
	return s
}

// setStatus is what Health reports of the admin set.
func (v *adminVerifier) setStatus() *pb.AdminSetStatus {
	sn, err := v.snap()
	if err != nil {
		return nil
	}
	st := &pb.AdminSetStatus{Version: sn.version, SetHash: sn.hash[:], Threshold: uint32(sn.threshold), FromState: sn.fromState, ConfigDiffers: sn.differs,
		Domain: v.domain, MaxValiditySeconds: int64(v.maxValidity / time.Second), MaxAgeSeconds: int64(v.maxAge / time.Second)}
	for _, k := range sn.keys {
		st.Keys = append(st.Keys, k)
	}
	return st
}
