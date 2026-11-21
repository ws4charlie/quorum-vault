package server

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ws4charlie/quorum-vault/mpc-party/api/admin"
	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

// AdminMessage and SignAdmin live in the api module (api/admin) so operator tooling can use them; these are aliases.
func AdminMessage(op, keysetID string, unixSeconds int64) []byte {
	return admin.Message(op, keysetID, unixSeconds)
}

func SignAdmin(priv ed25519.PrivateKey, op, keysetID string, now time.Time) *pb.AdminAuth {
	return admin.Sign(priv, op, keysetID, now)
}

// adminVerifier checks AdminAuth against this party's own configured keys. A signature is accepted once, also across restarts:
//
//  1. Durable seen set (adminSeenFile, in the data directory): every accepted signature is written, fsynced, BEFORE the operation runs and kept until
//     its timestamp is two windows old. A restart reloads it. A crash between "recorded" and "acted" leaves the request spent: the operator signs a new one.
//  2. Start-time rule: a request whose timestamp is older than this process's start is refused. It needs no file, so it also covers a data directory
//     rolled back to an older copy, a deleted or unreadable seen file, and any request captured before the restart. What neither rule covers: an operator
//     clock AHEAD of the party's by d seconds lets a request signed less than d seconds before a restart carry a timestamp after the start, so only the
//     file catches it (and a rollback of the file in the same case); two quick restarts are fine, each one moves the start forward.
//
// The set is per party: each party verifies AdminAuth against its own list and keeps its own memory (see the README).
type adminVerifier struct {
	keys   []ed25519.PublicKey
	maxAge time.Duration // clock skew and, for v1, the age of a signature

	// v2: the quorum, the upper limit of an authorization's validity and the deployment name it must carry. v1 is accepted only when allowV1.
	threshold   int
	maxValidity time.Duration
	domain      string
	allowV1     bool
	log         *slog.Logger
	v1Accepted  atomic.Uint64
	v2Accepted  atomic.Uint64
	now         func() time.Time
	start       time.Time
	mu          sync.Mutex
	seen        map[string]time.Time // v1: signature -> the request's timestamp
	seen2       map[string]time.Time // v2: hex of the signed message's hash -> the authorization's expiry

	// persistence: store (sealed under the attested sealer) or a plain file under dir; neither set means memory only (unit tests).
	store  *FileStore
	path   string
	loaded bool

	// The admin set in effect (adminset.go): keys and threshold above are the bootstrap list of the configuration; cur is the durable state once
	// one exists (a change was applied), and then wins.
	setPath string
	cur     *setSnap
	cfgSet  setSnap // the configuration's list, for the "the configuration is ignored" warning
}

// adminSeenFile is the durable seen set, in the data directory root (listed in the state table in sealer_local.go).
const adminSeenFile = "admin-seen.json"

type adminSeenDoc struct {
	V     int              `json:"v"`
	Seen  map[string]int64 `json:"seen"`            // v1: hex signature -> unix seconds of the request timestamp
	Seen2 map[string]int64 `json:"seen2,omitempty"` // v2: hex message hash -> unix seconds of the expiry
}

// persistOn makes the seen set durable in dataDir; st, when it is a FileStore, seals the file with the local key (attested sealer).
func (v *adminVerifier) persistOn(st any, dataDir string) {
	v.path = filepath.Join(dataDir, adminSeenFile)
	v.setPath = filepath.Join(dataDir, adminSetFile)
	if fs, ok := st.(*FileStore); ok {
		v.store = fs
	}
}

// ensure loads the file once. A missing, unparsable or migrated-away file counts as empty (the start-time rule covers what it held, and an attacker
// who can delete it could delete it anyway); any other failure (the sealer not ready, a sealed file that does not authenticate) refuses the request.
func (v *adminVerifier) ensure() error {
	if v.loaded || v.path == "" {
		return nil
	}
	if err := v.loadSet(); err != nil {
		return err
	}
	raw, err := os.ReadFile(v.path)
	if err == nil {
		if v.store != nil {
			raw, err = v.store.openLocal(context.Background(), "admin-seen", adminSeenFile, raw)
		}
		switch {
		case errors.Is(err, ErrLocalUnsealed), errors.Is(err, ErrLocalSealed):
			raw, err = nil, nil
		case err != nil:
			return fmt.Errorf("%w: seen set unreadable (remove %s and restart the party): %v", errAdmin, v.path, err)
		}
	} else if errors.Is(err, os.ErrNotExist) {
		raw, err = nil, nil
	} else {
		return fmt.Errorf("%w: seen set: %v", errAdmin, err)
	}
	var d adminSeenDoc
	if len(raw) > 0 && json.Unmarshal(raw, &d) == nil {
		for sig, ts := range d.Seen {
			if _, dup := v.seen[sig]; !dup {
				v.seen[sig] = time.Unix(ts, 0)
			}
		}
	}
	for id, ts := range d.Seen2 {
		if _, dup := v.seen2[id]; !dup {
			v.seen2[id] = time.Unix(ts, 0)
		}
	}
	v.loaded = true
	return nil
}

// save writes the set durably (temp file, fsync, rename, fsync of the directory).
func (v *adminVerifier) save() error {
	if v.path == "" {
		return nil
	}
	d := adminSeenDoc{V: 2, Seen: make(map[string]int64, len(v.seen)), Seen2: make(map[string]int64, len(v.seen2))}
	for sig, t := range v.seen {
		d.Seen[sig] = t.Unix()
	}
	for id, t := range v.seen2 {
		d.Seen2[id] = t.Unix()
	}
	raw, _ := json.Marshal(d)
	if v.store != nil {
		var err error
		if raw, err = v.store.sealLocal(context.Background(), "admin-seen", adminSeenFile, raw); err != nil {
			return err
		}
	}
	return writeAtomic(v.path, raw)
}

func newAdminVerifier(c *Config) (*adminVerifier, error) {
	v := &adminVerifier{maxAge: time.Duration(c.AdminMaxAgeSeconds) * time.Second, now: time.Now, seen: map[string]time.Time{}, seen2: map[string]time.Time{}, start: time.Now(),
		threshold: max(c.AdminThreshold, 1), maxValidity: time.Duration(c.AdminMaxValiditySeconds) * time.Second, domain: c.AdminDomain, allowV1: c.adminV1Allowed(),
		log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if v.maxValidity <= 0 {
		v.maxValidity = DefaultAdminMaxValidity
	}
	for _, k := range c.AdminKeys {
		b, err := hex.DecodeString(k)
		if err != nil || len(b) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("admin key %q", k)
		}
		v.keys = append(v.keys, ed25519.PublicKey(b))
	}
	v.cfgSet = v.bootSnap()
	return v, nil
}

// DefaultAdminMaxValidity is the default `admin_max_validity_seconds`: an authorization may be valid for an hour at most, long enough for several
// admins to sign one file in turn and short enough that a stolen file expires.
const DefaultAdminMaxValidity = time.Hour

var errAdmin = errors.New("admin authorization")

// policy is what the party needs of an authorization now: the admin set in effect (the durable one once a change was applied, else the
// configuration's) and the configured limits. It fails when the durable set cannot be read: nothing is accepted then.
func (v *adminVerifier) policy() (admin.Policy, error) {
	sn, err := v.snap()
	if err != nil {
		return admin.Policy{}, err
	}
	return v.policyOf(sn), nil
}

func (v *adminVerifier) policyOf(sn setSnap) admin.Policy {
	p := admin.Policy{Threshold: sn.threshold, MaxValidity: v.maxValidity, Skew: v.maxAge, Domain: v.domain}
	for _, k := range sn.keys {
		p.Keys = append(p.Keys, k)
	}
	return p
}

// writeMetrics adds the counters of accepted authorizations. A v1 count that keeps growing after the roll-over means a tool still signs the old way.
func (v *adminVerifier) writeMetrics(w io.Writer) {
	if v == nil {
		return
	}
	fmt.Fprintf(w, "# HELP qv_mpc_party_admin_auth_accepted_total Admin authorizations this party accepted, by format. v1 is the old single-signature format that does not cover the request body: it should stay at 0 once admin_threshold is set.\n# TYPE qv_mpc_party_admin_auth_accepted_total counter\n")
	fmt.Fprintf(w, "qv_mpc_party_admin_auth_accepted_total{version=\"v1\"} %d\nqv_mpc_party_admin_auth_accepted_total{version=\"v2\"} %d\n", v.v1Accepted.Load(), v.v2Accepted.Load())
	if st := v.setStatus(); st != nil {
		fmt.Fprintf(w, "# HELP qv_mpc_party_admin_set_version Version of this party's admin set (0 = the configuration's bootstrap list). Parties of one deployment must report the same value.\n# TYPE qv_mpc_party_admin_set_version gauge\nqv_mpc_party_admin_set_version %d\n", st.Version)
		differs := 0
		if st.ConfigDiffers {
			differs = 1
		}
		fmt.Fprintf(w, "# HELP qv_mpc_party_admin_config_ignored 1 when this party has a durable admin set and its configuration lists another one (the configuration is ignored).\n# TYPE qv_mpc_party_admin_config_ignored gauge\nqv_mpc_party_admin_config_ignored %d\n", differs)
	}
}

// check verifies a for (op, keyset, body): body is the request the party holds, WITHOUT its AdminAuth, in the canonical form of api/admin (DKGBody,
// RefreshBody, UnfreezeBody; a follower rebuilds it from the Open it received). It returns the admin keys that signed, for the audit log.
//
// v2: the signed message is rebuilt here from op, keyset, domain, the hash of body and the authorization's times and nonce, so any request
// field, the keyset, the operation or the deployment that differs from what was signed fails the signatures. Then: every signer a configured
// key (an unknown key refuses the whole authorization), no key twice, at least admin_threshold signers, inside its validity (and not longer
// than admin_max_validity_seconds), not issued before this process started, and not used before. The replay memory keys on the hash of the
// signed message: one authorization is spent once, whichever admins signed it and in whichever order, and a nonce an operator reuses on a
// different request does not collide.
//
// v1 only when the party's config allows it; it is logged and counted every time.
// checkOpen is check for a follower: the body is rebuilt from the Open the caller forwarded (admin.BodyFromOpen, every request field by name), so
// what the signature covers is what the follower is asked to do.
func (v *adminVerifier) checkOpen(op string, open *pb.Open) (string, error) {
	body, err := admin.BodyFromOpen(op, open)
	if err != nil {
		return "", err
	}
	return v.check(op, open.KeysetId, body, open.Admin)
}

func (v *adminVerifier) check(op, keysetID string, body proto.Message, a *pb.AdminAuth) (key string, err error) {
	if op == admin.OpAdminSet || op == admin.OpRecoveryKey {
		return "", fmt.Errorf("%w: internal: %s is checked by its own path", errAdmin, op)
	}
	switch {
	case a.GetV2() != nil:
		if len(a.PublicKey)+len(a.Signature) != 0 || a.UnixSeconds != 0 {
			return "", fmt.Errorf("%w: v1 and v2 fields both set", errAdmin)
		}
		return v.check2(op, keysetID, body, a.V2)
	case a == nil:
		return "", fmt.Errorf("%w: missing", errAdmin)
	}
	if _, err := v.snap(); err != nil { // an unreadable admin set refuses with its own reason, not with a misleading one about v1
		return "", fmt.Errorf("%w: %v", errAdmin, err)
	}
	if !v.v1Allowed() {
		return "", fmt.Errorf("%w: this party no longer accepts the v1 authorization format (it does not cover the request body or a quorum): sign a v2 request with qv-party-admin", errAdmin)
	}
	key, err = v.check1(op, keysetID, a)
	if err == nil {
		v.v1Accepted.Add(1)
		v.log.Warn("AUDIT admin authorization accepted in the v1 format (no request binding, no quorum): move the operators to v2 and set admin_threshold", "op", op, "keyset_id", keysetID, "admin_key", key)
	}
	return key, err
}

func (v *adminVerifier) check2(op, keysetID string, body proto.Message, a *pb.AdminAuthV2) (string, error) {
	if body == nil {
		return "", fmt.Errorf("%w: internal: no request body to check", errAdmin)
	}
	hash, err := admin.BodyHash(op, body)
	if err != nil {
		return "", fmt.Errorf("%w: %v", errAdmin, err)
	}
	sc, err := admin.Verify2(op, keysetID, hash, a)
	if err != nil {
		return "", fmt.Errorf("%w: %v", errAdmin, err)
	}
	now := v.now()
	pol, err := v.policy()
	if err != nil {
		return "", fmt.Errorf("%w: %v", errAdmin, err)
	}
	if err := admin.CheckAuth2(op, keysetID, a.Domain, a, pol, now); err != nil {
		return "", fmt.Errorf("%w: %v", errAdmin, err)
	}
	if a.IssuedUnix < v.start.Unix() {
		return "", fmt.Errorf("%w: issued at %d, before this party's start (%d): create and sign a new request", errAdmin, a.IssuedUnix, v.start.Unix())
	}
	id := admin.MessageID(sc.Message)
	idHex := hex.EncodeToString(id[:])
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.ensure(); err != nil {
		return "", err
	}
	for k, t := range v.seen2 { // forget entries that expired (with a margin for clock steps): no signature of theirs can pass the time check any more
		if now.Sub(t) > 2*v.maxAge {
			delete(v.seen2, k)
		}
	}
	if _, dup := v.seen2[idHex]; dup {
		return "", fmt.Errorf("%w: this authorization was already used", errAdmin)
	}
	v.seen2[idHex] = time.Unix(a.ExpiresUnix, 0)
	if err := v.save(); err != nil { // durable before the operation runs; on failure the request is refused and not spent
		delete(v.seen2, idHex)
		return "", fmt.Errorf("%w: cannot record the request: %v", errAdmin, err)
	}
	v.v2Accepted.Add(1)
	keys := ""
	for i, k := range sc.Signers {
		if i > 0 {
			keys += ","
		}
		keys += hex.EncodeToString(k)
	}
	return keys, nil
}

// check1 verifies a v1 authorization for (op, keyset): configured key, valid signature, fresh timestamp, not used before.
func (v *adminVerifier) check1(op, keysetID string, a *pb.AdminAuth) (key string, err error) {
	if len(a.Signature) != ed25519.SignatureSize || len(a.PublicKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("%w: missing or malformed signature", errAdmin)
	}
	sn, err := v.snap()
	if err != nil {
		return "", fmt.Errorf("%w: %v", errAdmin, err)
	}
	known := false
	for _, k := range sn.keys {
		if string(k) == string(a.PublicKey) {
			known = true
		}
	}
	if !known {
		return "", fmt.Errorf("%w: not a configured admin key", errAdmin)
	}
	now := v.now()
	age := now.Sub(time.Unix(a.UnixSeconds, 0))
	if age > v.maxAge || age < -v.maxAge {
		return "", fmt.Errorf("%w: timestamp %d is outside the accepted window of %s", errAdmin, a.UnixSeconds, v.maxAge)
	}
	if a.UnixSeconds < v.start.Unix() {
		return "", fmt.Errorf("%w: timestamp %d is older than this party's start (%d): sign a new request", errAdmin, a.UnixSeconds, v.start.Unix())
	}
	if !ed25519.Verify(ed25519.PublicKey(a.PublicKey), AdminMessage(op, keysetID, a.UnixSeconds), a.Signature) {
		return "", fmt.Errorf("%w: bad signature for (%s, %s)", errAdmin, op, keysetID)
	}
	sig := hex.EncodeToString(a.Signature)
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.ensure(); err != nil {
		return "", err
	}
	for k, t := range v.seen { // forget entries whose timestamp left the window (with a margin for clock steps)
		if now.Sub(t) > 2*v.maxAge {
			delete(v.seen, k)
		}
	}
	if _, dup := v.seen[sig]; dup {
		return "", fmt.Errorf("%w: signature already used", errAdmin)
	}
	v.seen[sig] = time.Unix(a.UnixSeconds, 0)
	if err := v.save(); err != nil { // durable before the operation runs; on failure the request is refused and not spent
		delete(v.seen, sig)
		return "", fmt.Errorf("%w: cannot record the request: %v", errAdmin, err)
	}
	return hex.EncodeToString(a.PublicKey), nil
}
