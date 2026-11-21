package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ws4charlie/quorum-vault/mpc-party/api/admin"
	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

// The recovery-key registry: which recovery key (by fingerprint) the backups of this party must be made under, and which ones are retired.
// Replacing the recovery key is a ceremony (docs/runbooks/mpc-backup-restore.md); the registry makes the party hold the line while it happens:
// `mpc-party backup export` refuses a retired key, and Health says per keyset which key its newest backup is under.
//
// It is changed like the admin set: an admin request (op "recovery-key") signed by the admin quorum, applied by every member to a durable
// record (recovery-key.json, sealed like the other local state), with a version that rises by one and the hash of the record it replaces. No record
// (version 0) restricts nothing, so a deployment that never registers a key behaves as before.

// recoveryRegFile is the durable registry, in the data directory root.
const recoveryRegFile = "recovery-key.json"

// RecoveryRegistry is the registry as the party holds it.
type RecoveryRegistry struct {
	Version uint64   `json:"version"`
	Current string   `json:"current"` // fingerprint (hex) of the key backups must be made under; "" = none named
	Retired []string `json:"retired"` // sorted
}

// Hash is the hash a request names as the record it replaces.
func (r RecoveryRegistry) Hash() [32]byte { return admin.RecoveryHash(r.Current, r.Retired) }

// IsRetired says whether fpr is a retired recovery key.
func (r RecoveryRegistry) IsRetired(fpr string) bool {
	for _, f := range r.Retired {
		if f == fpr {
			return true
		}
	}
	return false
}

// Allows says whether a backup may be made under the recovery key with fingerprint fpr: not when the key is retired, and, when the registry names a
// current key, only under that one. With no record (version 0) every key is allowed.
func (r RecoveryRegistry) Allows(fpr string) error {
	switch {
	case r.IsRetired(fpr):
		return fmt.Errorf("recovery key %s is RETIRED (registry version %d): a backup under it would be opened by a key that was replaced; use the current recovery key%s", fpr, r.Version, r.currentHint())
	case r.Current != "" && fpr != r.Current:
		return fmt.Errorf("recovery key %s is not the current one (registry version %d): backups must be made under %s", fpr, r.Version, r.Current)
	}
	return nil
}

func (r RecoveryRegistry) currentHint() string {
	if r.Current == "" {
		return " (none is registered yet: register the new key with qv-party-admin recovery-key first)"
	}
	return " " + r.Current
}

type recoveryDoc struct {
	V           int      `json:"v"`
	Version     uint64   `json:"version"`
	Current     string   `json:"current"`
	Retired     []string `json:"retired"`
	PrevHash    string   `json:"prev_hash"`
	AppliedUnix int64    `json:"applied_unix"`
	SignedBy    []string `json:"signed_by"`
}

type recoveryStore struct {
	path   string
	fs     *FileStore
	mu     sync.Mutex
	loaded bool
	cur    RecoveryRegistry
	now    func() time.Time
}

func newRecoveryStore(st any, dataDir string) *recoveryStore {
	r := &recoveryStore{path: filepath.Join(dataDir, recoveryRegFile), now: time.Now}
	if fs, ok := st.(*FileStore); ok {
		r.fs = fs
	}
	return r
}

// ReadRecoveryRegistry reads the registry of the party whose data directory st serves (for the offline commands). A missing record is version 0.
func ReadRecoveryRegistry(st *FileStore) (RecoveryRegistry, error) {
	r := newRecoveryStore(st, st.dir)
	return r.get()
}

func (r *recoveryStore) get() (RecoveryRegistry, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.load(); err != nil {
		return RecoveryRegistry{}, err
	}
	return r.cur, nil
}

func (r *recoveryStore) load() error {
	if r.loaded {
		return nil
	}
	raw, err := os.ReadFile(r.path)
	if errors.Is(err, os.ErrNotExist) {
		r.loaded = true
		return nil
	}
	if err != nil {
		return fmt.Errorf("recovery-key registry: %v", err)
	}
	if r.fs != nil {
		if raw, err = r.fs.openLocal(context.Background(), "recovery-key", recoveryRegFile, raw); err != nil {
			return fmt.Errorf("the recovery-key registry (%s) cannot be opened: %v", r.path, err)
		}
	} else if isEnvelope(raw) {
		return fmt.Errorf("the recovery-key registry (%s) is sealed by the attested sealer and this party has another sealer", r.path)
	}
	var d recoveryDoc
	if err := json.Unmarshal(raw, &d); err != nil || d.V != 1 {
		return fmt.Errorf("the recovery-key registry (%s) is not valid", r.path)
	}
	r.cur = RecoveryRegistry{Version: d.Version, Current: d.Current, Retired: d.Retired}
	r.loaded = true
	return nil
}

func (r *recoveryStore) save(reg RecoveryRegistry, prev [32]byte, signers [][]byte) error {
	d := recoveryDoc{V: 1, Version: reg.Version, Current: reg.Current, Retired: reg.Retired, PrevHash: hex.EncodeToString(prev[:]), AppliedUnix: r.now().Unix()}
	for _, k := range signers {
		d.SignedBy = append(d.SignedBy, hex.EncodeToString(k))
	}
	raw, _ := json.Marshal(d)
	if r.fs != nil {
		var err error
		if raw, err = r.fs.sealLocal(context.Background(), "recovery-key", recoveryRegFile, raw); err != nil {
			return err
		}
	}
	return writeAtomic(r.path, raw)
}

// apply verifies a registry change and applies it. verify checks the admin authorization (the admin set's quorum) and returns the signers.
func (r *recoveryStore) apply(b *pb.RecoveryKeyRequest, verify func() ([][]byte, error), log interface {
	Warn(string, ...any)
}) (pb.RecordOutcome, RecoveryRegistry, error) {
	if err := admin.CheckRecoveryRecord(b.RkCurrent, b.RkRetire); err != nil {
		return 0, RecoveryRegistry{}, fmt.Errorf("%w: %v", errAdmin, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.load(); err != nil {
		return 0, RecoveryRegistry{}, fmt.Errorf("%w: %v", errAdmin, err)
	}
	cur := r.cur
	already := b.RkVersion == cur.Version && b.RkCurrent == cur.Current
	for _, f := range b.RkRetire {
		already = already && cur.IsRetired(f)
	}
	hash := cur.Hash()
	switch {
	case already && cur.Version > 0:
		return pb.RecordOutcome_RECORD_OUTCOME_ALREADY, cur, nil
	case b.RkVersion <= cur.Version:
		return 0, cur, fmt.Errorf("%w: %w: this party is at registry version %d: version %d is old (it cannot be replayed)", errAdmin, errSetStep, cur.Version, b.RkVersion)
	case b.RkVersion != cur.Version+1:
		return 0, cur, fmt.Errorf("%w: %w: this party is at registry version %d, so it can take version %d next, not %d: apply the changes in between first", errAdmin, errSetStep, cur.Version, cur.Version+1, b.RkVersion)
	case !bytes.Equal(b.RkPrevHash, hash[:]):
		return 0, cur, fmt.Errorf("%w: %w: the request replaces another registry (%x...) than this party has (%x...)", errAdmin, errSetStep, head(b.RkPrevHash), hash[:4])
	case cur.IsRetired(b.RkCurrent):
		return 0, cur, fmt.Errorf("%w: recovery key %s was retired earlier and cannot become the current key again", errAdmin, b.RkCurrent)
	}
	signers, err := verify()
	if err != nil {
		return 0, cur, err
	}
	next := RecoveryRegistry{Version: cur.Version + 1, Current: b.RkCurrent}
	seen := map[string]bool{}
	for _, f := range append(append([]string(nil), cur.Retired...), b.RkRetire...) {
		if !seen[f] {
			seen[f] = true
			next.Retired = append(next.Retired, f)
		}
	}
	sort.Strings(next.Retired)
	if len(next.Retired) > admin.MaxRetired {
		return 0, cur, fmt.Errorf("%w: the registry would list %d retired recovery keys, at most %d", errAdmin, len(next.Retired), admin.MaxRetired)
	}
	if err := r.save(next, hash, signers); err != nil {
		return 0, cur, fmt.Errorf("%w: cannot record the registry: %v", errAdmin, err)
	}
	r.cur = next
	log.Warn("AUDIT recovery-key registry changed", "version", next.Version, "current", next.Current, "retired", len(next.Retired), "signed_by", signerHexList(signers))
	return pb.RecordOutcome_RECORD_OUTCOME_APPLIED, next, nil
}

func (r RecoveryRegistry) status() *pb.RecoveryKeyStatus {
	h := r.Hash()
	return &pb.RecoveryKeyStatus{Version: r.Version, Current: r.Current, Retired: r.Retired, Hash: h[:]}
}

// authorizeRecord checks a v2 authorization for a request that is applied by version rather than spent by nonce (the recovery-key registry): the
// signatures, the signers (the admin set in effect), the quorum, the domain and the time. It looks at no replay memory: the request's version and
// predecessor hash keep it from applying twice.
func (v *adminVerifier) authorizeRecord(op string, body proto.Message, a *pb.AdminAuth) ([][]byte, error) {
	if a.GetV2() == nil {
		return nil, fmt.Errorf("%w: this request needs a v2 authorization (the old v1 format signs no request body)", errAdmin)
	}
	if len(a.PublicKey)+len(a.Signature) != 0 || a.UnixSeconds != 0 {
		return nil, fmt.Errorf("%w: v1 and v2 fields both set", errAdmin)
	}
	hash, err := admin.BodyHash(op, body)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errAdmin, err)
	}
	sc, err := admin.Verify2(op, "", hash, a.V2)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errAdmin, err)
	}
	pol, err := v.policy()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errAdmin, err)
	}
	if err := admin.CheckAuth2(op, "", a.V2.Domain, a.V2, pol, v.now()); err != nil {
		return nil, fmt.Errorf("%w: %v", errAdmin, err)
	}
	if a.V2.IssuedUnix < v.start.Unix() {
		return nil, fmt.Errorf("%w: issued at %d, before this party's start (%d): create and sign a new request", errAdmin, a.V2.IssuedUnix, v.start.Unix())
	}
	return sc.Signers, nil
}
