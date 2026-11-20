package server

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ws4charlie/quorum-vault/mpc-party/api/admin"
	"os"
	"path/filepath"
	"sync"
	"time"

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
	maxAge time.Duration
	now    func() time.Time
	start  time.Time
	mu     sync.Mutex
	seen   map[string]time.Time // signature -> the request's timestamp

	// persistence: store (sealed under the attested sealer) or a plain file under dir; neither set means memory only (unit tests).
	store  *FileStore
	path   string
	loaded bool
}

// adminSeenFile is the durable seen set, in the data directory root (listed in the state table in sealer_local.go).
const adminSeenFile = "admin-seen.json"

type adminSeenDoc struct {
	V    int              `json:"v"`
	Seen map[string]int64 `json:"seen"` // hex signature -> unix seconds of the request timestamp
}

// persistOn makes the seen set durable in dataDir; st, when it is a FileStore, seals the file with the local key (attested sealer).
func (v *adminVerifier) persistOn(st any, dataDir string) {
	v.path = filepath.Join(dataDir, adminSeenFile)
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
	v.loaded = true
	return nil
}

// save writes the set durably (temp file, fsync, rename, fsync of the directory).
func (v *adminVerifier) save() error {
	if v.path == "" {
		return nil
	}
	d := adminSeenDoc{V: 1, Seen: make(map[string]int64, len(v.seen))}
	for sig, t := range v.seen {
		d.Seen[sig] = t.Unix()
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
	v := &adminVerifier{maxAge: time.Duration(c.AdminMaxAgeSeconds) * time.Second, now: time.Now, seen: map[string]time.Time{}, start: time.Now()}
	for _, k := range c.AdminKeys {
		b, err := hex.DecodeString(k)
		if err != nil || len(b) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("admin key %q", k)
		}
		v.keys = append(v.keys, ed25519.PublicKey(b))
	}
	return v, nil
}

var errAdmin = errors.New("admin authorization")

// check verifies a for (op, keyset): configured key, valid signature, fresh timestamp, not used before.
func (v *adminVerifier) check(op, keysetID string, a *pb.AdminAuth) (key string, err error) {
	if a == nil || len(a.Signature) != ed25519.SignatureSize || len(a.PublicKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("%w: missing or malformed signature", errAdmin)
	}
	known := false
	for _, k := range v.keys {
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
