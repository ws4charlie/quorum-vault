package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/ws4charlie/quorum-vault/mpc-party/internal/cbmpc"
)

var (
	ErrNotFound = errors.New("not found")
	ErrExists   = errors.New("already exists")
)

var idRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

func validID(s string) bool { return idRe.MatchString(s) && s != "." && s != ".." }

// KeyMeta describes a derived signing key (public data, kept by party A only). The key itself is re-derived with the
// peer inside every Sign session (about 1.5 ms), so no derived blob is ever stored.
type KeyMeta struct {
	KeyID        string    `json:"key_id"`
	KeysetID     string    `json:"keyset_id"`
	Alg          cbmpc.Alg `json:"alg"`
	HardenedPath []uint32  `json:"hardened_path"`
	Path         []uint32  `json:"path"`
	PublicKey    string    `json:"public_key"` // hex
	CreatedAt    time.Time `json:"created_at"`
}

// KeyStore persists keysets (secret) and key metadata (public). Implementations must write atomically.
type KeyStore interface {
	// PutKeyset stores the keyset under id, replacing a previous one only if replace is true (else ErrExists).
	PutKeyset(ctx context.Context, id string, ks *cbmpc.Keyset, replace bool) error
	// GetKeyset returns a keyset the caller must Wipe.
	GetKeyset(ctx context.Context, id string) (*cbmpc.Keyset, error)
	PutKey(ctx context.Context, m KeyMeta) error
	GetKey(ctx context.Context, keyID string) (KeyMeta, error)
}

// FileStore keeps one sealed file per keyset under dir/keysets and one JSON file per key under dir/keys. Files are 0600,
// directories 0700, writes are atomic (temp file in the same directory, fsync, rename, fsync of the directory).
type FileStore struct {
	dir    string
	role   string
	sealer Sealer
	mu     sync.Mutex
}

func NewFileStore(dir, role string, sealer Sealer) (*FileStore, error) {
	for _, d := range []string{dir, filepath.Join(dir, "keysets"), filepath.Join(dir, "keys"), filepath.Join(dir, "jobs")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
		if err := os.Chmod(d, 0o700); err != nil {
			return nil, err
		}
	}
	return &FileStore{dir: dir, role: role, sealer: sealer}, nil
}

type keysetFile struct {
	V      int       `json:"v"`
	Alg    cbmpc.Alg `json:"alg"`
	Role   string    `json:"role"`
	Sealed []byte    `json:"sealed"`
}

func aadKeyset(role, id string, alg cbmpc.Alg) []byte {
	return []byte(fmt.Sprintf("qv-mpc-party|keyset|v1|%s|%s|%s", role, id, alg))
}

func (s *FileStore) PutKeyset(_ context.Context, id string, ks *cbmpc.Keyset, replace bool) error {
	if !validID(id) {
		return fmt.Errorf("invalid keyset id %q", id)
	}
	blob, err := ks.Bytes()
	if err != nil {
		return err
	}
	defer cbmpc.WipeBytes(blob)
	sealed, err := s.sealer.Seal(aadKeyset(s.role, id, ks.Alg()), blob)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(keysetFile{V: 1, Alg: ks.Alg(), Role: s.role, Sealed: sealed})
	s.mu.Lock()
	defer s.mu.Unlock()
	path := filepath.Join(s.dir, "keysets", id+".json")
	if _, err := os.Stat(path); err == nil && !replace {
		return ErrExists
	}
	return writeAtomic(path, raw)
}

func (s *FileStore) GetKeyset(_ context.Context, id string) (*cbmpc.Keyset, error) {
	if !validID(id) {
		return nil, fmt.Errorf("invalid keyset id %q", id)
	}
	raw, err := os.ReadFile(filepath.Join(s.dir, "keysets", id+".json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}
	var f keysetFile
	if err := json.Unmarshal(raw, &f); err != nil || f.V != 1 || f.Role != s.role {
		return nil, fmt.Errorf("keyset %s: bad file", id)
	}
	blob, err := s.sealer.Open(aadKeyset(s.role, id, f.Alg), f.Sealed)
	if err != nil {
		return nil, fmt.Errorf("keyset %s: cannot unseal: %w", id, err)
	}
	role := cbmpc.P1
	if s.role == "B" {
		role = cbmpc.P2
	}
	return cbmpc.LoadKeyset(f.Alg, role, blob) // wipes blob
}

func (s *FileStore) PutKey(_ context.Context, m KeyMeta) error {
	if !validID(m.KeyID) {
		return fmt.Errorf("invalid key id %q", m.KeyID)
	}
	raw, _ := json.Marshal(m)
	s.mu.Lock()
	defer s.mu.Unlock()
	return writeAtomic(filepath.Join(s.dir, "keys", m.KeyID+".json"), raw)
}

func (s *FileStore) GetKey(_ context.Context, keyID string) (KeyMeta, error) {
	var m KeyMeta
	if !validID(keyID) {
		return m, ErrNotFound
	}
	raw, err := os.ReadFile(filepath.Join(s.dir, "keys", keyID+".json"))
	if errors.Is(err, os.ErrNotExist) {
		return m, ErrNotFound
	} else if err != nil {
		return m, err
	}
	return m, json.Unmarshal(raw, &m)
}

// JobRecord is the durable result of a Sign: the first signature for a job id, never replaced.
type JobRecord struct {
	JobID     string    `json:"job_id"`
	KeyID     string    `json:"key_id"`
	Algorithm int32     `json:"algorithm"`
	Digest    string    `json:"digest"`    // hex
	Signature string    `json:"signature"` // hex
	At        time.Time `json:"at"`
}

// JobStore is the idempotency record for Sign.
type JobStore interface {
	GetJob(ctx context.Context, jobID string) (JobRecord, error)
	// PutJob stores the record unless one exists (ErrExists then).
	PutJob(ctx context.Context, r JobRecord) error
}

func jobPath(dir, jobID string) string {
	h := sha256.Sum256([]byte(jobID))
	return filepath.Join(dir, "jobs", hex.EncodeToString(h[:])+".json")
}

func (s *FileStore) GetJob(_ context.Context, jobID string) (JobRecord, error) {
	var r JobRecord
	raw, err := os.ReadFile(jobPath(s.dir, jobID))
	if errors.Is(err, os.ErrNotExist) {
		return r, ErrNotFound
	} else if err != nil {
		return r, err
	}
	if err := json.Unmarshal(raw, &r); err != nil || r.JobID != jobID {
		return r, fmt.Errorf("job record for %q is corrupt", jobID)
	}
	return r, nil
}

func (s *FileStore) PutJob(_ context.Context, r JobRecord) error {
	raw, _ := json.Marshal(r)
	// No store-wide lock: writeExclusive is atomic by itself (hard link fails if the record exists), so concurrent
	// signs do not queue behind each other's fsync.
	return writeExclusive(jobPath(s.dir, r.JobID), raw)
}

// writeExclusive writes data to path durably unless path exists (ErrExists).
func writeExclusive(path string, data []byte) error {
	return writeFile(path, data, true)
}

func writeAtomic(path string, data []byte) error { return writeFile(path, data, false) }

func writeFile(path string, data []byte, exclusive bool) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok || exclusive {
			os.Remove(tmp)
		}
	}()
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
	if exclusive {
		if err := os.Link(tmp, path); err != nil {
			if errors.Is(err, os.ErrExist) {
				return ErrExists
			}
			return err
		}
	} else if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}
