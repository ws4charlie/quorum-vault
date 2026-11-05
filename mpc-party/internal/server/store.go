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

// KeysetState is the durable state of one keyset on one party. Generations only grow. During a refresh there is one
// candidate beside the current generation; the old generation's file stays until both parties confirmed the new one.
type KeysetState struct {
	Alg       cbmpc.Alg `json:"alg"`
	Current   uint64    `json:"current"`   // 0 while a DKG is still a candidate
	Candidate uint64    `json:"candidate"` // 0 = none
	Decision  uint64    `json:"decision"`  // party A only: the generation whose commit A decided (durable before B is told)
}

// KeyStore persists keysets (secret, sealed) and key metadata (public). Implementations must write atomically.
type KeyStore interface {
	// PutCandidate durably stores ks as candidate generation gen (the current generation is untouched).
	PutCandidate(ctx context.Context, id string, gen uint64, ks *cbmpc.Keyset) error
	// GetKeyset returns a keyset the caller must Wipe.
	GetKeyset(ctx context.Context, id string, gen uint64) (*cbmpc.Keyset, error)
	// State returns ErrNotFound if the keyset has no state at all.
	State(ctx context.Context, id string) (KeysetState, error)
	RecordDecision(ctx context.Context, id string, gen uint64) error
	// Promote makes the candidate gen current. The previous generation's file is kept.
	Promote(ctx context.Context, id string, gen uint64) error
	// DropCandidate deletes the candidate and clears the decision.
	DropCandidate(ctx context.Context, id string) error
	// DeleteGenerationsBelow deletes sealed files of generations older than gen.
	DeleteGenerationsBelow(ctx context.Context, id string, gen uint64) error
	// RemoveKeyset deletes everything of a keyset (an aborted DKG).
	RemoveKeyset(ctx context.Context, id string) error
	List(ctx context.Context) ([]string, error)
	PutKey(ctx context.Context, m KeyMeta) error
	GetKey(ctx context.Context, keyID string) (KeyMeta, error)
}

// FileStore keeps, per keyset, dir/keysets/<id>/state.json (public) and one sealed file per generation g<N>.json. Files are
// 0600, directories 0700, writes are atomic (temp file in the same directory, fsync, rename, fsync of the directory).
type FileStore struct {
	dir    string
	role   string
	sealer Sealer
	mu     sync.Mutex
}

func NewFileStore(dir, role string, sealer Sealer) (*FileStore, error) {
	for _, d := range []string{dir, filepath.Join(dir, "keysets"), filepath.Join(dir, "keys"), filepath.Join(dir, "jobs"), filepath.Join(dir, "backups")} {
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
	Gen    uint64    `json:"gen"`
	Sealed []byte    `json:"sealed"`
}

// AAD binds role, keyset id, generation and algorithm: a sealed blob moved to another party, keyset or generation does not open.
func aadKeyset(role, id string, gen uint64, alg cbmpc.Alg) []byte {
	return []byte(fmt.Sprintf("qv-mpc-party|keyset|v2|%s|%s|%d|%s", role, id, gen, alg))
}

func (s *FileStore) kdir(id string) string { return filepath.Join(s.dir, "keysets", id) }

func (s *FileStore) readState(id string) (KeysetState, error) {
	var st KeysetState
	raw, err := os.ReadFile(filepath.Join(s.kdir(id), "state.json"))
	if errors.Is(err, os.ErrNotExist) {
		return st, ErrNotFound
	} else if err != nil {
		return st, err
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		return st, fmt.Errorf("keyset %s: bad state file", id)
	}
	return st, nil
}

func (s *FileStore) writeState(id string, st KeysetState) error {
	raw, _ := json.Marshal(st)
	return writeAtomic(filepath.Join(s.kdir(id), "state.json"), raw)
}

func (s *FileStore) State(_ context.Context, id string) (KeysetState, error) {
	if !validID(id) {
		return KeysetState{}, ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readState(id)
}

func (s *FileStore) PutCandidate(_ context.Context, id string, gen uint64, ks *cbmpc.Keyset) error {
	if !validID(id) {
		return fmt.Errorf("invalid keyset id %q", id)
	}
	blob, err := ks.Bytes()
	if err != nil {
		return err
	}
	defer cbmpc.WipeBytes(blob)
	sealed, err := s.sealer.Seal(aadKeyset(s.role, id, gen, ks.Alg()), blob)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(keysetFile{V: 2, Alg: ks.Alg(), Role: s.role, Gen: gen, Sealed: sealed})
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(s.kdir(id), 0o700); err != nil {
		return err
	}
	st, err := s.readState(id)
	if errors.Is(err, ErrNotFound) {
		st = KeysetState{Alg: ks.Alg()}
	} else if err != nil {
		return err
	}
	if gen <= st.Current || (st.Candidate != 0 && st.Candidate != gen) {
		return fmt.Errorf("keyset %s: cannot store candidate generation %d (current %d, candidate %d)", id, gen, st.Current, st.Candidate)
	}
	if err := writeAtomic(filepath.Join(s.kdir(id), fmt.Sprintf("g%d.json", gen)), raw); err != nil {
		return err
	}
	st.Candidate = gen
	st.Decision = 0             // a new candidate never inherits an old decision
	return s.writeState(id, st) // the candidate exists only once this write is durable
}

func (s *FileStore) GetKeyset(_ context.Context, id string, gen uint64) (*cbmpc.Keyset, error) {
	if !validID(id) {
		return nil, fmt.Errorf("invalid keyset id %q", id)
	}
	raw, err := os.ReadFile(filepath.Join(s.kdir(id), fmt.Sprintf("g%d.json", gen)))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}
	var f keysetFile
	if err := json.Unmarshal(raw, &f); err != nil || f.V != 2 || f.Role != s.role || f.Gen != gen {
		return nil, fmt.Errorf("keyset %s generation %d: bad file", id, gen)
	}
	blob, err := s.sealer.Open(aadKeyset(s.role, id, gen, f.Alg), f.Sealed)
	if err != nil {
		return nil, fmt.Errorf("keyset %s generation %d: cannot unseal: %w", id, gen, err)
	}
	role := cbmpc.P1
	if s.role == "B" {
		role = cbmpc.P2
	}
	return cbmpc.LoadKeyset(f.Alg, role, blob) // wipes blob
}

func (s *FileStore) RecordDecision(_ context.Context, id string, gen uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.readState(id)
	if err != nil {
		return err
	}
	if st.Candidate != gen {
		return fmt.Errorf("keyset %s: cannot decide generation %d (candidate %d)", id, gen, st.Candidate)
	}
	st.Decision = gen
	return s.writeState(id, st)
}

func (s *FileStore) Promote(_ context.Context, id string, gen uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.readState(id)
	if err != nil {
		return err
	}
	if st.Current == gen && st.Candidate == 0 {
		return nil // already done (idempotent)
	}
	if st.Candidate != gen {
		return fmt.Errorf("keyset %s: cannot promote generation %d (candidate %d)", id, gen, st.Candidate)
	}
	if _, err := os.Stat(filepath.Join(s.kdir(id), fmt.Sprintf("g%d.json", gen))); err != nil {
		return fmt.Errorf("keyset %s: candidate file missing: %w", id, err)
	}
	st.Current, st.Candidate, st.Decision = gen, 0, 0
	return s.writeState(id, st)
}

func (s *FileStore) DropCandidate(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.readState(id)
	if errors.Is(err, ErrNotFound) {
		return nil
	} else if err != nil {
		return err
	}
	if st.Candidate == 0 {
		st.Decision = 0
		return s.writeState(id, st)
	}
	g := st.Candidate
	if st.Current == 0 { // an unfinished DKG: nothing of the keyset remains
		return os.RemoveAll(s.kdir(id))
	}
	st.Candidate, st.Decision = 0, 0
	if err := s.writeState(id, st); err != nil { // forget it first; the file is garbage once the state no longer names it
		return err
	}
	os.Remove(filepath.Join(s.kdir(id), fmt.Sprintf("g%d.json", g)))
	return nil
}

func (s *FileStore) DeleteGenerationsBelow(_ context.Context, id string, gen uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ents, err := os.ReadDir(s.kdir(id))
	if err != nil {
		return err
	}
	for _, e := range ents {
		var g uint64
		if n, _ := fmt.Sscanf(e.Name(), "g%d.json", &g); n == 1 && g < gen {
			os.Remove(filepath.Join(s.kdir(id), e.Name()))
		}
	}
	return nil
}

func (s *FileStore) RemoveKeyset(_ context.Context, id string) error {
	if !validID(id) {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return os.RemoveAll(s.kdir(id))
}

func (s *FileStore) List(_ context.Context) ([]string, error) {
	ents, err := os.ReadDir(filepath.Join(s.dir, "keysets"))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if e.IsDir() && validID(e.Name()) {
			out = append(out, e.Name())
		}
	}
	return out, nil
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
