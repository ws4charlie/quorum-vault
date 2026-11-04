package server

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// FreezeStore keeps keysets frozen after a cryptographic failure. Durable: it survives restart.
type FreezeStore interface {
	Freeze(keysetID, reason string) error
	Frozen(keysetID string) (bool, string)
	Unfreeze(keysetID string) error
}

type freezeRecord struct {
	KeysetID string    `json:"keyset_id"`
	Reason   string    `json:"reason"`
	At       time.Time `json:"at"`
}

type fileFreeze struct {
	dir string
	mu  sync.Mutex
	m   map[string]freezeRecord
}

// newFileFreeze loads dir/freeze/*.json.
func newFileFreeze(dataDir string) (*fileFreeze, error) {
	dir := filepath.Join(dataDir, "freeze")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f := &fileFreeze{dir: dir, m: map[string]freezeRecord{}}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range ents {
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		var r freezeRecord
		if json.Unmarshal(raw, &r) != nil || !validID(r.KeysetID) {
			continue
		}
		f.m[r.KeysetID] = r
	}
	return f, nil
}

func (f *fileFreeze) Freeze(id, reason string) error {
	if !validID(id) {
		return errors.New("invalid keyset id")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.m[id]; ok {
		return nil
	}
	r := freezeRecord{KeysetID: id, Reason: reason, At: time.Now().UTC()}
	raw, _ := json.Marshal(r)
	if err := writeAtomic(filepath.Join(f.dir, id+".json"), raw); err != nil {
		return err
	}
	f.m[id] = r
	return nil
}

func (f *fileFreeze) Frozen(id string) (bool, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.m[id]
	return ok, r.Reason
}

func (f *fileFreeze) Unfreeze(id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.m[id]; !ok {
		return nil
	}
	if err := os.Remove(filepath.Join(f.dir, id+".json")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	delete(f.m, id)
	return nil
}
