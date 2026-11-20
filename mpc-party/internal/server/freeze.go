package server

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
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

	// With the attested sealer the records are sealed (sealer_local.go) and can only be read once the data keys are released: they are loaded on
	// first use, and until then every keyset counts as frozen (fail closed).
	fs        *FileStore
	loaded    bool
	loadError error
}

// newFileFreeze loads dir/freeze/*.json (plain files: the sealers that need no sealing of local state).
func newFileFreeze(dataDir string) (*fileFreeze, error) {
	dir := filepath.Join(dataDir, "freeze")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f := &fileFreeze{dir: dir, m: map[string]freezeRecord{}}
	if err := f.load(); err != nil {
		return nil, err
	}
	f.loaded = true
	return f, nil
}

// newFileFreezeOn keeps the records through the store, so they are sealed when its sealer seals local state. Loading is lazy for such a store.
func newFileFreezeOn(fs *FileStore) (*fileFreeze, error) {
	if fs.scoped == nil {
		return newFileFreeze(fs.dir)
	}
	dir := filepath.Join(fs.dir, "freeze")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &fileFreeze{dir: dir, m: map[string]freezeRecord{}, fs: fs}, nil
}

func (f *fileFreeze) load() error {
	ents, err := os.ReadDir(f.dir)
	if err != nil {
		return err
	}
	f.m = map[string]freezeRecord{}
	for _, e := range ents {
		name := strings.TrimSuffix(e.Name(), ".json")
		raw, err := os.ReadFile(filepath.Join(f.dir, e.Name()))
		if err != nil {
			return err
		}
		if f.fs != nil {
			if !validID(name) || !strings.HasSuffix(e.Name(), ".json") {
				continue
			}
			plain, oerr := f.fs.openLocal(context.Background(), "freeze", name, raw)
			if oerr != nil {
				var ue *UnavailableError
				if errors.As(oerr, &ue) {
					return oerr // keys not released yet: try again later
				}
				// A record that does not open (forged, moved, damaged) is not "no record": the keyset stays frozen.
				f.m[name] = freezeRecord{KeysetID: name, Reason: "the freeze record of this keyset cannot be opened (forged, moved or damaged): " + oerr.Error(), At: time.Now().UTC()}
				continue
			}
			raw = plain
		}
		if f.fs == nil && isEnvelope(raw) {
			return ErrLocalSealed
		}
		var r freezeRecord
		if json.Unmarshal(raw, &r) != nil || !validID(r.KeysetID) {
			if f.fs != nil && validID(name) {
				f.m[name] = freezeRecord{KeysetID: name, Reason: "the freeze record of this keyset is unreadable", At: time.Now().UTC()}
			}
			continue
		}
		f.m[r.KeysetID] = r
	}
	return nil
}

// ensure loads the records once the sealer can open them.
func (f *fileFreeze) ensure() error {
	if f.loaded {
		return nil
	}
	if err := f.load(); err != nil {
		f.loadError = err
		return err
	}
	f.loaded, f.loadError = true, nil
	return nil
}

func (f *fileFreeze) Freeze(id, reason string) error {
	if !validID(id) {
		return errors.New("invalid keyset id")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.ensure(); err != nil {
		return err
	}
	if _, ok := f.m[id]; ok {
		return nil
	}
	r := freezeRecord{KeysetID: id, Reason: reason, At: time.Now().UTC()}
	raw, _ := json.Marshal(r)
	if f.fs != nil {
		var err error
		if raw, err = f.fs.sealLocal(context.Background(), "freeze", id, raw); err != nil {
			return err
		}
	}
	if err := writeAtomic(filepath.Join(f.dir, id+".json"), raw); err != nil {
		return err
	}
	f.m[id] = r
	return nil
}

func (f *fileFreeze) Frozen(id string) (bool, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.ensure(); err != nil {
		return true, "the freeze records cannot be read yet (the data keys are not released): " + err.Error()
	}
	r, ok := f.m[id]
	return ok, r.Reason
}

func (f *fileFreeze) Unfreeze(id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.ensure(); err != nil {
		return err
	}
	if _, ok := f.m[id]; !ok {
		return nil
	}
	if err := os.Remove(filepath.Join(f.dir, id+".json")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	delete(f.m, id)
	return nil
}
