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
	"time"

	"github.com/ws4charlie/quorum-vault/mpc-party/api/admin"
)

// RecordsFile is the public state a restored party needs besides its share: the admin set and the recovery-key registry the other parties hold.
// `qv-party-admin records export` writes it from the surviving parties, and only when they all agree; `mpc-party backup restore -records` writes the two
// records into the restored data directory. Both are public data. Each was applied as a signed, versioned request; the file is as trustworthy as the
// parties that agreed on it.
type RecordsFile struct {
	V        int              `json:"v"`
	AdminSet RecordsAdminSet  `json:"admin_set"`
	Registry RecoveryRegistry `json:"recovery_key_registry"`
}

type RecordsAdminSet struct {
	Version   uint64   `json:"version"`
	Keys      []string `json:"keys"` // hex
	Threshold int      `json:"threshold"`
	Hash      string   `json:"hash"` // hex, a check only: recomputed on reading
}

// ParseRecordsFile reads and checks a records file: known fields only, a valid admin set and registry, and the hash of the admin set recomputed.
func ParseRecordsFile(raw []byte) (RecordsFile, error) {
	var f RecordsFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil || f.V != 1 {
		return f, errors.New("not a records file (version 1)")
	}
	if f.AdminSet.Version > 0 {
		var keys [][]byte
		for _, k := range f.AdminSet.Keys {
			b, err := hex.DecodeString(k)
			if err != nil {
				return f, errors.New("records file: an admin key is not hex")
			}
			keys = append(keys, b)
		}
		if err := admin.CheckAdminSet(keys, f.AdminSet.Threshold); err != nil {
			return f, fmt.Errorf("records file: %w", err)
		}
		h := admin.SetHash(keys, f.AdminSet.Threshold)
		if hex.EncodeToString(h[:]) != f.AdminSet.Hash {
			return f, errors.New("records file: the admin set does not match its hash (the file was edited)")
		}
	}
	if f.Registry.Version > 0 {
		if err := admin.CheckRecoveryRecord(f.Registry.Current, f.Registry.Retired); err != nil {
			return f, fmt.Errorf("records file: %w", err)
		}
	}
	return f, nil
}

// WriteRestoredRecords writes the records of f into the data directory of st (a restore into an empty directory). A record at version 0 (never
// changed) is not written. It refuses a directory that already has either record.
func WriteRestoredRecords(ctx context.Context, st *FileStore, f RecordsFile) error {
	setPath, regPath := filepath.Join(st.dir, adminSetFile), filepath.Join(st.dir, recoveryRegFile)
	for _, p := range []string{setPath, regPath} {
		if _, err := os.Stat(p); err == nil {
			return fmt.Errorf("the target data directory already has %s: restore into an empty directory", filepath.Base(p))
		}
	}
	now := time.Now().Unix()
	if f.AdminSet.Version > 0 {
		d := adminSetDoc{V: 1, Version: f.AdminSet.Version, Keys: f.AdminSet.Keys, Threshold: f.AdminSet.Threshold, AppliedUnix: now, SignedBy: []string{}}
		raw, _ := json.Marshal(d)
		sealed, err := st.sealLocal(ctx, "admin-set", adminSetFile, raw)
		if err != nil {
			return err
		}
		if err := writeAtomic(setPath, sealed); err != nil {
			return err
		}
	}
	if f.Registry.Version > 0 {
		d := recoveryDoc{V: 1, Version: f.Registry.Version, Current: f.Registry.Current, Retired: f.Registry.Retired, AppliedUnix: now, SignedBy: []string{}}
		raw, _ := json.Marshal(d)
		sealed, err := st.sealLocal(ctx, "recovery-key", recoveryRegFile, raw)
		if err != nil {
			return err
		}
		if err := writeAtomic(regPath, sealed); err != nil {
			return err
		}
	}
	return nil
}
