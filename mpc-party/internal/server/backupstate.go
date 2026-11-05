package server

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// BackupState is the record of the last VERIFIED backup of a keyset on this party (public data only).
type BackupState struct {
	KeysetID   string    `json:"keyset_id"`
	Generation uint64    `json:"generation"`
	VerifiedAt time.Time `json:"verified_at"`
	FileSHA256 string    `json:"file_sha256"`
}

func backupStatePath(dataDir, id string) string { return filepath.Join(dataDir, "backups", id+".json") }

// RecordBackup is called by `mpc-party backup export` after it verified the file it wrote.
func RecordBackup(dataDir string, b BackupState) error {
	if !validID(b.KeysetID) {
		return errors.New("invalid keyset id")
	}
	if err := os.MkdirAll(filepath.Join(dataDir, "backups"), 0o700); err != nil {
		return err
	}
	raw, _ := json.Marshal(b)
	return writeAtomic(backupStatePath(dataDir, b.KeysetID), raw)
}

// ReadBackup returns the last verified backup, or a zero value if there is none.
func ReadBackup(dataDir, id string) BackupState {
	var b BackupState
	if raw, err := os.ReadFile(backupStatePath(dataDir, id)); err == nil {
		json.Unmarshal(raw, &b)
	}
	return b
}
