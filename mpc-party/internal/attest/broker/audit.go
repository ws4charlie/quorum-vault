package broker

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// Record is one audit line. It holds no secret: no key, no evidence bytes, no PIN. The nonce is public once used.
type Record struct {
	Time        time.Time `json:"time"`
	Event       string    `json:"event"`           // release, newkey, allowlist_load
	Party       string    `json:"party,omitempty"` // the party the caller's TLS key belongs to
	CtxParty    string    `json:"ctx_party,omitempty"`
	CallerPin   string    `json:"caller_pin,omitempty"`
	Measurement string    `json:"measurement,omitempty"` // PCR0 of the evidence, when it verified
	Nonce       string    `json:"nonce,omitempty"`
	Keyset      string    `json:"keyset,omitempty"`
	Generations []uint64  `json:"generations,omitempty"`
	Outcome     string    `json:"outcome"`          // released, refused, loaded
	Rule        string    `json:"rule,omitempty"`   // the failed rule, e.g. verify:debug, allowlist:expired, nonce:reused
	Detail      string    `json:"detail,omitempty"` // short text of the failure
	Seq         int64     `json:"seq,omitempty"`    // allowlist sequence (allowlist_load)
	Prev        string    `json:"prev"`             // hex SHA-256 of the previous line: a cut or edited line breaks the chain
}

const zeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Audit is an append-only JSON-lines file. Every record is written with O_APPEND and fsynced before the caller goes on; each line carries the
// SHA-256 of the previous one, so VerifyAudit finds a removed, changed or reordered line (not a cut of the tail: for that the file should also be
// append-only at the filesystem level, e.g. chattr +a, and shipped off the host; see the runbook). A failed write is an error, and the broker
// then refuses the release: no key leaves without a record.
type Audit struct {
	mu   sync.Mutex
	f    *os.File
	prev string
}

// OpenAudit opens or creates the file (0600) and continues its chain; a file whose chain is broken is refused.
func OpenAudit(path string) (*Audit, error) {
	if fi, err := os.Stat(path); err == nil && fi.Size() > 0 {
		if _, err := VerifyAudit(path); err != nil {
			return nil, fmt.Errorf("audit: existing log is broken: %w", err)
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	a := &Audit{f: f, prev: zeroHash}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		a.prev = lineHash(sc.Bytes())
	}
	return a, sc.Err()
}

func lineHash(line []byte) string { h := sha256.Sum256(line); return hex.EncodeToString(h[:]) }

// Write appends rec (its Time defaults to now) and syncs.
func (a *Audit) Write(rec Record, now time.Time) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if rec.Time.IsZero() {
		rec.Time = now.UTC()
	}
	rec.Prev = a.prev
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if _, err := a.f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("audit: write: %w", err)
	}
	if err := a.f.Sync(); err != nil {
		return fmt.Errorf("audit: sync: %w", err)
	}
	a.prev = lineHash(line)
	return nil
}

// Close closes the file.
func (a *Audit) Close() error { return a.f.Close() }

// ReadAudit returns the records of a log file.
func ReadAudit(path string) ([]Record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readRecords(f)
}

func readRecords(r io.Reader) ([]Record, error) {
	var out []Record
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var rec Record
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			return nil, fmt.Errorf("audit: line %d: %w", len(out)+1, err)
		}
		out = append(out, rec)
	}
	return out, sc.Err()
}

// VerifyAudit checks the hash chain of a log and returns the number of records.
func VerifyAudit(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	prev, n := zeroHash, 0
	for sc.Scan() {
		var rec Record
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			return n, fmt.Errorf("line %d: %w", n+1, err)
		}
		if rec.Prev != prev {
			return n, fmt.Errorf("line %d: chain broken (a line before it was removed, changed or reordered)", n+1)
		}
		prev = lineHash(sc.Bytes())
		n++
	}
	if err := sc.Err(); err != nil {
		return n, err
	}
	if n == 0 {
		return 0, errors.New("empty log")
	}
	return n, nil
}

func hexs(b []byte) string { return strings.ToLower(hex.EncodeToString(b)) }
