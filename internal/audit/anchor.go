package audit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5"
)

// Anchor is the head of a chain as it was published: the entry count and last hash at a time. Anyone who kept the anchors
// can later tell whether the table was cut short or rewritten, because the table can no longer produce that seq and hash.
type Anchor struct {
	Source string    `json:"source"` // "core", "gateway" or "cosigner"
	Seq    int64     `json:"seq"`    // 0: an empty chain
	Hash   string    `json:"hash"`   // hex of the last entry's hash
	At     time.Time `json:"at"`
}

// Head returns the current head of the chain of q's database. An empty chain has seq 0 and the genesis hash.
func Head(ctx context.Context, q Querier, source string) (Anchor, error) {
	a := Anchor{Source: source, Hash: hex.EncodeToString(genesis), At: time.Now().UTC().Truncate(time.Millisecond)}
	var h []byte
	err := q.QueryRow(ctx, `SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1`).Scan(&a.Seq, &h)
	if errors.Is(err, pgx.ErrNoRows) {
		return a, nil
	}
	if err != nil {
		return Anchor{}, fmt.Errorf("audit: head: %w", err)
	}
	a.Hash = hex.EncodeToString(h)
	return a, nil
}

// ReadAnchors reads anchors written one JSON object per line (what a consumer of qv.audit.heads dumps). Lines of other
// sources are skipped when source is not empty. A line that is not an anchor is an error: a file that cannot be read in
// full proves nothing.
func ReadAnchors(r io.Reader, source string) ([]Anchor, error) {
	var out []Anchor
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for n := 1; sc.Scan(); n++ {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var a Anchor
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&a); err != nil || a.Seq < 0 || len(a.Hash) != 64 {
			return nil, fmt.Errorf("audit: anchors line %d is not an anchor", n)
		}
		if source == "" || a.Source == source {
			out = append(out, a)
		}
	}
	return out, sc.Err()
}

// Report is the outcome of CheckAnchors.
type Report struct {
	OK       bool
	Problem  string // what is wrong, when not OK
	BadSeq   int64  // first entry the chain check rejected, if that was the problem
	Anchors  int    // anchors checked
	HeadSeq  int64
	HeadHash string
}

// CheckAnchors verifies the chain of q's database and then every anchor: the chain must still hold the entry the anchor names,
// with the same hash. A chain that was cut short fails the first anchor beyond its tail; a chain rewritten from some entry on
// fails the first anchor at or after it.
func CheckAnchors(ctx context.Context, q Querier, anchors []Anchor) (Report, error) {
	head, err := Head(ctx, q, "")
	if err != nil {
		return Report{}, err
	}
	rep := Report{Anchors: len(anchors), HeadSeq: head.Seq, HeadHash: head.Hash}
	ok, bad, err := VerifyChain(ctx, q)
	if err != nil {
		return Report{}, err
	}
	if !ok {
		rep.BadSeq, rep.Problem = bad, fmt.Sprintf("the chain is broken at seq %d (an entry was changed, removed or inserted)", bad)
		return rep, nil
	}
	for _, a := range anchors {
		if a.Seq == 0 {
			continue
		}
		var h []byte
		err := q.QueryRow(ctx, `SELECT hash FROM audit_log WHERE seq=$1`, a.Seq).Scan(&h)
		if errors.Is(err, pgx.ErrNoRows) {
			rep.Problem = fmt.Sprintf("anchor of %s names seq %d but the chain ends at seq %d: the tail was cut off", a.At.Format(time.RFC3339), a.Seq, head.Seq)
			return rep, nil
		}
		if err != nil {
			return Report{}, fmt.Errorf("audit: anchor lookup: %w", err)
		}
		if hex.EncodeToString(h) != a.Hash {
			rep.Problem = fmt.Sprintf("anchor of %s names seq %d with hash %s but the chain has %x there: the chain was rewritten", a.At.Format(time.RFC3339), a.Seq, a.Hash, h)
			return rep, nil
		}
	}
	rep.OK = true
	return rep, nil
}
