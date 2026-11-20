package approvecli

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Intent is the statement an approver signs, read from its canonical bytes. This is the only place that decides what the CLI shows as "what you
// approve": it never uses the core's JSON version of the intent, because that is what a lying core would change.
//
// Layout (internal/signjob Intent.Canonical): "qv-intent-v2\n", then ten fields in this order, each a 4-byte big-endian length and the bytes:
// kind, id, partition, chain, asset, from, to, amount, not_after (decimal seconds), requested_by. The reader is written again here, not imported
// from signjob, as web/approval/intent.js is written again in JavaScript: a bug in the writer must not be shared by the reader.
type Intent struct {
	Kind, ID, Partition, Chain, Asset, From, To, Amount string
	NotAfter                                            int64
	RequestedBy                                         string
}

const intentDomain = "qv-intent-v2\n"

// ParseCanonical returns the fields, or an error when the bytes are not exactly one v2 intent.
func ParseCanonical(b []byte) (*Intent, error) {
	if !strings.HasPrefix(string(b), intentDomain) {
		return nil, errors.New("not an intent of this version")
	}
	b = b[len(intentDomain):]
	var f [10]string
	for i := range f {
		if len(b) < 4 {
			return nil, errors.New("intent is cut short")
		}
		n := binary.BigEndian.Uint32(b)
		b = b[4:]
		if uint64(n) > uint64(len(b)) {
			return nil, errors.New("intent is cut short")
		}
		if !utf8.Valid(b[:n]) {
			return nil, errors.New("intent has a field that is not text")
		}
		f[i], b = string(b[:n]), b[n:]
	}
	if len(b) != 0 {
		return nil, errors.New("intent has extra bytes")
	}
	na, err := strconv.ParseInt(f[8], 10, 64)
	if err != nil || strconv.FormatInt(na, 10) != f[8] {
		return nil, errors.New("intent has an expiry that is not a number")
	}
	if f[7] == "" || strings.Trim(f[7], "0123456789") != "" {
		return nil, errors.New("intent has an amount that is not a number")
	}
	return &Intent{Kind: f[0], ID: f[1], Partition: f[2], Chain: f[3], Asset: f[4], From: f[5], To: f[6], Amount: f[7], NotAfter: na, RequestedBy: f[9]}, nil
}

// Checked is an intent the core sent, after the checks that make it safe to show.
type Checked struct {
	Intent *Intent
	Hash   [32]byte
	// Required is the number of approvals the core says the withdrawal needs (display only).
	Required int
}

// CheckIntent decides whether the core's answer may be trusted: the hash must be SHA-256 of the canonical bytes, the bytes must be a withdrawal,
// and it must be the withdrawal that was asked for. Anything else is an error, and nothing is shown to approve.
func CheckIntent(canonicalHex, hashHex, wantedID string) (*Checked, error) {
	canonical, err := hex.DecodeString(canonicalHex)
	if err != nil {
		return nil, errors.New("the core's canonical intent is not hex")
	}
	h := sha256.Sum256(canonical)
	got, err := hex.DecodeString(strings.ToLower(hashHex))
	if err != nil || subtle.ConstantTimeCompare(got, h[:]) != 1 {
		return nil, errors.New("the hash the core sent is not the hash of the intent it sent")
	}
	in, err := ParseCanonical(canonical)
	if err != nil {
		return nil, err
	}
	if in.Kind != "withdrawal" {
		return nil, fmt.Errorf("this is not a withdrawal (%s)", in.Kind)
	}
	if in.ID != wantedID {
		return nil, fmt.Errorf("the core answered with another withdrawal (%s)", in.ID)
	}
	return &Checked{Intent: in, Hash: h}, nil
}

// amountText shows base units as a decimal number when the asset's decimals are known, always with the base units next to it.
func amountText(amount, asset string, decimals map[string]int) string {
	d, ok := decimals[asset]
	if !ok || d <= 0 {
		return amount + " " + asset + " (base units)"
	}
	s := strings.Repeat("0", max(0, d+1-len(amount))) + amount
	whole, frac := s[:len(s)-d], strings.TrimRight(s[len(s)-d:], "0")
	if frac != "" {
		whole += "." + frac
	}
	return whole + " " + asset + " (" + amount + " base units)"
}

// Sentence is the intent in plain words.
func (c *Checked) Sentence(decimals map[string]int) string {
	i := c.Intent
	return fmt.Sprintf("Send %s to %s on %s, paid from the pool %s. Requested by %s. Valid until %s.",
		amountText(i.Amount, i.Asset, decimals), i.To, i.Chain, i.Partition, i.RequestedBy, time.Unix(i.NotAfter, 0).UTC().Format("2006-01-02 15:04:05 UTC"))
}
