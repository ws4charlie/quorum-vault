package attest

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"time"
)

// AllowEntry says that a party may run the image with this measurement during this window. The list is signed by the operators (task T2);
// this file only holds the matching rule, as a pure function the broker calls after the Verifier accepted the evidence.
type AllowEntry struct {
	Party       string    `json:"party"`
	Measurement string    `json:"measurement"` // hex of PCR0; case-insensitive
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`         // the zero time: no end ("valid-until" is optional)
	Version     string    `json:"version,omitempty"` // the release this measurement belongs to (informational, signed), e.g. v1.4.0
	Status      string    `json:"status,omitempty"`  // "active" (default) or "revoked": a revoked entry refuses its measurement whatever other entries say
}

// Entry status values.
const (
	StatusActive  = "active"
	StatusRevoked = "revoked"
)

var versionRE = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,64}$`)

type allowEntryJSON struct {
	Party       string     `json:"party"`
	Measurement string     `json:"measurement"`
	NotBefore   time.Time  `json:"not_before"`
	NotAfter    *time.Time `json:"not_after,omitempty"`
	Version     string     `json:"version,omitempty"`
	Status      string     `json:"status,omitempty"`
}

// MarshalJSON leaves not_after out when there is none.
func (e AllowEntry) MarshalJSON() ([]byte, error) {
	j := allowEntryJSON{e.Party, e.Measurement, e.NotBefore, nil, e.Version, e.Status}
	if !e.NotAfter.IsZero() {
		j.NotAfter = &e.NotAfter
	}
	return json.Marshal(j)
}

// UnmarshalJSON reads an entry; a missing or null not_after means no end.
func (e *AllowEntry) UnmarshalJSON(b []byte) error {
	var j allowEntryJSON
	if err := json.Unmarshal(b, &j); err != nil {
		return err
	}
	*e = AllowEntry{Party: j.Party, Measurement: j.Measurement, NotBefore: j.NotBefore, Version: j.Version, Status: j.Status}
	if j.NotAfter != nil {
		e.NotAfter = *j.NotAfter
	}
	return nil
}

// Revoked reports whether the entry is a revocation.
func (e AllowEntry) Revoked() bool { return e.Status == StatusRevoked }

// validEntry is the one rule for a well-formed entry (a malformed list is refused whole): returns the measurement bytes.
func validEntry(e AllowEntry, partyOK func(string) bool) ([]byte, bool) {
	m, err := hex.DecodeString(e.Measurement)
	switch {
	case !partyOK(e.Party), err != nil, len(m) == 0, e.NotBefore.IsZero():
		return nil, false
	case !e.NotAfter.IsZero() && e.NotAfter.Before(e.NotBefore):
		return nil, false
	case e.Status != "" && e.Status != StatusActive && e.Status != StatusRevoked:
		return nil, false
	case e.Version != "" && !versionRE.MatchString(e.Version):
		return nil, false
	}
	return m, true
}

// Reason says why an allowlist check refused.
type Reason string

const (
	ReasonDebug       Reason = "debug"
	ReasonNoMeasure   Reason = "no_measurement"
	ReasonBadEntry    Reason = "bad_entry"
	ReasonWrongParty  Reason = "party_not_listed"
	ReasonMeasurement Reason = "measurement_not_allowed"
	ReasonNotYetValid Reason = "not_yet_valid"
	ReasonExpired     Reason = "expired"
	ReasonRevoked     Reason = "revoked"
)

// DeniedError is a refusal with its reason.
type DeniedError struct {
	Reason Reason
	Detail string
}

func (e *DeniedError) Error() string {
	return "attest: allowlist: " + string(e.Reason) + ": " + e.Detail
}

// CheckAllowlist returns nil when claims show an image that entries allow for party at time now, else a *DeniedError. The rule:
//   - debug claims are never allowed (defence in depth; the Verifier already refuses them by default);
//   - an entry applies when its party equals party (exact) and its measurement equals PCR0 (hex, case-insensitive, compared as bytes);
//   - it allows when NotBefore <= now and (NotAfter is zero or now <= NotAfter); overlapping entries are the upgrade overlap, any one that allows is enough;
//   - a revoked entry (status "revoked") for the same party and measurement refuses, whatever other entries say and whatever its window is:
//     revocation wins over an overlap;
//   - an entry with an empty party, bad hex or a zero not_before is malformed and refuses the whole check (fail closed), so a bad file
//     cannot silently allow less or more than intended.
//
// When nothing allows, the reason names the most specific cause: the party has no entry, no entry has this measurement, the matching
// entries all start later (not_yet_valid) or all ended (expired).
func CheckAllowlist(c *Claims, party string, entries []AllowEntry, now time.Time) error {
	if c == nil {
		return &DeniedError{ReasonNoMeasure, "no claims"}
	}
	if c.Debug {
		return &DeniedError{ReasonDebug, "debug-mode evidence"}
	}
	pcr0, ok := c.Measurements[0]
	if !ok || len(pcr0) == 0 {
		return &DeniedError{ReasonNoMeasure, "evidence has no PCR0"}
	}
	wants := make([][]byte, len(entries))
	for i, e := range entries { // validate the whole list first, so a malformed entry refuses even when an earlier one would allow
		want, ok := validEntry(e, func(p string) bool { return p != "" })
		if !ok {
			return &DeniedError{ReasonBadEntry, fmt.Sprintf("entry %d is malformed", i)}
		}
		wants[i] = want
	}
	for i, e := range entries {
		if e.Party == party && e.Revoked() && bytes.Equal(wants[i], pcr0) {
			return &DeniedError{ReasonRevoked, fmt.Sprintf("measurement %s is revoked for party %q", hex.EncodeToString(pcr0), party)}
		}
	}
	var partyListed, measurementListed, future, past bool
	for i, e := range entries {
		want := wants[i]
		if e.Party != party {
			continue
		}
		partyListed = true
		if !bytes.Equal(want, pcr0) {
			continue
		}
		measurementListed = true
		switch {
		case now.Before(e.NotBefore):
			future = true
		case !e.NotAfter.IsZero() && now.After(e.NotAfter):
			past = true
		default:
			return nil
		}
	}
	switch {
	case !partyListed:
		return &DeniedError{ReasonWrongParty, fmt.Sprintf("no entry for party %q", party)}
	case !measurementListed:
		return &DeniedError{ReasonMeasurement, fmt.Sprintf("measurement %s is not allowed for party %q", hex.EncodeToString(pcr0), party)}
	case past:
		// an expired entry and a future one can coexist (a rollover); expired wins only when nothing is ahead
		if future {
			return &DeniedError{ReasonNotYetValid, "matching entry starts later"}
		}
		return &DeniedError{ReasonExpired, "matching entry has ended"}
	default:
		return &DeniedError{ReasonNotYetValid, "matching entry starts later"}
	}
}

// ReasonOf returns the reason of a refusal from CheckAllowlist, or "" for nil or another error.
func ReasonOf(err error) Reason {
	if d, ok := err.(*DeniedError); ok {
		return d.Reason
	}
	return ""
}
