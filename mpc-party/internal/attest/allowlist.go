package attest

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"time"
)

// AllowEntry says that a party may run the image with this measurement during this window. The list is signed by the operators (task T2);
// this file only holds the matching rule, as a pure function the broker calls after the Verifier accepted the evidence.
type AllowEntry struct {
	Party       string    `json:"party"`
	Measurement string    `json:"measurement"` // hex of PCR0; case-insensitive
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
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
//   - it allows when NotBefore <= now <= NotAfter; overlapping entries are the upgrade overlap, any one that allows is enough;
//   - an entry with an empty party, bad hex or a zero time bound is malformed and refuses the whole check (fail closed), so a bad file
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
		want, err := hex.DecodeString(e.Measurement)
		if e.Party == "" || err != nil || len(want) == 0 || e.NotBefore.IsZero() || e.NotAfter.IsZero() || e.NotAfter.Before(e.NotBefore) {
			return &DeniedError{ReasonBadEntry, fmt.Sprintf("entry %d is malformed", i)}
		}
		wants[i] = want
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
		case now.After(e.NotAfter):
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
