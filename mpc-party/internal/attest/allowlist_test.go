package attest

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestAllowlist(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	pcr0 := make([]byte, 48)
	pcr0[0], pcr0[47] = 0xab, 0xcd
	claims := &Claims{Measurements: map[int][]byte{0: pcr0}}
	m := hex.EncodeToString(pcr0)
	entry := func(party, meas string, from, to time.Duration) AllowEntry {
		return AllowEntry{Party: party, Measurement: meas, NotBefore: now.Add(from), NotAfter: now.Add(to)}
	}
	for _, tc := range []struct {
		name   string
		claims *Claims
		list   []AllowEntry
		want   Reason // "" = allowed
	}{
		{"match", claims, []AllowEntry{entry("A", m, -time.Hour, time.Hour)}, ""},
		{"match, upper-case hex", claims, []AllowEntry{entry("A", strings.ToUpper(m), -time.Hour, time.Hour)}, ""},
		{"window start is inclusive", claims, []AllowEntry{entry("A", m, 0, time.Hour)}, ""},
		{"window end is inclusive", claims, []AllowEntry{entry("A", m, -time.Hour, 0)}, ""},
		{"overlap: the old one expired, the new one allows", claims, []AllowEntry{entry("A", "00"+m[2:], -2*time.Hour, -time.Hour), entry("A", m, -time.Hour, time.Hour)}, ""},
		{"expired", claims, []AllowEntry{entry("A", m, -2*time.Hour, -time.Hour)}, ReasonExpired},
		{"not yet valid", claims, []AllowEntry{entry("A", m, time.Hour, 2*time.Hour)}, ReasonNotYetValid},
		{"expired and a later one coming", claims, []AllowEntry{entry("A", m, -3*time.Hour, -2*time.Hour), entry("A", m, time.Hour, 2*time.Hour)}, ReasonNotYetValid},
		{"wrong party", claims, []AllowEntry{entry("B", m, -time.Hour, time.Hour)}, ReasonWrongParty},
		{"wrong measurement", claims, []AllowEntry{entry("A", "00"+m[2:], -time.Hour, time.Hour)}, ReasonMeasurement},
		{"empty list", claims, nil, ReasonWrongParty},
		{"debug claims", &Claims{Debug: true, Measurements: map[int][]byte{0: pcr0}}, []AllowEntry{entry("A", m, -time.Hour, time.Hour)}, ReasonDebug},
		{"no PCR0", &Claims{Measurements: map[int][]byte{1: pcr0}}, []AllowEntry{entry("A", m, -time.Hour, time.Hour)}, ReasonNoMeasure},
		{"bad hex refuses the whole list", claims, []AllowEntry{entry("A", m, -time.Hour, time.Hour), entry("A", "zz", -time.Hour, time.Hour)}, ReasonBadEntry},
		{"zero time bound is bad", claims, []AllowEntry{{Party: "A", Measurement: m}}, ReasonBadEntry},
		{"no end date (zero not_after) allows", claims, []AllowEntry{{Party: "A", Measurement: m, NotBefore: now.Add(-time.Hour)}}, ""},
		{"no end date, not yet started", claims, []AllowEntry{{Party: "A", Measurement: m, NotBefore: now.Add(time.Hour)}}, ReasonNotYetValid},
		{"revoked entry refuses", claims, []AllowEntry{{Party: "A", Measurement: m, NotBefore: now.Add(-time.Hour), Status: StatusRevoked}}, ReasonRevoked},
		{"revocation wins over an active overlap", claims, []AllowEntry{entry("A", m, -time.Hour, time.Hour), {Party: "A", Measurement: m, NotBefore: now, Status: StatusRevoked}}, ReasonRevoked},
		{"revocation of another measurement does not matter", claims, []AllowEntry{entry("A", m, -time.Hour, time.Hour), {Party: "A", Measurement: "00" + m[2:], NotBefore: now, Status: StatusRevoked}}, ""},
		{"revocation for another party does not matter", claims, []AllowEntry{entry("A", m, -time.Hour, time.Hour), {Party: "B", Measurement: m, NotBefore: now, Status: StatusRevoked}}, ""},
		{"unknown status is bad", claims, []AllowEntry{{Party: "A", Measurement: m, NotBefore: now, Status: "maybe"}}, ReasonBadEntry},
		{"bad version is bad", claims, []AllowEntry{{Party: "A", Measurement: m, NotBefore: now, Version: "v 1"}}, ReasonBadEntry},
		{"end before start is bad", claims, []AllowEntry{entry("A", m, time.Hour, -time.Hour)}, ReasonBadEntry},
		{"empty party is bad", claims, []AllowEntry{entry("", m, -time.Hour, time.Hour)}, ReasonBadEntry},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckAllowlist(tc.claims, "A", tc.list, now)
			if tc.want == "" && err != nil {
				t.Fatalf("want allowed, got %v", err)
			}
			if tc.want != "" && ReasonOf(err) != tc.want {
				t.Fatalf("got %v, want reason %q", err, tc.want)
			}
		})
	}
}
