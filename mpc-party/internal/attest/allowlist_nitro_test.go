package attest

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func hexn(c byte, n int) string { return strings.Repeat(string("0123456789abcdef"[c%16]), 2*n) }

func nitroClaims() *Claims {
	return &Claims{EvidenceType: EvidenceTypeNitro, Measurements: map[int][]byte{
		0: bytes.Repeat([]byte{0xa0}, 48), 1: bytes.Repeat([]byte{0xa1}, 48), 2: bytes.Repeat([]byte{0xa2}, 48), 8: bytes.Repeat([]byte{0xa8}, 48)}}
}

func nitroEntry() AllowEntry {
	return AllowEntry{Party: "A", Measurement: strings.Repeat("a0", 48), NotBefore: time.Unix(1000, 0), Version: "v1",
		PCRs: map[string]string{"1": strings.Repeat("a1", 48), "2": strings.Repeat("a2", 48), "8": strings.Repeat("A8", 48)}}
}

func TestNitroEntryMatchesEveryListedPCR(t *testing.T) {
	now := time.Unix(2000, 0)
	if err := CheckAllowlist(nitroClaims(), "A", []AllowEntry{nitroEntry()}, now); err != nil {
		t.Fatal(err) // upper-case hex in the entry is the same value
	}
	for _, n := range []int{1, 2, 8} {
		c := nitroClaims()
		c.Measurements[n] = bytes.Repeat([]byte{0x11}, 48)
		if err := CheckAllowlist(c, "A", []AllowEntry{nitroEntry()}, now); ReasonOf(err) != ReasonMeasurement {
			t.Fatalf("PCR%d differs: %v", n, err)
		}
		d := nitroClaims()
		delete(d.Measurements, n)
		if err := CheckAllowlist(d, "A", []AllowEntry{nitroEntry()}, now); ReasonOf(err) != ReasonMeasurement {
			t.Fatalf("PCR%d absent: %v", n, err)
		}
	}
	// an entry without PCRs is still matched on PCR0 alone
	plain := nitroEntry()
	plain.PCRs = nil
	c := nitroClaims()
	c.Measurements[1] = bytes.Repeat([]byte{0x11}, 48)
	if err := CheckAllowlist(c, "A", []AllowEntry{plain}, now); err != nil {
		t.Fatal(err)
	}
	// overlap: the old image (plain) and the new (Nitro entry with other PCRs) both allow
	other := nitroEntry()
	other.Measurement = strings.Repeat("b0", 48)
	if err := CheckAllowlist(nitroClaims(), "A", []AllowEntry{other, nitroEntry()}, now); err != nil {
		t.Fatal(err)
	}
	// a revocation of PCR0 refuses the image whatever PCRs its entries list
	rev := AllowEntry{Party: "A", Measurement: nitroEntry().Measurement, NotBefore: time.Unix(1500, 0), Status: StatusRevoked}
	if err := CheckAllowlist(nitroClaims(), "A", []AllowEntry{nitroEntry(), rev}, now); ReasonOf(err) != ReasonRevoked {
		t.Fatalf("revoked: %v", err)
	}
}

func TestMalformedNitroEntriesRefuseTheWholeList(t *testing.T) {
	for name, p := range map[string]map[string]string{
		"pcr 0 is Measurement": {"0": hexn(1, 48)},
		"pcr 32":               {"32": hexn(1, 48)},
		"not a number":         {"x": hexn(1, 48)},
		"leading zero":         {"01": hexn(1, 48)},
		"negative":             {"-1": hexn(1, 48)},
		"not hex":              {"1": strings.Repeat("zz", 48)},
		"47 bytes":             {"1": hexn(1, 47)},
		"empty":                {"1": ""},
	} {
		e := nitroEntry()
		e.PCRs = p
		if err := CheckAllowlist(nitroClaims(), "A", []AllowEntry{nitroEntry(), e}, time.Unix(2000, 0)); ReasonOf(err) != ReasonBadEntry {
			t.Fatalf("%s: %v", name, err)
		}
		if err := ValidEntries([]AllowEntry{e}); err == nil {
			t.Fatalf("%s: ValidEntries accepted it", name)
		}
	}
}

func TestNitroEntryJSONAndSignedBytes(t *testing.T) {
	e := nitroEntry()
	b, _ := json.Marshal(e)
	var back AllowEntry
	if err := json.Unmarshal(b, &back); err != nil || len(back.PCRs) != 3 || back.PCRs["8"] != strings.Repeat("A8", 48) {
		t.Fatalf("%v %+v", err, back)
	}
	if err := json.Unmarshal([]byte(`{"party":"A","measurement":"aa","not_before":"2026-01-01T00:00:00Z","pcr":{"1":"aa"}}`), &back); err == nil {
		t.Fatal("a misspelled pcrs field was accepted")
	}
	// the operators sign the PCRs: changing one changes the message; an entry without PCRs signs exactly as before (no "pcrs" key at all)
	l := SignedAllowlist{Seq: 1, SignedAt: 5, Entries: []AllowEntry{e}}
	m1 := AllowlistMessage(l)
	l.Entries[0].PCRs = map[string]string{"1": strings.Repeat("a1", 48), "2": strings.Repeat("a2", 48), "8": strings.Repeat("a9", 48)}
	if bytes.Equal(m1, AllowlistMessage(l)) {
		t.Fatal("a changed PCR8 did not change the signed message")
	}
	l.Entries[0].PCRs = nil
	if bytes.Contains(AllowlistMessage(l), []byte("pcrs")) {
		t.Fatal("an entry without PCRs signs a pcrs key: old signatures would break")
	}
	// case of a PCR value does not matter to the signature
	a, b2 := nitroEntry(), nitroEntry()
	b2.PCRs["8"] = strings.ToLower(b2.PCRs["8"])
	if !bytes.Equal(AllowlistMessage(SignedAllowlist{Seq: 1, Entries: []AllowEntry{a}}), AllowlistMessage(SignedAllowlist{Seq: 1, Entries: []AllowEntry{b2}})) {
		t.Fatal("hex case changes the signed bytes")
	}
}
