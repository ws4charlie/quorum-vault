package gateway

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

func TestIntentPackageRoundTripAndStrictness(t *testing.T) {
	j := signjob.Job{ID: "job-1", Chain: "evm", PartitionID: "p", KeyRef: "m/0", Intent: []byte(`{"Kind":"withdrawal"}`),
		Payload: []byte(`{"a":1}`), Digest: bytes.Repeat([]byte{9}, 32),
		Approvals: []signjob.Approval{{Actor: "alice", Signature: []byte{1, 2, 3}}}}
	b, err := EncodePackage(j)
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := EncodePackage(j)
	if !bytes.Equal(b, b2) {
		t.Fatal("encoding is not deterministic")
	}
	got, err := DecodePackage(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != j.ID || got.Chain != j.Chain || got.PartitionID != j.PartitionID || got.KeyRef != j.KeyRef ||
		!bytes.Equal(got.Intent, j.Intent) || !bytes.Equal(got.Payload, j.Payload) || !bytes.Equal(got.Digest, j.Digest) ||
		len(got.Approvals) != 1 || got.Approvals[0].Actor != "alice" || !bytes.Equal(got.Approvals[0].Signature, []byte{1, 2, 3}) {
		t.Fatalf("round trip lost data: %+v", got)
	}
	var m map[string]any
	json.Unmarshal(b, &m)
	if m["v"] != IntentPackageVersion {
		t.Fatalf("version field: %v", m["v"])
	}
	for name, mut := range map[string]func(map[string]any){
		"unknown field": func(m map[string]any) { m["extra"] = 1 },
		"other version": func(m map[string]any) { m["v"] = "qv-intentpkg-v2" },
		"short digest":  func(m map[string]any) { m["digest"] = "AAAA" },
	} {
		c := map[string]any{}
		json.Unmarshal(b, &c)
		mut(c)
		raw, _ := json.Marshal(c)
		if _, err := DecodePackage(raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := DecodePackage(append(append([]byte{}, b...), []byte(` {}`)...)); err == nil {
		t.Error("trailing data accepted")
	}
	if _, err := DecodePackage(nil); err == nil {
		t.Error("empty accepted")
	}
	big := j
	big.Payload = bytes.Repeat([]byte("x"), MaxIntentPackage)
	if _, err := EncodePackage(big); err == nil {
		t.Error("oversize package encoded")
	}
}
