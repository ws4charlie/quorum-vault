package signjob

import (
	"encoding/json"
	"testing"
)

func testBatch() Batch {
	m := func(id, to string) BatchMember {
		return BatchMember{Intent: Intent{Kind: "withdrawal", ID: id, PartitionID: "p", Chain: "c", Asset: "BTC", To: to, Amount: "1000", NotAfter: 5},
			Approvals: []Approval{{Actor: "alice", Signature: []byte{1}}}}
	}
	return Batch{Kind: KindBatch, ID: "b1", PartitionID: "p", Chain: "c", Asset: "BTC", Members: []BatchMember{m("w1", "a"), m("w2", "b")}}
}

// The batch hash binds the id, the members and their order; approvals are not part of it.
func TestBatchHashBindsMembersAndOrder(t *testing.T) {
	b := testBatch()
	base := b.Hash()
	if again := testBatch().Hash(); again != base {
		t.Fatal("not deterministic")
	}
	reordered := testBatch()
	reordered.Members[0], reordered.Members[1] = reordered.Members[1], reordered.Members[0]
	fewer := testBatch()
	fewer.Members = fewer.Members[:1]
	moved := testBatch()
	moved.Members[1].Intent.To = "c"
	renamed := testBatch()
	renamed.ID = "b2"
	for name, other := range map[string]Batch{"reordered": reordered, "fewer": fewer, "another destination": moved, "another id": renamed} {
		if other.Hash() == base {
			t.Fatalf("%s has the same hash", name)
		}
	}
	signed := testBatch()
	signed.Members[0].Approvals = nil
	if signed.Hash() != base {
		t.Fatal("approvals are not part of the batch hash")
	}
}

func TestBatchJSONIsStrictAndRecognised(t *testing.T) {
	raw, _ := json.Marshal(testBatch())
	if !IsBatch(raw) {
		t.Fatal("a batch is not recognised")
	}
	if IsBatch([]byte(`{"Kind":"withdrawal"}`)) || IsBatch([]byte(`not json`)) {
		t.Fatal("something else is taken for a batch")
	}
	got, err := DecodeBatch(raw)
	if err != nil || got.Hash() != testBatch().Hash() {
		t.Fatalf("round trip: %v", err)
	}
	if _, err := DecodeBatch([]byte(`{"Kind":"batch","ID":"b","Extra":1}`)); err == nil {
		t.Fatal("an unknown field was accepted")
	}
	if _, err := DecodeBatch(append(raw, []byte(` {}`)...)); err == nil {
		t.Fatal("trailing data was accepted")
	}
}
