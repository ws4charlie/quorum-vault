package domain

import (
	"encoding/json"
	"math/big"
	"strings"
	"testing"
)

func TestPolicyJSONBigIntAsString(t *testing.T) {
	big1, _ := new(big.Int).SetString("123456789012345678901234567890", 10)
	p := Policy{WalletID: "w", DailyLimitWei: big1, PerTxLimitWei: big.NewInt(5), RequiredApprovals: 2}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{`"daily_limit_wei":"123456789012345678901234567890"`, `"per_tx_limit_wei":"5"`, `"approval_threshold_wei":null`, `"required_approvals":2`} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s in %s", want, s)
		}
	}
	var back Policy
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.DailyLimitWei.Cmp(big1) != 0 || back.PerTxLimitWei.Int64() != 5 || back.ApprovalThresholdWei != nil || back.WalletID != "w" {
		t.Fatalf("round trip mismatch: %+v", back)
	}
}

func TestSignRequestJSON(t *testing.T) {
	r := SignRequest{ID: "r", ValueWei: big.NewInt(42), MaxFeePerGas: big.NewInt(7), Status: StatusSigned, Decision: &Decision{Outcome: OutcomeAllow}}
	b, err := json.Marshal(&r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"value_wei":"42"`) || !strings.Contains(string(b), `"status":"signed"`) {
		t.Fatalf("unexpected %s", b)
	}
	var back SignRequest
	// bare numbers are accepted too
	if err := json.Unmarshal([]byte(`{"id":"r","value_wei":42,"max_fee_per_gas":"7"}`), &back); err != nil {
		t.Fatal(err)
	}
	if back.ValueWei.Int64() != 42 || back.MaxFeePerGas.Int64() != 7 || back.ID != "r" {
		t.Fatalf("got %+v", back)
	}
	if err := json.Unmarshal([]byte(`{"value_wei":"1.5"}`), &back); err == nil {
		t.Fatal("expected error for non-integer")
	}
}
