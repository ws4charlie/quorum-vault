package domain

import (
	"encoding/json"
	"fmt"
	"math/big"
)

// bigDec is a *big.Int that marshals as a JSON decimal string and unmarshals
// from either a string or a bare JSON number. nil marshals as null.
type bigDec struct{ p **big.Int }

func (b bigDec) MarshalJSON() ([]byte, error) {
	if *b.p == nil {
		return []byte("null"), nil
	}
	return json.Marshal((*b.p).String())
}

func (b bigDec) UnmarshalJSON(data []byte) error {
	s := string(data)
	if s == "null" {
		*b.p = nil
		return nil
	}
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
	}
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return fmt.Errorf("domain: invalid decimal integer %q", s)
	}
	*b.p = v
	return nil
}

// The struct methods below shadow each *big.Int field with a bigDec pointing
// at it; encoding/json picks the outer (shadowing) field of the same name.

func (p Policy) MarshalJSON() ([]byte, error) {
	type alias Policy
	return json.Marshal(struct {
		alias
		DailyLimitWei        bigDec `json:"daily_limit_wei"`
		PerTxLimitWei        bigDec `json:"per_tx_limit_wei"`
		ApprovalThresholdWei bigDec `json:"approval_threshold_wei"`
	}{alias(p), bigDec{&p.DailyLimitWei}, bigDec{&p.PerTxLimitWei}, bigDec{&p.ApprovalThresholdWei}})
}

func (p *Policy) UnmarshalJSON(data []byte) error {
	type alias Policy
	aux := struct {
		*alias
		DailyLimitWei        bigDec `json:"daily_limit_wei"`
		PerTxLimitWei        bigDec `json:"per_tx_limit_wei"`
		ApprovalThresholdWei bigDec `json:"approval_threshold_wei"`
	}{(*alias)(p), bigDec{&p.DailyLimitWei}, bigDec{&p.PerTxLimitWei}, bigDec{&p.ApprovalThresholdWei}}
	return json.Unmarshal(data, &aux)
}

func (r SignRequest) MarshalJSON() ([]byte, error) {
	type alias SignRequest
	return json.Marshal(struct {
		alias
		ValueWei             bigDec `json:"value_wei"`
		MaxFeePerGas         bigDec `json:"max_fee_per_gas"`
		MaxPriorityFeePerGas bigDec `json:"max_priority_fee_per_gas"`
	}{alias(r), bigDec{&r.ValueWei}, bigDec{&r.MaxFeePerGas}, bigDec{&r.MaxPriorityFeePerGas}})
}

func (r *SignRequest) UnmarshalJSON(data []byte) error {
	type alias SignRequest
	aux := struct {
		*alias
		ValueWei             bigDec `json:"value_wei"`
		MaxFeePerGas         bigDec `json:"max_fee_per_gas"`
		MaxPriorityFeePerGas bigDec `json:"max_priority_fee_per_gas"`
	}{(*alias)(r), bigDec{&r.ValueWei}, bigDec{&r.MaxFeePerGas}, bigDec{&r.MaxPriorityFeePerGas}}
	return json.Unmarshal(data, &aux)
}
