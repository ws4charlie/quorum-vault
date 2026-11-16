package btc

import "fmt"

// Fee-bump reserve. A withdrawal or hot-to-cold send is bumped by replacement with the same inputs (the signing zone's rule), paying every extra
// satoshi from its change. So that it can always be bumped to the fee cap, coin selection keeps enough in change:
//
//	sum(inputs) >= sum(payments) + feeCap(vs) + dust(change)        vs: the size of the final transaction, change output included
//	feeCap(vs)   = min(max_tx_fee_sats, max_fee_rate x vs)
//
// A bump spends the change down to dust at most, so the most the transaction can ever pay is sum - payments - dust; the rule makes that at least
// feeCap(vs). The bump then stops at a cap (an alert), never for dust or a missing change output. The rule takes the payments as a list so that a
// batch of k payments uses it unchanged: only vs and the sum grow.
//
// The core applies it when it picks coins (BuildWithdrawal); the signing zone applies the same function, with its own caps, to the first send of a
// withdrawal or a hot-to-cold move (Verifier.CheckFirstSend). Sweeps and consolidations have no change and bump from their own single output: no reserve.

// FeeCap is the most a transaction of vs virtual bytes may pay: the absolute cap and the rate ceiling, whichever is lower.
func FeeCap(maxTxFeeSats, maxFeeRate, vs uint64) uint64 { return min(maxTxFeeSats, maxFeeRate*vs) }

// ReserveNeed is the least the inputs must hold for payments (their sum) and a change output, for a final transaction of vs virtual bytes paying fee
// now (fee: today's market fee, which never counts for less than the cap's room when it is higher): the payments, the larger of the fee now and the fee cap,
// and one dust change.
func ReserveNeed(payments, fee, vs, maxTxFeeSats, maxFeeRate uint64) uint64 {
	return payments + max(fee, FeeCap(maxTxFeeSats, maxFeeRate, vs)) + DustLimit(KindP2WPKH)
}

// ReserveShortfall is how many satoshis the inputs (sum) lack to meet ReserveNeed; 0 when they meet it.
func ReserveShortfall(sum, payments, fee, vs, maxTxFeeSats, maxFeeRate uint64) uint64 {
	if need := ReserveNeed(payments, fee, vs, maxTxFeeSats, maxFeeRate); need > sum {
		return need - sum
	}
	return 0
}

// MaxTxVSize is the size of the largest transaction a withdrawal may build under the input limit: maxInputs inputs, maxPayments payment outputs of
// the largest standard script (P2WSH and P2TR, 34 bytes) and one P2WPKH change. Batching sets maxPayments from its own output limit; one send has 1.
func MaxTxVSize(maxInputs, maxPayments int) uint64 {
	scripts := make([][]byte, 0, maxPayments+1)
	for i := 0; i < maxPayments; i++ {
		scripts = append(scripts, make([]byte, 34)) // P2WSH / P2TR scripts are 34 bytes; EstimateVSize counts bytes only
	}
	scripts = append(scripts, make([]byte, 22)) // P2WPKH change
	return vsize(maxInputs, scripts...)
}

// CheckFeeCaps refuses fee caps that cannot let the largest transaction reach the rate ceiling: max_tx_fee_sats below max_fee_rate x its size means
// the reserve could never be spent at the ceiling rate, and a bump would stop at the absolute cap far below the rate the operator allowed. The
// message shows the numbers and the fix. maxPayments is 1 until batching adds its output limit here.
func CheckFeeCaps(who string, maxTxFeeSats, maxFeeRate uint64, maxInputs, maxPayments int) error {
	vs := MaxTxVSize(maxInputs, maxPayments)
	if want := maxFeeRate * vs; maxTxFeeSats < want {
		return fmt.Errorf("btc: %s: max_tx_fee_sats %d is below max_fee_rate %d sat/vB x %d vbytes = %d sats, the size of the largest transaction (%d inputs, %d payment output(s) and change): "+
			"raise max_tx_fee_sats to at least %d, or lower max_fee_rate to at most %d, or lower max_inputs",
			who, maxTxFeeSats, maxFeeRate, vs, want, maxInputs, maxPayments, want, maxTxFeeSats/vs)
	}
	return nil
}
