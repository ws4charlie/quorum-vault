package btc

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

func p2trAddr(t *testing.T) string {
	t.Helper()
	a, err := btcutil.NewAddressTaproot(bytes.Repeat([]byte{3}, 32), &chaincfg.RegressionNetParams)
	if err != nil {
		t.Fatal(err)
	}
	return a.EncodeAddress()
}

func TestFeeCapIsTheLowerOfTheTwoCaps(t *testing.T) {
	if got := FeeCap(100_000, 100, 141); got != 14_100 {
		t.Fatalf("rate cap binds: %d", got)
	}
	if got := FeeCap(10_000, 100, 141); got != 10_000 {
		t.Fatalf("total cap binds: %d", got)
	}
	if got := FeeCap(14_100, 100, 141); got != 14_100 {
		t.Fatalf("both equal: %d", got)
	}
}

// The rule itself: with inputs worth exactly ReserveNeed, a bump to the fee cap leaves at least dust in change; one satoshi less does not. For 1 to
// max_inputs inputs, a P2WPKH or P2TR payment, and a list of k payments (the rule takes their sum and the size of every output).
func TestReserveRuleLeavesDustAtTheCap(t *testing.T) {
	e := newWEnv(t)
	hot := mustScript(t, e.hot)
	scripts := map[string][]byte{"p2wpkh": mustScript(t, e.dest), "p2tr": mustScript(t, p2trAddr(t))}
	const maxTx, maxRate = 100_000, 100
	dust := DustLimit(KindP2WPKH)
	for name, script := range scripts {
		for k := 1; k <= 4; k++ { // k payments
			for n := 1; n <= 20; n++ {
				outs := make([][]byte, 0, k+1)
				for i := 0; i < k; i++ {
					outs = append(outs, script)
				}
				outs = append(outs, hot)
				vs := vsize(n, outs...)
				payments := uint64(k) * 50_000
				feeNow := vs * 12
				need := ReserveNeed(payments, feeNow, vs, maxTx, maxRate)
				if short := ReserveShortfall(need, payments, feeNow, vs, maxTx, maxRate); short != 0 {
					t.Fatalf("%s k=%d n=%d: the need itself is short by %d", name, k, n, short)
				}
				if short := ReserveShortfall(need-1, payments, feeNow, vs, maxTx, maxRate); short != 1 {
					t.Fatalf("%s k=%d n=%d: one satoshi under the need is short by %d, want 1", name, k, n, short)
				}
				// Bump to the cap: the change that is left is what the inputs hold beyond the payments and the cap.
				if left := need - payments - FeeCap(maxTx, maxRate, vs); left < dust {
					t.Fatalf("%s k=%d n=%d: %d sats of change at the cap, below dust %d", name, k, n, left, dust)
				}
			}
		}
	}
}

// When today's fee is above the cap's room (a config the start-up check refuses, but the function stays honest), the fee now is what is kept.
func TestReserveNeedKeepsTheLargerOfFeeAndCap(t *testing.T) {
	if got := ReserveNeed(1000, 5000, 100, 100_000, 10); got != 1000+5000+294 {
		t.Fatalf("%d", got)
	}
}

// Selection keeps adding inputs until the reserve is covered: three outputs of 30,000 pay 50,000 (two are enough for the payment and today's fee, not
// for the reserve).
func TestSelectionAddsInputsUntilTheReserveIsCovered(t *testing.T) {
	e := newWEnv(t)
	for i := 0; i < 5; i++ {
		e.fund(30_000)
	}
	u, err := e.build("w1", 50_000, true)
	if err != nil {
		t.Fatal(err)
	}
	p := e.payload(u)
	if len(p.Inputs) != 3 || len(p.Outputs) != 2 {
		t.Fatalf("%d inputs, %d outputs; want 3 and 2", len(p.Inputs), len(p.Outputs))
	}
	var sum uint64
	for _, in := range p.Inputs {
		sum += in.Value
	}
	vs := vsize(3, mustScript(t, e.dest), mustScript(t, e.hot))
	if sum < ReserveNeed(50_000, vs*10, vs, e.a.cfg.MaxTxFeeSats, e.a.cfg.MaxFeeRate) {
		t.Fatalf("inputs %d do not cover the need", sum)
	}
	if two := vsize(2, mustScript(t, e.dest), mustScript(t, e.hot)); 60_000 >= ReserveNeed(50_000, two*10, two, e.a.cfg.MaxTxFeeSats, e.a.cfg.MaxFeeRate) {
		t.Fatal("test setup: two inputs would have been enough")
	}
}

// A P2TR payment is larger than a P2WPKH one, so the reserve is too.
func TestReserveGrowsWithThePaymentScript(t *testing.T) {
	e := newWEnv(t)
	a := ReserveNeed(10_000, 0, vsize(1, mustScript(t, e.dest), mustScript(t, e.hot)), 25_000, 50)
	b := ReserveNeed(10_000, 0, vsize(1, mustScript(t, p2trAddr(t)), mustScript(t, e.hot)), 25_000, 50)
	if b <= a {
		t.Fatalf("p2tr need %d, p2wpkh need %d", b, a)
	}
}

// A wallet that the reserve makes thin: payment and fee are covered, the reserve is not. The build waits (ErrFeeReserve, nothing reserved), and the
// error names the output that releases it: that amount releases it, one satoshi less does not.
func TestThinShardWaitsForTheReserveThenARefillReleasesIt(t *testing.T) {
	e := newWEnv(t)
	e.fund(100_000)
	_, err := e.build("w1", 95_000, true)
	if !errors.Is(err, chain.ErrFeeReserve) || !errors.Is(err, chain.ErrNotEnoughOutputs) {
		t.Fatalf("%v", err)
	}
	if e.count("reserved") != 0 {
		t.Fatal("a build that waits for the reserve reserved outputs")
	}
	var missing uint64
	i := strings.Index(err.Error(), "one more output of at least ")
	if i < 0 || !strings.Contains(err.Error(), "reserve") {
		t.Fatalf("the error does not name the reserve and the amount that releases it: %q", err)
	}
	if _, err := fmt.Sscanf(err.Error()[i:], "one more output of at least %d sats releases it", &missing); err != nil || missing == 0 {
		t.Fatalf("amount in %q: %v", err, missing)
	}
	for _, tc := range []struct {
		refill int64
		ok     bool
	}{{int64(missing) - 1, false}, {int64(missing), true}} {
		e := newWEnv(t)
		e.fund(100_000)
		e.fund(tc.refill)
		_, err := e.build("w1", 95_000, true)
		if tc.ok && err != nil || !tc.ok && !errors.Is(err, chain.ErrFeeReserve) {
			t.Fatalf("a refill of %d (the error says %d releases it): %v", tc.refill, missing, err)
		}
	}
}

func TestCheckFeeCapsNamesTheNumbersAndTheFix(t *testing.T) {
	vs := MaxTxVSize(20, 1)
	if vs != 1445 { // 20 P2WPKH inputs, one 34-byte payment script, one change
		t.Fatalf("largest transaction %d vbytes", vs)
	}
	err := CheckFeeCaps("config", 100_000, 100, 20, 1)
	if err == nil {
		t.Fatal("100,000 sats at 100 sat/vB for 20 inputs was accepted")
	}
	for _, want := range []string{"max_tx_fee_sats 100000", "max_fee_rate 100", "1445 vbytes", "144500", "raise max_tx_fee_sats to at least 144500", "at most 69"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("%q lacks %q", err, want)
		}
	}
	if err := CheckFeeCaps("config", 144_500, 100, 20, 1); err != nil {
		t.Fatalf("exactly enough: %v", err)
	}
	if CheckFeeCaps("config", 144_500, 100, 20, 2) == nil { // the hook for batching: a second payment output makes the largest transaction larger
		t.Fatal("two payments fit in the size of one")
	}
}

func TestConfigAndVerifierRefuseInconsistentFeeCaps(t *testing.T) {
	e := newWEnv(t)
	cfg := e.cfg
	cfg.MaxTxFeeSats = 21_000 // 5 inputs at 50 sat/vB is 21,250
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "raise max_tx_fee_sats to at least 21250") {
		t.Fatalf("core: %v", err)
	}
	f := newFixture(t)
	sc := SigningConfig{Chain: vChain, Network: "regtest", AccountXpub: acctXpub(f.acct), HotShards: map[string]HotShard{pOmni0: {Address: f.hot0, Path: []uint32{1, 0}}},
		MaxTxFeeSats: 30_000, MaxFeeRate: 100, MaxInputs: 4} // 4 inputs at 100 sat/vB is 35,700
	if _, err := NewVerifier(sc); err == nil || !strings.Contains(err.Error(), "signing zone") || !strings.Contains(err.Error(), "raise max_tx_fee_sats to at least") {
		t.Fatalf("zone: %v", err)
	}
	sc.MaxTxFeeSats = 50_000
	if _, err := NewVerifier(sc); err != nil {
		t.Fatal(err)
	}
	if err := (Config{Chain: "x", Network: "regtest", AccountXpub: e.cfg.AccountXpub}).Validate(); err != nil {
		t.Fatalf("the defaults must pass their own check: %v", err)
	}
}

// The zone's own rule for the first send: change >= zoneFeeCap(vs) - fee + dust. A replacement of the same send (less change) is Verify's business and
// is still accepted at every step down to the cap.
func TestZoneChecksTheFirstSendButNotItsReplacements(t *testing.T) {
	f := newFixture(t)
	mk := func(sum, pay, change uint64) (Payload, signjob.Intent) {
		p := Payload{Version: 2, Inputs: []PayloadInput{in(1, sum, 1, 0)}, Outputs: []PayloadOutput{{f.other, pay}, {f.hot0, change}}}
		return p, signjob.Intent{Kind: "withdrawal", ID: "w1", PartitionID: pOmni0, Chain: vChain, Asset: "BTC", To: f.other, Amount: fmt.Sprint(pay)}
	}
	vs := vsize(1, mustScript(t, f.other), mustScript(t, f.hot0)) // the zone's caps: 50,000 sats, 100 sat/vB
	capSats := FeeCap(50_000, 100, vs)
	pay := uint64(100_000)
	need := pay + capSats + 294
	for name, tc := range map[string]struct {
		sum  uint64
		want string
	}{
		"exactly enough":      {need, ""},
		"one satoshi too few": {need - 1, "must keep at least 1 more"},
		"far too little":      {pay + 1_410 + 300, "to be bumped up to the fee cap"},
	} {
		fee := uint64(1_410)
		p, i := mk(tc.sum, pay, tc.sum-pay-fee)
		err := f.v.CheckFirstSend(f.job(p, 0), i)
		if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
			t.Fatalf("%s: %v", name, err)
		}
		if err := f.v.Verify(f.job(p, 0), i); err != nil { // the ordinary checks accept all of them
			t.Fatalf("%s: Verify: %v", name, err)
		}
	}
	// No change output at all.
	p, i := mk(pay+1_000, pay, 1)
	p.Outputs = p.Outputs[:1]
	if err := f.v.CheckFirstSend(f.job(p, 0), i); err == nil || !strings.Contains(err.Error(), "no change output") {
		t.Fatalf("no change: %v", err)
	}
	// Replacements down to the cap: same inputs, same payment, change down to what the cap leaves. Verify accepts each; the first-send rule is not applied.
	p, i = mk(need, pay, need-pay-1_410)
	for fee := uint64(1_410); fee <= capSats; fee += (capSats - 1_410) / 4 {
		p.Outputs[1].Value = need - pay - fee
		if err := f.v.Verify(f.job(p, 0), i); err != nil {
			t.Fatalf("a replacement paying %d: %v", fee, err)
		}
	}
	// Other kinds are not judged.
	p, i = mk(need-1, pay, 500)
	i.Kind = "cancel"
	if err := f.v.CheckFirstSend(f.job(p, 0), i); err != nil {
		t.Fatalf("a cancel: %v", err)
	}
}
