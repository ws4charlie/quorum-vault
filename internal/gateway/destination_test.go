package gateway

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// restrict puts the harness in the production posture: withdrawals of ETH and USDT may pay addrUser only.
func (h *harness) restrict(limit int) {
	cc := h.cfg.Chains[testChain]
	for _, s := range []string{"ETH", "USDT"} {
		p := cc.Assets[s]
		p.AnyDestination, p.Destinations = false, map[common.Address]bool{addrUser: true}
		cc.Assets[s] = p
	}
	cc.WithdrawalsPerHour = limit
}

func TestWithdrawalDestinationAllowlist(t *testing.T) {
	h := newHarness(t)
	h.restrict(1000)
	h.mustSign(h.withdrawal("d1", addrUser, 100, 0, "alice"))

	d := h.mustReject(h.withdrawal("d2", addrEvil, 100, 1, "alice"), ReasonDestination)
	if !strings.Contains(d.Reason, addrEvil.Hex()) {
		t.Fatalf("reason %q does not name the destination", d.Reason)
	}

	// The same address in another case is the same address (a checksum mix-up in the intent is refused earlier, by the verifier,
	// so the case is varied in the intent as all-lowercase, which the verifier accepts).
	lower := signjob.Intent{Kind: "withdrawal", ID: "w-low", Asset: "ETH", To: strings.ToLower(addrUser.Hex()), Amount: "100"}
	h.mustSign(h.job("d3", lower, h.ethTx(addrUser, 100, 2), "alice"))
	upper := signjob.Intent{Kind: "withdrawal", ID: "w-up", Asset: "ETH", To: "0x" + strings.ToUpper(addrUser.Hex()[2:]), Amount: "100"}
	h.mustSign(h.job("d4", upper, h.ethTx(addrUser, 100, 3), "alice"))

	// An ERC-20 transfer is checked on the recipient in the calldata, not on the token contract.
	tin := func(id string, to common.Address) signjob.Intent {
		return signjob.Intent{Kind: "withdrawal", ID: id, Asset: "USDT", To: to.Hex(), Amount: "1000"}
	}
	h.mustSign(h.job("d5", tin("w-t1", addrUser), h.tokenTx(addrUser, 1000, 4), "alice"))
	h.mustReject(h.job("d6", tin("w-t2", addrEvil), h.tokenTx(addrEvil, 1000, 5), "alice"), ReasonDestination)
	// Listing the token contract as a destination would not make a transfer to it a transfer to the contract's holder.
	if h.cfg.Chains[testChain].Assets["USDT"].AllowsDestination(addrToken) {
		t.Fatal("the token contract is allowed")
	}

	// Every refusal is in the audit chain with its code.
	var n int
	h.guardDB.QueryRow(t.Context(), `SELECT count(*) FROM audit_log WHERE type='sign.refused' AND payload->>'reason' LIKE 'policy_destination:%'`).Scan(&n)
	if n != 2 {
		t.Fatalf("%d destination refusals in the audit chain, want 2", n)
	}
}

// The decoded destination comes from the transaction.
func TestDecodeReadsTheRecipientFromTheTransaction(t *testing.T) {
	h := newHarness(t)
	codec := h.gw.codecs[testChain]
	for name, tc := range map[string]struct {
		spec txSpec
		want common.Address
	}{
		"native":         {h.ethTx(addrUser, 5, 0), addrUser},
		"token transfer": {h.tokenTx(addrEvil, 5, 0), addrEvil},
	} {
		payload, _ := h.payloadFor(tc.spec)
		info, err := codec.Decode(payload)
		if err != nil || info.Destination != tc.want.Hex() {
			t.Errorf("%s: destination %q, %v; want %s", name, info.Destination, err, tc.want)
		}
	}
}

func TestWithdrawalHourLimit(t *testing.T) {
	h := newHarness(t)
	h.restrict(2)
	h.mustSign(h.withdrawal("r1", addrUser, 10, 0, "alice"))
	h.mustSign(h.withdrawal("r2", addrUser, 10, 1, "alice"))
	d := h.mustReject(h.withdrawal("r3", addrUser, 10, 2, "alice"), ReasonWithdrawRate)
	if !strings.Contains(d.Reason, "limit 2") {
		t.Fatalf("reason %q", d.Reason)
	}
	// A replay of a signed intent (same intent, same digest under a new job) is not a new withdrawal and not counted again.
	again := h.withdrawal("r1", addrUser, 10, 0, "alice")
	again.ID = "r1-again"
	if d := h.mustSign(again); d.Outcome != OutcomeReplayed {
		t.Fatalf("outcome %s", d.Outcome)
	}
	// A replacement of a signed intent at the same nonce (higher fees) is not counted either.
	var count int
	h.guardDB.QueryRow(t.Context(), `SELECT count(*) FROM signed_intents WHERE kind='withdrawal'`).Scan(&count)
	if count != 2 {
		t.Fatalf("%d withdrawals counted, want 2", count)
	}
	// The hour passes: the limit recovers.
	h.advance(61 * time.Minute)
	in := signjob.Intent{Kind: "withdrawal", ID: "w-r4", Asset: "ETH", To: addrUser.Hex(), Amount: "10"}
	h.mustSign(h.job("r4", in, h.ethTx(addrUser, 10, 2), "alice"))
}

// A rogue gateway (or a business zone talking it into signing) does not get past party B: the cosigner checks the destination and
// the rate from its own config and its own store.
func TestCosignerStyleSecondDecider(t *testing.T) {
	h := newHarness(t)
	h.restrict(1)
	other := NewDecider(h.cfg, h.gw.codecs, mustGuard(t, h), ModeCosigner, h.clock)
	pub := h.signer.PublicKey()
	if _, err := other.Decide(t.Context(), h.withdrawal("x1", addrEvil, 10, 0, "alice"), pub); err == nil {
		t.Fatal("a destination outside the list was allowed")
	} else if why, _ := IsRejection(err); !strings.HasPrefix(why, ReasonDestination+":") {
		t.Fatalf("err %v", err)
	}
	if _, err := other.Decide(t.Context(), h.withdrawal("x2", addrUser, 10, 0, "alice"), pub); err != nil {
		t.Fatal(err)
	}
	_, err := other.Decide(t.Context(), h.withdrawal("x3", addrUser, 10, 1, "alice"), pub)
	if why, _ := IsRejection(err); !strings.HasPrefix(why, ReasonWithdrawRate+":") {
		t.Fatalf("err %v, want %s", err, ReasonWithdrawRate)
	}
}

func mustGuard(t *testing.T, h *harness) *Guard {
	t.Helper()
	g, err := OpenGuard(t.Context(), newGuardDB(t))
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestDestinationConfigValidation(t *testing.T) {
	good, err := os.ReadFile("config.example.json")
	if err != nil {
		t.Fatal(err)
	}
	mutate := func(fn func(chain, eth map[string]any)) []byte {
		var m map[string]any
		json.Unmarshal(good, &m)
		for _, c := range m["chains"].(map[string]any) {
			cm := c.(map[string]any)
			fn(cm, cm["assets"].(map[string]any)["ETH"].(map[string]any))
		}
		b, _ := json.Marshal(m)
		return b
	}
	if _, err := ParseConfig(mutate(func(c, e map[string]any) {})); err != nil {
		t.Fatalf("the example does not parse: %v", err)
	}
	cases := map[string][]byte{
		"neither list nor any_destination": mutate(func(c, e map[string]any) { delete(e, "withdrawal_destinations") }),
		"empty list":                       mutate(func(c, e map[string]any) { e["withdrawal_destinations"] = []any{} }),
		"both":                             mutate(func(c, e map[string]any) { e["any_destination"] = true }),
		"bad address":                      mutate(func(c, e map[string]any) { e["withdrawal_destinations"] = []any{"0x12"} }),
		"zero address": mutate(func(c, e map[string]any) {
			e["withdrawal_destinations"] = []any{"0x0000000000000000000000000000000000000000"}
		}),
		"no hourly limit":       mutate(func(c, e map[string]any) { delete(c, "withdrawals_per_hour") }),
		"zero hourly limit":     mutate(func(c, e map[string]any) { c["withdrawals_per_hour"] = 0 }),
		"negative hourly limit": mutate(func(c, e map[string]any) { c["withdrawals_per_hour"] = -5 }),
	}
	for name, b := range cases {
		if _, err := ParseConfig(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// any_destination alone is fine, and says so on purpose.
	cfg, err := ParseConfig(mutate(func(c, e map[string]any) { delete(e, "withdrawal_destinations"); e["any_destination"] = true }))
	if err != nil {
		t.Fatal(err)
	}
	for _, cc := range cfg.Chains {
		if !cc.Assets["ETH"].AnyDestination || cc.WithdrawalsPerHour != 120 {
			t.Fatalf("%+v", cc.Assets["ETH"])
		}
	}
}
