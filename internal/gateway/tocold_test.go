package gateway

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// Hot-to-cold moves: the destination is the cold address of this zone's config, no approval is needed, and the rate and the
// daily cap are enforced from this zone's own store whatever the intent carries.

func (h *harness) toCold(id string, amount int64, nonce uint64, approvers ...string) signjob.Job {
	in := signjob.Intent{Kind: "to-cold", ID: "m-" + id, PartitionID: testColdPartition, Asset: "ETH", To: addrCold.Hex(), Amount: fmt.Sprint(amount)}
	return h.job(id, in, h.ethTx(addrCold, amount, nonce), approvers...)
}

func TestToColdSignsWithoutApprovalsNativeAndToken(t *testing.T) {
	h := newHarness(t)
	h.mustSign(h.toCold("c1", 2000, 0))
	in := signjob.Intent{Kind: "to-cold", ID: "m-tok", PartitionID: testColdPartition, Asset: "USDT", To: addrCold.Hex(), Amount: "3000000"}
	h.mustSign(h.job("c2", in, h.tokenTx(addrCold, 3_000_000, 1)))
}

func TestAttackToColdOtherDestinationRefused(t *testing.T) {
	h := newHarness(t)
	// Intent and transaction both name the attacker: the configured cold address is what counts.
	in := signjob.Intent{Kind: "to-cold", ID: "m-evil", PartitionID: testColdPartition, Asset: "ETH", To: addrEvil.Hex(), Amount: "100"}
	d := h.mustReject(h.job("e1", in, h.ethTx(addrEvil, 100, 0)), ReasonTx)
	if !contains(d.Reason, "is not the configured cold address") {
		t.Fatalf("reason %q", d.Reason)
	}
	// The intent says cold, the transaction pays the attacker.
	in2 := signjob.Intent{Kind: "to-cold", ID: "m-evil2", PartitionID: testColdPartition, Asset: "ETH", To: addrCold.Hex(), Amount: "100"}
	d = h.mustReject(h.job("e2", in2, h.ethTx(addrEvil, 100, 1)), ReasonTx)
	if !contains(d.Reason, "to-cold transfer is to") {
		t.Fatalf("reason %q", d.Reason)
	}
	// A token transfer to the attacker under a to-cold intent.
	in3 := signjob.Intent{Kind: "to-cold", ID: "m-evil3", PartitionID: testColdPartition, Asset: "USDT", To: addrCold.Hex(), Amount: "100"}
	d = h.mustReject(h.job("e3", in3, h.tokenTx(addrEvil, 100, 2)), ReasonTx)
	if !contains(d.Reason, "calldata is not transfer") {
		t.Fatalf("reason %q", d.Reason)
	}
	// Approvals do not make a wrong destination right.
	in4 := signjob.Intent{Kind: "to-cold", ID: "m-evil4", PartitionID: testColdPartition, Asset: "ETH", To: addrEvil.Hex(), Amount: "100"}
	h.mustReject(h.job("e4", in4, h.ethTx(addrEvil, 100, 3), "alice", "bob"), ReasonTx)
}

func TestAttackToColdRateLimit(t *testing.T) {
	h := newHarness(t)
	h.mustSign(h.toCold("r1", 100, 0))
	h.mustSign(h.toCold("r2", 100, 1))
	d := h.mustReject(h.toCold("r3", 100, 2), ReasonToColdRate)
	if !contains(d.Reason, "2 hot-to-cold moves in the last hour, limit 2") {
		t.Fatalf("reason %q", d.Reason)
	}
}

func TestAttackToColdDailyCapHoldsEvenWithApprovals(t *testing.T) {
	h := newHarness(t)
	h.mustSign(h.toCold("d1", 4000, 0))
	// 4000 + 3000 > the 6000 cap, with or without the approvals of two approvers.
	d := h.mustReject(h.toCold("d2", 3000, 1), ReasonToColdCap)
	if !contains(d.Reason, "exceeds the cap 6000") {
		t.Fatalf("reason %q", d.Reason)
	}
	h.mustReject(h.toCold("d3", 3000, 1, "alice", "bob"), ReasonToColdCap)
	// Within the cap it still goes through, so the refusals above were about the cap.
	h.mustSign(h.toCold("d4", 2000, 1))
	// The day rolls over: the earlier moves no longer count.
	h.advance(25 * 3600 * 1e9)
	h.mustSign(h.toCold("d5", 5000, 2))
}

func TestToColdWithdrawalToTheColdAddressIsStillAWithdrawal(t *testing.T) {
	h := newHarness(t)
	// A withdrawal that happens to pay the cold address needs approvals and counts against the withdrawal caps, not the
	// to-cold ones: it is not a way around either limit.
	h.mustReject(h.withdrawal("w0", addrCold, 100, 0), ReasonApprovals)
	h.mustSign(h.withdrawal("w1", addrCold, 100, 0, "alice"))
	h.mustSign(h.toCold("w2", 6000, 1)) // the to-cold budget is untouched by the withdrawal
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }
