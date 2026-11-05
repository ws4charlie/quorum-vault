package gateway

import (
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// Hot-shard rebalance: the destination is another hot shard of this zone's own config, no approval is needed, and the rate and the
// daily cap are enforced from this zone's own store whatever the intent carries.

func (h *harness) rebalance(id string, to common.Address, amount int64, nonce uint64, approvers ...string) signjob.Job {
	in := signjob.Intent{Kind: "rebalance", ID: "rb-" + id, PartitionID: testColdPartition, Asset: "ETH", To: to.Hex(), Amount: fmt.Sprint(amount)}
	return h.job(id, in, h.ethTx(to, amount, nonce), approvers...)
}

func TestRebalanceSignsWithoutApprovalsNativeAndToken(t *testing.T) {
	h := newHarness(t)
	h.mustSign(h.rebalance("b1", addrShard2, 2000, 0))
	in := signjob.Intent{Kind: "rebalance", ID: "rb-tok", PartitionID: testColdPartition, Asset: "USDT", To: addrShard2.Hex(), Amount: "3000000"}
	h.mustSign(h.job("b2", in, h.tokenTx(addrShard2, 3_000_000, 1)))
}

func TestAttackRebalanceDestinationOutsideTheShardsRefused(t *testing.T) {
	h := newHarness(t)
	// Intent and transaction both name the attacker; approvals do not matter.
	d := h.mustReject(h.rebalance("e1", addrEvil, 100, 0), ReasonTx)
	if !contains(d.Reason, "is not the hot address of another shard") {
		t.Fatalf("reason %q", d.Reason)
	}
	h.mustReject(h.rebalance("e2", addrEvil, 100, 0, "alice", "bob"), ReasonTx)
	// The cold address and the sweep destination are not shards.
	h.mustReject(h.rebalance("e3", addrCold, 100, 0), ReasonTx)
	h.mustReject(h.rebalance("e4", addrDest, 100, 0), ReasonTx)
	// A shard of another pool is not a sibling.
	h.mustReject(h.rebalance("e5", addrOtherPl, 100, 0), ReasonTx)
	// The source itself.
	d = h.mustReject(h.rebalance("e6", h.hot, 100, 0), ReasonTx)
	if !contains(d.Reason, "is the source") {
		t.Fatalf("reason %q", d.Reason)
	}
	// The intent names a shard, the transaction pays the attacker.
	in := signjob.Intent{Kind: "rebalance", ID: "rb-e7", PartitionID: testColdPartition, Asset: "ETH", To: addrShard2.Hex(), Amount: "100"}
	d = h.mustReject(h.job("e7", in, h.ethTx(addrEvil, 100, 0)), ReasonTx)
	if !contains(d.Reason, "rebalance transfer is to") {
		t.Fatalf("reason %q", d.Reason)
	}
	// A token transfer to the attacker under a rebalance intent.
	in = signjob.Intent{Kind: "rebalance", ID: "rb-e8", PartitionID: testColdPartition, Asset: "USDT", To: addrShard2.Hex(), Amount: "100"}
	d = h.mustReject(h.job("e8", in, h.tokenTx(addrEvil, 100, 0)), ReasonTx)
	if !contains(d.Reason, "calldata is not transfer") {
		t.Fatalf("reason %q", d.Reason)
	}
}

func TestAttackRebalanceRateLimit(t *testing.T) {
	h := newHarness(t)
	h.mustSign(h.rebalance("r1", addrShard2, 100, 0))
	h.mustSign(h.rebalance("r2", addrShard2, 100, 1))
	d := h.mustReject(h.rebalance("r3", addrShard2, 100, 2), ReasonRebalanceRate)
	if !contains(d.Reason, "2 hot-shard rebalances in the last hour, limit 2") {
		t.Fatalf("reason %q", d.Reason)
	}
}

func TestAttackRebalanceDailyCapHoldsEvenWithApprovals(t *testing.T) {
	h := newHarness(t)
	h.mustSign(h.rebalance("d1", addrShard2, 4000, 0))
	d := h.mustReject(h.rebalance("d2", addrShard2, 3000, 1), ReasonRebalanceCap)
	if !contains(d.Reason, "exceeds the cap 6000") {
		t.Fatalf("reason %q", d.Reason)
	}
	h.mustReject(h.rebalance("d3", addrShard2, 3000, 1, "alice", "bob"), ReasonRebalanceCap)
	h.mustSign(h.rebalance("d4", addrShard2, 2000, 1))
	h.advance(25 * 3600 * 1e9) // the day rolls over
	h.mustSign(h.rebalance("d5", addrShard2, 5000, 2))
}

// The rebalance budget and the to-cold budget are separate: one is no way around the other.
func TestRebalanceAndToColdBudgetsAreSeparate(t *testing.T) {
	h := newHarness(t)
	h.mustSign(h.rebalance("s1", addrShard2, 6000, 0))
	h.mustSign(h.toCold("s2", 6000, 1))
	h.mustReject(h.rebalance("s3", addrShard2, 1, 2), ReasonRebalanceCap)
	h.mustReject(h.toCold("s4", 1, 2), ReasonToColdCap)
}
