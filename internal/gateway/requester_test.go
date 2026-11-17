package gateway

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// The zone refuses an approval by the person who requested the withdrawal. The requester is part of the signed intent, so it cannot be changed
// after the approvals were made.
func TestRequesterCannotApproveOwnWithdrawal(t *testing.T) {
	h := newHarness(t)
	mk := func(id, requester string, approvers ...string) signjob.Job {
		in := signjob.Intent{Kind: "withdrawal", RequestedBy: requester, ID: "w-" + id, Asset: "ETH", To: addrUser.Hex(), Amount: "100"}
		return h.job(id, in, h.ethTx(addrUser, 100, 0), approvers...)
	}
	h.mustReject(mk("r1", "alice", "alice"), ReasonRequester)
	// Even with a second, valid approver next to the requester's own: one counted approver is the requester.
	h.mustReject(mk("r2", "alice", "alice", "bob"), ReasonRequester)
	// The same intent, approved by somebody else, signs.
	h.mustSign(mk("r3", "alice", "bob"))
}

func TestRequesterEmptyIsRefused(t *testing.T) {
	h := newHarness(t)
	in := signjob.Intent{Kind: "withdrawal", ID: "w-empty", Asset: "ETH", To: addrUser.Hex(), Amount: "100"}
	h.mustReject(h.job("e1", in, h.ethTx(addrUser, 100, 0), "alice"), ReasonRequester)
	// An intent written before v2 (no requested_by, approvals over the v1 hash) is refused with that reason, not signed.
	h.mustReject(h.job("e2", in, h.ethTx(addrUser, 100, 0)), ReasonRequester)
}

// An approval is over one requester: moving it to a job that names another requester is a different hash and counts for nothing.
func TestRequesterTamperedIsRefused(t *testing.T) {
	h := newHarness(t)
	in := signjob.Intent{Kind: "withdrawal", RequestedBy: "carol", ID: "w-tamper", Asset: "ETH", To: addrUser.Hex(), Amount: "100"}
	j := h.job("t1", in, h.ethTx(addrUser, 100, 0), "bob") // bob approved a request by carol
	tampered := mustIntent(j.Intent)
	tampered.RequestedBy = "alice" // the core now claims another requester (to dodge a self-approval check, say)
	j.Intent = mustJSON(tampered)
	h.mustReject(j, ReasonApprovals)
}

// The automated approver is an approver like any other: a request in its own name cannot be approved by it, and its approvals need a requester.
func TestRequesterAutoApprover(t *testing.T) {
	h := newHarness(t)
	mk := func(id, requester string) signjob.Job {
		in := signjob.Intent{Kind: "withdrawal", RequestedBy: requester, ID: "w-" + id, Asset: "ETH", To: addrUser.Hex(), Amount: "100"}
		return h.job(id, in, h.ethTx(addrUser, 100, 0), "auto")
	}
	h.mustSign(mk("a1", "alice"))
	h.mustReject(mk("a2", "auto"), ReasonRequester)
	h.mustReject(mk("a3", ""), ReasonRequester)
}

// Two keys of one person are one approver: they count once for the tier, and the requester's second key cannot approve.
func TestRequesterIdentityIsThePersonNotTheKey(t *testing.T) {
	h := newHarness(t)
	b := h.cfg.Approvers["bob"]
	b.Identity = "alice" // bob's key is a second key of alice
	h.cfg.Approvers["bob"] = b
	big := signjob.Intent{Kind: "withdrawal", RequestedBy: "req", ID: "w-two", Asset: "ETH", To: addrUser.Hex(), Amount: "2000"} // needs 2 people
	h.mustReject(h.job("i1", big, h.ethTx(addrUser, 2000, 0), "alice", "bob"), ReasonTier)
	h.mustSign(h.job("i2", big, h.ethTx(addrUser, 2000, 0), "alice", "carol"))
	// A request by alice cannot be approved with bob's key either.
	own := signjob.Intent{Kind: "withdrawal", RequestedBy: "alice", ID: "w-own", Asset: "ETH", To: addrUser.Hex(), Amount: "100"}
	h.mustReject(h.job("i3", own, h.ethTx(addrUser, 100, 1), "bob"), ReasonRequester)
}

// Kinds nobody requests carry no requester; one that does is refused.
func TestRequesterOnKindsWithoutOne(t *testing.T) {
	h := newHarness(t)
	in := signjob.Intent{Kind: "to-cold", RequestedBy: "alice", ID: "m-rq", PartitionID: testColdPartition, Asset: "ETH", To: addrCold.Hex(), Amount: "10"}
	h.mustReject(h.job("k1", in, h.ethTx(addrCold, 10, 0)), ReasonRequester)
}

func TestBTCBatchRequesterIsApprover(t *testing.T) {
	b := newBatchHarness(t, nil)
	ms := []bm{{id: "q1", to: b.other, amount: 100_000}, {id: "q2", to: b.cold, amount: 120_000}}
	try := func(name, code string, mutate func(bt *signjob.Batch), i int) {
		t.Helper()
		bt := b.batchOf(fmt.Sprintf("rq%d", i), ms...)
		mutate(&bt)
		ins := []btc.PayloadInput{btcIn(130+i*2, 0, 600_000, 1, 0), btcIn(131+i*2, 0, 600_000, 1, 0)}
		js := b.batchJobs(fmt.Sprintf("rq%d", i), bt, b.batchPayload(ins, ms, 2_000))
		js[0].Intent = mustJSON(bt)
		t.Logf("case: %s", name)
		b.mustRefuse(js[0], code)
	}
	reapprove := func(bt *signjob.Batch, k int, requester string, who ...string) {
		m := &bt.Members[k]
		m.Intent.RequestedBy = requester
		m.Approvals = b.approvals(m.Intent, who...)
	}
	try("member 2's approver is its requester", ReasonRequester, func(bt *signjob.Batch) { reapprove(bt, 1, "auto", "auto") }, 1)
	try("one of two approvers is the requester", ReasonRequester, func(bt *signjob.Batch) { reapprove(bt, 0, "bob", "alice", "bob") }, 2)
	try("a member without a requester", ReasonRequester, func(bt *signjob.Batch) { reapprove(bt, 0, "", "auto") }, 3)
	try("a requester moved after the approval", ReasonApprovals, func(bt *signjob.Batch) { bt.Members[1].Intent.RequestedBy = "someone-else" }, 4)
}

// The cosigner's decider refuses a batch member approved by its requester too.
func TestBTCBatchRequesterCosigner(t *testing.T) {
	b := newBatchHarness(t, nil)
	cos := NewDecider(b.cfg, b.gw.codecs, mustGuard(t, b.harness), ModeCosigner, b.clock)
	key, err := b.tree.At(t.Context(), []uint32{1, 0})
	if err != nil {
		t.Fatal(err)
	}
	ms := []bm{{id: "cq1", to: b.other, amount: 100_000}, {id: "cq2", to: b.cold, amount: 120_000}}
	bt := b.batchOf("cq", ms...)
	m := &bt.Members[1]
	m.Intent.RequestedBy = "auto"
	m.Approvals = b.approvals(m.Intent, "auto")
	js := b.batchJobs("cq", bt, b.batchPayload(b.twoIn(1), ms, 2_000))
	js[0].Intent = mustJSON(bt)
	if _, err := cos.Decide(t.Context(), js[0], key.PublicKey()); err == nil {
		t.Fatal("the cosigner allowed a member approved by its requester")
	} else if why, _ := IsRejection(err); !strings.HasPrefix(why, ReasonRequester+":") {
		t.Fatalf("err %v", err)
	}
}
