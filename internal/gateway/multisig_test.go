package gateway

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/signer"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// A fake chain whose transactions need two signatures and consume two things (like a Bitcoin transaction with two
// inputs). Test code only: it proves the guard's rules do not depend on the EVM nonce.

const fakeChainName = "fake2"
const fakePartition = "p-fake"

type fakePayload struct {
	Digests []string `json:"digests"` // hex, one per signature
	Claims  []string `json:"claims"`
	Fee     int64    `json:"fee"`
	Dest    string   `json:"dest"`
	Note    string   `json:"note,omitempty"`
}

type fakeCodec struct{}

func (fakeCodec) Verify(u chain.UnsignedTx, i signjob.Intent) error {
	var p fakePayload
	if err := json.Unmarshal(u.Payload, &p); err != nil {
		return err
	}
	for _, d := range p.Digests {
		if d == hex.EncodeToString(u.Digest) {
			return nil
		}
	}
	return fmt.Errorf("digest %x is not one of the payload's", u.Digest)
}
func (fakeCodec) Decode(payload []byte) (TxInfo, error) {
	var p fakePayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return TxInfo{}, err
	}
	return TxInfo{Sender: "fake-hot", Destination: p.Dest, Claims: p.Claims, Fees: []*big.Int{big.NewInt(p.Fee)}}, nil
}
func (fakeCodec) OwnsSender(string) bool                     { return true }
func (fakeCodec) CheckSigner(TxInfo, *ecdsa.PublicKey) error { return nil }
func (fakeCodec) Canonical(a string) (string, error)         { return strings.ToLower(a), nil }
func (fakeCodec) FeesRaised(prev, next []*big.Int) bool      { return next[0].Cmp(prev[0]) > 0 }

// fake2 builds a gateway for the fake chain next to the harness's EVM chain.
func (h *harness) fake2(t *testing.T) *Gateway {
	t.Helper()
	cfg := *h.cfg
	cfg.Chains = map[string]*ChainConfig{}
	for k, v := range h.cfg.Chains {
		cfg.Chains[k] = v
	}
	cfg.Chains[fakeChainName] = &ChainConfig{Name: fakeChainName, Family: "fake", SweepsPerHour: 100, WithdrawalsPerHour: 100,
		Assets: map[string]AssetPolicy{"COIN": {PerTxCap: big.NewInt(1e9), DailyCap: big.NewInt(1e9), AnyDestination: true,
			ToColdDailyCap: new(big.Int), RebalanceDailyCap: new(big.Int)}}}
	for _, q := range []string{
		`INSERT INTO assets (chain, symbol, decimals) VALUES ('` + fakeChainName + `','COIN',8)`,
		`INSERT INTO partitions (id, entity, chain, asset, tier, pool, shard) VALUES ('` + fakePartition + `','qv-us','` + fakeChainName + `','COIN','hot','omnibus',0)`,
	} {
		if _, err := h.biz.Exec(context.Background(), q); err != nil {
			t.Fatal(err)
		}
	}
	codecs, err := NewCodecs(h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	codecs[fakeChainName] = fakeCodec{}
	gw, err := New(&cfg, codecs, map[string]signer.Signer{fakePartition: h.signer}, h.guard, h.biz,
		Options{WorkerID: "fake-w", Lease: time.Minute, Now: h.clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { gw.Wait(10 * time.Second) })
	return gw
}

func fakeDigest(s string) []byte { d := sha256.Sum256([]byte(s)); return d[:] }

// fakeTx returns the two sign jobs of one fake transaction (job IDs as custody names them: id and id.1).
func fakeTx(id, intentID string, claims []string, fee int64, note string) (j0, j1 signjob.Job) {
	d0, d1 := fakeDigest(id+"/0"), fakeDigest(id+"/1")
	p, _ := json.Marshal(fakePayload{Digests: []string{hex.EncodeToString(d0), hex.EncodeToString(d1)}, Claims: claims, Fee: fee, Dest: "Dest", Note: note})
	in, _ := json.Marshal(signjob.Intent{Kind: "sweep", ID: intentID, PartitionID: fakePartition, Chain: fakeChainName, Asset: "COIN", From: "a", To: "Dest", Amount: "10"})
	mk := func(jid, key string, d []byte) signjob.Job {
		return signjob.Job{ID: jid, PartitionID: fakePartition, KeyRef: key, Chain: fakeChainName, Intent: in, Digest: d, Payload: p}
	}
	return mk(id, "k/0", d0), mk(id+".1", "k/1", d1)
}

func (h *harness) runWith(gw *Gateway, j signjob.Job) Decision {
	h.t.Helper()
	h.put(j)
	d, ok, err := gw.RunOnce(context.Background())
	if err != nil || !ok || d.JobID != j.ID {
		h.t.Fatalf("RunOnce: job %s ok=%v err=%v got %s", j.ID, ok, err, d.JobID)
	}
	return d
}

// Both signatures of one transaction are signed: the second is another input of the same transaction, not a replacement
// that would need higher fees. Another intent that needs one of the same things is refused, and so is a different
// transaction of the same intent unless it pays more.
func TestTwoSignatureTransaction(t *testing.T) {
	h := newHarness(t)
	gw := h.fake2(t)
	base := h.signer.calls.Load()

	a0, a1 := fakeTx("t1", "i1", []string{"out1", "out2"}, 100, "")
	for _, j := range []signjob.Job{a0, a1} {
		if d := h.runWith(gw, j); d.Outcome != OutcomeSigned {
			t.Fatalf("job %s: %s %s", j.ID, d.Outcome, d.Reason)
		}
	}
	if got := h.signer.calls.Load() - base; got != 2 {
		t.Fatalf("%d signer calls for two inputs", got)
	}
	var rows, hashes int
	h.guardDB.QueryRow(context.Background(), `SELECT count(*), count(DISTINCT payload_hash) FROM signed_digests WHERE intent_id='i1'`).Scan(&rows, &hashes)
	if rows != 2 || hashes != 1 {
		t.Fatalf("guard rows %d, payload hashes %d; want 2 digests of 1 transaction", rows, hashes)
	}

	// Another intent that spends one of the same outputs: exclusive, refused, nothing signed.
	b0, _ := fakeTx("t2", "i2", []string{"out2", "out9"}, 500, "")
	if d := h.runWith(gw, b0); d.Outcome != OutcomeRejected || !strings.HasPrefix(d.Reason, ReasonNonceTaken) {
		t.Fatalf("overlapping claim: %s %s", d.Outcome, d.Reason)
	}
	// The same intent with other claims is not a replacement.
	c0, _ := fakeTx("t3", "i1", []string{"out1", "out7"}, 500, "")
	if d := h.runWith(gw, c0); d.Outcome != OutcomeRejected || !strings.HasPrefix(d.Reason, ReasonNonceChanged) {
		t.Fatalf("other claims for the intent: %s %s", d.Outcome, d.Reason)
	}
	// A different transaction of the same intent over the same claims must raise the fee.
	r0, r1 := fakeTx("t4", "i1", []string{"out1", "out2"}, 100, "same fee")
	if d := h.runWith(gw, r0); d.Outcome != OutcomeRejected || !strings.HasPrefix(d.Reason, ReasonFeeNotHigher) {
		t.Fatalf("same fee: %s %s", d.Outcome, d.Reason)
	}
	r0, r1 = fakeTx("t5", "i1", []string{"out1", "out2"}, 101, "bumped")
	for _, j := range []signjob.Job{r0, r1} {
		if d := h.runWith(gw, j); d.Outcome != OutcomeSigned {
			t.Fatalf("replacement job %s: %s %s", j.ID, d.Outcome, d.Reason)
		}
	}
	// Smuggling: the second job of the replacement carries the old fee in a payload of its own: a different
	// transaction, so it is judged as a replacement and refused.
	_, s1 := fakeTx("t6", "i1", []string{"out1", "out2"}, 100, "smuggled")
	if d := h.runWith(gw, s1); d.Outcome != OutcomeRejected || !strings.HasPrefix(d.Reason, ReasonFeeNotHigher) {
		t.Fatalf("a second signature under another payload at the old fee: %s %s", d.Outcome, d.Reason)
	}
}

// A crash between the two signatures resumes without signing twice: the first digest's stored signature comes back
// as a replay when the job is claimed again, and only the second digest is signed.
func TestCrashBetweenTwoSignaturesSignsEachDigestOnce(t *testing.T) {
	h := newHarness(t)
	gw := h.fake2(t)
	base := h.signer.calls.Load()
	j0, j1 := fakeTx("c1", "ic1", []string{"o1", "o2"}, 100, "")

	d := h.runWith(gw, j0)
	if d.Outcome != OutcomeSigned {
		t.Fatalf("%s %s", d.Outcome, d.Reason)
	}
	first := d.Sig
	// The process dies here, before the second job is looked at. Its lease runs out and the first job is claimed
	// again too, as if its completion had been lost.
	ctx := context.Background()
	if _, err := h.biz.Exec(ctx, `UPDATE sign_jobs SET status='signing', signature=NULL, locked_by='dead', locked_at=now() - interval '1 hour' WHERE id=$1`, j0.ID); err != nil {
		t.Fatal(err)
	}
	h.put(j1)
	got := map[string]Decision{}
	for i := 0; i < 2; i++ {
		d, ok, err := gw.RunOnce(ctx)
		if err != nil || !ok {
			t.Fatalf("RunOnce: %v %v", ok, err)
		}
		got[d.JobID] = d
	}
	if d := got[j0.ID]; d.Outcome != OutcomeReplayed || string(d.Sig) != string(first) {
		t.Fatalf("first job after the crash: %s (%s), want the stored signature replayed", d.Outcome, d.Reason)
	}
	if d := got[j1.ID]; d.Outcome != OutcomeSigned {
		t.Fatalf("second job: %s %s", d.Outcome, d.Reason)
	}
	if n := h.signer.calls.Load() - base; n != 2 {
		t.Fatalf("signer called %d times for two digests", n)
	}
}

// One refused signature refuses its transaction: the other job may have been signed, but the first refusal is what
// the attempt reports (see custody.JobStatus), and a refusal never records a digest.
func TestOneRefusedSignatureIsReported(t *testing.T) {
	h := newHarness(t)
	gw := h.fake2(t)
	j0, j1 := fakeTx("r1", "ir1", []string{"q1", "q2"}, 100, "")
	j1.Digest = fakeDigest("not part of the payload")
	if d := h.runWith(gw, j0); d.Outcome != OutcomeSigned {
		t.Fatalf("%s %s", d.Outcome, d.Reason)
	}
	if d := h.runWith(gw, j1); d.Outcome != OutcomeRejected || !strings.HasPrefix(d.Reason, ReasonTx) {
		t.Fatalf("a digest the payload does not hold: %s %s", d.Outcome, d.Reason)
	}
	got, _ := signjob.Get(context.Background(), h.biz, j1.ID)
	if got.Status != signjob.StatusRejected {
		t.Fatalf("job row %s", got.Status)
	}
}
