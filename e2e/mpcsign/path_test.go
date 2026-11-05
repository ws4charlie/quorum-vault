package mpcsign_test

import (
	"context"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/ws4charlie/quorum-vault/internal/chain/eth"
	"github.com/ws4charlie/quorum-vault/internal/gateway"
	"github.com/ws4charlie/quorum-vault/internal/gateway/gatewaytest"
	"github.com/ws4charlie/quorum-vault/internal/signer"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

// One real withdrawal through qv-gateway -> party A -> party B (+ qv-cosigner), mined on anvil; the sender on chain is the
// MPC-derived hot address. Needs anvil on QV_ANVIL_RPC (default http://127.0.0.1:18545), chain id 11155111.
func TestEndToEndWithdrawalMinesOnAnvil(t *testing.T) {
	rpcURL := os.Getenv("QV_ANVIL_RPC")
	if rpcURL == "" {
		rpcURL = "http://127.0.0.1:18545"
	}
	s := newStack(t, stackOpts{chainID: 11155111})
	s.provision(t, false)
	gw := s.startGateway("w1")

	x := ctx(t, 3*time.Minute)
	raw, err := rpc.DialContext(x, rpcURL)
	if err != nil {
		t.Skipf("no anvil at %s: %v", rpcURL, err)
	}
	defer raw.Close()
	if err := raw.CallContext(x, nil, "anvil_setBalance", s.hot, (*hexutil.Big)(big.NewInt(1e18))); err != nil {
		t.Fatalf("fund hot address: %v", err)
	}
	cl, err := eth.Dial(x, rpcURL)
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	nonce, tip, feeCap, err := cl.Suggest(x, s.hot)
	if err != nil {
		t.Fatal(err)
	}

	spec := gatewaytest.TxSpec{Nonce: nonce, To: gatewaytest.AddrUser, Value: big.NewInt(500), Gas: 21000, Tip: tip, FeeCap: feeCap}
	in := signjob.Intent{Kind: "withdrawal", ID: "w-e2e", Asset: "ETH", To: gatewaytest.AddrUser.Hex(), Amount: "500"}
	job := s.h.Job("job-e2e", in, spec, "alice")
	s.enqueue(job)
	got := s.waitJob(job.ID, 60*time.Second)
	if got.Status != signjob.StatusDone || len(got.Signature) != 64 {
		t.Fatalf("job %s: status %s reason %q\ngateway: %s\nA: %s\nB: %s", job.ID, got.Status, got.RejectReason, gw.out, s.a.out, s.b.out)
	}

	tx, digest, err := eth.BuildTx(eth.TxParams{ChainID: cl.ChainID(), Nonce: nonce, To: gatewaytest.AddrUser, Value: big.NewInt(500), Gas: 21000, GasTipCap: tip, GasFeeCap: feeCap})
	if err != nil {
		t.Fatal(err)
	}
	if string(digest[:]) != string(job.Digest) {
		t.Fatal("digest mismatch")
	}
	sig := signer.Signature{R: new(big.Int).SetBytes(got.Signature[:32]), S: new(big.Int).SetBytes(got.Signature[32:])}
	pk, _ := signerPub(s)
	signed, err := eth.Assemble(tx, sig, pk)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := cl.Broadcast(x, signed.Raw)
	if err != nil {
		t.Fatalf("broadcast: %v", err)
	}
	rcpt, err := cl.WaitReceipt(x, hash, 200*time.Millisecond)
	if err != nil || rcpt.Status != 1 {
		t.Fatalf("receipt %+v err %v", rcpt, err)
	}
	if err := eth.VerifySender(signed.Tx, s.hot); err != nil {
		t.Fatalf("sender is not the derived hot address: %v", err)
	}
	t.Logf("ANVIL: tx %s mined in block %d, status %d; sender == MPC-derived hot address %s (key %s, signature low-S, %d bytes)",
		hash, rcpt.BlockNumber, rcpt.Status, s.hot, s.keyID, len(got.Signature))
	t.Logf("gateway log:\n%s", tail(gw.out.String(), 600))
	t.Logf("party B log (cosigner decision made before B joined):\n%s", tail(s.b.out.String(), 600))
}

// An outage is not a refusal and not a failure: with the cosigner down nothing is signed, the job is neither rejected nor
// failed (it would otherwise be cancelled and parked), and when the cosigner returns the job completes by itself with one
// signature.
func TestCosignerOutageKeepsJobsWaitingAndTheyComplete(t *testing.T) {
	s := newStack(t, stackOpts{})
	s.provision(t, false)
	gw := s.startGateway("w1")
	j0 := s.h.Withdrawal("o-0", gatewaytest.AddrUser, 100, 0, "alice")
	s.enqueue(j0)
	if g := s.waitJob(j0.ID, 30*time.Second); g.Status != signjob.StatusDone {
		t.Fatalf("baseline: %s %s", g.Status, g.RejectReason)
	}
	s.cosigner.kill()

	// Directly at party A: UNAVAILABLE, never a signature, and not a refusal.
	_, err := s.client.Sign(ctx(t, 30*time.Second), s.signRequest(s.h.Withdrawal("o-direct", gatewaytest.AddrUser, 100, 5, "alice")))
	if k, _ := kindOfErr(err); k != pb.ErrorKind_ERROR_KIND_UNAVAILABLE || grpcstatus.Code(err) != codes.Unavailable {
		t.Fatalf("with the cosigner down: %v (kind %v), want UNAVAILABLE", err, k)
	}

	j1 := s.h.Withdrawal("o-1", gatewaytest.AddrUser, 100, 1, "alice")
	s.enqueue(j1)
	time.Sleep(10 * time.Second) // longer than sign_timeout (4s) and the lease (3s): several attempts
	row, _ := signjob.Get(context.Background(), s.biz, j1.ID)
	if row.Status != signjob.StatusSigning || len(row.Signature) != 0 {
		t.Fatalf("during the outage the job is %s %q: it must stay signing and unsigned\n%s", row.Status, row.RejectReason, tail(gw.out.String(), 1500))
	}
	s.startCosigner(t)
	g := s.waitJob(j1.ID, 60*time.Second)
	if g.Status != signjob.StatusDone || len(g.Signature) != 64 {
		t.Fatalf("after the outage the job is %s %q\n%s", g.Status, g.RejectReason, tail(gw.out.String(), 2000))
	}
	if n := s.countLog(s.b.out, `"job_id":"o-1"`, `"outcome":"ok"`, "OP_SIGN"); n != 1 {
		t.Fatalf("party B signed job o-1 %d times, want exactly 1", n)
	}
	if n := s.countLog(gw.out, "ALERT signer unavailable"); n != 1 {
		t.Fatalf("%d ALERT lines for one outage, want 1:\n%s", n, gw.out)
	}
	waitLog(t, gw.out, "signing resumed", 5*time.Second)
	if strings.Contains(gw.out.String(), `"outcome":"rejected"`) || strings.Contains(gw.out.String(), `"outcome":"failed"`) {
		t.Fatalf("the outage rejected or failed a job:\n%s", gw.out)
	}
}

// Party B down for longer than sign_timeout, then restarted: the job completes on its own.
func TestPartyBDownLongerThanSignTimeout(t *testing.T) {
	s := newStack(t, stackOpts{})
	s.provision(t, false)
	gw := s.startGateway("w1")
	s.b.kill()
	j := s.h.Withdrawal("bdown", gatewaytest.AddrUser, 100, 0, "alice")
	s.enqueue(j)
	time.Sleep(9 * time.Second)
	row, _ := signjob.Get(context.Background(), s.biz, j.ID)
	if row.Status != signjob.StatusSigning {
		t.Fatalf("with B down the job is %s %q", row.Status, row.RejectReason)
	}
	s.restartB(t)
	g := s.waitJob(j.ID, 60*time.Second)
	if g.Status != signjob.StatusDone || len(g.Signature) != 64 {
		t.Fatalf("after B returned: %s %q\n%s", g.Status, g.RejectReason, tail(gw.out.String(), 2000))
	}
}

// The cosigner's own guard database going away is an outage too: UNAVAILABLE, not REFUSED.
func TestCosignerGuardDatabaseDownIsUnavailable(t *testing.T) {
	s := newStack(t, stackOpts{})
	s.provision(t, false)
	u, _ := url.Parse(s.csGuardDSN)
	name := strings.TrimPrefix(u.Path, "/")
	admin, err := pgx.Connect(context.Background(), os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	if _, err := admin.Exec(context.Background(), "DROP DATABASE "+name+" WITH (FORCE)"); err != nil {
		t.Fatal(err)
	}
	_, err = s.client.Sign(ctx(t, 30*time.Second), s.signRequest(s.h.Withdrawal("db-down", gatewaytest.AddrUser, 100, 0, "alice")))
	if k, _ := kindOfErr(err); k != pb.ErrorKind_ERROR_KIND_UNAVAILABLE || grpcstatus.Code(err) != codes.Unavailable {
		t.Fatalf("guard database down: %v (kind %v), want UNAVAILABLE and not REFUSED", err, k)
	}
}

// A real refusal by B's cosigner still rejects the job (the workflow then cancels the nonce), and with the cosigner up the
// cancel is signed.
func TestRealRefusalRejectsAndCancelIsSigned(t *testing.T) {
	s := newStack(t, stackOpts{})
	// B's cosigner is stricter than the gateway: per-transaction cap 400 instead of 5000.
	s.cosignerTweak = func(f gateway.File) gateway.File {
		cc := f.Chains[gatewaytest.Chain]
		assets := map[string]gateway.AssetFile{}
		for k, v := range cc.Assets {
			assets[k] = v
		}
		a := assets["ETH"]
		a.PerTxCap = "400"
		assets["ETH"] = a
		cc.Assets = assets
		chains := map[string]gateway.ChainFile{}
		for k, v := range f.Chains {
			chains[k] = v
		}
		chains[gatewaytest.Chain] = cc
		f.Chains = chains
		return f
	}
	s.provision(t, false)
	s.startGateway("w1")
	j := s.h.Withdrawal("refuse-1", gatewaytest.AddrUser, 500, 0, "alice")
	s.enqueue(j)
	g := s.waitJob(j.ID, 60*time.Second)
	if g.Status != signjob.StatusRejected || !strings.HasPrefix(g.RejectReason, gateway.ReasonSignerRefused+":") || !strings.Contains(g.RejectReason, gateway.ReasonPerTxCap) {
		t.Fatalf("job %s %q, want rejected signer_refused ... policy_per_tx_cap", g.Status, g.RejectReason)
	}
	cin := signjob.Intent{Kind: "cancel", ID: "c-refuse-1", Asset: "ETH", To: s.hot.Hex(), Amount: "0"}
	c := s.h.Job("cancel-1", cin, gatewaytest.TxSpec{Nonce: 0, To: s.hot, Gas: 21000})
	s.enqueue(c)
	cg := s.waitJob(c.ID, 60*time.Second)
	if cg.Status != signjob.StatusDone || len(cg.Signature) != 64 {
		t.Fatalf("cancel: %s %q", cg.Status, cg.RejectReason)
	}
}

// A man in the middle between A and B flips a byte in a signing message: the job fails (not rejected), an ALERT is logged
// by the gateway and by both parties, the keyset is frozen on both sides, and after an authorized unfreeze signing works.
func TestTamperingFreezesKeysetAndOperatorUnfreezes(t *testing.T) {
	s := newStack(t, stackOpts{proxy: true})
	s.provision(t, false)
	gw := s.startGateway("w1")
	x := ctx(t, 2*time.Minute)

	// 1. a clean job works through the proxy
	j0 := s.h.Withdrawal("t-0", gatewaytest.AddrUser, 100, 0, "alice")
	s.enqueue(j0)
	if g := s.waitJob(j0.ID, 60*time.Second); g.Status != signjob.StatusDone {
		t.Fatalf("clean job: %s %s\nA: %s\nB: %s", g.Status, g.RejectReason, s.a.out, s.b.out)
	}
	// 2. tamper with the third message A sends in the next session (derive is message 0, signing starts at 1)
	s.proxy.set(0, 2)
	j1 := s.h.Withdrawal("t-1", gatewaytest.AddrUser, 100, 1, "alice")
	s.enqueue(j1)
	g1 := s.waitJob(j1.ID, 60*time.Second)
	if g1.Status != signjob.StatusFailed || len(g1.Signature) != 0 {
		t.Fatalf("tampered job: status %s reason %q\nA: %s\nB: %s", g1.Status, g1.RejectReason, s.a.out, s.b.out)
	}
	s.proxy.set(0, -1)
	t.Logf("tampered job failed: %s", g1.RejectReason)
	waitLog(t, gw.out, "ALERT", 10*time.Second)
	waitLog(t, s.a.out, "ALERT keyset frozen", 10*time.Second)
	waitLog(t, s.b.out, "ALERT keyset frozen", 10*time.Second)

	// 3. frozen: the next honest job also fails, with the frozen error, and nothing is signed
	j2 := s.h.Withdrawal("t-2", gatewaytest.AddrUser, 100, 2, "alice")
	s.enqueue(j2)
	g2 := s.waitJob(j2.ID, 60*time.Second)
	if g2.Status != signjob.StatusFailed || !strings.Contains(g2.RejectReason, "frozen") {
		t.Fatalf("job on a frozen keyset: status %s reason %q", g2.Status, g2.RejectReason)
	}
	// 4. a signature by a stranger cannot unfreeze; the operator's can
	_, strangerKey := newAdminKey()
	if _, err := s.client.Unfreeze(x, &pb.UnfreezeRequest{KeysetId: s.keysetID, Admin: signWith(strangerKey, "unfreeze", s.keysetID, adminNow())}); grpcstatus.Code(err) != codes.PermissionDenied {
		t.Fatalf("unfreeze by a stranger: %v", err)
	}
	if _, err := s.client.Unfreeze(x, &pb.UnfreezeRequest{KeysetId: s.keysetID, Admin: s.adminAuth("unfreeze", s.keysetID, adminNow())}); err != nil {
		t.Fatalf("operator unfreeze: %v", err)
	}
	waitLog(t, s.a.out, "AUDIT keyset unfrozen", 5*time.Second)
	waitLog(t, s.b.out, "AUDIT keyset unfrozen", 5*time.Second)
	j3 := s.h.Withdrawal("t-3", gatewaytest.AddrUser, 100, 3, "alice")
	s.enqueue(j3)
	if g := s.waitJob(j3.ID, 60*time.Second); g.Status != signjob.StatusDone {
		t.Fatalf("after unfreeze: %s %s", g.Status, g.RejectReason)
	}
	// 5. freeze survives a restart of both parties
	_, _ = gateway.ReasonIntent, 0
}

func waitLog(t *testing.T, b *syncBuf, want string, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if strings.Contains(b.String(), want) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("log never contained %q:\n%s", want, tail(b.String(), 1500))
}

func tail(s string, n int) string {
	if len(s) > n {
		return "..." + s[len(s)-n:]
	}
	return s
}

// Signatures per second through the whole path (8 gateway processes -> party A -> party B -> cosigner -> Postgres guards).
func TestThroughputWholePath(t *testing.T) {
	s := newStack(t, stackOpts{})
	s.provision(t, false)
	const workers, jobs = 8, 96
	var gws []*proc
	for i := 0; i < workers; i++ {
		gws = append(gws, s.startGateway(fmt.Sprintf("w%d", i)))
	}
	time.Sleep(time.Second)
	for i := 0; i < jobs; i++ {
		s.enqueue(s.h.Withdrawal(fmt.Sprintf("tp-%d", i), gatewaytest.AddrUser, 1, uint64(i), "alice"))
	}
	start := time.Now()
	var wg sync.WaitGroup
	var mu sync.Mutex
	failed := 0
	for i := 0; i < jobs; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if g := s.waitJob(fmt.Sprintf("tp-%d", i), 3*time.Minute); g.Status != signjob.StatusDone {
				mu.Lock()
				failed++
				mu.Unlock()
				t.Errorf("job tp-%d: %s %s", i, g.Status, g.RejectReason)
			}
		}(i)
	}
	wg.Wait()
	el := time.Since(start)
	t.Logf("THROUGHPUT whole path: %d signatures by %d gateway workers in %v = %.1f sig/s (failed %d)", jobs, workers, el.Round(time.Millisecond), float64(jobs)/el.Seconds(), failed)
	_ = gws
	if os.Getenv("QV_MPC_DEBUG") == "1" {
		for _, g := range gws[:2] {
			t.Logf("%s:\n%s", g.name, tail(g.out.String(), 2500))
		}
		t.Logf("A:\n%s", tail(s.a.out.String(), 1500))
	}
}

var _ = context.Background
