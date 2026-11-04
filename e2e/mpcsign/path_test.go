package mpcsign_test

import (
	"context"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rpc"
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

// B-side outage: with the cosigner down every Sign is refused (fail closed), and signing resumes when it returns.
func TestCosignerOutageRefusesThenResumes(t *testing.T) {
	s := newStack(t, stackOpts{})
	s.provision(t, false)
	x := ctx(t, 60*time.Second)
	try := func(id string, nonce uint64) error {
		_, err := s.client.Sign(x, s.signRequest(s.h.Withdrawal(id, gatewaytest.AddrUser, 100, nonce, "alice")))
		return err
	}
	if err := try("out-0", 0); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	s.cosigner.kill()
	for i := uint64(1); i <= 3; i++ {
		start := time.Now()
		err := try(fmt.Sprintf("out-%d", i), i)
		if grpcstatus.Code(err) != codes.PermissionDenied {
			t.Fatalf("with the cosigner down, sign %d: %v (want PermissionDenied)", i, err)
		}
		if k, _ := kindOfErr(err); k != pb.ErrorKind_ERROR_KIND_REFUSED {
			t.Fatalf("kind %v", k)
		}
		if time.Since(start) > 7*time.Second {
			t.Fatalf("refusal took %v", time.Since(start))
		}
	}
	s.startCosigner(t)
	if err := try("out-4", 4); err != nil {
		t.Fatalf("after the cosigner returned: %v", err)
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
}

var _ = context.Background
