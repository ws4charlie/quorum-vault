package sole2e

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/e2e/mpcstack"
	"github.com/ws4charlie/quorum-vault/internal/chain/sol"
	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

const lamportsPerSOL = 1_000_000_000

// payer funds a deposit address like a customer's wallet: a System Program transfer from the test funder.
func (s *system) paySOL(to string, lamports uint64) string {
	s.t.Helper()
	return s.c.run(s.funder, nil, s.c.sysTransfer(s.funder.pub, addrBytes(s.t, to), lamports))
}

// funderTokens makes the funder's own token account for mint and fills it.
func (s *system) funderTokens(mint key, amount uint64) [32]byte {
	s.t.Helper()
	acct := s.c.ata(s.funder.pub, mint.pub)
	s.c.run(s.funder, nil, s.c.createATA(s.funder.pub, acct, s.funder.pub, mint.pub), s.c.mintTo(mint.pub, acct, s.funder.pub, amount))
	return acct
}

// payToken sends tokens to the ATA of the deposit address (the wallet creates the ATA if it is not there, as wallets do).
func (s *system) payToken(from [32]byte, mint key, to string, amount uint64) string {
	s.t.Helper()
	owner := addrBytes(s.t, to)
	ata := s.c.ata(owner, mint.pub)
	return s.c.run(s.funder, nil, s.c.createATA(s.funder.pub, ata, owner, mint.pub), s.c.tokenTransfer(from, ata, s.funder.pub, amount))
}

func (s *system) deposits(customer string) int {
	return s.count(`SELECT count(*) FROM deposits WHERE customer_id=$1`, customer)
}

// The address the core hands out is the key the parties derive: public derivation from the account node equals Derive at [0, index].
func TestDerivedAddressesEqualMPCDerivedKeys(t *testing.T) {
	requireSOL(t)
	dir := t.TempDir()
	m := mpcstack.New(t, dir, mpcBin, mpcstack.Opts{})
	ed25519DKG(t, m, "sol-hd")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	node, err := sol.AccountNode(ctx, m.Client, "sol-hd")
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range []uint32{0, 1, 2, 7, 100, 4242, 1<<31 - 1} {
		got, err := node.DepositAddressAt(i)
		if err != nil {
			t.Fatal(err)
		}
		d, err := m.Client.Derive(ctx, &pb.DeriveRequest{KeysetId: "sol-hd", HardenedPath: sol.AccountPath(), Path: []uint32{sol.BranchExternal, i}})
		if err != nil {
			t.Fatal(err)
		}
		if want := sol.Address([32]byte(d.PublicKey)); got != want {
			t.Fatalf("index %d: derived offline %s, the parties derive %s", i, got, want)
		}
	}
	// the hot branch is separate: a different key at the same index
	h0, _ := node.Derive(sol.BranchHot, 0)
	d0, _ := node.DepositAddressAt(0)
	if sol.Address(h0.PublicKey) == d0 {
		t.Fatal("the hot branch and the deposit branch collide")
	}
}

func TestSOLDepositCreditedOnceAfterFinality(t *testing.T) {
	s := newSystem(t, opts{})
	addr := s.newCustomer("alice")
	start := s.cursor()
	sig := s.paySOL(addr, 2*lamportsPerSOL)
	slot, _ := s.c.waitStatus(sig, "confirmed", false)
	// Confirmed is not final: while the finalized slot is below the transaction's, nothing is credited.
	if fin, _ := s.c.rpc.Slot(s.ctx, sol.Finalized); fin < slot {
		if got := s.available("alice", "SOL"); got.Sign() != 0 {
			t.Fatalf("credited at confirmed commitment (slot %d, finalized %d): %v", slot, fin, got)
		}
	} else {
		t.Logf("the transaction was final before the check (slot %d, finalized %d)", slot, fin)
	}
	s.waitAvailable("alice", "SOL", 2*lamportsPerSOL, 60*time.Second)
	var h int64
	if err := s.pool.QueryRow(s.ctx, `SELECT block_height FROM deposits WHERE customer_id='alice'`).Scan(&h); err != nil {
		t.Fatal(err)
	}
	if fin, _ := s.c.rpc.Slot(s.ctx, sol.Finalized); uint64(h) > fin {
		t.Fatalf("credited a deposit of slot %d with the finalized slot at %d", h, fin)
	}
	// Scanning the same slots again credits nothing twice.
	if _, err := s.pool.Exec(s.ctx, `UPDATE chain_cursors SET next_height=$2 WHERE chain=$1`, s.chain, start); err != nil {
		t.Fatal(err)
	}
	s.waitScanned()
	s.holds(2*time.Second, "balance and deposit count stay", func() bool {
		return s.available("alice", "SOL").Cmp(bigU(2*lamportsPerSOL)) == 0 && s.deposits("alice") == 1
	})
	s.reconcileClean("after a rescan")
}

// A worker restart while a deposit is on its way to finality credits it once.
func TestSOLRestartDuringDeposit(t *testing.T) {
	s := newSystem(t, opts{})
	addr := s.newCustomer("bob")
	s.paySOL(addr, 3*lamportsPerSOL)
	s.restartWorker()
	s.waitAvailable("bob", "SOL", 3*lamportsPerSOL, 60*time.Second)
	s.restartWorker()
	s.waitScanned()
	s.holds(2*time.Second, "credited once", func() bool {
		return s.deposits("bob") == 1 && s.available("bob", "SOL").Cmp(bigU(3*lamportsPerSOL)) == 0
	})
	s.reconcileClean("after restarts")
}

// SPL: the ATA is credited. Another token account owned by the address is not (and is reported); another mint is not.
func TestSPLDepositToTheATAIsCredited(t *testing.T) {
	s := newSystem(t, opts{})
	addr := s.newCustomer("carol")
	owner := addrBytes(t, addr)
	src := s.funderTokens(s.mint, 10_000_000)

	s.payToken(src, s.mint, addr, 2_500_000)
	s.waitAvailable("carol", "TKN", 2_500_000, 60*time.Second)
	if got := s.available("carol", "SOL"); got.Sign() != 0 {
		t.Fatalf("a token deposit credited SOL: %v", got)
	}
	s.reconcileClean("after the token deposit")

	// A token account of the same mint that is owned by the address but is not its ATA: the tokens are there, the books never saw them.
	stray := newKey(t)
	s.c.run(s.funder, []key{stray}, s.c.createAccount(s.funder.pub, stray.pub, prog(t, sol.TokenProgram), s.c.rent(165), 165), s.c.initTokenAccount(stray.pub, s.mint.pub, owner))
	s.c.run(s.funder, nil, s.c.tokenTransfer(src, stray.pub, s.funder.pub, 1_000_000))

	// A token of another mint, into that mint's ATA of the address.
	other := s.c.newMint(s.funder, 6)
	otherSrc := s.funderTokens(other, 5_000_000)
	s.payToken(otherSrc, other, addr, 5_000_000)

	s.waitScanned()
	s.holds(3*time.Second, "nothing more is credited", func() bool {
		return s.available("carol", "TKN").Cmp(bigU(2_500_000)) == 0 && s.deposits("carol") == 1
	})
	s.reconcileClean("with tokens in a non-ATA account and another mint")
	if !fileContains(s.core.log, "not its associated token account") {
		t.Fatal("no ALERT for the tokens in a token account that is not the ATA")
	}
}

// A SOL transfer that would leave a new address below the rent-exempt minimum fails on chain; nothing is credited. The minimum itself works.
func TestRentMinimumToAFreshAddress(t *testing.T) {
	s := newSystem(t, opts{})
	addr := s.newCustomer("dave")
	min := s.c.rent(0)
	t.Logf("rent-exempt minimum of an empty account: %d lamports", min)
	tx := build(t, s.c.blockhash(), s.funder, nil, s.c.sysTransfer(s.funder.pub, addrBytes(t, addr), min-1))
	sig := s.c.send(tx, true) // skipPreflight: the node would refuse it up front; let it land and fail on chain
	if _, failed := s.c.waitStatus(sig, "finalized", true); !failed {
		t.Fatal("a transfer below the rent-exempt minimum to a fresh address succeeded")
	}
	s.waitScanned()
	s.holds(2*time.Second, "nothing credited for a failed transaction", func() bool { return s.available("dave", "SOL").Sign() == 0 && s.deposits("dave") == 0 })
	s.reconcileClean("after the failed deposit")
	s.paySOL(addr, min)
	s.waitAvailable("dave", "SOL", min, 60*time.Second)
	s.reconcileClean("after the minimum")
}

// Twenty customers at once, SOL for all and tokens for the odd ones.
func TestManyCustomersMixed(t *testing.T) {
	s := newSystem(t, opts{})
	const n = 20
	src := s.funderTokens(s.mint, 1_000_000_000)
	addrs := make([]string, n)
	for i := range addrs {
		addrs[i] = s.newCustomer(fmt.Sprintf("cust%02d", i))
	}
	seen := map[string]bool{}
	for _, a := range addrs {
		if seen[a] {
			t.Fatalf("address %s handed out twice", a)
		}
		seen[a] = true
	}
	var wg sync.WaitGroup
	for i := range addrs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s.paySOL(addrs[i], uint64(i+1)*10_000_000)
			if i%2 == 1 {
				s.payToken(src, s.mint, addrs[i], uint64(i+1)*1000)
			}
		}(i)
	}
	wg.Wait()
	for i := range addrs {
		c := fmt.Sprintf("cust%02d", i)
		s.waitAvailable(c, "SOL", uint64(i+1)*10_000_000, 90*time.Second)
		if i%2 == 1 {
			s.waitAvailable(c, "TKN", uint64(i+1)*1000, 90*time.Second)
		} else if got := s.available(c, "TKN"); got.Sign() != 0 {
			t.Fatalf("%s has tokens it was never sent: %v", c, got)
		}
	}
	s.reconcileClean("after twenty customers")
}

// A deposit below the configured minimum goes to suspense: it is on the chain, so Reconcile counts it, but the customer is not credited.
func TestBelowMinimumGoesToSuspense(t *testing.T) {
	s := newSystem(t, opts{minDeposit: "5000000"})
	addr := s.newCustomer("erin")
	s.paySOL(addr, 1_000_000) // above the rent-exempt minimum (it lands), below the configured minimum
	s.waitFor(60*time.Second, "the deposit in suspense", func() bool {
		return s.count(`SELECT count(*) FROM deposits WHERE address=$1 AND status='suspense'`, addr) == 1
	})
	if got := s.available("erin", "SOL"); got.Sign() != 0 {
		t.Fatalf("credited below the minimum: %v", got)
	}
	s.reconcileClean("with a deposit in suspense")
}

// A core configured for another cluster than the node is on refuses to start.
func TestWrongNetworkRefusesToStart(t *testing.T) {
	s := newSystem(t, opts{})
	cf := s.cf
	sc := *cf.Chain.SOL
	sc.Network = "mainnet"
	cf.Chain.SOL = &sc
	s.cfgPath = s.cfgPath + ".mainnet"
	s.writeConfig(cf)
	p := s.spawn("qv-core", "-config", s.cfgPath, "-dsn", s.bizDSN, "-addr", fmt.Sprintf("127.0.0.1:%d", freePort(t)), "-task-queue", s.queue)
	select {
	case <-p.done:
	case <-time.After(30 * time.Second):
		t.Fatal("qv-core started against a node of another cluster")
	}
	b, _ := bytesRead(p.log)
	if !strings.Contains(b, "cluster") {
		t.Fatalf("qv-core exited without naming the cluster:\n%s", b)
	}
}

var _ = bytes.Equal
