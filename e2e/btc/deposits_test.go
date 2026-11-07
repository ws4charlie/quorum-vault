package btce2e

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"

	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

// The design rests on this: the address derived from the account xpub equals the P2WPKH address of the public key that mpc-party
// derives at the same path. If cb-mpc's HD were not BIP32-compatible, every deposit address would be unspendable.
func TestXpubAddressesEqualMPCDerivedKeys(t *testing.T) {
	requireBTC(t)
	mpc := newMPC(t, t.TempDir())
	for _, network := range []string{"regtest", "mainnet"} {
		xpub := accountXpub(t, mpc, network)
		path := btc.AccountPath(network)
		params, _ := btc.Params(network)
		for i := uint32(0); i < 6; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			d, err := mpc.Client.Derive(ctx, &pb.DeriveRequest{KeysetId: mpc.KeysetID, HardenedPath: path, Path: []uint32{0, i}})
			cancel()
			if err != nil {
				t.Fatalf("Derive %s index %d: %v", network, i, err)
			}
			if _, err := btcec.ParsePubKey(d.PublicKey); err != nil {
				t.Fatal(err)
			}
			want, err := btc.P2WPKH(d.PublicKey, params)
			if err != nil {
				t.Fatal(err)
			}
			got, err := btc.DeriveAddress(network, xpub, i)
			if err != nil || got != want {
				t.Fatalf("%s index %d: xpub gives %q (%v), mpc-party's key gives %q", network, i, got, err, want)
			}
		}
	}
}

// One customer, one payment: not credited at depth 5, credited at 6, once, across a worker restart.
func TestDepositCreditedAtSixConfirmationsOnceAcrossRestart(t *testing.T) {
	s := newSystem(t, opts{})
	addr := s.newCustomer("c1")
	if !strings.HasPrefix(addr, "bcrt1q") {
		t.Fatalf("address %q", addr)
	}
	s.node.pay(map[string]string{addr: "0.01"})
	s.node.mine(1, "") // the payment has 1 confirmation
	s.node.mine(4, "") // 5
	s.holds(3*time.Second, "no credit at depth 5", func() bool { return s.available("c1").Sign() == 0 })
	s.node.mine(1, "") // 6
	s.waitAvailable("c1", 1_000_000, 30*time.Second)

	s.restartWorker()
	s.node.mine(3, "")
	s.holds(3*time.Second, "credited once across a restart", func() bool { return s.available("c1").Int64() == 1_000_000 })
	if n := s.count(`SELECT count(*) FROM deposits WHERE chain=$1`, s.chain); n != 1 {
		t.Fatalf("%d deposits", n)
	}
}

// Two outputs of one transaction, to two customers: two deposits, each credited to its own owner.
func TestTwoOutputsOfOneTransactionTwoCustomers(t *testing.T) {
	s := newSystem(t, opts{})
	a, b := s.newCustomer("ca"), s.newCustomer("cb")
	if a == b {
		t.Fatal("two customers share an address")
	}
	txid := s.node.pay(map[string]string{a: "0.002", b: "0.003"})
	s.node.mine(6, "")
	s.waitAvailable("ca", 200_000, 30*time.Second)
	s.waitAvailable("cb", 300_000, 30*time.Second)
	if n := s.count(`SELECT count(*) FROM deposits WHERE chain=$1 AND tx_hash=$2`, s.chain, txid); n != 2 {
		t.Fatalf("%d deposits for one transaction", n)
	}
	// The same customer pays again in a later transaction: a third deposit, same address.
	s.node.pay(map[string]string{a: "0.001"})
	s.node.mine(6, "")
	s.waitAvailable("ca", 300_000, 30*time.Second)
}

// A rescan of the same blocks credits nothing twice.
func TestRescanCreditsNothingTwice(t *testing.T) {
	s := newSystem(t, opts{})
	addr := s.newCustomer("c1")
	s.node.pay(map[string]string{addr: "0.01"})
	s.node.mine(6, "")
	s.waitAvailable("c1", 1_000_000, 30*time.Second)
	tip := s.cursor()
	if _, err := s.pool.Exec(s.ctx, `UPDATE chain_cursors SET next_height=$2 WHERE chain=$1`, s.chain, s.start); err != nil {
		t.Fatal(err)
	}
	s.waitFor(30*time.Second, "the scan caught up again", func() bool { return s.cursor() >= tip })
	s.holds(2*time.Second, "balance unchanged after the rescan", func() bool { return s.available("c1").Int64() == 1_000_000 })
	if n := s.count(`SELECT count(*) FROM deposits WHERE chain=$1`, s.chain); n != 1 {
		t.Fatalf("%d deposits after a rescan", n)
	}
}

// A shallow reorganization: the block with the payment is replaced before it is read. The payment is credited once, from the
// block that replaced it, and never while it was only 3 deep.
func TestShallowReorgCreditsTheReplacement(t *testing.T) {
	s := newSystem(t, opts{})
	addr := s.newCustomer("c1")
	s.node.pay(map[string]string{addr: "0.01"})
	first := s.node.mine(1, "")[0] // the block that will be replaced
	s.node.mine(2, "")             // 3 deep
	s.holds(2*time.Second, "nothing credited at depth 3", func() bool { return s.available("c1").Sign() == 0 })
	s.node.invalidate(first)       // the payment goes back to the mempool, three blocks are orphaned
	s.node.mine(8, s.node.fresh()) // the payment is mined again, in the new chain
	s.waitAvailable("c1", 1_000_000, 30*time.Second)
	s.holds(2*time.Second, "credited once", func() bool { return s.available("c1").Int64() == 1_000_000 })
	if n := s.count(`SELECT count(*) FROM deposits WHERE chain=$1`, s.chain); n != 1 {
		t.Fatalf("%d deposits", n)
	}
}

// A reorganization deeper than the safe depth, after a credit: ALERT, scanning stops, the credit stays, and a later payment on the
// new chain is not credited either (an operator decides).
func TestDeepReorgHaltsScanningAndKeepsTheCredit(t *testing.T) {
	s := newSystem(t, opts{})
	addr := s.newCustomer("c1")
	other := s.newCustomer("c2")
	s.node.pay(map[string]string{addr: "0.01"})
	s.node.mine(1, "")
	payBlock := s.node.blockHash(s.node.height())
	s.node.mine(8, "")
	s.waitAvailable("c1", 1_000_000, 30*time.Second)
	s.waitFor(30*time.Second, "the scan reached the safe head", func() bool { return s.cursor() >= s.node.height()-5 })

	s.node.invalidate(payBlock)     // every block from the payment's on is orphaned
	s.node.mine(14, s.node.fresh()) // the new chain is longer
	s.waitFor(30*time.Second, "scan halted", func() bool { return s.count(`SELECT count(*) FROM scan_halts WHERE chain=$1`, s.chain) == 1 })
	p := s.worker
	s.waitFor(10*time.Second, "an ALERT in the worker log", func() bool { return fileContains(p.log, "ALERT: scanning is halted") })

	s.node.pay(map[string]string{other: "0.001"})
	s.node.mine(8, "")
	s.holds(3*time.Second, "nothing credited while halted; the first credit stays", func() bool {
		return s.available("c1").Int64() == 1_000_000 && s.available("c2").Sign() == 0
	})
}

// Below min_deposit goes to suspense, as on EVM.
func TestBelowMinimumGoesToSuspense(t *testing.T) {
	s := newSystem(t, opts{minDeposit: "10000"})
	addr := s.newCustomer("c1")
	s.node.pay(map[string]string{addr: "0.00005"}) // 5000 sats
	s.node.mine(6, "")
	s.waitFor(30*time.Second, "the deposit is booked", func() bool {
		return s.count(`SELECT count(*) FROM deposits WHERE chain=$1 AND status='suspense'`, s.chain) == 1
	})
	if got := s.available("c1"); got.Sign() != 0 {
		t.Fatalf("customer credited %s", got)
	}
	var amt string
	if err := s.pool.QueryRow(s.ctx, `SELECT COALESCE(SUM(e.amount),0)::text FROM ledger_entries e WHERE e.account_id=$1`, "suspense:"+s.chain+":BTC").Scan(&amt); err != nil || amt != "5000" {
		t.Fatalf("suspense holds %s sats (%v)", amt, err)
	}
}

// A coinbase output to a deposit address is credited only after 100 confirmations.
func TestCoinbaseOutputWaitsForMaturity(t *testing.T) {
	s := newSystem(t, opts{})
	addr := s.newCustomer("c1")
	s.node.mine(1, addr) // the block reward of this block is the deposit
	h := s.node.height()
	s.node.mine(97, "") // tip h+97: 98 confirmations
	s.holds(4*time.Second, "an immature coinbase is not credited", func() bool { return s.available("c1").Sign() == 0 })
	s.node.mine(1, "") // 99
	s.holds(3*time.Second, "still immature at 99", func() bool { return s.available("c1").Sign() == 0 })
	s.node.mine(1, "") // 100: spendable
	if h2 := s.node.height(); h2 != h+99 {
		t.Fatalf("height %d, want %d", h2, h+99)
	}
	var got int64
	s.waitFor(60*time.Second, "the matured coinbase is credited", func() bool { got = s.available("c1").Int64(); return got > 0 })
	if want := s.node.coinbaseTo(h, addr); got != want {
		t.Fatalf("credited %d sats, the block reward paid %d", got, want)
	}
	if n := s.count(`SELECT count(*) FROM deposits WHERE chain=$1`, s.chain); n != 1 {
		t.Fatalf("%d deposits", n)
	}
}

// A key of another network in the config refuses to start: the process exits with a message.
func TestWrongNetworkConfigRefusesToStart(t *testing.T) {
	s := newSystem(t, opts{})
	mainnetXpub := accountXpub(t, s.mpc, "mainnet") // a key that belongs to mainnet
	bad := s.cf
	b := *bad.Chain.BTC
	b.AccountXpub = mainnetXpub // network stays regtest
	bad.Chain.BTC = &b
	path := filepath.Join(s.dir, "bad.json")
	old := s.cfgPath
	s.cfgPath = path
	s.writeConfig(bad)
	s.cfgPath = old
	for _, bin := range []string{"qv-core", "qv-worker"} {
		out, err := exec.Command(filepath.Join(binDir, bin), "-config", path, "-dsn", s.bizDSN).CombinedOutput()
		if err == nil || !strings.Contains(string(out), "another network") {
			t.Fatalf("%s with a mainnet key on regtest: err %v, output %s", bin, err, out)
		}
	}
}
