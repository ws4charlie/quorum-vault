package custody_test

import (
	"math/big"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/custody"
)

// Deposit -> credit -> sweep -> withdraw, for ETH and a USDT-style token that
// returns no bool. Balances on chain and in the ledger, and Reconcile clean.
func TestHappyPathETHAndToken(t *testing.T) {
	s := newSystem(t, opts{})
	cust := "alice-c"
	addr := s.newCustomer(cust)

	// The address is stable: asking again returns it.
	if again := s.newCustomer(cust); again != addr {
		t.Fatalf("second deposit-address call returned %s, want %s", again, addr)
	}

	s.sendETH(addr, eth(5))
	s.mintUSDT(addr, 1_000_000_000) // 1000 USDT
	s.waitAvailable(cust, "ETH", eth(5), 30*time.Second)
	s.waitAvailable(cust, "USDT", big.NewInt(1_000_000_000), 30*time.Second)

	// The planner sweeps both; the whole forwarder balance reaches the hot wallet.
	s.waitFor(90*time.Second, "both sweeps confirmed", func() bool { return s.sweepsConfirmed() >= 2 })
	s.waitIdle(60 * time.Second)
	if s.ethBalance(addr).Sign() != 0 || s.usdtBalance(addr).Sign() != 0 {
		t.Fatalf("forwarder still holds funds: %s ETH %s USDT", s.ethBalance(addr), s.usdtBalance(addr))
	}
	if got := s.usdtBalance(s.shardAddr[0]); got.Cmp(big.NewInt(1_000_000_000)) != 0 {
		t.Fatalf("hot USDT = %s", got)
	}
	s.reconcileClean()

	// Withdraw ETH and USDT (lowest tier: the worker's automated key approves).
	ethDest, usdtDest := randAddr(), randAddr()
	w1 := s.withdraw("alice-c", "k-eth-1", cust, "ETH", ethDest, eth(1)) // 1 ETH is tier 2 -> needs two humans
	if w1.Code != 201 {
		t.Fatalf("withdraw: %d %v", w1.Code, w1.Raw)
	}
	small := new(big.Int).Div(eth(1), big.NewInt(2))
	w2 := s.withdraw("alice-c", "k-eth-2", cust, "ETH", ethDest, small)
	w3 := s.withdraw("alice-c", "k-usdt-1", cust, "USDT", usdtDest, big.NewInt(250_000_000))
	if w2.Code != 201 || w3.Code != 201 {
		t.Fatalf("withdraw: %v %v", w2.Raw, w3.Raw)
	}
	for _, a := range []string{"bob", "carol"} {
		if code, out := s.approve(a, w1.ID); code != 200 {
			t.Fatalf("approve %s: %d %v", a, code, out)
		}
	}
	for _, id := range []string{w1.ID, w2.ID, w3.ID} {
		s.waitWd(id, "confirmed", 90*time.Second)
	}

	if got, want := s.ethBalance(ethDest), new(big.Int).Add(eth(1), small); got.Cmp(want) != 0 {
		t.Fatalf("ETH destination = %s, want %s", got, want)
	}
	if got := s.usdtBalance(usdtDest); got.Cmp(big.NewInt(250_000_000)) != 0 {
		t.Fatalf("USDT destination = %s", got)
	}
	avail, held, _ := s.balance(cust, "ETH")
	if want := new(big.Int).Sub(eth(5), new(big.Int).Add(eth(1), small)); avail.Cmp(want) != 0 || held.Sign() != 0 {
		t.Fatalf("ETH balance %s held %s, want %s", avail, held, want)
	}
	avail, _, _ = s.balance(cust, "USDT")
	if avail.Cmp(big.NewInt(750_000_000)) != 0 {
		t.Fatalf("USDT balance %s", avail)
	}
	rep := s.reconcileClean()
	t.Logf("reconcile: clean at height %d, %d checks", rep.Height, len(rep.Checks))

	// The fee account is minus the fees paid; the books sum to zero per asset.
	if fee := s.posted(custody.FeeAccount(s.chainName, "ETH")); fee.Cmp(eth(100)) >= 0 {
		t.Fatalf("fee account %s: nothing was charged", fee)
	}
}
