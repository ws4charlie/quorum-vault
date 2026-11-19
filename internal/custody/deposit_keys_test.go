package custody

import (
	"bytes"
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
	"github.com/ws4charlie/quorum-vault/internal/partition"
)

// genChain derives addresses per generation, like the Bitcoin and Solana cells do.
type genChain struct{ indexChain }

func (genChain) DeriveDepositAddressAt(_ context.Context, k chain.DepositKey, _ string, i uint64) (chain.DepositAddress, error) {
	return chain.DepositAddress{Chain: testChain, Address: "g" + strconv.Itoa(k.Generation) + "-" + k.Identity + "-" + strconv.Itoa(int(i)), Kind: chain.KindXpub, DerivationIndex: i}, nil
}

func (s *Service) inTree(t *testing.T, f func(tx pgx.Tx, id partition.ShardID) error) {
	t.Helper()
	id, err := s.Cfg.depositTreeID()
	if err != nil {
		t.Fatal(err)
	}
	if err := InTx(context.Background(), s.Pool, func(tx pgx.Tx) error { return f(tx, id) }); err != nil {
		t.Fatal(err)
	}
}

// One address per customer per generation: "my address" is the active generation's, made on first use; the answer lists the older addresses that are still
// watched; a retired generation's address is no longer listed. Indexes are never reused across generations.
func TestDepositAddressOfTheActiveGenerationAndTheOlderOnes(t *testing.T) {
	ctx := context.Background()
	s, fc := newSvc(t)
	s.Chain = genChain{indexChain{fc}}
	s.Cfg.Family = FamilyBTC
	for _, c := range []string{"a", "b"} {
		if _, _, err := s.CreateCustomer(ctx, "ops", c, ""); err != nil {
			t.Fatal(err)
		}
	}
	s.inTree(t, func(tx pgx.Tx, id partition.ShardID) error {
		_, err := partition.RegisterInitial(ctx, tx, "t", id, "K1", "", nil)
		if err == nil {
			_, err = partition.RegisterCandidate(ctx, tx, "t", id, "K2", "", nil)
		}
		return err
	})
	a1, err := s.EnsureDepositAddress(ctx, "ops", "a", testChain)
	if err != nil || a1.Generation != 1 || a1.Address != "g1-K1-0" || len(a1.Older) != 0 {
		t.Fatalf("generation 1: %+v %v", a1, err)
	}
	// the key is replaced: generation 1 drains, generation 2 is active
	s.inTree(t, func(tx pgx.Tx, id partition.ShardID) error {
		if _, err := partition.StartDraining(ctx, tx, "t", id, 1); err != nil {
			return err
		}
		_, err := partition.Activate(ctx, tx, "t", id, 2)
		return err
	})
	b2, err := s.EnsureDepositAddress(ctx, "ops", "b", testChain)
	if err != nil || b2.Generation != 2 || b2.Address != "g2-K2-1" || len(b2.Older) != 0 {
		t.Fatalf("a new customer: %+v %v", b2, err)
	}
	a2, err := s.EnsureDepositAddress(ctx, "ops", "a", testChain)
	if err != nil || a2.Generation != 2 || a2.Address != "g2-K2-2" || len(a2.Older) != 1 || a2.Older[0].Address != a1.Address || a2.Older[0].Generation != 1 {
		t.Fatalf("an old customer asking again: %+v %v", a2, err)
	}
	again, err := s.EnsureDepositAddress(ctx, "ops", "a", testChain)
	if err != nil || again.Address != a2.Address || len(again.Older) != 1 {
		t.Fatalf("asking twice: %+v %v", again, err)
	}
	var n int
	s.Pool.QueryRow(ctx, `SELECT count(*) FROM deposit_addresses WHERE customer_id='a' AND chain=$1`, testChain).Scan(&n)
	if n != 2 {
		t.Fatalf("customer a has %d addresses", n)
	}
	// a deposit to the old address is credited to its customer
	var who string
	if err := s.Pool.QueryRow(ctx, `SELECT customer_id FROM deposit_addresses d WHERE d.chain=$1 AND d.address=$2 AND `+partition.WatchedSQL, testChain, a1.Address).Scan(&who); err != nil || who != "a" {
		t.Fatalf("the old address is not watched: %q %v", who, err)
	}
	// after the window: generation 1 retires and leaves the list
	s.inTree(t, func(tx pgx.Tx, id partition.ShardID) error {
		_, err := partition.Retire(ctx, tx, "t", id, 1)
		return err
	})
	last, err := s.EnsureDepositAddress(ctx, "ops", "a", testChain)
	if err != nil || last.Address != a2.Address || len(last.Older) != 0 {
		t.Fatalf("after retiring: %+v %v", last, err)
	}
}

// Without a registry row for the tree (a tool that never bootstrapped) the customer gets generation 1, as before.
func TestDepositAddressWithoutARegisteredTreeIsGenerationOne(t *testing.T) {
	ctx := context.Background()
	s, fc := newSvc(t)
	s.Chain = indexChain{fc}
	s.Cfg.Family = FamilyBTC
	s.CreateCustomer(ctx, "ops", "a", "")
	d, err := s.EnsureDepositAddress(ctx, "ops", "a", testChain)
	if err != nil || d.Generation != 1 || d.Address != "addr-0" {
		t.Fatalf("%+v %v", d, err)
	}
}

// Bootstrap registers generation 1 of the deposit tree from the configured key, once; another key under the same generation refuses the start.
func TestLoadDepositTreeRegistersGenerationOneAndRefusesAnotherKey(t *testing.T) {
	ctx := context.Background()
	s, _ := newSvc(t)
	if err := s.loadDepositTree(ctx); err != nil { // EVM: no key, nothing registered
		t.Fatal(err)
	}
	var n int
	s.Pool.QueryRow(ctx, `SELECT count(*) FROM keysets WHERE shard_id LIKE '%/deposit-tree/0'`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d deposit tree rows on EVM", n)
	}
	xpub := func(seed byte) string {
		m, _ := hdkeychain.NewMaster(bytes.Repeat([]byte{seed}, 32), &chaincfg.RegressionNetParams)
		p, _ := m.Neuter()
		return p.String()
	}
	s.Cfg.Family = FamilyBTC
	s.Cfg.BTC = btc.Config{Network: "regtest", AccountXpub: xpub(3)}
	for i := 0; i < 2; i++ { // idempotent
		if err := s.loadDepositTree(ctx); err != nil {
			t.Fatal(err)
		}
	}
	var gen int
	var state, addr string
	var pub []byte
	if err := s.Pool.QueryRow(ctx, `SELECT generation, state, address, public_key FROM keysets WHERE shard_id LIKE '%/' || $1 || '/deposit-tree/0'`, testChain).Scan(&gen, &state, &addr, &pub); err != nil {
		t.Fatal(err)
	}
	if gen != 1 || state != "active" || addr != s.Cfg.BTC.AccountXpub || len(pub) != 33 {
		t.Fatalf("registered %d %s %s %d bytes", gen, state, addr, len(pub))
	}
	s.Cfg.BTC = btc.Config{Network: "regtest", AccountXpub: xpub(4)}
	if err := s.loadDepositTree(ctx); err == nil || !strings.Contains(err.Error(), "another address") {
		t.Fatalf("another key under generation 1: %v", err)
	}
}
