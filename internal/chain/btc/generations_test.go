package btc

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/partition"
)

// secondXpub is the account xpub of another key (the deposit key of generation 2 in these tests).
func secondXpub(t *testing.T) string {
	t.Helper()
	m, _ := hdkeychain.NewMaster(bytes.Repeat([]byte{8}, 32), &chaincfg.RegressionNetParams)
	k := m
	for _, n := range []uint32{hdkeychain.HardenedKeyStart + 84, hdkeychain.HardenedKeyStart + 1, hdkeychain.HardenedKeyStart} {
		k, _ = k.Derive(n)
	}
	x, _ := k.Neuter()
	return x.String()
}

// Generation 1 is the configured key: every address is what the configured account gives, whichever way it is asked for, and a later generation is another set.
func TestGenerationOneDerivesTodaysAddresses(t *testing.T) {
	xpub := XpubFromNodeForTest(t)
	v, err := Config{Chain: "btc", Network: "regtest", AccountXpub: xpub}.validated()
	if err != nil {
		t.Fatal(err)
	}
	a := &Adapter{cfg: v}
	id, pub, err := DepositIdentity("regtest", xpub)
	if err != nil || id != xpub || len(pub) != 33 {
		t.Fatalf("identity %q %d bytes %v", id, len(pub), err)
	}
	x2 := secondXpub(t)
	for i := uint64(0); i < 25; i++ {
		want, err := DeriveAddress("regtest", xpub, uint32(i))
		if err != nil {
			t.Fatal(err)
		}
		d0, err := a.DeriveDepositAddress(context.Background(), "c", i)
		if err != nil {
			t.Fatal(err)
		}
		d1, err := a.DeriveDepositAddressAt(context.Background(), chain.DepositKey{Generation: 1, Identity: id}, "c", i)
		if err != nil {
			t.Fatal(err)
		}
		d2, err := a.DeriveDepositAddressAt(context.Background(), chain.DepositKey{Generation: 2, Identity: x2}, "c", i)
		if err != nil {
			t.Fatal(err)
		}
		if d0.Address != want || d1.Address != want || d1.Kind != chain.KindXpub || d1.DerivationIndex != i {
			t.Fatalf("index %d: configured %s, generation 1 %s, want %s", i, d0.Address, d1.Address, want)
		}
		if d2.Address == want || !strings.HasPrefix(d2.Address, "bcrt1") {
			t.Fatalf("index %d: generation 2 gave %s", i, d2.Address)
		}
	}
}

// A generation above 1 that the account does not know is an error, never generation 1's key.
func TestAccountRefusesAnUnknownGeneration(t *testing.T) {
	acct, err := NewAccount("regtest", XpubFromNodeForTest(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acct.PubAt(2, []uint32{BranchDeposit, 0}); err == nil {
		t.Fatal("generation 2 resolved without a key")
	}
	if a0, _ := acct.PubAt(0, []uint32{BranchDeposit, 3}); !bytes.Equal(a0, mustPub(t, acct, 3)) {
		t.Fatal("generation 0 is not generation 1")
	}
}

func mustPub(t *testing.T, a *Account, i uint32) []byte {
	t.Helper()
	p, err := a.Pub([]uint32{BranchDeposit, i})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// registerTree writes the two generations of the deposit tree into the registry: generation 1 active, generation 2 a candidate.
func (e *wEnv) registerTree(x2 string) {
	e.t.Helper()
	ctx := context.Background()
	id, _ := partition.DepositTreeID("qv-us", "btc-t")
	tx, err := e.a.pool.Begin(ctx)
	if err != nil {
		e.t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := partition.RegisterInitial(ctx, tx, "t", id, e.cfg.AccountXpub, "", nil); err != nil {
		e.t.Fatal(err)
	}
	if _, err := partition.RegisterCandidate(ctx, tx, "t", id, x2, "", nil); err != nil {
		e.t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		e.t.Fatal(err)
	}
}

func (e *wEnv) setTree(f func(ctx context.Context, tx pgx.Tx, id partition.ShardID) error) {
	e.t.Helper()
	ctx := context.Background()
	id, _ := partition.DepositTreeID("qv-us", "btc-t")
	tx, _ := e.a.pool.Begin(ctx)
	defer tx.Rollback(ctx)
	if err := f(ctx, tx, id); err != nil {
		e.t.Fatal(err)
	}
	tx.Commit(ctx)
}

// A deposit to a generation-2 address is recorded under that generation's key path; the sweep of it names generation 2's key, builds the transaction from
// generation 2's account key, and says it moved the address's money. A generation-1 address of the same customer sweeps as ever.
func TestSweepOfASecondGenerationAddressNamesItsKey(t *testing.T) {
	e := newWEnv(t)
	ctx := context.Background()
	x2 := secondXpub(t)
	e.registerTree(x2)
	e.setTree(func(ctx context.Context, tx pgx.Tx, id partition.ShardID) error {
		if _, err := partition.StartDraining(ctx, tx, "t", id, 1); err != nil {
			return err
		}
		_, err := partition.Activate(ctx, tx, "t", id, 2)
		return err
	})
	old := e.depositAddr(1) // generation 1 (the column's default)
	d2, err := e.a.DeriveDepositAddressAt(ctx, chain.DepositKey{Generation: 2, Identity: x2}, "cs1", 6)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.a.pool.Exec(ctx, `INSERT INTO deposit_addresses (customer_id, chain, address, derivation_index, kind, generation) VALUES ('cs1','btc-t',$1,6,'xpub',2)`, d2.Address); err != nil {
		t.Fatal(err)
	}
	// the same customer holds one address per generation, not two of one
	if _, err := e.a.pool.Exec(ctx, `INSERT INTO deposit_addresses (customer_id, chain, address, derivation_index, kind, generation) VALUES ('cs1','btc-t','dup',7,'xpub',2)`); err == nil {
		t.Fatal("a second address of the same customer in generation 2 was accepted")
	}
	e.recordDeposit(old, 400_000)
	e.recordDeposit(d2.Address, 600_000)
	var path string
	if err := e.a.pool.QueryRow(ctx, `SELECT path FROM btc_utxos WHERE chain='btc-t' AND address=$1`, d2.Address).Scan(&path); err != nil || path != "g2/0/6" {
		t.Fatalf("stored path %q %v", path, err)
	}
	u1, err := e.buildSweep("s-old", old, 400_000)
	if err != nil {
		t.Fatal(err)
	}
	if u1.KeyRef.Path != "0/1" || e.payload(u1).Inputs[0].Gen != 0 {
		t.Fatalf("generation 1 sweep: key %q gen %d", u1.KeyRef.Path, e.payload(u1).Inputs[0].Gen)
	}
	u2, err := e.buildSweep("s-new", d2.Address, 600_000)
	if err != nil {
		t.Fatal(err)
	}
	p := e.payload(u2)
	if u2.KeyRef.Path != "g2/0/6" || len(p.Inputs) != 1 || p.Inputs[0].Gen != 2 || PathString(p.Inputs[0].Path) != "0/6" {
		t.Fatalf("generation 2 sweep: key %q inputs %+v", u2.KeyRef.Path, p.Inputs)
	}
	// the digest is over generation 2's script: the account finds the key through the registry
	built, err := BuildUnsigned(p, e.a.acct)
	if err != nil {
		t.Fatal(err)
	}
	acct2, _ := NewAccount("regtest", x2)
	want, _ := acct2.Address([]uint32{0, 6})
	if got, err := e.a.acct.AddressAt(2, []uint32{0, 6}); err != nil || got != want || got != d2.Address {
		t.Fatalf("account address of generation 2 %s %v, want %s", got, err, want)
	}
	moved, err := e.a.MovedAssets(ctx, built.TxID)
	if err != nil || len(moved) != 1 || moved[0].Address != d2.Address || moved[0].Amount.Int64() != 600_000 {
		t.Fatalf("moved %v %v", moved, err)
	}
	// a payload of generation 2 under the configured-key-only account (the signing zone today) cannot be built: it fails closed
	zone, _ := NewAccount("regtest", e.cfg.AccountXpub)
	if _, err := BuildUnsigned(p, zone); err == nil {
		t.Fatal("an account without generation 2 built a generation 2 transaction")
	}
}

// The watch list is every generation that is not retired: a retired generation's addresses leave it.
func TestWatchedSQLKeepsEveryGenerationButRetired(t *testing.T) {
	e := newWEnv(t)
	ctx := context.Background()
	x2 := secondXpub(t)
	e.registerTree(x2)
	a1 := e.depositAddr(1)
	d2, _ := e.a.DeriveDepositAddressAt(ctx, chain.DepositKey{Generation: 2, Identity: x2}, "cs1", 6)
	e.a.pool.Exec(ctx, `INSERT INTO deposit_addresses (customer_id, chain, address, derivation_index, kind, generation) VALUES ('cs1','btc-t',$1,6,'xpub',2)`, d2.Address)
	watched := func() map[string]bool {
		rows, err := e.a.pool.Query(ctx, `SELECT d.address FROM deposit_addresses d WHERE d.chain='btc-t' AND `+partition.WatchedSQL)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		m := map[string]bool{}
		for rows.Next() {
			var s string
			rows.Scan(&s)
			m[s] = true
		}
		return m
	}
	if w := watched(); !w[a1] || !w[d2.Address] { // generation 2 is still a candidate: its addresses are watched too
		t.Fatalf("watched %v", w)
	}
	e.setTree(func(ctx context.Context, tx pgx.Tx, id partition.ShardID) error {
		if _, err := partition.StartDraining(ctx, tx, "t", id, 1); err != nil {
			return err
		}
		if _, err := partition.Activate(ctx, tx, "t", id, 2); err != nil {
			return err
		}
		return nil
	})
	if w := watched(); !w[a1] || !w[d2.Address] {
		t.Fatalf("draining generation dropped from the watch list: %v", w)
	}
	e.setTree(func(ctx context.Context, tx pgx.Tx, id partition.ShardID) error {
		_, err := partition.Retire(ctx, tx, "t", id, 1)
		return err
	})
	if w := watched(); w[a1] || !w[d2.Address] {
		t.Fatalf("after retiring generation 1: %v", w)
	}
	_ = fmt.Sprint
}
