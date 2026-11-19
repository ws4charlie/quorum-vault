package evm

import (
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/e2e"
	"github.com/ws4charlie/quorum-vault/internal/chain"
)

// With two generations of a shard, new work is built from the active one, work already built keeps its address, and a replacement or a cancel is
// signed by the generation that signed the original.
func TestTwoGenerationsOfAShard(t *testing.T) {
	e := newEnv(t)
	const part, shard = "qv-us/evm-anvil/ETH/hot/omnibus/0", "qv-us/evm-anvil/omnibus/0"
	key2, _ := crypto.GenerateKey()
	gen2 := crypto.PubkeyToAddress(key2.PublicKey)
	if err := e2e.SetBalance(e.ctx, e.url, gen2, new(big.Int).Mul(big.NewInt(100), ether)); err != nil {
		t.Fatal(err)
	}
	cfg := e.cfg
	cfg.HotAddresses = map[string]common.Address{part: e.hot}
	ad, err := New(e.ctx, cfg, e.pool)
	if err != nil {
		t.Fatal(err)
	}
	defer ad.Close()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := e.pool.Exec(e.ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	// No registry rows at all: the configured address (tools and tests that never register a shard).
	build := func(id string) (chain.UnsignedTx, common.Address) {
		t.Helper()
		var u chain.UnsignedTx
		err := e.runTx(func(tx pgx.Tx) (err error) {
			u, err = ad.BuildWithdrawal(e.ctx, tx, chain.WithdrawalIntent{ID: id, PartitionID: part, Asset: "ETH", To: e.dest.Hex(), Amount: big.NewInt(1)})
			return err
		})
		if err != nil {
			t.Fatalf("build %s: %v", id, err)
		}
		pl, err := decodePayload(u.Payload)
		if err != nil {
			t.Fatal(err)
		}
		_, _, from, err := pl.tx()
		if err != nil {
			t.Fatal(err)
		}
		return u, from
	}
	if _, from := build("w0"); from != e.hot {
		t.Fatalf("without a registry the sender is the configured address: %s", from)
	}
	exec(`INSERT INTO keysets (shard_id, generation, address, state) VALUES ($1, 1, $2, 'active')`, shard, e.hot.Hex())
	exec(`INSERT INTO keysets (shard_id, generation, address, state) VALUES ($1, 2, $2, 'candidate')`, shard, gen2.Hex())
	if _, from := build("w1"); from != e.hot {
		t.Fatalf("with a candidate beside it the active generation still sends: %s", from)
	}

	// Generation 1 starts draining: between that and the activation the shard has no sender and the build says why, as a wait.
	exec(`UPDATE keysets SET state='draining' WHERE shard_id=$1 AND generation=1`, shard)
	err = e.runTx(func(tx pgx.Tx) error {
		_, err := ad.BuildWithdrawal(e.ctx, tx, chain.WithdrawalIntent{ID: "w2", PartitionID: part, Asset: "ETH", To: e.dest.Hex(), Amount: big.NewInt(1)})
		return err
	})
	if !errors.Is(err, ErrNoActiveKeyset) || !errors.Is(err, chain.ErrNotEnoughOutputs) {
		t.Fatalf("no active generation: %v", err)
	}
	exec(`UPDATE keysets SET state='active' WHERE shard_id=$1 AND generation=2`, shard)
	u2, from := build("w2")
	if from != gen2 {
		t.Fatalf("new work is built from the active generation 2, got %s", from)
	}
	if u2.KeyRef.PartitionID != part {
		t.Fatalf("key ref %q", u2.KeyRef.PartitionID)
	}
	// Nonces are per address: generation 2 starts at its own count, generation 1's open allocation is untouched.
	var n int
	if err := e.pool.QueryRow(e.ctx, `SELECT count(*) FROM evm_nonce_allocations WHERE lower(address)=lower($1)`, gen2.Hex()).Scan(&n); err != nil || n != 1 {
		t.Fatalf("allocations of generation 2: %d %v", n, err)
	}

	// The cancel of work built from generation 1 (w1) is built from generation 1, though generation 1 is draining: finishing signed work is allowed.
	cu, err := e.cancel(ad, "withdrawal", "w1")
	if err != nil {
		t.Fatal(err)
	}
	pl, _ := decodePayload(cu.Payload)
	if _, _, from, _ := pl.tx(); from != e.hot || cu.KeyRef.PartitionID != part {
		t.Fatalf("cancel of old work: from %s key ref %q", from, cu.KeyRef.PartitionID)
	}
	// And the cancel of work from generation 2, whose address is not in the configuration, still names the shard's partition.
	cu, err = e.cancel(ad, "withdrawal", "w2")
	if err != nil {
		t.Fatal(err)
	}
	pl, _ = decodePayload(cu.Payload)
	if _, _, from, _ := pl.tx(); from != gen2 || cu.KeyRef.PartitionID != part {
		t.Fatalf("cancel of generation 2 work: from %s key ref %q", from, cu.KeyRef.PartitionID)
	}

	// The factory must pay the active address of the sink shard: it pays e.dest, which is not generation 2's address, so sweeps stop with the reason
	// until the factory's destination is set to the new address (the cold ceremony).
	cfg.SweepDestination = e.hot // the configured sink is generation 1 of this shard
	ad2, err := New(e.ctx, cfg, e.pool)
	if err != nil {
		t.Fatal(err)
	}
	defer ad2.Close()
	if d, err := ad2.sweepDestination(e.ctx, e.pool); err != nil || d != gen2 {
		t.Fatalf("sweep destination follows the active generation: %s %v", d, err)
	}
}

func (e *tenv) runTx(fn func(tx pgx.Tx) error) error {
	tx, err := e.pool.Begin(e.ctx)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback(e.ctx)
		return err
	}
	return tx.Commit(e.ctx)
}

func (e *tenv) cancel(ad *Adapter, kind, id string) (u chain.UnsignedTx, err error) {
	err = e.runTx(func(tx pgx.Tx) (err error) {
		u, err = ad.BuildCancel(e.ctx, tx, kind, id)
		return err
	})
	return u, err
}
