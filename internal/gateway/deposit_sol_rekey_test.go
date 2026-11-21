package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/chain/sol"
	"github.com/ws4charlie/quorum-vault/internal/partition"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

func solEntry(gen int, state string) *KeysetEntry {
	return &KeysetEntry{Generation: gen, State: state}
}

// A Solana sweep may spend the deposit keys of generations that are active, draining or compromised; a candidate or a retired one signs nothing.
func TestSolDepositGenerationStates(t *testing.T) {
	cc := &ChainConfig{Name: "sol-t", Family: FamilySOL}
	v := &KeysetView{gens: map[partition.ShardID]map[int]*KeysetEntry{}}
	id := partition.ShardID("qv-us/sol-t/deposit-tree/0")
	e1 := solEntry(1, partition.StateActive)
	e1.Chain = "sol-t"
	v.gens[id] = map[int]*KeysetEntry{1: e1, 2: solEntry(2, partition.StateCandidate)}
	d := &Decider{}
		ok := func(gens ...uint32) error { return d.solDepositRules(v, cc, TxInfo{DepositGens: gens}) }
	if err := ok(); err != nil {
		t.Fatal("generation 1 alone:", err)
	}
	if err := ok(2); err == nil || !strings.Contains(err.Error(), "candidate") {
		t.Fatalf("candidate: %v", err)
	}
	for st, want := range map[string]bool{partition.StateActive: true, partition.StateDraining: true, partition.StateCompromised: true, partition.StateRetired: false} {
		v.gens[id][2].State = st
		if err := ok(1, 2); (err == nil) != want {
			t.Fatalf("state %s: %v", st, err)
		}
	}
	if err := ok(3); err == nil {
		t.Fatal("an unknown generation")
	}
	if err := d.solGenRules(context.Background(), nil, v, cc, signjob.Intent{Kind: "withdrawal"}, TxInfo{}, nil, false, time.Now()); err != nil {
		t.Fatal("withdrawals are not judged by the deposit tree:", err)
	}
}

// The identity of a Solana deposit tree record is checked; the verifier derives under the generations it is given and refuses others.
func TestSolDepositNodeIdentityAndVerifier(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	cc := make([]byte, 32)
	rand.Read(cc)
	id := hex.EncodeToString(pub) + ":" + hex.EncodeToString(cc)
	n, err := ParseSolNode(id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseSolNode("zz"); err == nil {
		t.Fatal("bad identity")
	}
	if _, err := n.Derive(sol.BranchExternal, 0); err != nil {
		t.Fatal(err)
	}
	if _, g, i, err := sol.ParseKeyRef("g2/d/7"); err != nil || g != 2 || i != 7 {
		t.Fatalf("%d %d %v", g, i, err)
	}
	for _, bad := range []string{"g1/d/7", "g2/", "g2", "g0/d/1"} {
		if _, _, _, err := sol.ParseKeyRef(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}
