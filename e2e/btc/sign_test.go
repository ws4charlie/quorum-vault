package btce2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/google/uuid"

	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
	"github.com/ws4charlie/quorum-vault/internal/gateway"
	"github.com/ws4charlie/quorum-vault/internal/gateway/gatewaytest"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// Correct two-input transactions, a withdrawal under the hot shard's key and a sweep under a deposit address's key, go through the gateway and party B's cosigner on real
// mpc-party, and the two signatures validate against the transaction with bitcoin's script interpreter (txscript), with the standard
// verification flags (witness program, low S, strict DER).
func TestTwoInputTransactionsSignOnMPCAndValidate(t *testing.T) {
	requireBTC(t)
	ctx := context.Background()
	dir := t.TempDir()
	mpc := newMPC(t, dir)
	xpub := accountXpub(t, mpc, "regtest")
	acct, err := btc.NewAccount("regtest", xpub)
	if err != nil {
		t.Fatal(err)
	}
	hot0, _ := acct.Address([]uint32{1, 0})
	hot1, _ := acct.Address([]uint32{1, 1})
	chainName := "btc-" + uuid.NewString()[:8]
	part := "qv-us/" + chainName + "/BTC/hot/omnibus/0"
	dest, _ := acct.Address([]uint32{0, 77}) // any regtest address will do as a destination

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	crt, key := mpc.CertGW.Write(t, mpc.Dir)
	gf := gateway.File{
		Approvers: map[string]gateway.ApproverFile{"alice": {PublicKey: hex.EncodeToString(pub), Enabled: true}},
		Signers: map[string]gateway.SignerFile{part: {Backend: "mpc", KeysetID: mpc.KeysetID, HardenedPath: btc.AccountPath("regtest"),
			MPC: &gateway.MPCSignerFile{Address: mpc.CallerA, CertFile: crt, KeyFile: key, ServerPin: mpc.CertA.Pin}}},
		SignTimeout: "20s",
		Chains: map[string]gateway.ChainFile{chainName: {Family: "btc", WithdrawalsPerHour: 100, SweepsPerHour: 100, CancelsPerHour: 100,
			BTC: &gateway.BTCFile{Network: "regtest", AccountXpub: xpub, MaxTxFeeSats: 50_000, MaxFeeRate: 1000, MaxInputs: 4,
				HotShards: map[string]gateway.HotShardFile{part: {Address: hot0, Path: []uint32{1, 0}}, "qv-us/" + chainName + "/BTC/hot/segregated:beta/0": {Address: hot1, Path: []uint32{1, 1}}}},
			Assets: map[string]gateway.AssetFile{"BTC": {AnyDestination: true, PerTxCap: "100000000", DailyCap: "1000000000", Tiers: []gateway.TierFile{{MinAmount: "0", Approvals: 1}}}}}},
	}
	gwPath := filepath.Join(dir, "gateway.json")
	cosPath := filepath.Join(dir, "cosigner.json")
	write := func(path string, f gateway.File) {
		b, _ := json.MarshalIndent(f, "", " ")
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(gwPath, gf)
	cf := gf
	cf.Signers = nil
	write(cosPath, cf)
	gwPool, gwDSN := gatewaytest.NewGuardDB(t)
	_, cosDSN := gatewaytest.NewGuardDB(t)
	mpc.StartCosigner(cosPath, cosDSN, gwDSN)

	cfg, err := gateway.LoadConfig(gwPath)
	if err != nil {
		t.Fatal(err)
	}
	signers, closeSigners, err := gateway.MPCSigners(cfg)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := gateway.OpenGuard(ctx, gwPool)
	if err != nil {
		t.Fatal(err)
	}
	biz := dbtest.New(t)
	gw, err := gateway.New(cfg, nil, signers, guard, biz, gateway.Options{WorkerID: "gw-btc", Lease: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { gw.Wait(10 * time.Second); closeSigners() })
	for _, q := range []string{
		`INSERT INTO assets (chain, symbol, decimals) VALUES ('` + chainName + `','BTC',8)`,
		`INSERT INTO partitions (id, entity, chain, asset, tier, pool, shard) VALUES ('` + part + `','qv-us','` + chainName + `','BTC','hot','omnibus',0)`,
	} {
		if _, err := biz.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}

	// Two transactions, under two different MPC-derived keys, each with two inputs: a withdrawal from the partition's own hot shard
	// (key 1/0) and a sweep of a deposit address (key 0/7) into that shard. Every input is one sign job.
	dep, _ := acct.Address([]uint32{0, 7})
	mkTxid := func(n int) string {
		var h [32]byte
		h[0], h[31] = byte(n), 0xDD
		return hex.EncodeToString(h[:])
	}
	type attempt struct {
		name    string
		payload btc.Payload
		intent  signjob.Intent
	}
	attempts := []attempt{
		{"withdrawal", btc.Payload{Version: 2,
			Inputs:  []btc.PayloadInput{{TxID: mkTxid(1), Value: 150_000, Path: []uint32{1, 0}, Sequence: btc.SequenceRBF}, {TxID: mkTxid(2), Value: 150_000, Path: []uint32{1, 0}, Sequence: btc.SequenceRBF}},
			Outputs: []btc.PayloadOutput{{Address: dest, Value: 100_000}, {Address: hot0, Value: 180_000}}},
			signjob.Intent{Kind: "withdrawal", ID: "w-btc", PartitionID: part, Chain: chainName, Asset: "BTC", To: dest, Amount: "100000", NotAfter: time.Now().Add(time.Hour).Unix()}},
		{"sweep", btc.Payload{Version: 2,
			Inputs:  []btc.PayloadInput{{TxID: mkTxid(3), Value: 60_000, Path: []uint32{0, 7}, Sequence: btc.SequenceRBF}, {TxID: mkTxid(4), Vout: 1, Value: 40_000, Path: []uint32{0, 7}, Sequence: btc.SequenceRBF}},
			Outputs: []btc.PayloadOutput{{Address: hot0, Value: 99_000}}},
			signjob.Intent{Kind: "sweep", ID: "s-btc", PartitionID: part, Chain: chainName, Asset: "BTC", From: dep, To: hot0, Amount: "100000"}},
	}
	for _, at := range attempts {
		p := at.payload
		built, err := btc.BuildUnsigned(p, acct)
		if err != nil {
			t.Fatal(err)
		}
		h := at.intent.Hash()
		raw, _ := json.Marshal(p)
		base := "id:" + at.name + ":a1"
		var ids []string
		for i := range p.Inputs {
			id := base
			if i > 0 {
				id = fmt.Sprintf("%s.%d", base, i)
			}
			ids = append(ids, id)
			j := signjob.Job{ID: id, PartitionID: part, KeyRef: btc.PathString(p.Inputs[i].Path), Chain: chainName, Intent: mustJSON(at.intent), Digest: built.Digests[i], Payload: raw}
			if at.intent.Kind == "withdrawal" {
				j.Approvals = []signjob.Approval{{Actor: "alice", Signature: ed25519.Sign(priv, h[:])}}
			}
			tx, err := biz.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := signjob.Enqueue(ctx, tx, j); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
		}
		for range ids {
			d, ok, err := gw.RunOnce(ctx)
			if err != nil || !ok || d.Outcome != gateway.OutcomeSigned {
				t.Fatalf("%s: gateway: %+v ok=%v err=%v\nA: %s\nB: %s\ncosigner: %s", at.name, d, ok, err, mpc.A.Output(), mpc.B.Output(), mpc.Cos.Output())
			}
		}
		// Assemble the witnesses and run the script interpreter on every input.
		tx := built.Tx
		for i, id := range ids {
			j, err := signjob.Get(ctx, biz, id)
			if err != nil || j.Status != signjob.StatusDone || len(j.Signature) != 64 {
				t.Fatalf("job %s: %+v %v", id, j, err)
			}
			der, err := asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(j.Signature[:32]), new(big.Int).SetBytes(j.Signature[32:])})
			if err != nil {
				t.Fatal(err)
			}
			tx.TxIn[i].Witness = wire.TxWitness{append(der, byte(txscript.SigHashAll)), built.Pubs[i]}
		}
		fetch := map[wire.OutPoint]*wire.TxOut{}
		for i, in := range tx.TxIn {
			fetch[in.PreviousOutPoint] = wire.NewTxOut(int64(p.Inputs[i].Value), built.Scripts[i])
		}
		pf := txscript.NewMultiPrevOutFetcher(fetch)
		hashes := txscript.NewTxSigHashes(tx, pf)
		for i := range tx.TxIn {
			vm, err := txscript.NewEngine(built.Scripts[i], tx, i, txscript.StandardVerifyFlags, nil, hashes, int64(p.Inputs[i].Value), pf)
			if err != nil {
				t.Fatal(err)
			}
			if err := vm.Execute(); err != nil {
				t.Fatalf("%s: input %d does not validate: %v", at.name, i, err)
			}
		}
		t.Logf("%s %s: 2 inputs under key %s validate with txscript", at.name, built.TxID, btc.PathString(p.Inputs[0].Path))
		// The signatures are not interchangeable between inputs of different transactions or outpoints.
		tx.TxIn[1].Witness[0] = tx.TxIn[0].Witness[0]
		vm, _ := txscript.NewEngine(built.Scripts[1], tx, 1, txscript.StandardVerifyFlags, nil, hashes, int64(p.Inputs[1].Value), pf)
		if err := vm.Execute(); err == nil {
			t.Fatalf("%s: a signature for input 0 validated input 1", at.name)
		}
	}
}
