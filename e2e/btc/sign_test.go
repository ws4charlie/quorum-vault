package btce2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
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

// A correct two-input transaction, each input under its own MPC-derived key, goes through the gateway and party B's cosigner on real
// mpc-party, and the two signatures validate against the transaction with bitcoin's script interpreter (txscript), with the standard
// verification flags (witness program, low S, strict DER).
func TestTwoInputTransactionSignsOnMPCAndValidates(t *testing.T) {
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
				HotShards: map[string]gateway.HotShardFile{part: {Address: hot0, Path: []uint32{1, 0}}, "p1": {Address: hot1, Path: []uint32{1, 1}}}},
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

	// Two hot inputs under two keys: 150_000 sats each; 100_000 to dest and 180_000 change (fee 20_000).
	var txid [2]string
	for i := range txid {
		var h [32]byte
		h[0], h[31] = byte(i+1), 0xDD
		txid[i] = hex.EncodeToString(h[:])
	}
	p := btc.Payload{Version: 2,
		Inputs:  []btc.PayloadInput{{TxID: txid[0], Value: 150_000, Path: []uint32{1, 0}, Sequence: btc.SequenceRBF}, {TxID: txid[1], Value: 150_000, Path: []uint32{1, 1}, Sequence: btc.SequenceRBF}},
		Outputs: []btc.PayloadOutput{{Address: dest, Value: 100_000}, {Address: hot0, Value: 180_000}}}
	built, err := btc.BuildUnsigned(p, acct)
	if err != nil {
		t.Fatal(err)
	}
	in := signjob.Intent{Kind: "withdrawal", ID: "w-btc", PartitionID: part, Chain: chainName, Asset: "BTC", To: dest, Amount: "100000", NotAfter: time.Now().Add(time.Hour).Unix()}
	h := in.Hash()
	raw, _ := json.Marshal(p)
	ids := []string{"wd:w-btc:a1", "wd:w-btc:a1.1"}
	for i := range p.Inputs {
		j := signjob.Job{ID: ids[i], PartitionID: part, KeyRef: btc.PathString(p.Inputs[i].Path), Chain: chainName, Intent: mustJSON(in), Digest: built.Digests[i], Payload: raw,
			Approvals: []signjob.Approval{{Actor: "alice", Signature: ed25519.Sign(priv, h[:])}}}
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
			t.Fatalf("gateway: %+v ok=%v err=%v\nA: %s\nB: %s\ncosigner: %s", d, ok, err, mpc.A.Output(), mpc.B.Output(), mpc.Cos.Output())
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
			t.Fatalf("input %d does not validate: %v", i, err)
		}
	}
	t.Logf("a 2-input transaction %s signed under two MPC-derived keys validates with txscript", built.TxID)

	// The two signatures are not interchangeable: input 0's signature does not validate input 1.
	tx.TxIn[1].Witness[0], tx.TxIn[0].Witness[0] = tx.TxIn[0].Witness[0], tx.TxIn[1].Witness[0]
	vm, _ := txscript.NewEngine(built.Scripts[1], tx, 1, txscript.StandardVerifyFlags, nil, hashes, int64(p.Inputs[1].Value), pf)
	if err := vm.Execute(); err == nil {
		t.Fatal("a signature for input 0 validated input 1")
	}
}
