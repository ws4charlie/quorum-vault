// Package gatewaytest builds signing-zone configs, sign jobs and replay-guard databases for tests of the gateway, the
// cosigner and the cb-mpc end-to-end tests. It is the exported twin of the gateway package's own test harness.
package gatewaytest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	neturl "net/url"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ws4charlie/quorum-vault/internal/chain/eth"
	"github.com/ws4charlie/quorum-vault/internal/chain/evm"
	"github.com/ws4charlie/quorum-vault/internal/gateway"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

const (
	Chain     = "evm-test"
	Partition = "p-hot"
	// ColdPartition is a hot partition with a well-formed ID (the to-cold verifier reads the pool from it), on the same hot
	// address as Partition.
	ColdPartition = "qv-us/evm-test/ETH/hot/omnibus/1"
	// Shard2Partition is another shard of the same pool on its own address (a rebalance destination); OtherPoolPartition is a shard
	// of a segregated pool, which a rebalance of the omnibus pool must not reach. Neither has a key: they exist in the config only.
	Shard2Partition    = "qv-us/evm-test/ETH/hot/omnibus/2"
	OtherPoolPartition = "qv-us/evm-test/ETH/hot/segregated:acme/0"
)

var (
	AddrFactory = common.HexToAddress("0x00000000000000000000000000000000000fAc70")
	AddrDest    = common.HexToAddress("0x000000000000000000000000000000000000De57")
	AddrToken   = common.HexToAddress("0x00000000000000000000000000000000000070C3")
	AddrUser    = common.HexToAddress("0x00000000000000000000000000000000000c0DE5")
	AddrEvil    = common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	AddrCold    = common.HexToAddress("0x00000000000000000000000000000000000c01d0") // the configured cold address
	AddrShard2  = common.HexToAddress("0x0000000000000000000000000000000000005a02") // hot address of Shard2Partition
	AddrOtherPl = common.HexToAddress("0x0000000000000000000000000000000000005a03") // hot address of OtherPoolPartition
)

// Harness is one signing-zone configuration: approvers alice, bob, carol (enabled), auto, dave (disabled), policies for
// ETH and USDT, and a hot address for Partition.
type Harness struct {
	T       testing.TB
	ChainID uint64
	Hot     common.Address
	Keys    map[string]ed25519.PrivateKey
	File    gateway.File
	Cfg     *gateway.Config
	Now     func() time.Time
}

// New builds a harness for chainID whose hot address is hot.
func New(t testing.TB, chainID uint64, hot common.Address) *Harness {
	t.Helper()
	h := &Harness{T: t, ChainID: chainID, Hot: hot, Keys: map[string]ed25519.PrivateKey{}, Now: time.Now}
	approvers := map[string]gateway.ApproverFile{}
	for _, name := range []string{"alice", "bob", "carol", "auto", "dave"} {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		h.Keys[name] = priv
		approvers[name] = gateway.ApproverFile{PublicKey: hex.EncodeToString(pub), Enabled: name != "dave"}
	}
	h.File = gateway.File{
		Approvers: approvers,
		Chains: map[string]gateway.ChainFile{Chain: {
			EVM: &gateway.EVMFile{ChainID: chainID, Factory: AddrFactory.Hex(), SweepDestination: AddrDest.Hex(),
				HotAddresses: map[string]string{Partition: hot.Hex(), ColdPartition: hot.Hex(),
					Shard2Partition: AddrShard2.Hex(), OtherPoolPartition: AddrOtherPl.Hex()},
				ColdAddresses: map[string]string{"omnibus/native": AddrCold.Hex(), "omnibus/token": AddrCold.Hex()},
				Tokens:        map[string]gateway.TokenFile{"USDT": {Address: AddrToken.Hex(), Decimals: 6}},
				MaxTxFeeWei:   "300000000000000"},
			Assets: map[string]gateway.AssetFile{
				"ETH":  {PerTxCap: "5000", DailyCap: "8000", Tiers: []gateway.TierFile{{MinAmount: "0", Approvals: 1}, {MinAmount: "1000", Approvals: 2}}, ToColdDailyCap: "6000", RebalanceDailyCap: "6000"},
				"USDT": {PerTxCap: "5000000", DailyCap: "8000000", Tiers: []gateway.TierFile{{MinAmount: "0", Approvals: 1}, {MinAmount: "1000000", Approvals: 2}}, ToColdDailyCap: "6000000", RebalanceDailyCap: "6000000"},
			},
			SweepsPerHour: 2, CancelsPerHour: 3, ToColdPerHour: 2, RebalancePerHour: 2,
		}},
	}
	h.Reparse()
	return h
}

// Reparse rebuilds Cfg from File.
func (h *Harness) Reparse() {
	raw, _ := json.Marshal(h.File)
	cfg, err := gateway.ParseConfig(raw)
	if err != nil {
		h.T.Fatal(err)
	}
	h.Cfg = cfg
}

// WriteConfig writes File as JSON and returns the path.
func (h *Harness) WriteConfig(path string) string {
	raw, _ := json.MarshalIndent(h.File, "", " ")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		h.T.Fatal(err)
	}
	return path
}

// TxSpec is a transaction to build from the hot address.
type TxSpec struct {
	Nonce  uint64
	To     common.Address
	Value  *big.Int
	Data   []byte
	Gas    uint64
	Tip    *big.Int
	FeeCap *big.Int
}

func (s TxSpec) fill() TxSpec {
	if s.Value == nil {
		s.Value = new(big.Int)
	}
	if s.Gas == 0 {
		s.Gas = 21000
	}
	if s.Tip == nil {
		s.Tip = big.NewInt(1e9)
	}
	if s.FeeCap == nil {
		s.FeeCap = big.NewInt(3e9)
	}
	return s
}

// ETH is a plain transfer.
func ETH(to common.Address, amount int64, nonce uint64) TxSpec {
	return TxSpec{Nonce: nonce, To: to, Value: big.NewInt(amount), Gas: 21000}
}

// Payload returns the evm.Payload JSON and the digest of s sent from the hot address.
func (h *Harness) Payload(s TxSpec) (payload, digest []byte) {
	s = s.fill()
	_, d, err := eth.BuildTx(eth.TxParams{ChainID: new(big.Int).SetUint64(h.ChainID), Nonce: s.Nonce, To: s.To, Value: s.Value, Data: s.Data,
		Gas: s.Gas, GasTipCap: s.Tip, GasFeeCap: s.FeeCap})
	if err != nil {
		h.T.Fatal(err)
	}
	pl, _ := json.Marshal(evm.Payload{ChainID: h.ChainID, From: h.Hot.Hex(), Nonce: s.Nonce, To: s.To.Hex(), Value: s.Value.String(),
		Data: hexutil.Encode(s.Data), Gas: s.Gas, Tip: s.Tip.String(), FeeCap: s.FeeCap.String()})
	return pl, d[:]
}

// Job assembles a sign job for intent in and tx s, approved by the named actors. A withdrawal without NotAfter gets
// now+1h.
func (h *Harness) Job(id string, in signjob.Intent, s TxSpec, approvers ...string) signjob.Job {
	if in.Chain == "" {
		in.Chain = Chain
	}
	if in.PartitionID == "" {
		in.PartitionID = Partition
	}
	if in.Kind == "withdrawal" && in.NotAfter == 0 {
		in.NotAfter = h.Now().Add(time.Hour).Unix()
	}
	payload, digest := h.Payload(s)
	ib, _ := json.Marshal(in)
	return signjob.Job{ID: id, PartitionID: in.PartitionID, KeyRef: "m/0", Chain: in.Chain, Intent: ib, Digest: digest, Payload: payload,
		Approvals: h.Approvals(in, approvers...)}
}

// Approvals signs the intent hash with the named approvers' keys.
func (h *Harness) Approvals(in signjob.Intent, actors ...string) []signjob.Approval {
	hash := in.Hash()
	out := []signjob.Approval{}
	for _, a := range actors {
		out = append(out, signjob.Approval{Actor: a, Signature: ed25519.Sign(h.Keys[a], hash[:])})
	}
	return out
}

// Withdrawal is a withdrawal job of ETH to `to`.
func (h *Harness) Withdrawal(id string, to common.Address, amount int64, nonce uint64, approvers ...string) signjob.Job {
	in := signjob.Intent{Kind: "withdrawal", ID: "w-" + id, Asset: "ETH", To: to.Hex(), Amount: fmt.Sprint(amount)}
	return h.Job(id, in, ETH(to, amount, nonce), approvers...)
}

// ToCold is a hot-to-cold job of ETH: the intent names intentTo, the transaction pays txTo. No approvals are needed.
func (h *Harness) ToCold(id string, intentTo, txTo common.Address, amount int64, nonce uint64, approvers ...string) signjob.Job {
	in := signjob.Intent{Kind: "to-cold", ID: "m-" + id, PartitionID: ColdPartition, Asset: "ETH", To: intentTo.Hex(), Amount: fmt.Sprint(amount)}
	return h.Job(id, in, ETH(txTo, amount, nonce), approvers...)
}

// Rebalance is a hot-shard rebalance job of ETH from ColdPartition (shard 1): the intent names intentTo, the transaction pays txTo.
// No approvals are needed.
func (h *Harness) Rebalance(id string, intentTo, txTo common.Address, amount int64, nonce uint64, approvers ...string) signjob.Job {
	in := signjob.Intent{Kind: "rebalance", ID: "rb-" + id, PartitionID: ColdPartition, Asset: "ETH", To: intentTo.Hex(), Amount: fmt.Sprint(amount)}
	return h.Job(id, in, ETH(txTo, amount, nonce), approvers...)
}

// NewGuardDB creates an empty database on the DATABASE_URL server (dropped at cleanup) and returns a pool. Each call is a
// different database: use one for the gateway's guard and another for the cosigner's.
func NewGuardDB(t testing.TB) (*pgxpool.Pool, string) {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		if os.Getenv("QV_REQUIRE_DB") == "1" {
			t.Fatal("DATABASE_URL is not set")
		}
		t.Skip("DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer admin.Close(ctx)
	name := "qv_guard_" + hex.EncodeToString(uuid.NewSHA1(uuid.NameSpaceOID, []byte(t.Name()+time.Now().String())).NodeID())
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, err := pgx.Connect(context.Background(), url)
		if err == nil {
			c.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
			c.Close(context.Background())
		}
	})
	cfg, _ := pgxpool.ParseConfig(url)
	cfg.ConnConfig.Database = name
	p, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	u, _ := neturl.Parse(url)
	u.Path = "/" + name
	return p, u.String()
}
