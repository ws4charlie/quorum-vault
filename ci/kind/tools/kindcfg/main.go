// Command kindcfg makes what the kind lane's withdrawal cases need around the charts, from public values only (no key is made or kept here except throwaway chain keys that
// never leave memory):
//
//	kindcfg chain  -rpc URL -hot ADDR                         deploys the deposit factory on the local chain (destination = the hot address), funds the hot address with gas money,
//	                                                          prints {"factory","height"} (JSON)
//	kindcfg gen    -keys keys.json -factory ADDR -height N -btc-height N -auto-seed FILE -out DIR -pins pins.json -btc-rpc URL -btc-user U -btc-pass-file F
//	                                                          writes signing.json (gateway), cosigner.json (the same rules without signers), custody-evm.json and custody-btc.json
//	kindcfg fundhot -cfg custody-evm.json -rpc URL -dsn DSN -eth N     books N ETH of gas money on the hot shard in the ledger (the operator's step; the e2e suite calls the same service method)
//
// Each file is parsed by the same code the services use before it is written, so a mistake fails here and not in a pod.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
	"github.com/ws4charlie/quorum-vault/internal/chain/evm"
	"github.com/ws4charlie/quorum-vault/internal/custody"
	"github.com/ws4charlie/quorum-vault/internal/gateway"
)

const (
	evmChain = "evm-kind"
	btcChain = "btc-kind"
	entity   = "qv-us"
)

// chainID is the EVM chain id of the lane's anvil, from QV_KIND_CHAIN_ID (laneChainID).
var chainID uint64

// laneChainID reads QV_KIND_CHAIN_ID. ci/kind/lib.sh sets it, the one place the lane's chain id is decided; there is no default here, so a run that
// did not source lib.sh fails instead of writing configs for another chain.
func laneChainID() (uint64, error) {
	v := os.Getenv("QV_KIND_CHAIN_ID")
	if v == "" {
		return 0, fmt.Errorf("QV_KIND_CHAIN_ID is not set (ci/kind/lib.sh sets it; run kindcfg through the lane's scripts or source lib.sh first)")
	}
	id, err := strconv.ParseUint(v, 10, 64)
	if err != nil || id == 0 || id > math.MaxInt64 {
		return 0, fmt.Errorf("QV_KIND_CHAIN_ID=%q is not a chain id", v)
	}
	return id, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: kindcfg chain|gen|fundhot ...")
		os.Exit(2)
	}
	var err error
	if chainID, err = laneChainID(); err != nil {
		fmt.Fprintln(os.Stderr, "kindcfg:", err)
		os.Exit(1)
	}
	switch os.Args[1] {
	case "chain":
		err = chainCmd(os.Args[2:])
	case "gen":
		err = gen(os.Args[2:])
	case "fundhot":
		err = fundhot(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "kindcfg:", err)
		os.Exit(1)
	}
}

func chainCmd(args []string) error {
	fs := flag.NewFlagSet("chain", flag.ExitOnError)
	rpcURL := fs.String("rpc", "", "the local chain's RPC address")
	hot := fs.String("hot", "", "the hot address")
	fs.Parse(args)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	rc, err := rpc.DialContext(ctx, *rpcURL)
	if err != nil {
		return err
	}
	defer rc.Close()
	ec := ethclient.NewClient(rc)
	if id, err := ec.ChainID(ctx); err != nil || id.Uint64() != chainID {
		return fmt.Errorf("refusing to deploy: chain id %v (want %d, anvil of the lane): %v", id, chainID, err)
	}
	var info map[string]any
	if err := rc.CallContext(ctx, &info, "anvil_nodeInfo"); err != nil {
		return fmt.Errorf("refusing to deploy: not an anvil node: %w", err)
	}
	_ = rc.CallContext(ctx, nil, "evm_setAutomine", true)
	deployer, _ := crypto.GenerateKey()
	from := crypto.PubkeyToAddress(deployer.PublicKey)
	if err := rc.CallContext(ctx, nil, "anvil_setBalance", from, (*hexutil.Big)(eth(1000))); err != nil {
		return err
	}
	// a factory whose admin and guardian are addresses nobody holds a key for: the lane never changes the destination or freezes
	nobody := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	rcpt, err := send(ctx, ec, deployer, nil, new(big.Int), evm.FactoryDeployData(common.HexToAddress(*hot), nobody, nobody))
	if err != nil {
		return err
	}
	if err := rc.CallContext(ctx, nil, "anvil_setBalance", common.HexToAddress(*hot), (*hexutil.Big)(eth(100))); err != nil {
		return err
	}
	h, err := ec.BlockNumber(ctx)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"factory": rcpt.ContractAddress.Hex(), "height": h})
}

func eth(n int64) *big.Int { return new(big.Int).Mul(big.NewInt(n), big.NewInt(1e18)) }

func send(ctx context.Context, ec *ethclient.Client, key *ecdsa.PrivateKey, to *common.Address, value *big.Int, data []byte) (*types.Receipt, error) {
	from := crypto.PubkeyToAddress(key.PublicKey)
	nonce, err := ec.PendingNonceAt(ctx, from)
	if err != nil {
		return nil, err
	}
	gas, err := ec.EstimateGas(ctx, ethereum.CallMsg{From: from, To: to, Value: value, Data: data})
	if err != nil {
		return nil, fmt.Errorf("estimate gas: %w", err)
	}
	h, err := ec.HeaderByNumber(ctx, nil)
	if err != nil {
		return nil, err
	}
	tip := big.NewInt(2e9)
	tx := types.NewTx(&types.DynamicFeeTx{ChainID: new(big.Int).SetUint64(chainID), Nonce: nonce, GasTipCap: tip,
		GasFeeCap: new(big.Int).Add(new(big.Int).Mul(h.BaseFee, big.NewInt(2)), tip), Gas: gas * 12 / 10, To: to, Value: value, Data: data})
	signed, err := types.SignTx(tx, types.LatestSignerForChainID(tx.ChainId()), key)
	if err != nil {
		return nil, err
	}
	if err := ec.SendTransaction(ctx, signed); err != nil {
		return nil, err
	}
	for i := 0; i < 200; i++ {
		if r, err := ec.TransactionReceipt(ctx, signed.Hash()); err == nil {
			if r.Status != 1 {
				return nil, fmt.Errorf("transaction %s reverted", signed.Hash())
			}
			return r, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil, fmt.Errorf("no receipt for %s", signed.Hash())
}

// ---- gen ----

type keysFile struct {
	Keyset    string `json:"keyset"`
	PublicKey string `json:"public_key"`
	Address   string `json:"address"`
	BTCKeyset string `json:"btc_keyset"`
	Xpub      string `json:"xpub"`
}

type pinsFile struct {
	Gateway string `json:"gateway_cert"` // the pod paths of the gateway's party certificate
	A       party  `json:"a"`
	B       party  `json:"b"`
	C       party  `json:"c"`
}

type party struct {
	Address string `json:"address"`
	Pin     string `json:"pin"`
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

func gen(args []string) error {
	fs := flag.NewFlagSet("gen", flag.ExitOnError)
	keysPath := fs.String("keys", "", "keys.json made by dkg.sh")
	factory := fs.String("factory", "", "the deposit factory (kindcfg chain)")
	height := fs.Uint64("height", 0, "the EVM scan starts here")
	btcHeight := fs.Uint64("btc-height", 0, "the Bitcoin scan starts here")
	autoSeed := fs.String("auto-seed", "", "the auto approver's seed file (only its public key is used)")
	out := fs.String("out", "", "output directory")
	pinsPath := fs.String("pins", "", "pins.json: party addresses and pins, the gateway's certificate paths")
	btcRPC := fs.String("btc-rpc", "http://bitcoind:18443", "bitcoind's address as the business pods see it")
	btcUser := fs.String("btc-user-file", "", "file with bitcoind's RPC user")
	btcPass := fs.String("btc-pass-file", "", "file with bitcoind's RPC password")
	fs.Parse(args)
	var k keysFile
	var pins pinsFile
	for p, v := range map[string]any{*keysPath: &k, *pinsPath: &pins} {
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(b, v); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
	}
	seedHex, err := os.ReadFile(*autoSeed)
	if err != nil {
		return err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(seedHex)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return fmt.Errorf("%s: not a 32-byte hex seed", *autoSeed)
	}
	autoPub := hex.EncodeToString(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	user, _ := os.ReadFile(*btcUser)
	pass, _ := os.ReadFile(*btcPass)

	// ---- the Bitcoin account: hot shard 0 at m/84'/1'/0'/1/0, a cold address at 1/1
	acct, err := btc.NewAccount("regtest", k.Xpub)
	if err != nil {
		return err
	}
	btcHot, err := acct.Address([]uint32{1, 0})
	if err != nil {
		return err
	}
	btcCold, err := acct.Address([]uint32{1, 1})
	if err != nil {
		return err
	}
	evmCold := "0x000000000000000000000000000000000000c01d"

	// ---- the business configs (one chain each: a business deployment serves one)
	tiers := func(sym string) map[string][]custody.TierFile {
		return map[string][]custody.TierFile{sym: {{MinAmount: "0", Approvals: 1, Auto: true}}}
	}
	wf := custody.WithdrawalFile{ApprovalWindow: "10m", ApprovalTimeout: "5m", SignTimeout: "30s", StuckAfter: "3m", HotWait: "5m", MaxReplacements: 3}
	cfEVM := custody.File{Entity: entity,
		Chain: custody.ChainFile{Name: evmChain, ChainID: chainID, RPCURL: "http://anvil:8545", Confirmations: 0, Factory: *factory, SweepDestination: k.Address, HotShards: []string{k.Address},
			MaxTxFeeWei: "100000000000000000", Assets: map[string]custody.AssetFile{"ETH": {Decimals: 18, MinDeposit: "0", PriceWei: "1"}}},
		Sweep:      custody.SweepFile{K: 20, MinSweepWei: "1000000000000000", PlanInterval: "5s"},
		Withdrawal: wf, Scan: custody.ScanFile{Interval: "2s", StartHeight: *height}}
	cfEVM.Withdrawal.Tiers = tiers("ETH")
	cfEVM.Cold = custody.ColdFile{Addresses: map[string]string{"omnibus/native": evmCold}, PlanInterval: "30s"}

	cfBTC := custody.File{Entity: entity,
		Chain: custody.ChainFile{Family: "btc", Name: btcChain,
			BTC: &custody.BTCFile{Network: "regtest", RPCURL: *btcRPC, RPCUser: strings.TrimSpace(string(user)), RPCPassword: strings.TrimSpace(string(pass)), Confirmations: 2, AccountXpub: k.Xpub,
				HotShards: []custody.BTCShardFile{{Address: btcHot, Path: []uint32{1, 0}}}, SpendConfirmations: 2, MaxFeeRate: 50, MaxTxFeeSats: 100_000, MaxInputs: 20},
			Assets: map[string]custody.AssetFile{"BTC": {Decimals: 8, MinDeposit: "1000"}}},
		Sweep:      custody.SweepFile{MinSweepWei: "100000000000", PlanInterval: "5s"}, // 1000 BTC: nothing is swept
		Withdrawal: wf, Scan: custody.ScanFile{Interval: "2s", StartHeight: *btcHeight}}
	cfBTC.Withdrawal.Tiers = tiers("BTC")
	cfBTC.Cold = custody.ColdFile{Addresses: map[string]string{"omnibus/native": btcCold}, PlanInterval: "30s"}

	if err := os.MkdirAll(*out, 0o700); err != nil {
		return err
	}
	cfgs := map[string]*custody.Config{}
	for name, cf := range map[string]custody.File{"custody-evm.json": cfEVM, "custody-btc.json": cfBTC} {
		p := filepath.Join(*out, name)
		if err := writeJSON(p, cf); err != nil {
			return err
		}
		c, err := custody.LoadConfig(p)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		cfgs[name] = c
	}

	// ---- the signing zone's config: both chains, one MPC signer each
	cert, key := pins.Gateway+"/tls.crt", pins.Gateway+"/tls.key"
	coord := func(name string, p party) gateway.MPCSignerFile {
		return gateway.MPCSignerFile{Name: name, Address: p.Address, CertFile: cert, KeyFile: key, ServerPin: p.Pin}
	}
	evmPart := cfgs["custody-evm.json"].PartitionKey("ETH", 0).String()
	btcPart := cfgs["custody-btc.json"].PartitionKey("BTC", 0).String()
	gf := gateway.File{
		Approvers:   map[string]gateway.ApproverFile{"auto": {PublicKey: autoPub, Enabled: true}},
		SignTimeout: "30s", MaxIntentAge: "24h",
		Signers: map[string]gateway.SignerFile{
			evmPart: {Backend: "mpc", Scheme: "ecdsa-2of3", KeysetID: k.Keyset, PublicKey: k.PublicKey, Coordinators: []gateway.MPCSignerFile{coord("A", pins.A), coord("B", pins.B)}},
			btcPart: {Backend: "mpc", KeysetID: k.BTCKeyset, HardenedPath: btc.AccountPath("regtest"), MPC: &gateway.MPCSignerFile{Address: pins.A.Address, CertFile: cert, KeyFile: key, ServerPin: pins.A.Pin}},
		},
		Chains: map[string]gateway.ChainFile{
			evmChain: {EVM: &gateway.EVMFile{ChainID: chainID, Factory: *factory, SweepDestination: k.Address, HotAddresses: map[string]string{evmPart: k.Address},
				ColdAddresses: map[string]string{"omnibus/native": evmCold}, MaxTxFeeWei: "100000000000000000"},
				Assets:        map[string]gateway.AssetFile{"ETH": {AnyDestination: true, PerTxCap: "5000000000000000000", DailyCap: "50000000000000000000", ToColdDailyCap: "50000000000000000000", RebalanceDailyCap: "0", Tiers: []gateway.TierFile{{MinAmount: "0", Approvals: 1}}}},
				SweepsPerHour: 600, WithdrawalsPerHour: 600, CancelsPerHour: 60, ToColdPerHour: 60},
			btcChain: {Family: "btc", BTC: &gateway.BTCFile{Network: "regtest", AccountXpub: k.Xpub, ColdAddresses: map[string]string{"omnibus/native": btcCold}, MaxTxFeeSats: 100_000, MaxFeeRate: 50, MaxInputs: 20,
				HotShards: map[string]gateway.HotShardFile{btcPart: {Address: btcHot, Path: []uint32{1, 0}}}},
				Assets:        map[string]gateway.AssetFile{"BTC": {AnyDestination: true, PerTxCap: "1000000000", DailyCap: "100000000000", ToColdDailyCap: "100000000000", Tiers: []gateway.TierFile{{MinAmount: "0", Approvals: 1}}}},
				SweepsPerHour: 600, WithdrawalsPerHour: 600, CancelsPerHour: 60, ToColdPerHour: 60, ConsolidationsPerHour: 6},
		},
	}
	cos := gf
	cos.Signers, cos.MPCRoute = nil, nil // the cosigner has the zone's rules and trust roots, no signer entries
	for name, v := range map[string]gateway.File{"signing.json": gf, "cosigner.json": cos} {
		p := filepath.Join(*out, name)
		if err := writeJSON(p, v); err != nil {
			return err
		}
		b, _ := os.ReadFile(p)
		if _, err := gateway.ParseConfig(b); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	fmt.Printf("evm partition %s\nbtc partition %s\n", evmPart, btcPart)
	return nil
}

// ---- fundhot ----

func fundhot(args []string) error {
	fs := flag.NewFlagSet("fundhot", flag.ExitOnError)
	cfgPath := fs.String("cfg", "", "the EVM custody config")
	rpcURL := fs.String("rpc", "", "the chain's RPC address as this machine sees it")
	dsn := fs.String("dsn", "", "business database DSN of a role that may book transfers (the core's)")
	n := fs.Int64("eth", 100, "ETH to book")
	fs.Parse(args)
	cfg, err := custody.LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	cfg.EVM.RPCURL = *rpcURL
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	pool, err := pgxpool.New(ctx, *dsn)
	if err != nil {
		return err
	}
	defer pool.Close()
	adapter, err := evm.New(ctx, cfg.EVM, pool)
	if err != nil {
		return err
	}
	defer adapter.Close()
	reader, err := custody.NewEVMReader(ctx, cfg)
	if err != nil {
		return err
	}
	defer reader.Close()
	if err := custody.New(pool, cfg, adapter, reader).FundHot(ctx, "kind-seed", 0, eth(*n)); err != nil {
		return err
	}
	fmt.Printf("booked %d ETH of gas money on the hot shard\n", *n)
	return nil
}
