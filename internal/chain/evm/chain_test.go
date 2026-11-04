package evm

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ws4charlie/quorum-vault/e2e"
	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// All tests below run against a local anvil node (chain ID 11155111) and a
// fresh database each. They skip unless QV_EVM_RPC_URL is set; with
// QV_REQUIRE_CHAIN=1 a missing URL fails. Keys are generated at run time.

var (
	ether  = new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	tokABI abi.ABI
)

type tenv struct {
	t           *testing.T
	ctx         context.Context
	url         string
	ec          *ethclient.Client
	rpc         *rpc.Client
	pool        *pgxpool.Pool
	cfg         Config
	ad          *Adapter
	deployer    *ecdsa.PrivateKey
	hotKey      *ecdsa.PrivateKey
	adminKey    *ecdsa.PrivateKey // factory admin (the "cold" key)
	guardianKey *ecdsa.PrivateKey
	hot         common.Address
	dest        common.Address
	usdt        common.Address // returns no bool
	dai         common.Address // returns bool
}

func requireAnvil(t *testing.T) string {
	t.Helper()
	u := os.Getenv("QV_EVM_RPC_URL")
	if u == "" {
		if os.Getenv("QV_REQUIRE_CHAIN") == "1" {
			t.Fatal("evm (QV_REQUIRE_CHAIN=1): QV_EVM_RPC_URL is not set")
		}
		t.Skip("evm: QV_EVM_RPC_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := e2e.CheckLocalChain(ctx, u); err != nil {
		t.Fatalf("evm: refusing to run: %v", err)
	}
	return u
}

func newEnv(t *testing.T) *tenv {
	t.Helper()
	url := requireAnvil(t)
	pool := dbtest.New(t)
	ctx := context.Background()
	rc, err := rpc.DialContext(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rc.Close)
	// A previous aborted run may have left automine off.
	_ = rc.CallContext(ctx, nil, "evm_setAutomine", true)
	e := &tenv{t: t, ctx: ctx, url: url, ec: ethclient.NewClient(rc), rpc: rc, pool: pool}
	e.deployer, _ = crypto.GenerateKey()
	e.hotKey, _ = crypto.GenerateKey()
	e.hot = crypto.PubkeyToAddress(e.hotKey.PublicKey)
	destKey, _ := crypto.GenerateKey()
	e.dest = crypto.PubkeyToAddress(destKey.PublicKey)
	for _, a := range []common.Address{crypto.PubkeyToAddress(e.deployer.PublicKey), e.hot} {
		if err := e2e.SetBalance(ctx, url, a, new(big.Int).Mul(big.NewInt(1000), ether)); err != nil {
			t.Fatal(err)
		}
	}
	if tokABI.Methods == nil {
		raw, err := os.ReadFile("testdata/Token.abi.json")
		if err != nil {
			t.Fatal(err)
		}
		if tokABI, err = abi.JSON(strings.NewReader(string(raw))); err != nil {
			t.Fatal(err)
		}
	}
	e.cfg.ChainID = 11155111
	e.adminKey, _ = crypto.GenerateKey()
	if err := e2e.SetBalance(ctx, url, crypto.PubkeyToAddress(e.adminKey.PublicKey), new(big.Int).Mul(big.NewInt(10), ether)); err != nil {
		t.Fatal(err)
	}
	e.guardianKey, _ = crypto.GenerateKey()
	if err := e2e.SetBalance(ctx, url, crypto.PubkeyToAddress(e.guardianKey.PublicKey), new(big.Int).Mul(big.NewInt(10), ether)); err != nil {
		t.Fatal(err)
	}
	// Frozen by default: deployed with destination zero; the admin sets the hot address below.
	factory := e.deploy(FactoryDeployData(common.Address{}, crypto.PubkeyToAddress(e.adminKey.PublicKey), crypto.PubkeyToAddress(e.guardianKey.PublicKey)))
	e.usdt = e.deploy(readBin(t, "testdata/UsdtLike.bin"))
	e.dai = e.deploy(readBin(t, "testdata/BoolToken.bin"))
	e.cfg = Config{
		Chain: "evm-anvil", ChainID: e.cfg.ChainID, MaxTxFeeWei: ether, RPCURL: url, Confirmations: 2, StuckAfterBlocks: 3,
		Factory: factory, SweepDestination: e.dest,
		HotAddresses: map[string]common.Address{"hot-0": e.hot},
		Assets:       map[string]Token{"USDT": {Address: e.usdt, Decimals: 6}, "DAI": {Address: e.dai, Decimals: 18}},
	}
	if err := loadABIs(); err != nil {
		t.Fatal(err)
	}
	if r := e.factoryTx(e.adminKey, "setDestination", e.dest); r.Status != 1 {
		t.Fatal("admin could not set the destination")
	}
	e.ad, err = New(ctx, e.cfg, pool)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.ad.Close)
	return e
}

func readBin(t *testing.T, path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return common.FromHex(strings.TrimSpace(string(b)))
}

func (e *tenv) fees() (tip, feeCap *big.Int) {
	tip = big.NewInt(2e9)
	h, err := e.ec.HeaderByNumber(e.ctx, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	return tip, new(big.Int).Add(new(big.Int).Mul(h.BaseFee, big.NewInt(2)), tip)
}

// sendRaw signs and sends a tx from key. gas == 0 means estimate.
func (e *tenv) sendRaw(key *ecdsa.PrivateKey, to *common.Address, value *big.Int, data []byte, gas uint64) *types.Transaction {
	e.t.Helper()
	from := crypto.PubkeyToAddress(key.PublicKey)
	nonce, err := e.ec.PendingNonceAt(e.ctx, from)
	if err != nil {
		e.t.Fatal(err)
	}
	if gas == 0 {
		if gas, err = e.ec.EstimateGas(e.ctx, ethereum.CallMsg{From: from, To: to, Value: value, Data: data}); err != nil {
			e.t.Fatalf("estimate: %v", err)
		}
	}
	tip, feeCap := e.fees()
	tx := types.NewTx(&types.DynamicFeeTx{ChainID: new(big.Int).SetUint64(e.cfg.ChainID), Nonce: nonce, GasTipCap: tip, GasFeeCap: feeCap, Gas: gas, To: to, Value: value, Data: data})
	signed, err := types.SignTx(tx, types.LatestSignerForChainID(tx.ChainId()), key)
	if err != nil {
		e.t.Fatal(err)
	}
	if err := e.ec.SendTransaction(e.ctx, signed); err != nil {
		e.t.Fatalf("send: %v", err)
	}
	return signed
}

func (e *tenv) receipt(h common.Hash) *types.Receipt {
	e.t.Helper()
	for i := 0; i < 100; i++ {
		if r, err := e.ec.TransactionReceipt(e.ctx, h); err == nil {
			return r
		}
		time.Sleep(50 * time.Millisecond)
	}
	e.t.Fatalf("no receipt for %s", h)
	return nil
}

func (e *tenv) send(key *ecdsa.PrivateKey, to *common.Address, value *big.Int, data []byte) *types.Receipt {
	e.t.Helper()
	r := e.receipt(e.sendRaw(key, to, value, data, 0).Hash())
	if r.Status != 1 {
		e.t.Fatalf("tx %s reverted", r.TxHash)
	}
	return r
}

func (e *tenv) deploy(code []byte) common.Address {
	e.t.Helper()
	return e.send(e.deployer, nil, new(big.Int), code).ContractAddress
}

func (e *tenv) mint(token, to common.Address, amt int64) {
	e.t.Helper()
	data, err := tokABI.Pack("mint", to, big.NewInt(amt))
	if err != nil {
		e.t.Fatal(err)
	}
	e.send(e.deployer, &token, new(big.Int), data)
}

func (e *tenv) tokenBalance(token, who common.Address) *big.Int {
	e.t.Helper()
	data, _ := tokABI.Pack("balanceOf", who)
	out, err := e.ec.CallContract(e.ctx, ethereum.CallMsg{To: &token, Data: data}, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	return new(big.Int).SetBytes(out)
}

func (e *tenv) mine(n uint64) {
	e.t.Helper()
	if err := e.rpc.CallContext(e.ctx, nil, "anvil_mine", hexutil.EncodeUint64(n)); err != nil {
		e.t.Fatal(err)
	}
}

func (e *tenv) automine(on bool) {
	e.t.Helper()
	if err := e.rpc.CallContext(e.ctx, nil, "evm_setAutomine", on); err != nil {
		e.t.Fatal(err)
	}
}

func (e *tenv) head() uint64 {
	h, err := e.ec.BlockNumber(e.ctx)
	if err != nil {
		e.t.Fatal(err)
	}
	return h
}

func (e *tenv) balance(a common.Address) *big.Int {
	b, err := e.ec.BalanceAt(e.ctx, a, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	return b
}

// addCustomer derives and stores a deposit address like P3 will.
func (e *tenv) addCustomer(id string, idx uint64) common.Address {
	e.t.Helper()
	d, err := e.ad.DeriveDepositAddress(e.ctx, id, idx)
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.pool.Exec(e.ctx, `INSERT INTO customers (id, entity) VALUES ($1,'qv-us') ON CONFLICT DO NOTHING`, id); err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.pool.Exec(e.ctx, `INSERT INTO deposit_addresses (customer_id, chain, asset, address, derivation_index, kind) VALUES ($1,$2,NULL,$3,$4,$5)`,
		id, d.Chain, d.Address, int64(d.DerivationIndex), d.Kind); err != nil {
		e.t.Fatal(err)
	}
	return common.HexToAddress(d.Address)
}

func sign(t *testing.T, u chain.UnsignedTx, key *ecdsa.PrivateKey) chain.Signature {
	t.Helper()
	sig, err := crypto.Sign(u.Digest, key)
	if err != nil {
		t.Fatal(err)
	}
	return chain.Signature{Bytes: sig}
}

func (e *tenv) buildW(id, asset, to string, amt int64) chain.UnsignedTx {
	e.t.Helper()
	tx, err := e.pool.Begin(e.ctx)
	if err != nil {
		e.t.Fatal(err)
	}
	u, err := e.ad.BuildWithdrawal(e.ctx, tx, chain.WithdrawalIntent{ID: id, PartitionID: "hot-0", Asset: asset, To: to, Amount: big.NewInt(amt)})
	if err != nil {
		_ = tx.Rollback(e.ctx)
		e.t.Fatal(err)
	}
	if err := tx.Commit(e.ctx); err != nil {
		e.t.Fatal(err)
	}
	return u
}

func payloadOf(t *testing.T, u chain.UnsignedTx) Payload {
	t.Helper()
	var p Payload
	if err := json.Unmarshal(u.Payload, &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func (e *tenv) mustBroadcast(u chain.UnsignedTx) string {
	e.t.Helper()
	s, err := e.ad.Assemble(u, sign(e.t, u, e.hotKey))
	if err != nil {
		e.t.Fatal(err)
	}
	h, err := e.ad.Broadcast(e.ctx, s)
	if err != nil {
		e.t.Fatal(err)
	}
	return h
}

func TestPredictMatchesOnChain(t *testing.T) {
	e := newEnv(t)
	if err := loadABIs(); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		id  string
		idx uint64
	}{{"alice", 0}, {"alice", 1}, {"bob", 0}} {
		d, _ := e.ad.DeriveDepositAddress(e.ctx, c.id, c.idx)
		salt := DeriveSalt(c.id, c.idx)
		data, err := factoryABI.Pack("predict", salt)
		if err != nil {
			t.Fatal(err)
		}
		out, err := e.ec.CallContract(e.ctx, ethereum.CallMsg{To: &e.cfg.Factory, Data: data}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := common.BytesToAddress(out); got.Hex() != d.Address {
			t.Fatalf("%s/%d: local %s, on-chain %s", c.id, c.idx, d.Address, got.Hex())
		}
	}
}

func TestDepositSweepEndToEnd(t *testing.T) {
	e := newEnv(t)
	addr := e.addCustomer("cust-1", 0)
	start := e.head() + 1

	ethDeposit := new(big.Int).Mul(big.NewInt(3), ether)
	e.send(e.deployer, &addr, ethDeposit, nil)
	e.mint(e.usdt, addr, 5_000_000)
	e.mint(e.dai, addr, 7_000) // a configured token we do not sweep in this run
	e.mine(e.cfg.Confirmations)

	res, err := e.ad.Scan(e.ctx, start)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]chain.ObservedDeposit{}
	for _, d := range res.Deposits {
		got[d.Asset] = d
		if d.Address != addr.Hex() || d.Chain != "evm-anvil" || d.BlockHeight == 0 {
			t.Fatalf("bad deposit %+v", d)
		}
	}
	if len(res.Deposits) != 3 {
		t.Fatalf("want 3 deposits, got %+v", res.Deposits)
	}
	if got["ETH"].Amount.Cmp(ethDeposit) != 0 || got["USDT"].Amount.Int64() != 5_000_000 || got["DAI"].Amount.Int64() != 7_000 {
		t.Fatalf("amounts: %+v", got)
	}
	if !strings.HasSuffix(got["ETH"].DedupKey, ":native") || !strings.HasPrefix(got["USDT"].DedupKey, "evm-anvil:0x") {
		t.Fatalf("dedup keys: %q %q", got["ETH"].DedupKey, got["USDT"].DedupKey)
	}
	if res.SafeHeadHeight != e.head()-e.cfg.Confirmations {
		t.Fatalf("safe head %d, head %d", res.SafeHeadHeight, e.head())
	}
	again, _ := e.ad.Scan(e.ctx, start)
	if len(again.Deposits) != 3 || again.Deposits[0].DedupKey != res.Deposits[0].DedupKey {
		t.Fatalf("scan is not repeatable: %+v", again.Deposits)
	}

	// Sweep USDT (ETH always rides along), verified offline before signing.
	tx, err := e.pool.Begin(e.ctx)
	if err != nil {
		t.Fatal(err)
	}
	si := chain.SweepIntent{ID: "sweep-1", Asset: "USDT", From: addr.Hex(), ToPartition: "hot-0", Amount: big.NewInt(5_000_000)}
	u, err := e.ad.BuildSweep(e.ctx, tx, si)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(e.ctx); err != nil {
		t.Fatal(err)
	}
	v, _ := NewVerifier(e.cfg)
	intent := signjob.Intent{Kind: "sweep", ID: "sweep-1", PartitionID: "hot-0", Chain: "evm-anvil", Asset: "USDT", From: addr.Hex(), To: e.dest.Hex(), Amount: "5000000"}
	if err := v.Verify(u, intent); err != nil {
		t.Fatal(err)
	}
	fee, err := e.ad.EstimateSweepFee(e.ctx, si)
	if err != nil || fee.Sign() <= 0 {
		t.Fatalf("fee %v err %v", fee, err)
	}

	destEth, destUsdt := e.balance(e.dest), e.tokenBalance(e.usdt, e.dest)
	hash := e.mustBroadcast(u)
	r := e.receipt(common.HexToHash(hash))
	if r.Status != 1 {
		t.Fatal("sweep reverted")
	}
	t.Logf("sweep (deploy + ETH + 1 token) gas used: %d", r.GasUsed)
	if d := new(big.Int).Sub(e.balance(e.dest), destEth); d.Cmp(ethDeposit) != 0 {
		t.Fatalf("destination ETH +%s, want +%s", d, ethDeposit)
	}
	if d := new(big.Int).Sub(e.tokenBalance(e.usdt, e.dest), destUsdt); d.Int64() != 5_000_000 {
		t.Fatalf("destination USDT +%s", d)
	}
	if e.balance(addr).Sign() != 0 || e.tokenBalance(e.usdt, addr).Sign() != 0 {
		t.Fatal("forwarder not empty")
	}
	if e.tokenBalance(e.dai, addr).Int64() != 7_000 {
		t.Fatal("unlisted token must stay put")
	}

	// Pending until Confirmations blocks are on top.
	if st, _ := e.ad.Status(e.ctx, hash); st != chain.TxPending {
		t.Fatalf("status %s, want pending", st)
	}
	e.mine(e.cfg.Confirmations)
	if st, _ := e.ad.Status(e.ctx, hash); st != chain.TxConfirmed {
		t.Fatalf("status %s, want confirmed", st)
	}

	// Second round on the deployed forwarder: sweeping flushes without redeploying.
	e.mint(e.usdt, addr, 11)
	tx, _ = e.pool.Begin(e.ctx)
	u2, err := e.ad.BuildSweep(e.ctx, tx, chain.SweepIntent{ID: "sweep-2", Asset: "USDT", From: addr.Hex(), ToPartition: "hot-0", Amount: big.NewInt(11)})
	if err != nil {
		t.Fatal(err)
	}
	_ = tx.Commit(e.ctx)
	r2 := e.receipt(common.HexToHash(e.mustBroadcast(u2)))
	t.Logf("sweep on deployed forwarder (ETH-less, 1 token) gas used: %d", r2.GasUsed)
	if r2.Status != 1 || e.tokenBalance(e.usdt, e.dest).Int64() != 5_000_011 {
		t.Fatal("second sweep failed")
	}
}

func TestSweepRejectsUnknownAddressAndAsset(t *testing.T) {
	e := newEnv(t)
	tx, _ := e.pool.Begin(e.ctx)
	defer tx.Rollback(e.ctx)
	if _, err := e.ad.BuildSweep(e.ctx, tx, chain.SweepIntent{ID: "x", Asset: "USDT", From: e.dest.Hex(), ToPartition: "hot-0"}); err == nil {
		t.Fatal("sweep from an address that is not a deposit address accepted")
	}
	addr := e.addCustomer("c", 0)
	if _, err := e.ad.BuildSweep(e.ctx, tx, chain.SweepIntent{ID: "x", Asset: "DOGE", From: addr.Hex(), ToPartition: "hot-0"}); err == nil {
		t.Fatal("unknown asset accepted")
	}
	if _, err := e.ad.BuildWithdrawal(e.ctx, tx, chain.WithdrawalIntent{ID: "x", PartitionID: "hot-0", Asset: "DOGE", To: e.dest.Hex(), Amount: big.NewInt(1)}); err == nil {
		t.Fatal("unknown withdrawal asset accepted")
	}
	if _, err := e.ad.BuildWithdrawal(e.ctx, tx, chain.WithdrawalIntent{ID: "x", PartitionID: "nope", Asset: "ETH", To: e.dest.Hex(), Amount: big.NewInt(1)}); err == nil {
		t.Fatal("unknown partition accepted")
	}
}

func TestScanIsReorgSafe(t *testing.T) {
	e := newEnv(t)
	addr := e.addCustomer("cust-r", 0)
	start := e.head() + 1
	r := e.send(e.deployer, &addr, big.NewInt(1000), nil)
	block := r.BlockNumber.Uint64()
	for i := uint64(0); i < e.cfg.Confirmations; i++ {
		res, err := e.ad.Scan(e.ctx, start)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Deposits) != 0 || res.SafeHeadHeight >= block {
			t.Fatalf("deposit at %d returned with safe head %d (head %d)", block, res.SafeHeadHeight, e.head())
		}
		e.mine(1)
	}
	res, _ := e.ad.Scan(e.ctx, start)
	if len(res.Deposits) != 1 || res.SafeHeadHeight != block || res.Deposits[0].Amount.Int64() != 1000 {
		t.Fatalf("after %d confirmations: %+v safe %d", e.cfg.Confirmations, res.Deposits, res.SafeHeadHeight)
	}
	// Resuming from the safe head returns nothing new and no error.
	res2, err := e.ad.Scan(e.ctx, res.SafeHeadHeight+1)
	if err != nil || len(res2.Deposits) != 0 {
		t.Fatalf("resume: %+v %v", res2.Deposits, err)
	}
}

func TestScanIgnoresRevertedAndUnrelated(t *testing.T) {
	e := newEnv(t)
	addr := e.addCustomer("cust-x", 0)
	other, _ := crypto.GenerateKey()
	stranger := crypto.PubkeyToAddress(other.PublicKey)
	start := e.head() + 1
	e.send(e.deployer, &stranger, big.NewInt(5), nil)
	e.mint(e.usdt, stranger, 9)
	// Deploy the forwarder, then send with only 21,000 gas: reverts, no value moves.
	d, _ := packDeployAndFlush(DeriveSalt("cust-x", 0), nil)
	e.send(e.deployer, &e.cfg.Factory, new(big.Int), d)
	rr := e.receipt(e.sendRaw(e.deployer, &addr, big.NewInt(77), nil, 21000).Hash())
	if rr.Status != 0 {
		t.Fatal("expected the 21,000-gas send to a deployed forwarder to revert")
	}
	e.mine(e.cfg.Confirmations)
	res, err := e.ad.Scan(e.ctx, start)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Deposits) != 0 {
		t.Fatalf("unexpected deposits %+v", res.Deposits)
	}
}

// Deposit gas: before deployment the address is an empty account, so a plain
// 21,000-gas send works. After deployment the (empty) receive() still has to run, so
// exactly 21,000 reverts; report the smallest limit that works. A contract using
// Solidity transfer() (2,300 gas) works too.
func TestPlainSendGasBeforeAndAfterDeployment(t *testing.T) {
	e := newEnv(t)
	addr := e.addCustomer("cust-g", 0)

	// Before deployment: 21,000 succeeds.
	if r := e.receipt(e.sendRaw(e.deployer, &addr, big.NewInt(1), nil, 21000).Hash()); r.Status != 1 {
		t.Fatal("21,000-gas send to an undeployed forwarder address reverted")
	}
	d, _ := packDeployAndFlush(DeriveSalt("cust-g", 0), nil)
	e.send(e.deployer, &e.cfg.Factory, new(big.Int), d)

	// After deployment: exactly 21,000 reverts and the value stays with the sender.
	before := e.balance(addr)
	r := e.receipt(e.sendRaw(e.deployer, &addr, big.NewInt(1), nil, 21000).Hash())
	if r.Status != 0 {
		t.Fatal("21,000-gas send to a deployed forwarder must revert")
	}
	if e.balance(addr).Cmp(before) != 0 {
		t.Fatal("a reverted send moved value")
	}
	// Smallest gas limit that succeeds (real transactions, binary search).
	lo, hi := uint64(21000), uint64(60000)
	for lo < hi {
		mid := (lo + hi) / 2
		if e.receipt(e.sendRaw(e.deployer, &addr, big.NewInt(1), nil, mid).Hash()).Status == 1 {
			hi = mid
		} else {
			lo = mid + 1
		}
	}
	est, _ := e.ec.EstimateGas(e.ctx, ethereum.CallMsg{From: crypto.PubkeyToAddress(e.deployer.PublicKey), To: &addr, Value: big.NewInt(1)})
	t.Logf("plain send to a deployed forwarder: 21000 reverts; minimum gas limit that succeeds = %d; eth_estimateGas = %d", lo, est)
	if lo <= 21000 {
		t.Fatalf("minimum %d", lo)
	}

	// Solidity transfer() (2,300 gas) from a contract works.
	sender := e.deploy(readBin(t, "testdata/TransferSender.bin"))
	raw, _ := os.ReadFile("testdata/TransferSender.abi.json")
	sabi, err := abi.JSON(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	data, _ := sabi.Pack("pay", addr)
	bal := e.balance(addr)
	if r := e.receipt(e.sendRaw(e.deployer, &sender, big.NewInt(1000), data, 200000).Hash()); r.Status != 1 {
		t.Fatal("transfer() from a contract to a deployed forwarder reverted")
	}
	if d := new(big.Int).Sub(e.balance(addr), bal); d.Int64() != 1000 {
		t.Fatalf("forwarder received %s", d)
	}
}

// admin sends a factory call as the admin key (or key) with a generous fixed gas limit.
func (e *tenv) factoryTx(key *ecdsa.PrivateKey, method string, args ...any) *types.Receipt {
	e.t.Helper()
	data, err := factoryABI.Pack(method, args...)
	if err != nil {
		e.t.Fatal(err)
	}
	return e.receipt(e.sendRaw(key, &e.cfg.Factory, new(big.Int), data, 3_000_000).Hash())
}

func (e *tenv) factoryDestination() common.Address {
	data, _ := factoryABI.Pack("destination")
	out, err := e.ec.CallContract(e.ctx, ethereum.CallMsg{To: &e.cfg.Factory, Data: data}, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	return common.BytesToAddress(out)
}

func (e *tenv) buildSweepErr(id, asset string, from common.Address) error {
	tx, _ := e.pool.Begin(e.ctx)
	defer tx.Rollback(e.ctx) //nolint:errcheck
	_, err := e.ad.BuildSweep(e.ctx, tx, chain.SweepIntent{ID: id, Asset: asset, From: from.Hex(), ToPartition: "hot-0", Amount: big.NewInt(1)})
	return err
}

func TestFrozenFactoryStopsSweepsAndKeepsFunds(t *testing.T) {
	e := newEnv(t)
	if err := loadABIs(); err != nil {
		t.Fatal(err)
	}
	addr := e.addCustomer("cust-z", 0)
	e.send(e.deployer, &addr, big.NewInt(5000), nil)
	e.mint(e.usdt, addr, 8)

	// A non-admin cannot freeze or redirect.
	if r := e.factoryTx(e.deployer, "setDestination", common.Address{}); r.Status != 0 {
		t.Fatal("non-admin setDestination succeeded")
	}
	if e.factoryDestination() != e.dest {
		t.Fatal("destination changed by a non-admin")
	}

	// Build a sweep while unfrozen, then freeze.
	if err := e.buildSweepErr("s0", "USDT", addr); err != nil {
		t.Fatal(err)
	}
	if r := e.factoryTx(e.adminKey, "setDestination", common.Address{}); r.Status != 1 {
		t.Fatal("admin freeze failed")
	}
	if err := e.buildSweepErr("s1", "USDT", addr); !errors.Is(err, ErrSweepFrozen) {
		t.Fatalf("BuildSweep when frozen: %v", err)
	}
	if _, err := e.ad.EstimateSweepFee(e.ctx, chain.SweepIntent{ID: "s1", Asset: "USDT", From: addr.Hex(), ToPartition: "hot-0"}); !errors.Is(err, ErrSweepFrozen) {
		t.Fatalf("EstimateSweepFee when frozen: %v", err)
	}
	// On chain: deployAndFlush and a direct flush revert; funds stay.
	d, _ := packDeployAndFlush(DeriveSalt("cust-z", 0), []common.Address{e.usdt})
	if r := e.receipt(e.sendRaw(e.deployer, &e.cfg.Factory, new(big.Int), d, 3_000_000).Hash()); r.Status != 0 {
		t.Fatal("deployAndFlush succeeded while frozen")
	}
	if e.balance(addr).Int64() != 5000 || e.tokenBalance(e.usdt, addr).Int64() != 8 || e.balance(e.dest).Sign() != 0 {
		t.Fatal("funds moved while frozen")
	}
	if c, _ := e.ec.CodeAt(e.ctx, addr, nil); len(c) != 0 {
		t.Fatal("frozen deployAndFlush deployed the forwarder")
	}

	// Unfreeze: the same sweep works.
	if r := e.factoryTx(e.adminKey, "setDestination", e.dest); r.Status != 1 {
		t.Fatal("admin unfreeze failed")
	}
	tx, _ := e.pool.Begin(e.ctx)
	u, err := e.ad.BuildSweep(e.ctx, tx, chain.SweepIntent{ID: "s2", Asset: "USDT", From: addr.Hex(), ToPartition: "hot-0", Amount: big.NewInt(8)})
	if err != nil {
		t.Fatal(err)
	}
	_ = tx.Commit(e.ctx)
	if r := e.receipt(common.HexToHash(e.mustBroadcast(u))); r.Status != 1 {
		t.Fatal("sweep after unfreeze reverted")
	}
	if e.balance(e.dest).Int64() != 5000 || e.tokenBalance(e.usdt, e.dest).Int64() != 8 {
		t.Fatal("funds did not arrive after unfreeze")
	}
}

func TestDestinationChangeMovesNoAddressAndNeedsMatchingConfig(t *testing.T) {
	e := newEnv(t)
	if err := loadABIs(); err != nil {
		t.Fatal(err)
	}
	addr := e.addCustomer("cust-d", 0)
	before := addr
	e.send(e.deployer, &addr, big.NewInt(100), nil)
	newKey, _ := crypto.GenerateKey()
	newDest := crypto.PubkeyToAddress(newKey.PublicKey)
	if r := e.factoryTx(e.adminKey, "setDestination", newDest); r.Status != 1 {
		t.Fatal("admin setDestination failed")
	}
	if d, _ := e.ad.DeriveDepositAddress(e.ctx, "cust-d", 0); d.Address != before.Hex() {
		t.Fatal("deposit address moved when the destination changed")
	}
	// Configuration still names the old destination: refuse to build.
	if err := e.buildSweepErr("s", "ETH", addr); !errors.Is(err, ErrDestinationMismatch) {
		t.Fatalf("stale config: %v", err)
	}
	// With the configuration (and the signing zone's) updated, the old address pays the new destination.
	cfg := e.cfg
	cfg.SweepDestination = newDest
	ad, err := New(e.ctx, cfg, e.pool)
	if err != nil {
		t.Fatal(err)
	}
	defer ad.Close()
	tx, _ := e.pool.Begin(e.ctx)
	u, err := ad.BuildSweep(e.ctx, tx, chain.SweepIntent{ID: "s-new", Asset: "ETH", From: addr.Hex(), ToPartition: "hot-0", Amount: big.NewInt(100)})
	if err != nil {
		t.Fatal(err)
	}
	_ = tx.Commit(e.ctx)
	v, _ := NewVerifier(cfg)
	if err := v.Verify(u, signjob.Intent{Kind: "sweep", ID: "s-new", PartitionID: "hot-0", Chain: "evm-anvil", Asset: "ETH", From: addr.Hex(), To: newDest.Hex(), Amount: "100"}); err != nil {
		t.Fatal(err)
	}
	// The old configuration's verifier refuses the new destination.
	vOld, _ := NewVerifier(e.cfg)
	if err := vOld.Verify(u, signjob.Intent{Kind: "sweep", ID: "s-new", PartitionID: "hot-0", Chain: "evm-anvil", Asset: "ETH", From: addr.Hex(), To: newDest.Hex(), Amount: "100"}); err == nil {
		t.Fatal("verifier with the old sweep destination accepted the new one")
	}
	s, _ := ad.Assemble(u, sign(t, u, e.hotKey))
	h, err := ad.Broadcast(e.ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	if e.receipt(common.HexToHash(h)).Status != 1 || e.balance(newDest).Int64() != 100 || e.balance(e.dest).Sign() != 0 {
		t.Fatal("old address did not pay the new destination")
	}
}

func TestDeployedFrozenDepositsArriveThenAdminStartsSweeping(t *testing.T) {
	e := newEnv(t)
	// A second factory, frozen by default (its destination is zero).
	frozen := e.deploy(FactoryDeployData(common.Address{}, crypto.PubkeyToAddress(e.adminKey.PublicKey), crypto.PubkeyToAddress(e.guardianKey.PublicKey)))
	cfg := e.cfg
	cfg.Factory = frozen
	cfg.Chain = "evm-anvil-frozen"
	ad, err := New(e.ctx, cfg, e.pool)
	if err != nil {
		t.Fatal(err)
	}
	defer ad.Close()
	d, _ := ad.DeriveDepositAddress(e.ctx, "cust-fz", 0)
	if _, err := e.pool.Exec(e.ctx, `INSERT INTO customers (id, entity) VALUES ('cust-fz','qv-us')`); err != nil {
		t.Fatal(err)
	}
	if _, err := e.pool.Exec(e.ctx, `INSERT INTO deposit_addresses (customer_id, chain, address, derivation_index, kind) VALUES ('cust-fz',$1,$2,0,'forwarder')`, d.Chain, d.Address); err != nil {
		t.Fatal(err)
	}
	addr := common.HexToAddress(d.Address)
	start := e.head() + 1
	e.send(e.deployer, &addr, big.NewInt(7000), nil) // deposits arrive while frozen
	e.mint(e.usdt, addr, 3)
	e.mine(cfg.Confirmations)
	res, err := ad.Scan(e.ctx, start)
	if err != nil || len(res.Deposits) != 2 {
		t.Fatalf("scan while frozen: %+v %v", res.Deposits, err)
	}
	tx, _ := e.pool.Begin(e.ctx)
	_, err = ad.BuildSweep(e.ctx, tx, chain.SweepIntent{ID: "s", Asset: "USDT", From: addr.Hex(), ToPartition: "hot-0", Amount: big.NewInt(3)})
	_ = tx.Rollback(e.ctx)
	if !errors.Is(err, ErrSweepFrozen) {
		t.Fatalf("BuildSweep on a frozen-by-default factory: %v", err)
	}
	data, _ := packDeployAndFlush(DeriveSalt("cust-fz", 0), []common.Address{e.usdt})
	if r := e.receipt(e.sendRaw(e.deployer, &frozen, new(big.Int), data, 3_000_000).Hash()); r.Status != 0 {
		t.Fatal("deployAndFlush succeeded on a frozen factory")
	}
	if e.balance(addr).Int64() != 7000 {
		t.Fatal("funds moved while frozen")
	}
	// The cold key sets the hot address; the same sweep now works.
	setData, _ := factoryABI.Pack("setDestination", e.dest)
	if r := e.receipt(e.sendRaw(e.adminKey, &frozen, new(big.Int), setData, 3_000_000).Hash()); r.Status != 1 {
		t.Fatal("admin setDestination failed")
	}
	tx, _ = e.pool.Begin(e.ctx)
	u, err := ad.BuildSweep(e.ctx, tx, chain.SweepIntent{ID: "s2", Asset: "USDT", From: addr.Hex(), ToPartition: "hot-0", Amount: big.NewInt(3)})
	if err != nil {
		t.Fatal(err)
	}
	_ = tx.Commit(e.ctx)
	s, _ := ad.Assemble(u, sign(t, u, e.hotKey))
	h, err := ad.Broadcast(e.ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	if e.receipt(common.HexToHash(h)).Status != 1 || e.balance(e.dest).Int64() != 7000 || e.tokenBalance(e.usdt, e.dest).Int64() != 3 {
		t.Fatal("sweep after the admin set the destination failed")
	}
}

func TestGuardianFreezesOnlyAdminUnfreezes(t *testing.T) {
	e := newEnv(t)
	addr := e.addCustomer("cust-gd", 0)
	e.send(e.deployer, &addr, big.NewInt(4000), nil)

	if r := e.factoryTx(e.deployer, "freeze"); r.Status != 0 {
		t.Fatal("a stranger froze the factory")
	}
	if e.factoryDestination() != e.dest {
		t.Fatal("destination changed by a stranger")
	}
	if r := e.factoryTx(e.guardianKey, "freeze"); r.Status != 1 {
		t.Fatal("guardian could not freeze")
	}
	if e.factoryDestination() != (common.Address{}) {
		t.Fatal("not frozen")
	}
	if err := e.buildSweepErr("g", "ETH", addr); !errors.Is(err, ErrSweepFrozen) {
		t.Fatalf("BuildSweep after guardian freeze: %v", err)
	}
	if e.balance(addr).Int64() != 4000 {
		t.Fatal("freeze moved funds")
	}
	// Freezing again is harmless.
	if r := e.factoryTx(e.guardianKey, "freeze"); r.Status != 1 {
		t.Fatal("second freeze reverted")
	}
	// The guardian cannot unfreeze, rotate itself, or touch admin.
	other, _ := crypto.GenerateKey()
	oa := crypto.PubkeyToAddress(other.PublicKey)
	for name, args := range map[string][]any{"setDestination": {e.dest}, "transferAdmin": {oa}, "setGuardian": {oa}} {
		if r := e.factoryTx(e.guardianKey, name, args...); r.Status != 0 {
			t.Fatalf("guardian could call %s", name)
		}
	}
	if e.factoryDestination() != (common.Address{}) {
		t.Fatal("guardian unfroze")
	}
	// Admin rotates the guardian: the old one loses power. Admin unfreezes.
	k2, _ := crypto.GenerateKey()
	if err := e2e.SetBalance(e.ctx, e.url, crypto.PubkeyToAddress(k2.PublicKey), new(big.Int).Mul(big.NewInt(10), ether)); err != nil {
		t.Fatal(err)
	}
	if r := e.factoryTx(e.deployer, "setGuardian", crypto.PubkeyToAddress(k2.PublicKey)); r.Status != 0 {
		t.Fatal("non-admin rotated the guardian")
	}
	if r := e.factoryTx(e.adminKey, "setGuardian", crypto.PubkeyToAddress(k2.PublicKey)); r.Status != 1 {
		t.Fatal("admin could not rotate the guardian")
	}
	if r := e.factoryTx(e.adminKey, "setDestination", e.dest); r.Status != 1 {
		t.Fatal("admin could not unfreeze")
	}
	if r := e.factoryTx(e.guardianKey, "freeze"); r.Status != 0 {
		t.Fatal("the old guardian kept its power")
	}
	if r := e.factoryTx(k2, "freeze"); r.Status != 1 {
		t.Fatal("the new guardian cannot freeze")
	}
	// Unfrozen sweep of what stayed in the deposit address.
	if r := e.factoryTx(e.adminKey, "setDestination", e.dest); r.Status != 1 {
		t.Fatal("unfreeze")
	}
	tx, _ := e.pool.Begin(e.ctx)
	u, err := e.ad.BuildSweep(e.ctx, tx, chain.SweepIntent{ID: "g2", Asset: "ETH", From: addr.Hex(), ToPartition: "hot-0", Amount: big.NewInt(4000)})
	if err != nil {
		t.Fatal(err)
	}
	_ = tx.Commit(e.ctx)
	if e.receipt(common.HexToHash(e.mustBroadcast(u))).Status != 1 || e.balance(e.dest).Int64() != 4000 {
		t.Fatal("funds left in the deposit address were not swept after unfreezing")
	}
}

func TestAdminTransferIsTwoStep(t *testing.T) {
	e := newEnv(t)
	if err := loadABIs(); err != nil {
		t.Fatal(err)
	}
	k2, _ := crypto.GenerateKey()
	admin2 := crypto.PubkeyToAddress(k2.PublicKey)
	if err := e2e.SetBalance(e.ctx, e.url, admin2, new(big.Int).Mul(big.NewInt(10), ether)); err != nil {
		t.Fatal(err)
	}
	if r := e.factoryTx(e.deployer, "transferAdmin", admin2); r.Status != 0 {
		t.Fatal("non-admin transferAdmin succeeded")
	}
	if r := e.factoryTx(e.adminKey, "transferAdmin", admin2); r.Status != 1 {
		t.Fatal("transferAdmin failed")
	}
	if r := e.factoryTx(k2, "setDestination", admin2); r.Status != 0 {
		t.Fatal("nominated admin had power before accepting")
	}
	if r := e.factoryTx(e.deployer, "acceptAdmin"); r.Status != 0 {
		t.Fatal("a non-pending caller accepted")
	}
	if r := e.factoryTx(k2, "acceptAdmin"); r.Status != 1 {
		t.Fatal("acceptAdmin failed")
	}
	if r := e.factoryTx(e.adminKey, "setDestination", admin2); r.Status != 0 {
		t.Fatal("the old admin kept its power")
	}
	if r := e.factoryTx(k2, "setDestination", e.dest); r.Status != 1 {
		t.Fatal("the new admin cannot act")
	}
}

func TestNonceConcurrentBuildsAreConsecutive(t *testing.T) {
	e := newEnv(t)
	e.mint(e.dai, e.hot, 1_000_000) // so token transfers estimate
	const n = 20
	nonces := make([]uint64, n)
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tx, err := e.pool.Begin(e.ctx)
			if err != nil {
				errs <- err
				return
			}
			asset := "ETH"
			if i%2 == 1 {
				asset = "DAI"
			}
			u, err := e.ad.BuildWithdrawal(e.ctx, tx, chain.WithdrawalIntent{ID: "w-" + string(rune('A'+i)), PartitionID: "hot-0", Asset: asset, To: e.dest.Hex(), Amount: big.NewInt(1)})
			if err != nil {
				_ = tx.Rollback(e.ctx)
				errs <- err
				return
			}
			nonces[i] = payloadOf(t, u).Nonce
			errs <- tx.Commit(e.ctx)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	sort.Slice(nonces, func(i, j int) bool { return nonces[i] < nonces[j] })
	for i := 1; i < n; i++ {
		if nonces[i] != nonces[0]+uint64(i) {
			t.Fatalf("nonces not distinct and consecutive: %v", nonces)
		}
	}
	var next int64
	_ = e.pool.QueryRow(e.ctx, `SELECT next_nonce FROM evm_nonces WHERE address=$1`, e.hot.Hex()).Scan(&next)
	if uint64(next) != nonces[0]+n {
		t.Fatalf("next_nonce %d, want %d", next, nonces[0]+n)
	}
}

func TestNonceRollbackLeavesNoGapAndRebuildIsStable(t *testing.T) {
	e := newEnv(t)
	W := func(id string) chain.WithdrawalIntent {
		return chain.WithdrawalIntent{ID: id, PartitionID: "hot-0", Asset: "ETH", To: e.dest.Hex(), Amount: big.NewInt(1)}
	}
	tx, _ := e.pool.Begin(e.ctx)
	u1, err := e.ad.BuildWithdrawal(e.ctx, tx, W("w-rolled-back"))
	if err != nil {
		t.Fatal(err)
	}
	n1 := payloadOf(t, u1).Nonce
	if err := tx.Rollback(e.ctx); err != nil {
		t.Fatal(err)
	}
	var cnt int
	_ = e.pool.QueryRow(e.ctx, `SELECT count(*) FROM evm_nonce_allocations`).Scan(&cnt)
	if cnt != 0 {
		t.Fatalf("rollback left %d allocations", cnt)
	}
	u2 := e.buildW("w-2", "ETH", e.dest.Hex(), 1)
	if n2 := payloadOf(t, u2).Nonce; n2 != n1 {
		t.Fatalf("nonce after rollback %d, want the released %d", n2, n1)
	}
	// Rebuilding for the same owner (also in a new transaction) keeps the nonce.
	u2b := e.buildW("w-2", "ETH", e.dest.Hex(), 1)
	if payloadOf(t, u2b).Nonce != n1 {
		t.Fatal("rebuild for the same owner took a second nonce")
	}
	u3 := e.buildW("w-3", "ETH", e.dest.Hex(), 1)
	if payloadOf(t, u3).Nonce != n1+1 {
		t.Fatal("next owner did not get the next nonce")
	}
	// Same owner id under another kind is a different owner.
	tx, _ = e.pool.Begin(e.ctx)
	addr := e.addCustomer("c-n", 0)
	us, err := e.ad.BuildSweep(e.ctx, tx, chain.SweepIntent{ID: "w-3", Asset: "ETH", From: addr.Hex(), ToPartition: "hot-0", Amount: big.NewInt(0)})
	if err != nil {
		t.Fatal(err)
	}
	_ = tx.Commit(e.ctx)
	if payloadOf(t, us).Nonce != n1+2 {
		t.Fatal("sweep with a reused id should be a new owner")
	}
}

func TestNonceInitializedFromChainPendingNonce(t *testing.T) {
	e := newEnv(t)
	e.send(e.hotKey, &e.dest, big.NewInt(1), nil) // hot nonce 0 used before the manager first sees it
	e.send(e.hotKey, &e.dest, big.NewInt(1), nil)
	u := e.buildW("w-init", "ETH", e.dest.Hex(), 1)
	if n := payloadOf(t, u).Nonce; n != 2 {
		t.Fatalf("first allocation %d, want the chain's pending nonce 2", n)
	}
}

func TestReplacementMinesAndOriginalDoesNot(t *testing.T) {
	e := newEnv(t)
	e.automine(false)
	t.Cleanup(func() { e.automine(true) })

	u := e.buildW("w-stuck", "ETH", e.dest.Hex(), 1234)
	n0 := payloadOf(t, u).Nonce
	origHash := e.mustBroadcast(u)
	if st, _ := e.ad.Status(e.ctx, origHash); st != chain.TxPending {
		t.Fatalf("status %s, want pending", st)
	}
	// Broadcasting the same transaction again is success ("already known").
	if h2 := e.mustBroadcast(u); h2 != origHash {
		t.Fatalf("second broadcast hash %s != %s", h2, origHash)
	}

	tx, _ := e.pool.Begin(e.ctx)
	ur, err := e.ad.BuildReplacement(e.ctx, tx, "withdrawal", "w-stuck")
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(e.ctx); err != nil {
		t.Fatal(err)
	}
	po, pr := payloadOf(t, u), payloadOf(t, ur)
	if pr.Nonce != n0 || pr.To != po.To || pr.Value != po.Value || pr.Data != po.Data || pr.Gas != po.Gas {
		t.Fatalf("replacement changed more than fees: %+v vs %+v", pr, po)
	}
	for name, pair := range map[string][2]string{"tip": {po.Tip, pr.Tip}, "cap": {po.FeeCap, pr.FeeCap}} {
		oldF, _ := new(big.Int).SetString(pair[0], 10)
		newF, _ := new(big.Int).SetString(pair[1], 10)
		min := new(big.Int).Mul(oldF, big.NewInt(115))
		min.Div(min, big.NewInt(100))
		if newF.Cmp(min) < 0 {
			t.Fatalf("%s bumped %s -> %s, less than 15%%", name, pair[0], pair[1])
		}
	}
	v, _ := NewVerifier(e.cfg)
	if err := v.Verify(ur, signjob.Intent{Kind: "withdrawal", ID: "w-stuck", PartitionID: "hot-0", Chain: "evm-anvil", Asset: "ETH", To: e.dest.Hex(), Amount: "1234"}); err != nil {
		t.Fatalf("replacement fails offline verification: %v", err)
	}
	before := e.balance(e.dest)
	replHash := e.mustBroadcast(ur)
	e.mine(1)

	if r := e.receipt(common.HexToHash(replHash)); r.Status != 1 {
		t.Fatal("replacement reverted")
	}
	if _, err := e.ec.TransactionReceipt(e.ctx, common.HexToHash(origHash)); err == nil {
		t.Fatal("the original also mined")
	}
	if d := new(big.Int).Sub(e.balance(e.dest), before); d.Int64() != 1234 {
		t.Fatalf("destination got %s, want exactly one transfer of 1234", d)
	}
	// The nonce counts as used only at the safe head (Confirmations deep), so the
	// original is still "pending" until then and cannot be mistaken for consumed.
	if st, _ := e.ad.Status(e.ctx, origHash); st != chain.TxPending {
		t.Fatalf("original status %s one block after the replacement, want pending", st)
	}
	e.mine(e.cfg.Confirmations)
	if st, _ := e.ad.Status(e.ctx, origHash); st != chain.TxDropped {
		t.Fatalf("original status %s, want dropped", st)
	}
	if st, _ := e.ad.Status(e.ctx, replHash); st != chain.TxConfirmed {
		t.Fatalf("replacement status %s, want confirmed", st)
	}
	var status string
	_ = e.pool.QueryRow(e.ctx, `SELECT status FROM evm_nonce_allocations WHERE owner_id='w-stuck'`).Scan(&status)
	if status != "confirmed" {
		t.Fatalf("allocation status %s", status)
	}
	if _, err := e.ad.BuildReplacement(e.ctx, mustBegin(e), "withdrawal", "w-stuck"); err == nil {
		t.Fatal("replacement of a confirmed transaction accepted")
	}
}

func mustBegin(e *tenv) pgx.Tx {
	tx, err := e.pool.Begin(e.ctx)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { _ = tx.Rollback(e.ctx) })
	return tx
}

func TestStatusFailedOnRevert(t *testing.T) {
	e := newEnv(t)
	addr := e.addCustomer("cust-f", 0)
	d, _ := packDeployAndFlush(DeriveSalt("cust-f", 0), nil)
	e.send(e.deployer, &e.cfg.Factory, new(big.Int), d)
	h := e.sendRaw(e.deployer, &addr, big.NewInt(1), nil, 21000).Hash()
	e.receipt(h)
	if st, err := e.ad.Status(e.ctx, h.Hex()); err != nil || st != chain.TxFailed {
		t.Fatalf("status %s err %v, want failed", st, err)
	}
}

func TestReconcileReportsGapsAndStuck(t *testing.T) {
	e := newEnv(t)
	// nonce N: allocated, then taken by an outside transaction (a gap).
	gapU := e.buildW("w-gap", "ETH", e.dest.Hex(), 1)
	nGap := payloadOf(t, gapU).Nonce
	e.send(e.hotKey, &e.dest, big.NewInt(1), nil)
	// nonce N+1: allocated and never broadcast (stuck once old enough).
	stuckU := e.buildW("w-stuck2", "ETH", e.dest.Hex(), 1)
	// nonce N+2: allocated, broadcast, mined: must be neither.
	okU := e.buildW("w-ok", "ETH", e.dest.Hex(), 1)
	_ = stuckU
	if payloadOf(t, okU).Nonce != nGap+2 {
		t.Fatal("unexpected nonce layout")
	}
	// The mined one needs nonce N+1 filled first; use a second outside tx? No:
	// broadcast the stuck one too and replace nothing; mine both, then re-add a
	// fresh never-broadcast allocation as the stuck case.
	e.mustBroadcast(stuckU)
	e.mustBroadcast(okU)
	stuck2 := e.buildW("w-never", "ETH", e.dest.Hex(), 1)
	if payloadOf(t, stuck2).Nonce != nGap+3 {
		t.Fatal("unexpected nonce layout")
	}
	time.Sleep(1200 * time.Millisecond) // block timestamps have 1 s resolution
	e.mine(e.cfg.Confirmations + e.cfg.StuckAfterBlocks)

	rep, err := e.ad.Reconcile(e.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Gaps) != 1 || rep.Gaps[0].Nonce != nGap || rep.Gaps[0].OwnerID != "w-gap" {
		t.Fatalf("gaps: %+v", rep.Gaps)
	}
	if len(rep.Stuck) != 1 || rep.Stuck[0].OwnerID != "w-never" {
		t.Fatalf("stuck: %+v", rep.Stuck)
	}
	var st string
	_ = e.pool.QueryRow(e.ctx, `SELECT status FROM evm_nonce_allocations WHERE owner_id='w-ok'`).Scan(&st)
	if st != "confirmed" {
		t.Fatalf("mined allocation status %s, want confirmed", st)
	}
}

func TestRefusesWrongChainID(t *testing.T) {
	e := newEnv(t)
	cfg := e.cfg
	cfg.ChainID = 1
	if _, err := New(e.ctx, cfg, e.pool); err == nil {
		t.Fatal("adapter accepted a node with another chain id")
	}
}

// TestMeasure logs scan speed and nonce allocation rate (go test -v -run Measure).
func TestMeasure(t *testing.T) {
	e := newEnv(t)
	addr := e.addCustomer("cust-m", 0)
	start := e.head() + 1
	e.send(e.deployer, &addr, big.NewInt(1), nil)
	e.mint(e.usdt, addr, 1)
	const blocks = 2000
	e.mine(blocks)
	t0 := time.Now()
	res, err := e.ad.Scan(e.ctx, start)
	if err != nil {
		t.Fatal(err)
	}
	el := time.Since(t0)
	t.Logf("scan: %d blocks, %d deposits in %s = %.0f blocks/s", blocks, len(res.Deposits), el.Round(time.Millisecond), float64(blocks)/el.Seconds())

	const allocs = 200
	tx, _ := e.pool.Begin(e.ctx)
	t0 = time.Now()
	for i := 0; i < allocs; i++ {
		if _, _, err := e.ad.allocateNonce(e.ctx, tx, e.hot, "withdrawal", "m-"+time.Now().Format("150405.000000")+string(rune('a'+i%26))+string(rune('a'+i/26)), big.NewInt(1), big.NewInt(1)); err != nil {
			t.Fatal(err)
		}
	}
	_ = tx.Commit(e.ctx)
	el = time.Since(t0)
	t.Logf("nonce allocation: %d in one transaction in %s = %.0f/s", allocs, el.Round(time.Millisecond), float64(allocs)/el.Seconds())

	t0 = time.Now()
	for i := 0; i < allocs; i++ {
		tx, _ := e.pool.Begin(e.ctx)
		if _, _, err := e.ad.allocateNonce(e.ctx, tx, e.hot, "withdrawal", "s-"+string(rune('a'+i%26))+string(rune('a'+i/26)), big.NewInt(1), big.NewInt(1)); err != nil {
			t.Fatal(err)
		}
		_ = tx.Commit(e.ctx)
	}
	el = time.Since(t0)
	t.Logf("nonce allocation: %d one-per-transaction in %s = %.0f/s (excluding RPC fee/gas calls)", allocs, el.Round(time.Millisecond), float64(allocs)/el.Seconds())
}

func (e *tenv) buildCancel(ownerKind, ownerID string) chain.UnsignedTx {
	e.t.Helper()
	tx, err := e.pool.Begin(e.ctx)
	if err != nil {
		e.t.Fatal(err)
	}
	u, err := e.ad.BuildCancel(e.ctx, tx, ownerKind, ownerID)
	if err != nil {
		_ = tx.Rollback(e.ctx)
		e.t.Fatal(err)
	}
	if err := tx.Commit(e.ctx); err != nil {
		e.t.Fatal(err)
	}
	return u
}

func (e *tenv) allocStatus(ownerID string) string {
	var st string
	if err := e.pool.QueryRow(e.ctx, `SELECT status FROM evm_nonce_allocations WHERE owner_id=$1`, ownerID).Scan(&st); err != nil {
		e.t.Fatal(err)
	}
	return st
}

// A transaction evicted from the mempool is the main case that needs replacing:
// BuildReplacement must work from stored data, not from the node.
func TestReplacementAfterNodeDroppedTheTransaction(t *testing.T) {
	e := newEnv(t)
	e.automine(false)
	t.Cleanup(func() { e.automine(true) })

	u := e.buildW("w-evicted", "ETH", e.dest.Hex(), 4321)
	origHash := e.mustBroadcast(u)
	if err := e.rpc.CallContext(e.ctx, nil, "anvil_dropTransaction", common.HexToHash(origHash)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.ec.TransactionByHash(e.ctx, common.HexToHash(origHash)); err == nil {
		t.Fatal("node still knows the dropped transaction")
	}
	tx, _ := e.pool.Begin(e.ctx)
	ur, err := e.ad.BuildReplacement(e.ctx, tx, "withdrawal", "w-evicted")
	if err != nil {
		t.Fatal(err)
	}
	_ = tx.Commit(e.ctx)
	if pr, po := payloadOf(t, ur), payloadOf(t, u); pr.Nonce != po.Nonce || pr.To != po.To || pr.Value != po.Value {
		t.Fatalf("replacement changed more than fees: %+v vs %+v", pr, po)
	}
	before := e.balance(e.dest)
	replHash := e.mustBroadcast(ur)
	e.mine(1)
	if r := e.receipt(common.HexToHash(replHash)); r.Status != 1 {
		t.Fatal("replacement reverted")
	}
	if _, err := e.ec.TransactionReceipt(e.ctx, common.HexToHash(origHash)); err == nil {
		t.Fatal("the dropped original mined")
	}
	if d := new(big.Int).Sub(e.balance(e.dest), before); d.Int64() != 4321 {
		t.Fatalf("destination got %s", d)
	}
	var n int
	_ = e.pool.QueryRow(e.ctx, `SELECT count(*) FROM evm_tx_attempts WHERE nonce=$1`, int64(payloadOf(t, u).Nonce)).Scan(&n)
	if n != 2 {
		t.Fatalf("want 2 recorded attempts, got %d", n)
	}
	var latest string
	_ = e.pool.QueryRow(e.ctx, `SELECT tx_hash FROM evm_nonce_allocations WHERE owner_id='w-evicted'`).Scan(&latest)
	if latest != replHash {
		t.Fatalf("allocation tx_hash %q, want only the latest %q", latest, replHash)
	}
}

func TestBroadcastWithoutAllocationIsRefused(t *testing.T) {
	e := newEnv(t)
	u := e.buildW("w-a", "ETH", e.dest.Hex(), 1)
	if _, err := e.pool.Exec(e.ctx, `DELETE FROM evm_nonce_allocations`); err != nil {
		t.Fatal(err)
	}
	s, err := e.ad.Assemble(u, sign(t, u, e.hotKey))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.ad.Broadcast(e.ctx, s); err == nil {
		t.Fatal("transaction with an unknown nonce was broadcast")
	}
	var n int
	_ = e.pool.QueryRow(e.ctx, `SELECT count(*) FROM evm_tx_attempts`).Scan(&n)
	if n != 0 {
		t.Fatal("an attempt was recorded for a refused broadcast")
	}
}

// A nonce committed for a refused job blocks every later nonce; BuildCancel frees it.
func TestCancelFreesBlockedNonce(t *testing.T) {
	e := newEnv(t)
	e.automine(false)
	t.Cleanup(func() { e.automine(true) })

	uN := e.buildW("w-refused", "ETH", e.dest.Hex(), 10)
	uN1 := e.buildW("w-later", "ETH", e.dest.Hex(), 20)
	n := payloadOf(t, uN).Nonce
	if payloadOf(t, uN1).Nonce != n+1 {
		t.Fatal("unexpected nonce layout")
	}
	// N is never signed (the gateway refused it). N+1 waits behind the gap.
	laterHash := e.mustBroadcast(uN1)
	e.mine(1)
	if _, err := e.ec.TransactionReceipt(e.ctx, common.HexToHash(laterHash)); err == nil {
		t.Fatal("N+1 mined before N: the test premise is wrong")
	}

	uc := e.buildCancel("withdrawal", "w-refused")
	pc := payloadOf(t, uc)
	if pc.Nonce != n || pc.To != e.hot.Hex() || pc.Value != "0" || pc.Data != "0x" || pc.Gas != 21000 {
		t.Fatalf("not a zero-value 21000-gas self-send at nonce %d: %+v", n, pc)
	}
	v, _ := NewVerifier(e.cfg)
	if err := v.Verify(uc, signjob.Intent{Kind: "cancel", ID: "w-refused", PartitionID: "hot-0", Chain: "evm-anvil", Asset: "ETH", To: e.hot.Hex(), Amount: "0"}); err != nil {
		t.Fatalf("cancel fails offline verification: %v", err)
	}
	cancelHash := e.mustBroadcast(uc)
	e.mine(1)

	rc, rl := e.receipt(common.HexToHash(cancelHash)), e.receipt(common.HexToHash(laterHash))
	if rc.Status != 1 || rl.Status != 1 || rc.BlockNumber.Uint64() > rl.BlockNumber.Uint64() {
		t.Fatalf("cancel block %d status %d, later block %d status %d", rc.BlockNumber, rc.Status, rl.BlockNumber, rl.Status)
	}
	e.mine(e.cfg.Confirmations)
	if st, _ := e.ad.Status(e.ctx, cancelHash); st != chain.TxConfirmed {
		t.Fatalf("cancel status %s", st)
	}
	if st, _ := e.ad.Status(e.ctx, laterHash); st != chain.TxConfirmed {
		t.Fatalf("later status %s", st)
	}
	if got := e.allocStatus("w-refused"); got != "cancelled" {
		t.Fatalf("refused allocation is %q, want cancelled", got)
	}
	if got := e.allocStatus("w-later"); got != "confirmed" {
		t.Fatalf("later allocation is %q", got)
	}
}

func TestCancelOfBroadcastNonceBumpsFees(t *testing.T) {
	e := newEnv(t)
	e.automine(false)
	t.Cleanup(func() { e.automine(true) })
	u := e.buildW("w-c", "ETH", e.dest.Hex(), 5)
	origHash := e.mustBroadcast(u)
	uc := e.buildCancel("withdrawal", "w-c")
	po, pc := payloadOf(t, u), payloadOf(t, uc)
	for name, pair := range map[string][2]string{"tip": {po.Tip, pc.Tip}, "cap": {po.FeeCap, pc.FeeCap}} {
		oldF, _ := new(big.Int).SetString(pair[0], 10)
		newF, _ := new(big.Int).SetString(pair[1], 10)
		min := new(big.Int).Mul(oldF, big.NewInt(115))
		min.Div(min, big.NewInt(100))
		if newF.Cmp(min) < 0 {
			t.Fatalf("%s bumped %s -> %s, less than 15%%", name, pair[0], pair[1])
		}
	}
	before := e.balance(e.dest)
	e.mustBroadcast(uc)
	e.mine(1)
	if _, err := e.ec.TransactionReceipt(e.ctx, common.HexToHash(origHash)); err == nil {
		t.Fatal("the cancelled original mined")
	}
	if e.balance(e.dest).Cmp(before) != 0 {
		t.Fatal("cancelled withdrawal moved funds")
	}
	e.mine(e.cfg.Confirmations)
	if st, _ := e.ad.Status(e.ctx, origHash); st != chain.TxDropped {
		t.Fatalf("original status %s, want dropped", st)
	}
}

func TestReplacementAndCancelRefuseFeesAboveTheCap(t *testing.T) {
	e := newEnv(t)
	e.automine(false)
	t.Cleanup(func() { e.automine(true) })
	u := e.buildW("w-cap", "ETH", e.dest.Hex(), 1)
	e.mustBroadcast(u)
	// Allow the original but not a 15% bump of it.
	po := payloadOf(t, u)
	fee := new(big.Int).Mul(new(big.Int).SetUint64(po.Gas), mustBig(po.FeeCap))
	cfg := e.cfg
	cfg.MaxTxFeeWei = fee
	ad, err := New(e.ctx, cfg, e.pool)
	if err != nil {
		t.Fatal(err)
	}
	defer ad.Close()
	tx, _ := e.pool.Begin(e.ctx)
	_, err = ad.BuildReplacement(e.ctx, tx, "withdrawal", "w-cap")
	_ = tx.Rollback(e.ctx) // release the allocation lock before the next build
	if err == nil {
		t.Fatal("replacement above the fee cap was built")
	}
	tx2, _ := e.pool.Begin(e.ctx)
	cfg.MaxTxFeeWei = new(big.Int).SetUint64(21000) // far below any cancel
	ad2, _ := New(e.ctx, cfg, e.pool)
	defer ad2.Close()
	_, err = ad2.BuildCancel(e.ctx, tx2, "withdrawal", "w-cap")
	_ = tx2.Rollback(e.ctx)
	if err == nil {
		t.Fatal("cancel above the fee cap was built")
	}
	// A fresh withdrawal is refused too.
	tx3, _ := e.pool.Begin(e.ctx)
	defer tx3.Rollback(e.ctx)
	if _, err := ad2.BuildWithdrawal(e.ctx, tx3, chain.WithdrawalIntent{ID: "x", PartitionID: "hot-0", Asset: "ETH", To: e.dest.Hex(), Amount: big.NewInt(1)}); err == nil {
		t.Fatal("withdrawal above the fee cap was built")
	}
}

func mustBig(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic(s)
	}
	return n
}
