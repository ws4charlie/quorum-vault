package evm

// Spike for contracts/src/SweepFactory.sol (the one-shot sweeper). Everything
// here is real, separate transactions on anvil: nothing is simulated inside one
// transaction, which would hide the EIP-6780 behavior of SELFDESTRUCT.
// Run it against anvil --hardfork cancun and against the default hardfork.

import (
	"context"
	"crypto/ecdsa"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/ws4charlie/quorum-vault/e2e"
)

// spike is a tenv without a database: deployer sends everything, hotKey is the
// SweepFactory admin ("cold" key), dest is the destination.
type spike struct {
	*tenv
	sf    common.Address
	sfABI abi.ABI
}

func newSpike(t *testing.T) *spike {
	t.Helper()
	url := requireAnvil(t)
	ctx := context.Background()
	rc, err := rpc.DialContext(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rc.Close)
	_ = rc.CallContext(ctx, nil, "evm_setAutomine", true)
	e := &tenv{t: t, ctx: ctx, url: url, ec: ethclient.NewClient(rc), rpc: rc}
	e.cfg.ChainID = 11155111
	e.deployer, _ = crypto.GenerateKey()
	e.hotKey, _ = crypto.GenerateKey()
	destKey, _ := crypto.GenerateKey()
	e.dest = crypto.PubkeyToAddress(destKey.PublicKey)
	for _, k := range []*ecdsa.PrivateKey{e.deployer, e.hotKey} {
		if err := e2e.SetBalance(ctx, url, crypto.PubkeyToAddress(k.PublicKey), new(big.Int).Mul(big.NewInt(1000), ether)); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile("testdata/Token.abi.json")
	if err != nil {
		t.Fatal(err)
	}
	if tokABI, err = abi.JSON(strings.NewReader(string(raw))); err != nil {
		t.Fatal(err)
	}
	e.usdt = e.deploy(readBin(t, "testdata/UsdtLike.bin"))
	e.dai = e.deploy(readBin(t, "testdata/BoolToken.bin"))

	sfRaw, err := os.ReadFile("testdata/SweepFactory.abi.json")
	if err != nil {
		t.Fatal(err)
	}
	sfABI, err := abi.JSON(strings.NewReader(string(sfRaw)))
	if err != nil {
		t.Fatal(err)
	}
	args, err := sfABI.Constructor.Inputs.Pack(e.dest, crypto.PubkeyToAddress(e.hotKey.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	s := &spike{tenv: e, sfABI: sfABI}
	s.sf = e.deploy(append(readBin(t, "testdata/SweepFactory.bin"), args...))
	var info struct {
		HardFork string `json:"hardFork"`
	}
	_ = rc.CallContext(ctx, &info, "anvil_nodeInfo")
	t.Logf("anvil hardfork: %q", info.HardFork)
	return s
}

func (s *spike) predict(salt [32]byte) common.Address {
	s.t.Helper()
	data, _ := s.sfABI.Pack("predict", salt)
	out, err := s.ec.CallContract(s.ctx, ethereum.CallMsg{To: &s.sf, Data: data}, nil)
	if err != nil {
		s.t.Fatal(err)
	}
	return common.BytesToAddress(out)
}

func (s *spike) destination() common.Address {
	data, _ := s.sfABI.Pack("destination")
	out, err := s.ec.CallContract(s.ctx, ethereum.CallMsg{To: &s.sf, Data: data}, nil)
	if err != nil {
		s.t.Fatal(err)
	}
	return common.BytesToAddress(out)
}

func (s *spike) code(a common.Address) []byte {
	c, err := s.ec.CodeAt(s.ctx, a, nil)
	if err != nil {
		s.t.Fatal(err)
	}
	return c
}

// call sends a transaction from key with a fixed gas limit and returns its
// receipt (which may show a revert).
func (s *spike) call(key *ecdsa.PrivateKey, method string, gas uint64, args ...any) *types.Receipt {
	s.t.Helper()
	data, err := s.sfABI.Pack(method, args...)
	if err != nil {
		s.t.Fatal(err)
	}
	if key == nil {
		key = s.deployer
	}
	return s.receipt(s.sendRaw(key, &s.sf, new(big.Int), data, gas).Hash())
}

func (s *spike) sweep(salt [32]byte, tokens ...common.Address) *types.Receipt {
	if tokens == nil {
		tokens = []common.Address{}
	}
	return s.call(nil, "sweep", 3_000_000, salt, tokens)
}

func (s *spike) sweepOK(salt [32]byte, tokens ...common.Address) *types.Receipt {
	s.t.Helper()
	r := s.sweep(salt, tokens...)
	if r.Status != 1 {
		s.t.Fatalf("sweep reverted")
	}
	return r
}

// deposit is a plain ETH send with the minimum 21,000 gas limit.
func (s *spike) deposit(a common.Address, wei int64) {
	s.t.Helper()
	r := s.receipt(s.sendRaw(s.deployer, &a, big.NewInt(wei), nil, 21000).Hash())
	if r.Status != 1 {
		s.t.Fatalf("plain 21,000-gas send to %s reverted", a)
	}
}

func saltOf(name string) [32]byte { return crypto.Keccak256Hash([]byte(name)) }

func TestSpikeRepeatedDepositSweepCycles(t *testing.T) {
	s := newSpike(t)
	e := s.tenv
	salt := saltOf("customer-1")
	a := s.predict(salt)
	if len(s.code(a)) != 0 {
		t.Fatal("code before the first sweep")
	}
	var ethWant, usdtWant, daiWant int64
	for round := int64(1); round <= 4; round++ {
		s.deposit(a, round*1_000_000_000_000_000) // 21,000-gas plain send, every round
		e.mint(e.usdt, a, round*1000)
		e.mint(e.dai, a, round*10)
		ethWant += round * 1_000_000_000_000_000
		usdtWant += round * 1000
		daiWant += round * 10
		r := s.sweepOK(salt, e.usdt, e.dai)
		t.Logf("round %d sweep gas used: %d", round, r.GasUsed)
		if got := e.balance(e.dest).Int64(); got != ethWant {
			t.Fatalf("round %d: destination ETH %d, want %d", round, got, ethWant)
		}
		if e.tokenBalance(e.usdt, e.dest).Int64() != usdtWant || e.tokenBalance(e.dai, e.dest).Int64() != daiWant {
			t.Fatalf("round %d: destination tokens wrong", round)
		}
		if e.balance(a).Sign() != 0 || e.tokenBalance(e.usdt, a).Sign() != 0 || e.tokenBalance(e.dai, a).Sign() != 0 {
			t.Fatalf("round %d: funds left on the deposit address", round)
		}
		if c := s.code(a); len(c) != 0 {
			t.Fatalf("round %d: eth_getCode = 0x%x, want empty", round, c)
		}
		// A 1 wei dust deposit swept with no token list, right before the next round
		// (the sequence that trips Foundry's --isolate mode, see docs/measurements/evm.md).
		s.deposit(a, 1)
		s.sweepOK(salt)
		ethWant++
		if got := e.balance(e.dest).Int64(); got != ethWant || e.balance(a).Sign() != 0 || len(s.code(a)) != 0 {
			t.Fatalf("round %d: dust sweep: destination %d want %d", round, got, ethWant)
		}
	}
}

func TestSpikeEthOnlyTokenOnlyBothEmpty(t *testing.T) {
	s := newSpike(t)
	e := s.tenv
	a1 := s.predict(saltOf("eth-only"))
	s.deposit(a1, 5000)
	s.sweepOK(saltOf("eth-only"), e.usdt)
	if e.balance(e.dest).Int64() != 5000 {
		t.Fatal("eth only")
	}
	a2 := s.predict(saltOf("tok-only")) // USDT-style: transfer returns nothing
	e.mint(e.usdt, a2, 77)
	s.sweepOK(saltOf("tok-only"), e.usdt)
	if e.tokenBalance(e.usdt, e.dest).Int64() != 77 {
		t.Fatal("usdt-style token only")
	}
	a3 := s.predict(saltOf("both"))
	s.deposit(a3, 1)
	e.mint(e.usdt, a3, 3)
	s.sweepOK(saltOf("both"), e.usdt)
	if e.balance(e.dest).Int64() != 5001 || e.tokenBalance(e.usdt, e.dest).Int64() != 80 {
		t.Fatal("both")
	}
	a4 := s.predict(saltOf("empty")) // nothing there: succeeds
	s.sweepOK(saltOf("empty"), e.usdt)
	for _, a := range []common.Address{a1, a2, a3, a4} {
		if len(s.code(a)) != 0 {
			t.Fatalf("code left on %s", a)
		}
	}
}

func TestSpikeSetDestination(t *testing.T) {
	s := newSpike(t)
	e := s.tenv
	salt := saltOf("mv")
	a := s.predict(salt)
	s.deposit(a, 1000)

	nk, _ := crypto.GenerateKey() // fresh address: anvil state outlives the test
	newDest := crypto.PubkeyToAddress(nk.PublicKey)
	if r := s.call(nil, "setDestination", 200_000, newDest); r.Status != 0 {
		t.Fatal("non-admin setDestination succeeded")
	}
	if got := s.destination(); got != e.dest {
		t.Fatalf("destination changed to %s", got)
	}
	if r := s.call(e.hotKey, "setDestination", 200_000, newDest); r.Status != 1 {
		t.Fatal("admin setDestination reverted")
	}
	if s.predict(salt) != a {
		t.Fatal("deposit address moved when the destination changed")
	}
	s.sweepOK(salt)
	if e.balance(newDest).Int64() != 1000 || e.balance(e.dest).Sign() != 0 {
		t.Fatalf("new %d old %d", e.balance(newDest).Int64(), e.balance(e.dest).Int64())
	}
}

// Same address twice in one transaction, and a token whose transfer reverts:
// everything reverts, nothing is stranded, no code is left behind.
func TestSpikeFailuresStrandNothing(t *testing.T) {
	s := newSpike(t)
	e := s.tenv
	bad := e.deploy(readBin(t, "testdata/FalseToken.bin"))

	salt := saltOf("dup")
	a := s.predict(salt)
	s.deposit(a, 4000)
	e.mint(e.usdt, a, 9)
	r := s.call(nil, "sweepMany", 3_000_000, [][32]byte{salt, salt}, []common.Address{e.usdt})
	if r.Status != 0 {
		t.Fatal("duplicate salt in one transaction did not revert")
	}
	t.Logf("duplicate salt: reverted, gas used %d of 3,000,000", r.GasUsed)
	if e.balance(a).Int64() != 4000 || e.tokenBalance(e.usdt, a).Int64() != 9 || len(s.code(a)) != 0 {
		t.Fatal("funds moved or code left after the reverted duplicate")
	}
	s.sweepOK(salt, e.usdt)
	if e.balance(e.dest).Int64() != 4000 || e.tokenBalance(e.usdt, e.dest).Int64() != 9 {
		t.Fatal("later sweep did not move the funds")
	}

	salt2 := saltOf("badtoken")
	a2 := s.predict(salt2)
	s.deposit(a2, 6000)
	e.mint(bad, a2, 1)
	e.mint(e.usdt, a2, 5)
	if r := s.sweep(salt2, e.usdt, bad); r.Status != 0 {
		t.Fatal("sweep with a reverting token succeeded")
	}
	if e.balance(a2).Int64() != 6000 || e.tokenBalance(e.usdt, a2).Int64() != 5 || len(s.code(a2)) != 0 {
		t.Fatal("funds moved or code left after a reverted sweep")
	}
	s.sweepOK(salt2, e.usdt) // leaving the bad token out recovers the rest
	if e.balance(e.dest).Int64() != 10000 || e.tokenBalance(e.usdt, e.dest).Int64() != 14 {
		t.Fatal("recovery sweep failed")
	}
	if e.tokenBalance(bad, a2).Int64() != 1 {
		t.Fatal("bad token balance should stay on the address")
	}
}

func TestSpikeGas(t *testing.T) {
	s := newSpike(t)
	e := s.tenv
	salt := saltOf("gas-1")
	a := s.predict(salt)
	for round := 1; round <= 2; round++ {
		s.deposit(a, 1000)
		e.mint(e.usdt, a, 5)
		r := s.sweepOK(salt, e.usdt)
		t.Logf("B single address, sweep %d (ETH + 1 token): gas used %d", round, r.GasUsed)
	}
	var salts [][32]byte
	for i := 0; i < 10; i++ {
		sl := saltOf("gas-batch-" + string(rune('a'+i)))
		salts = append(salts, sl)
		s.deposit(s.predict(sl), 1000)
		e.mint(e.usdt, s.predict(sl), 5)
	}
	r := s.call(nil, "sweepMany", 10_000_000, salts, []common.Address{e.usdt})
	if r.Status != 1 {
		t.Fatal("batch reverted")
	}
	t.Logf("B batch of 10 addresses (ETH + 1 token), one transaction: gas used %d", r.GasUsed)
	if e.balance(e.dest).Int64() != 2000+10_000 {
		t.Fatalf("destination ETH %d", e.balance(e.dest).Int64())
	}
}
