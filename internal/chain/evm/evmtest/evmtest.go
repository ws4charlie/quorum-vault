// Package evmtest holds what tests need of a local anvil node that stands in for Base Sepolia (chain 84532): the node check, a deployed EIP-3009 test
// token (contracts/test/mocks/Tokens.sol, Eip3009Token, behaving as Circle's USDC does), and the call a facilitator makes. It is test support: nothing
// outside tests imports it, and it refuses any node that is not a local anvil.
//
// A node is taken from QV_ANVIL_RPC (default http://127.0.0.1:18546, the compose node `anvil-base-sepolia`). In a CI lane that node is the lane's own anvil, so a test may set its chain id
// (anvil_setChainId) to 84532; the lane belongs to the group that runs it. A test is skipped without a node unless QV_REQUIRE_CHAIN=1.
package evmtest

import (
	"context"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/ws4charlie/quorum-vault/internal/chain/evm"
)

// BaseSepoliaChainID is the chain id of Base Sepolia, which the local node takes.
const BaseSepoliaChainID = 84532

// Node is a local anvil node on a given chain id.
type Node struct {
	URL string
	RPC *rpc.Client
	// Facilitator is an unlocked anvil account that pays the gas of what it sends, as an x402 facilitator does.
	Facilitator common.Address
}

// Anvil returns the node of QV_ANVIL_RPC with its chain id set to chainID. It skips the test when there is no node (fails with QV_REQUIRE_CHAIN=1) and
// refuses a node that is not a local anvil.
func Anvil(t testing.TB, chainID uint64) *Node {
	t.Helper()
	u := os.Getenv("QV_ANVIL_RPC")
	if u == "" {
		u = "http://127.0.0.1:18546" // the Base Sepolia node of docker-compose.yml (make base-up), not the Sepolia one the other e2e tests use
	}
	fail := func(format string, args ...any) {
		t.Helper()
		if os.Getenv("QV_REQUIRE_CHAIN") == "1" {
			t.Fatalf("evmtest (QV_REQUIRE_CHAIN=1): "+format, args...)
		}
		t.Skipf("evmtest: "+format, args...)
	}
	pu, err := url.Parse(u)
	if err != nil || (pu.Scheme != "http" && pu.Scheme != "ws") {
		t.Fatalf("evmtest: refusing rpc url %q", u)
	}
	if h := strings.ToLower(pu.Hostname()); h != "localhost" && h != "anvil" {
		if ip := net.ParseIP(h); ip == nil || !ip.IsLoopback() {
			t.Fatalf("evmtest: refusing rpc host %q: only a local anvil", h)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := rpc.DialContext(ctx, u)
	if err != nil {
		fail("dial %s: %v", u, err)
	}
	t.Cleanup(c.Close)
	var client string
	if err := c.CallContext(ctx, &client, "web3_clientVersion"); err != nil {
		fail("no node at %s: %v", u, err)
	}
	if !strings.Contains(strings.ToLower(client), "anvil") {
		t.Fatalf("evmtest: refusing node %q: not anvil", client)
	}
	var id hexutil.Big
	if err := c.CallContext(ctx, &id, "eth_chainId"); err != nil {
		t.Fatal(err)
	}
	if id.ToInt().Uint64() != chainID {
		if err := c.CallContext(ctx, nil, "anvil_setChainId", hexutil.Uint64(chainID)); err != nil {
			t.Fatalf("evmtest: anvil_setChainId %d: %v", chainID, err)
		}
		// A node that was not ours stays as it was found: the chain id goes back when the test ends (before the connection closes).
		orig := id.ToInt().Uint64()
		t.Cleanup(func() {
			rctx, rcancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer rcancel()
			if err := c.CallContext(rctx, nil, "anvil_setChainId", hexutil.Uint64(orig)); err != nil {
				t.Errorf("evmtest: restore chain id %d: %v", orig, err)
			}
		})
	}
	var accts []common.Address
	if err := c.CallContext(ctx, &accts, "eth_accounts"); err != nil || len(accts) == 0 {
		t.Fatalf("evmtest: eth_accounts: %v", err)
	}
	return &Node{URL: u, RPC: c, Facilitator: accts[len(accts)-1]}
}

func readTestdata(t testing.TB, name string) []byte {
	t.Helper()
	_, f, _, _ := runtime.Caller(0)
	b, err := os.ReadFile(filepath.Join(filepath.Dir(f), "..", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (n *Node) send(t testing.TB, to *common.Address, data []byte, gas uint64) (*types.Receipt, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	msg := map[string]any{"from": n.Facilitator, "data": hexutil.Bytes(data), "gas": hexutil.Uint64(gas)}
	if to != nil {
		msg["to"] = *to
	}
	var hash common.Hash
	if err := n.RPC.CallContext(ctx, &hash, "eth_sendTransaction", msg); err != nil {
		return nil, err
	}
	for {
		var r *types.Receipt
		if err := n.RPC.CallContext(ctx, &r, "eth_getTransactionReceipt", hash); err != nil {
			return nil, err
		}
		if r != nil {
			return r, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// Token is a deployed Eip3009Token.
type Token struct {
	n       *Node
	Address common.Address
	abi     abi.ABI
}

// DeployToken deploys the EIP-3009 test token with EIP-712 name (version "2", 6 decimals, as Circle's USDC).
func (n *Node) DeployToken(t testing.TB, name string) *Token {
	t.Helper()
	a, err := abi.JSON(strings.NewReader(string(readTestdata(t, "Eip3009Token.abi.json"))))
	if err != nil {
		t.Fatal(err)
	}
	args, err := a.Pack("", name)
	if err != nil {
		t.Fatal(err)
	}
	code := common.FromHex(strings.TrimSpace(string(readTestdata(t, "Eip3009Token.bin"))))
	r, err := n.send(t, nil, append(code, args...), 8_000_000)
	if err != nil || r.Status != 1 {
		t.Fatalf("evmtest: deploy token: %v %+v", err, r)
	}
	return &Token{n: n, Address: r.ContractAddress, abi: a}
}

func (k *Token) call(t testing.TB, method string, args ...any) (*types.Receipt, error) {
	t.Helper()
	data, err := k.abi.Pack(method, args...)
	if err != nil {
		t.Fatal(err)
	}
	return k.n.send(t, &k.Address, data, 500_000)
}

// Mint gives amount to account.
func (k *Token) Mint(t testing.TB, to common.Address, amount int64) {
	t.Helper()
	if r, err := k.call(t, "mint", to, big.NewInt(amount)); err != nil || r.Status != 1 {
		t.Fatalf("evmtest: mint: %v %+v", err, r)
	}
}

// BalanceOf reads a balance.
func (k *Token) BalanceOf(t testing.TB, who common.Address) *big.Int {
	t.Helper()
	return k.read(t, "balanceOf", who)
}

func (k *Token) read(t testing.TB, method string, args ...any) *big.Int {
	t.Helper()
	data, err := k.abi.Pack(method, args...)
	if err != nil {
		t.Fatal(err)
	}
	var out hexutil.Bytes
	if err := k.n.RPC.CallContext(context.Background(), &out, "eth_call", map[string]any{"to": k.Address, "data": hexutil.Bytes(data)}, "latest"); err != nil {
		t.Fatal(err)
	}
	return new(big.Int).SetBytes(out)
}

// Used reports authorizationState(authorizer, nonce).
func (k *Token) Used(t testing.TB, authorizer common.Address, nonce [32]byte) bool {
	t.Helper()
	return k.read(t, "authorizationState", authorizer, nonce).Sign() != 0
}

// DomainSeparator reads the token's own DOMAIN_SEPARATOR().
func (k *Token) DomainSeparator(t testing.TB) [32]byte {
	t.Helper()
	var out [32]byte
	k.read(t, "DOMAIN_SEPARATOR").FillBytes(out[:])
	return out
}

// BlockTime is the timestamp of the latest block.
func (n *Node) BlockTime(t testing.TB) uint64 {
	t.Helper()
	var b struct {
		Time hexutil.Uint64 `json:"timestamp"`
	}
	if err := n.RPC.CallContext(context.Background(), &b, "eth_getBlockByNumber", "latest", false); err != nil {
		t.Fatal(err)
	}
	return uint64(b.Time)
}

// Submit is the facilitator: it calls transferWithAuthorization with the authorization and the signature (v, r, s) and returns the receipt, or the error
// of a call the token refuses (anvil reports the revert when it estimates the call).
func (k *Token) Submit(t testing.TB, a evm.Authorization, v byte, r, s [32]byte) (*types.Receipt, error) {
	t.Helper()
	return k.call(t, "transferWithAuthorization", a.From, a.To, a.Value, new(big.Int).SetUint64(a.ValidAfter), new(big.Int).SetUint64(a.ValidBefore), a.Nonce, v, r, s)
}

// Warp moves the node's clock forward by seconds and mines a block, so that a later block is at or past a validBefore.
func (n *Node) Warp(t testing.TB, seconds uint64) {
	t.Helper()
	ctx := context.Background()
	if err := n.RPC.CallContext(ctx, nil, "evm_increaseTime", hexutil.Uint64(seconds)); err != nil {
		t.Fatal(err)
	}
	if err := n.RPC.CallContext(ctx, nil, "evm_mine"); err != nil {
		t.Fatal(err)
	}
}
