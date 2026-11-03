// Package e2e runs the whole service (HTTP API, policy, approvals, audit,
// SoftHSM and 2-of-3 MPC signers) against a local anvil node that
// impersonates Sepolia (chain ID 11155111), so the transactions the sign path
// produces are broadcast unchanged, mined, and checked by receipt.
//
// The tests skip unless SEPOLIA_RPC_URL is set (QV_REQUIRE_CHAIN=1 turns the
// skip into a failure) and refuse any endpoint that CheckLocalChain rejects:
// they must never send anything to a real network.
package e2e

import (
	"context"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rpc"
)

// SepoliaChainID is the chain ID the local node must report.
const SepoliaChainID int64 = 11155111

// localHosts are the only RPC hosts the tests may talk to: loopback, and
// "anvil", the service name in docker-compose.yml.
var localHosts = map[string]bool{"localhost": true, "127.0.0.1": true, "::1": true, "anvil": true}

// CheckLocalChain returns nil only when rpcURL is a local anvil node with
// chain ID 11155111. The host is checked before any connection is made, so a
// remote URL is refused without sending it a single request.
func CheckLocalChain(ctx context.Context, rpcURL string) error {
	u, err := url.Parse(rpcURL)
	if err != nil {
		return fmt.Errorf("e2e: parse rpc url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "ws" {
		return fmt.Errorf("e2e: refusing rpc url scheme %q: only plain http/ws to a local node", u.Scheme)
	}
	host := u.Hostname()
	if !localHosts[strings.ToLower(host)] {
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			return fmt.Errorf("e2e: refusing rpc host %q: only localhost, 127.0.0.1, ::1 or anvil", host)
		}
	}
	c, err := rpc.DialContext(ctx, rpcURL)
	if err != nil {
		return fmt.Errorf("e2e: dial %s: %w", rpcURL, err)
	}
	defer c.Close()
	var client string
	if err := c.CallContext(ctx, &client, "web3_clientVersion"); err != nil {
		return fmt.Errorf("e2e: web3_clientVersion: %w", err)
	}
	if !strings.Contains(strings.ToLower(client), "anvil") {
		return fmt.Errorf("e2e: refusing node %q: not anvil", client)
	}
	var id hexutil.Big
	if err := c.CallContext(ctx, &id, "eth_chainId"); err != nil {
		return fmt.Errorf("e2e: eth_chainId: %w", err)
	}
	if id.ToInt().Cmp(big.NewInt(SepoliaChainID)) != 0 {
		return fmt.Errorf("e2e: refusing chain id %s: want %d", id.ToInt(), SepoliaChainID)
	}
	return nil
}

// SetBalance sets addr's balance with anvil_setBalance (no transfer, no
// funded account needed). Call CheckLocalChain first.
func SetBalance(ctx context.Context, rpcURL string, addr common.Address, wei *big.Int) error {
	c, err := rpc.DialContext(ctx, rpcURL)
	if err != nil {
		return fmt.Errorf("e2e: dial %s: %w", rpcURL, err)
	}
	defer c.Close()
	if err := c.CallContext(ctx, nil, "anvil_setBalance", addr, (*hexutil.Big)(wei)); err != nil {
		return fmt.Errorf("e2e: anvil_setBalance %s: %w", addr.Hex(), err)
	}
	return nil
}
