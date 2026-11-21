package gen

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

// chain pays deposits from a funded key and reads balances: what the customers of a real system do outside it.
type chain struct {
	ec      *ethclient.Client
	key     *ecdsa.PrivateKey
	from    common.Address
	chainID *big.Int
	mu      sync.Mutex
	nonce   uint64
	price   *big.Int
}

func newChain(ctx context.Context, t *EVMTarget) (*chain, error) {
	// Connections are reused (a connection per poll runs out of ports through a port-forward); one that the node closed fails with EOF or a reset, and the
	// calls below try again.
	hc := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{MaxIdleConnsPerHost: 64, IdleConnTimeout: 5 * time.Second}}
	rc, err := rpc.DialOptions(ctx, t.RPC, rpc.WithHTTPClient(hc))
	if err != nil {
		return nil, err
	}
	ec := ethclient.NewClient(rc)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(t.FunderKeyFile)
	if err != nil {
		return nil, err
	}
	key, err := crypto.HexToECDSA(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", t.FunderKeyFile, err)
	}
	c := &chain{ec: ec, key: key, from: crypto.PubkeyToAddress(key.PublicKey), chainID: big.NewInt(t.ChainID)}
	if c.nonce, err = ec.PendingNonceAt(ctx, c.from); err != nil {
		return nil, err
	}
	if c.price, err = ec.SuggestGasPrice(ctx); err != nil {
		return nil, err
	}
	c.price = new(big.Int).Mul(c.price, big.NewInt(2))
	return c, nil
}

// send pays wei to an address and returns when the node has accepted the transaction. A connection that breaks mid-request (the node's port is
// published through Docker and resets connections under load) leaves the outcome open: the same signed transaction is looked up and, if the node never
// saw it, sent again, so a deposit is never paid twice.
func (c *chain) send(ctx context.Context, to common.Address, wei *big.Int) error {
	_, err := c.sendTx(ctx, to, wei)
	return err
}

// describe says what the node knows of a transaction (for the message of a deposit that never arrived).
func (c *chain) describe(h common.Hash) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, pending, err := c.ec.TransactionByHash(ctx, h)
	if err != nil {
		return "tx " + h.Hex()[:10] + ": " + err.Error()
	}
	rc, rerr := c.ec.TransactionReceipt(ctx, h)
	if rerr != nil {
		return fmt.Sprintf("tx %s nonce %d pending=%v no receipt: %v", h.Hex()[:10], tx.Nonce(), pending, rerr)
	}
	return fmt.Sprintf("tx %s nonce %d block %d status %d", h.Hex()[:10], tx.Nonce(), rc.BlockNumber, rc.Status)
}

func (c *chain) sendTx(ctx context.Context, to common.Address, wei *big.Int) (common.Hash, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// A deposit address is a contract once its first sweep has deployed the forwarder, and a transfer to it costs more than 21,000 gas: ask the node.
	gas, gerr := c.ec.EstimateGas(ctx, ethereum.CallMsg{From: c.from, To: &to, Value: wei})
	if gerr != nil || gas < 21000 {
		gas = 21000
	}
	gas = gas*13/10 + 1000
	tx := types.NewTx(&types.LegacyTx{Nonce: c.nonce, To: &to, Value: wei, Gas: gas, GasPrice: c.price})
	st, err := types.SignTx(tx, types.LatestSignerForChainID(c.chainID), c.key)
	if err != nil {
		return common.Hash{}, err
	}
	var last error
	for try := 0; try < 4; try++ {
		if try > 0 {
			if sleepCtx(ctx, 100*time.Millisecond); ctx.Err() != nil {
				return st.Hash(), &Failure{"chain", ctx.Err().Error()}
			}
			if _, _, err := c.ec.TransactionByHash(ctx, st.Hash()); err == nil { // it got there
				c.nonce++
				return st.Hash(), nil
			}
		}
		if last = c.ec.SendTransaction(ctx, st); last == nil {
			c.nonce++
			return st.Hash(), nil
		}
		// a nonce out of step (the key was used elsewhere): read it again and sign again
		if n, nerr := c.ec.PendingNonceAt(ctx, c.from); nerr == nil && n != c.nonce && strings.Contains(last.Error(), "nonce") {
			c.nonce = n
			tx = types.NewTx(&types.LegacyTx{Nonce: c.nonce, To: &to, Value: wei, Gas: gas, GasPrice: c.price})
			if st, err = types.SignTx(tx, types.LatestSignerForChainID(c.chainID), c.key); err != nil {
				return common.Hash{}, err
			}
		}
	}
	return st.Hash(), &Failure{"chain", last.Error()}
}

func (c *chain) balance(ctx context.Context, a common.Address) (*big.Int, error) {
	var last error
	for try := 0; try < 4; try++ {
		b, err := c.ec.BalanceAt(ctx, a, nil)
		if err == nil {
			return b, nil
		}
		last = err
		if ctx.Err() != nil {
			break
		}
		sleepCtx(ctx, 50*time.Millisecond)
	}
	return nil, &Failure{"chain", last.Error()}
}

func ethToWei(e float64) *big.Int {
	// float to wei at microether resolution: amounts are uniform draws, not accounting
	micro := int64(e*1e6 + 0.5)
	return new(big.Int).Mul(big.NewInt(micro), big.NewInt(1e12))
}

// AddressOfKeyFile is the address of the hex secp256k1 key in a file.
func AddressOfKeyFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	k, err := crypto.HexToECDSA(strings.TrimSpace(string(raw)))
	if err != nil {
		return "", err
	}
	return crypto.PubkeyToAddress(k.PublicKey).Hex(), nil
}
