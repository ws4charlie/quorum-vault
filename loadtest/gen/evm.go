package gen

import (
	"context"
	"crypto/ecdsa"
	"errors"
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
	// pending is the one signed payment whose outcome is not yet known; payments is every payment made
	pending  *types.Transaction
	payments []Payment
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

// Payment is one payment the generator made on the chain, kept independently of what the books say: the check at the end compares each customer's credits
// with exactly these.
type Payment struct {
	To    common.Address
	Wei   *big.Int
	Hash  common.Hash
	State string // "sent": the node accepted it; "unknown": the outcome could not be learnt (it may or may not be on the chain)
}

// Payments returns every payment made so far.
func (c *chain) Payments() []Payment {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Payment(nil), c.payments...)
}

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

// known asks whether the node has the transaction: yes, no (a definite "not found"), or an error (the answer is not known).
func (c *chain) known(ctx context.Context, h common.Hash) (bool, error) {
	_, _, err := c.ec.TransactionByHash(ctx, h)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, ethereum.NotFound):
		return false, nil
	}
	return false, err
}

// resolve settles the one payment whose outcome is open (c.pending), or says it cannot yet. The signed transaction is kept until its fate is known: it is
// looked up, and sent again if the node has not got it. An advanced nonce is no proof that another sender used it: only a definite "not found" for our
// hash after a "nonce too low" shows that, and then the nonce is read again. A lookup that fails leaves the payment pending and every later payment waits.
func (c *chain) resolve(ctx context.Context) error {
	for try := 0; try < 6 && c.pending != nil; try++ {
		if try > 0 {
			sleepCtx(ctx, 150*time.Millisecond)
			if ctx.Err() != nil {
				break
			}
		}
		h := c.pending.Hash()
		if ok, err := c.known(ctx, h); err == nil && ok { // it is there
			c.nonce = c.pending.Nonce() + 1
			c.markSent()
			return nil
		} else if err != nil {
			continue // cannot tell: ask again, do not send again blind
		}
		// the node has definitely not got it: send it again
		err := c.ec.SendTransaction(ctx, c.pending)
		if err == nil || strings.Contains(err.Error(), "already known") {
			c.nonce = c.pending.Nonce() + 1
			c.markSent()
			return nil
		}
		if strings.Contains(err.Error(), "nonce too low") {
			// the nonce was used, and our hash is not found: either by someone else, or our own earlier send landed and the lookup raced. Ask once more, definitely.
			if ok, kerr := c.known(ctx, h); kerr == nil {
				if ok {
					c.nonce = c.pending.Nonce() + 1
					c.markSent()
					return nil
				}
				// definitely not ours: the nonce was taken by another sender; this payment never happened
				n, nerr := c.ec.PendingNonceAt(ctx, c.from)
				if nerr == nil {
					c.nonce = n
					c.dropPending("nonce taken by another sender")
					return nil
				}
			}
		}
	}
	if c.pending != nil {
		return &Failure{"chain_unresolved", "the outcome of payment " + c.pending.Hash().Hex()[:10] + " is not known"}
	}
	return nil
}

// markSent records that the open payment is on the chain and closes it.
func (c *chain) markSent() {
	for i := range c.payments {
		if c.payments[i].Hash == c.pending.Hash() {
			c.payments[i].State = "sent"
		}
	}
	c.pending = nil
}

// dropPending forgets the open payment: it is known not to be on the chain.
func (c *chain) dropPending(why string) {
	for i := range c.payments {
		if c.payments[i].Hash == c.pending.Hash() {
			c.payments = append(c.payments[:i], c.payments[i+1:]...)
			break
		}
	}
	c.pending = nil
}

func (c *chain) sendTx(ctx context.Context, to common.Address, wei *big.Int) (common.Hash, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.resolve(ctx); err != nil {
		return common.Hash{}, err
	}
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
	c.pending = st
	c.payments = append(c.payments, Payment{To: to, Wei: new(big.Int).Set(wei), Hash: st.Hash(), State: "unknown"})
	idx := len(c.payments) - 1
	if err := c.ec.SendTransaction(ctx, st); err == nil {
		c.nonce++
		c.pending = nil
		c.payments[idx].State = "sent"
		return st.Hash(), nil
	}
	// the reply was an error or never came: settle it from the node, with the same signed transaction
	if err := c.resolve(ctx); err != nil {
		return st.Hash(), err // still pending and recorded as unknown: the check at the end allows for it
	}
	for i := range c.payments {
		if c.payments[i].Hash == st.Hash() {
			c.payments[i].State = "sent"
			return st.Hash(), nil
		}
	}
	return st.Hash(), &Failure{"chain", "the payment did not happen (its nonce was taken by another sender)"}
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
