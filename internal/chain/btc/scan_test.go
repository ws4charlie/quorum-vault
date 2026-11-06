package btc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
)

// fakeNode is a bitcoind that serves the four calls the scanner makes, from a chain of blocks the test builds and rewrites.
type fakeNode struct {
	mu     sync.Mutex
	blocks []Block // index = height
	srv    *httptest.Server
	// transactions: txid -> confirmations (0: in the mempool); a txid not here is unknown to the node
	txs     map[string]int64
	sent    []string // raw transactions given to sendrawtransaction
	sendErr *RPCError
}

type out struct {
	addr string
	val  string
}

func newNode(t *testing.T) *fakeNode {
	n := &fakeNode{txs: map[string]int64{}}
	n.srv = httptest.NewServer(http.HandlerFunc(n.serve))
	t.Cleanup(n.srv.Close)
	n.mine(nil...) // genesis
	return n
}

func (n *fakeNode) serve(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Method string            `json:"method"`
		Params []json.RawMessage `json:"params"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	n.mu.Lock()
	defer n.mu.Unlock()
	var res any
	switch req.Method {
	case "getblockchaininfo":
		res = map[string]any{"chain": "regtest"}
	case "estimatesmartfee":
		res = map[string]any{"errors": []string{"Insufficient data or no feerate found"}}
	case "getrawtransaction":
		var id string
		json.Unmarshal(req.Params[0], &id)
		c, ok := n.txs[id]
		if !ok {
			json.NewEncoder(w).Encode(map[string]any{"result": nil, "error": map[string]any{"code": -5, "message": "No such mempool or blockchain transaction"}})
			return
		}
		m := map[string]any{"txid": id}
		if c > 0 {
			m["confirmations"] = c
			m["blockhash"] = "bh"
		}
		res = m
	case "sendrawtransaction":
		var raw string
		json.Unmarshal(req.Params[0], &raw)
		n.sent = append(n.sent, raw)
		if n.sendErr != nil {
			json.NewEncoder(w).Encode(map[string]any{"result": nil, "error": n.sendErr})
			return
		}
		res = "sent"
	case "getblockcount":
		res = len(n.blocks) - 1
	case "getblockhash":
		var h int
		json.Unmarshal(req.Params[0], &h)
		if h < 0 || h >= len(n.blocks) {
			json.NewEncoder(w).Encode(map[string]any{"result": nil, "error": map[string]any{"code": -8, "message": "Block height out of range"}})
			return
		}
		res = n.blocks[h].Hash
	case "getblock":
		var hash string
		json.Unmarshal(req.Params[0], &hash)
		for _, b := range n.blocks {
			if b.Hash == hash {
				res = b
			}
		}
	}
	json.NewEncoder(w).Encode(map[string]any{"result": res, "error": nil})
}

var nonce int

// mine appends a block whose transactions are given (each a list of outputs; the first transaction is a coinbase when coinbase is set).
func (n *fakeNode) mine(txs ...[]out) { n.mineCB(false, txs...) }

func (n *fakeNode) mineCB(coinbase bool, txs ...[]out) {
	n.mu.Lock()
	defer n.mu.Unlock()
	nonce++
	b := Block{Height: uint64(len(n.blocks)), Hash: fmt.Sprintf("hash-%d-%d", len(n.blocks), nonce)}
	if len(n.blocks) > 0 {
		b.Previous = n.blocks[len(n.blocks)-1].Hash
	}
	for i, outs := range txs {
		tx := Tx{Txid: fmt.Sprintf("tx-%d-%d-%d", b.Height, i, nonce)}
		if coinbase && i == 0 {
			tx.Vin = []Vin{{Coinbase: "03"}}
		} else {
			tx.Vin = []Vin{{}}
		}
		for j, o := range outs {
			var vo Output
			vo.N = uint32(j)
			vo.Value = json.Number(o.val)
			vo.ScriptPubKey.Address = o.addr
			if o.addr == "" {
				vo.ScriptPubKey.Type = "nulldata"
			}
			tx.Vout = append(tx.Vout, vo)
		}
		b.Tx = append(b.Tx, tx)
	}
	n.blocks = append(n.blocks, b)
}

func (n *fakeNode) rewindTo(height int) { // drop blocks above height
	n.mu.Lock()
	n.blocks = n.blocks[:height+1]
	n.mu.Unlock()
}

func (n *fakeNode) height() int { n.mu.Lock(); defer n.mu.Unlock(); return len(n.blocks) - 1 }

func newAdapter(t *testing.T, n *fakeNode) (*Adapter, []string) {
	t.Helper()
	pool := dbtest.New(t)
	cfg := Config{Chain: "btc-t", Network: "regtest", RPCURL: n.srv.URL, AccountXpub: XpubFromNodeForTest(t), Confirmations: 6}
	a, err := New(context.Background(), cfg, pool)
	if err != nil {
		t.Fatal(err)
	}
	var addrs []string
	for i := 0; i < 3; i++ {
		d, err := a.DeriveDepositAddress(context.Background(), "c", uint64(i))
		if err != nil {
			t.Fatal(err)
		}
		cust := fmt.Sprintf("c%d", i)
		pool.Exec(context.Background(), `INSERT INTO customers (id, entity) VALUES ($1,'qv-us')`, cust)
		if _, err := pool.Exec(context.Background(), `INSERT INTO deposit_addresses (customer_id, chain, address, derivation_index, kind) VALUES ($1,$2,$3,$4,'xpub')`, cust, "btc-t", d.Address, i); err != nil {
			t.Fatal(err)
		}
		addrs = append(addrs, d.Address)
	}
	return a, addrs
}

// store applies what the custody service would: the block hashes of a result.
func store(t *testing.T, a *Adapter, res chain.ScanResult) {
	t.Helper()
	for _, b := range res.Blocks {
		if _, err := a.pool.Exec(context.Background(), `INSERT INTO scanned_blocks (chain, height, hash) VALUES ($1,$2,$3) ON CONFLICT (chain, height) DO UPDATE SET hash=EXCLUDED.hash`, "btc-t", b.Height, b.Hash); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDepositIsSeenAtSixConfirmationsNotFive(t *testing.T) {
	n := newNode(t)
	a, addrs := newAdapter(t, n)
	ctx := context.Background()
	n.mine()                         // 1
	n.mine([]out{{addrs[0], "0.5"}}) // block 2 holds the payment
	for n.height() < 6 {             // tip 6: block 2 has 5 confirmations
		n.mine()
	}
	res, err := a.Scan(ctx, 1)
	if err != nil || len(res.Deposits) != 0 || res.SafeHeadHeight != 1 {
		t.Fatalf("at depth 5: %+v %v", res, err)
	}
	store(t, a, res)
	n.mine() // tip 7: 6 confirmations
	res, err = a.Scan(ctx, 2)
	if err != nil || len(res.Deposits) != 1 || res.Deposits[0].Amount.String() != "50000000" || res.Deposits[0].BlockHeight != 2 || res.SafeHeadHeight != 2 {
		t.Fatalf("at depth 6: %+v %v", res, err)
	}
	// A rescan of the same blocks returns the same deposit with the same key.
	again, err := a.Scan(ctx, 2)
	if err != nil || len(again.Deposits) != 1 || again.Deposits[0].DedupKey != res.Deposits[0].DedupKey {
		t.Fatalf("rescan: %+v %v", again, err)
	}
}

func TestTwoOutputsOfOneTransactionAreTwoDeposits(t *testing.T) {
	n := newNode(t)
	a, addrs := newAdapter(t, n)
	n.mine([]out{{addrs[0], "0.1"}, {addrs[1], "0.2"}, {addrs[0], "0.3"}, {"", "0"}, {"bcrt1qnotours000000000000000000000000000000", "1"}})
	for n.height() < 8 {
		n.mine()
	}
	res, err := a.Scan(context.Background(), 1)
	if err != nil || len(res.Deposits) != 3 {
		t.Fatalf("%+v %v", res, err)
	}
	keys := map[string]bool{}
	for _, d := range res.Deposits {
		keys[d.DedupKey] = true
	}
	if len(keys) != 3 {
		t.Fatalf("dedup keys %v", keys)
	}
}

func TestCoinbaseOutputWaitsForMaturity(t *testing.T) {
	n := newNode(t)
	a, addrs := newAdapter(t, n)
	n.mineCB(true, []out{{addrs[0], "50"}}) // block 1: coinbase to a deposit address
	for n.height() < 7 {
		n.mine()
	}
	res, err := a.Scan(context.Background(), 1)
	if err != nil || len(res.Deposits) != 0 || len(res.Deferred) != 1 {
		t.Fatalf("immature coinbase: %+v %v", res, err)
	}
	d := res.Deferred[0]
	// Mature when the tip is at height 1+99 = 100; the scan then covers 100-6+1 = 95.
	if d.ReleaseAt != 95 {
		t.Fatalf("release at %d, want 95", d.ReleaseAt)
	}
	// Already mature when read late: a plain deposit.
	for n.height() < 120 {
		n.mine()
	}
	res, err = a.Scan(context.Background(), 1)
	if err != nil || len(res.Deposits) != 1 || len(res.Deferred) != 0 {
		t.Fatalf("mature coinbase: %+v %v", res, err)
	}
}

func TestBatchesAreBounded(t *testing.T) {
	n := newNode(t)
	a, _ := newAdapter(t, n)
	a.cfg.BatchBlocks = 10
	for n.height() < 60 {
		n.mine()
	}
	res, err := a.Scan(context.Background(), 1)
	if err != nil || len(res.Blocks) != 10 || res.SafeHeadHeight != 10 {
		t.Fatalf("%d blocks, head %d, %v", len(res.Blocks), res.SafeHeadHeight, err)
	}
}

// A block the scanner read is gone from the chain: deeper than the safe depth. Nothing is returned.
func TestDeepReorgIsRefused(t *testing.T) {
	n := newNode(t)
	a, addrs := newAdapter(t, n)
	ctx := context.Background()
	n.mine([]out{{addrs[0], "1"}})
	for n.height() < 10 {
		n.mine()
	}
	res, err := a.Scan(ctx, 1)
	if err != nil || len(res.Deposits) != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	store(t, a, res)
	last := res.SafeHeadHeight
	// The chain is rewritten from block 1 on (a 10-deep reorg) and grows past the old tip.
	n.rewindTo(0)
	for n.height() < 14 {
		n.mine()
	}
	if _, err := a.Scan(ctx, last+1); !errors.Is(err, chain.ErrReorgTooDeep) {
		t.Fatalf("after a deep reorg: %v", err)
	}
}

// A reorganization within the safe depth never reaches the scanner: the replaced block was not read yet.
func TestShallowReorgDoesNotCreditTheReplacedDeposit(t *testing.T) {
	n := newNode(t)
	a, addrs := newAdapter(t, n)
	ctx := context.Background()
	for n.height() < 3 {
		n.mine()
	}
	n.mine([]out{{addrs[0], "1"}}) // block 4, replaced below
	n.mine()
	n.mine()
	n.rewindTo(3)                  // the payment's block and its two successors are orphaned
	n.mine([]out{{addrs[1], "2"}}) // the replacement carries another payment
	for n.height() < 12 {
		n.mine()
	}
	res, err := a.Scan(ctx, 1)
	if err != nil || len(res.Deposits) != 1 || res.Deposits[0].Address != addrs[1] {
		t.Fatalf("%+v %v", res, err)
	}
}

func jsonNumber(s string) json.Number { return json.Number(s) }

// mineTx appends a block holding exactly the given transactions.
func (n *fakeNode) mineTx(txs ...Tx) {
	n.mu.Lock()
	defer n.mu.Unlock()
	nonce++
	b := Block{Height: uint64(len(n.blocks)), Hash: fmt.Sprintf("hash-%d-%d", len(n.blocks), nonce)}
	b.Previous = n.blocks[len(n.blocks)-1].Hash
	b.Tx = txs
	n.blocks = append(n.blocks, b)
}
