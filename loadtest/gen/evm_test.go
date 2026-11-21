package gen

import (
	"context"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// fakeNode is a JSON-RPC node that mines every transaction at once, and can lose the reply to a send and fail the lookups that follow.
type fakeNode struct {
	mu           sync.Mutex
	txs          map[common.Hash]*types.Transaction
	nonce        uint64
	dropNextSend bool // record the transaction, then cut the connection: the reply is lost
	failLookups  int  // this many hash lookups answer HTTP 500
	sends        int
}

func (n *fakeNode) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID     json.RawMessage   `json:"id"`
		Method string            `json:"method"`
		Params []json.RawMessage `json:"params"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	n.mu.Lock()
	defer n.mu.Unlock()
	reply := func(res any, rpcErr string) {
		m := map[string]any{"jsonrpc": "2.0", "id": req.ID}
		if rpcErr != "" {
			m["error"] = map[string]any{"code": -32000, "message": rpcErr}
		} else {
			m["result"] = res
		}
		_ = json.NewEncoder(w).Encode(m)
	}
	switch req.Method {
	case "eth_chainId":
		reply("0x1", "")
	case "eth_gasPrice":
		reply("0x3b9aca00", "")
	case "eth_getTransactionCount":
		reply(hexutil.EncodeUint64(n.nonce), "")
	case "eth_estimateGas":
		reply("0x5208", "")
	case "eth_sendRawTransaction":
		n.sends++
		var raw hexutil.Bytes
		_ = json.Unmarshal(req.Params[0], &raw)
		tx := new(types.Transaction)
		if err := tx.UnmarshalBinary(raw); err != nil {
			reply(nil, err.Error())
			return
		}
		if tx.Nonce() < n.nonce {
			reply(nil, "nonce too low")
			return
		}
		n.txs[tx.Hash()] = tx
		n.nonce = tx.Nonce() + 1
		if n.dropNextSend {
			n.dropNextSend = false
			hj, _ := w.(http.Hijacker)
			c, _, _ := hj.Hijack()
			c.Close()
			return
		}
		reply(tx.Hash().Hex(), "")
	case "eth_getTransactionByHash":
		if n.failLookups > 0 {
			n.failLookups--
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		var h common.Hash
		_ = json.Unmarshal(req.Params[0], &h)
		tx, ok := n.txs[h]
		if !ok {
			reply(nil, "")
			return
		}
		b, _ := json.Marshal(tx)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		m["blockNumber"], m["blockHash"], m["transactionIndex"] = "0x1", h.Hex(), "0x0"
		reply(m, "")
	default:
		reply(nil, "unsupported "+req.Method)
	}
}

func newTestChain(t *testing.T, n *fakeNode) *chain {
	t.Helper()
	srv := httptest.NewServer(n)
	t.Cleanup(srv.Close)
	k, _ := crypto.GenerateKey()
	kf := filepath.Join(t.TempDir(), "k")
	if err := os.WriteFile(kf, []byte(common.Bytes2Hex(crypto.FromECDSA(k))), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := newChain(context.Background(), &EVMTarget{RPC: srv.URL, FunderKeyFile: kf, ChainID: 1})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// A reply that is lost, and a lookup that fails after it, must not make the generator pay twice: the same signed transaction is kept until its fate is known.
func TestLostReplyAndFailedLookupDoNotPayTwice(t *testing.T) {
	n := &fakeNode{txs: map[common.Hash]*types.Transaction{}, dropNextSend: true, failLookups: 2}
	c := newTestChain(t, n)
	to := common.HexToAddress("0x01")
	if _, err := c.sendTx(context.Background(), to, big.NewInt(5)); err != nil {
		t.Fatalf("send: %v", err)
	}
	if _, err := c.sendTx(context.Background(), to, big.NewInt(7)); err != nil {
		t.Fatalf("second send: %v", err)
	}
	if len(n.txs) != 2 {
		t.Fatalf("the node holds %d transactions, want exactly 2 (one per payment)", len(n.txs))
	}
	seen := map[uint64]bool{}
	for _, tx := range n.txs {
		if seen[tx.Nonce()] {
			t.Fatalf("two transactions with nonce %d", tx.Nonce())
		}
		seen[tx.Nonce()] = true
	}
	ps := c.Payments()
	if len(ps) != 2 || ps[0].State != "sent" || ps[1].State != "sent" {
		t.Fatalf("payments %+v", ps)
	}
}

// When no lookup ever works, the payment stays open and recorded as unknown, later payments wait, and nothing is signed with a new nonce.
func TestUnresolvedPaymentIsKeptAndRecorded(t *testing.T) {
	n := &fakeNode{txs: map[common.Hash]*types.Transaction{}, dropNextSend: true, failLookups: 1000}
	c := newTestChain(t, n)
	to := common.HexToAddress("0x02")
	if _, err := c.sendTx(context.Background(), to, big.NewInt(5)); err == nil {
		t.Fatal("expected the outcome to be unresolved")
	}
	if _, err := c.sendTx(context.Background(), to, big.NewInt(7)); err == nil {
		t.Fatal("a later payment must wait for the open one")
	}
	if len(n.txs) != 1 {
		t.Fatalf("the node holds %d transactions, want 1: nothing may be signed again", len(n.txs))
	}
	ps := c.Payments()
	if len(ps) != 1 || ps[0].State != "unknown" || ps[0].Wei.Int64() != 5 {
		t.Fatalf("payments %+v", ps)
	}
	// the node recovers: the next call settles the open payment from the same signed transaction, then pays
	n.mu.Lock()
	n.failLookups = 0
	n.mu.Unlock()
	if _, err := c.sendTx(context.Background(), to, big.NewInt(7)); err != nil {
		t.Fatalf("after recovery: %v", err)
	}
	if len(n.txs) != 2 || n.sends != 2 {
		t.Fatalf("txs %d sends %d", len(n.txs), n.sends)
	}
	if ps := c.Payments(); ps[0].State != "sent" || ps[1].State != "sent" {
		t.Fatalf("payments %+v", ps)
	}
}
