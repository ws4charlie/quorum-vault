package btc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"
)

// RPC is a plain JSON-RPC 1.0 client for bitcoind: no wallet calls, no electrs.
type RPC struct {
	url, user, pass string
	hc              *http.Client
	id              atomic.Int64
}

// NewRPC returns a client for url with basic auth.
func NewRPC(url, user, pass string) *RPC {
	return &RPC{url: url, user: user, pass: pass, hc: &http.Client{Timeout: 60 * time.Second}}
}

// RPCError is an error answer of the node.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Method  string `json:"-"`
}

func (e *RPCError) Error() string { return fmt.Sprintf("btc rpc %s: %s (%d)", e.Method, e.Message, e.Code) }

// Call runs method and decodes its result into out (nil: ignore).
func (r *RPC) Call(ctx context.Context, out any, method string, params ...any) error {
	if params == nil {
		params = []any{}
	}
	body, err := json.Marshal(map[string]any{"jsonrpc": "1.0", "id": r.id.Add(1), "method": method, "params": params})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.SetBasicAuth(r.user, r.pass)
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.hc.Do(req)
	if err != nil {
		return fmt.Errorf("btc rpc %s: %w", method, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	if err != nil {
		return fmt.Errorf("btc rpc %s: %w", method, err)
	}
	var env struct {
		Result json.RawMessage `json:"result"`
		Error  *RPCError       `json:"error"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("btc rpc %s: HTTP %d: %.200s", method, resp.StatusCode, raw)
	}
	if env.Error != nil {
		env.Error.Method = method
		return env.Error
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(env.Result, out)
}

// Block is the part of getblock verbosity 2 the scanner reads.
type Block struct {
	Hash     string `json:"hash"`
	Previous string `json:"previousblockhash"`
	Height   uint64 `json:"height"`
	Tx       []Tx   `json:"tx"`
}

// Tx is a transaction of a block.
type Tx struct {
	Txid string   `json:"txid"`
	Vin  []Vin    `json:"vin"`
	Vout []Output `json:"vout"`
}

// Vin is an input; a coinbase input has the Coinbase field set.
type Vin struct {
	Coinbase string `json:"coinbase"`
}

// Output is a transaction output. Value is the decimal BTC amount exactly as the node wrote it.
type Output struct {
	Value        json.Number `json:"value"`
	N            uint32      `json:"n"`
	ScriptPubKey struct {
		Type    string `json:"type"`
		Address string `json:"address"`
	} `json:"scriptPubKey"`
}

// BlockCount is the height of the tip.
func (r *RPC) BlockCount(ctx context.Context) (int64, error) {
	var n int64
	return n, r.Call(ctx, &n, "getblockcount")
}

// BlockHash is the hash of the block at height in the node's best chain.
func (r *RPC) BlockHash(ctx context.Context, height uint64) (string, error) {
	var h string
	return h, r.Call(ctx, &h, "getblockhash", height)
}

// GetBlock reads a whole block with its transactions decoded.
func (r *RPC) GetBlock(ctx context.Context, hash string) (Block, error) {
	var b Block
	return b, r.Call(ctx, &b, "getblock", hash, 2)
}
