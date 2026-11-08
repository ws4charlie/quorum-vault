package btce2e

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/btcsuite/btcd/wire"
)

// noEstimateProxy is a JSON-RPC proxy in front of bitcoind for the systems whose tests assume the builder's configured fallback fee rate. It answers
// estimatesmartfee exactly as a node without data does, so the answer does not depend on what ran on the node before, and forwards everything else
// (path, headers including authentication, body, status and errors) untouched. A node that is down or restarted looks the same through it as without it.
// It is test code only: the system's core and worker use its URL as rpc_url.
func noEstimateProxy(t *testing.T) string {
	t.Helper()
	target, err := url.Parse(nodeURL())
	if err != nil {
		t.Fatal(err)
	}
	fwd := httputil.NewSingleHostReverseProxy(target)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var req struct {
			Method string          `json:"method"`
			ID     json.RawMessage `json:"id"`
		}
		if json.Unmarshal(body, &req) == nil && req.Method == "estimatesmartfee" {
			if len(req.ID) == 0 {
				req.ID = json.RawMessage("null")
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"result":{"errors":["Insufficient data or no feerate found"],"blocks":0},"error":null,"id":` + string(req.ID) + "}\n"))
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		fwd.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// feeProxy is a JSON-RPC proxy in front of bitcoind that makes the node refuse a transaction the way a node with a higher mempool minimum fee does:
// sendrawtransaction of a transaction that pays less than minFee satoshis gets the node's own message for it ("mempool min fee not met, X < Y",
// code -26), and one that pays at least that is forwarded to the real node, which takes or refuses it by its own rules. As on a real node the
// refusal is reflected in getmempoolinfo (mempoolminfee is the minimum fee rate the proxy asks for), so lowering the minimum is a change of the fee
// market the system can see. other, when set, makes the proxy refuse every sendrawtransaction with that message instead: a refusal a higher fee does not
// cure. estimatesmartfee answers as a node without data (like noEstimateProxy), so the builder's fee rate is the configured fallback. Everything else is
// forwarded untouched. It records every transaction it was offered, in order. Test code only.
type feeProxy struct {
	url string

	mu     sync.Mutex
	minFee int64  // satoshis; 0: no minimum beyond the node's own
	other  string // a non-fee refusal for every sendrawtransaction; "": none
	vsize  int64  // virtual size of the last transaction offered, to turn minFee into a fee rate
	sends  []proxySend
}

// proxySend is a transaction offered to sendrawtransaction.
type proxySend struct {
	Txid    string
	Fee     int64
	Verdict string // "taken" (the node took it), "fee" (refused by the minimum), "other" (refused by other), "node" (the node itself refused it)
}

func newFeeProxy(t *testing.T) *feeProxy {
	t.Helper()
	target, err := url.Parse(nodeURL())
	if err != nil {
		t.Fatal(err)
	}
	p := &feeProxy{}
	fwd := httputil.NewSingleHostReverseProxy(target)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var req struct {
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
			ID     json.RawMessage   `json:"id"`
		}
		_ = json.Unmarshal(body, &req)
		if len(req.ID) == 0 {
			req.ID = json.RawMessage("null")
		}
		reply := func(status int, result, errObj string) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			w.Write([]byte(`{"result":` + result + `,"error":` + errObj + `,"id":` + string(req.ID) + "}\n"))
		}
		switch req.Method {
		case "estimatesmartfee":
			reply(200, `{"errors":["Insufficient data or no feerate found"],"blocks":0}`, "null")
			return
		case "sendrawtransaction":
			if len(req.Params) > 0 && p.send(t, r, req.Params[0], reply) {
				return
			}
		case "getmempoolinfo":
			if p.mempoolInfo(t, r, body, w) {
				return
			}
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		fwd.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	p.url = srv.URL
	return p
}

// setMin sets the minimum fee, in satoshis, below which the proxy refuses a transaction as the mempool minimum would.
func (p *feeProxy) setMin(sats int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.minFee = sats
}

// setOther makes every sendrawtransaction fail with msg, a refusal a higher fee does not cure; "" ends it.
func (p *feeProxy) setOther(msg string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.other = msg
}

// offered is a copy of every transaction offered so far.
func (p *feeProxy) offered() []proxySend {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]proxySend(nil), p.sends...)
}

func (p *feeProxy) call(t *testing.T, r *http.Request, method string, params ...any) (json.RawMessage, error) {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "1.0", "id": 1, "method": method, "params": params})
	req, err := http.NewRequest(http.MethodPost, nodeURL(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", r.Header.Get("Authorization"))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var env struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return nil, err
	}
	if env.Error != nil {
		return nil, fmt.Errorf("%s: %s", method, env.Error.Message)
	}
	return env.Result, nil
}

// send judges one sendrawtransaction. It reports true when it answered (a refusal); false means: forward it to the node.
func (p *feeProxy) send(t *testing.T, r *http.Request, param json.RawMessage, reply func(int, string, string)) bool {
	var rawHex string
	if json.Unmarshal(param, &rawHex) != nil {
		return false
	}
	raw, err := hex.DecodeString(rawHex)
	if err != nil {
		return false
	}
	var tx wire.MsgTx
	if tx.Deserialize(bytes.NewReader(raw)) != nil {
		return false
	}
	var in int64
	for _, ti := range tx.TxIn {
		res, err := p.call(t, r, "getrawtransaction", ti.PreviousOutPoint.Hash.String(), true)
		if err != nil {
			return false
		}
		var prev struct {
			Vout []struct {
				Value json.Number `json:"value"`
				N     uint32      `json:"n"`
			} `json:"vout"`
		}
		if json.Unmarshal(res, &prev) != nil {
			return false
		}
		for _, o := range prev.Vout {
			if o.N == ti.PreviousOutPoint.Index {
				in += sats(o.Value)
			}
		}
	}
	var out int64
	for _, o := range tx.TxOut {
		out += o.Value
	}
	fee := in - out
	weight := int64(tx.SerializeSizeStripped())*3 + int64(tx.SerializeSize())
	rec := proxySend{Txid: tx.TxHash().String(), Fee: fee}

	p.mu.Lock()
	p.vsize = (weight + 3) / 4
	other, minFee := p.other, p.minFee
	verdict := ""
	switch {
	case other != "":
		verdict = "other"
	case fee < minFee:
		verdict = "fee"
	}
	rec.Verdict = verdict
	if verdict != "" {
		p.sends = append(p.sends, rec)
	}
	p.mu.Unlock()

	switch verdict {
	case "other":
		reply(http.StatusInternalServerError, "null", fmt.Sprintf(`{"code":-26,"message":%q}`, other))
		return true
	case "fee":
		reply(http.StatusInternalServerError, "null", fmt.Sprintf(`{"code":-26,"message":"mempool min fee not met, %d < %d"}`, fee, minFee))
		return true
	}
	// The node decides. What it answers is recorded by asking it here and replaying the answer.
	res, err := p.call(t, r, "sendrawtransaction", rawHex)
	rec.Verdict = "taken"
	if err != nil {
		rec.Verdict = "node"
		if strings.Contains(err.Error(), "already") {
			rec.Verdict = "known"
		}
	}
	p.mu.Lock()
	p.sends = append(p.sends, rec)
	p.mu.Unlock()
	if err != nil {
		return false // let the node answer again in its own words
	}
	reply(200, string(res), "null")
	return true
}

// mempoolInfo answers getmempoolinfo with the node's own answer, except that mempoolminfee is at least the fee rate the proxy's minimum asks for.
func (p *feeProxy) mempoolInfo(t *testing.T, r *http.Request, body []byte, w http.ResponseWriter) bool {
	p.mu.Lock()
	minFee, vs := p.minFee, p.vsize
	p.mu.Unlock()
	if minFee == 0 || vs == 0 {
		return false
	}
	res, err := p.call(t, r, "getmempoolinfo")
	if err != nil {
		return false
	}
	var info map[string]any
	if json.Unmarshal(res, &info) != nil {
		return false
	}
	rate := float64(minFee) / float64(vs) / 1e5 // BTC per kvB
	if cur, _ := info["mempoolminfee"].(float64); rate > cur {
		info["mempoolminfee"] = rate
	}
	b, _ := json.Marshal(info)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"result":` + string(b) + `,"error":null,"id":1}` + "\n"))
	return true
}

// sats converts a decimal BTC amount as the node wrote it to satoshis.
func sats(v json.Number) int64 {
	r, ok := new(big.Rat).SetString(v.String())
	if !ok {
		return 0
	}
	r.Mul(r, big.NewRat(100_000_000, 1))
	return new(big.Int).Div(r.Num(), r.Denom()).Int64()
}
