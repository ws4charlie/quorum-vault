package btce2e

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"
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
