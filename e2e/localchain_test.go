package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeNode is a JSON-RPC endpoint on 127.0.0.1 that answers web3_clientVersion
// and eth_chainId with fixed values.
func fakeNode(t *testing.T, client, chainIDHex string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		res := map[string]any{"jsonrpc": "2.0", "id": req.ID}
		switch req.Method {
		case "web3_clientVersion":
			res["result"] = client
		case "eth_chainId":
			res["result"] = chainIDHex
		default:
			res["error"] = map[string]any{"code": -32601, "message": "method not found"}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(res)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestCheckLocalChainAcceptsLocalAnvil(t *testing.T) {
	url := fakeNode(t, "anvil/v1.8.5", "0xaa36a7")
	if err := CheckLocalChain(context.Background(), url); err != nil {
		t.Fatal(err)
	}
}

func TestCheckLocalChainRefusesNonAnvil(t *testing.T) {
	url := fakeNode(t, "Geth/v1.14.0-stable/linux-amd64/go1.22", "0xaa36a7")
	err := CheckLocalChain(context.Background(), url)
	if err == nil || !strings.Contains(err.Error(), "not anvil") {
		t.Fatalf("err = %v, want refusal of a non-anvil node", err)
	}
}

func TestCheckLocalChainRefusesWrongChainID(t *testing.T) {
	for _, id := range []string{"0x1", "0x7a69"} { // mainnet, anvil's default 31337
		url := fakeNode(t, "anvil/v1.8.5", id)
		err := CheckLocalChain(context.Background(), url)
		if err == nil || !strings.Contains(err.Error(), "chain id") {
			t.Fatalf("chain %s: err = %v, want refusal", id, err)
		}
	}
}

func TestCheckLocalChainRefusesRemoteHostWithoutContact(t *testing.T) {
	for _, u := range []string{
		"https://sepolia.infura.io/v3/x",
		"http://sepolia.example.invalid:8545",
		"http://10.0.0.5:8545",
		"http://anvil.example.com:8545",
		"https://127.0.0.1:8545", // TLS is never a local dev node
	} {
		err := CheckLocalChain(context.Background(), u)
		if err == nil || !strings.Contains(err.Error(), "refusing rpc") {
			t.Fatalf("%s: err = %v, want refusal before dialing", u, err)
		}
	}
}
