package custody

import (
	"context"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

// The reader the withdrawal, sweep and rebalance paths book fees from counts an OP-stack chain's L1 data fee. The receipt is a real Base Sepolia
// one (internal/chain/evm/testdata); its sender paid 335993920556 wei, of which 58541920556 is l1Fee (see receiptfee_test.go there).
func TestEVMReaderReceiptFeeIncludesL1Fee(t *testing.T) {
	receipt, err := os.ReadFile("../chain/evm/testdata/receipt-base-sepolia.json")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		var call struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if json.Unmarshal(body, &call) != nil || call.Method != "eth_getTransactionReceipt" {
			http.Error(w, "unexpected call", http.StatusBadRequest)
			return
		}
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": call.ID, "result": json.RawMessage(receipt)})
	}))
	defer srv.Close()
	c, err := rpc.DialHTTP(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	r := &EVMReader{ec: ethclient.NewClient(c)}
	got, found, err := r.Receipt(context.Background(), "0x1414ba588db609e531e0ce9dd41b054b29e0bd5dffda69adaa128734315b9ffc")
	if err != nil || !found {
		t.Fatalf("found %v, err %v", found, err)
	}
	if !got.Success || got.Block != 0x3d2f399 || got.Fee == nil || got.Fee.Cmp(big.NewInt(335993920556)) != 0 {
		t.Fatalf("receipt = %+v, want success at 0x3d2f399 with fee 335993920556", got)
	}
}
