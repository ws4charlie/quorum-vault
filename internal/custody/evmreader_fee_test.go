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

	"github.com/ws4charlie/quorum-vault/internal/chain/evm"
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
	r := &EVMReader{cfg: &Config{EVM: evm.Config{ChainID: 84532}}, ec: ethclient.NewClient(c)}
	got, found, err := r.Receipt(context.Background(), "0x1414ba588db609e531e0ce9dd41b054b29e0bd5dffda69adaa128734315b9ffc")
	if err != nil || !found {
		t.Fatalf("found %v, err %v", found, err)
	}
	if !got.Success || got.Block != 0x3d2f399 || got.Fee == nil || got.Fee.Cmp(big.NewInt(335993920556)) != 0 {
		t.Fatalf("receipt = %+v, want success at 0x3d2f399 with fee 335993920556", got)
	}
}

// l1_fee: unset on Base Sepolia means required (a missing l1Fee is then an error); "none" is explicit; anything else refuses the config.
func TestChainFileL1Fee(t *testing.T) {
	build := func(l1 string) (*Config, error) {
		cf := File{
			Chain: ChainFile{Name: testChain, ChainID: 84532, Factory: "0x00000000000000000000000000000000000000f1", L1Fee: l1,
				SweepDestination: "0x00000000000000000000000000000000000000a1", HotShards: []string{"0x00000000000000000000000000000000000000a1"},
				MaxTxFeeWei: "1000000000000000000", Assets: map[string]AssetFile{"ETH": {Decimals: 18, PriceWei: "1"}}},
			Withdrawal: WithdrawalFile{Tiers: map[string][]TierFile{"ETH": {{MinAmount: "0", Approvals: 1, Auto: true}}}},
		}
		return cf.Build()
	}
	for l1, want := range map[string]evm.L1FeeMode{"": evm.L1FeeRequired, "required": evm.L1FeeRequired, "none": evm.L1FeeNone} {
		c, err := build(l1)
		if err != nil {
			t.Fatalf("l1_fee %q: %v", l1, err)
		}
		if got := c.EVM.L1FeeModeOf(); got != want {
			t.Errorf("l1_fee %q on 84532: %q, want %q", l1, got, want)
		}
	}
	if _, err := build("maybe"); err == nil {
		t.Error(`l1_fee "maybe" was accepted`)
	}
}
