package evm

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

// testdata/receipt-base-sepolia.json is the receipt of a real Base Sepolia (chain 84532) transaction, as the public node returns it: an EIP-1559
// approve() at block 0x3d2f399. Public chain data, no key. Its sender's balance fell by 335993920556 wei from block 0x3d2f398 to 0x3d2f399 (the
// sender's only transaction there, value 0): gasUsed 0xb4a2 × effectiveGasPrice 0x5b8d80 = 277452000000, plus l1Fee 0xda15ed12c = 58541920556.
const (
	baseSepoliaTx       = "0x1414ba588db609e531e0ce9dd41b054b29e0bd5dffda69adaa128734315b9ffc"
	baseSepoliaPaid     = 335993920556 // the balance change: what custody must book
	baseSepoliaGasOnly  = 277452000000 // gasUsed × effectiveGasPrice alone
	baseSepoliaL1FeeHex = `"0xda15ed12c"`
)

func baseSepoliaReceipt(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	b, err := os.ReadFile("testdata/receipt-base-sepolia.json")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func encode(t *testing.T, m map[string]json.RawMessage) []byte {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseReceiptBooksTheL1Fee(t *testing.T) {
	m := baseSepoliaReceipt(t)
	if string(m["l1Fee"]) != baseSepoliaL1FeeHex {
		t.Fatalf("fixture l1Fee = %s", m["l1Fee"])
	}
	r, fee, err := ParseReceipt(encode(t, m))
	if err != nil {
		t.Fatal(err)
	}
	if r.TxHash.Hex() != baseSepoliaTx {
		t.Fatalf("tx %s", r.TxHash.Hex())
	}
	if fee == nil || fee.Cmp(big.NewInt(baseSepoliaPaid)) != 0 {
		t.Fatalf("fee = %v, want %d (the sender's balance change on Base Sepolia; gas alone is %d)", fee, baseSepoliaPaid, baseSepoliaGasOnly)
	}
}

func TestParseReceiptWithoutL1FeeIsGasTimesPrice(t *testing.T) {
	for _, l1 := range []string{"", "null"} { // an L1 chain's receipt has no field; null counts as none
		m := baseSepoliaReceipt(t)
		delete(m, "l1Fee")
		if l1 != "" {
			m["l1Fee"] = json.RawMessage(l1)
		}
		_, fee, err := ParseReceipt(encode(t, m))
		if err != nil {
			t.Fatal(err)
		}
		if fee == nil || fee.Cmp(big.NewInt(baseSepoliaGasOnly)) != 0 {
			t.Fatalf("l1Fee %q: fee = %v, want %d", l1, fee, baseSepoliaGasOnly)
		}
	}
	m := baseSepoliaReceipt(t)
	delete(m, "effectiveGasPrice")
	if _, fee, err := ParseReceipt(encode(t, m)); err != nil || fee != nil {
		t.Fatalf("no effectiveGasPrice: fee %v, err %v; want nil, nil", fee, err)
	}
}

func TestParseReceiptRefusesAMalformedL1Fee(t *testing.T) {
	for _, l1 := range []string{`"0xzz"`, `"da15ed12c"`, `"0x"`, `""`, `"0x0da15ed12c"`, `"-0x1"`, `58541920556`, `true`, `{}`} {
		m := baseSepoliaReceipt(t)
		m["l1Fee"] = json.RawMessage(l1)
		if _, fee, err := ParseReceipt(encode(t, m)); err == nil {
			t.Errorf("l1Fee %s: fee %v, want an error (never 0)", l1, fee)
		}
	}
}

// receiptNode answers eth_getTransactionReceipt with receipt for hash, null for any other hash.
func receiptNode(t *testing.T, hash string, receipt []byte) *ethclient.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		var call struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params []string        `json:"params"`
		}
		if err := json.Unmarshal(body, &call); err != nil || call.Method != "eth_getTransactionReceipt" || len(call.Params) != 1 {
			http.Error(w, "unexpected call "+string(body), http.StatusBadRequest)
			return
		}
		result := json.RawMessage("null")
		if strings.EqualFold(call.Params[0], hash) {
			result = receipt
		}
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": call.ID, "result": result})
	}))
	t.Cleanup(srv.Close)
	c, err := rpc.DialHTTP(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return ethclient.NewClient(c)
}

func TestReadReceiptNotFound(t *testing.T) {
	ec := receiptNode(t, baseSepoliaTx, encode(t, baseSepoliaReceipt(t)))
	if _, _, err := ReadReceipt(context.Background(), ec.Client(), common.HexToHash("0x01")); !errors.Is(err, ethereum.NotFound) {
		t.Fatalf("err = %v, want ethereum.NotFound", err)
	}
}

// The adapter's two fee readers book what the Base Sepolia sender paid, l1Fee included.
func TestAdapterFeesIncludeTheL1Fee(t *testing.T) {
	ctx := context.Background()
	a := &Adapter{ec: receiptNode(t, baseSepoliaTx, encode(t, baseSepoliaReceipt(t)))}
	fee, err := a.TxFee(ctx, baseSepoliaTx)
	if err != nil || fee.Cmp(big.NewInt(baseSepoliaPaid)) != 0 {
		t.Fatalf("TxFee = %v, %v; want %d", fee, err, baseSepoliaPaid)
	}
	// a reverted refill paid its fee too (and RefillTxState returns before it needs the safe head)
	m := baseSepoliaReceipt(t)
	m["status"] = json.RawMessage(`"0x0"`)
	a = &Adapter{ec: receiptNode(t, baseSepoliaTx, encode(t, m))}
	st, fee, err := a.RefillTxState(ctx, baseSepoliaTx)
	if err != nil || st != RefillReverted || fee == nil || fee.Cmp(big.NewInt(baseSepoliaPaid)) != 0 {
		t.Fatalf("RefillTxState = %s, %v, %v; want reverted, %d", st, fee, err, baseSepoliaPaid)
	}
	if st, fee, err := a.RefillTxState(ctx, "0x01"); err != nil || st != RefillPending || fee != nil {
		t.Fatalf("no receipt: %s, %v, %v; want pending", st, fee, err)
	}
}
