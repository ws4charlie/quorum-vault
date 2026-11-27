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
	"path/filepath"
	"regexp"
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
	r, fee, err := ParseReceipt(encode(t, m), L1FeeRequired)
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
		_, fee, err := ParseReceipt(encode(t, m), L1FeeNone)
		if err != nil {
			t.Fatal(err)
		}
		if fee == nil || fee.Cmp(big.NewInt(baseSepoliaGasOnly)) != 0 {
			t.Fatalf("l1Fee %q: fee = %v, want %d", l1, fee, baseSepoliaGasOnly)
		}
		// on an OP-stack chain the same receipt is an error, never a fee of 0
		if _, fee, err := ParseReceipt(encode(t, m), L1FeeRequired); err == nil {
			t.Fatalf("l1Fee %q with mode required: fee %v, want an error", l1, fee)
		}
	}
	// mode none still books an l1Fee the node reports (the chain charged it)
	if _, fee, err := ParseReceipt(encode(t, baseSepoliaReceipt(t)), L1FeeNone); err != nil || fee.Cmp(big.NewInt(baseSepoliaPaid)) != 0 {
		t.Fatalf("mode none with l1Fee: %v, %v; want %d", fee, err, baseSepoliaPaid)
	}
	if _, _, err := ParseReceipt(encode(t, baseSepoliaReceipt(t)), ""); err == nil {
		t.Fatal("an unresolved mode must be refused")
	}
	m := baseSepoliaReceipt(t)
	delete(m, "effectiveGasPrice")
	if _, fee, err := ParseReceipt(encode(t, m), L1FeeRequired); err != nil || fee != nil {
		t.Fatalf("no effectiveGasPrice: fee %v, err %v; want nil, nil", fee, err)
	}
}

func TestParseReceiptRefusesAMalformedL1Fee(t *testing.T) {
	for _, l1 := range []string{`"0xzz"`, `"da15ed12c"`, `"0x"`, `""`, `"0x0da15ed12c"`, `"-0x1"`, `58541920556`, `true`, `{}`} {
		m := baseSepoliaReceipt(t)
		m["l1Fee"] = json.RawMessage(l1)
		if _, fee, err := ParseReceipt(encode(t, m), L1FeeRequired); err == nil {
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
	if _, _, err := ReadReceipt(context.Background(), ec.Client(), common.HexToHash("0x01"), L1FeeRequired); !errors.Is(err, ethereum.NotFound) {
		t.Fatalf("err = %v, want ethereum.NotFound", err)
	}
}

// The adapter's two fee readers book what the Base Sepolia sender paid, l1Fee included.
func TestAdapterFeesIncludeTheL1Fee(t *testing.T) {
	ctx := context.Background()
	a := &Adapter{cfg: Config{ChainID: 84532}, ec: receiptNode(t, baseSepoliaTx, encode(t, baseSepoliaReceipt(t)))}
	fee, err := a.TxFee(ctx, baseSepoliaTx)
	if err != nil || fee.Cmp(big.NewInt(baseSepoliaPaid)) != 0 {
		t.Fatalf("TxFee = %v, %v; want %d", fee, err, baseSepoliaPaid)
	}
	// a reverted refill paid its fee too (and RefillTxState returns before it needs the safe head)
	m := baseSepoliaReceipt(t)
	m["status"] = json.RawMessage(`"0x0"`)
	a = &Adapter{cfg: Config{ChainID: 84532}, ec: receiptNode(t, baseSepoliaTx, encode(t, m))}
	st, fee, err := a.RefillTxState(ctx, baseSepoliaTx)
	if err != nil || st != RefillReverted || fee == nil || fee.Cmp(big.NewInt(baseSepoliaPaid)) != 0 {
		t.Fatalf("RefillTxState = %s, %v, %v; want reverted, %d", st, fee, err, baseSepoliaPaid)
	}
	if st, fee, err := a.RefillTxState(ctx, "0x01"); err != nil || st != RefillPending || fee != nil {
		t.Fatalf("no receipt: %s, %v, %v; want pending", st, fee, err)
	}
}

func TestL1FeeModeDefaultsAndConfig(t *testing.T) {
	for id, want := range map[uint64]L1FeeMode{8453: L1FeeRequired, 84532: L1FeeRequired, 10: L1FeeRequired, 11155420: L1FeeRequired, 1: L1FeeNone, 11155111: L1FeeNone} {
		if got := (Config{ChainID: id}).L1FeeModeOf(); got != want {
			t.Errorf("chain %d: %q, want %q", id, got, want)
		}
	}
	if got := (Config{ChainID: 84532, L1Fee: L1FeeNone}).L1FeeModeOf(); got != L1FeeNone {
		t.Errorf("explicit none on 84532: %q", got)
	}
	for _, s := range []string{"", "required", "none"} {
		if _, err := ParseL1FeeMode(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	for _, s := range []string{"Required", "yes", "0"} {
		if _, err := ParseL1FeeMode(s); err == nil {
			t.Errorf("%q: want an error", s)
		}
	}
	c := Config{Chain: "base", ChainID: 84532, MaxTxFeeWei: big.NewInt(1), Factory: common.HexToAddress("0xf1"), SweepDestination: common.HexToAddress("0xd1"), L1Fee: "maybe"}
	if err := c.validate(); err == nil {
		t.Error("validate accepted l1 fee mode \"maybe\"")
	}
}

// A Base receipt without l1Fee is refused through the adapter too: never booked as gas alone.
func TestAdapterRefusesAMissingL1FeeOnBase(t *testing.T) {
	m := baseSepoliaReceipt(t)
	delete(m, "l1Fee")
	a := &Adapter{cfg: Config{ChainID: 84532}, ec: receiptNode(t, baseSepoliaTx, encode(t, m))}
	if fee, err := a.TxFee(context.Background(), baseSepoliaTx); err == nil {
		t.Fatalf("TxFee = %v, want an error", fee)
	}
	a.cfg.L1Fee = L1FeeNone // a node that charges none (anvil with --network ethereum)
	if fee, err := a.TxFee(context.Background(), baseSepoliaTx); err != nil || fee.Cmp(big.NewInt(baseSepoliaGasOnly)) != 0 {
		t.Fatalf("TxFee with none = %v, %v", fee, err)
	}
}

// The fee a transaction paid is computed in one place (ParseReceipt): a second gasUsed × effectiveGasPrice elsewhere would miss the OP-stack
// l1Fee again. No non-test file under internal/ or cmd/ other than receiptfee.go reads a receipt's effective gas price or multiplies its gas used.
func TestPaidFeeIsComputedOnlyInReceiptFee(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	own := filepath.Join(root, "internal/chain/evm/receiptfee.go")
	formula := regexp.MustCompile(`EffectiveGasPrice|effectiveGasPrice|SetUint64\([^)]*\.GasUsed\)`)
	scanned := 0
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") || p == own {
				return err
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			scanned++
			for i, line := range strings.Split(string(b), "\n") {
				if formula.MatchString(line) {
					t.Errorf("%s:%d computes a paid fee outside receiptfee.go (use evm.ReadReceipt): %s", strings.TrimPrefix(p, root+"/"), i+1, strings.TrimSpace(line))
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if scanned < 100 {
		t.Fatalf("scanned only %d files: wrong root %s?", scanned, root)
	}
}
