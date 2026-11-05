// Command qv-guardian is the operations command for the one thing the factory's guardian key may do: freeze it. The guardian key is
// an ONLINE operations key, one per chain; it cannot change the destination, only stop sweeping (the factory reverts anything else it
// tries). Unfreezing is a cold ceremony (qv-cold, set-destination). The gas the freeze costs is booked against the fee account when
// -core is given.
//
//	qv-guardian freeze -rpc URL -factory 0x... -key-file guardian.key [-core http://127.0.0.1:8081 -actor ops]
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "qv-guardian:", err)
		os.Exit(1)
	}
}

var (
	freezeSel   = crypto.Keccak256([]byte("freeze()"))[:4]
	guardianSel = crypto.Keccak256([]byte("guardian()"))[:4]
	destSel     = crypto.Keccak256([]byte("destination()"))[:4]
)

func run(args []string, out io.Writer) error {
	if len(args) == 0 || args[0] != "freeze" {
		return fmt.Errorf("usage: qv-guardian freeze -rpc URL -factory ADDR -key-file FILE [-core URL -actor NAME]  (freezing is all the guardian can do)")
	}
	fs := flag.NewFlagSet("freeze", flag.ContinueOnError)
	rpcURL := fs.String("rpc", "", "node JSON-RPC URL")
	factoryS := fs.String("factory", "", "forwarder factory address")
	keyFile := fs.String("key-file", "", "guardian key file (hex)")
	core := fs.String("core", "", "qv-core URL, to book the gas against the fee account")
	actor := fs.String("actor", "ops", "X-Actor for -core")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *rpcURL == "" || !common.IsHexAddress(*factoryS) || *keyFile == "" {
		return fmt.Errorf("-rpc, -factory and -key-file are required")
	}
	raw, err := os.ReadFile(*keyFile)
	if err != nil {
		return err
	}
	key, err := crypto.HexToECDSA(strings.TrimSpace(string(raw)))
	if err != nil {
		return fmt.Errorf("guardian key: %w", err)
	}
	return freeze(context.Background(), *rpcURL, common.HexToAddress(*factoryS), key, *core, *actor, out)
}

func freeze(ctx context.Context, rpcURL string, factory common.Address, key *ecdsa.PrivateKey, core, actor string, out io.Writer) error {
	ec, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return err
	}
	defer ec.Close()
	me := crypto.PubkeyToAddress(key.PublicKey)
	call := func(sel []byte) (common.Address, error) {
		b, err := ec.CallContract(ctx, ethereum.CallMsg{To: &factory, Data: sel}, nil)
		return common.BytesToAddress(b), err
	}
	guardian, err := call(guardianSel)
	if err != nil {
		return fmt.Errorf("read the factory: %w", err)
	}
	if guardian != me {
		return fmt.Errorf("this key is %s, the factory's guardian is %s: it would not be allowed to freeze", me, guardian)
	}
	if dest, _ := call(destSel); dest == (common.Address{}) {
		fmt.Fprintln(out, "the factory is already frozen; nothing to do")
		return nil
	}
	chainID, err := ec.ChainID(ctx)
	if err != nil {
		return err
	}
	nonce, err := ec.PendingNonceAt(ctx, me)
	if err != nil {
		return err
	}
	tip, err := ec.SuggestGasTipCap(ctx)
	if err != nil {
		return err
	}
	h, err := ec.HeaderByNumber(ctx, nil)
	if err != nil {
		return err
	}
	feeCap := new(big.Int).Add(new(big.Int).Mul(h.BaseFee, big.NewInt(3)), tip) // generous: freezing must not fail on a fee spike
	tx, err := types.SignNewTx(key, types.LatestSignerForChainID(chainID), &types.DynamicFeeTx{ChainID: chainID, Nonce: nonce, GasTipCap: tip, GasFeeCap: feeCap,
		Gas: 60000, To: &factory, Data: freezeSel})
	if err != nil {
		return err
	}
	if err := ec.SendTransaction(ctx, tx); err != nil {
		return err
	}
	fmt.Fprintf(out, "freeze sent: %s\n", tx.Hash())
	deadline := time.Now().Add(2 * time.Minute)
	for {
		r, err := ec.TransactionReceipt(ctx, tx.Hash())
		if err == nil {
			if r.Status != types.ReceiptStatusSuccessful {
				return fmt.Errorf("the freeze transaction %s reverted", tx.Hash())
			}
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("no receipt for %s after 2 minutes: check the node", tx.Hash())
		}
		time.Sleep(500 * time.Millisecond)
	}
	if dest, _ := call(destSel); dest != (common.Address{}) {
		return fmt.Errorf("the freeze mined but the destination is still %s", dest)
	}
	fmt.Fprintf(out, "FROZEN: the factory's destination is now none; unfreezing needs a cold ceremony (set-destination)\n")
	if core == "" {
		return nil
	}
	body, _ := json.Marshal(map[string]string{"tx": tx.Hash().Hex()})
	req, _ := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(core, "/")+"/v2/guardian/freezes", bytes.NewReader(body))
	req.Header.Set("X-Actor", actor)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("frozen, but booking the gas failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("frozen, but booking the gas failed: %d %s", resp.StatusCode, b)
	}
	fmt.Fprintln(out, "gas booked against the fee account")
	return nil
}

var _ = hex.EncodeToString
