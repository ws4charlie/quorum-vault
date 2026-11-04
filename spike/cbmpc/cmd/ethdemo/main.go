// Command ethdemo: builds an EIP-1559 tx, gets the signature from the 2-party MPC through the `party` binary
// (a separate process: cgo/C++ stays out of this binary), broadcasts to anvil and proves sender == derived address.
package main

import (
	"bytes"
	"context"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

var (
	partyBin = flag.String("party", "out/party", "party binary")
	p1dir    = flag.String("p1dir", "", "p1 state dir")
	addr     = flag.String("addr", "127.0.0.1:19001", "p2 address")
	rpcURL   = flag.String("rpc", "http://127.0.0.1:18545", "anvil RPC")
	delay    = flag.String("delay", "0s", "one-way delay for party frames")
)

func party(args ...string) string {
	a := append([]string{"-dir", *p1dir, "-addr", *addr, "-delay", *delay}, args...)
	out, err := exec.Command(*partyBin, a...).CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "party %v: %v\n%s", args, err, out)
		os.Exit(1)
	}
	return strings.TrimSpace(string(out))
}

func derToRS(der []byte) (r, s *big.Int, err error) {
	var sig struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil || len(rest) != 0 {
		return nil, nil, errors.New("bad DER")
	}
	return sig.R, sig.S, nil
}

func ethSig(der, digest, pub []byte) ([]byte, bool, error) {
	r, s, err := derToRS(der)
	if err != nil {
		return nil, false, err
	}
	n := crypto.S256().Params().N
	flipped := false
	if s.Cmp(new(big.Int).Rsh(n, 1)) > 0 { // EIP-2 low-S
		s = new(big.Int).Sub(n, s)
		flipped = true
	}
	sig := make([]byte, 65)
	r.FillBytes(sig[0:32])
	s.FillBytes(sig[32:64])
	for v := byte(0); v < 2; v++ {
		sig[64] = v
		if rec, err := crypto.SigToPub(digest, sig); err == nil && bytes.Equal(crypto.CompressPubkey(rec), pub) {
			return sig, flipped, nil
		}
	}
	return nil, false, errors.New("signature does not recover to the derived key")
}

func waitReceipt(ctx context.Context, cl *ethclient.Client, h common.Hash) (*types.Receipt, error) {
	for i := 0; i < 100; i++ {
		if r, err := cl.TransactionReceipt(ctx, h); err == nil {
			return r, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil, errors.New("receipt timeout")
}

func main() {
	flag.Parse()
	ctx := context.Background()
	t0 := time.Now()
	fmt.Println("== DKG (one per master key)")
	fmt.Println(party("dkg", "ecdsa", "ks-ecdsa"))
	fmt.Println("== derive child key (hardened path 44/60/0 via VRF, non-hardened 0/7)")
	fmt.Println(party("derive", "ecdsa", "ks-ecdsa", "evm-child", "44,60,0", "0,7"))
	pub, _ := hex.DecodeString(party("pubkey", "ecdsa", "evm-child"))
	pk, err := crypto.DecompressPubkey(pub)
	if err != nil {
		panic(err)
	}
	from := crypto.PubkeyToAddress(*pk)
	fmt.Printf("child pub  %x\nchild addr %s\n", pub, from)

	rc, err := rpc.DialContext(ctx, *rpcURL)
	if err != nil {
		panic(err)
	}
	cl := ethclient.NewClient(rc)
	chainID, err := cl.ChainID(ctx)
	if err != nil {
		panic(err)
	}
	var accts []common.Address
	if err := rc.CallContext(ctx, &accts, "eth_accounts"); err != nil || len(accts) == 0 {
		panic(fmt.Sprint("eth_accounts: ", err))
	}
	var fundTx common.Hash
	if err := rc.CallContext(ctx, &fundTx, "eth_sendTransaction", map[string]any{"from": accts[0], "to": from, "value": "0xde0b6b3a7640000"}); err != nil {
		panic(err)
	}
	if _, err := waitReceipt(ctx, cl, fundTx); err != nil {
		panic(err)
	}
	bal, _ := cl.BalanceAt(ctx, from, nil)
	fmt.Printf("funded     %s wei on chain %s\n", bal, chainID)

	nonce, _ := cl.PendingNonceAt(ctx, from)
	head, _ := cl.HeaderByNumber(ctx, nil)
	tip := big.NewInt(1_000_000_000)
	tx := types.NewTx(&types.DynamicFeeTx{ChainID: chainID, Nonce: nonce, GasTipCap: tip,
		GasFeeCap: new(big.Int).Add(new(big.Int).Mul(head.BaseFee, big.NewInt(2)), tip), Gas: 21000, To: &accts[0], Value: big.NewInt(12345)})
	signer := types.LatestSignerForChainID(chainID)
	digest := signer.Hash(tx).Bytes()
	t2 := time.Now()
	derHex := party("sign-hex", "ecdsa", "evm-child", hex.EncodeToString(digest))
	fmt.Printf("MPC sign (incl. process start + connect) %v\n", time.Since(t2))
	der, _ := hex.DecodeString(derHex)
	sig, flipped, err := ethSig(der, digest, pub)
	if err != nil {
		panic(err)
	}
	fmt.Printf("DER sig %x (s flipped to low-S: %v)\n", der, flipped)
	stx, err := tx.WithSignature(signer, sig)
	if err != nil {
		panic(err)
	}
	if err := cl.SendTransaction(ctx, stx); err != nil {
		panic(err)
	}
	rcpt, err := waitReceipt(ctx, cl, stx.Hash())
	if err != nil {
		panic(err)
	}
	sender, err := cl.TransactionSender(ctx, stx, rcpt.BlockHash, rcpt.TransactionIndex)
	if err != nil {
		panic(err)
	}
	fmt.Printf("tx %s mined in block %d, status %d\n", stx.Hash(), rcpt.BlockNumber, rcpt.Status)
	fmt.Printf("sender per chain  %s\nderived address   %s\n", sender, from)
	if sender != from || rcpt.Status != 1 {
		fmt.Println("FAIL")
		os.Exit(1)
	}
	fmt.Printf("PASS: EIP-1559 tx signed by 2-party MPC (HD child key) mined on anvil; sender == derived address (total %v)\n", time.Since(t0))
}
