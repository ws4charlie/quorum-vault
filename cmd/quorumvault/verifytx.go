package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/core/types"

	"github.com/ws4charlie/quorum-vault/internal/chain/eth"
)

// verifyTx implements `quorumvault verify-tx <0x raw tx> [expected sender]`:
// an offline check, independent of the server, that decodes a raw EIP-1559
// transaction, recovers its sender from the signature and (optionally)
// compares it with the expected wallet address. Exit status 1 on mismatch.
func verifyTx(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: quorumvault verify-tx <0x-raw-tx> [expected-sender]")
		return 2
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(args[0], "0x"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "raw tx is not hex:", err)
		return 2
	}
	tx, err := eth.DecodeRaw(raw)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	from, err := types.Sender(types.LatestSignerForChainID(tx.ChainId()), tx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "recover sender:", err)
		return 1
	}
	out := map[string]any{
		"type": tx.Type(), "chain_id": tx.ChainId().String(), "nonce": tx.Nonce(), "to": tx.To().Hex(),
		"value_wei": tx.Value().String(), "gas": tx.Gas(), "max_fee_per_gas": tx.GasFeeCap().String(),
		"max_priority_fee_per_gas": tx.GasTipCap().String(), "tx_hash": tx.Hash().Hex(), "recovered_sender": from.Hex(),
	}
	code := 0
	if len(args) > 1 {
		match := strings.EqualFold(from.Hex(), args[1])
		out["expected_sender"], out["sender_matches"] = args[1], match
		if !match {
			code = 1
		}
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(b))
	return code
}
