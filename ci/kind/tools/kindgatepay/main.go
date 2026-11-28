// Command kindgatepay is AgentGate's side of one x402 payment in the kind lane's gate smoke case (ci/kind/smoke/gate.sh). It runs in a pod in the Gate namespace with
// only the onboarding output (ci/kind/gate.sh) and Gate's own key mounted, so it is built static for linux and imports nothing with cgo.
//
//	kindgatepay -out DIR -key FILE -kid K [-amount N] [-refuse no-cert|no-credential]
//
// -refuse sends the same request with one proof missing and succeeds only when the core refuses it with nothing signed: no-cert (Gate's token without
// its client certificate: 403 client_not_authorized, or the TLS handshake refused), no-credential (the payment from Gate's shard without a credential:
// 400 credential_missing). It prints {"refused": status, "code": code}.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/google/uuid"

	"github.com/ws4charlie/quorum-vault/internal/chain/evm"
	"github.com/ws4charlie/quorum-vault/internal/gatecred"
)

// pay is AgentGate's side of one x402 payment, using nothing but the onboarding output directory (and Gate's own signing key): a client-credentials
// token from token_url, a credential signed with Gate's key, the EIP-3009 typed data built by hand (as Gate does), the call to /v2/gate/signatures
// with Gate's client certificate, the signature checked against the token's own EIP-712 domain and wallet_address, and transferWithAuthorization
// submitted to rpc_url as a facilitator would. It prints one JSON line with what it did.
func main() {
	if err := pay(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "kindgatepay:", err)
		os.Exit(1)
	}
}

func pay(args []string) error {
	fs := flag.NewFlagSet("kindgatepay", flag.ExitOnError)
	dir := fs.String("out", "", "the onboarding output directory")
	keyPath := fs.String("key", "", "Gate's Ed25519 seed (hex)")
	kid := fs.String("kid", "", "Gate's key id")
	amount := fs.Int64("amount", 10000, "the payment, USDC base units (10000 = 0.01 USDC)")
	refuse := fs.String("refuse", "", "no-cert or no-credential: expect the core to refuse the request (see the command's doc)")
	fs.Parse(args)
	if *refuse != "" && *refuse != "no-cert" && *refuse != "no-credential" {
		return fmt.Errorf("-refuse %q: want no-cert or no-credential", *refuse)
	}
	rd := func(n string) string {
		b, err := os.ReadFile(filepath.Join(*dir, n))
		if err != nil {
			fmt.Fprintln(os.Stderr, "kindgatepay:", err)
			os.Exit(1)
		}
		return strings.TrimSpace(string(b))
	}
	seed, err := hex.DecodeString(rd2(*keyPath))
	if err != nil || len(seed) != ed25519.SeedSize {
		return fmt.Errorf("%s: not a hex Ed25519 seed", *keyPath)
	}
	gateKey := ed25519.NewKeyFromSeed(seed)
	chainID, err := strconv.ParseUint(rd("chain_id"), 10, 64)
	if err != nil {
		return fmt.Errorf("chain_id: %w", err)
	}
	token, wallet := common.HexToAddress(rd("usdc_address")), common.HexToAddress(rd("wallet_address"))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// 1. the token
	tokCA, err := pool(filepath.Join(*dir, "token_ca.crt"))
	if err != nil {
		return err
	}
	tc := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: tokCA}}}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {rd("client_id")}, "client_secret": {rd("client_secret")}}
	resp, err := tc.PostForm(rd("token_url"), form)
	if err != nil {
		return fmt.Errorf("token: %w", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if resp.StatusCode != 200 || json.Unmarshal(body, &tok) != nil || tok.AccessToken == "" {
		return fmt.Errorf("token: %d %s", resp.StatusCode, body)
	}

	// 2. the payment: typed data built by hand from the contract's own form, and a credential for exactly it
	payeeKey, _ := crypto.GenerateKey()
	payee := crypto.PubkeyToAddress(payeeKey.PublicKey)
	now := time.Now().Unix()
	validAfter, validBefore := uint64(now-30), uint64(now+240)
	var nonce [32]byte
	_, _ = rand.Read(nonce[:])
	payload := map[string]any{
		"types": map[string]any{
			"EIP712Domain":              []map[string]string{{"name": "name", "type": "string"}, {"name": "version", "type": "string"}, {"name": "chainId", "type": "uint256"}, {"name": "verifyingContract", "type": "address"}},
			"TransferWithAuthorization": []map[string]string{{"name": "from", "type": "address"}, {"name": "to", "type": "address"}, {"name": "value", "type": "uint256"}, {"name": "validAfter", "type": "uint256"}, {"name": "validBefore", "type": "uint256"}, {"name": "nonce", "type": "bytes32"}},
		},
		"primaryType": "TransferWithAuthorization",
		"domain":      map[string]any{"name": "USDC", "version": "2", "chainId": chainID, "verifyingContract": strings.ToLower(token.Hex())},
		"message": map[string]string{"from": strings.ToLower(wallet.Hex()), "to": strings.ToLower(payee.Hex()), "value": strconv.FormatInt(*amount, 10),
			"validAfter": strconv.FormatUint(validAfter, 10), "validBefore": strconv.FormatUint(validBefore, 10), "nonce": "0x" + hex.EncodeToString(nonce[:])},
	}
	cred := gatecred.Credential{V: 1, KID: *kid, CredentialID: uuid.NewString(), ObligationID: "kind-smoke-" + uuid.NewString()[:8], Audience: rd("audience"),
		WalletID: rd("wallet_id"), Chain: fmt.Sprintf("eip155:%d", chainID), Asset: strings.ToLower(token.Hex()), Payee: strings.ToLower(payee.Hex()),
		Amount: strconv.FormatInt(*amount, 10), IssuedAt: now - 30, ExpiresAt: now + 300, PolicyVersion: "kind-smoke", DecisionReason: "kind smoke: within budget"}
	cred.Sig = ed25519.Sign(gateKey, cred.SignedBytes())
	req := map[string]any{"wallet_id": rd("wallet_id"), "kind": "evm_eip3009", "payload": payload, "credential": json.RawMessage(cred.Wire())}

	// 3. the signing API, with Gate's client certificate
	vaultCA, err := pool(filepath.Join(*dir, "ca.crt"))
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(*dir, "tls.crt"), filepath.Join(*dir, "tls.key"))
	if err != nil {
		return err
	}
	certs := []tls.Certificate{cert}
	switch *refuse {
	case "no-cert":
		certs = nil
	case "no-credential":
		delete(req, "credential")
	}
	vc := &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: vaultCA, Certificates: certs}}}
	b, _ := json.Marshal(req)
	if *refuse != "" {
		return expectRefused(ctx, vc, rd("vault_url"), tok.AccessToken, b, *refuse)
	}
	var signed struct {
		CredentialID string `json:"credential_id"`
		Signature    string `json:"signature"`
	}
	for try := 0; ; try++ { // 503 retry_later: the same request again continues the same job (docs/gate-credential.md)
		hr, _ := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(rd("vault_url"), "/")+"/v2/gate/signatures", bytes.NewReader(b))
		hr.Header.Set("Content-Type", "application/json")
		hr.Header.Set("Authorization", "Bearer "+tok.AccessToken)
		resp, err := vc.Do(hr)
		if err != nil {
			return fmt.Errorf("signing API: %w", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == 503 && bytes.Contains(body, []byte("retry_later")) && try < 10 {
			time.Sleep(2 * time.Second)
			continue
		}
		if resp.StatusCode != 200 {
			return fmt.Errorf("signing API: %d %s", resp.StatusCode, body)
		}
		if err := json.Unmarshal(body, &signed); err != nil || signed.CredentialID != cred.CredentialID {
			return fmt.Errorf("signing API answer %s: %v", body, err)
		}
		break
	}
	sig, err := hex.DecodeString(strings.TrimPrefix(signed.Signature, "0x"))
	if err != nil || len(sig) != 65 || (sig[64] != 27 && sig[64] != 28) {
		return fmt.Errorf("signature %q is not r||s||v with v 27 or 28", signed.Signature)
	}

	// 4. the signature against the token's own domain: DOMAIN_SEPARATOR() on the chain equals the one of (USDC, 2, chain id, usdc_address), and the
	// digest recovers wallet_address
	rc, err := rpc.DialContext(ctx, rd("rpc_url"))
	if err != nil {
		return err
	}
	defer rc.Close()
	ec := ethclient.NewClient(rc)
	if id, err := ec.ChainID(ctx); err != nil || id.Uint64() != chainID {
		return fmt.Errorf("rpc_url: chain id %v, want %d: %v", id, chainID, err)
	}
	a, err := abi.JSON(strings.NewReader(eip3009ABI))
	if err != nil {
		return err
	}
	data, _ := a.Pack("DOMAIN_SEPARATOR")
	ds, err := ec.CallContract(ctx, callMsg(token, data), nil)
	if err != nil {
		return err
	}
	if want := evm.DomainSeparator("USDC", "2", chainID, token); !bytes.Equal(ds, want[:]) {
		return fmt.Errorf("the token's DOMAIN_SEPARATOR %x is not the one of (USDC, 2, %d, %s)", ds, chainID, token.Hex())
	}
	digest := evm.Digest712("USDC", "2", chainID, token, wallet, payee, big.NewInt(*amount), validAfter, validBefore, nonce)
	rsv := append([]byte(nil), sig...)
	rsv[64] -= 27
	pub, err := crypto.SigToPub(digest[:], rsv)
	if err != nil {
		return err
	}
	recovered := crypto.PubkeyToAddress(*pub)
	if got := recovered; got != wallet {
		return fmt.Errorf("the signature recovers %s, not wallet_address %s", got.Hex(), wallet.Hex())
	}

	// 5. the facilitator: a fresh account with gas (anvil_setBalance) submits transferWithAuthorization; it must mine and pay the payee
	fac, _ := crypto.GenerateKey()
	if err := rc.CallContext(ctx, nil, "anvil_setBalance", crypto.PubkeyToAddress(fac.PublicKey), (*hexutil.Big)(big.NewInt(1e18))); err != nil {
		return err
	}
	var r, s [32]byte
	copy(r[:], sig[:32])
	copy(s[:], sig[32:64])
	data, err = a.Pack("transferWithAuthorization", wallet, payee, big.NewInt(*amount), new(big.Int).SetUint64(validAfter), new(big.Int).SetUint64(validBefore), nonce, sig[64], r, s)
	if err != nil {
		return err
	}
	rcpt, err := send(ctx, ec, fac, &token, data)
	if err != nil {
		return fmt.Errorf("transferWithAuthorization: %w", err)
	}
	data, _ = a.Pack("balanceOf", payee)
	out, err := ec.CallContract(ctx, callMsg(token, data), nil)
	if err != nil {
		return err
	}
	if got := new(big.Int).SetBytes(out); got.Int64() != *amount {
		return fmt.Errorf("payee holds %s after the transfer, want %d", got, *amount)
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"credential_id": cred.CredentialID, "signature": signed.Signature, "recovered": recovered.Hex(),
		"payee": payee.Hex(), "amount": *amount, "tx": rcpt.TxHash.Hex(), "block": rcpt.BlockNumber.Uint64()})
}

func rd2(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func pool(path string) (*x509.CertPool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("%s: no certificate", path)
	}
	return p, nil
}

func callMsg(to common.Address, data []byte) ethereum.CallMsg {
	return ethereum.CallMsg{To: &to, Data: data}
}

// send signs and sends one transaction from key and waits for its receipt; a reverted one is an error.
func send(ctx context.Context, ec *ethclient.Client, key *ecdsa.PrivateKey, to *common.Address, data []byte) (*types.Receipt, error) {
	from := crypto.PubkeyToAddress(key.PublicKey)
	id, err := ec.ChainID(ctx)
	if err != nil {
		return nil, err
	}
	nonce, err := ec.PendingNonceAt(ctx, from)
	if err != nil {
		return nil, err
	}
	gas, err := ec.EstimateGas(ctx, ethereum.CallMsg{From: from, To: to, Data: data})
	if err != nil {
		return nil, fmt.Errorf("estimate gas: %w", err)
	}
	h, err := ec.HeaderByNumber(ctx, nil)
	if err != nil {
		return nil, err
	}
	tip := big.NewInt(2e9)
	tx := types.NewTx(&types.DynamicFeeTx{ChainID: id, Nonce: nonce, GasTipCap: tip, GasFeeCap: new(big.Int).Add(new(big.Int).Mul(h.BaseFee, big.NewInt(2)), tip),
		Gas: gas * 12 / 10, To: to, Value: new(big.Int), Data: data})
	signed, err := types.SignTx(tx, types.LatestSignerForChainID(id), key)
	if err != nil {
		return nil, err
	}
	if err := ec.SendTransaction(ctx, signed); err != nil {
		return nil, err
	}
	for i := 0; i < 300; i++ {
		if r, err := ec.TransactionReceipt(ctx, signed.Hash()); err == nil {
			if r.Status != 1 {
				return nil, fmt.Errorf("transaction %s reverted", signed.Hash())
			}
			return r, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil, fmt.Errorf("no receipt for %s", signed.Hash())
}

// eip3009ABI is the part of the token's ABI the facilitator and the check use (the pod has no repository checkout).
const eip3009ABI = `[
{"type":"function","name":"DOMAIN_SEPARATOR","stateMutability":"view","inputs":[],"outputs":[{"type":"bytes32"}]},
{"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"name":"a","type":"address"}],"outputs":[{"type":"uint256"}]},
{"type":"function","name":"transferWithAuthorization","stateMutability":"nonpayable","inputs":[{"name":"from","type":"address"},{"name":"to","type":"address"},{"name":"value","type":"uint256"},{"name":"validAfter","type":"uint256"},{"name":"validBefore","type":"uint256"},{"name":"nonce","type":"bytes32"},{"name":"v","type":"uint8"},{"name":"r","type":"bytes32"},{"name":"s","type":"bytes32"}],"outputs":[]}
]`

// expectRefused sends the request once and succeeds only on the refusal the mode expects. A TLS handshake the core refuses for want of a client
// certificate is a refusal too (the core asks for one; an empty answer may end the handshake).
func expectRefused(ctx context.Context, c *http.Client, vaultURL, token string, body []byte, mode string) error {
	hr, _ := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(vaultURL, "/")+"/v2/gate/signatures", bytes.NewReader(body))
	hr.Header.Set("Content-Type", "application/json")
	hr.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.Do(hr)
	if err != nil {
		// only the core's own refusal of a missing client certificate: the TLS alert certificate_required (TLS 1.3) or bad_certificate, never any
		// other TLS failure (an untrusted server certificate also says "certificate")
		if e := err.Error(); mode == "no-cert" && (strings.Contains(e, "certificate required") || strings.Contains(e, "bad certificate")) {
			return json.NewEncoder(os.Stdout).Encode(map[string]any{"refused": "tls", "code": err.Error()})
		}
		return fmt.Errorf("signing API: %w", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var rf struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(raw, &rf)
	want := map[string]struct {
		status int
		code   string
	}{"no-cert": {403, "client_not_authorized"}, "no-credential": {400, "credential_missing"}}[mode]
	if resp.StatusCode != want.status || rf.Code != want.code {
		return fmt.Errorf("%s: want %d %s, got %d %s", mode, want.status, want.code, resp.StatusCode, raw)
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"refused": resp.StatusCode, "code": rf.Code})
}
