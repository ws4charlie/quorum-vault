// Command kindwd drives the kind lane's withdrawal cases against the real pods, from the host, through port-forwards. It does what a customer-facing system and an operator do:
// get tokens from Keycloak (the dev realm's users), create a customer and its deposit address, pay a deposit on the local chain, request a withdrawal and wait for it to settle,
// and ask core for Reconcile. Nothing here signs: the gateway and the three parties do, and the auto approver in the worker approves the small tier.
//
//	kindwd [common flags] setup  -asset ETH|BTC -customer C -amount N   customer, deposit address, the deposit itself (base units), waits until it is available
//	kindwd [common flags] pay    -asset A -customer C -amount N         requests a withdrawal to a fresh address, prints {"id","to","amount"}
//	kindwd [common flags] settle -asset A -id I -to ADDR -amount N      waits for `confirmed` (mining on Bitcoin), checks the payout is exactly N, Reconcile is clean
//	kindwd [common flags] reconcile                         exits 1 unless Reconcile is clean
//	kindwd [common flags] await  -id I -until signing,...  returns as soon as the withdrawal has one of the statuses (the crash cases kill a pod then)
//	kindwd [common flags] status -id I                      prints the withdrawal's status
//
// Common flags: -core, -kc (host:port of the port-forwards), -ca (the business CA file), -work (the lane's gitignored secrets dir), -rpc (anvil), -btc (bitcoind).
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

type env struct {
	core, kc, ca, work, rpcURL, btcURL string
	ctx                                context.Context
	coreC, kcC                         *http.Client
	secrets                            string
	tok                                map[string]string
}

func main() {
	fs := flag.NewFlagSet("kindwd", flag.ExitOnError)
	e := &env{ctx: context.Background(), tok: map[string]string{}}
	fs.StringVar(&e.core, "core", "", "core's API, host:port of a port-forward")
	fs.StringVar(&e.kc, "kc", "", "Keycloak, host:port of a port-forward")
	fs.StringVar(&e.ca, "ca", "", "the business CA certificate (PEM)")
	fs.StringVar(&e.secrets, "secrets", "", "the lane's secrets directory")
	fs.StringVar(&e.rpcURL, "rpc", "", "anvil, as http://host:port")
	fs.StringVar(&e.btcURL, "btc", "", "bitcoind, as http://host:port")
	fs.Parse(os.Args[1:])
	args := fs.Args()
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: kindwd [flags] setup|pay|settle|reconcile|status ...")
		os.Exit(2)
	}
	if err := e.run(args[0], args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "kindwd:", err)
		os.Exit(1)
	}
}

func (e *env) run(cmd string, args []string) error {
	pool := x509.NewCertPool()
	pem, err := os.ReadFile(e.ca)
	if err != nil {
		return err
	}
	pool.AppendCertsFromPEM(pem)
	client := func(addr, name string) *http.Client {
		return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: name},
			DialContext: func(ctx context.Context, n, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, n, addr)
			}}}
	}
	e.coreC, e.kcC = client(e.core, "qv-core.qv.svc"), client(e.kc, "keycloak")
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	asset := fs.String("asset", "ETH", "ETH or BTC")
	customer := fs.String("customer", "", "customer id")
	amount := fs.String("amount", "", "amount in base units (wei, satoshis)")
	id := fs.String("id", "", "withdrawal id")
	to := fs.String("to", "", "destination address")
	hot := fs.String("hot", "", "setup: the hot address. BTC: also fund it with -hot-sats satoshis; ETH: the deposit must be swept into it (waits for that)")
	hotSats := fs.Int64("hot-sats", 0, "")
	key := fs.String("key", "", "idempotency key (default: random)")
	until := fs.String("until", "signing", "await: the statuses to wait for (comma separated; the first one reached ends the wait)")
	fs.Parse(args)
	switch cmd {
	case "setup":
		return e.setup(*asset, *customer, *amount, *hot, *hotSats)
	case "pay":
		return e.pay(*asset, *customer, *amount, *key)
	case "settle":
		return e.settle(*asset, *id, *to, *amount)
	case "reconcile":
		return e.reconcile()
	case "await":
		return e.await(*id, strings.Split(*until, ","))
	case "status":
		w, err := e.getWd(*id)
		if err != nil {
			return err
		}
		fmt.Println(w["status"])
		return nil
	}
	return fmt.Errorf("unknown command %q", cmd)
}

func readSecret(dir, name string) (string, error) {
	b, err := os.ReadFile(filepath.Join(dir, name))
	return strings.TrimSpace(string(b)), err
}

// ---- Keycloak ----

func (e *env) form(path string, v url.Values) (map[string]any, error) {
	resp, err := e.kcC.PostForm("https://keycloak:8443"+path, v)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("keycloak %s: %d %s", path, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return out, nil
}

func (e *env) kcAdmin(method, path string, body any) ([]byte, error) {
	pw, err := readSecret(e.secrets, "kc-admin")
	if err != nil {
		return nil, err
	}
	t, err := e.form("/realms/master/protocol/openid-connect/token", url.Values{"grant_type": {"password"}, "client_id": {"admin-cli"}, "username": {"admin"}, "password": {pw}})
	if err != nil {
		return nil, err
	}
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, "https://keycloak:8443"+path, rd)
	req.Header.Set("Authorization", "Bearer "+t["access_token"].(string))
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.kcC.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("keycloak admin %s %s: %d %s", method, path, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return b, nil
}

// token is a fresh access token of a dev realm user (alice requests, ops operates), made through the realm's login page the way the e2e suite does (e2e/idp): authorization code, the
// username and password step only, with the client qv-e2e that is bound to the realm's test-only flow (the passkey step of qv-cli needs a browser).
func (e *env) token(user string) (string, error) {
	pw, err := readSecret(e.secrets, "kc-"+user)
	if err != nil {
		return "", err
	}
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Timeout: 30 * time.Second, Jar: jar, Transport: e.kcC.Transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	redirect := "http://127.0.0.1/cb"
	base := "https://keycloak:8443/realms/quorumvault/protocol/openid-connect/"
	resp, err := c.Get(base + "auth?" + url.Values{"client_id": {"qv-e2e"}, "response_type": {"code"}, "scope": {"openid"}, "redirect_uri": {redirect}, "state": {"s"}}.Encode())
	if err != nil {
		return "", err
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := regexp.MustCompile(`<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"`).FindSubmatch(page)
	if m == nil {
		return "", fmt.Errorf("keycloak: no login form (HTTP %d)", resp.StatusCode)
	}
	resp, err = c.PostForm(html.UnescapeString(string(m[1])), url.Values{"username": {user}, "password": {pw}, "credentialId": {""}})
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	loc, err := resp.Location()
	if err != nil || loc.Query().Get("code") == "" {
		return "", fmt.Errorf("keycloak login of %s did not redirect with a code (HTTP %d)", user, resp.StatusCode)
	}
	t, err := e.form("/realms/quorumvault/protocol/openid-connect/token", url.Values{"grant_type": {"authorization_code"}, "client_id": {"qv-e2e"}, "code": {loc.Query().Get("code")}, "redirect_uri": {redirect}})
	if err != nil {
		return "", err
	}
	return t["access_token"].(string), nil
}

// ---- core ----

func (e *env) call(user, method, path string, hdr map[string]string, body any) (int, map[string]any, error) {
	tok, err := e.token(user)
	if err != nil {
		return 0, nil, err
	}
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, "https://qv-core.qv.svc:8443"+path, rd)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := e.coreC.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out, nil
}

func (e *env) must(user, method, path string, hdr map[string]string, body any, ok ...int) (map[string]any, error) {
	code, out, err := e.call(user, method, path, hdr, body)
	if err != nil {
		return nil, err
	}
	for _, c := range ok {
		if code == c {
			return out, nil
		}
	}
	return nil, fmt.Errorf("%s %s: %d %v", method, path, code, out)
}

func chainOf(asset string) string {
	if asset == "BTC" {
		return "btc-kind"
	}
	return "evm-kind"
}

func (e *env) waitFor(d time.Duration, what string, f func() (bool, error)) error {
	dl := time.Now().Add(d)
	for {
		ok, err := f()
		if err != nil {
			return fmt.Errorf("%s: %w", what, err)
		}
		if ok {
			return nil
		}
		if time.Now().After(dl) {
			return fmt.Errorf("timed out after %s waiting for %s", d, what)
		}
		time.Sleep(2 * time.Second)
	}
}

func (e *env) available(customer, asset string) (*big.Int, error) {
	out, err := e.must("ops", "GET", "/v2/customers/"+customer+"/balances", nil, nil, 200)
	if err != nil {
		return nil, err
	}
	a := new(big.Int)
	bs, _ := out["balances"].([]any)
	for _, b := range bs {
		m := b.(map[string]any)
		if m["asset"] == asset {
			a.SetString(m["available"].(string), 10)
		}
	}
	return a, nil
}

func (e *env) setup(asset, customer, amount, hotAddr string, hotSats int64) error {
	amt, ok := new(big.Int).SetString(amount, 10)
	if !ok || customer == "" {
		return fmt.Errorf("-customer and -amount are required")
	}
	if _, err := e.must("ops", "POST", "/v2/customers", nil, map[string]any{"id": customer}, 200, 201); err != nil {
		return err
	}
	out, err := e.must("ops", "POST", "/v2/customers/"+customer+"/deposit-addresses", nil, map[string]any{"chain": chainOf(asset)}, 200)
	if err != nil {
		return err
	}
	addr, _ := out["address"].(string)
	var hotBefore *big.Int
	if asset == "ETH" {
		if hotAddr != "" {
			if hotBefore, err = e.evmBalance(hotAddr); err != nil {
				return err
			}
		}
		err = e.evmPay(addr, amt)
	} else {
		err = e.btcDeposit(addr, amt, hotAddr, hotSats)
	}
	if err != nil {
		return err
	}
	if err := e.waitFor(3*time.Minute, "the deposit to be available", func() (bool, error) {
		a, err := e.available(customer, asset)
		return a != nil && a.Cmp(amt) >= 0, err
	}); err != nil {
		return err
	}
	if asset != "ETH" || hotBefore == nil {
		return nil
	}
	// The deposit must be SWEPT, by the pods: the deposit address is emptied and the hot shard holds the amount (less the gas of the sweep, which the hot shard pays). Without this a broken
	// sweep would pass: the withdrawals below are paid from the hot shard's seeded gas money, which is there whether or not a deposit ever arrives.
	slack := new(big.Int).Div(amt, big.NewInt(10)) // the sweep's gas, at most a tenth of the deposit (the lane deposits 5 ETH; a sweep costs well under 0.01)
	return e.waitFor(3*time.Minute, "the deposit to be swept to the hot shard", func() (bool, error) {
		d, err := e.evmBalance(addr)
		if err != nil || d.Sign() != 0 {
			return false, err
		}
		h, err := e.evmBalance(hotAddr)
		if err != nil {
			return false, err
		}
		return h.Cmp(new(big.Int).Sub(new(big.Int).Add(hotBefore, amt), slack)) >= 0, nil
	})
}

func newID() string { b := make([]byte, 6); _, _ = rand.Read(b); return hex.EncodeToString(b) }

func (e *env) pay(asset, customer, amount, key string) error {
	if key == "" {
		key = "kind-" + newID()
	}
	var dest string
	if asset == "ETH" {
		k, _ := crypto.GenerateKey()
		dest = crypto.PubkeyToAddress(k.PublicKey).Hex()
	} else {
		var err error
		if dest, err = e.btcAddress(); err != nil {
			return err
		}
	}
	out, err := e.must("alice", "POST", "/v2/withdrawals", map[string]string{"Idempotency-Key": key}, map[string]any{"customer": customer, "asset": asset, "to": dest, "amount": amount}, 200, 201)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"id": out["id"], "to": dest, "amount": amount})
}

func (e *env) getWd(id string) (map[string]any, error) {
	return e.must("ops", "GET", "/v2/withdrawals/"+id, nil, nil, 200)
}

func (e *env) settle(asset, id, to, amount string) error {
	amt, _ := new(big.Int).SetString(amount, 10)
	var last string
	err := e.waitFor(6*time.Minute, "withdrawal "+id+" to be confirmed", func() (bool, error) {
		w, err := e.getWd(id)
		if err != nil {
			return false, err
		}
		s, _ := w["status"].(string)
		if s != last {
			fmt.Fprintf(os.Stderr, "withdrawal %s: %s\n", id, s)
			last = s
		}
		switch s {
		case "failed":
			return false, fmt.Errorf("withdrawal failed: %v", w["failure_reason"])
		case "broadcast":
			if asset == "BTC" { // the chain is regtest: nothing mines unless we do
				_ = e.btcMine(2)
			}
		}
		return s == "confirmed", nil
	})
	if err != nil {
		return err
	}
	var got *big.Int
	if asset == "ETH" {
		got, err = e.evmBalance(to)
	} else {
		got, err = e.btcReceived(to)
	}
	if err != nil {
		return err
	}
	if got.Cmp(amt) != 0 {
		return fmt.Errorf("withdrawal %s paid %s to %s, want exactly %s", id, got, to, amt)
	}
	fmt.Printf("withdrawal %s: confirmed, %s %s paid once to %s\n", id, got, asset, to)
	return e.reconcile()
}

func (e *env) await(id string, want []string) error {
	return e.waitFor(3*time.Minute, "withdrawal "+id+" to be "+strings.Join(want, " or "), func() (bool, error) {
		w, err := e.getWd(id)
		if err != nil {
			return false, err
		}
		s, _ := w["status"].(string)
		if s == "failed" {
			return false, fmt.Errorf("withdrawal failed: %v", w["failure_reason"])
		}
		for _, x := range want {
			if s == x {
				fmt.Println(s)
				return true, nil
			}
		}
		return false, nil
	})
}

func (e *env) reconcile() error {
	return e.waitFor(2*time.Minute, "Reconcile to be clean", func() (bool, error) {
		out, err := e.must("ops", "GET", "/v2/reconcile", nil, nil, 200)
		if err != nil {
			return false, err
		}
		return out["clean"] == true, nil
	})
}

// ---- EVM ----

func (e *env) evmPay(to string, amt *big.Int) error {
	rc, err := rpc.DialContext(e.ctx, e.rpcURL)
	if err != nil {
		return err
	}
	defer rc.Close()
	ec := ethclient.NewClient(rc)
	// a sender that exists only for this payment: anvil gives it the balance, the key is dropped after (a signed transaction: the scanner recomputes hashes, which an impersonated one does not survive)
	k, _ := crypto.GenerateKey()
	from := crypto.PubkeyToAddress(k.PublicKey)
	if err := rc.CallContext(e.ctx, nil, "anvil_setBalance", from, (*hexutil.Big)(new(big.Int).Add(amt, big.NewInt(1e18)))); err != nil {
		return err
	}
	dest := common.HexToAddress(to)
	h, err := ec.HeaderByNumber(e.ctx, nil)
	if err != nil {
		return err
	}
	gas, err := ec.EstimateGas(e.ctx, ethereum.CallMsg{From: from, To: &dest, Value: amt}) // 21000 to an account, more to a deposit contract that a sweep has already deployed
	if err != nil {
		return err
	}
	tip := big.NewInt(2e9)
	tx := types.NewTx(&types.DynamicFeeTx{ChainID: big.NewInt(11155111), Nonce: 0, GasTipCap: tip, GasFeeCap: new(big.Int).Add(new(big.Int).Mul(h.BaseFee, big.NewInt(2)), tip), Gas: gas * 12 / 10, To: &dest, Value: amt})
	signed, err := types.SignTx(tx, types.LatestSignerForChainID(tx.ChainId()), k)
	if err != nil {
		return err
	}
	if err := ec.SendTransaction(e.ctx, signed); err != nil {
		return err
	}
	for i := 0; i < 100; i++ {
		if r, err := ec.TransactionReceipt(e.ctx, signed.Hash()); err == nil && r.Status == 1 {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("no receipt for the deposit %s", signed.Hash())
}

func (e *env) evmBalance(a string) (*big.Int, error) {
	ec, err := ethclient.DialContext(e.ctx, e.rpcURL)
	if err != nil {
		return nil, err
	}
	defer ec.Close()
	return ec.BalanceAt(e.ctx, common.HexToAddress(a), nil)
}

// ---- Bitcoin ----

func (e *env) btcCall(wallet, method string, params ...any) (json.RawMessage, error) {
	user, err := readSecret(e.secrets, "btc-rpc-user")
	if err != nil {
		return nil, err
	}
	pass, err := readSecret(e.secrets, "btc-rpc-pass")
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(map[string]any{"jsonrpc": "1.0", "id": "kind", "method": method, "params": params})
	path := ""
	if wallet != "" {
		path = "/wallet/" + wallet
	}
	req, _ := http.NewRequest("POST", e.btcURL+path, bytes.NewReader(body))
	req.SetBasicAuth(user, pass)
	resp, err := (&http.Client{Timeout: time.Minute}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var r struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	raw, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("bitcoind %s: %d %s", method, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if r.Error != nil {
		return nil, fmt.Errorf("bitcoind %s: %d %s", method, r.Error.Code, r.Error.Message)
	}
	return r.Result, nil
}

const miner = "kind"

// btcWallet makes (or loads) the lane's wallet and gives it spendable coins.
func (e *env) btcWallet() error {
	if _, err := e.btcCall("", "createwallet", miner); err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			return err
		}
		if _, err := e.btcCall("", "loadwallet", miner); err != nil && !strings.Contains(err.Error(), "already loaded") {
			return err
		}
	}
	var bal float64
	raw, err := e.btcCall(miner, "getbalance")
	if err != nil {
		return err
	}
	_ = json.Unmarshal(raw, &bal)
	if bal < 10 {
		return e.btcMine(101)
	}
	return nil
}

func (e *env) btcAddress() (string, error) {
	if err := e.btcWallet(); err != nil {
		return "", err
	}
	raw, err := e.btcCall(miner, "getnewaddress", "", "bech32")
	if err != nil {
		return "", err
	}
	var a string
	_ = json.Unmarshal(raw, &a)
	return a, nil
}

func (e *env) btcMine(n int) error {
	a, err := e.btcAddress0()
	if err != nil {
		return err
	}
	_, err = e.btcCall(miner, "generatetoaddress", n, a)
	return err
}

func (e *env) btcAddress0() (string, error) {
	raw, err := e.btcCall(miner, "getnewaddress", "", "bech32")
	if err != nil {
		return "", err
	}
	var a string
	_ = json.Unmarshal(raw, &a)
	return a, nil
}

func btcAmount(sats *big.Int) string {
	s := sats.Int64()
	return fmt.Sprintf("%d.%08d", s/1e8, s%1e8)
}

func (e *env) btcDeposit(addr string, amt *big.Int, hot string, hotSats int64) error {
	if err := e.btcWallet(); err != nil {
		return err
	}
	pay := map[string]string{addr: btcAmount(amt)}
	if hot != "" && hotSats > 0 {
		pay[hot] = btcAmount(big.NewInt(hotSats))
	}
	if _, err := e.btcCall(miner, "sendmany", "", pay); err != nil {
		return err
	}
	return e.btcMine(6)
}

func (e *env) btcReceived(addr string) (*big.Int, error) {
	raw, err := e.btcCall(miner, "getreceivedbyaddress", addr, 1)
	if err != nil {
		return nil, err
	}
	var v json.Number
	_ = json.Unmarshal(raw, &v)
	f, _, err := big.ParseFloat(string(v), 10, 128, big.ToNearestEven)
	if err != nil {
		return nil, err
	}
	r := new(big.Float).Mul(f, big.NewFloat(1e8))
	r.Add(r, big.NewFloat(0.5))
	out, _ := r.Int(nil)
	return out, nil
}
