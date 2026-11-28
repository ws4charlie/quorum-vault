// Command kindgate is the kind lane's helper for onboarding AgentGate (ci/kind/gate.sh) and for its smoke case (ci/kind/smoke/gate.sh). Every key it makes is
// a throwaway made at run time into the lane's gitignored work dir; nothing here is committed.
//
//	kindgate keygen -out DIR                         a Gate Ed25519 key for the smoke case: DIR/gate.key (seed, hex) and DIR/gate.pub (public key, base64url)
//	kindgate usdc   -rpc URL -chain-id ID -state FILE -to ADDR -fund N -pending FILE
//	                                                 deploys the EIP-3009 mock USDC (contracts/test/mocks/Tokens.sol, internal/chain/evm/testdata) once (its address is kept
//	                                                 in -state and reused while the chain still has its code), then mints so that ADDR holds exactly N if it holds less, and
//	                                                 appends "<tx> <amount>" of the mint to -pending (the books must record it: book). Prints the address.
//	kindgate cfg    -in DIR -out DIR -usdc ADDR -wallet-id ID -audience A -kid K -pubkey FILE -ops DIR [-per-payment N -per-hour N -per-day N]
//	                                                 from the lane's generated configs (signing.json, cosigner.json, custody-evm.json in -in) writes the Gate versions of them
//	                                                 to -out (USDC with x402 on hot shard 0, the operators section, the core's gate section) and the gate setting (setting.json).
//	                                                 The two zone operators' keys are made in -ops once. Prints {"partition","wallet_address"}.
//	kindgate book   -cfg custody.json -rpc URL -dsn DSN -pending FILE
//	                                                 books each mint of -pending on the Gate wallet's hot shard (the operator's seed step), once per mint transaction, then
//	                                                 empties the file. The books follow the chain mint by mint, so a top-up while a payment is still being booked keeps them equal.
//
// AgentGate's side of a payment, run in a pod, is ci/kind/tools/kindgatepay.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
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
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ws4charlie/quorum-vault/internal/chain/evm"
	"github.com/ws4charlie/quorum-vault/internal/custody"
	"github.com/ws4charlie/quorum-vault/internal/gateway"
)

const asset = "USDC" // the lane's x402 asset symbol, in the core's and the zone's config

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: kindgate keygen|usdc|cfg|book ...")
		os.Exit(2)
	}
	var err error
	args := os.Args[2:]
	switch os.Args[1] {
	case "keygen":
		err = keygen(args)
	case "usdc":
		err = usdc(args)
	case "cfg":
		err = cfg(args)
	case "book":
		err = book(args)
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "kindgate:", err)
		os.Exit(1)
	}
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "", "output directory")
	fs.Parse(args)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*out, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*out, "gate.key"), []byte(hex.EncodeToString(priv.Seed())+"\n"), 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(*out, "gate.pub"), []byte(base64.RawURLEncoding.EncodeToString(pub)+"\n"), 0o644)
}

// readPub reads a Gate Ed25519 public key in any of the forms a key tool prints: base64url or base64 (with or without padding), hex, or a PEM
// "PUBLIC KEY" (SPKI). It returns the 32-byte key.
func readPub(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if blk, _ := pem.Decode(b); blk != nil {
		if len(blk.Bytes) == 44 { // SPKI of Ed25519: a 12-byte header and the key
			return ed25519.PublicKey(blk.Bytes[12:]), nil
		}
		return nil, fmt.Errorf("%s: PEM block is not an Ed25519 public key", path)
	}
	s := strings.TrimSpace(string(b))
	for _, dec := range []func(string) ([]byte, error){base64.RawURLEncoding.DecodeString, base64.URLEncoding.DecodeString, base64.RawStdEncoding.DecodeString, base64.StdEncoding.DecodeString, hex.DecodeString} {
		if k, err := dec(s); err == nil && len(k) == ed25519.PublicKeySize {
			return ed25519.PublicKey(k), nil
		}
	}
	return nil, fmt.Errorf("%s: not a 32-byte Ed25519 public key (base64url, base64, hex or PEM)", path)
}

// ---- usdc ----

func dialChain(ctx context.Context, url string) (*rpc.Client, *ethclient.Client, error) {
	rc, err := rpc.DialContext(ctx, url)
	if err != nil {
		return nil, nil, err
	}
	return rc, ethclient.NewClient(rc), nil
}

func tokenABI() (abi.ABI, error) {
	b, err := os.ReadFile("internal/chain/evm/testdata/Eip3009Token.abi.json")
	if err != nil {
		return abi.ABI{}, err
	}
	return abi.JSON(strings.NewReader(string(b)))
}

func usdc(args []string) error {
	fs := flag.NewFlagSet("usdc", flag.ExitOnError)
	rpcURL := fs.String("rpc", "", "the chain's RPC address as this machine sees it")
	state := fs.String("state", "", "file that keeps the token's address")
	to := fs.String("to", "", "the Gate wallet's address")
	fund := fs.String("fund", "", "the wallet's USDC balance to top up to (base units)")
	chainID := fs.Uint64("chain-id", 0, "the chain id the node must have")
	pending := fs.String("pending", "", "file the mints are appended to, for book")
	fs.Parse(args)
	want, ok := new(big.Int).SetString(*fund, 10)
	if !ok || want.Sign() < 0 {
		return fmt.Errorf("-fund %q is not an amount", *fund)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	rc, ec, err := dialChain(ctx, *rpcURL)
	if err != nil {
		return err
	}
	defer rc.Close()
	if id, err := ec.ChainID(ctx); err != nil || id.Uint64() != *chainID {
		return fmt.Errorf("refusing: chain id %v, want %d (the lane's anvil): %v", id, *chainID, err)
	}
	a, err := tokenABI()
	if err != nil {
		return err
	}
	// a deployer/minter only this run knows: the mock lets anyone mint, and anvil_setBalance gives it gas
	key, _ := crypto.GenerateKey()
	from := crypto.PubkeyToAddress(key.PublicKey)
	if err := rc.CallContext(ctx, nil, "anvil_setBalance", from, (*hexutil.Big)(new(big.Int).Mul(big.NewInt(10), big.NewInt(1e18)))); err != nil {
		return fmt.Errorf("refusing: not an anvil node: %w", err)
	}
	var tok common.Address
	if b, err := os.ReadFile(*state); err == nil {
		tok = common.HexToAddress(strings.TrimSpace(string(b)))
		if code, err := ec.CodeAt(ctx, tok, nil); err != nil || len(code) == 0 {
			fmt.Fprintf(os.Stderr, "usdc: %s has no code (a new chain): deploying again\n", tok.Hex())
			tok = common.Address{}
		}
	}
	if tok == (common.Address{}) {
		bin, err := os.ReadFile("internal/chain/evm/testdata/Eip3009Token.bin")
		if err != nil {
			return err
		}
		ctor, err := a.Pack("", "USDC") // EIP-712 name "USDC", version "2", 6 decimals: the domain of Circle's USDC
		if err != nil {
			return err
		}
		r, err := send(ctx, ec, key, nil, append(common.FromHex(strings.TrimSpace(string(bin))), ctor...))
		if err != nil {
			return fmt.Errorf("deploy: %w", err)
		}
		tok = r.ContractAddress
		if err := os.WriteFile(*state, []byte(tok.Hex()+"\n"), 0o600); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "usdc: deployed %s\n", tok.Hex())
	}
	holder := common.HexToAddress(*to)
	have, err := balanceOf(ctx, ec, a, tok, holder)
	if err != nil {
		return err
	}
	if d := new(big.Int).Sub(want, have); d.Sign() > 0 {
		data, _ := a.Pack("mint", holder, d)
		r, err := send(ctx, ec, key, &tok, data)
		if err != nil {
			return fmt.Errorf("mint: %w", err)
		}
		f, err := os.OpenFile(*pending, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(f, "%s %s\n", r.TxHash.Hex(), d)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "usdc: minted %s to %s (now %s)\n", d, holder.Hex(), want)
	} else {
		fmt.Fprintf(os.Stderr, "usdc: %s holds %s (>= %s), nothing minted\n", holder.Hex(), have, want)
	}
	fmt.Println(tok.Hex())
	return nil
}

func balanceOf(ctx context.Context, ec *ethclient.Client, a abi.ABI, tok, who common.Address) (*big.Int, error) {
	data, _ := a.Pack("balanceOf", who)
	out, err := ec.CallContract(ctx, callMsg(tok, data), nil)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(out), nil
}

// ---- cfg ----

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

// opKey returns the public key of zone operator name, making its key (hex seed, the form qv-approvers -key reads) in dir once.
func opKey(dir, name string) (string, error) {
	p := filepath.Join(dir, name+".key")
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return "", err
		}
		b = []byte(hex.EncodeToString(priv.Seed()))
		if err := os.WriteFile(p, b, 0o600); err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return "", fmt.Errorf("%s: not a hex Ed25519 seed", p)
	}
	return hex.EncodeToString(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)), nil
}

func cfg(args []string) error {
	fs := flag.NewFlagSet("cfg", flag.ExitOnError)
	in := fs.String("in", "", "the lane's generated configs (signing.json, cosigner.json, custody-evm.json)")
	out := fs.String("out", "", "output directory")
	tok := fs.String("usdc", "", "the mock USDC's address")
	walletID := fs.String("wallet-id", "", "Gate's wallet id (lower-case UUID)")
	audience := fs.String("audience", "", "this deployment's name (the credential's audience)")
	kid := fs.String("kid", "", "Gate's key id")
	pubPath := fs.String("pubkey", "", "Gate's Ed25519 public key file")
	ops := fs.String("ops", "", "directory of the zone operators' keys (made once)")
	perPayment := fs.String("per-payment", "100000", "fast lane and x402: the largest single payment (base units; 100000 = 0.10 USDC)")
	perHour := fs.String("per-hour", "1000000", "fast lane: the total in a rolling hour")
	perDay := fs.String("per-day", "2000000", "fast lane: the total in a rolling day")
	fs.Parse(args)
	pub, err := readPub(*pubPath)
	if err != nil {
		return err
	}
	if !common.IsHexAddress(*tok) {
		return fmt.Errorf("-usdc %q is not an address", *tok)
	}
	token := common.HexToAddress(*tok).Hex()
	var gf, cos gateway.File
	var cf custody.File
	for p, v := range map[string]any{"signing.json": &gf, "cosigner.json": &cos, "custody-evm.json": &cf} {
		if err := readJSON(filepath.Join(*in, p), v); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
	}
	if err := os.MkdirAll(*out, 0o700); err != nil {
		return err
	}

	// ---- the core: USDC on the chain, x402 on hot shard 0, the gate section
	cf.Chain.Assets[asset] = custody.AssetFile{Address: token, Decimals: 6, MinDeposit: "1000", PriceWei: "300000000"}
	cf.Chain.X402 = map[string]custody.X402File{asset: {Name: "USDC", Version: "2", MaxWindowSeconds: 600, PerPaymentLimit: *perPayment, Shard: 0}}
	if cf.Withdrawal.Tiers == nil {
		cf.Withdrawal.Tiers = map[string][]custody.TierFile{}
	}
	cf.Withdrawal.Tiers[asset] = []custody.TierFile{{MinAmount: "0", Approvals: 1, Auto: true}}
	cf.Gate = nil
	custodyPath := filepath.Join(*out, "custody.json")
	if err := writeJSON(custodyPath, cf); err != nil {
		return err
	}
	c, err := custody.LoadConfig(custodyPath)
	if err != nil {
		return fmt.Errorf("custody.json: %w", err)
	}
	part := c.PartitionKey(asset, 0).String()
	ethPart := c.PartitionKey(c.Native, 0).String()
	wallet := cf.Chain.HotShards[0]
	cf.Gate = &custody.GateFile{Audience: *audience, Wallets: map[string]custody.GateWalletFile{*walletID: {Partition: part}}}
	if err := writeJSON(custodyPath, cf); err != nil {
		return err
	}
	if _, err := custody.LoadConfig(custodyPath); err != nil {
		return fmt.Errorf("custody.json: %w", err)
	}

	// ---- the zone: the token, its x402 domain and bounds, the USDC partition of hot shard 0 (the same key), an asset policy, two operators
	opf := &gateway.OperatorsFile{Keys: map[string]gateway.OperatorFile{}, MinOperators: 2}
	for _, n := range []string{"op1", "op2"} {
		k, err := opKey(*ops, n)
		if err != nil {
			return err
		}
		opf.Keys[n] = gateway.OperatorFile{PublicKey: k}
	}
	zone := func(f *gateway.File) error {
		for name, ch := range f.Chains {
			if ch.EVM == nil {
				continue
			}
			e := ch.EVM
			if e.Tokens == nil {
				e.Tokens = map[string]gateway.TokenFile{}
			}
			e.Tokens[asset] = gateway.TokenFile{Address: token, Decimals: 6}
			e.X402 = map[string]gateway.X402File{asset: {Name: "USDC", Version: "2", MaxWindowSeconds: 600, PerPaymentLimit: *perPayment}}
			hot, ok := e.HotAddresses[ethPart]
			if !ok {
				return fmt.Errorf("zone config: chain %s has no hot address for %s", name, ethPart)
			}
			e.HotAddresses[part] = hot
			if _, ok := e.ColdAddresses["omnibus/token"]; !ok {
				e.ColdAddresses["omnibus/token"] = e.ColdAddresses["omnibus/native"]
			}
			ch.Assets[asset] = gateway.AssetFile{AnyDestination: true, PerTxCap: "10000000", DailyCap: "100000000", ToColdDailyCap: "0", RebalanceDailyCap: "0",
				Tiers: []gateway.TierFile{{MinAmount: "0", Approvals: 1}}}
			f.Chains[name] = ch
		}
		if s, ok := f.Signers[ethPart]; ok { // the gateway's: the USDC partition signs with hot shard 0's key (the cosigner has no signers)
			f.Signers[part] = s
		}
		f.Operators = opf
		return nil
	}
	for name, f := range map[string]*gateway.File{"signing.json": &gf, "cosigner.json": &cos} {
		if err := zone(f); err != nil {
			return err
		}
		p := filepath.Join(*out, name)
		if err := writeJSON(p, f); err != nil {
			return err
		}
		b, _ := os.ReadFile(p)
		if _, err := gateway.ParseConfig(b); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}

	// ---- the gate setting the operators sign: Gate's key, the wallet, its fast lane
	setting := gateway.GateSettingFile{Audience: *audience, SkewSeconds: 30, MaxTTLSeconds: 600,
		Keys: []gateway.GateKeyFile{{KID: *kid, PublicKey: base64.RawURLEncoding.EncodeToString(pub)}},
		Wallets: []gateway.GateWalletFile{{WalletID: *walletID, Partition: part,
			Limits: map[string]gateway.GateLimitFile{asset: {PerPayment: *perPayment, PerHour: *perHour, PerDay: *perDay}}}}}
	if err := writeJSON(filepath.Join(*out, "setting.json"), setting); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]string{"partition": part, "wallet_address": common.HexToAddress(wallet).Hex()})
}

// ---- book ----

func book(args []string) error {
	fs := flag.NewFlagSet("book", flag.ExitOnError)
	cfgPath := fs.String("cfg", "", "the core's custody config (with USDC)")
	rpcURL := fs.String("rpc", "", "the chain's RPC address as this machine sees it")
	dsn := fs.String("dsn", "", "business database DSN of a role that may book transfers (the core's)")
	pending := fs.String("pending", "", "the mints to book (usdc -pending)")
	fs.Parse(args)
	b, err := os.ReadFile(*pending)
	if errors.Is(err, os.ErrNotExist) || (err == nil && strings.TrimSpace(string(b)) == "") {
		fmt.Println("books: no mint to book")
		return nil
	} else if err != nil {
		return err
	}
	cfg, err := custody.LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	cfg.EVM.RPCURL = *rpcURL
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	pool, err := pgxpool.New(ctx, *dsn)
	if err != nil {
		return err
	}
	defer pool.Close()
	adapter, err := evm.New(ctx, cfg.EVM, pool)
	if err != nil {
		return err
	}
	defer adapter.Close()
	reader, err := custody.NewEVMReader(ctx, cfg)
	if err != nil {
		return err
	}
	defer reader.Close()
	svc := custody.New(pool, cfg, adapter, reader)
	part := cfg.PartitionKey(asset, 0).String()
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		f := strings.Fields(line)
		amt, ok := new(big.Int), false
		if len(f) == 2 {
			amt, ok = amt.SetString(f[1], 10)
		}
		if !ok || amt.Sign() <= 0 {
			return fmt.Errorf("%s: bad line %q", *pending, line)
		}
		// the mint's transaction names the entry: booking the same mint again books nothing
		if err := svc.FundHotAsset(ctx, "kind-gate-mint-"+strings.ToLower(f[0]), 0, asset, amt); err != nil {
			return err
		}
		fmt.Printf("books: %s USDC base units on hot:%s (mint %s)\n", amt, part, f[0])
	}
	return os.Remove(*pending)
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
