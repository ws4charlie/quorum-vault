// Command qv-cold is the OFFLINE cold signer. It runs on a machine with no network: it opens no connection at all, it contains
// no network client (internal/coldsign's tests check the import graph), and everything crosses the air gap as files.
//
// Commands:
//
//	keygen        create the cold key in the qv-cold token and print its public key and CKA_ID
//	operator-key  create an operator's Ed25519 key file and print its public key
//	inspect       show a request in words, and say whether this signer would sign it
//	approve       an operator signs a request with their own key
//	sign          check the request, count the approvals, sign in the HSM, write the signed transaction file
//
// A Bitcoin config ("family": "btc") and a Bitcoin request take the same commands; keygen -network <name> also prints the Bitcoin cold address.
//
// SoftHSM cannot enforce M-of-N with cards the way a real HSM does, so THIS TOOL enforces it in software with operator
// signatures. That is a stand-in, and the output says so.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"

	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/ws4charlie/quorum-vault/internal/coldsign"
	"github.com/ws4charlie/quorum-vault/internal/domain"
	"github.com/ws4charlie/quorum-vault/internal/hsm"
)

const softwareNote = "NOTE: M-of-N here is enforced in software with operator Ed25519 signatures (SoftHSM has no cards). A hardware HSM would enforce it itself."

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "qv-cold:", err)
		os.Exit(1)
	}
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func run(args []string, out, errw io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: qv-cold keygen|operator-key|inspect|approve|sign ...")
	}
	cmd, args := args[0], args[1:]
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(errw)
	cfgPath := fs.String("config", "", "offline config file")
	reqPath := fs.String("request", "", "request file")
	outPath := fs.String("out", "", "output file (default: stdout)")
	keyPath := fs.String("key", "", "operator key file (hex seed)")
	operator := fs.String("operator", "", "operator name")
	lib := fs.String("lib", hsm.DefaultLibPath(), "PKCS#11 module (keygen)")
	token := fs.String("token", "qv-cold", "token label (keygen)")
	network := fs.String("network", "", "bitcoin network (keygen): also print the cold address for it (mainnet, testnet3, signet, regtest)")
	curve := fs.String("curve", "secp256k1", "key type (keygen): secp256k1 (EVM, Bitcoin) or ed25519 (Solana)")
	pinEnv := fs.String("pin-env", "QV_COLD_PIN", "environment variable holding the token PIN (keygen)")
	var approvals multi
	fs.Var(&approvals, "approval", "approval file (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	write := func(v any) error {
		b, _ := json.MarshalIndent(v, "", "  ")
		if *outPath == "" {
			_, err := fmt.Fprintln(out, string(b))
			return err
		}
		return os.WriteFile(*outPath, append(b, '\n'), 0o600)
	}

	switch cmd {
	case "keygen":
		pin := os.Getenv(*pinEnv)
		if pin == "" {
			return fmt.Errorf("the token PIN is not in $%s", *pinEnv)
		}
		l, err := hsm.LoadLib(*lib)
		if err != nil {
			return err
		}
		defer l.Close()
		tok, err := l.OpenToken(*token, pin)
		if err != nil {
			return err
		}
		defer tok.Close()
		id := make([]byte, 16)
		rand.Read(id)
		if *curve == "ed25519" { // a Solana cold key: the address is the public key in base58
			pub, err := tok.GenerateEd25519KeyPair(context.Background(), "qv-cold-"+hex.EncodeToString(id[:4]), id)
			if err != nil {
				return err
			}
			addr := base58.Encode(pub)
			fmt.Fprintf(errw, "solana cold address %s\n", addr)
			return write(map[string]string{"key_id": hex.EncodeToString(id), "public_key": hex.EncodeToString(pub), "address": addr})
		}
		pub, err := tok.GenerateECKeyPair(context.Background(), domain.CurveSecp256k1, "qv-cold-"+hex.EncodeToString(id[:4]), id)
		if err != nil {
			return err
		}
		pk, err := crypto.UnmarshalPubkey(pub)
		if err != nil {
			return err
		}
		fmt.Fprintf(errw, "cold address %s\n", crypto.PubkeyToAddress(*pk))
		res := map[string]string{"key_id": hex.EncodeToString(id), "public_key": hex.EncodeToString(pub), "address": crypto.PubkeyToAddress(*pk).Hex()}
		if *network != "" { // the same key as a Bitcoin cold key: a compressed key and its P2WPKH address on the network
			comp, err := coldsign.CompressPublicKey(hex.EncodeToString(pub))
			if err != nil {
				return err
			}
			addr, err := coldsign.BTCAddressOf(*network, comp)
			if err != nil {
				return err
			}
			fmt.Fprintf(errw, "bitcoin cold address (%s) %s\n", *network, addr)
			res["btc_public_key"], res["btc_address"] = comp, addr
		}
		return write(res)

	case "operator-key":
		if *keyPath == "" {
			return fmt.Errorf("-key <file> is required")
		}
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		if err := os.WriteFile(*keyPath, []byte(hex.EncodeToString(priv.Seed())), 0o600); err != nil {
			return err
		}
		fmt.Fprintln(out, hex.EncodeToString(pub))
		return nil

	case "inspect", "sign":
		if cb, err := os.ReadFile(*cfgPath); err == nil && coldsign.IsBTCConfig(cb) {
			return runBTC(cmd, *cfgPath, *reqPath, approvals, out, write)
		} else if err == nil && coldsign.IsSOLConfig(cb) {
			return runSOL(cmd, *cfgPath, *reqPath, approvals, out, write)
		}
		cfg, err := coldsign.LoadConfig(*cfgPath)
		if err != nil {
			return err
		}
		rf, err := readJSON[coldsign.RequestFile](*reqPath)
		if err != nil {
			return err
		}
		r, _, cerr := cfg.Check(rf)
		pol := cfg.Assets[r.Asset]
		fmt.Fprintf(out, "REQUEST\n%s  hash      %s\n", r.Summary(pol.Decimals), rf.RequestHash)
		var apps []coldsign.Approval
		for _, p := range approvals {
			a, err := readJSON[coldsign.Approval](p)
			if err != nil {
				return err
			}
			apps = append(apps, a)
		}
		names, ignored := cfg.CountApprovals(rf.RequestHash, apps)
		fmt.Fprintf(out, "APPROVALS  %d of %d required: %v\n", len(names), cfg.Threshold, names)
		for _, ig := range ignored {
			fmt.Fprintf(out, "  not counted: %s\n", ig)
		}
		fmt.Fprintln(out, softwareNote)
		if cerr != nil {
			return cerr
		}
		if cmd == "inspect" {
			fmt.Fprintln(out, "CHECK      this signer would accept the request (the approvals are checked at signing)")
			return nil
		}
		pin := os.Getenv(cfg.HSM.PinEnv)
		if pin == "" {
			return fmt.Errorf("the token PIN is not in $%s", cfg.HSM.PinEnv)
		}
		l, err := hsm.LoadLib(orDefault(cfg.HSM.Lib, hsm.DefaultLibPath()))
		if err != nil {
			return err
		}
		defer l.Close()
		tok, err := l.OpenToken(cfg.HSM.Token, pin)
		if err != nil {
			return err
		}
		defer tok.Close()
		id, err := hex.DecodeString(cfg.HSM.KeyID)
		if err != nil {
			return fmt.Errorf("config hsm.key_id: %w", err)
		}
		signed, _, err := cfg.Sign(context.Background(), rf, apps, tokenSigner{tok: tok, id: id})
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "SIGNED     tx %s by %s\n", signed.TxHash, signed.Signer)
		return write(signed)

	case "approve":
		if *keyPath == "" || *operator == "" || *reqPath == "" {
			return fmt.Errorf("approve needs -operator, -key and -request")
		}
		if rb, err := os.ReadFile(*reqPath); err == nil && coldsign.IsBTCRequest(rb) {
			return approveBTC(*operator, *keyPath, *reqPath, out, write)
		} else if err == nil && coldsign.IsSOLRequest(rb) {
			return approveSOL(*operator, *keyPath, *reqPath, out, write)
		}
		rf, err := readJSON[coldsign.RequestFile](*reqPath)
		if err != nil {
			return err
		}
		if rf.RequestHash != rf.Request.HashHex() {
			return fmt.Errorf("the request file is damaged: its hash does not match its content; do not approve")
		}
		seedHex, err := os.ReadFile(*keyPath)
		if err != nil {
			return err
		}
		seed, err := hex.DecodeString(strings.TrimSpace(string(seedHex)))
		if err != nil || len(seed) != ed25519.SeedSize {
			return fmt.Errorf("operator key file must hold %d hex bytes", ed25519.SeedSize)
		}
		fmt.Fprintf(out, "You are approving, as %s:\n%s  hash      %s\n", *operator, rf.Request.Summary(0), rf.RequestHash)
		return write(coldsign.Approve(*operator, ed25519.NewKeyFromSeed(seed), rf.RequestHash))
	}
	return fmt.Errorf("unknown command %q", cmd)
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func readJSON[T any](path string) (T, error) {
	var v T
	if path == "" {
		return v, fmt.Errorf("a file argument is missing")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return v, err
	}
	return v, json.Unmarshal(b, &v)
}

// tokenSigner signs with the cold key inside the token.
type tokenSigner struct {
	tok *hsm.Token
	id  []byte
}

func (s tokenSigner) SignDigest(ctx context.Context, digest [32]byte) (*big.Int, *big.Int, error) {
	return s.tok.SignECDSA(ctx, s.id, digest)
}

// runBTC is inspect and sign for a Bitcoin config: the same steps, the Bitcoin rules.
func runBTC(cmd, cfgPath, reqPath string, approvals []string, out io.Writer, write func(any) error) error {
	cfg, err := coldsign.LoadBTCConfig(cfgPath)
	if err != nil {
		return err
	}
	rf, err := readJSON[coldsign.BTCRequestFile](reqPath)
	if err != nil {
		return err
	}
	r, _, cerr := cfg.Check(rf)
	fmt.Fprintf(out, "REQUEST\n%s  hash      %s\n", r.Summary(), rf.RequestHash)
	var apps []coldsign.Approval
	for _, p := range approvals {
		a, err := readJSON[coldsign.Approval](p)
		if err != nil {
			return err
		}
		apps = append(apps, a)
	}
	names, ignored := cfg.CountApprovals(rf.RequestHash, apps)
	fmt.Fprintf(out, "APPROVALS  %d of %d required: %v\n", len(names), cfg.Threshold, names)
	for _, ig := range ignored {
		fmt.Fprintf(out, "  not counted: %s\n", ig)
	}
	fmt.Fprintln(out, softwareNote)
	if cerr != nil {
		return cerr
	}
	if cmd == "inspect" {
		fmt.Fprintln(out, "CHECK      this signer would accept the request (the approvals and the record of signed outpoints are checked at signing)")
		return nil
	}
	pin := os.Getenv(cfg.HSM.PinEnv)
	if pin == "" {
		return fmt.Errorf("the token PIN is not in $%s", cfg.HSM.PinEnv)
	}
	l, err := hsm.LoadLib(orDefault(cfg.HSM.Lib, hsm.DefaultLibPath()))
	if err != nil {
		return err
	}
	defer l.Close()
	tok, err := l.OpenToken(cfg.HSM.Token, pin)
	if err != nil {
		return err
	}
	defer tok.Close()
	id, err := hex.DecodeString(cfg.HSM.KeyID)
	if err != nil {
		return fmt.Errorf("config hsm.key_id: %w", err)
	}
	signed, _, err := cfg.Sign(context.Background(), rf, apps, tokenSigner{tok: tok, id: id})
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "SIGNED     tx %s by %s\n", signed.TxID, signed.Signer)
	return write(signed)
}

func approveBTC(operator, keyPath, reqPath string, out io.Writer, write func(any) error) error {
	rf, err := readJSON[coldsign.BTCRequestFile](reqPath)
	if err != nil {
		return err
	}
	if rf.RequestHash != rf.Request.HashHex() {
		return fmt.Errorf("the request file is damaged: its hash does not match its content; do not approve")
	}
	seedHex, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(seedHex)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return fmt.Errorf("operator key file must hold %d hex bytes", ed25519.SeedSize)
	}
	fmt.Fprintf(out, "You are approving, as %s:\n%s  hash      %s\n", operator, rf.Request.Summary(), rf.RequestHash)
	return write(coldsign.Approve(operator, ed25519.NewKeyFromSeed(seed), rf.RequestHash))
}

func (s tokenSigner) SignMessage(ctx context.Context, msg []byte) ([]byte, error) {
	return s.tok.SignEd25519(ctx, s.id, msg)
}

// runSOL is inspect and sign for a Solana config.
func runSOL(cmd, cfgPath, reqPath string, approvals []string, out io.Writer, write func(any) error) error {
	cfg, err := coldsign.LoadSOLConfig(cfgPath)
	if err != nil {
		return err
	}
	rf, err := readJSON[coldsign.SOLRequestFile](reqPath)
	if err != nil {
		return err
	}
	r, _, cerr := cfg.Check(rf)
	fmt.Fprintf(out, "REQUEST\n%s  hash      %s\n", r.Summary(r.Decimals), rf.RequestHash)
	var apps []coldsign.Approval
	for _, p := range approvals {
		a, err := readJSON[coldsign.Approval](p)
		if err != nil {
			return err
		}
		apps = append(apps, a)
	}
	names, ignored := cfg.CountApprovals(rf.RequestHash, apps)
	fmt.Fprintf(out, "APPROVALS  %d of %d required: %v\n", len(names), cfg.Threshold, names)
	for _, ig := range ignored {
		fmt.Fprintf(out, "  not counted: %s\n", ig)
	}
	fmt.Fprintln(out, softwareNote)
	if cerr != nil {
		return cerr
	}
	if cmd == "inspect" {
		fmt.Fprintln(out, "CHECK      this signer would accept the request (the approvals and the record of signed nonce values are checked at signing)")
		return nil
	}
	pin := os.Getenv(cfg.HSM.PinEnv)
	if pin == "" {
		return fmt.Errorf("the token PIN is not in $%s", cfg.HSM.PinEnv)
	}
	l, err := hsm.LoadLib(orDefault(cfg.HSM.Lib, hsm.DefaultLibPath()))
	if err != nil {
		return err
	}
	defer l.Close()
	tok, err := l.OpenToken(cfg.HSM.Token, pin)
	if err != nil {
		return err
	}
	defer tok.Close()
	id, err := hex.DecodeString(cfg.HSM.KeyID)
	if err != nil {
		return fmt.Errorf("config hsm.key_id: %w", err)
	}
	signed, _, err := cfg.Sign(context.Background(), rf, apps, tokenSigner{tok: tok, id: id})
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "SIGNED     tx %s by %s\n", signed.TxHash, signed.Signer)
	return write(signed)
}

func approveSOL(operator, keyPath, reqPath string, out io.Writer, write func(any) error) error {
	rf, err := readJSON[coldsign.SOLRequestFile](reqPath)
	if err != nil {
		return err
	}
	if rf.RequestHash != rf.Request.HashHex() {
		return fmt.Errorf("the request file is damaged: its hash does not match its content; do not approve")
	}
	seedHex, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(seedHex)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return fmt.Errorf("operator key file must hold %d hex bytes", ed25519.SeedSize)
	}
	fmt.Fprintf(out, "You are approving, as %s:\n%s  hash      %s\n", operator, rf.Request.Summary(rf.Request.Decimals), rf.RequestHash)
	return write(coldsign.Approve(operator, ed25519.NewKeyFromSeed(seed), rf.RequestHash))
}
