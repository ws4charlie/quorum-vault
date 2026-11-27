package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/ws4charlie/quorum-vault/internal/chain/sol/solmsg"
	"github.com/ws4charlie/quorum-vault/internal/coldsign"
	"github.com/ws4charlie/quorum-vault/internal/hsm"
	"github.com/ws4charlie/quorum-vault/internal/hsm/hsmtest"
)

// The production guard of the cold signer, the same rule as qv-gateway and qv-rekey: with QV_ENV unset (production) a SoftHSM module is
// refused and a PIN in an environment variable is refused, before any key is made or used; with QV_ENV=dev SoftHSM works with one warning line.
func TestColdRefusesSoftHSMInProduction(t *testing.T) {
	hsmtest.Token(t, "qv-cold") // skips (or fails under QV_REQUIRE_HSM) when the token is missing
	pin := hsmtest.PIN(t)
	pinFile := filepath.Join(t.TempDir(), "pin")
	if err := os.WriteFile(pinFile, []byte(pin+"\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	keygen := func() (string, string, error) {
		var out, errb bytes.Buffer
		err := run([]string{"keygen", "-lib", hsm.DefaultLibPath(), "-pin-env", "QV_COLD_TEST_PIN"}, &out, &errb)
		return out.String(), errb.String(), err
	}

	t.Run("production, PIN file, SoftHSM: refused", func(t *testing.T) {
		t.Setenv("QV_ENV", "") // unset is production
		t.Setenv("QV_COLD_TEST_PIN", "")
		t.Setenv(hsm.PINFileEnv, pinFile)
		out, _, err := keygen()
		if err == nil || !strings.Contains(err.Error(), "is SoftHSM") || !strings.Contains(err.Error(), "refused in production") {
			t.Fatalf("keygen in production on SoftHSM: err %v, want the SoftHSM refusal", err)
		}
		if out != "" {
			t.Fatalf("a refused keygen wrote a key:\n%s", out)
		}
	})
	t.Run("production, PIN in the environment: refused", func(t *testing.T) {
		t.Setenv("QV_ENV", "production")
		t.Setenv("QV_COLD_TEST_PIN", pin)
		t.Setenv(hsm.PINFileEnv, "")
		out, _, err := keygen()
		if err == nil || !strings.Contains(err.Error(), "$QV_COLD_TEST_PIN is refused in production") {
			t.Fatalf("keygen in production with an environment PIN: err %v, want the PIN refusal", err)
		}
		if out != "" {
			t.Fatalf("a refused keygen wrote a key:\n%s", out)
		}
	})
	t.Run("dev, SoftHSM: works with a warning", func(t *testing.T) {
		t.Setenv("QV_ENV", "dev")
		t.Setenv("QV_COLD_TEST_PIN", pin)
		t.Setenv(hsm.PINFileEnv, "")
		out, errOut, err := keygen()
		if err != nil {
			t.Fatalf("keygen in dev: %v\n%s", err, errOut)
		}
		if !strings.Contains(out, `"key_id"`) {
			t.Fatalf("keygen in dev printed no key:\n%s", out)
		}
		if n := strings.Count(errOut, "WARNING: the PKCS#11 module is SoftHSM"); n != 1 {
			t.Fatalf("dev keygen printed the SoftHSM warning %d times, want once:\n%s", n, errOut)
		}
	})
}

// The same guard on every sign path (EVM, Bitcoin, Solana): a valid request with enough approvals is still refused in production on SoftHSM,
// and with a PIN in the environment, before the token is opened (the cold keys here are not even in the token). A PIN file with a mode others
// can read is refused too.
func TestColdSignRefusedInProduction(t *testing.T) {
	hsmtest.Lib(t) // the SoftHSM module; skips (or fails under QV_REQUIRE_HSM) when it is missing
	dir := t.TempDir()
	pinFile := filepath.Join(dir, "pin")
	if err := os.WriteFile(pinFile, []byte("not-the-pin\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	ops := map[string]ed25519.PrivateKey{}
	opsPub := map[string]string{}
	for _, n := range []string{"alice", "bob", "carol"} {
		p, k, _ := ed25519.GenerateKey(rand.Reader)
		ops[n], opsPub[n] = k, hex.EncodeToString(p)
	}
	hsmCfg := coldsign.HSMConfig{Token: "qv-cold", PinEnv: "QV_COLD_TEST_PIN", KeyID: "00112233"}
	writeJSON := func(name string, v any) string {
		p := filepath.Join(dir, name)
		b, _ := json.Marshal(v)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	approvals := func(name, hash string) []string {
		var args []string
		for _, n := range []string{"alice", "bob"} {
			args = append(args, "-approval", writeJSON(name+"-"+n+".approval", coldsign.Approve(n, ops[n], hash)))
		}
		return args
	}
	type ceremony struct{ cfg, req, hash string }
	var cases = map[string]ceremony{}

	{ // EVM
		k, _ := crypto.GenerateKey()
		pub := hex.EncodeToString(crypto.FromECDSAPub(&k.PublicKey))
		hot := common.HexToAddress("0x0000000000000000000000000000000000000407")
		cfg := coldsign.Config{Chain: "evm-test", ChainID: 31337, Pool: "omnibus", Operators: opsPub, Threshold: 2, Destinations: []string{hot.Hex()},
			Assets: map[string]coldsign.AssetPolicy{"ETH": {Decimals: 18, MaxAmount: "5000000000000000000"}}, MaxFeeWei: "5000000000000000",
			PublicKey: pub, HSM: hsmCfg, RecordDir: filepath.Join(dir, "evm-record")}
		r := coldsign.Request{Version: coldsign.RequestVersion, ID: "rf-1", Revision: 1, Chain: "evm-test", ChainID: 31337, Pool: "omnibus", Asset: "ETH",
			From: crypto.PubkeyToAddress(k.PublicKey).Hex(), To: hot.Hex(), Amount: "1000000000000000000", Nonce: 3, Gas: 21000, MaxFeePerGas: "30000000000", MaxPriorityFeePerGas: "1000000000"}
		cases["evm"] = ceremony{writeJSON("evm-cfg.json", cfg), writeJSON("evm-req.json", r.File()), r.HashHex()}
	}
	{ // Bitcoin
		key := func() string {
			k, _ := crypto.GenerateKey()
			c, err := coldsign.CompressPublicKey(hex.EncodeToString(crypto.FromECDSAPub(&k.PublicKey)))
			if err != nil {
				t.Fatal(err)
			}
			return c
		}
		coldPub, hotPub := key(), key()
		cold, _ := coldsign.BTCAddressOf("regtest", coldPub)
		hot, _ := coldsign.BTCAddressOf("regtest", hotPub)
		cfg := coldsign.BTCConfig{Family: "btc", Network: "regtest", Chain: "btc-t", Pool: "omnibus", Operators: opsPub, Threshold: 2, HotShards: []string{hot},
			MaxAmount: 50_000_000, MaxFeeSats: 20_000, MaxFeeRate: 100, MaxInputs: 5, PublicKey: coldPub, HSM: hsmCfg, RecordDir: filepath.Join(dir, "btc-record")}
		txid := sha256.Sum256([]byte("outpoint"))
		r := coldsign.BTCRequest{Version: coldsign.BTCRequestVersion, ID: "rf-1", Revision: 1, Network: "regtest", Chain: "btc-t", Pool: "omnibus", From: cold,
			Inputs:  []coldsign.BTCInput{{TxID: hex.EncodeToString(txid[:]), Value: 5_000_000, Address: cold}},
			Outputs: []coldsign.BTCOutput{{Address: hot, Value: 4_000_000}, {Address: cold, Value: 998_000}}}
		cases["btc"] = ceremony{writeJSON("btc-cfg.json", cfg), writeJSON("btc-req.json", r.File()), r.HashHex()}
	}
	{ // Solana
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		hotB := make([]byte, 32)
		rand.Read(hotB)
		hot, cold := base58.Encode(hotB), base58.Encode(pub)
		cfg := coldsign.SOLConfig{Family: "sol", Chain: "solana-localnet", Pool: "p1", Operators: opsPub, Threshold: 2, Destinations: []string{hot},
			Assets: map[string]coldsign.SOLAssetPolicy{"SOL": {Decimals: 9, MaxAmount: "10000000000"}}, NoncePool: 4, MaxComputeUnits: 200_000,
			MaxMicroLamports: 1_000_000, MaxPriorityLamports: 50_000, PublicKey: hex.EncodeToString(pub), HSM: hsmCfg, RecordDir: filepath.Join(dir, "sol-record")}
		coldA, _ := solmsg.ParseAddress(cold)
		var v [32]byte
		rand.Read(v[:])
		r := coldsign.SOLRequest{Version: coldsign.SOLRequestVersion, ID: "r-1", Chain: "solana-localnet", Pool: "p1", Asset: "SOL", Decimals: 9, From: cold, To: hot,
			Amount: "1000000", NonceAccount: solmsg.Address(solmsg.NonceAddress(coldA, 0)), NonceValue: base58.Encode(v[:]), ComputeUnitLimit: 100_000}
		cases["sol"] = ceremony{writeJSON("sol-cfg.json", cfg), writeJSON("sol-req.json", r.File()), r.HashHex()}
	}

	for name, c := range cases {
		sign := func(t *testing.T) (string, error) {
			t.Helper()
			var out, errb bytes.Buffer
			args := append([]string{"sign", "-config", c.cfg, "-request", c.req, "-out", filepath.Join(dir, name+"-signed.json")}, approvals(name, c.hash)...)
			err := run(args, &out, &errb)
			if !strings.Contains(out.String(), "APPROVALS  2 of 2 required") {
				t.Fatalf("%s: the request did not reach the HSM step (approvals not counted):\n%s%s", name, out.String(), errb.String())
			}
			return out.String(), err
		}
		t.Run(name+": production, PIN file, SoftHSM: refused", func(t *testing.T) {
			t.Setenv("QV_ENV", "")
			t.Setenv("QV_COLD_TEST_PIN", "")
			t.Setenv(hsm.PINFileEnv, pinFile)
			out, err := sign(t)
			if err == nil || !strings.Contains(err.Error(), "is SoftHSM") || !strings.Contains(err.Error(), "refused in production") {
				t.Fatalf("err %v, want the SoftHSM refusal", err)
			}
			if strings.Contains(out, "SIGNED") {
				t.Fatalf("signed in production on SoftHSM:\n%s", out)
			}
		})
		t.Run(name+": production, PIN in the environment: refused", func(t *testing.T) {
			t.Setenv("QV_ENV", "production")
			t.Setenv("QV_COLD_TEST_PIN", "not-the-pin")
			t.Setenv(hsm.PINFileEnv, "")
			if _, err := sign(t); err == nil || !strings.Contains(err.Error(), "$QV_COLD_TEST_PIN is refused in production") {
				t.Fatalf("err %v, want the PIN refusal", err)
			}
		})
	}

	t.Run("a PIN file others can read: refused", func(t *testing.T) {
		loose := filepath.Join(dir, "loose-pin")
		if err := os.WriteFile(loose, []byte("not-the-pin\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(loose, 0o644); err != nil {
			t.Fatal(err)
		}
		for _, env := range []string{"", "dev"} {
			t.Setenv("QV_ENV", env)
			t.Setenv("QV_COLD_TEST_PIN", "")
			t.Setenv(hsm.PINFileEnv, loose)
			var out, errb bytes.Buffer
			err := run([]string{"keygen", "-lib", hsm.DefaultLibPath(), "-pin-env", "QV_COLD_TEST_PIN"}, &out, &errb)
			if err == nil || !strings.Contains(err.Error(), "others must have no access") {
				t.Fatalf("QV_ENV=%q, PIN file mode 0644: err %v, want the mode refusal", env, err)
			}
			if out.Len() != 0 {
				t.Fatalf("QV_ENV=%q: a refused keygen wrote a key:\n%s", env, out.String())
			}
		}
	})
}
