package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/ws4charlie/quorum-vault/internal/coldsign"
	"github.com/ws4charlie/quorum-vault/internal/hsm"
	"github.com/ws4charlie/quorum-vault/internal/hsm/hsmtest"
)

// The whole offline ceremony through the command line, with a real key in the qv-cold SoftHSM token: keygen, three operators, a
// request for 1 ETH, inspect, two approvals, sign; then the refusals the tool must give.
func TestCeremonyThroughTheCommandLine(t *testing.T) {
	hsmtest.Token(t, "qv-cold") // skips (or fails under QV_REQUIRE_HSM) when the token is missing
	t.Setenv("QV_HSM_PIN", hsmtest.PIN(t))
	dir := t.TempDir()
	runOK := func(args ...string) string {
		t.Helper()
		var out, errb bytes.Buffer
		if err := run(args, &out, &errb); err != nil {
			t.Fatalf("qv-cold %v: %v\n%s%s", args, err, out.String(), errb.String())
		}
		return out.String()
	}
	runErr := func(args ...string) string {
		t.Helper()
		var out, errb bytes.Buffer
		err := run(args, &out, &errb)
		if err == nil {
			t.Fatalf("qv-cold %v succeeded, want a refusal\n%s", args, out.String())
		}
		return err.Error() + "\n" + out.String()
	}

	var key struct{ KeyID, PublicKey, Address string }
	kj := filepath.Join(dir, "key.json")
	runOK("keygen", "-lib", hsm.DefaultLibPath(), "-pin-env", "QV_HSM_PIN", "-out", kj)
	b, _ := os.ReadFile(kj)
	var raw map[string]string
	json.Unmarshal(b, &raw)
	key.KeyID, key.PublicKey, key.Address = raw["key_id"], raw["public_key"], raw["address"]

	ops := map[string]string{}
	for _, n := range []string{"alice", "bob", "carol"} {
		ops[n] = strings.TrimSpace(runOK("operator-key", "-key", filepath.Join(dir, n+".key")))
	}
	hot := common.HexToAddress("0x0000000000000000000000000000000000000407")
	cfg := coldsign.Config{Chain: "evm-test", ChainID: 31337, Pool: "omnibus", Operators: ops, Threshold: 2, Destinations: []string{hot.Hex()},
		Assets: map[string]coldsign.AssetPolicy{"ETH": {Decimals: 18, MaxAmount: "5000000000000000000"}}, MaxFeeWei: "5000000000000000",
		PublicKey: key.PublicKey, HSM: coldsign.HSMConfig{Token: "qv-cold", PinEnv: "QV_HSM_PIN", KeyID: key.KeyID}, RecordDir: filepath.Join(dir, "record")}
	cfgPath := filepath.Join(dir, "cfg.json")
	cb, _ := json.Marshal(cfg)
	os.WriteFile(cfgPath, cb, 0o600)

	mk := func(name string, mut func(*coldsign.Request)) string {
		r := coldsign.Request{Version: coldsign.RequestVersion, ID: "rf-1", Revision: 1, Chain: "evm-test", ChainID: 31337, Pool: "omnibus", Asset: "ETH",
			From: key.Address, To: hot.Hex(), Amount: "1000000000000000000", Nonce: 3, Gas: 21000, MaxFeePerGas: "30000000000", MaxPriorityFeePerGas: "1000000000"}
		if mut != nil {
			mut(&r)
		}
		p := filepath.Join(dir, name+".json")
		jb, _ := json.Marshal(r.File())
		os.WriteFile(p, jb, 0o600)
		return p
	}
	req := mk("req", nil)
	insp := runOK("inspect", "-config", cfgPath, "-request", req)
	for _, want := range []string{"to        " + hot.Hex(), "amount    1 (1000000000000000000 base units)", "nonce     3", "at most 630000000000000 wei", "enforced in software", "this signer would accept"} {
		if !strings.Contains(insp, want) {
			t.Errorf("inspect output lacks %q:\n%s", want, insp)
		}
	}
	approve := func(who, reqPath string) string {
		p := filepath.Join(dir, who+"-"+filepath.Base(reqPath))
		runOK("approve", "-operator", who, "-key", filepath.Join(dir, who+".key"), "-request", reqPath, "-out", p)
		return p
	}
	signedPath := filepath.Join(dir, "signed.json")
	// One approval is not enough.
	if msg := runErr("sign", "-config", cfgPath, "-request", req, "-approval", approve("alice", req), "-out", signedPath); !strings.Contains(msg, "1 valid approval(s)") {
		t.Errorf("one approval: %s", msg)
	}
	out := runOK("sign", "-config", cfgPath, "-request", req, "-approval", approve("alice", req), "-approval", approve("carol", req), "-out", signedPath)
	if !strings.Contains(out, "APPROVALS  2 of 2 required: [alice carol]") || !strings.Contains(out, "SIGNED     tx 0x") {
		t.Errorf("sign output:\n%s", out)
	}
	var sg coldsign.Signed
	sb, _ := os.ReadFile(signedPath)
	json.Unmarshal(sb, &sg)
	rf := coldsign.RequestFile{}
	rb, _ := os.ReadFile(req)
	json.Unmarshal(rb, &rf)
	if _, err := coldsign.VerifySignedMatches(rf.Request, rf.RequestHash, sg); err != nil {
		t.Fatalf("the signed file does not match its request: %v", err)
	}
	if sg.Signer != key.Address {
		t.Fatalf("signed by %s, the cold key is %s", sg.Signer, key.Address)
	}

	// Refusals through the same command line: other destination, amount above the cap, same nonce with other content.
	evil := mk("evil", func(r *coldsign.Request) { r.To = "0x000000000000000000000000000000000000dEaD"; r.Nonce = 4 })
	if msg := runErr("sign", "-config", cfgPath, "-request", evil, "-approval", approve("alice", evil), "-approval", approve("bob", evil)); !strings.Contains(msg, "is not one of the pinned hot addresses") {
		t.Errorf("destination: %s", msg)
	}
	big := mk("big", func(r *coldsign.Request) { r.Amount = "9000000000000000000"; r.Nonce = 5 })
	if msg := runErr("sign", "-config", cfgPath, "-request", big, "-approval", approve("alice", big), "-approval", approve("bob", big)); !strings.Contains(msg, "above the per-ceremony cap") {
		t.Errorf("cap: %s", msg)
	}
	dup := mk("dup", func(r *coldsign.Request) { r.Amount = "2000000000000000000" }) // nonce 3 again, other amount
	if msg := runErr("sign", "-config", cfgPath, "-request", dup, "-approval", approve("alice", dup), "-approval", approve("bob", dup)); !strings.Contains(msg, "was already signed for different content") {
		t.Errorf("same nonce: %s", msg)
	}
	// A damaged request file is not even approved.
	dmg := mk("dmg", nil)
	db, _ := os.ReadFile(dmg)
	os.WriteFile(dmg, bytes.Replace(db, []byte("1000000000000000000"), []byte("2000000000000000000"), 1), 0o600)
	if msg := runErr("approve", "-operator", "alice", "-key", filepath.Join(dir, "alice.key"), "-request", dmg); !strings.Contains(msg, "damaged") {
		t.Errorf("damaged file approved: %s", msg)
	}
	_ = rand.Reader
	_ = hex.EncodeToString
}
