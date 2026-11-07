package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ws4charlie/quorum-vault/internal/coldsign"
	"github.com/ws4charlie/quorum-vault/internal/hsm"
	"github.com/ws4charlie/quorum-vault/internal/hsm/hsmtest"
)

// The whole Bitcoin ceremony through the command line, only files crossing, with a real secp256k1 key in the qv-cold SoftHSM token: keygen for the
// network, operators, a request, inspect, approvals, sign; the online check of the signed file; then the refusals and the fee attack.
func TestBitcoinCeremonyThroughTheCommandLine(t *testing.T) {
	hsmtest.Token(t, "qv-cold")
	t.Setenv("QV_HSM_PIN", hsmtest.PIN())
	dir := t.TempDir()
	runOK := func(args ...string) string {
		t.Helper()
		var out, errb bytes.Buffer
		if err := run(args, &out, &errb); err != nil {
			t.Fatalf("qv-cold %v: %v\n%s%s", args, err, out.String(), errb.String())
		}
		return out.String() + errb.String()
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

	kj := filepath.Join(dir, "key.json")
	msg := runOK("keygen", "-lib", hsm.DefaultLibPath(), "-pin-env", "QV_HSM_PIN", "-network", "regtest", "-out", kj)
	if !strings.Contains(msg, "bitcoin cold address (regtest) bcrt1q") {
		t.Fatalf("keygen did not print the address for the network:\n%s", msg)
	}
	var key map[string]string
	kb, _ := os.ReadFile(kj)
	json.Unmarshal(kb, &key)
	cold := key["btc_address"]

	ops := map[string]string{}
	for _, n := range []string{"alice", "bob", "carol"} {
		ops[n] = strings.TrimSpace(runOK("operator-key", "-key", filepath.Join(dir, n+".key")))
	}
	hot, err := coldsign.BTCAddressOf("regtest", hex.EncodeToString(append([]byte{2}, bytes.Repeat([]byte{7}, 32)...)))
	if err != nil {
		// not a valid point: take the cold key's own address of another network's worth of bytes instead
		t.Skip("could not make a hot address")
	}
	cfg := coldsign.BTCConfig{Family: "btc", Network: "regtest", Chain: "btc-t", Pool: "omnibus", Operators: ops, Threshold: 2, HotShards: []string{hot},
		MaxAmount: 50_000_000, MaxFeeSats: 20_000, MaxFeeRate: 100, MaxInputs: 5, PublicKey: key["btc_public_key"],
		HSM: coldsign.HSMConfig{Token: "qv-cold", PinEnv: "QV_HSM_PIN", KeyID: key["key_id"]}, RecordDir: filepath.Join(dir, "record")}
	cfgPath := filepath.Join(dir, "cfg.json")
	cb, _ := json.Marshal(cfg)
	os.WriteFile(cfgPath, cb, 0o600)

	n := 0
	txid := func() string {
		n++
		h := sha256.Sum256([]byte(fmt.Sprint("outpoint", n)))
		return hex.EncodeToString(h[:])
	}
	mk := func(name string, r coldsign.BTCRequest) string {
		p := filepath.Join(dir, name+".json")
		jb, _ := json.Marshal(r.File())
		os.WriteFile(p, jb, 0o600)
		return p
	}
	base := coldsign.BTCRequest{Version: coldsign.BTCRequestVersion, ID: "rf-1", Revision: 1, Network: "regtest", Chain: "btc-t", Pool: "omnibus", From: cold,
		Inputs:  []coldsign.BTCInput{{TxID: txid(), Value: 5_000_000, Address: cold}, {TxID: txid(), Value: 4_000_000, Address: cold}},
		Outputs: []coldsign.BTCOutput{{Address: hot, Value: 6_000_000}, {Address: cold, Value: 2_998_000}}}
	req := mk("req", base)
	insp := runOK("inspect", "-config", cfgPath, "-request", req)
	for _, want := range []string{"output 0  " + hot + "  6000000 sats (to the hot shard)", "change, back to the cold address", "fee       2000 sats", "enforced in software", "this signer would accept"} {
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
	if m := runErr("sign", "-config", cfgPath, "-request", req, "-approval", approve("alice", req), "-out", signedPath); !strings.Contains(m, "1 valid approval(s)") {
		t.Errorf("one approval: %s", m)
	}
	out := runOK("sign", "-config", cfgPath, "-request", req, "-approval", approve("alice", req), "-approval", approve("carol", req), "-out", signedPath)
	if !strings.Contains(out, "APPROVALS  2 of 2 required: [alice carol]") || !strings.Contains(out, "SIGNED     tx ") {
		t.Errorf("sign output:\n%s", out)
	}
	var sg coldsign.BTCSigned
	sb, _ := os.ReadFile(signedPath)
	json.Unmarshal(sb, &sg)
	if _, err := coldsign.VerifyBTCSignedMatches(base, base.HashHex(), sg); err != nil {
		t.Fatalf("the signed file does not match its request: %v", err)
	}
	if sg.Signer != cold {
		t.Fatalf("signed by %s, the cold key is %s", sg.Signer, cold)
	}

	// Refusals through the same command line.
	evil := base
	evil.ID, evil.Inputs = "rf-evil", []coldsign.BTCInput{{TxID: txid(), Value: 5_000_000, Address: cold}}
	evil.Outputs = []coldsign.BTCOutput{{Address: cold[:len(cold)-1] + "q", Value: 4_990_000}}
	evilPath := mk("evil", evil)
	if m := runErr("sign", "-config", cfgPath, "-request", evilPath, "-approval", approve("alice", evilPath), "-approval", approve("bob", evilPath)); !strings.Contains(m, "refused") {
		t.Errorf("an unpinned destination: %s", m)
	}
	// The fee attack: the first outpoint again, with another value.
	lie := base
	lie.ID = "rf-lie"
	lie.Inputs = []coldsign.BTCInput{{TxID: base.Inputs[0].TxID, Value: 1_000_000, Address: cold}, {TxID: txid(), Value: 9_000_000, Address: cold}}
	lie.Outputs = []coldsign.BTCOutput{{Address: hot, Value: 9_990_000}}
	liePath := mk("lie", lie)
	if m := runErr("sign", "-config", cfgPath, "-request", liePath, "-approval", approve("alice", liePath), "-approval", approve("bob", liePath)); !strings.Contains(m, "a second value for a signed outpoint is refused") {
		t.Errorf("the fee attack: %s", m)
	}
	// A replacement with a higher fee is signed in a second ceremony; an equal one is not.
	repl := base
	repl.Revision = 2
	repl.Outputs = []coldsign.BTCOutput{{Address: hot, Value: 6_000_000}, {Address: cold, Value: 2_996_000}}
	replPath := mk("repl", repl)
	runOK("sign", "-config", cfgPath, "-request", replPath, "-approval", approve("alice", replPath), "-approval", approve("bob", replPath), "-out", filepath.Join(dir, "signed2.json"))
	again := repl
	again.Revision = 3
	again.Outputs = []coldsign.BTCOutput{{Address: hot, Value: 6_000_000}, {Address: cold, Value: 2_996_000}}
	againPath := mk("again", again)
	if m := runErr("sign", "-config", cfgPath, "-request", againPath, "-approval", approve("alice", againPath), "-approval", approve("bob", againPath)); !strings.Contains(m, "must pay more") {
		t.Errorf("an equal fee: %s", m)
	}
	// A damaged request file is not even approved.
	dmg := mk("dmg", base)
	db, _ := os.ReadFile(dmg)
	os.WriteFile(dmg, bytes.Replace(db, []byte("6000000"), []byte("6000001"), 1), 0o600)
	if m := runErr("approve", "-operator", "alice", "-key", filepath.Join(dir, "alice.key"), "-request", dmg); !strings.Contains(m, "damaged") {
		t.Errorf("damaged file approved: %s", m)
	}
}
