package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ws4charlie/quorum-vault/internal/chain/evm"
	"github.com/ws4charlie/quorum-vault/internal/gatecred"
	"github.com/ws4charlie/quorum-vault/internal/gatecred/gatecredtest"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// The Gate credential rule through the whole zone: real guard databases, the gateway's job loop and a cosigner's decider, each with its own guard
// and its own copy of the operator-signed setting. The credentials are minted with the TEST ONLY keys of the shared vectors (gatecredtest), in test
// code only.

var gateToken = common.HexToAddress(gatecredtest.VectorsToken)

// gateZone is the software harness made into a zone with a Gate setting: two operators, the vectors' token as USDT, high withdrawal caps (the fast
// lane is what bounds these payments), the clock at the vectors' now, and a cosigner decider with its own guard database.
type gateZone struct {
	*harness
	ops      map[string]ed25519.PrivateKey
	cos      *Decider
	cosGuard *Guard
	cosDB    *pgxpool.Pool
	version  int64
	wallet   string
	nonce    uint64
	auth     byte
	limits   map[string]GateLimitFile
	keys     []gatecredtest.Key
}

func newGateZone(t *testing.T, chainID uint64) *gateZone {
	t.Helper()
	h := newHarnessWith(t, chainID, true)
	z := &gateZone{harness: h, ops: map[string]ed25519.PrivateKey{}, wallet: gatecredtest.VectorsWallet,
		keys: []gatecredtest.Key{gatecredtest.TestKey(1), gatecredtest.TestKey(2)}}
	oc := &OperatorConfig{Keys: map[string]ed25519.PublicKey{}, Min: 2, MaxAge: 10 * time.Minute}
	for _, n := range []string{"op1", "op2"} {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		z.ops[n], oc.Keys[n] = priv, pub
	}
	h.cfg.Operators = oc
	cc := h.cfg.Chains[testChain]
	cc.EVM.Assets["USDT"] = evm.Token{Address: gateToken, Decimals: 6}
	cc.EVM.X402 = map[string]evm.X402Token{"USDT": {Name: "USDC", Version: "2", MaxWindowSeconds: 3600, PerPaymentLimit: new(big.Int).Lsh(big.NewInt(1), 100)}}
	huge := new(big.Int).Lsh(big.NewInt(1), 120)
	for _, a := range []string{"ETH", "USDT"} {
		p := cc.Assets[a]
		p.PerTxCap, p.DailyCap = huge, huge
		cc.Assets[a] = p
	}
	h.now = time.Unix(gatecredtest.VectorsNow, 0)
	h.gw = h.newGateway("w-gate")
	z.cosDB = newGuardDB(t)
	var err error
	if z.cosGuard, err = OpenGuard(context.Background(), z.cosDB); err != nil {
		t.Fatal(err)
	}
	codecs, err := NewCodecs(h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	z.cos = NewDecider(h.cfg, codecs, z.cosGuard, ModeCosigner, h.clock)
	z.limits = map[string]GateLimitFile{"ETH": {PerPayment: huge.String(), PerHour: huge.String(), PerDay: huge.String()},
		"USDT": {PerPayment: huge.String(), PerHour: huge.String(), PerDay: huge.String()}}
	return z
}

func (z *gateZone) settingFile() GateSettingFile {
	f := GateSettingFile{Audience: gatecredtest.VectorsAudience, SkewSeconds: 30, MaxTTLSeconds: 600,
		Wallets: []GateWalletFile{{WalletID: z.wallet, Partition: testPartition, Limits: z.limits}}}
	for _, k := range z.keys {
		f.Keys = append(f.Keys, GateKeyFile{KID: k.KID, PublicKey: b64(k.Pub)})
	}
	return f
}

func (z *gateZone) signed(f GateSettingFile, version int64) GateChange {
	c := GateChange{Version: version, SignedAt: z.clock().Unix(), Setting: f}
	var parts []GateChange
	for _, n := range []string{"op1", "op2"} {
		parts = append(parts, SignGateChange(z.ops[n], n, c))
	}
	m, err := MergeGateChanges(parts...)
	if err != nil {
		z.t.Fatal(err)
	}
	return m
}

// apply signs the next version of f and applies it to the given guards (default: the gateway's and the cosigner's).
func (z *gateZone) apply(f GateSettingFile, guards ...*Guard) {
	z.t.Helper()
	if len(guards) == 0 {
		guards = []*Guard{z.guard, z.cosGuard}
	}
	z.version++
	c := z.signed(f, z.version)
	for _, g := range guards {
		if err := g.ApplyGateChange(context.Background(), z.cfg, c, z.clock(), "test"); err != nil {
			z.t.Fatal(err)
		}
	}
}

func (z *gateZone) govern() { z.apply(z.settingFile()) }

func b64(b []byte) string { return strings.TrimRight(base64URL(b), "=") }

func base64URL(b []byte) string {
	const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	var out []byte
	for i := 0; i < len(b); i += 3 {
		var n uint32
		k := min(3, len(b)-i)
		for j := 0; j < 3; j++ {
			n <<= 8
			if j < k {
				n |= uint32(b[i+j])
			}
		}
		for j := 0; j < k+1; j++ {
			out = append(out, a[(n>>(18-6*j))&63])
		}
	}
	return string(out)
}

// cred mints a credential for a payment of the zone's wallet, valid now; mod changes fields before signing.
func (z *gateZone) cred(asset, payee string, amount *big.Int, mod func(*gatecred.Credential)) string {
	now := z.clock().Unix()
	c := gatecred.Credential{V: 1, KID: z.keys[0].KID, CredentialID: uuid.NewString(), ObligationID: "obl-" + uuid.NewString()[:8],
		Audience: gatecredtest.VectorsAudience, WalletID: z.wallet, Chain: fmt.Sprintf("eip155:%d", z.chainID), Asset: asset,
		Payee: strings.ToLower(payee), Amount: amount.String(), IssuedAt: now - 10, ExpiresAt: now + 590, PolicyVersion: "policy-v1",
		DecisionReason: "test: within budget"}
	if mod != nil {
		mod(&c)
	}
	key := z.keys[0]
	for _, k := range append(z.keys, gatecredtest.TestKey(3)) {
		if k.KID == c.KID {
			key = k
		}
	}
	return string(gatecredtest.Mint(key, c))
}

func (z *gateZone) nextNonce() uint64 { z.nonce++; return z.nonce - 1 }

// native is a withdrawal of wei to payee from the governed partition, carrying credential (may be "").
func (z *gateZone) native(id string, payee common.Address, wei *big.Int, credential string, approvers ...string) signjob.Job {
	in := signjob.Intent{Kind: "withdrawal", RequestedBy: "agentgate", ID: "w-" + id, Asset: "ETH", To: payee.Hex(), Amount: wei.String(), Credential: credential}
	return z.job(id, in, txSpec{nonce: z.nextNonce(), to: payee, value: wei, gas: 21000}, approvers...)
}

// token is a withdrawal of USDT (the vectors' token) to payee.
func (z *gateZone) token(id string, payee common.Address, units *big.Int, credential string, approvers ...string) signjob.Job {
	data, err := erc20.Pack("transfer", payee, units)
	if err != nil {
		z.t.Fatal(err)
	}
	in := signjob.Intent{Kind: "withdrawal", RequestedBy: "agentgate", ID: "w-" + id, Asset: "USDT", To: payee.Hex(), Amount: units.String(), Credential: credential}
	return z.job(id, in, txSpec{nonce: z.nextNonce(), to: gateToken, data: data}, approvers...)
}

// authorization is an EIP-3009 authorization of USDT to payee with the given window.
func (z *gateZone) authorization(id string, payee common.Address, units *big.Int, after, before int64, credential string) signjob.Job {
	z.auth++
	var nonce [32]byte
	nonce[30], nonce[31] = 0x6a, z.auth
	payload, digest, err := z.cfg.Chains[testChain].EVM.NewPayload3009("USDT", z.hot, payee, units, uint64(after), uint64(before), nonce)
	if err != nil {
		z.t.Fatal(err)
	}
	in := signjob.Intent{Kind: evm.KindEIP3009, ID: "x-" + id, PartitionID: testPartition, Chain: testChain, Asset: "USDT", To: payee.Hex(), Amount: units.String(),
		Credential: credential}
	return signjob.Job{ID: id, PartitionID: testPartition, KeyRef: "m/0", Chain: testChain, Intent: mustJSON(in), Digest: digest[:], Payload: payload}
}

// cosign is the cosigner's decision on job: "" when it allows, else the refusal reason.
func (z *gateZone) cosign(job signjob.Job) string {
	z.t.Helper()
	v, err := z.cos.DecideKey(context.Background(), job, SignerKey{ECDSA: z.signer.PublicKey()})
	if err != nil {
		if why, ok := IsRejection(err); ok {
			return why
		}
		z.t.Fatalf("cosigner: %v", err)
	}
	if !v.NeedSign {
		z.t.Fatalf("cosigner: no signing allowed and no refusal")
	}
	return ""
}

// gate runs job through the gateway: "" when signed (or the stored signature returned), else the refusal reason.
func (z *gateZone) gate(job signjob.Job) string {
	z.t.Helper()
	d := z.run(job)
	switch d.Outcome {
	case OutcomeSigned, OutcomeReplayed:
		z.checkSig(job.Digest, d.Sig)
		return ""
	case OutcomeRejected:
		return d.Reason
	}
	z.t.Fatalf("job %s: outcome %s (%s)", job.ID, d.Outcome, d.Reason)
	return ""
}

// want checks a decision against a code ("" = signed) and, when given, the field.
func want(t *testing.T, what, reason, code, field string) {
	t.Helper()
	if code == "" {
		if reason != "" {
			t.Fatalf("%s: refused %q, want signed", what, reason)
		}
		return
	}
	if !strings.HasPrefix(reason, code+": ") {
		t.Fatalf("%s: reason %q, want code %s", what, reason, code)
	}
	if field != "" {
		if _, f, _ := GateRefusal(reason); f != field {
			t.Fatalf("%s: reason %q, want field %s", what, reason, field)
		}
	}
}

// ---- the shared vectors, through the zone ----

func loadVectors(t *testing.T) gatecredtest.Vectors {
	t.Helper()
	b, err := os.ReadFile("../../testdata/gate-credential/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v gatecredtest.Vectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// vectorJob builds the job whose payload the zone decodes into exactly the vector's payment: a native or token withdrawal, or an EIP-3009
// authorization when the payment has a window.
func (z *gateZone) vectorJob(id string, p gatecredtest.VPayment, credential string) signjob.Job {
	z.t.Helper()
	amt, ok := new(big.Int).SetString(p.Amount, 10)
	if !ok {
		z.t.Fatalf("amount %q", p.Amount)
	}
	payee := common.HexToAddress(p.Payee)
	switch {
	case p.ValidAfter != nil:
		if p.Asset != gatecredtest.VectorsToken {
			z.t.Fatalf("an authorization of %s", p.Asset)
		}
		return z.authorization(id, payee, amt, *p.ValidAfter, *p.ValidBefore, credential)
	case p.Asset == gatecred.NativeAsset:
		return z.native(id, payee, amt, credential)
	case p.Asset == gatecredtest.VectorsToken:
		return z.token(id, payee, amt, credential)
	}
	z.t.Fatalf("payment asset %q", p.Asset)
	return signjob.Job{}
}

// Every case of testdata/gate-credential/vectors.json runs through the zone rule, in gateway mode (the job loop, its guard) and in cosigner mode (a
// decider with its own guard), including the reuse cases.
func TestGateVectorsThroughTheZone(t *testing.T) {
	v := loadVectors(t)
	zones := map[uint64]*gateZone{}
	zone := func(chain string) *gateZone {
		var id uint64
		if _, err := fmt.Sscanf(chain, "eip155:%d", &id); err != nil {
			t.Fatalf("chain %q", chain)
		}
		if zones[id] == nil {
			zones[id] = newGateZone(t, id)
			zones[id].govern()
		}
		return zones[id]
	}
	n := 0
	for _, c := range v.Cases {
		z := zone(c.Payment.Chain)
		if c.Payment.WalletID != z.wallet {
			z.wallet = c.Payment.WalletID
			z.govern()
		}
		now := v.Now
		if c.Now != nil {
			now = *c.Now
		}
		z.mu.Lock()
		z.now = time.Unix(now, 0)
		z.mu.Unlock()
		cred := ""
		if c.Credential != nil {
			cred = *c.Credential
		}
		if s := c.Substitute; s != nil {
			b, _ := hex.DecodeString(s.With)
			cred = strings.Replace(cred, s.Find, string(b), 1)
		}
		wantCode, wantField := c.Expect.Code, c.Expect.Field
		if c.Substitute != nil {
			// Invalid UTF-8 cannot reach the zone: the intent is JSON, whose encoder turns the bad bytes into U+FFFD, so the zone sees a
			// well-formed credential whose signed bytes changed. It must still be refused.
			wantCode, wantField = string(gatecred.SignatureInvalid), ""
		}
		n++
		job := z.vectorJob(fmt.Sprintf("v%d", n), c.Payment, cred)
		want(t, c.Name+" (gateway)", z.gate(job), wantCode, wantField)
		want(t, c.Name+" (cosigner)", z.cosign(job), wantCode, wantField)
		for k, r := range c.Then {
			p := c.Payment
			if r.Payment != nil {
				p = *r.Payment
			}
			n++
			again := z.vectorJob(fmt.Sprintf("v%d", n), p, cred) // another payload: another nonce
			want(t, fmt.Sprintf("%s reuse %d (gateway)", c.Name, k), z.gate(again), r.Code, r.Field)
			want(t, fmt.Sprintf("%s reuse %d (cosigner)", c.Name, k), z.cosign(again), r.Code, r.Field)
		}
	}
	if n < len(v.Cases) {
		t.Fatalf("ran %d of %d cases", n, len(v.Cases))
	}
}

// ---- the brief's four negatives, end to end through the zone ----

func TestGateFourNegatives(t *testing.T) {
	z := newGateZone(t, 84532)
	z.govern()
	payee := common.HexToAddress(gatecredtest.VectorsPayee)
	wei := big.NewInt(7_000_000)
	// No credential, even with every approval.
	j := z.native("n1", payee, wei, "", "alice", "bob", "carol")
	want(t, "no credential (gateway)", z.gate(j), string(gatecred.CredentialMissing), "")
	want(t, "no credential (cosigner)", z.cosign(j), string(gatecred.CredentialMissing), "")
	// Amount tampered after minting: the credential's own bytes changed.
	good := z.cred(gatecred.NativeAsset, payee.Hex(), wei, nil)
	tampered := strings.Replace(good, `"amount":"7000000"`, `"amount":"7000001"`, 1)
	j = z.native("n2", payee, big.NewInt(7_000_001), tampered)
	want(t, "tampered (gateway)", z.gate(j), string(gatecred.SignatureInvalid), "")
	want(t, "tampered (cosigner)", z.cosign(j), string(gatecred.SignatureInvalid), "")
	// And the payload tampered instead: the credential is intact, the transaction pays more.
	j = z.native("n2b", payee, big.NewInt(7_000_001), good)
	want(t, "payload tampered (gateway)", z.gate(j), string(gatecred.PaymentMismatch), "amount")
	// Expired.
	exp := z.cred(gatecred.NativeAsset, payee.Hex(), wei, func(c *gatecred.Credential) { c.IssuedAt, c.ExpiresAt = c.IssuedAt-1000, c.IssuedAt-500 })
	j = z.native("n3", payee, wei, exp)
	want(t, "expired (gateway)", z.gate(j), string(gatecred.Expired), "expires_at")
	want(t, "expired (cosigner)", z.cosign(j), string(gatecred.Expired), "expires_at")
	// Replayed credential_id: the first use signs, a second payload under it is refused at each checker.
	j = z.native("n4", payee, wei, good)
	want(t, "first use (gateway)", z.gate(j), "", "")
	want(t, "first use (cosigner)", z.cosign(j), "", "")
	j = z.native("n5", payee, wei, good)
	want(t, "replay (gateway)", z.gate(j), string(gatecred.Replayed), "")
	want(t, "replay (cosigner)", z.cosign(j), string(gatecred.Replayed), "")
	if z.signer.calls.Load() != 1 {
		t.Fatalf("the signer was called %d times, want 1", z.signer.calls.Load())
	}
}

// ---- the proof ----

// For a Gate-governed wallet, every kind the decider accepts on an EVM chain, with every human approval and no credential: the internal kinds are
// signed as today (but a rebalance to a shard that is not Gate-governed, GC2b), every payment kind is refused. Same in cosigner mode. Then the same internal kinds carrying a credential are refused (a credential
// rides only on a payment), and a credential-less payment of the other partition of the same address is refused too (the wallet is the shard).
func TestNoPathSignsAGateGovernedPaymentWithoutACredential(t *testing.T) {
	z := newGateZone(t, 84532)
	z.govern()
	payee := common.HexToAddress(gatecredtest.VectorsPayee)
	all := []string{"alice", "bob", "carol", "auto"}
	sweep, from := z.sweepTx("cust-gate", 0)
	type tc struct {
		name    string
		job     func(id string, cred string) signjob.Job
		payment bool
		refused string // an internal kind the gate rule still refuses (a rebalance to a wallet that is not Gate-governed, GC2b)
	}
	cases := []tc{
		{"withdrawal native", func(id, cred string) signjob.Job { return z.native(id, payee, big.NewInt(1000), cred, all...) }, true, ""},
		{"withdrawal token", func(id, cred string) signjob.Job { return z.token(id, payee, big.NewInt(1000), cred, all...) }, true, ""},
		{"withdrawal native, other partition of the same address", func(id, cred string) signjob.Job {
			in := signjob.Intent{Kind: "withdrawal", RequestedBy: "req", ID: "w-" + id, PartitionID: testColdPartition, Asset: "ETH", To: payee.Hex(), Amount: "1000", Credential: cred}
			return z.job(id, in, z.ethTx(payee, 1000, z.nextNonce()), all...)
		}, true, ""},
		{"eip3009", func(id, cred string) signjob.Job {
			now := z.clock().Unix()
			j := z.authorization(id, payee, big.NewInt(1000), now-5, now+300, cred)
			j.Approvals = z.approvals(x402Intent(t, j), all...)
			return j
		}, true, ""},
		{"sweep", func(id, cred string) signjob.Job {
			sweep.nonce = z.nextNonce()
			return z.job(id, signjob.Intent{Kind: "sweep", ID: "s-" + id, Asset: "ETH", From: from.Hex(), To: addrDest.Hex(), Amount: "5", Credential: cred}, sweep, all...)
		}, false, ""},
		{"cancel", func(id, cred string) signjob.Job {
			return z.job(id, signjob.Intent{Kind: "cancel", ID: "c-" + id, Asset: "ETH", To: z.hot.Hex(), Amount: "0", Credential: cred}, z.cancelTx(z.nextNonce()), all...)
		}, false, ""},
		{"to-cold", func(id, cred string) signjob.Job {
			return z.job(id, signjob.Intent{Kind: "to-cold", ID: "tc-" + id, PartitionID: testColdPartition, Asset: "ETH", To: addrCold.Hex(), Amount: "10", Credential: cred}, z.ethTx(addrCold, 10, z.nextNonce()), all...)
		}, false, ""},
		{"rebalance", func(id, cred string) signjob.Job {
			return z.job(id, signjob.Intent{Kind: "rebalance", ID: "rb-" + id, PartitionID: testColdPartition, Asset: "ETH", To: addrShard2.Hex(), Amount: "10", Credential: cred},
				z.ethTx(addrShard2, 10, z.nextNonce()), all...)
		}, false, ReasonGateRebalance},
	}
	for i, c := range cases {
		j := c.job(fmt.Sprintf("p%d", i), "")
		gw, co := z.gate(j), z.cosign(j)
		if c.payment {
			want(t, c.name+" (gateway)", gw, string(gatecred.CredentialMissing), "")
			want(t, c.name+" (cosigner)", co, string(gatecred.CredentialMissing), "")
		} else {
			want(t, c.name+" (gateway)", gw, c.refused, "")
			want(t, c.name+" (cosigner)", co, c.refused, "")
		}
	}
	// A credential on an internal kind is refused: it is a permission for a payment only.
	someCred := z.cred(gatecred.NativeAsset, payee.Hex(), big.NewInt(10), nil)
	for i, c := range cases {
		if c.payment {
			continue
		}
		j := c.job(fmt.Sprintf("q%d", i), someCred)
		want(t, c.name+" with a credential (gateway)", z.gate(j), ReasonIntent, "")
		want(t, c.name+" with a credential (cosigner)", z.cosign(j), ReasonIntent, "")
	}
	// Only the internal kinds were signed.
	var n int
	z.guardDB.QueryRow(context.Background(), `SELECT count(*) FROM signed_intents WHERE kind IN ('withdrawal','eip3009')`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d payment intents were signed without a credential", n)
	}
	if got := z.signer.calls.Load(); got != 3 {
		t.Fatalf("the signer was called %d times, want 3 (sweep, cancel, to-cold)", got)
	}
}

// Without a gate setting nothing changes for a withdrawal (approvals as today), and a credential or an authorization for a wallet that is not
// Gate-governed is refused (check 0).
func TestGateNotGovernedWalletUnchanged(t *testing.T) {
	z := newGateZone(t, 84532)
	payee := common.HexToAddress(gatecredtest.VectorsPayee)
	want(t, "plain withdrawal", z.gate(z.native("a1", payee, big.NewInt(100), "", "alice")), "", "")
	want(t, "no approval", z.gate(z.native("a2", payee, big.NewInt(100), "")), ReasonApprovals, "")
	c := z.cred(gatecred.NativeAsset, payee.Hex(), big.NewInt(100), nil)
	want(t, "credential, not governed", z.gate(z.native("a3", payee, big.NewInt(100), c, "alice")), string(gatecred.WalletNotGateGoverned), "")
	want(t, "credential, not governed (cosigner)", z.cosign(z.native("a4", payee, big.NewInt(100), c, "alice")), string(gatecred.WalletNotGateGoverned), "")
	now := z.clock().Unix()
	want(t, "authorization, not governed", z.gate(z.authorization("a5", payee, big.NewInt(100), now-5, now+60, c)), string(gatecred.WalletNotGateGoverned), "")
	// Governing another wallet (shard 2) leaves this one as it was.
	z.apply(GateSettingFile{Audience: gatecredtest.VectorsAudience, Keys: []GateKeyFile{{KID: z.keys[0].KID, PublicKey: b64(z.keys[0].Pub)}},
		Wallets: []GateWalletFile{{WalletID: "11111111-2222-4333-8444-555555555555", Partition: testShard2}}})
	want(t, "plain withdrawal, other wallet governed", z.gate(z.native("a6", payee, big.NewInt(100), "", "alice")), "", "")
}

// ---- the fast lane ----

func TestGateFastLane(t *testing.T) {
	z := newGateZone(t, 84532)
	z.limits = map[string]GateLimitFile{"ETH": {PerPayment: "100", PerHour: "250", PerDay: "400"}}
	z.govern()
	payee := common.HexToAddress(gatecredtest.VectorsPayee)
	pay := func(id string, amount int64) (string, string) {
		a := big.NewInt(amount)
		j := z.native(id, payee, a, z.cred(gatecred.NativeAsset, payee.Hex(), a, nil))
		return z.gate(j), z.cosign(j)
	}
	both := func(what string, amount int64, code string) {
		t.Helper()
		gw, co := pay(what, amount)
		want(t, what+" (gateway)", gw, code, "")
		want(t, what+" (cosigner)", co, code, "")
	}
	cap := string(gatecred.FastLaneCap)
	both("per payment over", 101, cap)
	both("per payment at", 100, "")
	both("hour: 200 of 250", 100, "")
	both("hour over: 200+51", 51, cap)
	both("hour at: 200+50", 50, "")
	// A token has no limit set: all three are 0.
	j := z.token("tok", payee, big.NewInt(1), z.cred(gatecredtest.VectorsToken, payee.Hex(), big.NewInt(1), nil))
	want(t, "asset without limits", z.gate(j), cap, "")
	// The counts survive a restart: a new gateway and a new cosigner decider on the same guard databases.
	z.advance(61 * time.Minute)
	z.gw = z.newGateway("w-restart")
	codecs, _ := NewCodecs(z.cfg)
	z.cos = NewDecider(z.cfg, codecs, z.cosGuard, ModeCosigner, z.clock)
	both("day: 250 of 400, hour empty, 151 over", 151-1+1, cap) // 250+151 > 400
	both("day at: 250+100", 100, "")
	both("day at: 350+50", 50, "")
	both("day over: 400+1", 1, cap)
	z.advance(24 * time.Hour)
	both("a day later", 100, "")
}

// ---- disagreement ----

// The gateway has a newer setting than a cosigner: what the gateway accepts, the cosigner (on the older version) refuses, so no MPC signature is
// made. Here the newer version adds the Gate key the credential is signed with.
func TestGateCosignerOnAnOlderSettingRefuses(t *testing.T) {
	z := newGateZone(t, 84532)
	z.keys = []gatecredtest.Key{gatecredtest.TestKey(2)}
	z.govern() // v1 everywhere: key 2 only
	z.keys = []gatecredtest.Key{gatecredtest.TestKey(1), gatecredtest.TestKey(2)}
	z.apply(z.settingFile(), z.guard) // v2 on the gateway only: key 1 too
	payee := common.HexToAddress(gatecredtest.VectorsPayee)
	a := big.NewInt(500)
	j := z.native("d1", payee, a, z.cred(gatecred.NativeAsset, payee.Hex(), a, nil)) // signed with key 1
	want(t, "cosigner on v1", z.cosign(j), string(gatecred.KIDUnknown), "kid")
	// The gateway's own decision (before it would ask party B) accepts.
	codecs, _ := NewCodecs(z.cfg)
	gwd := NewDecider(z.cfg, codecs, z.guard, ModeGateway, z.clock)
	if _, err := gwd.DecideKey(context.Background(), j, SignerKey{ECDSA: z.signer.PublicKey()}); err != nil {
		t.Fatalf("gateway on v2: %v", err)
	}
	// And the other way: a wallet governed only at the cosigner is refused there without a credential, whatever the gateway thinks.
	z2 := newGateZone(t, 84532)
	z2.apply(z2.settingFile(), z2.cosGuard)
	j2 := z2.native("d2", payee, a, "", "alice")
	want(t, "governed at the cosigner only", z2.cosign(j2), string(gatecred.CredentialMissing), "")
}

// ---- retries ----

// A retry of the same digest is not a second use: the gateway returns its stored signature and the cosigner allows the same digest again, with no new
// record and no second count.
func TestGateRetryOfTheSameDigest(t *testing.T) {
	z := newGateZone(t, 84532)
	z.limits = map[string]GateLimitFile{"ETH": {PerPayment: "100", PerHour: "100", PerDay: "100"}}
	z.govern()
	payee := common.HexToAddress(gatecredtest.VectorsPayee)
	a := big.NewInt(100)
	j := z.native("r1", payee, a, z.cred(gatecred.NativeAsset, payee.Hex(), a, nil))
	want(t, "first", z.gate(j), "", "")
	want(t, "first (cosigner)", z.cosign(j), "", "")
	want(t, "retry (cosigner)", z.cosign(j), "", "") // the limit is used up: a second count would refuse
	again := j
	again.ID = "r1-again"
	d := z.run(again)
	if d.Outcome != OutcomeReplayed {
		t.Fatalf("retry at the gateway: %s %s", d.Outcome, d.Reason)
	}
	for _, db := range []*pgxpool.Pool{z.guardDB, z.cosDB} {
		var n int
		db.QueryRow(context.Background(), `SELECT count(*) FROM gate_credentials_used`).Scan(&n)
		if n != 1 {
			t.Fatalf("%d records, want 1", n)
		}
	}
	if z.signer.calls.Load() != 1 {
		t.Fatalf("signed %d times", z.signer.calls.Load())
	}
}

// ---- the setting ----

func TestGateSettingIsOperatorSigned(t *testing.T) {
	z := newGateZone(t, 84532)
	ctx := context.Background()
	f := z.settingFile()
	// One operator is not enough.
	c := SignGateChange(z.ops["op1"], "op1", GateChange{Version: 1, SignedAt: z.clock().Unix(), Setting: f})
	if err := z.guard.ApplyGateChange(ctx, z.cfg, c, z.clock(), "test"); err == nil {
		t.Fatal("a version with one operator's signature was applied")
	}
	// Stale.
	if err := z.guard.ApplyGateChange(ctx, z.cfg, z.signed(f, 1), z.clock().Add(time.Hour), "test"); err == nil {
		t.Fatal("a stale version was applied")
	}
	// A wallet that is not a hot partition of an EVM chain here.
	bad := f
	bad.Wallets = []GateWalletFile{{WalletID: z.wallet, Partition: "nope"}}
	if err := z.guard.ApplyGateChange(ctx, z.cfg, z.signed(bad, 1), z.clock(), "test"); err == nil {
		t.Fatal("a wallet of an unknown partition was applied")
	}
	// A limit for an asset the chain does not have.
	bad = f
	bad.Wallets = []GateWalletFile{{WalletID: z.wallet, Partition: testPartition, Limits: map[string]GateLimitFile{"DOGE": {"1", "1", "1"}}}}
	if err := z.guard.ApplyGateChange(ctx, z.cfg, z.signed(bad, 1), z.clock(), "test"); err == nil {
		t.Fatal("a limit for an unknown asset was applied")
	}
	z.govern()
	// The same version again is not an error; an older or equal one with other content is refused.
	if err := z.guard.ApplyGateChange(ctx, z.cfg, z.signed(f, 1), z.clock(), "test"); err != nil {
		t.Fatalf("the same version again: %v", err)
	}
	f2 := f
	f2.Audience = "qv-other"
	if err := z.guard.ApplyGateChange(ctx, z.cfg, z.signed(f2, 1), z.clock(), "test"); err == nil {
		t.Fatal("another content under the same version was applied")
	}
	// A row written by anyone else (SQL access to the guard database) is ignored: here, a version that governs nothing.
	forged, _ := json.Marshal(GateSettingFile{Audience: "qv-test", Keys: f.Keys})
	if _, err := z.guardDB.Exec(ctx, `INSERT INTO gate_setting_changes (version, setting, signed_at, signatures) VALUES (9, $1, $2, '[]')`, forged, z.clock().Unix()); err != nil {
		t.Fatal(err)
	}
	s, err := z.guard.EffectiveGate(ctx, z.cfg)
	if err != nil || s.Version != 1 || s.Ignored != 1 || len(s.Wallets) != 1 {
		t.Fatalf("effective %+v %v", s, err)
	}
	// The log is append-only.
	if _, err := z.guardDB.Exec(ctx, `DELETE FROM gate_setting_changes`); err == nil {
		t.Fatal("the log could be deleted")
	}
	// The change is in the audit trail.
	var n int
	z.guardDB.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE type=$1`, EventGateSettingChanged).Scan(&n)
	if n != 1 {
		t.Fatalf("%d audit events of the setting", n)
	}
}

// Keys: the bootstrap set of the config is Gate's until a version retires a key; a retired kid or key is never used again; a key outside its time
// window is kid_unknown.
func TestGateKeysBootstrapRetireAndWindows(t *testing.T) {
	z := newGateZone(t, 84532)
	k1, k2 := gatecredtest.TestKey(1), gatecredtest.TestKey(2)
	z.cfg.GateBootstrap = []GateKey{{KID: k1.KID, Public: k1.Pub}}
	z.keys = nil
	z.govern() // the setting names no key: the bootstrap one signs
	payee := common.HexToAddress(gatecredtest.VectorsPayee)
	a := big.NewInt(10)
	z.keys = []gatecredtest.Key{k1}
	want(t, "bootstrap key", z.gate(z.native("k1", payee, a, z.cred(gatecred.NativeAsset, payee.Hex(), a, nil))), "", "")
	// Rotate: add key 2, retire key 1.
	f := z.settingFile()
	f.Keys = []GateKeyFile{{KID: k2.KID, PublicKey: b64(k2.Pub)}}
	f.Retired = []string{k1.KID}
	z.apply(f)
	want(t, "retired key", z.gate(z.native("k2", payee, a, z.cred(gatecred.NativeAsset, payee.Hex(), a, nil))), string(gatecred.KIDUnknown), "kid")
	z.keys = []gatecredtest.Key{k2}
	want(t, "new key", z.gate(z.native("k3", payee, a, z.cred(gatecred.NativeAsset, payee.Hex(), a, nil))), "", "")
	// A retired key is never used again, under its kid or another.
	again := f
	again.Retired = nil
	again.Keys = append(again.Keys, GateKeyFile{KID: "renamed", PublicKey: b64(k1.Pub)})
	z.version++
	if err := z.guard.ApplyGateChange(context.Background(), z.cfg, z.signed(again, z.version), z.clock(), "test"); err == nil {
		t.Fatal("a retired key came back under another kid")
	}
	z.version--
	// Windows: key 2 ends now; a credential signed with it is refused from now on.
	f.Keys = []GateKeyFile{{KID: k2.KID, PublicKey: b64(k2.Pub), NotAfter: z.clock().Unix()}}
	z.apply(f)
	want(t, "key past not_after", z.gate(z.native("k4", payee, a, z.cred(gatecred.NativeAsset, payee.Hex(), a, nil))), string(gatecred.KIDUnknown), "kid")
}

// ---- audit and pruning ----

func TestGateAuditAndPruning(t *testing.T) {
	z := newGateZone(t, 84532)
	z.govern()
	ctx := context.Background()
	payee := common.HexToAddress(gatecredtest.VectorsPayee)
	a := big.NewInt(42)
	ok := z.cred(gatecred.NativeAsset, payee.Hex(), a, func(c *gatecred.Credential) { c.DecisionReason = "naïve 🙂 \"quoted\"" })
	want(t, "accepted", z.gate(z.native("au1", payee, a, ok)), "", "")
	want(t, "malformed", z.gate(z.native("au2", payee, a, `{"not":"a credential"}`)), string(gatecred.CredentialMalformed), "")
	type ev struct {
		Gate map[string]any `json:"gate"`
	}
	read := func(typ, job string) map[string]any {
		var p []byte
		if err := z.guardDB.QueryRow(ctx, `SELECT payload FROM audit_log WHERE type=$1 AND payload->>'job'=$2`, typ, job).Scan(&p); err != nil {
			t.Fatalf("%s %s: %v", typ, job, err)
		}
		var e ev
		json.Unmarshal(p, &e)
		return e.Gate
	}
	g := read(EventSignAllowed, "au1")
	cred, _ := gatecred.Parse([]byte(ok))
	if g["credential_id"] != cred.CredentialID || g["decision_reason"] != cred.DecisionReason || g["obligation_id"] != cred.ObligationID ||
		g["policy_version"] != cred.PolicyVersion || g["wallet_id"] != z.wallet || g["checker"] != "qv-gateway" || g["code"] != "accepted" {
		t.Fatalf("accept audit %v", g)
	}
	if p, _ := g["payment"].(map[string]any); p["amount"] != "42" || p["payee"] != strings.ToLower(payee.Hex()) || p["asset"] != "native" {
		t.Fatalf("payment %v", g["payment"])
	}
	g = read(EventSignRefused, "au2")
	if g["code"] != string(gatecred.CredentialMalformed) || g["credential_size"] == nil || g["credential_sha256"] == nil || g["credential_id"] != nil {
		t.Fatalf("refusal audit %v", g)
	}
	// Pruning keeps the record for a day after signing at least, then removes it.
	if n, err := z.guard.PruneGateCredentials(ctx, z.clock().Add(23*time.Hour)); err != nil || n != 0 {
		t.Fatalf("pruned %d early (%v)", n, err)
	}
	if n, err := z.guard.PruneGateCredentials(ctx, z.clock().Add(25*time.Hour)); err != nil || n != 1 {
		t.Fatalf("pruned %d (%v)", n, err)
	}
}

func TestGateRefusalParses(t *testing.T) {
	for reason, wantCode := range map[string]string{
		"payment_mismatch: field amount: payload moves another amount": "payment_mismatch",
		"replayed: credential x was already used":                      "replayed",
		"approval_invalid: no valid approval":                          "",
	} {
		c, f, ok := GateRefusal(reason)
		if string(c) != wantCode || ok != (wantCode != "") || (wantCode == "payment_mismatch" && f != "amount") {
			t.Fatalf("%q: %q %q %v", reason, c, f, ok)
		}
	}
}

// ---- fix 1: a retired key never comes back ----

// A public key retired in a version cannot come back under a new kid, neither in the same version nor in a later one, and a credential it signs is
// refused whichever kid it names.
func TestGateRetiredKeyNeverReturnsUnderAnotherKid(t *testing.T) {
	z := newGateZone(t, 84532)
	k1, k2 := gatecredtest.TestKey(1), gatecredtest.TestKey(2)
	z.keys = []gatecredtest.Key{k1, k2}
	z.govern()
	ctx := context.Background()
	refused := func(what string, f GateSettingFile) {
		t.Helper()
		if err := z.guard.ApplyGateChange(ctx, z.cfg, z.signed(f, z.version+1), z.clock(), "test"); err == nil {
			t.Fatalf("%s: the version was applied", what)
		}
	}
	// Same version: retire k1 and add its public key as "k1-again".
	same := z.settingFile()
	same.Keys = []GateKeyFile{{KID: k2.KID, PublicKey: b64(k2.Pub)}, {KID: "k1-again", PublicKey: b64(k1.Pub)}}
	same.Retired = []string{k1.KID}
	refused("retire and re-add in one version", same)
	// Two later versions: retire k1, then add it under a new kid.
	z.keys = []gatecredtest.Key{k2}
	retire := z.settingFile()
	retire.Retired = []string{k1.KID}
	z.apply(retire)
	later := z.settingFile()
	later.Keys = append(later.Keys, GateKeyFile{KID: "k1-later", PublicKey: b64(k1.Pub)})
	refused("re-add in a later version", later)
	// A credential signed by k1 is refused under any kid.
	payee := common.HexToAddress(gatecredtest.VectorsPayee)
	a := big.NewInt(10)
	for _, kid := range []string{k1.KID, "k1-again", "k1-later", k2.KID} {
		now := z.clock().Unix()
		c := gatecred.Credential{V: 1, KID: kid, CredentialID: uuid.NewString(), ObligationID: "o", Audience: gatecredtest.VectorsAudience, WalletID: z.wallet,
			Chain: "eip155:84532", Asset: gatecred.NativeAsset, Payee: strings.ToLower(payee.Hex()), Amount: "10", IssuedAt: now - 10, ExpiresAt: now + 300,
			PolicyVersion: "p", DecisionReason: "r"}
		code := string(gatecred.KIDUnknown)
		if kid == k2.KID {
			code = string(gatecred.SignatureInvalid) // k2's kid, k1's signature
		}
		want(t, "signed by k1 as "+kid, z.gate(z.native("rk-"+kid, payee, a, string(gatecredtest.Mint(k1, c)))), code, "")
	}
}

// ---- fix 2: a retry after expiry ----

// A retry of the same digest after the credential expired gets the decision already made: the stored signature (gateway), the same digest allowed
// again (cosigner); no new record, nothing counted again. Another payload under that credential_id after expiry is refused as expired: the pure checks
// (9) run before the replay record (12), in the spec's order.
func TestGateRetryAfterExpiry(t *testing.T) {
	z := newGateZone(t, 84532)
	z.limits = map[string]GateLimitFile{"ETH": {PerPayment: "100", PerHour: "100", PerDay: "100"}}
	z.govern()
	payee := common.HexToAddress(gatecredtest.VectorsPayee)
	a := big.NewInt(100)
	cred := z.cred(gatecred.NativeAsset, payee.Hex(), a, nil) // expires now+590
	j := z.native("e1", payee, a, cred)
	d := z.run(j)
	if d.Outcome != OutcomeSigned {
		t.Fatalf("first: %s %s", d.Outcome, d.Reason)
	}
	want(t, "first (cosigner)", z.cosign(j), "", "")
	z.advance(600*time.Second + 31*time.Second) // past expires_at + skew
	again := j
	again.ID = "e1-retry"
	d2 := z.run(again)
	if d2.Outcome != OutcomeReplayed || string(d2.Sig) != string(d.Sig) {
		t.Fatalf("retry at the gateway after expiry: %s %s", d2.Outcome, d2.Reason)
	}
	want(t, "retry (cosigner) after expiry", z.cosign(j), "", "")
	for _, db := range []*pgxpool.Pool{z.guardDB, z.cosDB} {
		var n int
		db.QueryRow(context.Background(), `SELECT count(*) FROM gate_credentials_used`).Scan(&n)
		if n != 1 {
			t.Fatalf("%d records, want 1", n)
		}
	}
	var retries int
	z.guardDB.QueryRow(context.Background(), `SELECT count(*) FROM audit_log WHERE payload->'gate'->>'retry' = 'true'`).Scan(&retries)
	if retries != 1 {
		t.Fatalf("%d retries audited at the gateway, want 1", retries)
	}
	other := z.native("e2", payee, a, cred) // another nonce: another digest
	want(t, "other payload after expiry (gateway)", z.gate(other), string(gatecred.Expired), "expires_at")
	want(t, "other payload after expiry (cosigner)", z.cosign(other), string(gatecred.Expired), "expires_at")
	if z.signer.calls.Load() != 1 {
		t.Fatalf("signed %d times", z.signer.calls.Load())
	}
}

// ---- fix 3: the zone's own refusals carry the gate facts ----

func TestGateFactsOnTheZonesOwnRefusals(t *testing.T) {
	z := newGateZone(t, 84532)
	cc := z.cfg.Chains[testChain]
	p := cc.Assets["ETH"]
	p.AnyDestination, p.Destinations = false, map[string]bool{addrUser.Hex(): true}
	cc.Assets["ETH"] = p
	z.govern()
	payee := common.HexToAddress(gatecredtest.VectorsPayee)
	a := big.NewInt(10)
	cred := z.cred(gatecred.NativeAsset, payee.Hex(), a, nil)
	want(t, "destination outside the list", z.gate(z.native("f1", payee, a, cred)), ReasonDestination, "")
	var raw []byte
	if err := z.guardDB.QueryRow(context.Background(), `SELECT payload->'gate' FROM audit_log WHERE type=$1 AND payload->>'job'='f1'`, EventSignRefused).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var g map[string]any
	json.Unmarshal(raw, &g)
	parsed, _ := gatecred.Parse([]byte(cred))
	if g["credential_id"] != parsed.CredentialID || g["code"] != ReasonDestination || g["wallet_id"] != z.wallet || g["payment"] == nil {
		t.Fatalf("gate facts %v", g)
	}
}

// ---- GC2b: a rebalance out of a Gate-governed wallet pays only another Gate-governed wallet ----

func TestGateRebalanceOnlyToAnotherGateWallet(t *testing.T) {
	shard2 := GateWalletFile{WalletID: "22222222-3333-4444-8555-666666666666", Partition: testShard2}
	rebalance := func(z *gateZone, id string, amount int64) signjob.Job {
		return z.job(id, signjob.Intent{Kind: "rebalance", ID: "rb-" + id, PartitionID: testColdPartition, Asset: "ETH", To: addrShard2.Hex(), Amount: fmt.Sprint(amount)},
			z.ethTx(addrShard2, amount, z.nextNonce()), "alice", "bob")
	}
	both := func(z *gateZone, what string, j signjob.Job, code string) {
		t.Helper()
		want(t, what+" (gateway)", z.gate(j), code, "")
		want(t, what+" (cosigner)", z.cosign(j), code, "")
	}

	// Governed source, destination not governed: refused, approvals or not.
	z := newGateZone(t, 84532)
	z.govern()
	both(z, "governed to not governed", rebalance(z, "a1", 10), ReasonGateRebalance)
	// Governed to governed: signed.
	f := z.settingFile()
	f.Wallets = append(f.Wallets, shard2)
	z.apply(f)
	both(z, "governed to governed", rebalance(z, "a2", 10), "")
	// To cold from a governed wallet: unchanged.
	both(z, "to-cold from governed", z.job("a3", signjob.Intent{Kind: "to-cold", ID: "tc-a3", PartitionID: testColdPartition, Asset: "ETH", To: addrCold.Hex(), Amount: "10"},
		z.ethTx(addrCold, 10, z.nextNonce())), "")

	// Source not governed, destination governed: unchanged.
	z2 := newGateZone(t, 84532)
	z2.apply(GateSettingFile{Audience: gatecredtest.VectorsAudience, Keys: []GateKeyFile{{KID: z2.keys[0].KID, PublicKey: b64(z2.keys[0].Pub)}},
		Wallets: []GateWalletFile{shard2}})
	both(z2, "not governed to governed", rebalance(z2, "b1", 10), "")
	// And with no Gate setting at all: unchanged.
	z3 := newGateZone(t, 84532)
	both(z3, "no gate setting", rebalance(z3, "c1", 10), "")
}
