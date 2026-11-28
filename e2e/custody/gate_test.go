package custody_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/e2e/idp"
	"github.com/ws4charlie/quorum-vault/internal/chain/evm"
	"github.com/ws4charlie/quorum-vault/internal/chain/evm/evmtest"
	"github.com/ws4charlie/quorum-vault/internal/custody"
	"github.com/ws4charlie/quorum-vault/internal/gatecred"
	"github.com/ws4charlie/quorum-vault/internal/gatecred/gatecredtest"
	"github.com/ws4charlie/quorum-vault/internal/gateway"
	"github.com/ws4charlie/quorum-vault/internal/pki/pkitest"
)

// The GATE-CONNECT demo (docs/gate-credential.md): AgentGate's payments from a Gate-governed hot wallet, end to end on the real services.
const (
	gateDemoAudience = "qv-e2e"
	gateDemoWallet   = "7d1e0c5a-2f4b-4a9e-8c3d-6b5a4f3e2d1c"
	// gateDemoShard is the Gate-governed hot shard. Not shard 0: a Gate shard is Gate's alone, and Vault's sweeps land on shard 0.
	gateDemoShard = 1
)

// TestGatePaymentSignedByMPCOnALocalBaseSepolia is the demo of the Gate connection with everything real: qv-core's signing API behind AgentGate's client
// certificate and service token, the sign job, the gateway and both cosigners each checking the credential against the typed data they decode, the
// two-party MPC signature (QV_CUSTODY_SIGNER=mpc; the HSM in the default mode), a facilitator submitting transferWithAuthorization to the EIP-3009 token
// on a node with chain id 84532, and the worker booking the x402 liability. The gate setting is signed by two zone operators with qv-approvers and applied
// to the gateway's guard and each cosigner's. Then: the same request returns the same answer with no second job; no credential and a tampered amount are
// refused with nothing signed; a job placed straight into the queue without a credential (a core that skips the API) is refused by the zone; and an
// authorization nobody submits releases its hold once its validBefore has passed. Reconcile is clean after the payment and at the end.
func TestGatePaymentSignedByMPCOnALocalBaseSepolia(t *testing.T) {
	s := newSystem(t, opts{gate: true})
	t.Logf("signer: %s", map[bool]string{true: "two-party MPC (mpc-party A and B, cosigners of B and C)", false: "HSM"}[mpcMode()])
	part := s.cfg.PartitionKey("USDT", gateDemoShard).String()
	payer := s.shardAddr[gateDemoShard]
	if now, chainNow := time.Now().Unix(), int64(s.base.BlockTime(t)); chainNow > now+60 || chainNow < now-600 {
		t.Fatalf("the node's clock (%d) is not near this machine's (%d): an earlier test moved it; use a fresh node", chainNow, now)
	}

	// 1. Two zone operators sign the gate setting (the wallet, its shard, its fast-lane limits, Gate's TEST ONLY key) and apply it to every checker.
	k1 := gatecredtest.TestKey(1)
	setting := gateway.GateSettingFile{Audience: gateDemoAudience, SkewSeconds: 30, MaxTTLSeconds: 600,
		Keys: []gateway.GateKeyFile{{KID: k1.KID, PublicKey: base64.RawURLEncoding.EncodeToString(k1.Pub)}},
		Wallets: []gateway.GateWalletFile{{WalletID: gateDemoWallet, Partition: part,
			Limits: map[string]gateway.GateLimitFile{"USDT": {PerPayment: "500000", PerHour: "1000000", PerDay: "1000000"}}}}}
	settingPath, versionPath := filepath.Join(s.dir, "gate-setting.json"), filepath.Join(s.dir, "gate-v1.json")
	writeJSON(t, settingPath, setting)
	s.qvApprovers("gate-sign", "-operator", "op1", "-key", filepath.Join(s.dir, "op1.key"), "-setting", settingPath, "-version", "1", "-out", versionPath)
	s.qvApprovers("gate-sign", "-operator", "op2", "-key", filepath.Join(s.dir, "op2.key"), "-join", versionPath, "-out", versionPath)
	apply := []string{"gate-apply", "-config", s.gwPath, "-guard-dsn", "gateway=" + s.guardDSN}
	if mpcMode() {
		apply = append(apply, "-guard-dsn", "cosigner-b="+s.cosGuardDSN, "-guard-dsn", "cosigner-c="+s.cosCGuardDSN)
	}
	t.Logf("gate-apply:\n%s", s.qvApprovers(append(apply, versionPath)...))

	// The x402 money: the wallet holds 1 USDT on chain and in the books.
	s.x402.Mint(t, payer, 1_000_000)
	if err := s.svc.FundHotAsset(s.ctx, "seed-usdt-"+s.tag, gateDemoShard, "USDT", big.NewInt(1_000_000)); err != nil {
		t.Fatal(err)
	}
	s.reconcileClean()
	hotBefore := s.posted("hot:" + part)

	payee := randAddr()
	now := uint64(time.Now().Unix())
	credential := func(id string, amount string, validFor int64) gatecred.Credential {
		return gatecred.Credential{V: 1, KID: k1.KID, CredentialID: id, ObligationID: "obl-" + id[:8], Audience: gateDemoAudience, WalletID: gateDemoWallet,
			Chain: fmt.Sprintf("eip155:%d", evmtest.BaseSepoliaChainID), Asset: strings.ToLower(s.usdt.Hex()), Payee: strings.ToLower(payee.Hex()),
			Amount: amount, IssuedAt: int64(now) - 30, ExpiresAt: int64(now) + validFor, PolicyVersion: "policy-7", DecisionReason: "demo: within budget"}
	}
	payload := func(amount int64, validBefore uint64) json.RawMessage {
		var nonce [32]byte
		_, _ = rand.Read(nonce[:])
		p, _, err := s.cfg.EVM.NewPayload3009("USDT", payer, payee, big.NewInt(amount), now-30, validBefore, nonce) // validAfter = issued_at: the window lies inside the credential's (check 11)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	jobs := func() int { return s.count(`SELECT count(*) FROM sign_jobs WHERE id LIKE 'x402:%'`) }

	// 2. A Gate-approved payment: signed, submitted by the facilitator, paid, booked.
	id1 := "3c9e5a1b-7d2f-4e6a-9b8c-1a2b3c4d5e6f"
	p1 := payload(250_000, now+240)
	req1 := map[string]any{"wallet_id": gateDemoWallet, "kind": custody.GateKindEIP3009, "payload": p1, "credential": json.RawMessage(gatecredtest.Mint(k1, credential(id1, "250000", 300)))}
	code, body := s.gatePost(pkitest.ServiceClient("agentgate"), req1)
	if code != 200 {
		t.Fatalf("signing API: %d %s", code, body)
	}
	var signed custody.GateSigned
	if err := json.Unmarshal(body, &signed); err != nil || signed.CredentialID != id1 {
		t.Fatalf("answer %s: %v", body, err)
	}
	sig, err := hex.DecodeString(strings.TrimPrefix(signed.Signature, "0x"))
	if err != nil || len(sig) != 65 {
		t.Fatalf("signature %q", signed.Signature)
	}
	auth, err := evm.NewVerifierForTest(s.cfg.EVM).DecodeAuthorization(p1)
	if err != nil {
		t.Fatal(err)
	}
	var r, ss [32]byte
	copy(r[:], sig[:32])
	copy(ss[:], sig[32:64])
	if rc, err := s.x402.Submit(t, auth, sig[64], r, ss); err != nil || rc.Status != 1 {
		t.Fatalf("the token refused the signature: %v %+v", err, rc)
	}
	if got := s.usdtBalance(payee); got.Int64() != 250_000 {
		t.Fatalf("payee holds %s", got)
	}
	if got := s.usdtBalance(payer); got.Int64() != 750_000 {
		t.Fatalf("hot wallet holds %s", got)
	}
	s.waitFor(scaled(30*time.Second), "the worker books the used authorization", func() bool {
		return s.count(`SELECT count(*) FROM x402_authorizations WHERE id=$1 AND status='used'`, id1) == 1
	})
	x402Acct := custody.X402Account(s.cfg.Chain, "USDT")
	if got := s.posted(x402Acct); got.Int64() != -250_000 {
		t.Fatalf("%s posted %s, want -250000", x402Acct, got)
	}
	if d := new(big.Int).Sub(s.posted("hot:"+part), hotBefore); d.Int64() != 250_000 { // the other side of the same entry
		t.Fatalf("hot:%s moved by %s, want 250000", part, d)
	}
	s.reconcileClean()

	// 3. The same request again: the same answer, no second job.
	if code, again := s.gatePost(pkitest.ServiceClient("agentgate"), req1); code != 200 || !bytes.Equal(again, body) {
		t.Fatalf("repeat: %d %s", code, again)
	}
	if n := jobs(); n != 1 {
		t.Fatalf("%d x402 jobs after the repeat, want 1", n)
	}

	// 4. Refusals in front of the zone: no credential; AgentGate's token without its certificate. Nothing is placed.
	noCred := map[string]any{"wallet_id": gateDemoWallet, "kind": custody.GateKindEIP3009, "payload": payload(1000, now+240)}
	s.expectGateRefusal(pkitest.ServiceClient("agentgate"), noCred, 400, "credential_missing", "")
	id2 := "4d0f6b2c-8e3a-4f7b-ac9d-2b3c4d5e6f70"
	req2 := map[string]any{"wallet_id": gateDemoWallet, "kind": custody.GateKindEIP3009, "payload": payload(1000, now+240), "credential": json.RawMessage(gatecredtest.Mint(k1, credential(id2, "1000", 300)))}
	s.expectGateRefusal(pkitest.PeopleClient(), req2, 403, "client_not_authorized", "")
	if n := jobs(); n != 1 {
		t.Fatalf("%d x402 jobs after the refusals, want 1", n)
	}

	// 5. A credential for 999 on a payload of 1000: the zone decodes the amount and refuses; nothing is signed and the hold is released.
	id3 := "5e1a7c3d-9f4b-4a8c-bd0e-3c4d5e6f7081"
	req3 := map[string]any{"wallet_id": gateDemoWallet, "kind": custody.GateKindEIP3009, "payload": payload(1000, now+240), "credential": json.RawMessage(gatecredtest.Mint(k1, credential(id3, "999", 300)))}
	s.expectGateRefusal(pkitest.ServiceClient("agentgate"), req3, 403, "payment_mismatch", "amount")
	s.expectZoneRefused("x402:"+id3, "")

	// 6. A job placed straight into the queue for the Gate-governed wallet, with no credential (a core that skips the signing API): the zone refuses it.
	direct := "direct-" + s.tag
	if _, _, err := s.svc.RequestX402(s.ctx, custody.X402Request{ID: direct, Asset: "USDT", Payee: payee.Hex(), Amount: big.NewInt(1000),
		ValidAfter: now - 60, ValidBefore: now + 240}); err != nil {
		t.Fatal(err)
	}
	s.expectZoneRefused("x402:"+direct, "credential_missing")

	// 7. An authorization nobody submits: signed, held, and released once a final block is past its validBefore.
	id4 := "6f2b8d4e-0a5c-4b9d-8e1f-4d5e6f708192"
	vb := uint64(time.Now().Unix()) + 20
	req4 := map[string]any{"wallet_id": gateDemoWallet, "kind": custody.GateKindEIP3009, "payload": payload(100_000, vb), "credential": json.RawMessage(gatecredtest.Mint(k1, credential(id4, "100000", 300)))}
	if code, b := s.gatePost(pkitest.ServiceClient("agentgate"), req4); code != 200 {
		t.Fatalf("signing API: %d %s", code, b)
	}
	if n := s.count(`SELECT count(*) FROM ledger_holds WHERE id=$1 AND status='pending'`, "x402-hold:"+id4); n != 1 {
		t.Fatal("the signed authorization holds nothing")
	}
	for uint64(time.Now().Unix()) <= vb {
		time.Sleep(250 * time.Millisecond)
	}
	if err := s.rc.CallContext(s.ctx, nil, "evm_mine"); err != nil { // a block past validBefore: no later block can include the authorization
		t.Fatal(err)
	}
	s.waitFor(scaled(30*time.Second), "the worker releases the expired authorization", func() bool {
		return s.count(`SELECT count(*) FROM x402_authorizations WHERE id=$1 AND status='expired'`, id4) == 1
	})
	if n := s.count(`SELECT count(*) FROM ledger_holds WHERE id=$1 AND status='voided'`, "x402-hold:"+id4); n != 1 {
		t.Fatal("the expired authorization's hold was not voided")
	}
	if got := s.posted(x402Acct); got.Int64() != -250_000 {
		t.Fatalf("%s posted %s after the expiry, want -250000", x402Acct, got)
	}
	if got := s.usdtBalance(payer); got.Int64() != 750_000 {
		t.Fatalf("hot wallet holds %s after the expiry", got)
	}
	s.reconcileClean()
}

// gatePost calls the signing API with AgentGate's service token through client (AgentGate's certificate, or another).
func (s *system) gatePost(client *http.Client, body any) (int, []byte) {
	s.t.Helper()
	b, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, s.apiURL+"/v2/gate/signatures", bytes.NewReader(b))
	if err != nil {
		s.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", idp.GateBearer())
	resp, err := client.Do(req)
	if err != nil {
		s.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

func (s *system) expectGateRefusal(client *http.Client, body any, status int, code, field string) {
	s.t.Helper()
	got, raw := s.gatePost(client, body)
	var rf custody.GateRefusal
	_ = json.Unmarshal(raw, &rf)
	if got != status || rf.Code != code || rf.Field != field {
		s.t.Fatalf("want %d %s field %q, got %d %s", status, code, field, got, raw)
	}
}

// expectZoneRefused waits for the zone to refuse the job (with code in its reason, when given) and checks that nothing was signed and the hold is void.
func (s *system) expectZoneRefused(jobID, code string) {
	s.t.Helper()
	var status, reason string
	s.waitFor(scaled(30*time.Second), "the zone refuses "+jobID, func() bool {
		if err := s.pool.QueryRow(s.ctx, `SELECT status, coalesce(reject_reason,'') FROM sign_jobs WHERE id=$1`, jobID).Scan(&status, &reason); err != nil {
			s.t.Fatal(err)
		}
		return status == "rejected" || status == "failed" || status == "done"
	})
	if status != "rejected" || (code != "" && !strings.Contains(reason, code)) {
		s.t.Fatalf("job %s: %s %q, want rejected with %q", jobID, status, reason, code)
	}
	if n := s.count(`SELECT count(*) FROM sign_jobs WHERE id=$1 AND signature IS NOT NULL`, jobID); n != 0 {
		s.t.Fatalf("job %s has a signature", jobID)
	}
	id := strings.TrimPrefix(jobID, "x402:")
	s.waitFor(scaled(30*time.Second), "the refused authorization is released", func() bool {
		return s.count(`SELECT count(*) FROM x402_authorizations WHERE id=$1 AND status='refused'`, id) == 1 &&
			s.count(`SELECT count(*) FROM ledger_holds WHERE id=$1 AND status='voided'`, "x402-hold:"+id) == 1
	})
}
