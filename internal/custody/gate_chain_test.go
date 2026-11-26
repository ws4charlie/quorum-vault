package custody

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/chain/evm"
	"github.com/ws4charlie/quorum-vault/internal/chain/evm/evmtest"
	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
	"github.com/ws4charlie/quorum-vault/internal/domain"
	"github.com/ws4charlie/quorum-vault/internal/gatecred"
	"github.com/ws4charlie/quorum-vault/internal/gatecred/gatecredtest"
	"github.com/ws4charlie/quorum-vault/internal/gateway"
	"github.com/ws4charlie/quorum-vault/internal/signer"
)

// gateSoftSigner is the hot key in software, as the gateway's own tests use it.
type gateSoftSigner struct{ key *ecdsa.PrivateKey }

func (s gateSoftSigner) Backend() domain.Backend     { return domain.BackendHSM }
func (s gateSoftSigner) Key() domain.Key             { return domain.Key{} }
func (s gateSoftSigner) PublicKey() *ecdsa.PublicKey { return &s.key.PublicKey }
func (s gateSoftSigner) SignDigest(_ context.Context, d [32]byte, _ signer.SignOptions) (signer.Result, error) {
	sig, err := crypto.Sign(d[:], s.key)
	if err != nil {
		return signer.Result{}, err
	}
	return signer.Result{Sig: signer.NormalizeLowS(signer.Signature{R: new(big.Int).SetBytes(sig[:32]), S: new(big.Int).SetBytes(sig[32:64])})}, nil
}

// The whole path on a local node that stands in for Base Sepolia (chain 84532): AgentGate's request through the core's API, the sign job with the
// credential in its intent, the real gateway (decider, replay guard, software hot key) with the zone's own credential rule and an operator-signed gate
// setting, the signature back through the API, and the token accepting it in transferWithAuthorization submitted by a facilitator. The same request
// again returns the same answer without a second signing; a credential whose amount differs from the payload's comes back as the zone's
// payment_mismatch with its field. Run: QV_REQUIRE_CHAIN=1 QV_ANVIL_RPC=http://127.0.0.1:18546 with DATABASE_URL and QV_SIGNING_DB_URL.
func TestGateAPIThroughTheZoneOnALocalBaseSepolia(t *testing.T) {
	node := evmtest.Anvil(t, evmtest.BaseSepoliaChainID)
	token := node.DeployToken(t, "USDC")
	ctx := context.Background()

	key, _ := crypto.GenerateKey()
	payer := crypto.PubkeyToAddress(key.PublicKey)
	cfg := testConfig(t)
	cfg.EVM.ChainID, cfg.EVM.RPCURL, cfg.EVM.Confirmations = evmtest.BaseSepoliaChainID, node.URL, 0
	cfg.HotShards[0] = payer
	for _, sym := range cfg.AssetList {
		cfg.EVM.HotAddresses[cfg.PartitionKey(sym, 0).String()] = payer
	}
	a := cfg.Assets["USDT"]
	a.Address = token.Address
	cfg.Assets["USDT"] = a
	cfg.EVM.Assets["USDT"] = evm.Token{Address: token.Address, Decimals: 6}
	cfg.EVM.X402 = map[string]evm.X402Token{"USDT": {Name: "USDC", Version: "2", MaxWindowSeconds: 600, PerPaymentLimit: big.NewInt(500_000)}}
	cfg.X402Shard = map[string]int{"USDT": 0}
	part := cfg.PartitionKey("USDT", 0).String()
	cfg.Gate = &GateConfig{Audience: gateAudience, Skew: 30 * time.Second, Wait: 20 * time.Second,
		Wallets: map[string]GateWallet{gateWallet: {ID: gateWallet, Partition: part, Asset: "USDT"}}}
	rd, err := NewEVMReader(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rd.Close)
	pool := dbtest.New(t)
	s := New(pool, cfg, &fakeChain{fee: big.NewInt(7), statuses: map[string]chain.TxStatus{}}, rd)
	clock := func() time.Time { return time.Unix(int64(node.BlockTime(t)), 0) }
	s.Now = clock
	if err := s.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	token.Mint(t, payer, 1_000_000)
	if err := s.FundHotAsset(ctx, "seed", 0, "USDT", big.NewInt(1_000_000)); err != nil {
		t.Fatal(err)
	}

	// The zone: the gateway with its own config, guard database and the hot key.
	apub, _, _ := ed25519.GenerateKey(rand.Reader)
	zf := gateway.File{
		Approvers: map[string]gateway.ApproverFile{"alice": {PublicKey: hex.EncodeToString(apub), Enabled: true}},
		Chains: map[string]gateway.ChainFile{testChain: {
			EVM: &gateway.EVMFile{ChainID: evmtest.BaseSepoliaChainID, Factory: "0x00000000000000000000000000000000000000f1",
				SweepDestination: "0x00000000000000000000000000000000000000a1",
				HotAddresses:     map[string]string{part: payer.Hex()},
				ColdAddresses:    map[string]string{"omnibus/native": "0x00000000000000000000000000000000000000b1", "omnibus/token": "0x00000000000000000000000000000000000000b1"},
				Tokens:           map[string]gateway.TokenFile{"USDT": {Address: token.Address.Hex(), Decimals: 6}},
				MaxTxFeeWei:      "300000000000000",
				X402:             map[string]gateway.X402File{"USDT": {Name: "USDC", Version: "2", MaxWindowSeconds: 600, PerPaymentLimit: "500000"}}},
			Assets: map[string]gateway.AssetFile{
				"ETH":  {AnyDestination: true, PerTxCap: "5000", DailyCap: "8000", Tiers: []gateway.TierFile{{MinAmount: "0", Approvals: 1}}, ToColdDailyCap: "1", RebalanceDailyCap: "1"},
				"USDT": {AnyDestination: true, PerTxCap: "5000000", DailyCap: "8000000", Tiers: []gateway.TierFile{{MinAmount: "0", Approvals: 1}}, ToColdDailyCap: "1", RebalanceDailyCap: "1"},
			},
			SweepsPerHour: 1, WithdrawalsPerHour: 1, CancelsPerHour: 1, ToColdPerHour: 1, RebalancePerHour: 1,
		}},
	}
	raw, _ := json.Marshal(zf)
	zcfg, err := gateway.ParseConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	gcfg, err := pgxpool.ParseConfig(dbtest.CreateGuardDB(t, "qv_guard_gate_"))
	if err != nil {
		t.Fatal(err)
	}
	guardPool, err := pgxpool.NewWithConfig(ctx, gcfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(guardPool.Close)
	guard, err := gateway.OpenGuard(ctx, guardPool)
	if err != nil {
		t.Fatal(err)
	}
	// Two zone operators sign the gate setting: the wallet, its shard, its limits and Gate's TEST ONLY key.
	k1 := gatecredtest.TestKey(1)
	ops := map[string]ed25519.PrivateKey{}
	zcfg.Operators = &gateway.OperatorConfig{Keys: map[string]ed25519.PublicKey{}, Min: 2, MaxAge: 10 * time.Minute}
	for _, n := range []string{"op1", "op2"} {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		ops[n], zcfg.Operators.Keys[n] = priv, pub
	}
	change := gateway.GateChange{Version: 1, SignedAt: clock().Unix(), Setting: gateway.GateSettingFile{Audience: gateAudience, SkewSeconds: 30,
		MaxTTLSeconds: 600, Keys: []gateway.GateKeyFile{{KID: k1.KID, PublicKey: base64.RawURLEncoding.EncodeToString(k1.Pub)}},
		Wallets: []gateway.GateWalletFile{{WalletID: gateWallet, Partition: part,
			Limits: map[string]gateway.GateLimitFile{"USDT": {PerPayment: "500000", PerHour: "1000000", PerDay: "1000000"}}}}}}
	var parts []gateway.GateChange
	for _, n := range []string{"op1", "op2"} {
		parts = append(parts, gateway.SignGateChange(ops[n], n, change))
	}
	signed, err := gateway.MergeGateChanges(parts...)
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.ApplyGateChange(ctx, zcfg, signed, clock(), "test"); err != nil {
		t.Fatal(err)
	}
	gw, err := gateway.New(zcfg, nil, map[string]signer.Signer{part: gateSoftSigner{key}}, guard, pool,
		gateway.Options{WorkerID: "w-gate", Lease: time.Minute, Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	zctx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); _ = gw.Run(zctx, 50*time.Millisecond) }()
	t.Cleanup(func() { stop(); <-done; gw.Wait(10 * time.Second) })

	// AgentGate's request: the typed data of the authorization and a credential of the test minter for exactly that payment.
	now := uint64(clock().Unix())
	var nonce [32]byte // all zero: Gate's nonce is signed as given, and the token accepts it
	payload, _, err := cfg.EVM.NewPayload3009("USDT", payer, common.HexToAddress(gatePayee), big.NewInt(250_000), now-60, now+240, nonce)
	if err != nil {
		t.Fatal(err)
	}
	const id = "0b6c1d52-8a4f-4e17-b3d9-5f2a7c9e1a77"
	cred := gatecred.Credential{V: 1, KID: k1.KID, CredentialID: id, ObligationID: "obl-e2e", Audience: gateAudience, WalletID: gateWallet,
		Chain: fmt.Sprintf("eip155:%d", evmtest.BaseSepoliaChainID), Asset: strings.ToLower(token.Address.Hex()), Payee: gatePayee, Amount: "250000",
		IssuedAt: int64(now) - 60, ExpiresAt: int64(now) + 300, PolicyVersion: "p-1", DecisionReason: "e2e"}
	req := GateRequest{WalletID: gateWallet, Kind: GateKindEIP3009, Payload: payload, Credential: gatecredtest.Mint(k1, cred)}

	status, body := s.GateSign(ctx, req, nil)
	if status != 200 {
		t.Fatalf("API: %d %s", status, body)
	}
	var out GateSigned
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	sig, err := hex.DecodeString(strings.TrimPrefix(out.Signature, "0x"))
	if err != nil || len(sig) != 65 {
		t.Fatalf("signature %q", out.Signature)
	}
	auth, err := evm.NewVerifierForTest(cfg.EVM).DecodeAuthorization(payload)
	if err != nil {
		t.Fatal(err)
	}
	var r, ss [32]byte
	copy(r[:], sig[:32])
	copy(ss[:], sig[32:64])
	rc, err := token.Submit(t, auth, sig[64], r, ss)
	if err != nil || rc.Status != 1 {
		t.Fatalf("the token refused the API's signature: %v %+v", err, rc)
	}
	if got := token.BalanceOf(t, common.HexToAddress(gatePayee)); got.Int64() != 250_000 {
		t.Fatalf("payee holds %s", got)
	}
	// The same request again: the stored answer, no second job.
	status2, body2 := s.GateSign(ctx, req, nil)
	if status2 != 200 || string(body2) != string(body) {
		t.Fatalf("repeat: %d %s", status2, body2)
	}
	var jobs int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM sign_jobs`).Scan(&jobs); err != nil || jobs != 1 {
		t.Fatalf("%d jobs, %v", jobs, err)
	}
	// A credential for another amount than the payload's: the zone refuses it, and the API answers with the zone's code and field.
	_, _ = rand.Read(nonce[:])
	payload2, _, err := cfg.EVM.NewPayload3009("USDT", payer, common.HexToAddress(gatePayee), big.NewInt(1000), now-60, now+240, nonce)
	if err != nil {
		t.Fatal(err)
	}
	bad := cred
	bad.CredentialID, bad.Amount = "0b6c1d52-8a4f-4e17-b3d9-5f2a7c9e1a78", "999"
	status3, body3 := s.GateSign(ctx, GateRequest{WalletID: gateWallet, Kind: GateKindEIP3009, Payload: payload2, Credential: gatecredtest.Mint(k1, bad)}, nil)
	var rf GateRefusal
	_ = json.Unmarshal(body3, &rf)
	if status3 != 403 || rf.Code != "payment_mismatch" || rf.Field != "amount" {
		t.Fatalf("tampered amount: %d %s", status3, body3)
	}
}
