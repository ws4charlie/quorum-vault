package btce2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
	"github.com/ws4charlie/quorum-vault/internal/custody"
	"github.com/ws4charlie/quorum-vault/internal/gateway"
	"github.com/ws4charlie/quorum-vault/internal/gateway/gatewaytest"
	"github.com/ws4charlie/quorum-vault/internal/ledger"
)

const btcTier2 = "50000000" // withdrawals of at least 0.5 BTC need two approvals

// setupWithdrawals adds the withdrawal path to the system under construction: the hot shard in the business config, approvers, the automated key,
// the signing zone's config (gateway and cosigner), and party B's cosigner.
func (s *system) setupWithdrawals(o opts) {
	t := s.t
	acct, err := btc.NewAccount("regtest", s.xpub)
	if err != nil {
		t.Fatal(err)
	}
	s.acct = acct
	s.hotAddr, err = acct.Address([]uint32{1, 0})
	if err != nil {
		t.Fatal(err)
	}
	s.part = "qv-us/" + s.chain + "/BTC/hot/omnibus/0"
	s.cf.Chain.BTC.HotShards = []custody.BTCShardFile{{Address: s.hotAddr, Path: []uint32{1, 0}}}
	s.cf.Chain.BTC.SpendConfirmations = 2
	s.cf.Chain.BTC.MaxFeeRate = 50
	s.cf.Chain.BTC.MaxTxFeeSats = 50_000
	s.cf.Withdrawal.Tiers = map[string][]custody.TierFile{"BTC": {{MinAmount: "0", Approvals: 1, Auto: true}, {MinAmount: btcTier2, Approvals: 2}}}
	s.cf.Withdrawal.HotWait = "4m"
	s.cf.Withdrawal.SignTimeout = "20s"
	s.cf.Withdrawal.StuckAfter = "10m"
	if o.stuckAfter != "" {
		s.cf.Withdrawal.StuckAfter = o.stuckAfter
	}
	if o.fallbackRate != 0 {
		s.cf.Chain.BTC.FallbackFeeRate = o.fallbackRate
	}
	s.lease = "30s"
	if o.lease != "" {
		s.lease = o.lease
	}

	s.approv = map[string]ed25519.PrivateKey{}
	apprFiles := map[string]gateway.ApproverFile{}
	for _, name := range []string{"alice", "bob", "carol", "auto"} {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		s.approv[name] = priv
		apprFiles[name] = gateway.ApproverFile{PublicKey: hex.EncodeToString(pub), Enabled: true}
	}
	s.keyPath = filepath.Join(s.dir, "auto.key")
	if err := os.WriteFile(s.keyPath, []byte(hex.EncodeToString(s.approv["auto"].Seed())), 0o600); err != nil {
		t.Fatal(err)
	}

	sweepsPerHour := 100000
	if o.gwSweepsPerHour > 0 {
		sweepsPerHour = o.gwSweepsPerHour
	}
	s.coldAddr = s.node.fresh()
	if o.refill {
		s.coldAddr = s.newColdKit(o)
	}
	s.cf.Cold.Addresses = map[string]string{"omnibus/native": s.coldAddr}
	s.cf.Cold.PlanInterval = "500ms"
	if o.coldHigh != "" {
		low := o.coldLow
		if low == "" {
			low = "0"
		}
		s.cf.Cold.Limits = map[string]custody.LimitFile{"BTC": {Low: low, High: o.coldHigh, Target: o.coldTarget}}
	}
	toColdCap := "1000000000000"
	if o.toColdCap != "" {
		toColdCap = o.toColdCap
	}
	crt, key := s.mpc.CertGW.Write(t, s.mpc.Dir)
	asset := gateway.AssetFile{PerTxCap: "1000000000", DailyCap: "100000000000", ToColdDailyCap: toColdCap, Tiers: []gateway.TierFile{{MinAmount: "0", Approvals: 1}, {MinAmount: btcTier2, Approvals: 2}}}
	if len(o.gwDest) > 0 {
		asset.WithdrawalDestinations = o.gwDest
	} else {
		asset.AnyDestination = true
	}
	gf := gateway.File{
		Approvers: apprFiles, SignTimeout: "20s", MaxIntentAge: "24h",
		Signers: map[string]gateway.SignerFile{s.part: {Backend: "mpc", KeysetID: s.mpc.KeysetID, HardenedPath: btc.AccountPath("regtest"),
			MPC: &gateway.MPCSignerFile{Address: s.mpc.CallerA, CertFile: crt, KeyFile: key, ServerPin: s.mpc.CertA.Pin}}},
		Chains: map[string]gateway.ChainFile{s.chain: {Family: "btc", WithdrawalsPerHour: 100000, SweepsPerHour: sweepsPerHour, CancelsPerHour: 1000, ToColdPerHour: 1000, RebalancePerHour: 1000,
			BTC: &gateway.BTCFile{Network: "regtest", AccountXpub: s.xpub, ColdAddresses: map[string]string{"omnibus/native": s.coldAddr}, MaxTxFeeSats: 100_000, MaxFeeRate: 200, MaxInputs: 20,
				HotShards: map[string]gateway.HotShardFile{s.part: {Address: s.hotAddr, Path: []uint32{1, 0}}}},
			Assets: map[string]gateway.AssetFile{"BTC": asset}}},
	}
	s.gwFile = gf
	s.gwPath = filepath.Join(s.dir, "gateway.json")
	writeJSONFile(t, s.gwPath, gf)
	cf := gf
	cf.Signers = nil
	cosPath := filepath.Join(s.dir, "cosigner.json")
	writeJSONFile(t, cosPath, cf)
	_, s.gwGuard = gatewaytest.NewGuardDB(t)
	_, cosGuard := gatewaytest.NewGuardDB(t)
	s.mpc.StartCosigner(cosPath, cosGuard, s.gwGuard)
}

func writeJSONFile(t *testing.T, path string, v any) {
	t.Helper()
	b, _ := json.MarshalIndent(v, "", " ")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// startGateway lets role qv_gateway log in (it may only read and update sign_jobs) and starts qv-gateway.
func (s *system) startGateway() {
	url := os.Getenv("DATABASE_URL")
	c, err := pgx.Connect(s.ctx, url)
	if err != nil {
		s.t.Fatal(err)
	}
	if _, err := c.Exec(s.ctx, `ALTER ROLE qv_gateway LOGIN`); err != nil {
		s.t.Fatal(err)
	}
	c.Close(s.ctx)
	s.t.Cleanup(func() {
		if c, err := pgx.Connect(context.Background(), url); err == nil {
			c.Exec(context.Background(), `ALTER ROLE qv_gateway NOLOGIN`)
			c.Close(context.Background())
		}
	})
	jobs := strings.Replace(s.bizDSN, "//qv@", "//qv_gateway@", 1)
	s.gateway = s.spawn("qv-gateway", "-config", s.gwPath, "-jobs-dsn", jobs, "-guard-dsn", s.gwGuard, "-interval", "200ms", "-lease", s.lease, "-worker-id", "gw-"+uuid.NewString()[:6])
	p := s.gateway
	s.waitFor(30*time.Second, "gateway started", func() bool { return fileContains(p.log, "gateway") })
}

type wd struct {
	ID, Status, Reason, Tx string
	Code                   int
	Raw                    map[string]any
}

func (s *system) withdraw(actor, key, customer, to string, amount int64) wd {
	s.t.Helper()
	key += "~" + s.tag
	code, out := s.call2("POST", "/v2/withdrawals", map[string]string{"X-Actor": actor, "Idempotency-Key": key},
		map[string]any{"customer": customer, "asset": "BTC", "to": to, "amount": fmt.Sprint(amount)})
	w := wd{Code: code, Raw: out}
	if code == 200 || code == 201 {
		w.ID, _ = out["id"].(string)
		w.Status, _ = out["status"].(string)
	}
	return w
}

func (s *system) call2(method, path string, hdr map[string]string, body any) (int, map[string]any) {
	s.t.Helper()
	return s.callWith(method, path, hdr, body)
}

func (s *system) getWd(id string) wd {
	s.t.Helper()
	code, out := s.call("GET", "/v2/withdrawals/"+id, nil)
	if code != 200 {
		s.t.Fatalf("get withdrawal: %d %v", code, out)
	}
	w := wd{ID: id, Code: code, Raw: out}
	w.Status, _ = out["status"].(string)
	w.Reason, _ = out["failure_reason"].(string)
	w.Tx, _ = out["tx_hash"].(string)
	return w
}

func (s *system) waitWd(id, status string, timeout time.Duration) wd {
	s.t.Helper()
	var w wd
	s.waitFor(timeout, fmt.Sprintf("withdrawal %s = %s", id, status), func() bool {
		w = s.getWd(id)
		if w.Status == "failed" && status != "failed" {
			s.t.Fatalf("withdrawal %s failed: %s", id, w.Reason)
		}
		return w.Status == status
	})
	return w
}

func (s *system) approve(actor, id string) (int, map[string]any) {
	s.t.Helper()
	code, in := s.call("GET", "/v2/withdrawals/"+id+"/intent", nil)
	if code != 200 {
		s.t.Fatalf("intent: %d %v", code, in)
	}
	h, _ := hex.DecodeString(in["hash"].(string))
	sig := ed25519.Sign(s.approv[actor], h)
	return s.callWith("POST", "/v2/withdrawals/"+id+"/approvals", map[string]string{"X-Actor": actor},
		map[string]any{"actor": actor, "signature": hex.EncodeToString(sig)})
}

// fundHot sends sats from the node's wallet to the hot address, mines to safe depth and waits until the scan has recorded it as an output and
// booked it as operator funding.
func (s *system) fundHot(sats int64) {
	s.t.Helper()
	before := s.count(`SELECT count(*) FROM btc_utxos WHERE chain=$1 AND NOT deposit AND NOT cold`, s.chain)
	s.node.pay(map[string]string{s.hotAddr: btcAmount(sats)})
	s.node.mine(6, "")
	s.waitFor(60*time.Second, "the hot funding is recorded", func() bool {
		return s.count(`SELECT count(*) FROM btc_utxos WHERE chain=$1 AND NOT deposit AND NOT cold`, s.chain) > before
	})
}

func btcAmount(sats int64) string { return fmt.Sprintf("%d.%08d", sats/1e8, sats%1e8) }

// deposit credits a customer: a payment to its deposit address, mined to the deposit depth.
func (s *system) deposit(customer string, sats int64) {
	s.t.Helper()
	addr := s.newCustomer(customer)
	s.node.pay(map[string]string{addr: btcAmount(sats)})
	s.node.mine(6, "")
	s.waitAvailable(customer, sats, 60*time.Second)
}

func (s *system) utxoCount(status string) int {
	return s.count(`SELECT count(*) FROM btc_utxos WHERE chain=$1 AND NOT deposit AND NOT cold AND status=$2`, s.chain, status)
}

func (s *system) utxoValue(status string) int64 {
	var v int64
	if err := s.pool.QueryRow(s.ctx, `SELECT COALESCE(SUM(value),0) FROM btc_utxos WHERE chain=$1 AND NOT deposit AND NOT cold AND status=$2`, s.chain, status).Scan(&v); err != nil {
		s.t.Fatal(err)
	}
	return v
}

// received is what the address has received on chain in blocks (at least minConf confirmations), in satoshis.
func (s *system) received(addr string, minConf int) int64 {
	s.t.Helper()
	var v json.Number
	if err := s.node.w.Call(s.ctx, &v, "getreceivedbyaddress", addr, minConf); err != nil {
		s.t.Fatal(err)
	}
	n, err := btc.Sats(v.String())
	if err != nil {
		s.t.Fatal(err)
	}
	return n.Int64()
}

func (s *system) ledgerOK() {
	s.t.Helper()
	if err := ledger.CheckInvariants(s.ctx, s.pool); err != nil {
		s.t.Fatal(err)
	}
}

func (s *system) posted(acct string) *big.Int {
	s.t.Helper()
	var v string
	if err := s.pool.QueryRow(s.ctx, `SELECT posted::text FROM ledger_accounts WHERE id=$1`, acct).Scan(&v); err != nil {
		s.t.Fatal(err)
	}
	n, _ := new(big.Int).SetString(v, 10)
	return n
}

func (s *system) hotPosted() *big.Int { return s.posted(custody.HotAccount(s.part)) }

var _ = bytes.NewReader
