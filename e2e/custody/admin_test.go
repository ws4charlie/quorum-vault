package custody_test

import (
	"encoding/json"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/ws4charlie/quorum-vault/internal/coldsign"
	"github.com/ws4charlie/quorum-vault/internal/custody"
)

// Factory administration: the cold key is the forwarder factory's admin. Changing the sweep destination, freezing and unfreezing,
// the guardian and the admin role are all offline ceremonies; the only online power is the guardian's freeze.

func adminOpts() opts {
	return opts{shards: 2, frozen: true, cold: &coldOpts{coldHSM: true, factoryAdmin: true, ethHigh: hugeMark, usdtHigh: hugeMark}}
}

func (s *system) factoryAddr(getter string) common.Address {
	s.t.Helper()
	sel := crypto.Keccak256([]byte(getter + "()"))[:4]
	out, err := s.ec.CallContract(s.ctx, ethereum.CallMsg{To: &s.factory, Data: sel}, nil)
	if err != nil {
		s.t.Fatal(err)
	}
	return common.BytesToAddress(out)
}

// requestAction opens a factory-call request through the API and returns its ID.
func (s *system) requestAction(kind, param, signer string) string {
	s.t.Helper()
	body := map[string]string{"kind": kind, "param": param}
	if signer != "" {
		body["signer"] = signer
	}
	code, out := s.call("POST", "/v2/cold/actions", map[string]string{"X-Actor": "ops"}, body)
	if code != 201 {
		s.t.Fatalf("request %s: %d %v", kind, code, out)
	}
	return out["id"].(string)
}

// runAction does the whole ceremony for a factory call with kit k and waits for the end state.
func (s *system) runAction(k *coldKit, name, kind, param, signer, want string) string {
	s.t.Helper()
	id := s.requestAction(kind, param, signer)
	rf := s.exportRefill(id)
	if rf.Request.Kind != kind || rf.Request.Contract != s.factory.Hex() {
		s.t.Fatalf("export of %s: %+v", kind, rf.Request)
	}
	sg, out, err := k.ceremony(name, rf, "alice", "bob")
	if err != nil {
		s.t.Fatalf("ceremony %s: %v\n%s", name, err, out)
	}
	if code, res := s.importRefill(id, sg); code != 200 {
		s.t.Fatalf("import %s: %d %v", name, code, res)
	}
	s.waitFor(90*time.Second, name+" to reach "+want, func() bool { return s.refillStatus(id) == want })
	return id
}

// rotate changes the sweep destination in every config that names it (business, gateway, cosigner) and restarts the processes that
// read it: what the runbook asks of the operators by hand.
func (s *system) rotateSweepDestination(dest common.Address) {
	s.t.Helper()
	s.cf.Chain.SweepDestination = dest.Hex()
	s.gf.Chains[s.chainName].EVM.SweepDestination = dest.Hex()
	writeJSON(s.t, s.cfgPath, s.cf)
	writeJSON(s.t, s.gwPath, s.gf)
	s.worker.stop()
	s.core.stop()
	s.gateway.stop()
	if s.mpc != nil {
		gf := s.gf
		gf.Signers = nil
		writeJSON(s.t, s.cosPath, gf)
		s.mpc.Cos.Stop()
		s.mpc.StartCosignerAgain()
	}
	s.startGateway()
	s.startWorker("")
	s.startCore()
}

func TestFactoryAdminRotationCeremony(t *testing.T) {
	s := newSystem(t, adminOpts())
	k := s.cold
	s.fundETH(s.coldAddr, eth(5)) // gas for the ceremonies
	if err := s.svc.FundCold(s.ctx, "gas-1", 0, "ETH", eth(5)); err != nil {
		t.Fatal(err)
	}
	if d := s.factoryAddr("destination"); d != (common.Address{}) {
		t.Fatalf("the factory was deployed with destination %s, want frozen", d)
	}
	if a := s.factoryAddr("admin"); a != k.addr {
		t.Fatalf("factory admin %s, want the cold key %s", a, k.addr)
	}

	// Deposits arrive while frozen and wait.
	a1 := s.newCustomer("c-rot-1")
	s.sendETH(a1, eth(3))
	s.waitAvailable("c-rot-1", "ETH", eth(3), 30*time.Second)
	s.holds(2*time.Second, "no sweep while the factory is frozen", func() bool { return s.count(`SELECT count(*) FROM sweeps`) == 0 })

	// Ceremony 1: set the destination to shard 0. Sweeps start.
	s.runAction(k, "dest0", "set-destination", s.shardAddr[0].Hex(), "", "confirmed")
	if d := s.factoryAddr("destination"); d != s.shardAddr[0] {
		t.Fatalf("destination %s after the ceremony", d)
	}
	s.waitFor(90*time.Second, "the deposit to be swept", func() bool { return s.sweepsConfirmed() >= 1 })
	s.waitIdle(60 * time.Second)
	if s.ethBalance(a1).Sign() != 0 {
		t.Fatal("the deposit address was not emptied")
	}

	// Rotation after a suspected compromise: the ceremony moves the destination to shard 1. Until the configs are updated, sweeps
	// are refused and wait; nothing is lost.
	s.runAction(k, "dest1", "set-destination", s.shardAddr[1].Hex(), "", "confirmed")
	a2 := s.newCustomer("c-rot-2")
	s.sendETH(a2, eth(2))
	s.waitAvailable("c-rot-2", "ETH", eth(2), 30*time.Second)
	s.waitFor(60*time.Second, "the destination-changed ALERT", func() bool { return s.alertCount("sweep destination was changed on chain") >= 1 })
	before := s.count(`SELECT count(*) FROM sweeps`)
	s.holds(2*time.Second, "no sweep and no lost funds while the config is stale", func() bool {
		return s.count(`SELECT count(*) FROM sweeps`) == before && s.ethBalance(a2).Cmp(eth(2)) == 0
	})
	if n := s.alertCount("sweep destination was changed on chain"); n != 1 {
		t.Fatalf("%d ALERTs for one change, want 1", n)
	}
	hot1 := s.ethBalance(s.shardAddr[1])

	// Operators update the configs (gateway, cosigner, business) and restart: sweeps go to the new address.
	s.rotateSweepDestination(s.shardAddr[1])
	s.waitFor(90*time.Second, "the waiting deposit to reach the new destination", func() bool { return s.ethBalance(a2).Sign() == 0 })
	s.waitIdle(60 * time.Second)
	// The old deposit address still works, and pays the new destination.
	s.sendETH(a1, eth(1))
	s.waitAvailable("c-rot-1", "ETH", eth(4), 30*time.Second)
	s.waitFor(90*time.Second, "the old deposit address to be swept to the new destination", func() bool { return s.ethBalance(a1).Sign() == 0 })
	s.waitIdle(60 * time.Second)
	if got := new(big.Int).Sub(s.ethBalance(s.shardAddr[1]), hot1); got.Cmp(eth(3)) > 0 || got.Cmp(new(big.Int).Sub(eth(3), big.NewInt(1e16))) < 0 {
		t.Fatalf("the new hot address received %s, want 3 ETH less the sweep fees", got)
	}

	// Operator spend out of the cold address is booked too (here: taken out by hand), and the books still match the chain.
	spent := new(big.Int).Div(eth(1), big.NewInt(2))
	s.fundETH(s.coldAddr, new(big.Int).Sub(s.ethBalance(s.coldAddr), spent))
	if code, out := s.call("POST", "/v2/cold/spends", map[string]string{"X-Actor": "ops"}, map[string]any{"id": "spend-1", "asset": "ETH", "shard": 0, "amount": spent.String()}); code != 200 {
		t.Fatalf("spend: %d %v", code, out)
	}
	s.reconcileClean() // the cold fees of both ceremonies, the funding and the spend are all in the books
	s.requireAudit("cold.funded", "cold.spent", "cold_action.requested", "refill.exported", "refill.imported")
}

func TestGuardianFreezeAndCeremonyUnfreeze(t *testing.T) {
	s := newSystem(t, adminOpts())
	k := s.cold
	s.fundETH(s.coldAddr, eth(5))
	if err := s.svc.FundCold(s.ctx, "gas-1", 0, "ETH", eth(5)); err != nil {
		t.Fatal(err)
	}
	s.runAction(k, "dest0", "set-destination", s.shardAddr[0].Hex(), "", "confirmed")
	a := s.newCustomer("c-frz-1")
	s.sendETH(a, eth(2))
	s.waitFor(90*time.Second, "the first deposit to be swept", func() bool { return s.sweepsConfirmed() >= 1 })
	s.waitIdle(60 * time.Second)

	// The guardian key lives online. A stranger's key is refused by the command itself; the guardian's freezes.
	guardianKey := filepath.Join(s.dir, "guardian.key")
	if err := os.WriteFile(guardianKey, []byte(common.Bytes2Hex(crypto.FromECDSA(s.guardian))), 0o600); err != nil {
		t.Fatal(err)
	}
	strangerKey := filepath.Join(s.dir, "stranger.key")
	os.WriteFile(strangerKey, []byte(common.Bytes2Hex(crypto.FromECDSA(s.deployer))), 0o600)
	guardian := func(key string) (string, error) {
		out, err := exec.Command(filepath.Join(binDir, "qv-guardian"), "freeze", "-rpc", s.rpcURL, "-factory", s.factory.Hex(), "-key-file", key,
			"-core", s.apiURL, "-actor", "ops").CombinedOutput()
		return string(out), err
	}
	if out, err := guardian(strangerKey); err == nil || !strings.Contains(out, "would not be allowed to freeze") {
		t.Fatalf("a key that is not the guardian: err=%v\n%s", err, out)
	}
	feeBefore := s.posted(custody.FeeAccount(s.chainName, "ETH"))
	out, err := guardian(guardianKey)
	if err != nil || !strings.Contains(out, "FROZEN") || !strings.Contains(out, "gas booked against the fee account") {
		t.Fatalf("guardian freeze: %v\n%s", err, out)
	}
	if d := s.factoryAddr("destination"); d != (common.Address{}) {
		t.Fatalf("destination %s after the freeze", d)
	}
	if feeAfter := s.posted(custody.FeeAccount(s.chainName, "ETH")); feeAfter.Cmp(feeBefore) >= 0 {
		t.Fatalf("the guardian's gas was not booked against the fee account (%s -> %s)", feeBefore, feeAfter)
	}
	// Freezing again is a harmless no-op.
	if out, err := guardian(guardianKey); err != nil || !strings.Contains(out, "already frozen") {
		t.Fatalf("second freeze: %v\n%s", err, out)
	}

	// Frozen: a new deposit waits. The guardian cannot unfreeze: only the admin can.
	b := s.newCustomer("c-frz-2")
	s.sendETH(b, eth(1))
	s.waitAvailable("c-frz-2", "ETH", eth(1), 30*time.Second)
	n := s.sweepsConfirmed()
	s.holds(2*time.Second, "no sweep while frozen", func() bool { return s.sweepsConfirmed() == n && s.ethBalance(b).Cmp(eth(1)) == 0 })
	data, _ := s.factoryABI.Pack("setDestination", s.shardAddr[0])
	g := crypto.PubkeyToAddress(s.guardian.PublicKey)
	if _, err := s.ec.CallContract(s.ctx, ethereum.CallMsg{From: g, To: &s.factory, Data: data}, nil); err == nil {
		t.Fatal("the guardian could call setDestination")
	}

	// The ceremony unfreezes (set-destination), and the waiting deposit is swept.
	s.runAction(k, "unfreeze", "set-destination", s.shardAddr[0].Hex(), "", "confirmed")
	s.waitFor(90*time.Second, "the waiting deposit to be swept", func() bool { return s.ethBalance(b).Sign() == 0 })
	s.waitIdle(60 * time.Second)
	s.reconcileClean()
	s.requireAudit("guardian.freeze", "factory.frozen", "factory.unfrozen", "cold_action.requested")
}

func TestAdminRoleTransferTwoSteps(t *testing.T) {
	s := newSystem(t, adminOpts())
	k1 := s.cold
	s.fundETH(s.coldAddr, eth(5))
	if err := s.svc.FundCold(s.ctx, "gas-1", 0, "ETH", eth(5)); err != nil {
		t.Fatal(err)
	}
	// A second cold key, to take the role over.
	k2 := newColdKey(t, s, "cold2")
	k2.configure(s)
	s.fundETH(k2.addr, eth(1)) // gas for its own transactions (its address is not one the books track)
	newGuardian := crypto.PubkeyToAddress(s.admin.PublicKey)
	k1.cfg.NewAdmins = []string{k2.addr.Hex()}
	k1.cfg.NewGuardians = []string{newGuardian.Hex()}
	k1.write()

	// Step 1: nominate. Nothing changes yet.
	s.runAction(k1, "nominate", "transfer-admin", k2.addr.Hex(), "", "confirmed")
	if p, a := s.factoryAddr("pendingAdmin"), s.factoryAddr("admin"); p != k2.addr || a != k1.addr {
		t.Fatalf("after nominating: pending %s admin %s", p, a)
	}
	// The guardian can be rotated by the admin.
	s.runAction(k1, "guardian", "set-guardian", newGuardian.Hex(), "", "confirmed")
	if g := s.factoryAddr("guardian"); g != newGuardian {
		t.Fatalf("guardian %s", g)
	}
	// Step 2: the new admin accepts, signing from its own key (its own offline config).
	s.runAction(k2, "accept", "accept-admin", "", k2.addr.Hex(), "confirmed")
	if a, p := s.factoryAddr("admin"), s.factoryAddr("pendingAdmin"); a != k2.addr || p != (common.Address{}) {
		t.Fatalf("after accepting: admin %s pending %s", a, p)
	}
	// The old admin has lost its power: its ceremony still signs and broadcasts, but the factory reverts it.
	s.runAction(k1, "old-admin", "set-destination", s.shardAddr[0].Hex(), "", "failed")
	if d := s.factoryAddr("destination"); d != (common.Address{}) {
		t.Fatalf("the old admin changed the destination to %s", d)
	}
	// The new one can.
	s.runAction(k2, "new-admin", "set-destination", s.shardAddr[1].Hex(), k2.addr.Hex(), "confirmed")
	if d := s.factoryAddr("destination"); d != s.shardAddr[1] {
		t.Fatalf("destination %s", d)
	}
	s.reconcileClean() // the old admin's fees (including the reverted call) are in the books; the new admin's are operator expenses
}

// A parked request is closed by an operator through the API, not by editing the database; it stops blocking new requests.
func TestParkedRefillIsClosedByAnOperator(t *testing.T) {
	s := newSystem(t, refillOpts(""))
	s.fundedCold("cold-funding-1")
	id := s.openRefill()
	if code, _ := s.call("POST", "/v2/refills/"+id+"/close", map[string]string{"X-Actor": "ops"}, map[string]string{"reason": "no"}); code != 400 {
		t.Fatalf("closing a request that is not parked: %d", code)
	}
	if _, err := s.pool.Exec(s.ctx, `UPDATE refills SET failure_reason='parked: the nonce was used by another transaction' WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if code, _ := s.call("POST", "/v2/refills/"+id+"/close", map[string]string{"X-Actor": "ops"}, map[string]string{"reason": " "}); code != 400 {
		t.Fatalf("closing without a reason: %d", code)
	}
	if code, _ := s.call("POST", "/v2/refills/"+id+"/close", nil, map[string]string{"reason": "x"}); code != 401 {
		t.Fatalf("closing without an actor: %d", code)
	}
	code, out := s.call("POST", "/v2/refills/"+id+"/close", map[string]string{"X-Actor": "ops"}, map[string]string{"reason": "nonce was spent by the treasury; a new request will be made"})
	if code != 200 || out["status"] != "failed" || !strings.Contains(out["failure_reason"].(string), "closed by ops") {
		t.Fatalf("close: %d %v", code, out)
	}
	if code, _ := s.call("POST", "/v2/refills/"+id+"/close", map[string]string{"X-Actor": "ops"}, map[string]string{"reason": "again"}); code != 400 {
		t.Fatalf("closing a closed request: %d", code)
	}
	// The planner opens a fresh request, since the hot wallet is still low and nothing blocks the cold address any more.
	var next string
	s.waitFor(60*time.Second, "a new request", func() bool {
		_, o := s.call("GET", "/v2/refills", nil, nil)
		for _, r := range o["refills"].([]any) {
			m := r.(map[string]any)
			if m["status"] == "requested" && m["id"] != id {
				next = m["id"].(string)
				return true
			}
		}
		return false
	})
	_ = next
	_ = json.Marshal
	_ = coldsign.KindFreeze
	s.requireAudit("refill.closed")
	var by string
	if err := s.pool.QueryRow(s.ctx, `SELECT actor FROM audit_log WHERE type='refill.closed'`).Scan(&by); err != nil || by != "ops" {
		t.Fatalf("refill.closed actor = %q, %v", by, err)
	}
}
