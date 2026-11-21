package sole2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/chain/sol"
	"github.com/ws4charlie/quorum-vault/internal/gateway"
)

// A replacement of a Solana hot shard's key (K4) driven by qv-rekey on the real binaries: a second 2-of-3 Ed25519 keyset on the three parties, operator-signed
// records in the gateway's and both cosigners' guard databases, a withdrawal in flight on the old key's nonce while the key is replaced, the drain of tokens,
// SOL and the old nonce pool into the new key, and the retirement. (Not run on a machine whose local validator does not finalize slots; CI runs it.)

func (s *wdSys) hotShardID() string { return "qv-us/" + s.chain + "/omnibus/0" }

// hotChange is a change of the hot shard signed by two operators with qv-keysets.
func (s *wdSys) hotChange(ops map[string]ed25519.PrivateKey, name string, seq int, args ...string) string {
	s.t.Helper()
	bin := filepath.Join(binDir, "qv-keysets")
	f := filepath.Join(s.dir, "hot-"+name+".json")
	run := func(a ...string) {
		s.t.Helper()
		if out, err := exec.Command(bin, a...).CombinedOutput(); err != nil {
			s.t.Fatalf("qv-keysets %v: %v\n%s", a, err, out)
		}
	}
	run(append([]string{"sign", "-seq", fmt.Sprint(seq), "-shard", s.hotShardID(), "-operator", "op1", "-key", s.opKey("op1", ops["op1"]), "-out", f}, args...)...)
	run("sign", "-operator", "op2", "-key", s.opKey("op2", ops["op2"]), "-join", f, "-out", f)
	return f
}

func (s *wdSys) hotStates() map[int]string {
	rows, err := s.pool.Query(s.ctx, `SELECT generation, state FROM keysets WHERE shard_id=$1`, s.hotShardID())
	if err != nil {
		s.t.Fatal(err)
	}
	defer rows.Close()
	out := map[int]string{}
	for rows.Next() {
		var g int
		var st string
		if err := rows.Scan(&g, &st); err != nil {
			s.t.Fatal(err)
		}
		out[g] = st
	}
	return out
}

func (s *wdSys) drainState(gen int) (state, reason string) {
	_ = s.pool.QueryRow(context.Background(), `SELECT state, reason FROM keyset_drains WHERE shard_id=$1 AND generation=$2`, s.hotShardID(), gen).Scan(&state, &reason)
	return state, reason
}

func (s *wdSys) payersOfJobs() map[string]int {
	rows, err := s.pool.Query(s.ctx, `SELECT payload FROM sign_jobs WHERE chain=$1 AND status='done' AND key_ref=''`, s.chain)
	if err != nil {
		s.t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var p []byte
		if err := rows.Scan(&p); err != nil {
			s.t.Fatal(err)
		}
		var pl sol.Payload
		if json.Unmarshal(p, &pl) != nil {
			continue
		}
		if m, err := sol.DecodeMessage(pl.Message); err == nil {
			out[sol.Address(m.Keys[0])]++
		}
	}
	return out
}

func TestSwFlowsHotKeyReplacementDrivenByTheTool(t *testing.T) {
	ops := map[string]ed25519.PrivateKey{}
	s := newWdSystem(t, wdOpts{pool: 3, minSweep: "5000000", batch: 3, gwTweak: func(gf *gateway.File) {
		gf.Operators = &gateway.OperatorsFile{Keys: map[string]gateway.OperatorFile{}, MinOperators: 2}
		for _, n := range []string{"op1", "op2", "op3"} {
			pub, priv, _ := ed25519.GenerateKey(rand.Reader)
			ops[n] = priv
			gf.Operators.Keys[n] = gateway.OperatorFile{PublicKey: hex.EncodeToString(pub)}
		}
		for name, cc := range gf.Chains {
			n := 50
			cc.DrainsPerHour = &n
			gf.Chains[name] = cc
		}
	}})
	oldHot := s.hotAddr()
	oldATA := sol.Address(s.hotATA)

	// customers with money, swept into the old key
	s.deposit("k4-a", 30*oneSOL, 5_000*tknUnit)
	s.waitDeposits("k4-a", 30*oneSOL, 5_000*tknUnit)
	addrA, _ := s.depositAddressOf("k4-a")["address"].(string)
	s.waitSwept("the deposits swept into the old key", "SOL", addrA)
	s.reconcileClean("before the replacement")
	tokensBefore := s.tokensOf(oldHot)
	if tokensBefore == 0 {
		t.Fatal("the old key holds no tokens")
	}

	// a withdrawal is broadcast on a nonce of the OLD pool and held back: it is in flight while the key is replaced
	s.proxy.hold.Store(true)
	dest1 := s.freshAddr()
	w1 := s.request("initiator", "k4-w1", "k4-a", "SOL", dest1, 3*oneSOL)
	if w1.Code != 201 {
		t.Fatalf("%d %v", w1.Code, w1.Raw)
	}
	s.approve("alice", w1.ID)
	s.waitFor(60*time.Second, "the withdrawal to be broadcast", func() bool { return s.proxy.heldCount() > 0 })

	// open, DKG of the new 2-of-3 Ed25519 keyset on A, B and C, candidate, draining, activate
	dir := filepath.Join(s.dir, "rekey")
	s.rekeyMust(dir, "open", "-shard", s.hotShardID(), "-mode", "mpc", "-reason", "e2e")
	keyset := strings.Trim(slugSol.ReplaceAllString(strings.ToLower(s.hotShardID()), "-"), "-") + "-g2"
	s.rekeyMust(dir, "dkg", "-admin-auth", s.partyAuthHotFor(keyset))
	var plan struct {
		KeyRef    string `json:"key_ref"`
		PublicKey string `json:"public_key"`
		Address   string `json:"address"`
	}
	b, err := os.ReadFile(filepath.Join(dir, "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &plan); err != nil || plan.KeyRef != keyset || len(plan.PublicKey) != 64 || plan.Address == "" || plan.Address == oldHot {
		t.Fatalf("plan %+v (%v)", plan, err)
	}
	newHot := plan.Address
	s.rekeyMust(dir, "candidate", "-change", s.hotChange(ops, "cand", 1, "-action", "register-candidate", "-generation", "2", "-address", plan.Address, "-key-ref", plan.KeyRef, "-public-key", plan.PublicKey))
	caps := []string{"-cap", "SOL=1000000000000", "-cap", "TKN=100000000000000"}
	s.rekeyMust(dir, append([]string{"drain-start", "-change", s.hotChange(ops, "drain", 2, append([]string{"-action", "start-draining", "-generation", "1", "-successor", "2"}, caps...)...)}, caps...)...)
	s.rekeyMust(dir, "activate", "-change", s.hotChange(ops, "act", 3, "-action", "activate", "-generation", "2"))
	if st := s.hotStates(); st[1] != "draining" || st[2] != "active" {
		t.Fatalf("keysets %v", st)
	}

	// the zone refuses an ordinary withdrawal signed for the old generation (and the new key has no pool and no money yet, so nothing goes out from it)
	to := newKey(t).pub
	s.mustRefuse("k4-old-wd", s.wdIntent("k4-old-wd", to, 1000), s.wdMsg(0, [32]byte{9}, 1000, startUnit, to, 1000), "keyset_state", "alice")

	// the in-flight withdrawal lands once, from the old key: release what was held back
	s.proxy.hold.Store(false)
	for _, raw := range s.proxy.takeHeld() {
		s.sendDirect(raw)
	}
	s.waitWd(w1.ID, "confirmed", 120*time.Second)
	if got := s.lamports(dest1); got != 3*oneSOL {
		t.Fatalf("the destination holds %d, want exactly %d (one withdrawal, landed once)", got, 3*oneSOL)
	}
	if al := s.allocs(w1.ID); len(al) != 1 || al[0].Status != "confirmed" {
		t.Fatalf("allocations %+v", al)
	}
	s.reconcileClean("the in-flight withdrawal landed, the old key is draining")

	// the drain moves the tokens and the SOL the new key needs for its pool, then waits for the pool
	s.waitFor(3*time.Minute, "the drain to wait for the new key's nonce pool", func() bool {
		st, why := s.drainState(1)
		return st == "waiting" && strings.Contains(why, "nonce pool")
	})
	if got := s.tokensOf(newHot); got != tokensBefore {
		t.Fatalf("the new key holds %d tokens, the old one held %d", got, tokensBefore)
	}
	if _, err := s.c.rpc.GetAccount(s.ctx, oldATA, sol.Finalized); err == nil {
		t.Fatal("the old key's token account is still open")
	}
	s.reconcileClean("tokens drained, the pool is next")
	// crash safety: the worker dies in the middle of the drain, and the tool is run again at steps already done (each is skipped)
	s.restartWorker()
	s.rekeyMust(dir, "activate", "-change", s.hotChange(ops, "act", 3, "-action", "activate", "-generation", "2"))
	s.rekeyMust(dir, "status")

	// a new withdrawal waits (no pool); the operator creates the new key's pool; it goes out from the new key
	dest2 := s.freshAddr()
	w2 := s.request("initiator", "k4-w2", "k4-a", "SOL", dest2, 2*oneSOL)
	s.approve("alice", w2.ID)
	s.holds(3*time.Second, "a withdrawal waits while the new key has no pool", func() bool { return s.wdGet(w2.ID).Status != "confirmed" })
	if out, err := s.nonceTool(t); err != nil {
		t.Fatalf("qv-sol-nonces: %v\n%s", err, out)
	}
	s.waitWd(w2.ID, "confirmed", 120*time.Second)
	if got := s.lamports(dest2); got != 2*oneSOL {
		t.Fatalf("the destination holds %d, want %d", got, 2*oneSOL)
	}

	// the drain finishes: the old pool, then the last lamports: the old address ends at zero
	s.waitFor(4*time.Minute, "the old generation to be drained", func() bool { st, _ := s.drainState(1); return st == "drained" })
	if got := s.lamports(oldHot); got != 0 {
		t.Fatalf("the old address holds %d lamports", got)
	}
	for i := 0; i < 3; i++ {
		if s.nonceExists(i) {
			t.Fatalf("pool account %d of the old key is still open", i)
		}
	}
	s.reconcileClean("the old generation is drained")

	// retire
	s.rekeyMust(dir, "retire", "-change", s.hotChange(ops, "ret", 4, "-action", "retire", "-generation", "1"))
	if st := s.hotStates(); st[1] != "retired" || st[2] != "active" {
		t.Fatalf("keysets %v", st)
	}
	s.reconcileClean("after the retirement")

	// new work comes from the new key: a token withdrawal, and a deposit swept into the new address
	dest3 := s.freshAddr()
	w3 := s.request("initiator", "k4-w3", "k4-a", "TKN", dest3, 100*tknUnit)
	s.approve("alice", w3.ID)
	s.waitWd(w3.ID, "confirmed", 120*time.Second)
	if got := s.tokensOf(dest3); got != 100*tknUnit {
		t.Fatalf("the destination holds %d tokens", got)
	}
	s.deposit("k4-b", 4*oneSOL, 0)
	s.waitDeposits("k4-b", 4*oneSOL, 0)
	addrB, _ := s.depositAddressOf("k4-b")["address"].(string)
	s.waitSwept("a deposit swept into the new key", "SOL", addrB)
	hot2 := s.lamports(newHot)
	if hot2 == 0 {
		t.Fatal("the new key holds nothing")
	}
	// every transaction signed after the activation was paid by the new key, except what the old key signed to finish its own work and to drain
	payers := s.payersOfJobs()
	if payers[newHot] == 0 || payers[oldHot] == 0 {
		t.Fatalf("payers of the jobs signed: %v", payers)
	}
	s.mustRefuse("k4-retired-wd", s.wdIntent("k4-retired-wd", to, 1000), s.wdMsg(0, [32]byte{9}, 1000, startUnit, to, 1000), "keyset_state", "alice")
	s.reconcileClean("at the end")
}

// A token account of the old key that is empty is closed like the others (a move with no amount): the drain goes on to the nonce accounts and the last SOL.
func TestSwFlowsHotKeyReplacementWithAnEmptyTokenAccount(t *testing.T) {
	ops := map[string]ed25519.PrivateKey{}
	s := newWdSystem(t, wdOpts{pool: 3, seedTKN: []uint64{0}, gwTweak: func(gf *gateway.File) {
		gf.Operators = &gateway.OperatorsFile{Keys: map[string]gateway.OperatorFile{}, MinOperators: 2}
		for _, n := range []string{"op1", "op2", "op3"} {
			pub, priv, _ := ed25519.GenerateKey(rand.Reader)
			ops[n] = priv
			gf.Operators.Keys[n] = gateway.OperatorFile{PublicKey: hex.EncodeToString(pub)}
		}
		for name, cc := range gf.Chains {
			n := 50
			cc.DrainsPerHour = &n
			gf.Chains[name] = cc
		}
	}})
	oldHot, oldATA := s.hotAddr(), sol.Address(s.hotATA)
	if _, err := s.c.rpc.GetAccount(s.ctx, oldATA, sol.Finalized); err != nil || s.tokensOf(oldHot) != 0 {
		t.Fatalf("the old key should hold an empty token account: %v, %d tokens", err, s.tokensOf(oldHot))
	}
	dir := filepath.Join(s.dir, "rekey")
	s.rekeyMust(dir, "open", "-shard", s.hotShardID(), "-mode", "mpc", "-reason", "e2e")
	keyset := strings.Trim(slugSol.ReplaceAllString(strings.ToLower(s.hotShardID()), "-"), "-") + "-g2"
	s.rekeyMust(dir, "dkg", "-admin-auth", s.partyAuthHotFor(keyset))
	var plan struct {
		KeyRef, PublicKey, Address string
	}
	b, err := os.ReadFile(filepath.Join(dir, "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	plan.KeyRef, _ = raw["key_ref"].(string)
	plan.PublicKey, _ = raw["public_key"].(string)
	plan.Address, _ = raw["address"].(string)
	s.rekeyMust(dir, "candidate", "-change", s.hotChange(ops, "cand", 1, "-action", "register-candidate", "-generation", "2", "-address", plan.Address, "-key-ref", plan.KeyRef, "-public-key", plan.PublicKey))
	caps := []string{"-cap", "SOL=1000000000000", "-cap", "TKN=100000000000000"}
	s.rekeyMust(dir, append([]string{"drain-start", "-change", s.hotChange(ops, "drain", 2, append([]string{"-action", "start-draining", "-generation", "1", "-successor", "2"}, caps...)...)}, caps...)...)
	s.rekeyMust(dir, "activate", "-change", s.hotChange(ops, "act", 3, "-action", "activate", "-generation", "2"))
	// the empty account is closed (not stuck on), then the drain waits for the new key's pool
	s.waitFor(3*time.Minute, "the drain to wait for the new key's nonce pool", func() bool {
		st, why := s.drainState(1)
		return st == "waiting" && strings.Contains(why, "nonce pool")
	})
	if _, err := s.c.rpc.GetAccount(s.ctx, oldATA, sol.Finalized); err == nil {
		t.Fatal("the empty token account of the old key is still open")
	}
	if out, err := s.nonceTool(t); err != nil {
		t.Fatalf("qv-sol-nonces: %v\n%s", err, out)
	}
	s.waitFor(4*time.Minute, "the old generation to be drained", func() bool { st, _ := s.drainState(1); return st == "drained" })
	if got := s.lamports(oldHot); got != 0 {
		t.Fatalf("the old address holds %d lamports", got)
	}
	s.reconcileClean("after draining an empty token account")
}

// The emergency (K8): the old key is marked compromised. It signs only its drain to the successor, the drain waits for nothing an operator does (the new
// pool is created afterwards), and the key is never retired.
func TestSwFlowsHotKeyCompromisedDrainsWithoutWaitingForThePool(t *testing.T) {
	ops := map[string]ed25519.PrivateKey{}
	s := newWdSystem(t, wdOpts{pool: 3, gwTweak: func(gf *gateway.File) {
		gf.Operators = &gateway.OperatorsFile{Keys: map[string]gateway.OperatorFile{}, MinOperators: 2}
		for _, n := range []string{"op1", "op2", "op3"} {
			pub, priv, _ := ed25519.GenerateKey(rand.Reader)
			ops[n] = priv
			gf.Operators.Keys[n] = gateway.OperatorFile{PublicKey: hex.EncodeToString(pub)}
		}
	}})
	oldHot := s.hotAddr()
	tokensBefore := s.tokensOf(oldHot)
	if tokensBefore == 0 || s.lamports(oldHot) == 0 {
		t.Fatal("the old key holds nothing")
	}
	dir := filepath.Join(s.dir, "rekey")
	s.rekeyMust(dir, "open", "-shard", s.hotShardID(), "-mode", "mpc", "-reason", "the hot key may be stolen (e2e)")
	keyset := strings.Trim(slugSol.ReplaceAllString(strings.ToLower(s.hotShardID()), "-"), "-") + "-g2"
	s.rekeyMust(dir, "dkg", "-admin-auth", s.partyAuthHotFor(keyset))
	b, err := os.ReadFile(filepath.Join(dir, "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	keyRef, _ := raw["key_ref"].(string)
	pub, _ := raw["public_key"].(string)
	newHot, _ := raw["address"].(string)
	s.rekeyMust(dir, "candidate", "-change", s.hotChange(ops, "cand", 1, "-action", "register-candidate", "-generation", "2", "-address", newHot, "-key-ref", keyRef, "-public-key", pub))
	caps := []string{"-cap", "SOL=1000000000000", "-cap", "TKN=100000000000000"}
	s.rekeyMust(dir, append([]string{"drain-start", "-compromised", "-change", s.hotChange(ops, "mark", 2, append([]string{"-action", "mark-compromised", "-generation", "1", "-successor", "2"}, caps...)...)}, caps...)...)
	// the zone: a compromised key signs no ordinary withdrawal
	to := newKey(t).pub
	s.mustRefuse("k4-c-wd", s.wdIntent("k4-c-wd", to, 1000), s.wdMsg(0, [32]byte{9}, 1000, startUnit, to, 1000), "keyset_state", "alice")
	s.rekeyMust(dir, "activate", "-change", s.hotChange(ops, "act", 3, "-action", "activate", "-generation", "2"))

	// the drain does not wait for the new pool: the old address ends at zero with no pool created for the new key
	var lastSt, lastWhy string
	t.Cleanup(func() { t.Logf("drain state %q: %s", lastSt, lastWhy) })
	s.waitFor(4*time.Minute, "the compromised generation to be drained", func() bool { lastSt, lastWhy = s.drainState(1); return lastSt == "drained" })
	if got := s.lamports(oldHot); got != 0 {
		t.Fatalf("the old address holds %d lamports", got)
	}
	if got := s.tokensOf(newHot); got != tokensBefore {
		t.Fatalf("the new key holds %d tokens, the old one held %d", got, tokensBefore)
	}
	for i := 0; i < 3; i++ {
		if s.nonceExists(i) {
			t.Fatalf("pool account %d of the old key is still open", i)
		}
	}
	s.reconcileClean("the compromised generation is drained")
	// never retired
	if o, err := s.rekeyTool(dir, "retire", "-change", s.hotChange(ops, "ret", 4, "-action", "retire", "-generation", "1")); err == nil {
		t.Fatalf("retire of a compromised generation was accepted:\n%s", o)
	}
	// the new key takes over once its pool exists
	if out, err := s.nonceTool(t); err != nil {
		t.Fatalf("qv-sol-nonces: %v\n%s", err, out)
	}
	s.reconcileClean("the new key has its pool")
}
