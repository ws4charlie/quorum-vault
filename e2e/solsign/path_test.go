package solsign_test

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/chain/sol"
	st "github.com/ws4charlie/quorum-vault/internal/chain/sol/soltest"
	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

func (s *stack) ata(owner, mint [32]byte) [32]byte { return st.ATAOf(owner, mint) }

// fundHotTokens makes the hot shard's own token account and fills it (the test funder is the mint's authority).
func (s *stack) fundHotTokens(amount uint64) [32]byte {
	s.t.Helper()
	acct := s.ata(s.hotPub, s.mint.Pub)
	s.n.run(s.funder, nil, st.CreateATA(s.funder.Pub, acct, s.hotPub, s.mint.Pub), st.MintTo(s.mint.Pub, acct, s.funder.Pub, amount))
	return acct
}

// A SOL withdrawal from the hot shard, signed by the 2-of-3 keyset through A and B with both cosigners, lands on the validator. A second job for
// the same message returns the stored signature byte for byte.
func TestSOLWithdrawalFromTheHotShardLands(t *testing.T) {
	s := newStack(t, optsT{})
	dest := st.NewKey()
	const amount = 2_000_000
	in := s.intent("withdrawal", "w1", "SOL", partSOL, "", dest.Address(), amount)
	msg := s.msgFromHot(st.SetLimit(10_000), st.SetPrice(1000), st.Transfer(s.hotPub, dest.Pub, amount))
	sig := s.sign("j1", in, msg, sol.PathHot, nil)
	s.n.land(st.Assemble(msg, sig))
	if got := s.n.lamports(dest.Pub); got != amount {
		t.Fatalf("destination holds %d", got)
	}
	// the same message again, as another job: the stored signature, nothing signed
	before := s.mpc.A.CountLog(`"op":"sign"`)
	again := s.sign("j2", in, msg, sol.PathHot, nil)
	if !bytes.Equal(again, sig) {
		t.Fatal("a second job for the same message got another signature")
	}
	if after := s.mpc.A.CountLog(`"op":"sign"`); after != before {
		t.Fatalf("party A signed again (%d -> %d)", before, after)
	}
}

func TestSPLWithdrawalFromTheHotShardLands(t *testing.T) {
	s := newStack(t, optsT{})
	hotATA := s.fundHotTokens(10_000_000)
	dest := st.NewKey()
	const amount = 2_500_000
	in := s.intent("withdrawal", "w1", "TKN", partTKN, "", dest.Address(), amount)
	destATA := s.ata(dest.Pub, s.mint.Pub)
	msg := s.msgFromHot(st.SetLimit(80_000), st.CreateATA(s.hotPub, destATA, dest.Pub, s.mint.Pub), st.CheckedTransfer(hotATA, s.mint.Pub, destATA, s.hotPub, amount, 6))
	sig := s.sign("j1", in, msg, sol.PathHot, nil)
	s.n.land(st.Assemble(msg, sig))
	if got := s.n.tokens(dest.Pub, s.mint.Pub); got != amount {
		t.Fatalf("destination holds %d tokens", got)
	}
	if got := s.n.tokens(s.hotPub, s.mint.Pub); got != 10_000_000-amount {
		t.Fatalf("hot shard holds %d tokens", got)
	}
}

// With party A down the gateway signs through B (with C), one ALERT says so, and the transaction lands.
func TestWithdrawalWithPartyADownLands(t *testing.T) {
	s := newStack(t, optsT{})
	s.mpc.A.Kill()
	dest := st.NewKey()
	const amount = 1_500_000
	in := s.intent("withdrawal", "w1", "SOL", partSOL, "", dest.Address(), amount)
	msg := s.msgFromHot(st.SetLimit(10_000), st.Transfer(s.hotPub, dest.Pub, amount))
	sig := s.sign("j1", in, msg, sol.PathHot, nil)
	s.n.land(st.Assemble(msg, sig))
	if got := s.n.lamports(dest.Pub); got != amount {
		t.Fatalf("destination holds %d", got)
	}
	if !strings.Contains(s.gw.Output(), "ALERT mpc signer degraded") {
		t.Fatalf("no degraded ALERT in the gateway log:\n%s", tailOf(s.gw.Output()))
	}
	if n := strings.Count(s.gw.Output(), "ALERT mpc signer degraded"); n != 1 {
		t.Fatalf("%d degraded ALERTs", n)
	}
}

// A sweep needs two signatures over one message: the hot shard's (fee payer) and the deposit key's (owner). Both come through the gateway, the
// transaction lands, and the deposit address keeps exactly the rent-exempt minimum.
func TestSweepSignedByTheDepositKeyLands(t *testing.T) {
	s := newStack(t, optsT{})
	const idx = 5
	depNode, err := s.node.Derive(sol.BranchExternal, idx)
	if err != nil {
		t.Fatal(err)
	}
	dep := depNode.PublicKey
	s.n.run(s.funder, nil, st.Transfer(s.funder.Pub, dep, 1_000_000_000))
	rent := s.n.rent(0)
	amount := s.n.lamports(dep) - rent
	hotBefore := s.n.lamports(s.hotPub)
	di := uint32(idx)
	in := s.intent("sweep", "s1", "SOL", partSOL, sol.Address(dep), sol.Address(s.hotPub), amount)
	msg := s.msgFromHot(st.SetLimit(10_000), st.Transfer(dep, s.hotPub, amount))
	hotSig := s.sign("s1-hot", in, msg, sol.PathHot, &di)
	depSig := s.sign("s1-dep", in, msg, sol.DepositPath(idx), &di)
	s.n.land(st.Assemble(msg, hotSig, depSig))
	if got := s.n.lamports(dep); got != rent {
		t.Fatalf("the deposit address holds %d, want the rent-exempt minimum %d", got, rent)
	}
	if got := s.n.lamports(s.hotPub); got != hotBefore+amount-2*5000 {
		t.Fatalf("hot shard holds %d, want %d", got, hotBefore+amount-2*5000)
	}
}

// A token sweep with the deposit token account closed afterwards and its rent going to the hot shard.
func TestTokenSweepWithCloseLands(t *testing.T) {
	s := newStack(t, optsT{})
	hotATA := s.fundHotTokens(1_000)
	const idx = 9
	depNode, _ := s.node.Derive(sol.BranchExternal, idx)
	dep := depNode.PublicKey
	depATA := s.ata(dep, s.mint.Pub)
	funderATA := s.ata(s.funder.Pub, s.mint.Pub)
	s.n.run(s.funder, nil, st.CreateATA(s.funder.Pub, funderATA, s.funder.Pub, s.mint.Pub), st.MintTo(s.mint.Pub, funderATA, s.funder.Pub, 50_000),
		st.CreateATA(s.funder.Pub, depATA, dep, s.mint.Pub), st.CheckedTransfer(funderATA, s.mint.Pub, depATA, s.funder.Pub, 7_000, 6))
	di := uint32(idx)
	in := s.intent("sweep", "s2", "TKN", partTKN, sol.Address(dep), sol.Address(s.hotPub), 7_000)
	msg := s.msgFromHot(st.SetLimit(80_000), st.CheckedTransfer(depATA, s.mint.Pub, hotATA, dep, 7_000, 6), st.CloseAccount(depATA, s.hotPub, dep))
	hotSig := s.sign("s2-hot", in, msg, sol.PathHot, &di)
	depSig := s.sign("s2-dep", in, msg, sol.DepositPath(idx), &di)
	s.n.land(st.Assemble(msg, hotSig, depSig))
	if got := s.n.tokens(s.hotPub, s.mint.Pub); got != 1_000+7_000 {
		t.Fatalf("hot shard holds %d tokens", got)
	}
	if got := s.n.lamports(depATA); got != 0 {
		t.Fatalf("the deposit token account still holds %d lamports", got)
	}
}

// A rogue gateway (holding the gateway's certificate) asks party A to sign things the approved intent does not cover. Party B's cosigner
// refuses before any signing message; with A down, party C's refuses the same asks through B.
func TestRoguePayloadsAreRefusedByTheCosigners(t *testing.T) {
	s := newStack(t, optsT{})
	dest, evil := st.NewKey(), st.NewKey()
	const amount = 2_000_000
	in := s.intent("withdrawal", "w-rogue", "SOL", partSOL, "", dest.Address(), amount)
	good := s.msgFromHot(st.SetLimit(10_000), st.Transfer(s.hotPub, dest.Pub, amount))
	bad := s.msgFromHot(st.SetLimit(10_000), st.Transfer(s.hotPub, evil.Pub, amount))
	other := s.msgFromHot(st.SetLimit(10_000), st.Transfer(s.hotPub, dest.Pub, amount*100))
	pkgFor := func(id string, msg []byte, in2 interface{}) []byte { return nil }
	_ = pkgFor
	type ask struct {
		name string
		msg  []byte // the message the gateway asks to be signed
		pkg  []byte // the intent package it sends along
	}
	jobPkg := func(id string, msg []byte) []byte {
		j := s.job(id, in, msg, sol.PathHot, nil)
		b, err := encodePackage(j)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	asks := []ask{
		{"the message pays someone else, the package says so honestly", bad, jobPkg("r1", bad)},
		{"the message pays someone else, the package shows the good one", bad, jobPkg("r2", good)},
		{"ten times the amount", other, jobPkg("r3", other)},
	}
	try := func(via, label string) {
		for _, a := range asks {
			id := a.name + "|" + label
			_ = id
			x, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			resp, err := s.mpc.Client(via).Sign(x, &pb.SignRequest{KeyId: "sol-hot", Algorithm: pb.Algorithm_ALGORITHM_ED25519, Digest: a.msg,
				JobId: "rogue-" + label + "-" + a.name[:6], IntentPackage: a.pkg})
			cancel()
			if err == nil {
				t.Fatalf("%s via %s: a signature of %d bytes came back", a.name, via, len(resp.Signature))
			}
			if !strings.Contains(err.Error(), "refused") {
				t.Fatalf("%s via %s: not a refusal: %v", a.name, via, err)
			}
		}
	}
	try("A", "via-a")
	s.mpc.A.Kill()
	try("B", "via-b")
	// and the honest job still signs afterwards (the refusals froze nothing)
	sig := s.sign("honest", in, good, sol.PathHot, nil)
	s.n.land(st.Assemble(good, sig))
	if got := s.n.lamports(dest.Pub); got != amount {
		t.Fatalf("destination holds %d", got)
	}
	if got := s.n.lamports(evil.Pub); got != 0 {
		t.Fatalf("the attacker's account holds %d", got)
	}
}

// The gateway refuses what the policy does not allow, before any party is asked.
func TestGatewayRefusesBeforeAskingTheParties(t *testing.T) {
	s := newStack(t, optsT{})
	dest := st.NewKey()
	in := s.intent("withdrawal", "w1", "SOL", partSOL, "", dest.Address(), 2_000_000)
	before := s.mpc.A.CountLog(`"op":"sign"`)
	bad := s.msgFromHot(st.SetLimit(10_000), st.SetPrice(100_001), st.Transfer(s.hotPub, dest.Pub, 2_000_000))
	if why := s.refused("g1", in, bad, sol.PathHot, nil); !contains(why, "tx_mismatch") {
		t.Fatalf("reason %q", why)
	}
	// a v0 message
	v0 := append([]byte{0x80}, s.msgFromHot(st.SetLimit(10_000), st.Transfer(s.hotPub, dest.Pub, 2_000_000))...)
	if why := s.refused("g2", in, v0, sol.PathHot, nil); !contains(why, "tx_mismatch") {
		t.Fatalf("reason %q", why)
	}
	if after := s.mpc.A.CountLog(`"op":"sign"`); after != before {
		t.Fatalf("party A was asked to sign a refused job (%d -> %d)", before, after)
	}
}

// ---- the second-signature case ----

// cb-mpc's Ed25519 is randomized: two signatures over one message are two different valid signatures. If a job were signed through A and again
// through B, the network could in principle see two transactions with one message. It does not run both: Agave's duplicate check keys the
// status cache on the MESSAGE hash (runtime/src/bank/check_transactions.rs, is_transaction_already_processed: `sanitized_tx.message_hash()`),
// not on the signature. This test makes two valid signatures of one message with a randomized signer and sends both, one after the other and
// at the same time, and requires that the payment happens once.
func TestSecondSignatureOfOneMessageDoesNotLand(t *testing.T) {
	requireSOL(t)
	n := &node{t: t, rpc: sol.NewRPC(nodeURL())}
	payer := st.NewKey()
	n.airdrop(payer.Pub, 20*1_000_000_000)

	// one after the other
	dest := st.NewKey()
	msg := st.Compile(payer.Pub, n.blockhash(), st.SetLimit(10_000), st.Transfer(payer.Pub, dest.Pub, 3_000_000))
	s1, s2 := payer.Sign(msg), payer.Sign(msg)
	if bytes.Equal(s1, s2) {
		t.Fatal("the randomized signer gave the same signature twice")
	}
	sig1, err := n.sendRaw(st.Assemble(msg, s1), false)
	if err != nil {
		t.Fatal(err)
	}
	if e := n.wait(sig1, "finalized"); e != nil {
		t.Fatalf("the first transaction failed: %v", e)
	}
	_, err = n.sendRaw(st.Assemble(msg, s2), false)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "already been processed") && !strings.Contains(err.Error(), "AlreadyProcessed") {
		t.Fatalf("the second signature of an executed message: %v", err)
	}
	t.Logf("second signature of an executed message: %v", err)
	// even sent without the node's own pre-check, it cannot execute
	if sigB, err := n.sendRaw(st.Assemble(msg, s2), true); err == nil {
		time.Sleep(3 * time.Second)
		var out struct {
			Value []*struct {
				Err any `json:"err"`
			} `json:"value"`
		}
		n.rpc.Call(context.Background(), &out, "getSignatureStatuses", []string{sigB}, map[string]bool{"searchTransactionHistory": true})
		if len(out.Value) == 1 && out.Value[0] != nil && out.Value[0].Err == nil {
			t.Fatal("the second signature of an executed message was executed")
		}
	}
	if got := n.lamports(dest.Pub); got != 3_000_000 {
		t.Fatalf("destination holds %d after two signatures of one message", got)
	}

	// at the same time, several times: whichever lands, the payment happens once
	for round := 0; round < 4; round++ {
		d := st.NewKey()
		m := st.Compile(payer.Pub, n.blockhash(), st.SetLimit(10_000), st.Transfer(payer.Pub, d.Pub, 2_000_000))
		a, b := payer.Sign(m), payer.Sign(m)
		var wg sync.WaitGroup
		var sigs [2]string
		for i, sg := range [][]byte{a, b} {
			wg.Add(1)
			go func(i int, sg []byte) {
				defer wg.Done()
				sigs[i], _ = n.sendRaw(st.Assemble(m, sg), true)
			}(i, sg)
		}
		wg.Wait()
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) && n.lamports(d.Pub) == 0 {
			time.Sleep(200 * time.Millisecond)
		}
		time.Sleep(3 * time.Second) // time for a second execution, if one were possible
		t.Logf("round %d: two signatures sent at once (%.8s, %.8s): the destination holds %d", round, sigs[0], sigs[1], n.lamports(d.Pub))
		if got := n.lamports(d.Pub); got != 2_000_000 {
			t.Fatalf("round %d: destination holds %d after two simultaneous signatures of one message", round, got)
		}
	}
}
