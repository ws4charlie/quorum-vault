package gateway

import (
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/chain/sol"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// A refused attempt can leave the guard's claim on one nonce account of the old pool with no signature (a cosigner refused after the gateway reserved). When
// the generation is then marked compromised it signs only drains. The drain's own step for that account is a withdrawal on a recent blockhash: it makes no
// claim, so the zone signs it although the account is claimed, and the account's lamports leave with the rest. (A cancel would be refused, which is why the
// core releases such an attempt for a compromised generation instead of asking for one.)
func TestSolCompromisedDrainTakesAClaimedNonceAccount(t *testing.T) {
	g := newSolGen(t)
	old, new2 := g.s.hot.k.Pub, g.hot2.k.Pub
	g.candidate2()
	// the attempt: admitted by the gateway, which claims nonce account 0 of the old pool for it
	g.sign(g.wdFrom("w1", old), g.s.hot)
	// the claim is there: another transaction at the same nonce account and value is refused as taken (the same blockhash, so the same nonce value)
	in2 := signjob.Intent{Kind: "withdrawal", RequestedBy: "req", ID: "w2", Asset: "SOL", PartitionID: solPartSOL, To: sol.Address(g.s.dest), Amount: "999", NotAfter: g.s.clock().Add(time.Hour).Unix()}
	g.refuse(g.job("j-w2", in2, g.msg(old, true, sol.TransferIx(old, g.s.dest, 999)), "alice"), "replay_nonce_taken")
	g.activate2Compromised(t)
	can, cm := g.s.cancelAt("cx", 1000, 0)
	g.refuse(g.s.job("cx1", can, cm, solPartSOL, sol.PathHot, nil), "compromised")
	// the drain's withdrawal of that very account is signed
	g.sign(g.job("dn0", g.drainIntent("dn0", "SOL", "1447680", new2), g.msg(old, false, sol.WithdrawNonceIx(sol.NonceAddress(old, 0), new2, old, 1_447_680))), g.s.hot)
}
