package custody

import (
	"context"
	"fmt"
	"math/big"
	"testing"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/chain/sol"
	"github.com/ws4charlie/quorum-vault/internal/coldsign"
)

// solWorld is a fake chain for the old cold address: SOL, one token account (maybe empty), and a pool of nonce accounts. apply plays a request's effects.
type solWorld struct {
	chain.Adapter // never called
	lamports      int64
	tokens        int64
	ata           bool
	nonces        []sol.ColdNonce
	version       int
}

const (
	testRent    = 1_447_680
	testATARent = 2_039_280
)

func (w *solWorld) ColdNonces(context.Context, string) ([]sol.ColdNonce, error) {
	return append([]sol.ColdNonce(nil), w.nonces...), nil
}
func (w *solWorld) ColdNonceValue(context.Context, string) (string, error) { return "", nil }
func (w *solWorld) ColdSetupState(context.Context, string) ([]int, []string, string, uint64, error) {
	return nil, nil, "", 0, nil
}
func (w *solWorld) SendRawTx(context.Context, []byte) (string, error) { return "", nil }
func (w *solWorld) TokenAccountMissing(_ context.Context, owner, _ string) (bool, error) {
	if owner == "new" {
		return false, nil
	}
	return !w.ata, nil
}
func (w *solWorld) AccountLamports(context.Context, string) (uint64, error) { return testRent, nil }
func (w *solWorld) ColdBlockhash(context.Context) (string, error)           { return "recentblockhash0000", nil }
func (w *solWorld) MintOf(string) (string, bool)                            { return "mint", true }
func (w *solWorld) SafeHead(context.Context) (uint64, error)                { return 0, nil }
func (w *solWorld) TxBlock(context.Context, string) (uint64, error)         { return 0, nil }
func (w *solWorld) Balance(_ context.Context, addr, asset string, _ uint64) (*big.Int, error) {
	if asset == "TKN" {
		return big.NewInt(w.tokens), nil
	}
	return big.NewInt(w.lamports), nil
}

func (w *solWorld) apply(t *testing.T, r coldsign.SOLRequest) {
	t.Helper()
	pay := func(n int64) {
		if w.lamports < n {
			t.Fatalf("%s %s: the old address holds %d lamports and cannot pay %d", r.Kind, r.ID, w.lamports, n)
		}
		w.lamports -= n
	}
	amt, ok := new(big.Int).SetString(r.Amount, 10)
	if !ok {
		amt = new(big.Int)
	}
	switch r.Kind {
	case coldsign.KindSOLColdMove:
		pay(solMoveFee)
		if r.Mint != "" {
			if amt.Int64() != w.tokens && amt.Sign() != 0 {
				t.Fatalf("a token move of %s with %d tokens held", amt, w.tokens)
			}
			w.tokens = 0
			if r.CloseSource {
				w.ata = false
				w.lamports += testATARent
			}
		} else {
			w.lamports -= amt.Int64() // paid out; the check below is the rent rule
		}
	case coldsign.KindSOLColdMoveClose:
		pay(solMoveFee)
		gone := map[int]bool{}
		for _, i := range r.NonceIndexes {
			gone[i] = true
		}
		var keep []sol.ColdNonce
		for _, n := range w.nonces {
			if !gone[n.Index] {
				keep = append(keep, n)
			}
		}
		w.nonces = keep
		if amt.Sign() > 0 {
			pay(amt.Int64())
		}
	}
	w.version++
	for i := range w.nonces {
		w.nonces[i].Value = fmt.Sprintf("nonce-value-%03d-%06d", w.nonces[i].Index, w.version)
	}
	// A system account may hold zero or at least the rent minimum, never between.
	if w.lamports != 0 && w.lamports < 890_880 {
		t.Fatalf("after %s the old address holds %d lamports: below the rent minimum", r.Kind, w.lamports)
	}
}

func newSolWorld(n int, tokens int64, ata bool) *solWorld {
	w := &solWorld{lamports: 30_000_000_000, tokens: tokens, ata: ata}
	for i := 0; i < n; i++ {
		w.nonces = append(w.nonces, sol.ColdNonce{Index: i, Account: fmt.Sprintf("nonce-%d", i), Value: fmt.Sprintf("nonce-value-%03d-000000", i)})
	}
	return w
}

func runSolReplacement(t *testing.T, w *solWorld) (steps []string) {
	t.Helper()
	cfg := &Config{Native: "SOL", AssetList: []string{"SOL", "TKN"}, Assets: map[string]Asset{"SOL": {Decimals: 9}, "TKN": {Decimals: 6}},
		ColdRetiring: map[string]string{"omnibus": "old"}}
	cfg.SOL.ColdAddresses = map[string]string{"omnibus": "new"}
	cfg.SOL.ComputeUnitLimit = 50_000
	s := &Service{Cfg: cfg, Chain: w, Reader: w}
	for i := 0; i < 30; i++ {
		rf, done, err := s.ExportColdMoveSOL(context.Background(), "omnibus")
		if err != nil {
			t.Fatal(err)
		}
		if done {
			return steps
		}
		steps = append(steps, fmt.Sprintf("%s:%s:%d", rf.Request.Kind, rf.Request.Amount, len(rf.Request.NonceIndexes)))
		w.apply(t, rf.Request)
	}
	t.Fatalf("the replacement did not end: %v", steps)
	return nil
}

// Up to 64 nonce accounts are closed eight to a request; the old address must be able to pay every request's fee and ends at zero, with the empty token
// account's rent recovered.
func TestSOLColdMoveEmptiesTheOldAddressForAnyNumberOfNonceAccounts(t *testing.T) {
	for _, n := range []int{1, 3, 8, 9, 17, 64} {
		for _, withATA := range []bool{false, true} {
			w := newSolWorld(n, 0, withATA) // an empty token account when withATA
			steps := runSolReplacement(t, w)
			if w.lamports != 0 || len(w.nonces) != 0 || w.ata {
				t.Errorf("%d nonce accounts, token account %v: ended with %d lamports, %d nonce accounts, token account %v (steps %v)", n, withATA, w.lamports, len(w.nonces), w.ata, steps)
			}
			closes := 0
			for _, s := range steps {
				if len(s) > 15 && s[:15] == "cold-move-close" {
					closes++
				}
			}
			if want := (n + 7) / 8; closes != want {
				t.Errorf("%d nonce accounts: %d close requests, want %d", n, closes, want)
			}
		}
	}
}

// A token account that holds tokens is emptied and closed; one that holds none is closed on its own; both return their rent to the old address first.
func TestSOLColdMoveClosesEmptyAndFullTokenAccounts(t *testing.T) {
	full := newSolWorld(3, 5_000, true)
	runSolReplacement(t, full)
	if full.tokens != 0 || full.ata || full.lamports != 0 {
		t.Fatalf("full token account: %+v", full)
	}
	empty := newSolWorld(3, 0, true)
	steps := runSolReplacement(t, empty)
	if len(steps) < 1 || steps[0] != "cold-move:0:0" {
		t.Fatalf("empty token account: steps %v, want a close first", steps)
	}
}
