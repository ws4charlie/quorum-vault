package gen

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"math/big"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// OpRecord is one operation of a run, as the client saw it.
type OpRecord struct {
	N        int              `json:"n"`
	Key      string           `json:"key"` // "deposit:ETH", "withdraw:auto", "withdraw:two"
	Step     int              `json:"step"`
	StartMS  int64            `json:"start_ms"` // scheduled arrival, ms since the start of the arrival phase
	LateMS   int64            `json:"late_ms,omitempty"`
	Stages   map[string]int64 `json:"stages_ms"` // stage -> ms since the scheduled arrival
	Err      string           `json:"err,omitempty"`
	ErrMsg   string           `json:"err_msg,omitempty"`
	ID       string           `json:"id,omitempty"`       // the withdrawal's id, or the deposit's customer
	Customer string           `json:"customer,omitempty"` // withdrawal: whose money
	WeiAsked string           `json:"wei,omitempty"`
	Dest     string           `json:"dest,omitempty"`
	End      string           `json:"end,omitempty"` // withdraw: the last status seen
	// SettledLate: the generator had given up (drain over) and the withdrawal ended afterwards, found by the settle step
	SettledLate bool `json:"settled_late,omitempty"`
}

type wcust struct {
	id string
	mu sync.Mutex
	// budget is what the generator may still ask this customer to withdraw (wei): funded amount minus what is asked and not yet settled, plus what failed
	budget *big.Int
	funded *big.Int
	spent  *big.Int // asked and confirmed
}

type dcust struct {
	id       string
	addr     common.Address
	credited *big.Int // sum of deposits seen credited
}

// createCustomer makes a customer and its deposit address on the chain.
func (r *Runner) createCustomer(ctx context.Context, id string) (common.Address, error) {
	if _, _, err := r.C.Call(ctx, r.T.Actors.Ops, "POST", "/v2/customers", nil, map[string]any{"id": id}); err != nil {
		return common.Address{}, err
	}
	_, out, err := r.C.Call(ctx, r.T.Actors.Ops, "POST", "/v2/customers/"+id+"/deposit-addresses", nil, map[string]any{"chain": r.T.EVM.Chain})
	if err != nil {
		return common.Address{}, err
	}
	a, _ := out["address"].(string)
	if a == "" {
		return common.Address{}, &Failure{"other", "no address in the answer"}
	}
	return common.HexToAddress(a), nil
}

func (r *Runner) available(ctx context.Context, customer, asset string) (*big.Int, *big.Int, error) {
	_, out, err := r.C.Call(ctx, r.T.Actors.Ops, "GET", "/v2/customers/"+customer+"/balances", nil, nil)
	if err != nil {
		return nil, nil, err
	}
	avail, held := new(big.Int), new(big.Int)
	bs, _ := out["balances"].([]any)
	for _, b := range bs {
		m, _ := b.(map[string]any)
		if m["asset"] == asset {
			avail.SetString(fmt.Sprint(m["available"]), 10)
			held.SetString(fmt.Sprint(m["held"]), 10)
		}
	}
	return avail, held, nil
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// doDeposit pays ETH to a customer's deposit address and waits until it is credited and the forwarder is swept (the address holds nothing).
func (r *Runner) doDeposit(ctx context.Context, rec *OpRecord, t0 time.Time, st Stream, rng *rand.Rand) error {
	var dc *dcust
	select {
	case dc = <-r.free:
	default:
		return &Failure{"no_free_address", "every deposit address has a deposit open: raise setup.deposit_customers"}
	}
	defer func() { r.free <- dc }()
	wei := ethToWei(st.AmountETH[0] + rng.Float64()*(st.AmountETH[1]-st.AmountETH[0]))
	rec.ID, rec.WeiAsked = dc.id, wei.String()
	want := new(big.Int).Add(dc.credited, wei)
	h, err := r.chain.sendTx(ctx, dc.addr, wei)
	if err != nil {
		return err
	}
	rec.Stages["sent"] = time.Since(t0).Milliseconds()
	credited, swept, sawFunds := false, false, false
	var lastAvail *big.Int
	reverted := false
	for {
		if !credited {
			a, _, err := r.available(ctx, dc.id, "ETH")
			if err != nil {
				return err
			}
			lastAvail = a
			if a.Cmp(want) >= 0 {
				credited = true
				rec.Stages["credited"] = time.Since(t0).Milliseconds()
				r.Obs.opStage(rec.Key, "credited", time.Since(t0))
				dc.credited = want
			}
		}
		if !swept {
			b, err := r.chain.balance(ctx, dc.addr)
			if err != nil {
				return err
			}
			// the address holds nothing before the deposit lands and after the sweep: swept counts only once the funds were seen or the deposit credited
			if b.Sign() != 0 {
				sawFunds = true
			}
			if b.Sign() == 0 && (sawFunds || credited) {
				swept = true
				rec.Stages["swept"] = time.Since(t0).Milliseconds()
				r.Obs.opStage(rec.Key, "swept", time.Since(t0))
			}
		}
		if credited && (swept || st.Until == "credited") {
			return nil
		}
		if !credited && !reverted && time.Since(t0) > 3*time.Second {
			reverted = true // look once: a transfer that the chain refused will never be credited
			if rc, err := r.chain.ec.TransactionReceipt(ctx, h); err == nil && rc.Status != 1 {
				return &Failure{"deposit_tx_reverted", "the payment to the deposit address reverted on the chain: " + r.chain.describe(h)}
			}
		}
		if !sleepCtx(ctx, 100*time.Millisecond) {
			onChain, _ := r.chain.balance(context.Background(), dc.addr)
			return &Failure{"timeout", fmt.Sprintf("deposit %s not final: credited=%v swept=%v; available %v, wanted %v, the address holds %v; %s", dc.id, credited, swept, lastAvail, want, onChain, r.chain.describe(h))}
		}
	}
}

func randAddr(rng *rand.Rand) common.Address {
	var a common.Address
	rng.Read(a[:])
	return a
}

// pickCustomer reserves wei of some customer's budget.
func (r *Runner) pickCustomer(rng *rand.Rand, wei *big.Int) *wcust {
	n := len(r.wcust)
	off := rng.Intn(n)
	for i := 0; i < n; i++ {
		c := r.wcust[(off+i)%n]
		c.mu.Lock()
		if c.budget.Cmp(wei) >= 0 {
			c.budget.Sub(c.budget, wei)
			c.mu.Unlock()
			return c
		}
		c.mu.Unlock()
	}
	return nil
}

// doWithdraw requests a withdrawal, approves it if the tier asks for people, and follows it to its end.
func (r *Runner) doWithdraw(ctx context.Context, rec *OpRecord, t0 time.Time, st Stream, rng *rand.Rand) error {
	wei := ethToWei(st.AmountETH[0] + rng.Float64()*(st.AmountETH[1]-st.AmountETH[0]))
	c := r.pickCustomer(rng, wei)
	if c == nil {
		return &Failure{"no_funds", "every withdrawing customer is out of budget: raise setup.fund_each_eth or the customers"}
	}
	dest := randAddr(rng)
	rec.WeiAsked, rec.Dest, rec.Customer = wei.String(), dest.Hex(), c.id
	settled := false
	defer func() {
		c.mu.Lock()
		if settled {
			c.spent.Add(c.spent, wei)
		} else {
			c.budget.Add(c.budget, wei) // not paid: the amount is the customer's again
		}
		c.mu.Unlock()
	}()
	code, out, err := r.C.Call(ctx, r.T.Actors.Initiator, "POST", "/v2/withdrawals", map[string]string{"Idempotency-Key": fmt.Sprintf("%s-w-%d", r.RunID, rec.N)},
		map[string]any{"customer": c.id, "asset": "ETH", "to": dest.Hex(), "amount": wei.String()})
	if err != nil {
		return err
	}
	_ = code
	id, _ := out["id"].(string)
	rec.ID = id
	rec.Stages["request"] = time.Since(t0).Milliseconds()
	r.Obs.opStage(rec.Key, "request", time.Since(t0))

	if st.Tier == "two" {
		if err := r.approve(ctx, id); err != nil {
			return err
		}
		rec.Stages["approvals"] = time.Since(t0).Milliseconds()
		r.Obs.opStage(rec.Key, "approvals", time.Since(t0))
	}
	order := map[string]int{"requested": 0, "approved": 1, "signing": 2, "broadcast": 3, "confirmed": 4}
	for {
		_, w, err := r.C.Call(ctx, r.T.Actors.Ops, "GET", "/v2/withdrawals/"+id, nil, nil)
		if err != nil {
			if kindOf(err) == "timeout" && ctx.Err() != nil {
				return &Failure{"drain_timeout", "not final at the end of the drain: " + rec.End}
			}
			return err
		}
		status, _ := w["status"].(string)
		rec.End = status
		if _, ok := order[status]; ok && status != "requested" {
			if _, seen := rec.Stages[status]; !seen {
				rec.Stages[status] = time.Since(t0).Milliseconds()
				r.Obs.opStage(rec.Key, status, time.Since(t0))
			}
		}
		switch status {
		case "confirmed":
			settled = true
			return nil
		case "failed":
			reason, _ := w["failure_reason"].(string)
			return &Failure{"withdrawal_failed", reason}
		}
		if !sleepCtx(ctx, 100*time.Millisecond) {
			return &Failure{"drain_timeout", "not final at the end of the drain: " + status}
		}
	}
}

// approve signs the withdrawal's intent hash with the approvers' keys, as the approval page or the CLI does, until enough have approved.
func (r *Runner) approve(ctx context.Context, id string) error {
	_, in, err := r.C.Call(ctx, r.T.Actors.Ops, "GET", "/v2/withdrawals/"+id+"/intent", nil, nil)
	if err != nil {
		return err
	}
	h, err := hex.DecodeString(fmt.Sprint(in["hash"]))
	if err != nil {
		return &Failure{"other", "intent hash: " + err.Error()}
	}
	need := 2
	if f, ok := in["approvals_required"].(float64); ok && int(f) > 0 {
		need = int(f)
	}
	for i := 0; i < need && i < len(r.T.Actors.Approvers); i++ {
		name := r.T.Actors.Approvers[i]
		key, ok := r.approvers[name]
		if !ok {
			return &Failure{"other", "no key for approver " + name}
		}
		sig := ed25519.Sign(key, h)
		if _, _, err := r.C.Call(ctx, name, "POST", "/v2/withdrawals/"+id+"/approvals", nil, map[string]any{"actor": name, "signature": hex.EncodeToString(sig)}); err != nil {
			return err
		}
	}
	return nil
}

func errKind(err error) (string, string) {
	if err == nil {
		return "", ""
	}
	return kindOf(err), strings.TrimSpace(err.Error())
}
