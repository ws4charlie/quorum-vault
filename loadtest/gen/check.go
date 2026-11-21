package gen

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// CheckResult is one correctness check after the load. A run that is fast and wrong has failed.
type CheckResult struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Warn   bool   `json:"warn,omitempty"` // reported, does not fail the run
	Detail string `json:"detail,omitempty"`
}

func (r *Runner) addCheck(name string, ok bool, format string, a ...any) {
	r.checks = append(r.checks, CheckResult{Name: name, OK: ok, Detail: fmt.Sprintf(format, a...)})
	r.logf("check %-28s %v %s", name, map[bool]string{true: "ok", false: "FAILED"}[ok], fmt.Sprintf(format, a...))
}

// runChecks makes the checks. The books are read through the API and the chain, so the same checks run against a cluster. (The stack's own test adds the
// ones that need the database: outbox, sign jobs, holds in the ledger.)
func (r *Runner) runChecks(ctx context.Context) {
	// Operations the generator gave up on may still settle: give them time (settle_s), then judge each by the state it reached.
	open := r.settleOpen(ctx, time.Duration(r.S.SettleS*float64(time.Second)))
	if open == 0 {
		r.addCheck("backlog_drained", true, "every withdrawal ended (settle time allowed: %.0f s)", r.S.SettleS)
	} else {
		r.addCheck("backlog_drained", false, "%d withdrawals still open after the settle time of %.0f s: the run did not drain (their holds and unpaid destinations are judged as open work below)", open, r.S.SettleS)
	}
	r.checks[len(r.checks)-1].Warn = true

	// 0. what was paid to whom, from the generator's own record of its payments and the chain's receipts, independent of anything the books say
	credits := r.verifyPayments(ctx)

	// 1. every withdrawal paid exactly once (the destination holds the amount) or not at all (it holds nothing), by the state it reached
	type cust struct{ paid, returned, open, unknown *big.Int }
	byCust := map[string]*cust{}
	get := func(id string) *cust {
		c := byCust[id]
		if c == nil {
			c = &cust{new(big.Int), new(big.Int), new(big.Int), new(big.Int)}
			byCust[id] = c
		}
		return c
	}
	bad, paid, unpaid, openN, unknown, unreadable := 0, 0, 0, 0, 0, 0
	var examples []string
	for _, rec := range r.records {
		if rec.Dest == "" {
			continue
		}
		want, _ := new(big.Int).SetString(rec.WeiAsked, 10)
		c := get(rec.Customer)
		state := rec.End
		if rec.ID == "" { // the request did not return an answer we have: a refusal (4xx) created nothing, anything else is unknown
			if strings.HasPrefix(rec.Err, "http_4") {
				state = "refused"
			} else {
				state = "unknown"
			}
		}
		b, err := r.chain.balance(ctx, common.HexToAddress(rec.Dest))
		if err != nil {
			unreadable++
			continue
		}
		fail := func(format string, a ...any) {
			bad++
			examples = append(examples, fmt.Sprintf(format, a...))
		}
		switch state {
		case "confirmed":
			c.paid.Add(c.paid, want)
			paid++
			if b.Cmp(want) != 0 {
				fail("%s confirmed but its destination holds %s, asked %s", rec.ID, b, want)
			}
		case "failed", "refused":
			c.returned.Add(c.returned, want)
			unpaid++
			if b.Sign() != 0 {
				fail("%s %s but its destination holds %s", rec.ID, state, b)
			}
		case "unknown":
			c.unknown.Add(c.unknown, want)
			unknown++
			if b.Sign() != 0 && b.Cmp(want) != 0 {
				fail("unknown request: destination holds %s, asked %s", b, want)
			}
		default: // still open: not paid yet, or paid and not yet seen as confirmed
			c.open.Add(c.open, want)
			openN++
			if b.Sign() != 0 && b.Cmp(want) != 0 {
				fail("%s open (%s) and its destination holds %s, asked %s", rec.ID, state, b, want)
			}
		}
	}
	r.addCheck("withdrawals_paid_exactly_once", bad == 0 && unreadable == 0, "%d confirmed and paid the exact amount, %d refused or failed and paid nothing, %d still open, %d of unknown outcome, %d wrong, %d unreadable %s", paid, unpaid, openN, unknown, bad, unreadable, strings.Join(first(examples, 3), "; "))

	// 2. holds match what is still open, and every customer's books equal funded minus paid minus what is open
	holds, mism := 0, 0
	var ex2 []string
	for _, c := range r.wcust {
		a, h, err := r.available(ctx, c.id, "ETH")
		if err != nil {
			mism++
			ex2 = append(ex2, c.id+": "+err.Error())
			continue
		}
		st := get(c.id)
		if st.unknown.Sign() != 0 || credits[c.id].unknown.Sign() != 0 {
			continue // a request whose outcome the generator never learnt: this customer cannot be judged exactly
		}
		if h.Cmp(st.open) != 0 {
			holds++
			ex2 = append(ex2, fmt.Sprintf("%s holds %s, open withdrawals %s", c.id, h, st.open))
		}
		want := new(big.Int).Sub(credits[c.id].confirmed, st.paid)
		want.Sub(want, st.open)
		if a.Cmp(want) != 0 {
			mism++
			ex2 = append(ex2, fmt.Sprintf("%s available %s, expected %s", c.id, a, want))
		}
	}
	r.addCheck("no_hold_left_behind", holds == 0, "%d customers whose hold differs from what is still open (0 open after a drain: no hold at all) %s", holds, strings.Join(first(ex2, 3), "; "))
	r.addCheck("customer_books_match", mism == 0, "%d customers differ from funded minus paid minus open %s", mism, strings.Join(first(ex2, 3), "; "))

	// 3. deposits credited exactly once and every address swept
	// Every customer's credit equals what the chain shows was paid to their addresses: equality, in both directions. Late credits get time (settle_s).
	r.checkDepositCredits(ctx, credits)
	notSwept := 0
	for i := 0; i < 60 && ctx.Err() == nil; i++ { // the sweeps of the last deposits may still be running
		notSwept = 0
		for _, d := range r.dcusts {
			if credits[d.id].confirmed.Sign() > 0 {
				if b, err := r.chain.balance(ctx, d.addr); err == nil && b.Sign() != 0 {
					notSwept++
				}
			}
		}
		if notSwept == 0 {
			break
		}
		sleepCtx(ctx, 2*time.Second)
	}
	r.addCheck("deposit_addresses_swept", notSwept == 0, "%d addresses still hold funds", notSwept)

	// 4. Reconcile clean (retry a little: a sweep may be mid-flight, and a report with a skipped comparison is not clean)
	var last string
	ok := false
	for i := 0; i < 30 && ctx.Err() == nil; i++ {
		_, out, err := r.C.Call(ctx, r.T.Actors.Ops, "GET", "/v2/reconcile", nil, nil)
		if err == nil {
			cl, _ := out["clean"].(bool)
			if cl {
				ok, last = true, fmt.Sprintf("clean at height %v, in flight %v", out["height"], out["in_flight"])
				break
			}
			b, _ := json.Marshal(out["checks"])
			last = "not clean: " + truncate(string(b), 300)
		} else {
			last = err.Error()
		}
		sleepCtx(ctx, 2*time.Second)
	}
	r.addCheck("reconcile_clean", ok, "%s", last)
	bgBad := 0
	for _, p := range r.bgRec {
		if p.Err == "" && !p.Clean {
			bgBad++
		}
	}
	r.addCheck("reconcile_clean_during_load", bgBad == 0, "%d calls during the load, %d reported a difference (a call in the middle of a sweep may show a transient one)", len(r.bgRec), bgBad)
	r.checks[len(r.checks)-1].Warn = true

	// 5. the audit chain verifies
	_, out, err := r.C.Call(ctx, r.T.Actors.Ops, "GET", "/v2/audit/verify", nil, nil)
	if err != nil {
		r.addCheck("audit_chain_verifies", false, "%v", err)
	} else {
		v, _ := out["ok"].(bool)
		r.addCheck("audit_chain_verifies", v, "head seq %v", out["head_seq"])
	}

	// 6. alerts
	if r.T.PrometheusURL != "" {
		fired, err := firingAlerts(ctx, r.T.PrometheusURL, time.Since(r.started))
		if err != nil {
			r.addCheck("no_alert_fired", false, "could not ask Prometheus: %v", err)
		} else {
			r.addCheck("no_alert_fired", len(fired) == 0, "%d alerts fired during the run %s", len(fired), strings.Join(fired, ", "))
		}
	}

	// 7. the generator itself kept up
	lateMS := r.Obs.late * 1000
	r.addCheck("generator_kept_up", r.dropped.Load() == 0 && lateMS < 500, "%d arrivals dropped at the in-flight cap, largest lateness of a scheduled arrival %.0f ms", r.dropped.Load(), lateMS)
	r.checks[len(r.checks)-1].Warn = true
}

func first(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// settleOpen follows every withdrawal that is not final until it is, or the time is up, and returns how many are still open.
func (r *Runner) settleOpen(ctx context.Context, d time.Duration) int {
	dl, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	var openRecs []*OpRecord
	for _, rec := range r.records {
		if rec.ID != "" && strings.HasPrefix(rec.Key, "withdraw") && rec.End != "confirmed" && rec.End != "failed" {
			openRecs = append(openRecs, rec)
		}
	}
	if len(openRecs) > 0 {
		r.logf("settling %d withdrawals that were open at the end of the drain (up to %s)", len(openRecs), d)
	}
	sem := make(chan struct{}, 32)
	var wg sync.WaitGroup
	for _, rec := range openRecs {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			for dl.Err() == nil {
				_, w, err := r.C.Call(dl, r.T.Actors.Ops, "GET", "/v2/withdrawals/"+rec.ID, nil, nil)
				if err == nil {
					if s, _ := w["status"].(string); s == "confirmed" || s == "failed" {
						rec.End = s
						rec.SettledLate = true
						return
					}
				}
				sleepCtx(dl, time.Second)
			}
		}()
	}
	wg.Wait()
	n := 0
	for _, rec := range openRecs {
		if rec.End != "confirmed" && rec.End != "failed" {
			n++
		}
	}
	return n
}

// firingAlerts asks Prometheus which alerts were firing at any time in the last since: the history of the whole run, not only what still fires after the
// drain (an alert that fired and cleared during the load is the one that matters). It needs the alert rules loaded in that Prometheus.
func firingAlerts(ctx context.Context, base string, since time.Duration) ([]string, error) {
	q := fmt.Sprintf(`max_over_time(ALERTS{alertstate="firing"}[%ds])`, int(since.Seconds())+30)
	req, _ := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(base, "/")+"/api/v1/query?query="+url.QueryEscape(q), nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var out struct {
		Status string `json:"status"`
		Data   struct {
			Result []struct {
				Metric map[string]string `json:"metric"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &out); err != nil || out.Status != "success" {
		return nil, fmt.Errorf("prometheus answered %d: %s", resp.StatusCode, truncate(string(b), 200))
	}
	seen := map[string]bool{}
	var names []string
	for _, r := range out.Data.Result {
		if n := r.Metric["alertname"]; !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	return names, nil
}

type credit struct{ confirmed, unknown *big.Int }

// verifyPayments reads the receipt of every payment the generator made and totals them by customer: confirmed (mined, status 1) and unknown (the generator
// could not learn the outcome). A payment to an address that belongs to no customer of the run, or a reverted one, is a problem of the run itself and fails it.
func (r *Runner) verifyPayments(ctx context.Context) map[string]credit {
	out := map[string]credit{}
	get := func(id string) credit {
		c, ok := out[id]
		if !ok {
			c = credit{new(big.Int), new(big.Int)}
			out[id] = c
		}
		return c
	}
	for _, c := range r.wcust {
		get(c.id)
	}
	for _, d := range r.dcusts {
		get(d.id)
	}
	var problems []string
	n, reverted := 0, 0
	for _, p := range r.chain.Payments() {
		id, ok := r.owner[p.To]
		if !ok {
			problems = append(problems, "payment to an address of no customer: "+p.To.Hex())
			continue
		}
		c := get(id)
		n++
		rc, err := r.chain.ec.TransactionReceipt(ctx, p.Hash)
		switch {
		case err == nil && rc.Status == 1:
			c.confirmed.Add(c.confirmed, p.Wei)
		case err == nil:
			reverted++
		case p.State == "unknown":
			c.unknown.Add(c.unknown, p.Wei)
		default:
			problems = append(problems, fmt.Sprintf("no receipt for accepted payment %s: %v", p.Hash.Hex()[:10], err))
		}
	}
	r.addCheck("payments_confirmed_on_chain", len(problems) == 0 && reverted == 0, "%d payments made, %d reverted, %d problems %s", n, reverted, len(problems), strings.Join(first(problems, 3), "; "))
	return out
}

// checkDepositCredits: each deposit customer's available balance equals the sum of the confirmed payments to their addresses (within the unknown ones, if
// the generator never learnt a payment's outcome). It waits for late credits, and fails on a credit that is too small or too large.
func (r *Runner) checkDepositCredits(ctx context.Context, credits map[string]credit) {
	dl, cancel := context.WithTimeout(ctx, time.Duration(r.S.SettleS*float64(time.Second)))
	defer cancel()
	bad := func(d *dcust) (string, bool) {
		a, _, err := r.available(ctx, d.id, "ETH")
		if err != nil {
			return err.Error(), true
		}
		c := credits[d.id]
		if c.confirmed == nil {
			c = credit{new(big.Int), new(big.Int)}
		}
		hi := new(big.Int).Add(c.confirmed, c.unknown)
		if a.Cmp(c.confirmed) < 0 {
			return fmt.Sprintf("%s credited %s, paid %s", d.id, a, c.confirmed), true
		}
		if a.Cmp(hi) > 0 {
			return fmt.Sprintf("%s credited %s, more than the %s paid to its addresses", d.id, a, hi), true
		}
		return "", false
	}
	var msgs []string
	for {
		msgs = msgs[:0]
		for _, d := range r.dcusts {
			if m, b := bad(d); b {
				msgs = append(msgs, m)
			}
		}
		if len(msgs) == 0 || dl.Err() != nil {
			break
		}
		sleepCtx(dl, 2*time.Second)
	}
	r.addCheck("deposit_credits_exact", len(msgs) == 0, "%d of %d deposit customers whose credit differs from what the chain shows was paid to them %s", len(msgs), len(r.dcusts), strings.Join(first(msgs, 3), "; "))
}
