package btce2e

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
)

// Batching tests: several withdrawals of one hot shard in one transaction, on real mpc-party, the signing gateway and party B's cosigner (which check every
// payment against its own approval), the workflows and bitcoind regtest. A system starts with batching on (opts.batching); the helpers read the batch rows
// and the booking.

// batchDeposit is what the customer of a batching test holds (the node's wallet has to cover it and the hot funding).
const batchDeposit = 100_000_000

// batchSystem is a withdrawal system with batching on, a funded hot shard and one customer with a large balance.
func batchSystem(t *testing.T, o opts, b batchingOpts, hotOutputs ...int64) *system {
	t.Helper()
	o.withdraw = true
	o.batching = &b
	s := newSystem(t, o)
	for _, v := range hotOutputs {
		s.fundHot(v)
	}
	s.deposit("c1", batchDeposit)
	return s
}

// bw is a withdrawal of a batching test: where it pays and how much.
type bw struct {
	wd
	dest   string
	amount int64
}

// pay requests a withdrawal of amount from c1 to a fresh address. The automated key approves it (the lowest tier), so it joins the queue by itself.
func (s *system) pay(amount int64) bw {
	s.t.Helper()
	dest := s.node.fresh()
	w := s.withdraw("ini", fmt.Sprintf("k%d", time.Now().UnixNano()), "c1", dest, amount)
	if w.ID == "" {
		s.t.Fatalf("withdrawal refused: %d %v", w.Code, w.Raw)
	}
	return bw{wd: w, dest: dest, amount: amount}
}

// bt is a batch row.
type bt struct {
	ID, Status, Tx, Cancel string
	Fee                    int64
	Members                []string // withdrawal IDs in payment order
}

func (s *system) batchRows() []bt {
	s.t.Helper()
	rows, err := s.pool.Query(s.ctx, `SELECT id, status, COALESCE(tx_hash,''), COALESCE(cancel_tx,''), COALESCE(fee,0)::bigint FROM btc_batches WHERE chain=$1 ORDER BY sealed_at, id`, s.chain)
	if err != nil {
		s.t.Fatal(err)
	}
	var out []bt
	for rows.Next() {
		var b bt
		if err := rows.Scan(&b.ID, &b.Status, &b.Tx, &b.Cancel, &b.Fee); err != nil {
			s.t.Fatal(err)
		}
		out = append(out, b)
	}
	rows.Close()
	for i := range out {
		m, err := s.pool.Query(s.ctx, `SELECT withdrawal_id FROM btc_batch_items WHERE batch_id=$1 ORDER BY position`, out[i].ID)
		if err != nil {
			s.t.Fatal(err)
		}
		for m.Next() {
			var id string
			if err := m.Scan(&id); err != nil {
				s.t.Fatal(err)
			}
			out[i].Members = append(out[i].Members, id)
		}
		m.Close()
	}
	return out
}

func (s *system) batchesIn(status string) []bt {
	var out []bt
	for _, b := range s.batchRows() {
		if b.Status == status {
			out = append(out, b)
		}
	}
	return out
}

// untilBatches waits until n batches have the status and returns them.
func (s *system) untilBatches(status string, n int, timeout time.Duration) []bt {
	s.t.Helper()
	var got []bt
	s.waitFor(timeout, fmt.Sprintf("%d batches %s", n, status), func() bool {
		got = s.batchesIn(status)
		return len(got) >= n
	})
	return got
}

// mineBatch mines a batch to the spend depth and waits for it to be booked.
func (s *system) mineBatch(id string) bt {
	s.t.Helper()
	s.node.mine(2, "")
	var got bt
	s.waitFor(90*time.Second, "batch "+id+" confirmed", func() bool {
		for _, b := range s.batchRows() {
			if b.ID == id {
				got = b
				return b.Status == "confirmed"
			}
		}
		return false
	})
	return got
}

// withdrawalRow is what the books say about one withdrawal.
type withdrawalRow struct {
	Status, Tx, Batch, Reason string
	Fee                       int64
	Queued                    bool
}

func (s *system) wdRow(id string) withdrawalRow {
	s.t.Helper()
	var r withdrawalRow
	if err := s.pool.QueryRow(s.ctx, `SELECT status, COALESCE(tx_hash,''), COALESCE(batch_id,''), COALESCE(failure_reason,''), COALESCE(fee,0)::bigint, queued_at IS NOT NULL FROM withdrawals WHERE id=$1`, id).
		Scan(&r.Status, &r.Tx, &r.Batch, &r.Reason, &r.Fee, &r.Queued); err != nil {
		s.t.Fatal(err)
	}
	return r
}

// feeShares are the shares the batch booked, in payment order.
func (s *system) feeShares(batch string) []int64 {
	s.t.Helper()
	rows, err := s.pool.Query(s.ctx, `SELECT COALESCE(fee_share,-1)::bigint FROM btc_batch_items WHERE batch_id=$1 ORDER BY position`, batch)
	if err != nil {
		s.t.Fatal(err)
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			s.t.Fatal(err)
		}
		out = append(out, v)
	}
	return out
}

// assertBooked checks a confirmed batch: every member confirmed once, in its batch's transaction, with its fee share, the shares adding up to the
// fee the transaction really paid; every destination received exactly its amount.
func (s *system) assertBooked(b bt, ws ...bw) {
	s.t.Helper()
	if b.Status != "confirmed" || b.Tx == "" || len(b.Members) != len(ws) {
		s.t.Fatalf("batch %+v, want %d members confirmed", b, len(ws))
	}
	shares := s.feeShares(b.ID)
	var sum int64
	for i, id := range b.Members {
		var w *bw
		for j := range ws {
			if ws[j].ID == id {
				w = &ws[j]
			}
		}
		if w == nil {
			s.t.Fatalf("batch member %s is not among the withdrawals under test", id)
		}
		r := s.wdRow(id)
		if r.Status != "confirmed" || r.Tx != b.Tx || r.Fee != shares[i] || shares[i] < 0 {
			s.t.Fatalf("withdrawal %s: %+v, share %d, batch tx %s", id, r, shares[i], b.Tx)
		}
		sum += shares[i]
		if got := s.received(w.dest, 1); got != w.amount {
			s.t.Fatalf("withdrawal %s: the destination received %d, want %d", id, got, w.amount)
		}
	}
	if real := s.attemptFee(b.Tx); sum != real || b.Fee != real {
		s.t.Fatalf("the fee shares add up to %d, the batch booked %d, the transaction paid %d", sum, b.Fee, real)
	}
}

// voutsOf reads the outputs of a transaction from the node: how many it has.
func (s *system) outputsOf(txid string) int {
	s.t.Helper()
	var tx struct {
		Vout []json.RawMessage `json:"vout"`
	}
	if err := s.node.root.Call(s.ctx, &tx, "getrawtransaction", txid, true); err != nil {
		s.t.Fatalf("transaction %s: %v", txid, err)
	}
	return len(tx.Vout)
}

// payloadOf is the payload of an attempt.
func (s *system) payloadOf(txid string) btc.Payload {
	s.t.Helper()
	var raw []byte
	if err := s.pool.QueryRow(s.ctx, `SELECT payload FROM btc_attempts WHERE chain=$1 AND txid=$2`, s.chain, txid).Scan(&raw); err != nil {
		s.t.Fatal(err)
	}
	p, err := btc.DecodePayload(raw)
	if err != nil {
		s.t.Fatal(err)
	}
	return p
}

// reject calls the rejection (cancel) endpoint for a withdrawal.
func (s *system) reject(id, reason string) (int, map[string]any) {
	s.t.Helper()
	return s.callWith("POST", "/v2/withdrawals/"+id+"/rejections", map[string]string{"X-Actor": "carol"}, map[string]any{"reason": reason})
}

// cancelBatch asks for the whole batch to be cancelled.
func (s *system) cancelBatch(id string) (int, map[string]any) {
	s.t.Helper()
	return s.callWith("POST", "/v2/batches/"+id+"/cancel", map[string]string{"X-Actor": "ops"}, map[string]any{})
}

func (s *system) hasInput(p btc.Payload, txid string) bool {
	for _, in := range p.Inputs {
		if in.TxID == txid {
			return true
		}
	}
	return false
}

var _ = strings.Contains
