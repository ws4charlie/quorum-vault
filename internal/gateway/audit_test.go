package gateway

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ws4charlie/quorum-vault/internal/audit"
)

type auditRow struct {
	Seq     int64
	Actor   string
	Type    string
	Payload map[string]any
}

func (h *harness) auditRows() []auditRow {
	h.t.Helper()
	rows, err := h.guardDB.Query(context.Background(), `SELECT seq, actor, type, payload::text FROM audit_log ORDER BY seq`)
	if err != nil {
		h.t.Fatal(err)
	}
	defer rows.Close()
	var out []auditRow
	for rows.Next() {
		var r auditRow
		var p string
		if err := rows.Scan(&r.Seq, &r.Actor, &r.Type, &p); err != nil {
			h.t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(p), &r.Payload); err != nil {
			h.t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func types(rs []auditRow) []string {
	var out []string
	for _, r := range rs {
		out = append(out, r.Type)
	}
	return out
}

// Every decision is in the zone's own chain: the permission to sign and the release of the signature, a repeat, and a refusal
// with its reason. No payload holds a signature.
func TestEveryDecisionIsAudited(t *testing.T) {
	h := newHarness(t)
	j := h.withdrawal("a1", addrUser, 500, 0, "alice")
	h.mustSign(j)
	again := j // the same transaction under a new job ID returns the stored signature
	again.ID = "a1b"
	h.mustSign(again)
	h.mustReject(h.withdrawal("a2", addrUser, 500, 1), ReasonApprovals)
	h.mustReject(h.withdrawal("a3", addrUser, 9000, 2, "alice"), ReasonPerTxCap)

	rows := h.auditRows()
	got := strings.Join(types(rows), ",")
	if want := "sign.allowed,sign.completed,sign.replayed,sign.refused,sign.refused"; got != want {
		t.Fatalf("audit types = %s, want %s", got, want)
	}
	allowed := rows[0]
	if allowed.Actor != "qv-gateway" || allowed.Payload["intent"] != "w-a1" || allowed.Payload["kind"] != "withdrawal" ||
		allowed.Payload["amount"] != "500" || allowed.Payload["job"] != "a1" {
		t.Errorf("sign.allowed = %+v", allowed)
	}
	if ap, _ := allowed.Payload["approvers"].([]any); len(ap) != 1 || ap[0] != "alice" {
		t.Errorf("approvers = %v, want [alice]", allowed.Payload["approvers"])
	}
	if r := rows[3].Payload["reason"].(string); !strings.HasPrefix(r, ReasonApprovals+":") {
		t.Errorf("refusal reason = %q", r)
	}
	if r := rows[4].Payload["reason"].(string); !strings.HasPrefix(r, ReasonPerTxCap+":") {
		t.Errorf("refusal reason = %q", r)
	}
	for _, r := range rows {
		for k := range r.Payload {
			if strings.Contains(k, "sig") && k != "signer" {
				t.Errorf("%s payload has a %q field", r.Type, k)
			}
		}
	}
	if ok, bad, err := audit.VerifyChain(context.Background(), h.guardDB); err != nil || !ok {
		t.Fatalf("guard chain: ok=%v bad=%d err=%v", ok, bad, err)
	}
}

// The decision does not need qv-core or the job queue: the Decider uses only its guard database, and a refusal is recorded there.
func TestRefusalIsRecordedWithCoreStopped(t *testing.T) {
	h := newHarness(t)
	dec := NewDecider(h.cfg, h.gw.codecs, h.guard, ModeGateway, nil)
	h.biz.Close() // the business database (qv-core's) is gone
	for _, j := range []struct {
		name string
		code string
	}{{"c1", ReasonApprovals}, {"c2", ReasonPerTxCap}} {
		var job = h.withdrawal(j.name, addrUser, 500, 0)
		if j.code == ReasonPerTxCap {
			job = h.withdrawal(j.name, addrUser, 9000, 0, "alice")
		}
		_, err := dec.Decide(context.Background(), job, h.signer.PublicKey())
		if why, ok := IsRejection(err); !ok || !strings.HasPrefix(why, j.code+":") {
			t.Fatalf("%s: err = %v, want rejection %s", j.name, err, j.code)
		}
	}
	rows := h.auditRows()
	if len(rows) != 2 || rows[0].Type != EventSignRefused || rows[1].Type != EventSignRefused {
		t.Fatalf("audit = %v, want two sign.refused", types(rows))
	}
}

// No signature without a record: when the audit record cannot be written, the digest is not reserved, the signer does not run
// and the job gets neither a signature nor a refusal (it is retried).
func TestNoSignatureWithoutRecord(t *testing.T) {
	h := newHarness(t)
	if _, err := h.guardDB.Exec(context.Background(), `ALTER TABLE audit_log RENAME TO audit_log_gone`); err != nil {
		t.Fatal(err)
	}
	j := h.withdrawal("n1", addrUser, 500, 0, "alice")
	before := h.signer.calls.Load()
	d := h.run(j)
	if d.Outcome != OutcomeRetry || len(d.Sig) != 0 {
		t.Fatalf("outcome %s (%s) sig %d bytes, want retry and no signature", d.Outcome, d.Reason, len(d.Sig))
	}
	if h.signer.calls.Load() != before {
		t.Fatal("the signer ran although the decision could not be recorded")
	}
	var n int
	h.guardDB.QueryRow(context.Background(), `SELECT count(*) FROM signed_digests`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d digests reserved without an audit record", n)
	}
	// A refusal is not reported either when it cannot be recorded.
	d = h.run(h.withdrawal("n2", addrUser, 500, 1))
	if d.Outcome != OutcomeRetry {
		t.Fatalf("an unrecorded refusal ended as %s, want retry", d.Outcome)
	}
}
