package server

import (
	"strings"
	"testing"
)

// Every combination of durable states after a crash must converge on one generation or be refused with a clear message.
func TestPlanReconcile(t *testing.T) {
	st := func(cur, cand, dec uint64) KeysetState {
		return KeysetState{Current: cur, Candidate: cand, Decision: dec}
	}
	b := func(cur, cand uint64) peerKS { return peerKS{Exists: true, Current: cur, Candidate: cand} }
	type tc struct {
		name    string
		a       KeysetState
		aEx     bool
		b       peerKS
		want    plan
		wantErr string
	}
	cases := []tc{
		{name: "steady state", a: st(3, 0, 0), aEx: true, b: b(3, 0), want: plan{Target: 3}},
		// refresh from 3 to 4
		{name: "crash after selftest: nothing stored", a: st(3, 0, 0), aEx: true, b: b(3, 0), want: plan{Target: 3}},
		{name: "B stored candidate, A has none (A died before storing)", a: st(3, 0, 0), aEx: true, b: b(3, 4), want: plan{Target: 3, DropB: true}},
		{name: "both stored, no decision", a: st(3, 4, 0), aEx: true, b: b(3, 4), want: plan{Target: 3, DropA: true, DropB: true}},
		{name: "A decided, B not told", a: st(3, 4, 4), aEx: true, b: b(3, 4), want: plan{Target: 4, PromoteA: true, PromoteB: true}},
		{name: "A decided, B switched, A not", a: st(3, 4, 4), aEx: true, b: b(4, 0), want: plan{Target: 4, PromoteA: true}},
		{name: "both switched, confirm lost", a: st(4, 0, 0), aEx: true, b: b(4, 0), want: plan{Target: 4}},
		{name: "A switched (decision cleared), B still has the candidate", a: st(4, 0, 0), aEx: true, b: b(3, 4), wantErr: "party B is on generation 3"},
		// DKG (generation 1)
		{name: "DKG: both stored, no decision: abort", a: st(0, 1, 0), aEx: true, b: b(0, 1), want: plan{Target: 0, DropA: true, DropB: true}},
		{name: "DKG: A decided, B not told", a: st(0, 1, 1), aEx: true, b: b(0, 1), want: plan{Target: 1, PromoteA: true, PromoteB: true}},
		{name: "DKG: only B stored", a: st(0, 0, 0), aEx: false, b: b(0, 1), want: plan{DropB: true}},
		{name: "DKG: only A stored", a: st(0, 1, 0), aEx: true, b: peerKS{}, want: plan{DropA: true}},
		{name: "DKG: A decided, B switched", a: st(0, 1, 1), aEx: true, b: b(1, 0), want: plan{Target: 1, PromoteA: true}},
		{name: "keyset unknown everywhere", aEx: false, b: peerKS{}, want: plan{}},
		// stale restores
		{name: "A restored from an older backup", a: st(3, 0, 0), aEx: true, b: b(5, 0), wantErr: "party A is on generation 3 but party B is on 5"},
		{name: "B restored from an older backup", a: st(5, 0, 0), aEx: true, b: b(3, 0), wantErr: "party B is on generation 3 but party A is on 5"},
		{name: "B lost everything", a: st(5, 0, 0), aEx: true, b: peerKS{}, wantErr: "party B has no state"},
		{name: "A lost everything", aEx: false, b: b(5, 0), wantErr: "party A has no state"},
		{name: "A decided but B lacks the generation", a: st(3, 4, 4), aEx: true, b: b(3, 0), wantErr: "restore party B"},
	}
	for _, c := range cases {
		got := planReconcile(c.a, c.aEx, c.b)
		if c.wantErr != "" {
			if !strings.Contains(got.Err, c.wantErr) {
				t.Errorf("%s: want error containing %q, got %+v", c.name, c.wantErr, got)
			}
			continue
		}
		if got != c.want {
			t.Errorf("%s: got %+v want %+v", c.name, got, c.want)
		}
	}
}
