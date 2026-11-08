package server

import (
	"strings"
	"testing"
)

func ks(cur, cand uint64) peerKS { return peerKS{Exists: true, Current: cur, Candidate: cand} }

// Every case of the three-way reconciliation plan.
func TestPlanReconcileThreeWay(t *testing.T) {
	none := peerKS{}
	cases := []struct {
		name     string
		st       [3]peerKS
		decision uint64
		target   uint64
		promote  [3]bool
		drop     [3]bool
		errHas   string
	}{
		{"nothing anywhere", [3]peerKS{none, none, none}, 0, 0, [3]bool{}, [3]bool{}, ""},
		{"all on 3, no candidates", [3]peerKS{ks(3, 0), ks(3, 0), ks(3, 0)}, 0, 3, [3]bool{}, [3]bool{}, ""},
		{"candidates dropped when nothing was decided", [3]peerKS{ks(3, 4), ks(3, 4), ks(3, 0)}, 0, 3, [3]bool{}, [3]bool{true, true, false}, ""},
		{"decision, nobody switched", [3]peerKS{ks(3, 4), ks(3, 4), ks(3, 4)}, 4, 4, [3]bool{true, true, true}, [3]bool{}, ""},
		{"decision, B switched", [3]peerKS{ks(3, 4), ks(4, 0), ks(3, 4)}, 4, 4, [3]bool{true, false, true}, [3]bool{}, ""},
		{"decision, everyone but A switched", [3]peerKS{ks(3, 4), ks(4, 0), ks(4, 0)}, 4, 4, [3]bool{true, false, false}, [3]bool{}, ""},
		{"decision, all switched", [3]peerKS{ks(4, 0), ks(4, 0), ks(4, 0)}, 4, 4, [3]bool{}, [3]bool{}, ""},
		{"decision but C lost its candidate", [3]peerKS{ks(3, 4), ks(3, 4), ks(3, 0)}, 4, 0, [3]bool{}, [3]bool{}, "party C holds neither"},
		{"decision but C has no state", [3]peerKS{ks(3, 4), ks(3, 4), none}, 4, 0, [3]bool{}, [3]bool{}, "party C has no state"},
		{"aborted DKG (candidates only)", [3]peerKS{ks(0, 1), ks(0, 1), ks(0, 1)}, 0, 0, [3]bool{}, [3]bool{}, ""},
		{"DKG decided, B promoted, C not yet", [3]peerKS{ks(0, 1), ks(1, 0), ks(0, 1)}, 1, 1, [3]bool{true, false, true}, [3]bool{}, ""},
		{"C stale", [3]peerKS{ks(5, 0), ks(5, 0), ks(4, 0)}, 0, 0, [3]bool{}, [3]bool{}, "party C is on generation 4 but another party is on 5"},
		{"A stale", [3]peerKS{ks(4, 0), ks(5, 0), ks(5, 0)}, 0, 0, [3]bool{}, [3]bool{}, "party A is on generation 4 but another party is on 5"},
		{"B has no state", [3]peerKS{ks(5, 0), none, ks(5, 0)}, 0, 0, [3]bool{}, [3]bool{}, "party B has no state"},
		{"A has no state", [3]peerKS{none, ks(5, 0), ks(5, 0)}, 0, 0, [3]bool{}, [3]bool{}, "party A has no state"},
	}
	for _, c := range cases {
		p := planReconcileT(c.st, c.decision)
		if c.errHas != "" {
			if !strings.Contains(p.Err, c.errHas) {
				t.Errorf("%s: err %q, want it to contain %q", c.name, p.Err, c.errHas)
			}
			continue
		}
		if p.Err != "" || p.Target != c.target || p.Promote != c.promote || p.Drop != c.drop {
			t.Errorf("%s: plan %+v, want target %d promote %v drop %v", c.name, p, c.target, c.promote, c.drop)
		}
	}
}
