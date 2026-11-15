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

// Every case of the pair plan: two members reconcile without the third only when nothing can be pending from it.
func TestPlanPair(t *testing.T) {
	none := peerKS{}
	cases := []struct {
		name     string
		mine     peerKS
		theirs   peerKS
		decision uint64
		target   uint64
		reason   string // "" = reconcile
	}{
		{"same generation, clean", ks(3, 0), ks(3, 0), 0, 3, ""},
		{"generation 1 (just after DKG)", ks(1, 0), ks(1, 0), 0, 1, ""},
		{"candidate on mine", ks(3, 4), ks(3, 0), 0, 0, "a commit may be unfinished"},
		{"candidate on theirs", ks(3, 0), ks(3, 4), 0, 0, "a commit may be unfinished"},
		{"candidate on both (A may have decided)", ks(3, 4), ks(3, 4), 0, 0, "a commit may be unfinished"},
		{"a recorded decision", ks(3, 0), ks(3, 0), 4, 0, "a commit may be unfinished"},
		{"theirs is older", ks(4, 0), ks(3, 0), 0, 0, "generations 4 and 3"},
		{"mine is older", ks(3, 0), ks(4, 0), 0, 0, "generations 3 and 4"},
		{"one switched to the decided generation, the other did not", ks(4, 0), ks(3, 4), 0, 0, "generations 4 and 3"},
		{"they have no state", ks(3, 0), none, 0, 0, "no state"},
		{"I have no state", none, ks(3, 0), 0, 0, "no state"},
		{"aborted DKG (candidates only)", ks(0, 1), ks(0, 1), 0, 0, "generations 0 and 0"},
	}
	for _, c := range cases {
		target, why := planPair("B", "C", "party A", c.mine, c.theirs, c.decision)
		if c.reason == "" {
			if why != "" || target != c.target {
				t.Errorf("%s: target %d reason %q, want target %d", c.name, target, why, c.target)
			}
			continue
		}
		if target != 0 || !strings.Contains(why, c.reason) || !strings.Contains(why, "party A") {
			t.Errorf("%s: target %d reason %q, want a refusal containing %q and naming party A", c.name, target, why, c.reason)
		}
	}
}
