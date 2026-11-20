package chain

import "testing"

func TestKeyPathAtAndSplit(t *testing.T) {
	for _, c := range []struct {
		gen        int
		path, want string
	}{{0, "0/5", "0/5"}, {1, "0/5", "0/5"}, {1, "d/7", "d/7"}, {2, "0/5", "g2/0/5"}, {12, "d/7", "g12/d/7"}} {
		got := KeyPathAt(c.gen, c.path)
		if got != c.want {
			t.Errorf("KeyPathAt(%d,%q) = %q, want %q", c.gen, c.path, got, c.want)
		}
		g, p, err := SplitKeyPath(got)
		wantGen := max(c.gen, 1)
		if err != nil || g != wantGen || p != c.path {
			t.Errorf("SplitKeyPath(%q) = %d %q %v", got, g, p, err)
		}
	}
	for _, bad := range []string{"g/0/5", "g1/0/5", "g02/0/5", "g2", "gx/0/5"} {
		if _, _, err := SplitKeyPath(bad); err == nil {
			t.Errorf("SplitKeyPath(%q) accepted", bad)
		}
	}
}
