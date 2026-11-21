package mpcstack

import (
	"net"
	"strconv"
	"testing"
)

// The addresses for parties are below the dynamic port range (a client socket never takes them) and never repeat.
func TestFreeAddrStaysBelowTheDynamicRange(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		a := FreeAddr(t)
		if seen[a] {
			t.Fatalf("%s given twice", a)
		}
		seen[a] = true
		_, p, _ := net.SplitHostPort(a)
		if n, _ := strconv.Atoi(p); n >= 32768 {
			t.Fatalf("%s is in the dynamic range", a)
		}
	}
}
