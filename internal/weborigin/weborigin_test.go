package weborigin

import (
	"strings"
	"testing"
)

// TestCheck: an approver origin is accepted only in the exact form a browser writes into clientDataJSON (lowercase, ASCII/punycode,
// no default or empty port, no path), and http only on an exact loopback host outside production. On 0b9b109 the gateway used
// strings.HasPrefix(o, "http://localhost"); the first version of this fix still accepted the non-canonical forms, which never match.
func TestCheck(t *testing.T) {
	cases := []struct {
		origin    string
		dev, prod bool   // accepted with dev/test, accepted in production
		canonical string // when refused for form only: the canonical form the error must name
	}{
		{"https://a.example", true, true, ""},
		{"https://a.example:8443", true, true, ""},
		{"https://xn--bcher-kva.example", true, true, ""},
		{"https://[2001:db8::1]", true, true, ""},
		{"http://localhost:8080", true, false, ""},
		{"http://localhost", true, false, ""},
		{"http://127.0.0.1:8080", true, false, ""},
		{"http://[::1]:8080", true, false, ""},

		{"http://localhost.evil.example", false, false, ""},
		{"http://localhost.evil.example:8080", false, false, ""},
		{"http://localhostevil.example", false, false, ""},
		{"http://a.example", false, false, ""},
		{"ftp://a.example", false, false, ""},
		{"a.example", false, false, ""},
		{"https://", false, false, ""},
		{"https://a.example/path", false, false, "https://a.example"},
		{"https://a.example/", false, false, "https://a.example"},
		{"http://localhost/", false, false, "http://localhost"},
		{"https://a.example?x=1", false, false, "https://a.example"},
		{"https://a.example#f", false, false, "https://a.example"},
		{"https://user@a.example", false, false, "https://a.example"},

		{"HTTPS://a.example", false, false, "https://a.example"},
		{"https://A.Example", false, false, "https://a.example"},
		{"http://LOCALHOST:8080", false, false, "http://localhost:8080"},
		{"https://a.example.", false, false, "https://a.example"},
		{"https://a.example:443", false, false, "https://a.example"},
		{"http://localhost:80", false, false, "http://localhost"},
		{"https://a.example:", false, false, "https://a.example"},
		{"https://a.example:0443", false, false, "https://a.example"},
		{"https://a.example:99999", false, false, ""},
		{"http://[0:0:0:0:0:0:0:1]:8080", false, false, "http://[::1]:8080"},
		{"https://[2001:DB8::1]", false, false, "https://[2001:db8::1]"},
		{"https://a%2eexample", false, false, ""},
		{"http://local%68ost:8080", false, false, ""},
		{"https://bücher.example", false, false, "punycode"},
	}
	for _, c := range cases {
		for _, dev := range []bool{true, false} {
			want := c.prod
			if dev {
				want = c.dev
			}
			err := Check(c.origin, dev)
			if got := err == nil; got != want {
				t.Errorf("dev=%v origin %q: accepted=%v, want %v (err %v)", dev, c.origin, got, want, err)
				continue
			}
			if err == nil {
				continue
			}
			if !strings.Contains(err.Error(), "origin") {
				t.Errorf("origin %q: error does not name the origin rule: %v", c.origin, err)
			}
			if c.canonical != "" && !strings.Contains(err.Error(), c.canonical) {
				t.Errorf("origin %q: error does not name the canonical form %q: %v", c.origin, c.canonical, err)
			}
		}
	}
}
