package pki_test

import (
	"slices"
	"testing"

	"github.com/ws4charlie/quorum-vault/internal/pki"
)

// The chart's names are the catalog's, split: dnsNames and ipAddresses (every environment) never hold a loopback name, devDnsNames and devIpAddresses
// (env dev or test only) hold only loopback names, and together they are the catalog entry's names in its order (local issuance keeps using all of them).
func TestChartCatalogKeepsLoopbackNamesApart(t *testing.T) {
	ce := pki.ChartCatalog()
	if len(ce) != len(pki.Catalog) {
		t.Fatalf("%d chart entries for %d catalog entries", len(ce), len(pki.Catalog))
	}
	dev := 0
	for i, e := range pki.Catalog {
		c := ce[i]
		for _, n := range append(append([]string{}, c.DNS...), c.IPs...) {
			if pki.Loopback(n) {
				t.Errorf("%s: production name %s is a loopback name", c.Name, n)
			}
		}
		for _, n := range append(append([]string{}, c.DevDNS...), c.DevIPs...) {
			if !pki.Loopback(n) {
				t.Errorf("%s: dev-only name %s is not a loopback name", c.Name, n)
			}
			dev++
		}
		if !slices.Equal(append(append([]string{}, c.DNS...), c.DevDNS...), e.DNS) || !slices.Equal(append(append([]string{}, c.IPs...), c.DevIPs...), e.IPs) {
			t.Errorf("%s: chart names %v %v + %v %v are not the catalog's %v %v", c.Name, c.DNS, c.IPs, c.DevDNS, c.DevIPs, e.DNS, e.IPs)
		}
	}
	if dev == 0 {
		t.Fatal("no loopback name in the catalog: the test proves nothing")
	}
	for _, n := range []string{"localhost", "127.0.0.1", "::1"} {
		if !pki.Loopback(n) {
			t.Errorf("Loopback(%q) = false", n)
		}
	}
	if pki.Loopback("qv-core") || pki.Loopback("10.0.0.1") {
		t.Error("Loopback accepts a real name")
	}
}
