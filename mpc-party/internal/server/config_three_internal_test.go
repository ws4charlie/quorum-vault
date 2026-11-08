package server

import (
	"strings"
	"testing"
)

// Config rules of E23-2: party C dials nobody, needs a pin per caller, and A's and B's certificates must differ.
func TestConfigThreeParty(t *testing.T) {
	pin := strings.Repeat("ab", 32)
	pin2 := strings.Repeat("cd", 32)
	admin := strings.Repeat("11", 32)
	base := func() Config {
		return Config{Role: "C", CallerListen: "127.0.0.1:1", PeerListen: "127.0.0.1:2", CertFile: "c", KeyFile: "k", DataDir: "d",
			CallerPins: []string{pin}, PeerAPins: []string{pin}, PeerBPins: []string{pin2}, AdminKeys: []string{admin},
			Sealer: SealerConfig{Type: "pkcs11"}, Authorizer: AuthorizerConfig{Type: "deny-all"}}
	}
	ok := base()
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid C config rejected: %v", err)
	}
	for name, mod := range map[string]func(c *Config){
		"C dials":               func(c *Config) { c.PeerCAddress, c.PeerCPins = "127.0.0.1:3", []string{pin} },
		"C with peer_pins":      func(c *Config) { c.PeerPins = []string{pin} },
		"C without A's pin":     func(c *Config) { c.PeerAPins = nil },
		"C without B's pin":     func(c *Config) { c.PeerBPins = nil },
		"A and B share a pin":   func(c *Config) { c.PeerBPins = []string{strings.ToUpper(pin)} },
		"C without peer_listen": func(c *Config) { c.PeerListen = "" },
		"address without pin (A/B)": func(c *Config) {
			c.Role, c.PeerListen, c.PeerAPins, c.PeerBPins, c.PeerPins, c.PeerCAddress = "B", "127.0.0.1:2", nil, nil, []string{pin}, "127.0.0.1:3"
		},
		"A with peer_a_pins": func(c *Config) {
			c.Role, c.PeerListen, c.PeerAddress, c.PeerPins = "A", "", "127.0.0.1:2", []string{pin}
		},
	} {
		c := base()
		mod(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A and B with C configured
	a := Config{Role: "A", CallerListen: "127.0.0.1:1", PeerAddress: "127.0.0.1:2", PeerPins: []string{pin}, CertFile: "c", KeyFile: "k", DataDir: "d",
		CallerPins: []string{pin}, AdminKeys: []string{admin}, PeerCAddress: "127.0.0.1:3", PeerCPins: []string{pin2},
		Sealer: SealerConfig{Type: "pkcs11"}, Authorizer: AuthorizerConfig{Type: "deny-all"}}
	if err := a.Validate(); err != nil {
		t.Fatalf("valid A config rejected: %v", err)
	}
}
