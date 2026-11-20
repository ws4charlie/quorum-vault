package broker

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ws4charlie/quorum-vault/mpc-party/api/cosigner"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/attest"
)

// testRootMarker is in the subject of every test root the simulation builds make (attest.NewMockCA); the production build refuses such a root.
const testRootMarker = "TEST ONLY"

// Config is the broker's JSON config. Secrets are not in it: the token PIN is a file or environment variable, the TLS key and operator keys
// are files.
type Config struct {
	Listen       string `json:"listen"`                  // mutual-TLS address, e.g. ":8443"
	HealthListen string `json:"health_listen,omitempty"` // optional plain-HTTP /healthz and /metrics, e.g. "127.0.0.1:8444" (no data, no auth)
	TLSCert      string `json:"tls_cert"`
	TLSKey       string `json:"tls_key"`

	PKCS11 PKCS11Config `json:"pkcs11"`

	// TrustRoots is a PEM file of the vendor root(s) of the evidence (AWS Nitro root G1 in production, the test root in simulation).
	TrustRoots string `json:"trust_roots"`
	// AllowDebug accepts debug-mode evidence at the verifier. Only a simulation build (-tags teesim) starts with it set.
	AllowDebug bool `json:"allow_debug,omitempty"`

	AllowlistFile string                `json:"allowlist_file"`
	Operators     attest.OperatorsFile  `json:"operators"`
	Parties       map[string]PartyEntry `json:"parties"` // party role -> the TLS keys that may speak for it
	AuditLog      string                `json:"audit_log"`

	NonceTTL       string `json:"nonce_ttl,omitempty"`       // default "60s"
	ReloadInterval string `json:"reload_interval,omitempty"` // allowlist file poll, default "10s"; "0" turns polling off (SIGHUP still reloads)
	RatePerMinute  int    `json:"rate_per_minute,omitempty"` // per party, challenge and release calls together; default 30
	RateBurst      int    `json:"rate_burst,omitempty"`      // default 10
}

// PartyEntry lists the public-key pins (SHA-256 of the SPKI, as every pinned link uses) of the callers of one party.
type PartyEntry struct {
	CallerPins []string `json:"caller_pins"`
}

type settings struct {
	nonceTTL, reload time.Duration
	rate, burst      int
	pins             map[[32]byte]string // caller pin -> party
	pinSet           map[cosigner.Pin]bool
}

// LoadConfig reads a config file (unknown fields refused).
func LoadConfig(path string) (Config, error) {
	var c Config
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("broker: config: %w", err)
	}
	return c, nil
}

func (c Config) settings() (*settings, error) {
	s := &settings{nonceTTL: time.Minute, reload: 10 * time.Second, rate: 30, burst: 10, pins: map[[32]byte]string{}, pinSet: map[cosigner.Pin]bool{}}
	var err error
	if c.NonceTTL != "" {
		if s.nonceTTL, err = time.ParseDuration(c.NonceTTL); err != nil || s.nonceTTL < time.Second || s.nonceTTL > 10*time.Minute {
			return nil, errors.New("broker: config: nonce_ttl must be between 1s and 10m")
		}
	}
	if c.ReloadInterval != "" {
		if s.reload, err = time.ParseDuration(c.ReloadInterval); err != nil || s.reload < 0 {
			return nil, errors.New("broker: config: reload_interval is not a duration")
		}
	}
	if c.RatePerMinute != 0 {
		s.rate = c.RatePerMinute
	}
	if c.RateBurst != 0 {
		s.burst = c.RateBurst
	}
	if s.rate < 1 || s.burst < 1 {
		return nil, errors.New("broker: config: rate_per_minute and rate_burst must be positive")
	}
	if len(c.Parties) == 0 {
		return nil, errors.New("broker: config: parties is empty")
	}
	for party, e := range c.Parties {
		if err := (attest.RequestContext{Party: party, Keyset: "k", Generations: []uint64{1}, Purpose: attest.PurposeUnseal}).Validate(); err != nil {
			return nil, fmt.Errorf("broker: config: party %q: %w", party, err)
		}
		if len(e.CallerPins) == 0 {
			return nil, fmt.Errorf("broker: config: party %q has no caller_pins", party)
		}
		for _, ps := range e.CallerPins {
			p, err := cosigner.ParsePin(ps)
			if err != nil {
				return nil, fmt.Errorf("broker: config: party %q: %w", party, err)
			}
			if other, dup := s.pins[p]; dup {
				return nil, fmt.Errorf("broker: config: one caller key is listed for parties %q and %q", other, party)
			}
			s.pins[p] = party
			s.pinSet[p] = true
		}
	}
	for name, v := range map[string]string{"listen": c.Listen, "tls_cert": c.TLSCert, "tls_key": c.TLSKey, "trust_roots": c.TrustRoots,
		"allowlist_file": c.AllowlistFile, "audit_log": c.AuditLog} {
		if v == "" {
			return nil, fmt.Errorf("broker: config: %s is required", name)
		}
	}
	return s, nil
}

func (c Config) tlsConfig(s *settings) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(c.TLSCert, c.TLSKey)
	if err != nil {
		return nil, fmt.Errorf("broker: tls: %w", err)
	}
	if err := cosigner.CheckValid(cert, time.Now()); err != nil {
		return nil, fmt.Errorf("broker: tls certificate: %w", err)
	}
	return cosigner.ServerTLS(cert, s.pinSet), nil
}
