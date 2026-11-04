// Package server is the mpc-party service: one party (A or B) of the 2-party signer, with a caller port (gRPC over
// mTLS, callers pinned) and a peer port (gRPC over mTLS, the other party pinned).
package server

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"
)

// Config is the JSON config file. Unknown fields are an error; a missing or invalid file stops the process.
type Config struct {
	Role         string `json:"role"`          // "A" (coordinator, P1) or "B" (follower, P2)
	CallerListen string `json:"caller_listen"` // gRPC for callers; mTLS, callers pinned by certificate fingerprint
	PeerListen   string `json:"peer_listen"`   // B only: gRPC for party A; mTLS, A pinned
	PeerAddress  string `json:"peer_address"`  // A only: B's peer_listen address

	CertFile string `json:"cert_file"` // this party's certificate (PEM), used on both ports
	KeyFile  string `json:"key_file"`

	// Pins are lowercase hex SHA-256 fingerprints of the DER leaf certificate.
	PeerPins   []string `json:"peer_pins"`   // the other party's certificate (exactly the cert it presents)
	CallerPins []string `json:"caller_pins"` // certificates allowed on the caller port

	DataDir string `json:"data_dir"`

	// AdminKeys are the operators' Ed25519 public keys (64 hex chars). DKG, Refresh and Unfreeze need a signature by one of
	// them, checked by BOTH parties against their own list, so a compromised party A cannot start them.
	AdminKeys          []string `json:"admin_keys"`
	AdminMaxAgeSeconds int      `json:"admin_max_age_seconds"` // accepted clock skew / age of an admin signature; default 300

	Sealer     SealerConfig     `json:"sealer"`
	Authorizer AuthorizerConfig `json:"authorizer"`
	Limits     Limits           `json:"limits"`
}

type SealerConfig struct {
	// Type: "insecure-static-key-for-tests" is the only one until P5b-4 adds the HSM sealer.
	Type    string `json:"type"`
	KeyFile string `json:"key_file"` // hex, 32 bytes
}

type AuthorizerConfig struct {
	// Type: "cosigner" (party B: ask the qv-cosigner process on Socket; fail closed), "pinned-caller" (party A: its pinned
	// caller, the gateway, has already decided), "deny-all", or "dev-allow-all" (only compiled with -tags devauth).
	Type string `json:"type"`
	// Socket is the unix socket of qv-cosigner, type "cosigner". TimeoutMS bounds one decision (default 5000).
	Socket    string `json:"socket"`
	TimeoutMS int    `json:"timeout_ms"`
	// AcceptRisk must be exactly DevAllowAllRiskPhrase for "dev-allow-all".
	AcceptRisk string `json:"accept_risk"`
}

// DevAllowAllRiskPhrase must be written into the config of a binary built with -tags devauth to enable dev-allow-all.
const DevAllowAllRiskPhrase = "I UNDERSTAND THIS PARTY SIGNS ANYTHING WITHOUT POLICY CHECKS"

// Limits. Zero values take the defaults.
type Limits struct {
	RecvTimeoutMS     int     `json:"recv_timeout_ms"`      // per protocol message from the peer; default 5000
	SessionTimeoutMS  int     `json:"session_timeout_ms"`   // whole session; default 30000
	MaxPeerSessions   int     `json:"max_peer_sessions"`    // concurrent sessions, each direction; default 2 x cores
	MaxFrameBytes     int     `json:"max_frame_bytes"`      // largest protocol message; default 1 MiB
	SessionsPerSecKey float64 `json:"sessions_per_sec_key"` // per key id or keyset id; default 200
	MaxIntentBytes    int     `json:"max_intent_bytes"`     // intent_package; default 256 KiB
	ShutdownGraceMS   int     `json:"shutdown_grace_ms"`    // default 10000
	ReplayCacheSize   int     `json:"replay_cache_size"`    // remembered session ids; default 200000
}

func (l *Limits) applyDefaults() {
	if l.RecvTimeoutMS <= 0 {
		l.RecvTimeoutMS = 5000
	}
	if l.SessionTimeoutMS <= 0 {
		l.SessionTimeoutMS = 30000
	}
	if l.MaxPeerSessions <= 0 {
		l.MaxPeerSessions = 2 * runtime.NumCPU()
	}
	if l.MaxFrameBytes <= 0 {
		l.MaxFrameBytes = 1 << 20
	}
	if l.SessionsPerSecKey <= 0 {
		l.SessionsPerSecKey = 200
	}
	if l.MaxIntentBytes <= 0 {
		l.MaxIntentBytes = 256 << 10
	}
	if l.ShutdownGraceMS <= 0 {
		l.ShutdownGraceMS = 10000
	}
	if l.ReplayCacheSize <= 0 {
		l.ReplayCacheSize = 200000
	}
}

func (l Limits) RecvTimeout() time.Duration { return time.Duration(l.RecvTimeoutMS) * time.Millisecond }
func (l Limits) SessionTimeout() time.Duration {
	return time.Duration(l.SessionTimeoutMS) * time.Millisecond
}
func (l Limits) ShutdownGrace() time.Duration {
	return time.Duration(l.ShutdownGraceMS) * time.Millisecond
}

// LoadConfig reads and validates a config file.
func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var c Config
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("config %s: trailing data", path)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	return &c, nil
}

// Validate checks the config and fills defaults.
func (c *Config) Validate() error {
	var errs []error
	req := func(name, v string) {
		if strings.TrimSpace(v) == "" {
			errs = append(errs, fmt.Errorf("%s is required", name))
		}
	}
	switch c.Role {
	case "A":
		req("peer_address", c.PeerAddress)
	case "B":
		req("peer_listen", c.PeerListen)
	default:
		errs = append(errs, fmt.Errorf(`role must be "A" or "B", got %q`, c.Role))
	}
	req("caller_listen", c.CallerListen)
	req("cert_file", c.CertFile)
	req("key_file", c.KeyFile)
	req("data_dir", c.DataDir)
	if c.Role == "A" && c.PeerListen != "" {
		errs = append(errs, errors.New("peer_listen is only for role B (party A dials B)"))
	}
	if c.Role == "B" && c.PeerAddress != "" {
		errs = append(errs, errors.New("peer_address is only for role A"))
	}
	if c.PeerListen != "" && c.PeerListen == c.CallerListen && !strings.HasSuffix(c.PeerListen, ":0") {
		errs = append(errs, errors.New("peer_listen and caller_listen must be different listeners"))
	}
	if len(c.PeerPins) == 0 {
		errs = append(errs, errors.New("peer_pins: at least one pin is required"))
	}
	if len(c.CallerPins) == 0 {
		errs = append(errs, errors.New("caller_pins: at least one pin is required"))
	}
	for _, p := range append(append([]string{}, c.PeerPins...), c.CallerPins...) {
		if _, err := ParsePin(p); err != nil {
			errs = append(errs, err)
		}
	}
	if len(c.AdminKeys) == 0 {
		errs = append(errs, errors.New("admin_keys: at least one operator key is required"))
	}
	for _, k := range c.AdminKeys {
		if b, err := hex.DecodeString(k); err != nil || len(b) != ed25519.PublicKeySize {
			errs = append(errs, fmt.Errorf("admin_keys: %q is not a 32-byte hex Ed25519 public key", k))
		}
	}
	if c.AdminMaxAgeSeconds <= 0 {
		c.AdminMaxAgeSeconds = 300
	}
	req("sealer.type", c.Sealer.Type)
	req("authorizer.type", c.Authorizer.Type)
	c.Limits.applyDefaults()
	if c.Limits.MaxFrameBytes > 64<<20 {
		errs = append(errs, errors.New("limits.max_frame_bytes above 64 MiB"))
	}
	return errors.Join(errs...)
}
