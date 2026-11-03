// Package mpc is a 2-of-3 threshold ECDSA (secp256k1) signer built on
// tss-lib's GG20 implementation.
//
// All parties run in this process and talk over in-memory channels (see
// transport.go); tss-lib itself provides no transport. Keygen is a dealerless
// DKG: no process ever holds the whole private key. Each party's keygen output
// ("save data": its secret share Xi, its Paillier key and everyone's public
// parameters) is sealed with AES-GCM under an AES key inside that party's own
// PKCS#11 token (package seal) before it touches disk.
//
// On-disk layout under Config.DataDir:
//
//	preparams/party-<id>.json      sealed Paillier/safe-prime pre-params (AAD "preparams|party-<id>")
//	keys/<keyRef>/party-<id>.sealed sealed keygen save data            (AAD "<keyRef>|party-<id>")
package mpc

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sync"
	"time"

	golog "github.com/ipfs/go-log"

	"github.com/bnb-chain/tss-lib/v4/tss"

	"github.com/ws4charlie/quorum-vault/internal/hsm"
)

type PartyConfig struct {
	ID         int // 1-based; also the party's tss-lib key (Shamir x-coordinate)
	TokenLabel string
	PIN        string
}

type Config struct {
	DataDir          string
	Parties          []PartyConfig
	Threshold        int           // tss-lib t: t+1 parties sign. 1 => 2-of-3. 0 means 1.
	PreParamsTimeout time.Duration // per party; 0 means 10 minutes
}

// DefaultConfig is the project's 2-of-3 setup on tokens qv-party-{1,2,3}.
func DefaultConfig(dataDir, pin string) Config {
	cfg := Config{DataDir: dataDir, Threshold: 1}
	for id := 1; id <= 3; id++ {
		cfg.Parties = append(cfg.Parties, PartyConfig{ID: id, TokenLabel: fmt.Sprintf("qv-party-%d", id), PIN: pin})
	}
	return cfg
}

// Stats describes one ceremony. Messages and Bytes count deliveries: a
// broadcast to two peers counts twice, as it would on a network. Rounds is
// the highest protocol round number that sent a message.
type Stats struct {
	Duration                time.Duration
	Rounds, Messages, Bytes int
}

var (
	ErrKeyExists         = errors.New("mpc: key already exists")
	ErrKeyNotFound       = errors.New("mpc: key not found")
	ErrNotEnoughParties  = errors.New("mpc: not enough parties to sign")
	ErrUnknownParty      = errors.New("mpc: unknown party")
	ErrPublicKeyMismatch = errors.New("mpc: parties disagree on the public key")
)

var keyRefRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type party struct {
	cfg PartyConfig
	tok *hsm.Token
}

// newPID makes a fresh tss PartyID per ceremony: tss.SortPartyIDs writes the
// Index into it, so ceremonies must not share them.
func newPID(id int) *tss.PartyID {
	name := partyName(id)
	return tss.NewPartyID(name, name, big.NewInt(int64(id)))
}

// Cluster is the set of parties of one MPC group. Safe for concurrent use;
// ceremonies are independent.
type Cluster struct {
	cfg     Config
	parties []*party // sorted by ID
	ppMu    sync.Mutex
}

var quietOnce sync.Once

// NewCluster validates cfg and opens every party's token through lib.
func NewCluster(cfg Config, lib *hsm.Lib) (*Cluster, error) {
	if cfg.Threshold == 0 {
		cfg.Threshold = 1
	}
	if cfg.PreParamsTimeout == 0 {
		cfg.PreParamsTimeout = 10 * time.Minute
	}
	if cfg.DataDir == "" {
		return nil, errors.New("mpc: Config.DataDir is empty")
	}
	if n := len(cfg.Parties); n < 2 || cfg.Threshold < 1 || cfg.Threshold >= n {
		return nil, fmt.Errorf("mpc: invalid threshold %d for %d parties", cfg.Threshold, n)
	}
	pcs := slices.Clone(cfg.Parties)
	slices.SortFunc(pcs, func(a, b PartyConfig) int { return a.ID - b.ID })
	for i, pc := range pcs {
		if pc.ID < 1 || (i > 0 && pcs[i-1].ID == pc.ID) {
			return nil, fmt.Errorf("mpc: party IDs must be unique and >= 1 (got %d)", pc.ID)
		}
	}
	cfg.Parties = pcs

	// tss-lib logs every round at INFO; keep it quiet unless asked.
	quietOnce.Do(func() {
		if lvl := os.Getenv("QV_TSS_LOG"); lvl != "" {
			golog.SetLogLevel("tss-lib", lvl)
		} else {
			golog.SetLogLevel("tss-lib", "error")
		}
	})

	c := &Cluster{cfg: cfg}
	for _, pc := range pcs {
		tok, err := lib.OpenToken(pc.TokenLabel, pc.PIN)
		if err != nil {
			c.Close()
			return nil, fmt.Errorf("mpc: party %d: %w", pc.ID, err)
		}
		c.parties = append(c.parties, &party{cfg: pc, tok: tok})
	}
	return c, nil
}

// Close closes the party tokens.
func (c *Cluster) Close() error {
	var errs []error
	for _, p := range c.parties {
		errs = append(errs, p.tok.Close())
	}
	return errors.Join(errs...)
}

func (c *Cluster) Threshold() int { return c.cfg.Threshold }

// PartyIDs returns the configured party IDs in ascending order.
func (c *Cluster) PartyIDs() []int {
	ids := make([]int, len(c.parties))
	for i, p := range c.parties {
		ids[i] = p.cfg.ID
	}
	return ids
}

func (c *Cluster) party(id int) (*party, error) {
	for _, p := range c.parties {
		if p.cfg.ID == id {
			return p, nil
		}
	}
	return nil, fmt.Errorf("%w: %d", ErrUnknownParty, id)
}

func partyName(id int) string { return fmt.Sprintf("party-%d", id) }

func (c *Cluster) keyDir(keyRef string) string { return filepath.Join(c.cfg.DataDir, "keys", keyRef) }

func shareAAD(keyRef string, id int) []byte { return []byte(keyRef + "|" + partyName(id)) }

func checkKeyRef(keyRef string) error {
	if !keyRefRE.MatchString(keyRef) {
		return fmt.Errorf("mpc: invalid keyRef %q", keyRef)
	}
	return nil
}

// sessionNonce is fresh and secret per ceremony; every party gets the same
// value (tss-lib mixes it into the SSID, binding proofs to this run).
func sessionNonce() (*big.Int, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}

// recoverErr turns a panic in tss-lib constructors (they panic on invalid
// parameters) into an error.
func recoverErr(err *error) {
	if r := recover(); r != nil {
		*err = fmt.Errorf("mpc: tss-lib: %v", r)
	}
}
