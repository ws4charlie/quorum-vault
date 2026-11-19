package btce2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
	"github.com/ws4charlie/quorum-vault/internal/custody"
	"github.com/ws4charlie/quorum-vault/internal/gateway"
)

// Signed fee-cap changes (docs/runbooks/btc-fee-caps.md) on the real binaries: the config sections, the operator tools qv-fee-caps and qv-approvers run
// as an operator runs them (separate processes, the databases' own connection strings), and readers of what they leave behind.

// feeCapsOpts turns on fee_caps_change in the core's and the zone's config. The zone's bounds are fcMin*..fcMax* (no signature goes outside them);
// the approvers are the four of the harness (alice, bob, carol, auto), the same in the core and the zone, identity = name.
type feeCapsOpts struct {
	minApprovers int // default 2
	// operators > 0 adds the operators section (that many operator keys, min_operators 2): approvers can then be revoked with signatures.
	operators int
}

const (
	fcMinRate, fcMaxRate = 1, 200
	fcMinTx, fcMaxTx     = 1_000, 1_000_000
)

func (o *feeCapsOpts) min() int {
	if o.minApprovers > 0 {
		return o.minApprovers
	}
	return 2
}

// feeCapsCore puts the section in the core's config: the approvers' keys. Called once the approvers exist.
func (s *system) feeCapsCore(o opts) {
	if o.feeCaps == nil {
		return
	}
	fc := &custody.FeeCapsChangeFile{Approvers: map[string]custody.FeeCapsApproverFile{}, MinApprovers: o.feeCaps.min()}
	for name, priv := range s.approv {
		fc.Approvers[name] = custody.FeeCapsApproverFile{Key: hex.EncodeToString(priv.Public().(ed25519.PublicKey)), Identity: name}
	}
	s.cf.Chain.BTC.FeeCapsChange = fc
}

// feeCapsZone puts the bounds and the rules in the zone's config (the gateway's and, as a copy, the cosigner's), and the operators.
func (s *system) feeCapsZone(gf *gateway.File, o opts) {
	if o.feeCaps == nil {
		return
	}
	gf.Chains[s.chain].BTC.FeeCapsChange = &gateway.FeeCapsChangeFile{MinFeeRate: fcMinRate, MaxFeeRate: fcMaxRate, MinTxFeeSats: fcMinTx, MaxTxFeeSats: fcMaxTx,
		MinApprovers: o.feeCaps.min(), MaxChangeAge: "10m"}
	if n := o.feeCaps.operators; n > 0 {
		s.ops = map[string]ed25519.PrivateKey{}
		gf.Operators = &gateway.OperatorsFile{Keys: map[string]gateway.OperatorFile{}, MinOperators: 2}
		for i := 1; i <= n; i++ {
			pub, priv, _ := ed25519.GenerateKey(rand.Reader)
			name := fmt.Sprintf("op%d", i)
			s.ops[name] = priv
			gf.Operators.Keys[name] = gateway.OperatorFile{PublicKey: hex.EncodeToString(pub)}
		}
	}
}

// tool runs an operator tool built for the suite and returns what it printed (both streams).
func (s *system) tool(name string, args ...string) (string, error) {
	s.t.Helper()
	cmd := exec.Command(filepath.Join(binDir, name), args...)
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// keyFile writes a private key's seed as hex, the way an approver's or operator's key file looks.
func (s *system) keyFile(name string, priv ed25519.PrivateKey) string {
	s.t.Helper()
	p := filepath.Join(s.dir, name+".key")
	if err := os.WriteFile(p, []byte(hex.EncodeToString(priv.Seed())), 0o600); err != nil {
		s.t.Fatal(err)
	}
	return p
}

// signCaps is `qv-fee-caps sign` by one approver; it returns the signature file.
func (s *system) signCaps(actor string, maxTx, maxRate uint64, seq int64) string {
	s.t.Helper()
	out := filepath.Join(s.dir, fmt.Sprintf("caps-%s-%d-%d-%d.json", actor, maxTx, maxRate, seq))
	if o, err := s.tool("qv-fee-caps", "sign", "-actor", actor, "-key", s.keyFile(actor, s.approv[actor]), "-chain", s.chain,
		"-max-tx-fee-sats", fmt.Sprint(maxTx), "-max-fee-rate", fmt.Sprint(maxRate), "-seq", fmt.Sprint(seq), "-out", out); err != nil {
		s.t.Fatalf("qv-fee-caps sign: %v\n%s", err, o)
	}
	return out
}

// dbs is which databases a command names: the signing zone's guards (the gateway's and the cosigner's) and the core's.
type dbs struct{ zone, core bool }

var (
	everywhere = dbs{true, true}
	zoneOnly   = dbs{zone: true}
	coreOnly   = dbs{core: true}
)

func (s *system) dbArgs(d dbs) []string {
	var a []string
	if d.zone {
		a = append(a, "-guard-dsn", "gateway="+s.gwGuard, "-guard-dsn", "cosigner-b="+s.cosGuard)
	}
	if d.core {
		a = append(a, "-core-dsn", s.bizDSN)
	}
	return a
}

// applyCaps is `qv-fee-caps apply` of the joined files to the named databases; it returns the output and the error.
func (s *system) applyCaps(d dbs, files ...string) (string, error) {
	s.t.Helper()
	args := append([]string{"apply", "-config", s.gwPath}, s.dbArgs(d)...)
	return s.tool("qv-fee-caps", append(args, files...)...)
}

// mustApply applies to the named databases and fails the test if the command does.
func (s *system) mustApply(d dbs, files ...string) {
	s.t.Helper()
	if out, err := s.applyCaps(d, files...); err != nil {
		s.t.Fatalf("qv-fee-caps apply: %v\n%s", err, out)
	}
}

// signedBy signs the change with each actor and returns the files.
func (s *system) signedBy(maxTx, maxRate uint64, seq int64, actors ...string) []string {
	var fs []string
	for _, a := range actors {
		fs = append(fs, s.signCaps(a, maxTx, maxRate, seq))
	}
	return fs
}

// capsRow is one line of `qv-fee-caps show`.
type capsRow struct{ tx, rate, seq int64 }

var showLine = regexp.MustCompile(`^(\S+)\s+max_tx_fee_sats (\d+), max_fee_rate (\d+) sat/vB, sequence (\d+)`)

// show runs `qv-fee-caps show` on the named databases and returns each one's caps and sequence number, and the whole output.
func (s *system) showCaps(d dbs) (map[string]capsRow, string) {
	s.t.Helper()
	out, err := s.tool("qv-fee-caps", append([]string{"show", "-config", s.gwPath, "-chain", s.chain}, s.dbArgs(d)...)...)
	if err != nil {
		s.t.Fatalf("qv-fee-caps show: %v\n%s", err, out)
	}
	rows := map[string]capsRow{}
	for _, l := range strings.Split(out, "\n") {
		if m := showLine.FindStringSubmatch(l); m != nil {
			a, _ := strconv.ParseInt(m[2], 10, 64)
			b, _ := strconv.ParseInt(m[3], 10, 64)
			c, _ := strconv.ParseInt(m[4], 10, 64)
			rows[m[1]] = capsRow{a, b, c}
		}
	}
	return rows, out
}

// wantCaps checks that every database named has the caps and sequence number.
func (s *system) wantCaps(d dbs, tx, rate, seq int64) {
	s.t.Helper()
	rows, out := s.showCaps(d)
	n := 0
	if d.zone {
		n += 2
	}
	if d.core {
		n++
	}
	if len(rows) != n {
		s.t.Fatalf("show lists %d databases, want %d:\n%s", len(rows), n, out)
	}
	for name, r := range rows {
		if r != (capsRow{tx, rate, seq}) {
			s.t.Fatalf("%s is at %+v, want max_tx_fee_sats %d, max_fee_rate %d, sequence %d:\n%s", name, r, tx, rate, seq, out)
		}
	}
}

// metrics runs `qv-fee-caps metrics` and returns every sample by its name and, for the per-database ones, store: "name{store}".
func (s *system) metrics(d dbs) map[string]float64 {
	s.t.Helper()
	file := filepath.Join(s.dir, "qv_fee_caps.prom")
	if out, err := s.tool("qv-fee-caps", append([]string{"metrics", "-config", s.gwPath, "-chain", s.chain, "-out", file}, s.dbArgs(d)...)...); err != nil {
		s.t.Fatalf("qv-fee-caps metrics: %v\n%s", err, out)
	}
	b, err := os.ReadFile(file)
	if err != nil {
		s.t.Fatal(err)
	}
	re := regexp.MustCompile(`^(\w+)\{chain="[^"]*"(?:,store="([^"]*)")?\} (\d+)$`)
	m := map[string]float64{}
	for _, l := range strings.Split(string(b), "\n") {
		if g := re.FindStringSubmatch(l); g != nil {
			v, _ := strconv.ParseFloat(g[3], 64)
			key := g[1]
			if g[2] != "" {
				key += "{" + g[2] + "}"
			}
			m[key] = v
		}
	}
	return m
}

// capRows counts the rows of the fee-cap table in each database (core, gateway, cosigner): what the tools wrote, valid or not.
func (s *system) capRows() []int {
	s.t.Helper()
	var out []int
	for _, dsn := range []string{s.bizDSN, s.gwGuard, s.cosGuard} {
		c, err := pgx.Connect(context.Background(), dsn)
		if err != nil {
			s.t.Fatal(err)
		}
		var n int
		err = c.QueryRow(context.Background(), `SELECT count(*) FROM `+btc.FeeCapsTable).Scan(&n)
		c.Close(context.Background())
		if err != nil {
			s.t.Fatal(err)
		}
		out = append(out, n)
	}
	return out
}

// strip rewrites a signature file so that it carries no signatures.
func (s *system) stripSignatures(file string) string {
	s.t.Helper()
	b, err := os.ReadFile(file)
	if err != nil {
		s.t.Fatal(err)
	}
	var c btc.FeeCapsChange
	if err := json.Unmarshal(b, &c); err != nil {
		s.t.Fatal(err)
	}
	c.Signatures = nil
	out := file + ".unsigned"
	writeJSONFile(s.t, out, c)
	return out
}

// alive reports whether a process is still the one that was started.
func alive(p *proc) bool {
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}

// readChange reads and joins signature files.
func (s *system) readChange(files ...string) btc.FeeCapsChange {
	s.t.Helper()
	var parts []btc.FeeCapsChange
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			s.t.Fatal(err)
		}
		var c btc.FeeCapsChange
		if err := json.Unmarshal(b, &c); err != nil {
			s.t.Fatal(err)
		}
		parts = append(parts, c)
	}
	c, err := btc.MergeFeeCaps(parts...)
	if err != nil {
		s.t.Fatal(err)
	}
	return c
}

// tamper joins the files and changes max_fee_rate afterwards: the signatures are over the old value.
func (s *system) tamper(a, b string, rate uint64) string {
	s.t.Helper()
	c := s.readChange(a, b)
	c.Caps.MaxFeeRate = rate
	out := a + ".tampered"
	writeJSONFile(s.t, out, c)
	return out
}

// withSeq joins the files and sets the sequence number afterwards.
func (s *system) withSeq(a, b string, seq int64) string {
	s.t.Helper()
	c := s.readChange(a, b)
	c.Seq = seq
	out := a + ".seq"
	writeJSONFile(s.t, out, c)
	return out
}

// signedAs is a signature file made by a key that is not the approver's: an outsider's key under the approver's name (claim is the name it signs under).
func (s *system) signedAs(claim string, maxTx, maxRate uint64, seq int64) string {
	s.t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	out := filepath.Join(s.dir, fmt.Sprintf("caps-forged-%s-%d.json", claim, seq))
	if o, err := s.tool("qv-fee-caps", "sign", "-actor", claim, "-key", s.keyFile("forged-"+claim, priv), "-chain", s.chain,
		"-max-tx-fee-sats", fmt.Sprint(maxTx), "-max-fee-rate", fmt.Sprint(maxRate), "-seq", fmt.Sprint(seq), "-out", out); err != nil {
		s.t.Fatalf("sign: %v\n%s", err, o)
	}
	return out
}
