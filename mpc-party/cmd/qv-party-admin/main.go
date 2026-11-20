// Command qv-party-admin is the operator's tool for the MPC parties' signed admin calls: DKG, refresh and unfreeze, and a read-only status.
// An admin call needs the signatures of M of the party's N admin keys (admin_threshold) over ONE request that names everything the call does.
// Creating, signing and sending are separate steps, usually on different machines; the parties verify the signatures themselves:
//
//	qv-party-admin request  -op dkg|refresh|unfreeze -keyset ID [-scheme hd|ecdsa-2of3|ed25519-2of3] [-curve secp256k1|ed25519] [-domain NAME] [-valid-for 1h] [-out F]
//	qv-party-admin sign     -key ADMIN.key -in F [-out F]       each admin, on their own machine: adds a signature, changes nothing else in the file
//	qv-party-admin verify   -in F (-config PARTY.json ... | -admin-key HEX ... -threshold M) [-domain NAME]   anyone: what the file says, who signed, whether a party would take it
//	qv-party-admin pubkey   -key ADMIN.key                      prints the public key (hex) to put in the parties' admin_keys
//	qv-party-admin dkg      -auth F -party A=ADDR@PIN -party B=ADDR@PIN [-party C=...] -cert F -key F (-config PARTY.json ... | -admin-key HEX ... -threshold M)
//	qv-party-admin refresh  -auth F  (the same)
//	qv-party-admin unfreeze -auth F  (the same)
//	qv-party-admin status   (the same -party, -cert and -key flags; no -auth) [-keyset ID]
//
// The file carries the request (keyset and, for a DKG, scheme and curve), the deployment domain, the time it was issued and expires and a nonce;
// every admin signs the same bytes, in any order, and a party rebuilds what was signed from the call it receives, so a changed field, keyset or
// operation fails the signatures. `send` (dkg, refresh, unfreeze) refuses, before it contacts any party, a file with too few signatures, an unknown
// key, a wrong domain or an expired one. The sending commands run inside the parties' network with a caller certificate and hold no signing key.
// A file is accepted once per party. Party A (the first -party, or the one named A) takes the call and tells the others. A server pin is the
// SHA-256 of the party's certificate public key (SPKI), 64 hex chars. Before and after every call the tool asks every named party for its keysets and
// refuses to go on, or to call the outcome good, when they disagree. `sign -op ... -keyset ...` without -in still writes the old v1 file (one
// signature, nothing but operation, keyset and time covered), only for parties that still accept v1 during the roll-over.
// See docs/runbooks/key-ceremony.md.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/ws4charlie/quorum-vault/mpc-party/api/admin"
	wire "github.com/ws4charlie/quorum-vault/mpc-party/api/cosigner"
	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, out, errw io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(errw, "usage: qv-party-admin request|sign|verify|pubkey|dkg|refresh|unfreeze|status (see the file header and docs/runbooks/key-ceremony.md)")
		return 2
	}
	var err error
	switch args[0] {
	case "request":
		err = requestCmd(args[1:], out, errw)
	case "sign":
		err = signCmd(args[1:], out, errw)
	case "verify":
		err = verifyCmd(args[1:], out)
	case "pubkey":
		err = pubkeyCmd(args[1:], out)
	case "dkg", "refresh", "unfreeze":
		err = sendCmd(args[0], args[1:], out, errw)
	case "status":
		err = statusCmd(args[1:], out)
	default:
		err = fmt.Errorf("unknown command %q", args[0])
	}
	if err != nil {
		fmt.Fprintln(errw, "qv-party-admin:", err)
		return 1
	}
	return 0
}

// ---- request, sign, verify ----

func requestCmd(args []string, out, errw io.Writer) error {
	fs := flag.NewFlagSet("request", flag.ContinueOnError)
	fs.SetOutput(errw)
	op := fs.String("op", "", "dkg, refresh or unfreeze")
	keyset := fs.String("keyset", "", "the keyset ID")
	scheme := fs.String("scheme", "hd", "dkg: hd (two-party HD keyset), ecdsa-2of3 or ed25519-2of3")
	curve := fs.String("curve", "secp256k1", "dkg, scheme hd: secp256k1 or ed25519")
	domain := fs.String("domain", "", "the parties' admin_domain (the deployment name); empty when they have none")
	validFor := fs.Duration("valid-for", admin.DefaultValidity, "how long the request stays valid for signing and sending (the parties' admin_max_validity_seconds is the upper limit)")
	outFile := fs.String("out", "", "write the file here (default stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *op == "" || *keyset == "" {
		return errors.New("-op and -keyset are required")
	}
	d := dkgRequest{}
	if *op == admin.OpDKG {
		var err error
		if d, err = dkgFlags(*scheme, *curve); err != nil {
			return err
		}
	}
	now := time.Now()
	r, err := admin.NewRequest(*op, *keyset, *domain, d.scheme, d.curve, now, *validFor)
	if err != nil {
		return err
	}
	fmt.Fprintf(errw, "request: %s of keyset %s\n%s\nvalid until %s: it needs the signatures of the party's admin_threshold admin keys (qv-party-admin sign), then send\n",
		r.Op, r.Keyset, describe(r), time.Unix(r.ExpiresUnix, 0).Format("2006-01-02 15:04:05 MST"))
	if *outFile == "" {
		_, err = out.Write(r.JSON())
		return err
	}
	return os.WriteFile(*outFile, r.JSON(), 0o600)
}

// describe says in words what the signatures cover, so a signer reads what they sign.
func describe(r admin.Request) string {
	s := fmt.Sprintf("  covers: operation %q, keyset %q, domain %q, issued %s, nonce %s\n  request body: %s", r.Op, r.Keyset, r.Domain,
		time.Unix(r.IssuedUnix, 0).Format("15:04:05"), r.Nonce, r.Body)
	return s
}

func signCmd(args []string, out, errw io.Writer) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	fs.SetOutput(errw)
	keyFile := fs.String("key", "", "file with the admin's Ed25519 private key, hex (32-byte seed or 64-byte key)")
	in := fs.String("in", "", "the request file (from `request`, maybe already signed by others) to add this admin's signature to")
	outFile := fs.String("out", "", "write the file here (default: back into -in, or stdout for the old v1 form)")
	op := fs.String("op", "", "OLD v1 form only (no -in): dkg, refresh or unfreeze")
	keyset := fs.String("keyset", "", "OLD v1 form only (no -in): the keyset ID")
	maxAge := fs.Duration("window", admin.DefaultMaxAge, "OLD v1 form only: the parties' admin_max_age_seconds, only to print when the file expires")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyFile == "" {
		return errors.New("-key is required")
	}
	priv, err := admin.ReadKeyFile(*keyFile)
	if err != nil {
		return err
	}
	if *in == "" {
		return signV1(priv, *op, *keyset, *maxAge, *outFile, out, errw)
	}
	raw, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	r, err := admin.ParseRequest(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", *in, err)
	}
	if time.Now().After(time.Unix(r.ExpiresUnix, 0)) {
		return fmt.Errorf("%s expired at %s: create a new request", *in, time.Unix(r.ExpiresUnix, 0).Format(time.RFC3339))
	}
	fmt.Fprintf(errw, "signing: %s\n%s\n", r.Op, describe(r))
	if err := r.Sign(priv); err != nil {
		return err
	}
	fmt.Fprintf(errw, "signatures now: %d (%s)\n", len(r.Signatures), signerList(r))
	dest := *outFile
	if dest == "" {
		dest = *in
	}
	return os.WriteFile(dest, r.JSON(), 0o600)
}

func signerList(r admin.Request) string {
	var l []string
	for _, s := range r.Signatures {
		l = append(l, s.PublicKey[:8]+"...")
	}
	return strings.Join(l, ", ")
}

func signV1(priv ed25519.PrivateKey, op, keyset string, maxAge time.Duration, outFile string, out, errw io.Writer) error {
	if op == "" || keyset == "" {
		return errors.New("-in FILE (a request from `request`) is required; the old v1 form needs -op and -keyset")
	}
	now := time.Now()
	f, err := admin.NewFile(priv, op, keyset, now)
	if err != nil {
		return err
	}
	fmt.Fprintf(errw, "OLD v1 authorisation (one signature, covers only operation, keyset and time; refused by parties with admin_threshold set): %s of keyset %s by operator key %s\nvalid until about %s (%s window, once per party): send it now\n",
		f.Op, f.Keyset, f.PublicKey, now.Add(maxAge).Format("15:04:05 MST"), maxAge)
	if outFile == "" {
		_, err = out.Write(f.JSON())
		return err
	}
	return os.WriteFile(outFile, f.JSON(), 0o600)
}

func pubkeyCmd(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("pubkey", flag.ContinueOnError)
	keyFile := fs.String("key", "", "file with the admin's Ed25519 private key, hex")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyFile == "" {
		return errors.New("-key is required")
	}
	priv, err := admin.ReadKeyFile(*keyFile)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, hex.EncodeToString(priv.Public().(ed25519.PublicKey)))
	return nil
}

// policyFlags are the ways to say what a party needs: its config files, or its admin keys and threshold.
type policyFlags struct {
	configs     stringList
	keys        stringList
	threshold   int
	domain      string
	maxValidity time.Duration
	skew        time.Duration
}

type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, ",") }
func (l *stringList) Set(v string) error { *l = append(*l, v); return nil }

func (p *policyFlags) flags(fs *flag.FlagSet) {
	fs.Var(&p.configs, "config", "a party's config file (repeat for each party): its admin_keys, admin_threshold, admin_domain and limits decide")
	fs.Var(&p.keys, "admin-key", "an admin public key the parties are configured with, 64 hex (repeat for each); with -threshold, instead of -config")
	fs.IntVar(&p.threshold, "threshold", 0, "the parties' admin_threshold; with -admin-key, instead of -config")
	fs.StringVar(&p.domain, "domain", "", "with -admin-key: the parties' admin_domain")
	fs.DurationVar(&p.maxValidity, "max-validity", time.Hour, "with -admin-key: the parties' admin_max_validity_seconds")
	fs.DurationVar(&p.skew, "window", admin.DefaultMaxAge, "the parties' admin_max_age_seconds (the clock skew they tolerate)")
}

// policies gives one policy per party config, or the single one from the flags. It refuses to guess: without either there is nothing to check against.
func (p *policyFlags) policies() ([]admin.Policy, error) {
	switch {
	case len(p.configs) > 0 && (len(p.keys) > 0 || p.threshold > 0):
		return nil, errors.New("give either -config files or -admin-key with -threshold, not both")
	case len(p.configs) > 0:
		var l []admin.Policy
		for _, f := range p.configs {
			raw, err := os.ReadFile(f)
			if err != nil {
				return nil, err
			}
			var c struct {
				Keys      []string `json:"admin_keys"`
				Threshold int      `json:"admin_threshold"`
				MaxAge    int      `json:"admin_max_age_seconds"`
				MaxValid  int      `json:"admin_max_validity_seconds"`
				Domain    string   `json:"admin_domain"`
			}
			if err := json.Unmarshal(raw, &c); err != nil {
				return nil, fmt.Errorf("%s: %w", f, err)
			}
			pol, err := mkPolicy(c.Keys, c.Threshold, c.Domain, time.Duration(c.MaxValid)*time.Second, time.Duration(c.MaxAge)*time.Second)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", f, err)
			}
			l = append(l, pol)
		}
		return l, nil
	case len(p.keys) > 0 && p.threshold > 0:
		pol, err := mkPolicy(p.keys, p.threshold, p.domain, p.maxValidity, p.skew)
		return []admin.Policy{pol}, err
	}
	return nil, errors.New("say what the parties need: -config PARTY.json (each party), or -admin-key HEX (each) with -threshold M")
}

func mkPolicy(keys []string, threshold int, domain string, maxValidity, skew time.Duration) (admin.Policy, error) {
	p := admin.Policy{Threshold: max(threshold, 1), Domain: domain, MaxValidity: maxValidity, Skew: skew}
	if p.MaxValidity <= 0 {
		p.MaxValidity = time.Hour
	}
	if p.Skew <= 0 {
		p.Skew = admin.DefaultMaxAge
	}
	for _, k := range keys {
		b, err := hex.DecodeString(k)
		if err != nil || len(b) != ed25519.PublicKeySize {
			return p, fmt.Errorf("admin key %q is not 32 bytes of hex", k)
		}
		p.Keys = append(p.Keys, b)
	}
	if len(p.Keys) == 0 {
		return p, errors.New("no admin keys")
	}
	if p.Threshold > len(p.Keys) {
		return p, fmt.Errorf("admin_threshold %d is more than the %d admin keys", p.Threshold, len(p.Keys))
	}
	if p.Threshold > admin.MaxSignatures {
		return p, fmt.Errorf("admin_threshold %d is more than the %d signatures one authorization may carry: no request could reach it", p.Threshold, admin.MaxSignatures)
	}
	return p, nil
}

func verifyCmd(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	in := fs.String("in", "", "the request file")
	var pf policyFlags
	pf.flags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" {
		return errors.New("-in is required")
	}
	raw, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	if admin.FileVersion(raw) == 1 {
		return errors.New("this is an old v1 file: it covers only operation, keyset and time and has one signature; it cannot be checked against a quorum")
	}
	r, err := admin.ParseRequest(raw)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "%s\n  signatures that verify: %d (%s)\n", describe(r), len(r.Signatures), signerList(r))
	pols, err := pf.policies()
	if err != nil {
		return err
	}
	for i, p := range pols {
		if err := r.Check(p, time.Now()); err != nil {
			return fmt.Errorf("a party %d of %d would refuse this file: %w", i+1, len(pols), err)
		}
	}
	fmt.Fprintf(out, "OK: every configuration checked (%d) would take it (a party also refuses a file it has already used)\n", len(pols))
	return nil
}

// ---- parties ----

type partyFlag struct {
	name, addr string
	pin        wire.Pin
}

type partyList []partyFlag

func (l *partyList) String() string { return fmt.Sprint(len(*l), " parties") }
func (l *partyList) Set(v string) error {
	name, rest, ok := strings.Cut(v, "=")
	addr, pin, ok2 := strings.Cut(rest, "@")
	if !ok || !ok2 || name == "" || addr == "" {
		return fmt.Errorf("-party %q: want NAME=HOST:PORT@PIN (PIN: sha256 of the party certificate's public key, 64 hex chars)", v)
	}
	p, err := wire.ParsePin(pin)
	if err != nil {
		return err
	}
	for _, e := range *l {
		if e.name == name {
			return fmt.Errorf("-party %s given twice", name)
		}
	}
	*l = append(*l, partyFlag{name, addr, p})
	return nil
}

type conn struct {
	name   string
	client pb.MpcPartyClient
	cc     *grpc.ClientConn
}

type common struct {
	parties partyList
	cert    string
	key     string
	timeout time.Duration
}

func (c *common) flags(fs *flag.FlagSet) {
	fs.Var(&c.parties, "party", "a party's caller address and pin, NAME=HOST:PORT@PIN (repeat for A, B and, with 2-of-3 keysets, C). The coordinator is party A, or the first one if none is named A")
	fs.StringVar(&c.cert, "cert", "", "the caller certificate (PEM) the parties pin")
	fs.StringVar(&c.key, "key", "", "its private key (PEM)")
	fs.DurationVar(&c.timeout, "timeout", 4*time.Minute, "how long to wait for the call")
}

func (c *common) check() error {
	if len(c.parties) == 0 || c.cert == "" || c.key == "" {
		return errors.New("-party (at least one), -cert and -key are required")
	}
	return nil
}

func (c *common) dial() ([]*conn, error) {
	cert, err := tls.LoadX509KeyPair(c.cert, c.key)
	if err != nil {
		return nil, fmt.Errorf("caller certificate: %w", err)
	}
	if err := wire.CheckValid(cert, time.Now()); err != nil {
		return nil, fmt.Errorf("caller certificate: %w", err)
	}
	var cs []*conn
	for _, p := range c.parties {
		creds := credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true, //nolint:gosec // pinned
			VerifyPeerCertificate: wire.VerifyPinned(map[wire.Pin]bool{p.pin: true}, time.Now)})
		cc, err := grpc.NewClient(p.addr, grpc.WithTransportCredentials(creds))
		if err != nil {
			closeAll(cs)
			return nil, fmt.Errorf("party %s: %w", p.name, err)
		}
		cs = append(cs, &conn{p.name, pb.NewMpcPartyClient(cc), cc})
	}
	// the coordinator first
	sort.SliceStable(cs, func(i, j int) bool { return cs[i].name == "A" && cs[j].name != "A" })
	return cs, nil
}

func closeAll(cs []*conn) {
	for _, c := range cs {
		c.cc.Close()
	}
}

// ---- status ----

type view struct {
	name   string
	health *pb.HealthResponse
	err    error
}

func healthOf(ctx context.Context, cs []*conn) []view {
	vs := make([]view, len(cs))
	done := make(chan int, len(cs))
	for i, c := range cs {
		go func() {
			x, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			h, err := c.client.Health(x, &pb.HealthRequest{})
			vs[i] = view{c.name, h, err}
			done <- i
		}()
	}
	for range cs {
		<-done
	}
	return vs
}

func keysetMap(h *pb.HealthResponse) map[string]*pb.KeysetStatus {
	m := map[string]*pb.KeysetStatus{}
	for _, k := range h.Keysets {
		m[k.KeysetId] = k
	}
	return m
}

// compare lists every way the parties disagree about one keyset (only keysets named in want, or all when want is empty), and every party that did not answer.
// ignoreFrozen: an unfreeze starts from parties that disagree about the frozen flag (freeze notices are best effort and the parties' own Unfreeze
// handles members that are not frozen); generation and public key must still agree.
func compare(vs []view, want string, ignoreFrozen bool) []string {
	var bad []string
	ids := map[string]bool{}
	for _, v := range vs {
		if v.err != nil {
			bad = append(bad, fmt.Sprintf("party %s did not answer: %v", v.name, v.err))
			continue
		}
		for id := range keysetMap(v.health) {
			if want == "" || id == want {
				ids[id] = true
			}
		}
	}
	if want != "" {
		ids[want] = ids[want] // keep the name even when no party has it
	}
	var sorted []string
	for id := range ids {
		sorted = append(sorted, id)
	}
	sort.Strings(sorted)
	for _, id := range sorted {
		var ref *pb.KeysetStatus
		var refName string
		for _, v := range vs {
			if v.err != nil {
				continue
			}
			k := keysetMap(v.health)[id]
			if k == nil {
				if v.health.Role == "C" && hdKeyset(vs, id) {
					continue // a two-party HD keyset lives on A and B only
				}
				if ref != nil || hasKeyset(vs, id) {
					bad = append(bad, fmt.Sprintf("keyset %s: party %s does not have it", id, v.name))
				}
				continue
			}
			if !k.Resolved {
				bad = append(bad, fmt.Sprintf("keyset %s: party %s has not reconciled it with its peers yet", id, v.name))
			}
			if ref == nil {
				ref, refName = k, v.name
				continue
			}
			if k.Generation != ref.Generation {
				bad = append(bad, fmt.Sprintf("keyset %s: party %s is at generation %d, party %s at %d", id, v.name, k.Generation, refName, ref.Generation))
			}
			if !ignoreFrozen && k.Frozen != ref.Frozen {
				bad = append(bad, fmt.Sprintf("keyset %s: frozen on party %s=%v but on party %s=%v", id, v.name, k.Frozen, refName, ref.Frozen))
			}
			if k.Scheme != ref.Scheme {
				bad = append(bad, fmt.Sprintf("keyset %s: scheme differs between party %s and party %s", id, v.name, refName))
			}
			if len(k.PublicKey) > 0 && len(ref.PublicKey) > 0 && string(k.PublicKey) != string(ref.PublicKey) {
				bad = append(bad, fmt.Sprintf("keyset %s: the public key of party %s differs from party %s", id, v.name, refName))
			}
		}
	}
	return bad
}

func hdKeyset(vs []view, id string) bool {
	for _, v := range vs {
		if v.err == nil {
			if k := keysetMap(v.health)[id]; k != nil && k.Scheme == pb.Scheme_SCHEME_UNSPECIFIED {
				return true
			}
		}
	}
	return false
}

func hasKeyset(vs []view, id string) bool {
	for _, v := range vs {
		if v.err == nil && keysetMap(v.health)[id] != nil {
			return true
		}
	}
	return false
}

func printStatus(out io.Writer, vs []view, want string) {
	for _, v := range vs {
		if v.err != nil {
			fmt.Fprintf(out, "party %s: UNREACHABLE: %v\n", v.name, v.err)
			continue
		}
		h := v.health
		peers := ""
		for _, p := range h.Peers {
			peers += fmt.Sprintf(" %s=%v", p.Name, p.Reachable)
		}
		if peers == "" {
			peers = fmt.Sprintf(" peer=%v", h.PeerReachable)
		}
		fmt.Fprintf(out, "party %s: role %s, version %s, links%s, %d active sessions\n", v.name, h.Role, h.Version, peers, h.ActiveSessions)
		ks := keysetMap(h)
		var ids []string
		for id := range ks {
			if want == "" || id == want {
				ids = append(ids, id)
			}
		}
		sort.Strings(ids)
		for _, id := range ids {
			k := ks[id]
			pub := hex.EncodeToString(k.PublicKey)
			if pub == "" {
				pub = "-"
			}
			fmt.Fprintf(out, "  keyset %s: generation %d, %s, frozen=%v, resolved=%v, backup generation %d (stale=%v), public key %s\n",
				id, k.Generation, schemeName(k.Scheme), k.Frozen, k.Resolved, k.BackupGeneration, k.BackupStale, pub)
		}
	}
}

func schemeName(s pb.Scheme) string {
	switch s {
	case pb.Scheme_SCHEME_ECDSA_2OF3:
		return "ecdsa-2of3"
	case pb.Scheme_SCHEME_ED25519_2OF3:
		return "ed25519-2of3"
	}
	return "hd"
}

func statusCmd(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	var c common
	c.flags(fs)
	keyset := fs.String("keyset", "", "show only this keyset")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := c.check(); err != nil {
		return err
	}
	cs, err := c.dial()
	if err != nil {
		return err
	}
	defer closeAll(cs)
	vs := healthOf(context.Background(), cs)
	printStatus(out, vs, *keyset)
	bad := compare(vs, *keyset, false)
	if *keyset != "" { // unrelated disagreements are a warning, not a failure
		for _, w := range compare(vs, "", false) {
			if !contains(bad, w) {
				fmt.Fprintln(out, "WARNING (another keyset):", w)
			}
		}
	}
	if len(bad) > 0 {
		return disagree(bad)
	}
	return nil
}

func contains(l []string, x string) bool {
	for _, e := range l {
		if e == x {
			return true
		}
	}
	return false
}

func anyMentions(bad []string, id string) bool {
	for _, b := range bad {
		if strings.Contains(b, "keyset "+id+":") {
			return true
		}
	}
	return false
}

func anyUnanswered(vs []view) bool {
	for _, v := range vs {
		if v.err != nil {
			return true
		}
	}
	return false
}

func disagree(bad []string) error {
	return fmt.Errorf("THE PARTIES DISAGREE, do not go on until this is understood:\n  - %s", strings.Join(bad, "\n  - "))
}

// ---- dkg, refresh, unfreeze ----

func sendCmd(op string, args []string, out, errw io.Writer) error {
	fs := flag.NewFlagSet(op, flag.ContinueOnError)
	fs.SetOutput(errw)
	var c common
	c.flags(fs)
	var pf policyFlags
	pf.flags(fs)
	expectKeyset := fs.String("keyset", "", "the keyset this call is meant for: refused, before any call, when the authorisation file names another (a Job names it so a wrong file cannot act on another keyset)")
	authFile := fs.String("auth", "", "the authorisation file: a request from `qv-party-admin request`, signed by the admin_threshold admins with `sign` (or an old v1 file during the roll-over)")
	scheme := fs.String("scheme", "hd", "dkg: hd (two-party HD keyset), ecdsa-2of3 or ed25519-2of3; must match the request file, which decides")
	curve := fs.String("curve", "secp256k1", "dkg, scheme hd: secp256k1 or ed25519; must match the request file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *authFile == "" {
		return errors.New("-auth is required: a request file signed by the admins (`qv-party-admin request`, then `sign` by each); this command holds no signing key")
	}
	if err := c.check(); err != nil {
		return err
	}
	raw, err := os.ReadFile(*authFile)
	if err != nil {
		return err
	}
	var (
		fkeyset string
		auth    *pb.AdminAuth
		req     dkgRequest
		now     = time.Now()
	)
	switch admin.FileVersion(raw) {
	case 2:
		r, err := admin.ParseRequest(raw)
		if err != nil {
			return fmt.Errorf("%s: %w", *authFile, err)
		}
		if r.Op != op {
			return fmt.Errorf("%s is an authorisation for %s of keyset %s, not for %s", *authFile, r.Op, r.Keyset, op)
		}
		if *expectKeyset != "" && *expectKeyset != r.Keyset {
			return fmt.Errorf("%s is an authorisation for keyset %s, but this call is for keyset %s: nothing was sent", *authFile, r.Keyset, *expectKeyset)
		}
		pols, err := pf.policies()
		if err != nil {
			return err
		}
		for i, p := range pols { // too few signatures, an unknown key, another domain, a stale file: refused here, before any party is contacted
			if err := r.Check(p, now); err != nil {
				return fmt.Errorf("%s would be refused by the parties (configuration %d of %d): %w: nothing was sent", *authFile, i+1, len(pols), err)
			}
		}
		if auth, err = r.Auth(); err != nil {
			return err
		}
		fkeyset = r.Keyset
		if op == admin.OpDKG {
			sch, cur, _ := r.DKGParams()
			req = dkgRequest{sch, cur}
			set := map[string]bool{}
			fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
			if set["scheme"] || set["curve"] {
				want, err := dkgFlags(*scheme, *curve)
				if err != nil {
					return err
				}
				if admin.DKGBody("k", want.scheme, want.curve).Curve != admin.DKGBody("k", sch, cur).Curve || want.scheme != sch {
					return fmt.Errorf("-scheme/-curve differ from the request in %s (%s, %s): the file decides; make a new request to change them", *authFile, schemeName(sch), cur)
				}
			}
		}
	case 1:
		f, err := admin.ReadFile(*authFile)
		if err != nil {
			return err
		}
		fmt.Fprintln(errw, "WARNING: an old v1 file (one signature; it covers only operation, keyset and time): parties with admin_threshold set refuse it")
		if f.Op != op {
			return fmt.Errorf("%s is an authorisation for %s of keyset %s, not for %s", *authFile, f.Op, f.Keyset, op)
		}
		if *expectKeyset != "" && *expectKeyset != f.Keyset {
			return fmt.Errorf("%s is an authorisation for keyset %s, but this call is for keyset %s: nothing was sent", *authFile, f.Keyset, *expectKeyset)
		}
		if age := f.Age(now); age > pf.skew || age < -pf.skew {
			return fmt.Errorf("%s was signed %s ago, outside the %s the parties accept: have the operator sign a new one and send it at once", *authFile, age.Round(time.Second), pf.skew)
		}
		auth, _ = f.Auth()
		fkeyset = f.Keyset
		if op == admin.OpDKG {
			if req, err = dkgFlags(*scheme, *curve); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("%s is not an authorisation file", *authFile)
	}
	f := struct{ Keyset string }{fkeyset}
	cs, err := c.dial()
	if err != nil {
		return err
	}
	defer closeAll(cs)
	ctx := context.Background()

	// before: every named party answers, and they agree
	before := healthOf(ctx, cs)
	// only the keyset this call is about matters: another keyset's trouble does not block it (status shows it as a warning)
	if op == admin.OpDKG {
		for _, v := range before {
			if v.err != nil {
				printStatus(out, before, f.Keyset)
				return disagree(compare(before, f.Keyset, false))
			}
		}
		for _, v := range before {
			if st := keysetMap(v.health)[f.Keyset]; st != nil {
				return fmt.Errorf("keyset %s already exists (generation %d) on party %s: a DKG would not make a new one", f.Keyset, st.Generation, v.name)
			}
		}
	} else {
		if bad := compare(before, f.Keyset, op == admin.OpUnfreeze); len(bad) > 0 {
			printStatus(out, before, f.Keyset)
			return disagree(bad)
		}
		var st *pb.KeysetStatus
		frozen := false
		for _, v := range before {
			if k := keysetMap(v.health)[f.Keyset]; k != nil {
				st = k
				frozen = frozen || k.Frozen
			}
		}
		if st == nil {
			return fmt.Errorf("keyset %s does not exist on the parties", f.Keyset)
		}
		if op == admin.OpRefresh && frozen {
			return fmt.Errorf("keyset %s is frozen: find out why, then unfreeze it, before a refresh", f.Keyset)
		}
		if op == admin.OpUnfreeze && !frozen {
			return fmt.Errorf("keyset %s is not frozen", f.Keyset)
		}
	}

	x, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	coord := cs[0].client
	var callErr error
	var rootPub []byte
	switch op {
	case admin.OpDKG:
		var r *pb.DKGResponse
		r, callErr = coord.DKG(x, &pb.DKGRequest{KeysetId: f.Keyset, Curve: req.curve, Scheme: req.scheme, Admin: auth})
		if callErr == nil {
			rootPub = r.RootPublicKey
		}
	case admin.OpRefresh:
		var r *pb.RefreshResponse
		r, callErr = coord.Refresh(x, &pb.RefreshRequest{KeysetId: f.Keyset, Admin: auth})
		if callErr == nil {
			rootPub = r.RootPublicKey
		}
	case admin.OpUnfreeze:
		_, callErr = coord.Unfreeze(x, &pb.UnfreezeRequest{KeysetId: f.Keyset, Admin: auth})
	}

	// after: the call may have finished on the parties although the answer was lost, so look again either way
	after := healthOf(ctx, cs)
	printStatus(out, after, f.Keyset)
	if callErr != nil {
		return fmt.Errorf("%s of keyset %s through party %s: %w\n(the status above is what the parties report now; the authorisation may be used up: sign a new one before trying again)", op, f.Keyset, cs[0].name, callErr)
	}
	if bad := compare(after, f.Keyset, false); len(bad) > 0 {
		return disagree(bad)
	}
	k := keysetMap(after[0].health)[f.Keyset]
	if k == nil {
		return fmt.Errorf("the call succeeded but party %s does not report keyset %s", cs[0].name, f.Keyset)
	}
	switch op {
	case admin.OpUnfreeze:
		if k.Frozen {
			return fmt.Errorf("the call succeeded but keyset %s is still frozen on party %s", f.Keyset, cs[0].name)
		}
		fmt.Fprintf(out, "OK unfreeze: keyset %s is not frozen on any of the %d parties\n", f.Keyset, len(cs))
	default:
		pub := rootPub
		if len(k.PublicKey) > 0 {
			pub = k.PublicKey
		}
		fmt.Fprintf(out, "OK %s: keyset %s generation %d\nroot_public_key: %s\n", op, f.Keyset, k.Generation, hex.EncodeToString(pub))
	}
	return nil
}

type dkgRequest struct {
	scheme pb.Scheme
	curve  pb.Curve
}

func dkgFlags(scheme, curve string) (dkgRequest, error) {
	switch scheme {
	case "hd":
		switch curve {
		case "secp256k1":
			return dkgRequest{pb.Scheme_SCHEME_UNSPECIFIED, pb.Curve_CURVE_SECP256K1}, nil
		case "ed25519":
			return dkgRequest{pb.Scheme_SCHEME_UNSPECIFIED, pb.Curve_CURVE_ED25519}, nil
		}
		return dkgRequest{}, errors.New("-curve: secp256k1 or ed25519")
	case "ecdsa-2of3":
		return dkgRequest{pb.Scheme_SCHEME_ECDSA_2OF3, pb.Curve_CURVE_UNSPECIFIED}, nil
	case "ed25519-2of3":
		return dkgRequest{pb.Scheme_SCHEME_ED25519_2OF3, pb.Curve_CURVE_UNSPECIFIED}, nil
	}
	return dkgRequest{}, errors.New("-scheme: hd, ecdsa-2of3 or ed25519-2of3")
}
