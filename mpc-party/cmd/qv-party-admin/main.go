// Command qv-party-admin is the operator's tool for the MPC parties' signed admin calls: DKG, refresh and unfreeze, and a read-only status.
// Signing and sending are two steps on two machines, and the parties verify the signature themselves:
//
//	qv-party-admin sign     -key OPERATOR.key -op dkg|refresh|unfreeze -keyset ID [-out F]     on the operator's own machine; holds the only signing key
//	qv-party-admin dkg      -auth F -party A=ADDR@PIN -party B=ADDR@PIN [-party C=...] -cert F -key F [-scheme hd|ecdsa-2of3|ed25519-2of3] [-curve secp256k1|ed25519]
//	qv-party-admin refresh  -auth F  (the same -party, -cert and -key flags)
//	qv-party-admin unfreeze -auth F  (the same)
//	qv-party-admin status   (the same -party, -cert and -key flags; no -auth) [-keyset ID]
//
// The three sending commands run inside the parties' network with a caller certificate; they hold no signing key. The file is valid for the
// parties' own window (admin_max_age_seconds, 300 s by default) and is accepted once per party. Party A (the first -party, or the one
// named A) takes the call and tells the others. A server pin is the SHA-256 of the party's certificate public key (SPKI), 64 hex chars.
// Before and after every call the tool asks every named party for its keysets and refuses to go on, or to call the outcome good, when they disagree.
// See docs/runbooks/key-ceremony.md.
package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
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
		fmt.Fprintln(errw, "usage: qv-party-admin sign|dkg|refresh|unfreeze|status (see the file header and docs/runbooks/key-ceremony.md)")
		return 2
	}
	var err error
	switch args[0] {
	case "sign":
		err = signCmd(args[1:], out, errw)
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

// ---- sign ----

func signCmd(args []string, out, errw io.Writer) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	fs.SetOutput(errw)
	keyFile := fs.String("key", "", "file with the operator's Ed25519 private key, hex (32-byte seed or 64-byte key)")
	op := fs.String("op", "", "dkg, refresh or unfreeze")
	keyset := fs.String("keyset", "", "the keyset ID")
	maxAge := fs.Duration("window", admin.DefaultMaxAge, "the parties' admin_max_age_seconds, only to print when the file expires")
	outFile := fs.String("out", "", "write the file here (default stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyFile == "" || *op == "" || *keyset == "" {
		return errors.New("-key, -op and -keyset are required")
	}
	priv, err := admin.ReadKeyFile(*keyFile)
	if err != nil {
		return err
	}
	now := time.Now()
	f, err := admin.NewFile(priv, *op, *keyset, now)
	if err != nil {
		return err
	}
	fmt.Fprintf(errw, "authorisation: %s of keyset %s by operator key %s\nvalid until about %s (%s window, once per party): send it now\n",
		f.Op, f.Keyset, f.PublicKey, now.Add(*maxAge).Format("15:04:05 MST"), *maxAge)
	if *outFile == "" {
		_, err = out.Write(f.JSON())
		return err
	}
	return os.WriteFile(*outFile, f.JSON(), 0o600)
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
func compare(vs []view, want string) []string {
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
			if k.Frozen != ref.Frozen {
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
	if bad := compare(vs, ""); len(bad) > 0 && (*keyset == "" || anyMentions(bad, *keyset) || anyUnanswered(vs)) {
		return disagree(bad)
	}
	return nil
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
	authFile := fs.String("auth", "", "the authorisation file `qv-party-admin sign` wrote for this operation (valid for the parties' window, once per party)")
	maxAge := fs.Duration("window", admin.DefaultMaxAge, "the parties' admin_max_age_seconds: a file older than this is refused here without a call")
	scheme := fs.String("scheme", "hd", "dkg: hd (two-party HD keyset), ecdsa-2of3 or ed25519-2of3")
	curve := fs.String("curve", "secp256k1", "dkg, scheme hd: secp256k1 or ed25519")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *authFile == "" {
		return errors.New("-auth is required: an operator's file from `qv-party-admin sign` on their own machine; this command holds no signing key")
	}
	if err := c.check(); err != nil {
		return err
	}
	f, err := admin.ReadFile(*authFile)
	if err != nil {
		return err
	}
	if f.Op != op {
		return fmt.Errorf("%s is an authorisation for %s of keyset %s, not for %s", *authFile, f.Op, f.Keyset, op)
	}
	now := time.Now()
	if age := f.Age(now); age > *maxAge || age < -*maxAge {
		return fmt.Errorf("%s was signed %s ago, outside the %s the parties accept: have the operator sign a new one and send it at once", *authFile, age.Round(time.Second), *maxAge)
	}
	auth, _ := f.Auth()
	req := dkgRequest{}
	if op == admin.OpDKG {
		if req, err = dkgFlags(*scheme, *curve); err != nil {
			return err
		}
	}
	cs, err := c.dial()
	if err != nil {
		return err
	}
	defer closeAll(cs)
	ctx := context.Background()

	// before: every named party answers, and they agree
	before := healthOf(ctx, cs)
	if bad := compare(before, ""); len(bad) > 0 {
		printStatus(out, before, f.Keyset)
		return disagree(bad)
	}
	st := keysetMap(before[0].health)[f.Keyset]
	switch op {
	case admin.OpDKG:
		if st != nil {
			return fmt.Errorf("keyset %s already exists (generation %d) on the parties: a DKG would not make a new one", f.Keyset, st.Generation)
		}
	case admin.OpRefresh:
		if st == nil {
			return fmt.Errorf("keyset %s does not exist on the parties", f.Keyset)
		}
		if st.Frozen {
			return fmt.Errorf("keyset %s is frozen: find out why, then unfreeze it, before a refresh", f.Keyset)
		}
	case admin.OpUnfreeze:
		if st == nil {
			return fmt.Errorf("keyset %s does not exist on the parties", f.Keyset)
		}
		if !st.Frozen {
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
	if bad := compare(after, f.Keyset); len(bad) > 0 {
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
