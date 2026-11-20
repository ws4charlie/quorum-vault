// Package approvecli is qv-approve: an approver's command-line client. It fetches a withdrawal's intent from the core, recomputes the hash from the
// canonical bytes, prints every field in plain words, and asks a FIDO2 security key to sign the hash (WebAuthn, challenge = the hash, user
// verification required). It is the "small client on a minimal approver machine" of research/SPIRE-and-YubiKey.md section 2.2: a browser is a large
// thing to trust, and this is not. It still trusts its own host: see docs/runbooks/webauthn-approver.md for what that does and does not buy.
//
// The key sits behind ctap.Authenticator and the login behind TokenFunc, so tests run the whole path with a software key (internal/ctap/ctaptest,
// never linked into cmd/qv-approve).
package approvecli

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/ctap"
)

// Env is what the CLI runs on. Zero values are the production ones.
type Env struct {
	Key    ctap.Authenticator // nil: the libfido2 tools (ctap.Tools)
	Token  TokenFunc          // nil: the OIDC loopback login
	HTTP   *http.Client       // nil: built from -ca-file
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

const usage = `usage: qv-approve <command> [flags]

  show <withdrawal>      fetch the intent, recompute its hash, print every field
  approve <withdrawal>   the same, then ask the security key to approve it
  enrol                  make a credential on the security key and print the approver entry for the operators

flags (each also has an environment variable):
  -api URL            the core API (QV_API)
  -issuer URL         the OIDC issuer (QV_OIDC_ISSUER)
  -client-id ID       the public OIDC client of this CLI (QV_APPROVE_CLIENT_ID, default qv-approve)
  -ca-file FILE       the CA that signs the core's and the issuer's certificates (QV_OIDC_CA_FILE)
  -origin ORIGIN      the origin written into the assertion; it must be in the zone's list for you (QV_APPROVE_ORIGIN)
  -rp-id ID           the relying party id (default: the host of the origin)
  -entry FILE         your approver entry, as 'enrol' printed it: credential id, rp id and origin
  -credential-id ID   your credential id, base64url (instead of -entry)
  -device PATH        the key's device path (default: the one key that is plugged in)
  -tools-dir DIR      where fido2-token, fido2-cred and fido2-assert are (default: PATH)
  -asset-decimals S   decimals to show amounts with, e.g. ETH=18,USDT=6
approve: -yes skips the typed confirmation.  enrol: -identity NAME, -out FILE.
`

type options struct {
	api, issuer, clientID, caFile, origin, rpID, entry, credID, device, toolsDir, decimals string
	yes                                                                                    bool
	identity, out                                                                          string
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// Run runs one command and returns the process exit code.
func Run(ctx context.Context, args []string, env Env) int {
	if env.Stdin == nil {
		env.Stdin = os.Stdin
	}
	if env.Stdout == nil {
		env.Stdout = os.Stdout
	}
	if env.Stderr == nil {
		env.Stderr = os.Stderr
	}
	if len(args) == 0 || args[0] == "-h" || args[0] == "help" {
		fmt.Fprint(env.Stderr, usage)
		return 2
	}
	cmd, args := args[0], args[1:]
	if cmd != "show" && cmd != "approve" && cmd != "enrol" {
		fmt.Fprintf(env.Stderr, "qv-approve: unknown command %q\n\n%s", cmd, usage)
		return 2
	}
	var o options
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	fs.StringVar(&o.api, "api", envOr("QV_API", ""), "")
	fs.StringVar(&o.issuer, "issuer", envOr("QV_OIDC_ISSUER", ""), "")
	fs.StringVar(&o.clientID, "client-id", envOr("QV_APPROVE_CLIENT_ID", "qv-approve"), "")
	fs.StringVar(&o.caFile, "ca-file", envOr("QV_OIDC_CA_FILE", ""), "")
	fs.StringVar(&o.origin, "origin", envOr("QV_APPROVE_ORIGIN", ""), "")
	fs.StringVar(&o.rpID, "rp-id", "", "")
	fs.StringVar(&o.entry, "entry", "", "")
	fs.StringVar(&o.credID, "credential-id", "", "")
	fs.StringVar(&o.device, "device", "", "")
	fs.StringVar(&o.toolsDir, "tools-dir", "", "")
	fs.StringVar(&o.decimals, "asset-decimals", "", "")
	fs.BoolVar(&o.yes, "yes", false, "")
	fs.StringVar(&o.identity, "identity", "", "")
	fs.StringVar(&o.out, "out", "", "")
	// Flags may come before or after the withdrawal id.
	var pos []string
	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			return 2
		}
		if fs.NArg() == 0 {
			break
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
	c := &cli{o: o, env: env, cmd: cmd}
	var err error
	switch cmd {
	case "show", "approve":
		if len(pos) != 1 {
			fmt.Fprintf(env.Stderr, "qv-approve %s: give exactly one withdrawal id\n", cmd)
			return 2
		}
		err = c.showOrApprove(ctx, pos[0])
	case "enrol":
		if len(pos) != 0 {
			fmt.Fprintln(env.Stderr, "qv-approve enrol: takes no argument")
			return 2
		}
		err = c.enrol(ctx)
	}
	if err != nil {
		fmt.Fprintf(env.Stderr, "qv-approve: %v\n", err)
		return 1
	}
	return 0
}

type cli struct {
	o   options
	env Env
	cmd string
	hc  *http.Client
	tok string
}

func (c *cli) out(f string, a ...any) { fmt.Fprintf(c.env.Stdout, f, a...) }

func (c *cli) client() (*http.Client, error) {
	if c.hc != nil {
		return c.hc, nil
	}
	if c.env.HTTP != nil {
		c.hc = c.env.HTTP
		return c.hc, nil
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.o.caFile != "" {
		pem, err := os.ReadFile(c.o.caFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s holds no certificate", c.o.caFile)
		}
		tc.RootCAs = pool
	}
	c.hc = &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{TLSClientConfig: tc},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return c.hc, nil
}

func (c *cli) token(ctx context.Context) (string, error) {
	if c.tok != "" {
		return c.tok, nil
	}
	var err error
	if c.env.Token != nil {
		c.tok, err = c.env.Token(ctx)
	} else {
		var hc *http.Client
		if hc, err = c.client(); err == nil {
			c.tok, err = loopbackLogin(ctx, hc, c.o.issuer, c.o.clientID, c.env.Stdout)
		}
	}
	return c.tok, err
}

func (c *cli) key() ctap.Authenticator {
	if c.env.Key != nil {
		return c.env.Key
	}
	return &ctap.Tools{Dir: c.o.toolsDir, Device: c.o.device, Notify: func(s string) { fmt.Fprintln(c.env.Stdout, s) }}
}

// where works out the relying party id, the origin and the credential id from the flags and the entry file. Flags win.
func (c *cli) where(needCred bool) (rpID, origin string, credID []byte, err error) {
	origin, rpID = c.o.origin, c.o.rpID
	var e struct {
		CredentialID string   `json:"credential_id"`
		RPID         string   `json:"rp_id"`
		Origins      []string `json:"origins"`
	}
	if c.o.entry != "" {
		b, err := os.ReadFile(c.o.entry)
		if err != nil {
			return "", "", nil, err
		}
		if err := json.Unmarshal(b, &e); err != nil {
			return "", "", nil, fmt.Errorf("%s: %w", c.o.entry, err)
		}
		if origin == "" && len(e.Origins) > 0 {
			origin = e.Origins[0]
		}
		if rpID == "" {
			rpID = e.RPID
		}
	}
	if origin == "" {
		return "", "", nil, errors.New("give the origin (-origin, or -entry with an origin): it must be one the signing zone lists for you")
	}
	u, perr := url.Parse(origin)
	if perr != nil || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.User != nil {
		return "", "", nil, fmt.Errorf("origin %q must look like https://approve.example.com", origin)
	}
	if u.Scheme != "https" && !strings.HasPrefix(origin, "http://localhost") { // the zone's own rule (internal/gateway config)
		return "", "", nil, fmt.Errorf("origin %q must be https (or http://localhost for tests): the zone refuses any other", origin)
	}
	if rpID == "" {
		rpID = u.Hostname()
	}
	if needCred {
		id := c.o.credID
		if id == "" {
			id = e.CredentialID
		}
		if credID, err = base64.RawURLEncoding.DecodeString(id); err != nil || len(credID) == 0 {
			return "", "", nil, errors.New("give your credential id (-credential-id, or -entry from 'enrol')")
		}
	}
	return rpID, origin, credID, nil
}

func parseDecimals(s string) (map[string]int, error) {
	m := map[string]int{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		k, v, ok := strings.Cut(p, "=")
		n, err := strconv.Atoi(v)
		if !ok || err != nil || n < 0 || n > 36 {
			return nil, fmt.Errorf("-asset-decimals: %q is not SYMBOL=digits", p)
		}
		m[k] = n
	}
	return m, nil
}

// core calls the core API with the approver's token and returns the status and body.
func (c *cli) core(ctx context.Context, method, path string, body any) (int, http.Header, []byte, error) {
	if c.o.api == "" {
		return 0, nil, nil, errors.New("give the core address (-api or QV_API)")
	}
	tok, err := c.token(ctx)
	if err != nil {
		return 0, nil, nil, err
	}
	hc, err := c.client()
	if err != nil {
		return 0, nil, nil, err
	}
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.o.api, "/")+path, rd)
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := hc.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, resp.Header, b, nil
}

func errText(b []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(b, &e)
	return e.Error
}

// fetch gets the intent of a withdrawal and checks it.
func (c *cli) fetch(ctx context.Context, id string) (*Checked, error) {
	code, hdr, b, err := c.core(ctx, http.MethodGet, "/v2/withdrawals/"+url.PathEscape(id)+"/intent", nil)
	if err != nil {
		return nil, err
	}
	if code == http.StatusUnauthorized && strings.Contains(hdr.Get("WWW-Authenticate"), "insufficient_user_authentication") {
		return nil, errors.New("the core wants a fresher sign-in: run the command again and sign in when asked")
	}
	if code != 200 {
		return nil, fmt.Errorf("the core answered %d: %s", code, errText(b))
	}
	var r struct {
		Hash      string `json:"hash"`
		Canonical string `json:"canonical"`
		Required  int    `json:"approvals_required"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("the core's answer is not JSON: %w", err)
	}
	ch, err := CheckIntent(r.Canonical, r.Hash, id)
	if err != nil {
		return nil, fmt.Errorf("REFUSED. %w. Nothing was signed", err)
	}
	ch.Required = r.Required
	return ch, nil
}

func (c *cli) print(ch *Checked, decimals map[string]int) {
	i := ch.Intent
	c.out("\n%s\n\n", ch.Sentence(decimals))
	row := func(k, v string) { c.out("  %-16s %s\n", k, v) }
	row("Withdrawal", i.ID)
	row("Amount", amountText(i.Amount, i.Asset, decimals))
	row("Asset", i.Asset)
	row("Pay to", i.To)
	row("Chain", i.Chain)
	row("Pool", i.Partition+" (from "+i.From+")")
	row("Requested by", i.RequestedBy)
	row("Valid until", time.Unix(i.NotAfter, 0).UTC().Format(time.RFC3339))
	if ch.Required > 0 {
		row("Approvals needed", strconv.Itoa(ch.Required))
	}
	row("Hash you sign", hex.EncodeToString(ch.Hash[:]))
	c.out("\nThe hash was computed here from the intent above and equals the hash the core sent.\nCompare the payee and amount with the request you received through another channel.\n")
}

func (c *cli) showOrApprove(ctx context.Context, id string) error {
	decimals, err := parseDecimals(c.o.decimals)
	if err != nil {
		return err
	}
	var rpID, origin string
	var credID []byte
	if c.cmd == "approve" {
		if rpID, origin, credID, err = c.where(true); err != nil {
			return err
		}
	}
	ch, err := c.fetch(ctx, id)
	if err != nil {
		return err
	}
	c.print(ch, decimals)
	if c.cmd == "show" {
		return nil
	}
	tok, err := c.token(ctx)
	if err != nil {
		return err
	}
	actor, err := subjectOf(tok)
	if err != nil {
		return err
	}
	if ch.Intent.RequestedBy == actor {
		return errors.New("you requested this withdrawal: you cannot approve it")
	}
	if !c.o.yes {
		short := hex.EncodeToString(ch.Hash[:])[:8]
		c.out("\nTo approve, type the first 8 characters of the hash (%s): ", short)
		line, _ := bufio.NewReader(c.env.Stdin).ReadString('\n')
		if strings.TrimSpace(line) != short {
			return errors.New("not approved: the confirmation did not match")
		}
	}
	// What a browser would write into clientDataJSON; the origin is the one this CLI is configured with.
	cd, _ := json.Marshal(struct {
		Type        string `json:"type"`
		Challenge   string `json:"challenge"`
		Origin      string `json:"origin"`
		CrossOrigin bool   `json:"crossOrigin"`
	}{"webauthn.get", base64.RawURLEncoding.EncodeToString(ch.Hash[:]), origin, false})
	req := ctap.AssertRequest{RPID: rpID, CredentialID: credID, ClientDataHash: sha256.Sum256(cd)}
	as, err := c.key().GetAssertion(ctx, req)
	if err != nil {
		return fmt.Errorf("the key gave no assertion: %w", err)
	}
	flags, err := ctap.ParseAssertion(req, as)
	if err != nil {
		return err
	}
	if flags&ctap.FlagUV == 0 {
		fmt.Fprintln(c.env.Stderr, "WARNING: the key did not report user verification (no PIN or biometric). The signing zone will refuse this approval.")
	}
	b64 := base64.RawURLEncoding.EncodeToString
	code, hdr, b, err := c.core(ctx, http.MethodPost, "/v2/withdrawals/"+url.PathEscape(id)+"/approvals", map[string]any{
		"actor":    actor,
		"webauthn": map[string]string{"credential_id": b64(credID), "authenticator_data": b64(as.AuthData), "client_data_json": b64(cd), "signature": b64(as.Signature)},
	})
	if err != nil {
		return err
	}
	switch {
	case code == http.StatusUnauthorized && strings.Contains(hdr.Get("WWW-Authenticate"), "insufficient_user_authentication"):
		return errors.New("the core wants a fresher sign-in: run the command again and sign in when asked")
	case code != 200:
		return fmt.Errorf("not approved: the core answered %d: %s", code, errText(b))
	}
	var ok struct {
		Approvals int `json:"approvals"`
	}
	_ = json.Unmarshal(b, &ok)
	c.out("\nApproval accepted by the core (approvals so far: %d).\nThe core only stores it. The signing zone checks it when it signs: if the origin, credential or user verification is wrong, the withdrawal fails with 'gateway refused'. Check its status.\n", ok.Approvals)
	return nil
}

func (c *cli) enrol(ctx context.Context) error {
	rpID, origin, _, err := c.where(false)
	if err != nil {
		return err
	}
	identity := c.o.identity
	if identity == "" {
		tok, err := c.token(ctx)
		if err != nil {
			return err
		}
		if identity, err = subjectOf(tok); err != nil {
			return err
		}
	}
	chal := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, chal); err != nil {
		return err
	}
	cd, _ := json.Marshal(map[string]any{"type": "webauthn.create", "challenge": base64.RawURLEncoding.EncodeToString(chal), "origin": origin, "crossOrigin": false})
	uid := sha256.Sum256([]byte(identity))
	req := ctap.MakeRequest{RPID: rpID, UserName: identity, UserID: uid[:], ClientDataHash: sha256.Sum256(cd), Algs: []ctap.Alg{ctap.EdDSA, ctap.ES256}}
	res, err := c.key().MakeCredential(ctx, req)
	if err != nil {
		return fmt.Errorf("the key made no credential: %w", err)
	}
	cred, err := ctap.ParseAttestation(req, res)
	if err != nil {
		return err
	}
	entry := map[string]any{"scheme": "webauthn", "alg": cred.Alg.Name(), "public_key": cred.PublicKeyHex,
		"credential_id": base64.RawURLEncoding.EncodeToString(cred.CredentialID), "rp_id": rpID, "origins": []string{origin}, "identity": identity, "enabled": true}
	eb, _ := json.MarshalIndent(entry, "", "  ")
	if c.o.out != "" {
		if err := os.WriteFile(c.o.out, append(eb, '\n'), 0o644); err != nil {
			return err
		}
	}
	a := cred.Attestation
	c.out("\nCredential made for %s on %s (user verification was required and reported).\n\nWhat the key said about itself (not checked against the FIDO Metadata Service; compare by hand):\n", identity, rpID)
	row := func(k, v string) {
		if v != "" {
			c.out("  %-22s %s\n", k, v)
		}
	}
	row("AAGUID (model)", formatAAGUID(cred.AAGUID))
	row("Attestation format", a.Format)
	row("Attestation type", a.Type)
	row("Attestation signature", a.SignatureCheck)
	row("Certificate subject", a.CertSubject)
	row("Certificate issuer", a.CertIssuer)
	row("Certificate serial", a.CertSerial)
	row("Certificate SHA-256", a.CertSHA256)
	row("Certificate AAGUID", a.CertAAGUID)
	row("Certificate expires", a.CertNotAfter)
	row("Signature counter", strconv.FormatUint(uint64(cred.SignCount), 10))
	c.out("\nApprover entry for the operators (sign it into the zone: qv-approvers sign -action enrol -name %s -approver-file <file> ...):\n\n%s\n", identity, eb)
	if c.o.out != "" {
		c.out("\n(also written to %s)\n", c.o.out)
	}
	return nil
}

func formatAAGUID(a [16]byte) string {
	h := hex.EncodeToString(a[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}
