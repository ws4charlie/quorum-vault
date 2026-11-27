package approvecli_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/approvecli"
	"github.com/ws4charlie/quorum-vault/internal/ctap"
	"github.com/ws4charlie/quorum-vault/internal/ctap/ctaptest"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
	"github.com/ws4charlie/quorum-vault/internal/webauthn"
)

// SIMULATED throughout: a software key, a fake core and a fake identity provider. The end-to-end tests against the real core and zone are in
// e2e/custody (yubikey_cli_test.go).

const origin = "https://approve.example.com"

func jwt(sub string) string {
	b, _ := json.Marshal(map[string]any{"sub": sub})
	return "x." + base64.RawURLEncoding.EncodeToString(b) + ".y"
}

// fakeCore serves the intent of withdrawal "w1" and records approvals.
type fakeCore struct {
	srv       *httptest.Server
	intent    signjob.Intent
	tamper    func(m map[string]any)
	approvals []map[string]any
	status    int // status of the approvals route; 0 = 200
	challenge string
}

func newCore(t *testing.T) *fakeCore {
	f := &fakeCore{intent: signjob.Intent{Kind: "withdrawal", ID: "w1", PartitionID: "pool-1", Chain: "eth-dev", Asset: "ETH", From: "0xhot", To: "0xdest",
		Amount: "2000000000000000000", NotAfter: 1900000000, RequestedBy: "alice"}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v2/withdrawals/{id}/intent", func(w http.ResponseWriter, r *http.Request) {
		in := f.intent
		in.ID = r.PathValue("id")
		h := in.Hash()
		m := map[string]any{"intent": in, "hash": hex.EncodeToString(h[:]), "canonical": hex.EncodeToString(in.Canonical()), "approvals_required": 2}
		if f.tamper != nil {
			f.tamper(m)
		}
		json.NewEncoder(w).Encode(m)
	})
	mux.HandleFunc("POST /v2/withdrawals/{id}/approvals", func(w http.ResponseWriter, r *http.Request) {
		if f.status != 0 {
			if f.challenge != "" {
				w.Header().Set("WWW-Authenticate", f.challenge)
			}
			w.WriteHeader(f.status)
			io.WriteString(w, `{"error":"no"}`)
			return
		}
		var m map[string]any
		json.NewDecoder(r.Body).Decode(&m)
		m["_auth"] = r.Header.Get("Authorization")
		f.approvals = append(f.approvals, m)
		io.WriteString(w, `{"approvals":1}`)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

type result struct {
	code     int
	out, err string
}

func run(t *testing.T, key ctap.Authenticator, tok string, in string, args ...string) result {
	t.Helper()
	var out, errb bytes.Buffer
	env := approvecli.Env{Key: key, Token: func(context.Context) (string, error) { return tok, nil }, Stdin: strings.NewReader(in), Stdout: &out, Stderr: &errb}
	code := approvecli.Run(context.Background(), args, env)
	return result{code, out.String(), errb.String()}
}

func enrol(t *testing.T, s *ctaptest.Soft, identity string) (entryFile string, entry map[string]any) {
	t.Helper()
	entryFile = filepath.Join(t.TempDir(), "entry.json")
	r := run(t, s, jwt(identity), "", "enrol", "-origin", origin, "-out", entryFile)
	if r.code != 0 {
		t.Fatalf("enrol: %d %s %s", r.code, r.out, r.err)
	}
	b, _ := os.ReadFile(entryFile)
	if err := json.Unmarshal(b, &entry); err != nil {
		t.Fatal(err)
	}
	return entryFile, entry
}

// zoneKey reads an approver entry the way the zone does (internal/gateway ApproverFile.webauthnKey) for the verifier.
func zoneKey(t *testing.T, e map[string]any) *webauthn.Key {
	t.Helper()
	raw, _ := hex.DecodeString(e["public_key"].(string))
	cred, _ := base64.RawURLEncoding.DecodeString(e["credential_id"].(string))
	k := &webauthn.Key{Alg: e["alg"].(string), CredentialID: cred, RPID: e["rp_id"].(string), Origins: []string{e["origins"].([]any)[0].(string)}}
	if k.Alg == "ES256" {
		x, y := elliptic.Unmarshal(elliptic.P256(), raw)
		k.ES256 = &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	} else {
		k.Ed25519 = ed25519.PublicKey(raw)
	}
	return k
}

func TestEnrolPrintsEntryAndAttestationFacts(t *testing.T) {
	s := ctaptest.New()
	file, e := enrol(t, s, "bob")
	if e["scheme"] != "webauthn" || e["alg"] != "EdDSA" || e["rp_id"] != "approve.example.com" || e["identity"] != "bob" || e["enabled"] != true {
		t.Fatalf("entry %v", e)
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatal(err)
	}
	r := run(t, s, jwt("bob"), "", "enrol", "-origin", origin)
	for _, want := range []string{"AAGUID (model)", "Attestation type", "basic", "valid (signed by the certificate above)", "Certificate SHA-256", "compare by hand"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("enrol output lacks %q:\n%s", want, r.out)
		}
	}
	// An older key without EdDSA gets ES256.
	old := ctaptest.New()
	old.Algs = []ctap.Alg{ctap.ES256}
	if _, e := enrol(t, old, "bob"); e["alg"] != "ES256" || len(e["public_key"].(string)) != 130 {
		t.Fatalf("ES256 entry %v", e)
	}
	// A key that skips user verification is not enrolled.
	noUV := ctaptest.New()
	noUV.NoUV = true
	if r := run(t, noUV, jwt("bob"), "", "enrol", "-origin", origin); r.code == 0 || !strings.Contains(r.err, "did not verify the user") || strings.Contains(r.out, "approver entry") {
		t.Fatalf("no UV: %+v", r)
	}
	// An origin the zone would refuse is refused at once, by the zone's own rule (internal/weborigin).
	if r := run(t, s, jwt("bob"), "", "enrol", "-origin", "http://evil.example"); r.code == 0 || !strings.Contains(r.err, "must be https") {
		t.Fatalf("http origin: %+v", r)
	}
}

// TestEnrolRefusesWhatTheZoneRefuses: enrol checks the origin with the zone's rule and the same QV_ENV switch. On 0b9b109 it used
// strings.HasPrefix(origin, "http://localhost"), so it enrolled http://localhost.evil.example, http in production, and
// non-canonical origins that the zone never matches.
func TestEnrolRefusesWhatTheZoneRefuses(t *testing.T) {
	s := ctaptest.New()
	for _, env := range []string{"", "dev"} {
		t.Setenv("QV_ENV", env)
		refused := map[string]string{
			"http://localhost.evil.example": "must be https",
			"https://A.example":             `write "https://a.example"`,
			"https://a.example:443":         `write "https://a.example"`,
			"https://bücher.example":        "punycode",
		}
		if env == "" {
			refused["http://localhost:8080"] = "refused in production"
		}
		for o, want := range refused {
			if r := run(t, s, jwt("bob"), "", "enrol", "-origin", o); r.code == 0 || !strings.Contains(r.err, want) || strings.Contains(r.out, "approver entry") {
				t.Errorf("QV_ENV=%q origin %q: want refused with %q, got %+v", env, o, want, r)
			}
		}
	}
	// In dev, the loopback http origin passes the origin check (and the enrolment goes on).
	t.Setenv("QV_ENV", "dev")
	if r := run(t, s, jwt("bob"), "", "enrol", "-origin", "http://localhost:8080"); r.code != 0 || !strings.Contains(r.out, "Credential made") {
		t.Fatalf("dev loopback origin refused: %+v", r)
	}
}

func TestShowRecomputesAndPrintsEveryField(t *testing.T) {
	f := newCore(t)
	r := run(t, nil, jwt("bob"), "", "show", "w1", "-api", f.srv.URL, "-asset-decimals", "ETH=18")
	if r.code != 0 {
		t.Fatalf("%+v", r)
	}
	h := f.intent.Hash() // f.intent.ID is "w1"
	for _, want := range []string{"Send 2 ETH (2000000000000000000 base units) to 0xdest on eth-dev", "pool-1", "alice", "2030-03-17", "Approvals needed 2", hex.EncodeToString(h[:])} {
		if !strings.Contains(r.out, want) {
			t.Errorf("show output lacks %q:\n%s", want, r.out)
		}
	}
}

func TestShowRefusesALyingCore(t *testing.T) {
	cases := map[string]func(m map[string]any){
		"hash changed": func(m map[string]any) { h := m["hash"].(string); m["hash"] = "0" + h[1:] },
		"canonical changed, hash of the old one": func(m map[string]any) {
			b, _ := hex.DecodeString(m["canonical"].(string))
			m["canonical"] = hex.EncodeToString(bytes.Replace(b, []byte("0xdest"), []byte("0xevil"), 1))
		},
		"another withdrawal": func(m map[string]any) {
			in := signjob.Intent{Kind: "withdrawal", ID: "w2", PartitionID: "p", Chain: "c", Asset: "ETH", To: "0xdest", Amount: "1", NotAfter: 1, RequestedBy: "alice"}
			h := in.Hash()
			m["canonical"], m["hash"] = hex.EncodeToString(in.Canonical()), hex.EncodeToString(h[:])
		},
		"not an intent": func(m map[string]any) {
			m["canonical"] = hex.EncodeToString([]byte("pay mallory"))
			h := sha256.Sum256([]byte("pay mallory"))
			m["hash"] = hex.EncodeToString(h[:])
		},
		"not a withdrawal": func(m map[string]any) {
			in := signjob.Intent{Kind: "sweep", ID: "w1", Amount: "1"}
			h := in.Hash()
			m["canonical"], m["hash"] = hex.EncodeToString(in.Canonical()), hex.EncodeToString(h[:])
		},
	}
	for name, tamper := range cases {
		f := newCore(t)
		f.tamper = tamper
		s := ctaptest.New()
		file, _ := enrol(t, s, "bob")
		r := run(t, s, jwt("bob"), "", "approve", "w1", "-api", f.srv.URL, "-entry", file, "-yes")
		if r.code == 0 || !strings.Contains(r.err, "REFUSED") || !strings.Contains(r.err, "Nothing was signed") {
			t.Errorf("%s: %+v", name, r)
		}
		if s.Calls.Assert != 0 || len(f.approvals) != 0 || strings.Contains(r.out, "Hash you sign") {
			t.Errorf("%s: the key was asked (%d), %d approvals sent, or fields were shown", name, s.Calls.Assert, len(f.approvals))
		}
	}
}

func TestApproveSendsAnAssertionTheZoneVerifies(t *testing.T) {
	for _, algs := range [][]ctap.Alg{{ctap.ES256, ctap.EdDSA}, {ctap.ES256}} {
		f := newCore(t)
		s := ctaptest.New()
		s.Algs = algs
		file, e := enrol(t, s, "bob")
		r := run(t, s, jwt("bob"), "", "approve", "w1", "-api", f.srv.URL, "-entry", file, "-yes")
		if r.code != 0 || !strings.Contains(r.out, "Approval accepted by the core") {
			t.Fatalf("%+v", r)
		}
		if len(f.approvals) != 1 || f.approvals[0]["actor"] != "bob" || f.approvals[0]["_auth"] != "Bearer "+jwt("bob") {
			t.Fatalf("approvals %v", f.approvals)
		}
		w := f.approvals[0]["webauthn"].(map[string]any)
		dec := func(k string) []byte {
			b, err := base64.RawURLEncoding.DecodeString(w[k].(string))
			must(t, err)
			return b
		}
		f.intent.ID = "w1"
		h := f.intent.Hash()
		as := &webauthn.Assertion{CredentialID: dec("credential_id"), AuthenticatorData: dec("authenticator_data"), ClientDataJSON: dec("client_data_json"), Signature: dec("signature")}
		if err := webauthn.Verify(zoneKey(t, e), h[:], as); err != nil {
			t.Fatalf("the zone's verifier (%s): %v", e["alg"], err)
		}
		// The origin is the configured one: another is written into the client data, and the verifier refuses it.
		r = run(t, s, jwt("bob"), "", "approve", "w1", "-api", f.srv.URL, "-entry", file, "-origin", "https://other.example.com", "-yes")
		w = f.approvals[1]["webauthn"].(map[string]any)
		as.ClientDataJSON, as.AuthenticatorData, as.Signature = dec("client_data_json"), dec("authenticator_data"), dec("signature")
		if err := webauthn.Verify(zoneKey(t, e), h[:], as); err == nil || !strings.Contains(err.Error(), "origin") {
			t.Fatalf("another origin: %v", err)
		}
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestApproveRefusals(t *testing.T) {
	f := newCore(t)
	s := ctaptest.New()
	file, _ := enrol(t, s, "bob")
	// The requester cannot approve.
	if r := run(t, s, jwt("alice"), "", "approve", "w1", "-api", f.srv.URL, "-entry", file, "-yes"); r.code == 0 || !strings.Contains(r.err, "you requested this withdrawal") || s.Calls.Assert != 0 {
		t.Fatalf("requester: %+v", r)
	}
	// A wrong confirmation does not reach the key.
	if r := run(t, s, jwt("bob"), "nope\n", "approve", "w1", "-api", f.srv.URL, "-entry", file); r.code == 0 || s.Calls.Assert != 0 {
		t.Fatalf("confirmation: %+v", r)
	}
	// The right confirmation does.
	f.intent.ID = "w1"
	h := f.intent.Hash()
	if r := run(t, s, jwt("bob"), hex.EncodeToString(h[:])[:8]+"\n", "approve", "w1", "-api", f.srv.URL, "-entry", file); r.code != 0 || s.Calls.Assert != 1 {
		t.Fatalf("typed confirmation: %+v", r)
	}
	// A key that skips user verification: the CLI refuses to send. (The zone's own refusal is tested in e2e with a client that bypasses the CLI.)
	noUV := ctaptest.New()
	file2, _ := enrol(t, noUV, "carol")
	noUV.NoUV = true
	n := len(f.approvals)
	if r := run(t, noUV, jwt("carol"), "", "approve", "w1", "-api", f.srv.URL, "-entry", file2, "-yes"); r.code == 0 || !strings.Contains(r.err, "did not report user verification") || len(f.approvals) != n {
		t.Fatalf("no UV: %+v", r)
	}
	// The core asks for a fresher sign-in.
	f.status, f.challenge = 401, `Bearer realm="qv-core", error="insufficient_user_authentication"`
	if r := run(t, s, jwt("bob"), "", "approve", "w1", "-api", f.srv.URL, "-entry", file, "-yes"); r.code == 0 || !strings.Contains(r.err, "fresher sign-in") {
		t.Fatalf("step-up: %+v", r)
	}
	// Self-approval refused by the core (403).
	f.status, f.challenge = 403, ""
	if r := run(t, s, jwt("bob"), "", "approve", "w1", "-api", f.srv.URL, "-entry", file, "-yes"); r.code == 0 || !strings.Contains(r.err, "403") {
		t.Fatalf("403: %+v", r)
	}
}

// A fake identity provider for the loopback login: it checks what a real one would (PKCE S256, a fresh sign-in asked for, the redirect URI) and
// hands out a token only for the right verifier.
func TestLoopbackLogin(t *testing.T) {
	var mu sync.Mutex
	var challenge, redirect, gotQuery string
	var idp *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"issuer": idp.URL, "authorization_endpoint": idp.URL + "/auth", "token_endpoint": idp.URL + "/token"})
	})
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		mu.Lock()
		challenge, redirect, gotQuery = q.Get("code_challenge"), q.Get("redirect_uri"), r.URL.RawQuery
		mu.Unlock()
		http.Redirect(w, r, redirect+"?code=abc&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		v := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		mu.Lock()
		defer mu.Unlock()
		if r.Form.Get("code") != "abc" || base64.RawURLEncoding.EncodeToString(v[:]) != challenge || r.Form.Get("redirect_uri") != redirect || r.Form.Get("client_secret") != "" {
			w.WriteHeader(400)
			io.WriteString(w, `{"error_description":"bad"}`)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"access_token": jwt("bob")})
	})
	idp = httptest.NewServer(mux)
	defer idp.Close()

	f := newCore(t)
	pr, pw := io.Pipe()
	var errb bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- approvecli.Run(context.Background(), []string{"show", "w1", "-api", f.srv.URL, "-issuer", idp.URL, "-client-id", "qv-approve"},
			approvecli.Env{Stdin: strings.NewReader(""), Stdout: pw, Stderr: &errb})
		pw.Close()
	}()
	// The person's browser: read the sign-in link from the terminal output and open it.
	var all bytes.Buffer
	go func() {
		re := regexp.MustCompile(`https?://\S+/auth\?\S+`)
		buf := make([]byte, 4096)
		opened := false
		for {
			n, err := pr.Read(buf)
			all.Write(buf[:n])
			if m := re.FindString(all.String()); m != "" && !opened {
				opened = true
				go func() {
					resp, err := http.Get(m)
					if err == nil {
						resp.Body.Close()
					}
				}()
			}
			if err != nil {
				return
			}
		}
	}()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit %d: %s\n%s", code, errb.String(), all.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatal("timed out")
	}
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	for _, want := range []string{"prompt=login", "max_age=0", "code_challenge_method=S256", "response_type=code", "client_id=qv-approve", "redirect_uri=http%3A%2F%2F127.0.0.1%3A"} {
		if !strings.Contains(gotQuery, want) {
			t.Errorf("the sign-in request lacks %q: %s", want, gotQuery)
		}
	}
	if !strings.Contains(all.String(), "Send ") {
		t.Fatalf("after login the intent was not shown:\n%s", all.String())
	}
}

func TestParseCanonicalMatchesSignjob(t *testing.T) {
	in := signjob.Intent{Kind: "withdrawal", ID: "w9", PartitionID: "p", Chain: "c", Asset: "A", From: "f", To: "t", Amount: "12", NotAfter: 77, RequestedBy: "r"}
	got, err := approvecli.ParseCanonical(in.Canonical())
	if err != nil || got.ID != "w9" || got.Amount != "12" || got.NotAfter != 77 || got.RequestedBy != "r" || got.From != "f" {
		t.Fatalf("%v %+v", err, got)
	}
	b := in.Canonical()
	for name, bad := range map[string][]byte{"extra": append(append([]byte{}, b...), 0), "short": b[:len(b)-1], "domain": append([]byte("x"), b...)} {
		if _, err := approvecli.ParseCanonical(bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
