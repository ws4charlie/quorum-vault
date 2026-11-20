package custody_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/e2e/idp"
	"github.com/ws4charlie/quorum-vault/internal/approvecli"
	"github.com/ws4charlie/quorum-vault/internal/ctap"
	"github.com/ws4charlie/quorum-vault/internal/ctap/ctaptest"
	"github.com/ws4charlie/quorum-vault/internal/pki/pkitest"
)

// qv-approve (internal/approvecli, what cmd/qv-approve runs) against the real core and the real signing zone, with a SIMULATED security key: a
// software CTAP2 authenticator (internal/ctap/ctaptest). No hardware key and no person is involved; the steps with a real YubiKey are the manual
// test in docs/runbooks/webauthn-approver.md.
//
//  1. bob enrols the key with the CLI; operators sign the printed approver entry into the zone (the zone's own loader accepts it).
//  2. alice requests a withdrawal; bob approves it with the CLI, carol with an Ed25519 key: it is signed and settles.
//  3. a core that sends a wrong hash is refused by the CLI: the key is not asked and nothing is sent.
//  4. a key that skips user verification, and an origin the zone does not list for bob, are each refused by the zone: nothing is paid.
//  5. show prints the fields of the intent the core holds.

// cliRun runs qv-approve as person actor with the key (nil key: none is needed) against the core at api.
func (s *system) cliRun(actor string, key *ctaptest.Soft, api string, args ...string) (int, string, string) {
	s.t.Helper()
	var out, errb bytes.Buffer
	env := approvecli.Env{
		Token: func(context.Context) (string, error) { return strings.TrimPrefix(idp.Bearer(actor), "Bearer "), nil },
		HTTP:  pkitest.PeopleClient(), Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb,
	}
	if key != nil {
		env.Key = key
	}
	code := approvecli.Run(context.Background(), append(args, "-api", api), env)
	return code, out.String(), errb.String()
}

func TestApproverCLIWithASoftwareKey(t *testing.T) {
	s, _ := funded(t, opts{approvalWeb: true, approvalTimeout: "8m"}, "c-cli", 8) // approvalWeb: operators in the zone config, and bob is not a bootstrap approver
	key := ctaptest.New()
	const origin = "https://approve.example.com" // a convention for a CLI: the origin it writes is the one the zone lists for bob

	// 1. Enrol.
	entryFile := filepath.Join(s.dir, "bob-cli-entry.json")
	if code, out, errb := s.cliRun("bob", key, s.apiURL, "enrol", "-origin", origin, "-out", entryFile); code != 0 {
		t.Fatalf("enrol: %d\n%s\n%s", code, out, errb)
	} else if !strings.Contains(out, "AAGUID") || !strings.Contains(out, "Attestation type") {
		t.Fatalf("enrol printed no attestation facts:\n%s", out)
	}
	entry, err := os.ReadFile(entryFile)
	if err != nil {
		t.Fatal(err)
	}
	s.enrolApprover("bob", string(entry)) // qv-approvers sign, sign, apply: the zone builds the key from the entry or refuses it

	req := func(k string) (wd, string) {
		to := randAddr()
		w := s.withdraw("alice", k, "c-cli", "ETH", to, eth(2)) // tier 2: two approvals
		if w.Code != 201 {
			t.Fatalf("%d %v", w.Code, w.Raw)
		}
		return w, to.Hex()
	}
	approve := func(w wd, api string, extra ...string) (int, string, string) {
		return s.cliRun("bob", key, api, append([]string{"approve", w.ID, "-entry", entryFile, "-yes", "-asset-decimals", "ETH=18"}, extra...)...)
	}

	// 5. show: every field, and the hash the core holds.
	w1, dest1 := req("k-cli-1")
	code, out, errb := s.cliRun("bob", nil, s.apiURL, "show", w1.ID, "-asset-decimals", "ETH=18")
	_, in := s.call("GET", "/v2/withdrawals/"+w1.ID+"/intent", nil, nil)
	for _, want := range []string{"Send 2 ETH", dest1, "alice", w1.ID, in["hash"].(string)} {
		if code != 0 || !strings.Contains(out, want) {
			t.Fatalf("show (%d) lacks %q:\n%s\n%s", code, want, out, errb)
		}
	}

	// 2. Approve with the CLI and an Ed25519 key: signed and settled.
	if code, out, errb := approve(w1, s.apiURL); code != 0 || !strings.Contains(out, "Approval accepted by the core") {
		t.Fatalf("approve: %d\n%s\n%s", code, out, errb)
	}
	if code, out := s.approve("carol", w1.ID); code != 200 {
		t.Fatalf("carol: %d %v", code, out)
	}
	s.waitWd(w1.ID, "confirmed", 90*time.Second)
	if s.ethBalance(common20(dest1)).Cmp(eth(2)) != 0 {
		t.Fatalf("destination = %s", s.ethBalance(common20(dest1)))
	}

	// 3. A lying core: the CLI refuses before it asks the key.
	w2, dest2 := req("k-cli-2")
	proxy := startCoreProxy(t, s.apiURL)
	proxy.tamper.Store(true)
	asked := key.Calls.Assert
	if code, out, errb := approve(w2, proxy.URL); code == 0 || !strings.Contains(errb, "REFUSED") || strings.Contains(out, "Hash you sign") {
		t.Fatalf("a tampered hash: %d\n%s\n%s", code, out, errb)
	}
	if key.Calls.Assert != asked || proxy.approvals.Load() != 0 {
		t.Fatalf("the key was asked %d times or %d approvals reached the core", key.Calls.Assert-asked, proxy.approvals.Load())
	}

	// 4a. The CLI refuses to send an assertion without user verification. The zone's own refusal is tested by sending such an assertion through this
	// test's client, not through the CLI.
	key.NoUV = true
	code, out, errb = approve(w2, s.apiURL)
	if code == 0 || !strings.Contains(errb, "did not report user verification") {
		t.Fatalf("no UV: %d\n%s\n%s", code, out, errb)
	}
	s.postNoUVAssertion(key, entryFile, w2.ID, origin)
	key.NoUV = false
	if c, o := s.approve("carol", w2.ID); c != 200 {
		t.Fatalf("carol: %d %v", c, o)
	}
	got := s.waitWd(w2.ID, "failed", 120*time.Second)
	if !strings.Contains(got.Reason, "gateway refused") {
		t.Fatalf("reason %q", got.Reason)
	}
	if s.ethBalance(common20(dest2)).Sign() != 0 {
		t.Fatal("paid out on an assertion without user verification")
	}

	// 4b. An origin the zone does not list for bob.
	w3, dest3 := req("k-cli-3")
	if code, out, errb := approve(w3, s.apiURL, "-origin", "https://other.example.com"); code != 0 {
		t.Fatalf("other origin: %d\n%s\n%s", code, out, errb)
	}
	if c, o := s.approve("carol", w3.ID); c != 200 {
		t.Fatalf("carol: %d %v", c, o)
	}
	got = s.waitWd(w3.ID, "failed", 120*time.Second)
	if !strings.Contains(got.Reason, "gateway refused") {
		t.Fatalf("reason %q", got.Reason)
	}
	if s.ethBalance(common20(dest3)).Sign() != 0 {
		t.Fatal("paid out on an assertion made for another origin")
	}
	s.waitIdle(30 * time.Second)
	s.reconcileClean()
}

// The loopback login of the CLI against the real Keycloak: a script plays the person at the browser (SIMULATED: the test client skips the passkey
// step of the identity provider, as qv-approval-e2e does for the page).
func TestApproverCLILoopbackLoginWithKeycloak(t *testing.T) {
	if !idp.Real() {
		t.Skip("QV_E2E_KEYCLOAK_URL is not set: no Keycloak")
	}
	s, _ := funded(t, opts{approvalWeb: true, approvalTimeout: "8m"}, "c-cli-kc", 3)
	w := s.withdraw("alice", "k-cli-kc", "c-cli-kc", "ETH", randAddr(), eth(1))
	if w.Code != 201 {
		t.Fatalf("%d %v", w.Code, w.Raw)
	}
	pr, pw := io.Pipe()
	var mu sync.Mutex
	var seen bytes.Buffer
	go func() { // the browser
		re := regexp.MustCompile(`https://\S+/auth\?\S+`)
		buf := make([]byte, 4096)
		done := false
		for {
			n, err := pr.Read(buf)
			mu.Lock()
			seen.Write(buf[:n])
			link := re.FindString(seen.String())
			mu.Unlock()
			if link != "" && !done {
				done = true
				go browse(t, link, "bob")
			}
			if err != nil {
				return
			}
		}
	}()
	var errb bytes.Buffer
	code := approvecli.Run(context.Background(), []string{"show", w.ID, "-api", s.apiURL, "-issuer", os.Getenv("QV_OIDC_ISSUER"), "-client-id", "qv-approve-e2e"},
		approvecli.Env{HTTP: pkitest.PeopleClient(), Stdin: strings.NewReader(""), Stdout: pw, Stderr: &errb})
	pw.Close()
	mu.Lock()
	defer mu.Unlock()
	if code != 0 || !strings.Contains(seen.String(), "Send ") {
		t.Fatalf("show after the loopback login: %d\n%s\n%s", code, seen.String(), errb.String())
	}
}

// browse signs in at the identity provider's form and follows the redirect to the CLI's loopback address.
func browse(t *testing.T, link, user string) {
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Timeout: 30 * time.Second, Jar: jar, Transport: pkitest.PeopleClient().Transport}
	resp, err := hc.Get(link)
	if err != nil {
		t.Errorf("browser: %v", err)
		return
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := regexp.MustCompile(`<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"`).FindSubmatch(page)
	if m == nil {
		t.Errorf("browser: no login form (HTTP %d)", resp.StatusCode)
		return
	}
	pass := os.Getenv("QV_TEST_PASSWORD_" + strings.ToUpper(user))
	resp, err = hc.PostForm(strings.ReplaceAll(string(m[1]), "&amp;", "&"), url.Values{"username": {user}, "password": {pass}, "credentialId": {""}})
	if err != nil {
		t.Errorf("browser: %v", err)
		return
	}
	resp.Body.Close()
}

// postNoUVAssertion builds the assertion the CLI would (same client data) from a key that skips user verification and posts it to the core directly.
func (s *system) postNoUVAssertion(key *ctaptest.Soft, entryFile, id, origin string) {
	s.t.Helper()
	eb, _ := os.ReadFile(entryFile)
	var e struct {
		CredentialID string `json:"credential_id"`
		RPID         string `json:"rp_id"`
	}
	if err := json.Unmarshal(eb, &e); err != nil {
		s.t.Fatal(err)
	}
	cred, _ := base64.RawURLEncoding.DecodeString(e.CredentialID)
	code, in := s.call("GET", "/v2/withdrawals/"+id+"/intent", nil, nil)
	if code != 200 {
		s.t.Fatalf("intent: %d %v", code, in)
	}
	h, _ := hex.DecodeString(in["hash"].(string))
	cd, _ := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": base64.RawURLEncoding.EncodeToString(h), "origin": origin, "crossOrigin": false})
	as, err := key.GetAssertion(context.Background(), ctap.AssertRequest{RPID: e.RPID, CredentialID: cred, ClientDataHash: sha256.Sum256(cd)})
	if err != nil {
		s.t.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	if c, o := s.call("POST", "/v2/withdrawals/"+id+"/approvals", map[string]string{"X-Actor": "bob"}, map[string]any{"actor": "bob",
		"webauthn": map[string]string{"credential_id": b64(cred), "authenticator_data": b64(as.AuthData), "client_data_json": b64(cd), "signature": b64(as.Signature)}}); c != 200 {
		s.t.Fatalf("post: %d %v", c, o)
	}
}
