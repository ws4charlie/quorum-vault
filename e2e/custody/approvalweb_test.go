package custody_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/ethereum/go-ethereum/common"

	"github.com/ws4charlie/quorum-vault/e2e/approvalweb"
	"github.com/ws4charlie/quorum-vault/e2e/idp"
	"github.com/ws4charlie/quorum-vault/internal/gateway"
	"github.com/ws4charlie/quorum-vault/internal/pki/pkitest"
)

// The approval page (web/approval), served by qv-approval-web from its own origin, in a real headless Chromium with a virtual authenticator
// (SIMULATED: a software passkey, no hardware, no person), against the real gateway, the real core and the dev Keycloak.
//
//  1. bob signs in on the page and enrols a passkey; operators enrol it in the signing zone with qv-approvers.
//  2. alice requests a withdrawal; bob approves it on the page with his passkey, carol with an Ed25519 key: it is signed and settles.
//  3. a core that sends a wrong hash is refused by the page: nothing is signed, nothing is sent.
//  4. an approval made on another origin (the core's CORS lets it through, the zone's list does not) is refused by the zone; the page also
//     walks through a fresh sign-in when the core asks for step-up.
//  5. a requester cannot approve their own withdrawal on the page.

// newOperators makes two operator keys (files under the system's dir, as the runbook has operators keep them) and the zone config's section for them.
func (s *system) newOperators() *gateway.OperatorsFile {
	f := &gateway.OperatorsFile{Keys: map[string]gateway.OperatorFile{}, MinOperators: 2}
	for _, name := range []string{"op1", "op2"} {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		f.Keys[name] = gateway.OperatorFile{PublicKey: hex.EncodeToString(pub)}
		if err := os.WriteFile(filepath.Join(s.dir, name+".key"), []byte(hex.EncodeToString(priv.Seed())), 0o600); err != nil {
			s.t.Fatal(err)
		}
	}
	return f
}

// qvApprovers runs the operators' tool.
func (s *system) qvApprovers(args ...string) string {
	s.t.Helper()
	out, err := exec.Command(filepath.Join(binDir, "qv-approvers"), args...).CombinedOutput()
	if err != nil {
		s.t.Fatalf("qv-approvers %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// enrolApprover does what docs/runbooks/approvers.md asks of two operators: sign the change, add the second signature, apply it to the guard database.
func (s *system) enrolApprover(name, entryJSON string) {
	s.t.Helper()
	entry := filepath.Join(s.dir, name+"-entry.json")
	change := filepath.Join(s.dir, name+"-change.json")
	if err := os.WriteFile(entry, []byte(entryJSON), 0o600); err != nil {
		s.t.Fatal(err)
	}
	s.qvApprovers("sign", "-operator", "op1", "-key", filepath.Join(s.dir, "op1.key"), "-seq", "1", "-action", "enrol", "-name", name, "-approver-file", entry, "-out", change)
	s.qvApprovers("sign", "-operator", "op2", "-key", filepath.Join(s.dir, "op2.key"), "-join", change, "-out", change)
	s.qvApprovers("apply", "-config", s.gwPath, "-guard-dsn", "gateway="+s.guardDSN, change)
}

// coreProxy is a reverse proxy to the core that a test can make lie: it can change the hash of an intent, and answer the first approval with the
// step-up challenge. It forwards everything else untouched, CORS headers included.
type coreProxy struct {
	URL       string
	tamper    atomic.Bool
	stepUp    atomic.Bool
	approvals atomic.Int32 // approval posts that reached the core
}

func startCoreProxy(t *testing.T, core string) *coreProxy {
	t.Helper()
	target, _ := url.Parse(core)
	p := &coreProxy{}
	rp := httputil.NewSingleHostReverseProxy(target)
	rp.Transport = pkitest.PeopleClient().Transport
	rp.ModifyResponse = func(r *http.Response) error {
		if !p.tamper.Load() || !strings.HasSuffix(r.Request.URL.Path, "/intent") || r.StatusCode != 200 {
			return nil
		}
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			return err
		}
		h := m["hash"].(string)
		flip := map[byte]byte{'0': '1'}
		c := byte('0')
		if h[0] == '0' {
			c = flip['0']
		}
		m["hash"] = string(c) + h[1:] // a different hash for the same canonical bytes
		nb, _ := json.Marshal(m)
		r.Body = io.NopCloser(strings.NewReader(string(nb)))
		r.ContentLength = int64(len(nb))
		r.Header.Set("Content-Length", strconv.Itoa(len(nb)))
		return nil
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/approvals") {
			if p.stepUp.CompareAndSwap(true, false) { // the core's answer when the login is too old (internal/auth)
				w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
				w.Header().Set("Access-Control-Expose-Headers", "WWW-Authenticate")
				w.Header().Set("WWW-Authenticate", `Bearer realm="qv-core", error="insufficient_user_authentication", error_description="a fresh authentication is required", acr_values="aal3", max_age="300"`)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				io.WriteString(w, `{"error":"step-up authentication required"}`)
				return
			}
			p.approvals.Add(1)
		}
		rp.ServeHTTP(w, r)
	})}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	p.URL = "http://" + l.Addr().String()
	return p
}

// startPage runs qv-approval-web on the port for the core at api.
func (s *system) startPage(port int, api string) {
	s.t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "..", "web", "approval"))
	if err != nil {
		s.t.Fatal(err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	p := s.spawn("qv-approval-web", nil, "-listen", addr, "-dir", dir, "-issuer", os.Getenv("QV_OIDC_ISSUER"), "-client-id", "qv-approval-e2e", "-api", api,
		"-asset-decimals", "ETH=18,USDT=6")
	s.waitFor(15*time.Second, "qv-approval-web listening", func() bool { return fileContains(p.log, "qv-approval-web listening") })
}

// signIn fills the identity provider's login form if the page sent the browser there, and waits for the page's own element sel.
func signIn(p *approvalweb.Person, user, sel string) {
	p.T().Helper()
	if p.WaitFor(60*time.Second, sel, "#username") == 1 {
		pw := os.Getenv("QV_TEST_PASSWORD_" + strings.ToUpper(user))
		if pw == "" {
			p.T().Fatalf("QV_TEST_PASSWORD_%s is unset: run scripts/keycloak-env.sh", strings.ToUpper(user))
		}
		p.Run("log in as "+user, chromedp.SendKeys("#username", user, chromedp.ByQuery), chromedp.SendKeys("#password", pw, chromedp.ByQuery), chromedp.Click("#kc-login", chromedp.ByQuery))
		p.WaitFor(60*time.Second, sel)
	}
}

func TestApprovalPageInARealBrowser(t *testing.T) {
	if !idp.Real() {
		t.Skip("QV_E2E_KEYCLOAK_URL is not set: no Keycloak")
	}
	br := approvalweb.Start(t) // SIMULATED passkeys: a virtual authenticator of the DevTools protocol

	// Two origins of the page, both allowed by the core's CORS; only the first is in the zone's approver entry (it is the one the passkey is enrolled on).
	portA, portB := freePort(t), freePort(t)
	originA, originB := fmt.Sprintf("http://localhost:%d", portA), fmt.Sprintf("http://localhost:%d", portB)
	t.Setenv("QV_APPROVAL_ORIGINS", originA+","+originB)
	s, _ := funded(t, opts{approvalWeb: true, approvalTimeout: "8m"}, "c-web", 8)
	proxy := startCoreProxy(t, s.apiURL)
	s.startPage(portA, s.apiURL)
	s.startPage(portB, proxy.URL)

	req := func(key string) (wd, common.Address) {
		to := randAddr()
		w := s.withdraw("alice", key, "c-web", "ETH", to, eth(2)) // tier 2: two approvals
		if w.Code != 201 {
			t.Fatalf("%d %v", w.Code, w.Raw)
		}
		return w, to
	}
	bob := br.NewPerson()

	// 1. bob signs in and enrols a passkey on origin A; operators enrol it in the zone.
	bob.Run("open the enrol page", chromedp.Navigate(originA+"/#/enrol"))
	bob.WaitFor(30*time.Second, "#signin")
	bob.Run("sign in", chromedp.Click("#signin", chromedp.ByQuery))
	signIn(bob, "bob", "#create")
	bob.Run("create the passkey", chromedp.Click("#create", chromedp.ByQuery))
	bob.WaitFor(30*time.Second, "#entry-json")
	entry := bob.Text("#entry-json")
	var e gateway.ApproverFile
	if err := json.Unmarshal([]byte(entry), &e); err != nil {
		t.Fatalf("the approver entry the page showed: %v\n%s", err, entry)
	}
	if e.Scheme != "webauthn" || e.Alg != "ES256" || e.RPID != "localhost" || len(e.Origins) != 1 || e.Origins[0] != originA || len(e.PublicKey) != 130 {
		t.Fatalf("approver entry: %s", entry)
	}
	s.enrolApprover("bob", entry)

	// 2. alice requests; bob approves on the page; carol approves with an Ed25519 key. Signed, settled.
	w1, to1 := req("k-web-1")
	dest1 := to1.Hex()
	bob.Run("open the withdrawal", chromedp.Navigate(originA+"/#/withdrawals/"+w1.ID))
	bob.WaitFor(30*time.Second, "#sentence")
	for _, want := range []string{"2 ETH", dest1, "alice"} {
		if sentence := bob.Text("#sentence"); !strings.Contains(sentence, want) {
			t.Fatalf("the page's sentence %q does not say %q", sentence, want)
		}
	}
	var intentHash string
	if code, in := s.call("GET", "/v2/withdrawals/"+w1.ID+"/intent", nil, nil); code != 200 {
		t.Fatalf("intent: %d %v", code, in)
	} else {
		intentHash, _ = in["hash"].(string)
	}
	if got := bob.Text("#hash"); got != intentHash {
		t.Fatalf("the page computed hash %s, the core says %s", got, intentHash)
	}
	bob.Run("approve", chromedp.Click("#approve", chromedp.ByQuery))
	if bob.WaitFor(60*time.Second, "#outcome", "#username") == 1 { // a login older than the page's limit: the page asks for a fresh one first
		signIn(bob, "bob", "#approve")
		bob.Run("approve again", chromedp.Click("#approve", chromedp.ByQuery))
		bob.WaitFor(60*time.Second, "#outcome")
	}
	if out := bob.Text("#outcome"); !strings.Contains(out, "accepted") {
		t.Fatalf("outcome: %s", out)
	}
	if code, out := s.approve("carol", w1.ID); code != 200 {
		t.Fatalf("carol: %d %v", code, out)
	}
	s.waitWd(w1.ID, "confirmed", 90*time.Second)
	if s.ethBalance(to1).Cmp(eth(2)) != 0 {
		t.Fatalf("destination = %s", s.ethBalance(to1))
	}

	// 3. a core that lies about the hash: the page refuses, offers no button, and sends nothing.
	w2, to2 := req("k-web-2")
	proxy.tamper.Store(true)
	bob.Run("open on origin B", chromedp.Navigate(originB+"/#/withdrawals/"+w2.ID))
	bob.WaitFor(30*time.Second, "#signin")
	bob.Run("sign in on B", chromedp.Click("#signin", chromedp.ByQuery))
	signIn(bob, "bob", "p.bad")
	if txt := bob.Text("p.bad"); !strings.Contains(txt, "REFUSED") || !strings.Contains(txt, "Nothing was signed") {
		t.Fatalf("the page said %q", txt)
	}
	if bob.Has("#approve") || bob.Has("#sentence") {
		t.Fatal("the page offered an approval for an intent whose hash does not match")
	}
	if n := proxy.approvals.Load(); n != 0 {
		t.Fatalf("%d approvals reached the core", n)
	}
	proxy.tamper.Store(false)

	// 4. the same page on origin B, honest core, but B is not in the zone's entry. The core is asked for step-up on the first try: the page sends
	// bob through a fresh login (the identity provider shows its form although he has a session), and he approves again.
	bob.Run("leave the withdrawal", chromedp.Evaluate(`location.hash = "#/"`, nil)) // the page keeps bob's token in memory: no new sign-in
	bob.Run("open it again", chromedp.Evaluate(`location.hash = "#/withdrawals/`+w2.ID+`"`, nil))
	bob.WaitFor(30*time.Second, "#approve")
	proxy.stepUp.Store(true)
	bob.Run("approve on B", chromedp.Click("#approve", chromedp.ByQuery))
	bob.WaitFor(60*time.Second, "#username") // the fresh login the step-up asked for
	var u string
	bob.Eval(`location.href`, &u)
	if q, _ := url.Parse(u); !strings.Contains(q.RawQuery, "prompt=login") || !strings.Contains(q.RawQuery, "max_age=0") || !strings.Contains(q.RawQuery, "code_challenge_method=S256") {
		t.Fatalf("the step-up login request: %s", u)
	}
	signIn(bob, "bob", "#approve")
	bob.Run("approve on B again", chromedp.Click("#approve", chromedp.ByQuery))
	bob.WaitFor(60*time.Second, "#outcome")
	if out := bob.Text("#outcome"); !strings.Contains(out, "accepted") { // the core stores any well-formed assertion; the zone judges it
		t.Fatalf("outcome: %s", out)
	}
	if code, out := s.approve("carol", w2.ID); code != 200 {
		t.Fatalf("carol: %d %v", code, out)
	}
	got := s.waitWd(w2.ID, "failed", 120*time.Second)
	if !strings.Contains(got.Reason, "gateway refused") {
		t.Fatalf("reason %q", got.Reason)
	}
	if s.ethBalance(to2).Sign() != 0 {
		t.Fatal("paid out on an assertion made on another origin")
	}

	// 5. alice, the requester, opens her own withdrawal on the page: she sees it and cannot approve it. (A bypass of the page is refused by the core too.)
	w3, _ := req("k-web-3")
	alice := br.NewPerson()
	alice.ClearCookies() // bob's identity-provider session must not sign alice in
	alice.Run("open", chromedp.Navigate(originA+"/#/withdrawals/"+w3.ID))
	alice.WaitFor(30*time.Second, "#signin")
	alice.Run("sign in", chromedp.Click("#signin", chromedp.ByQuery))
	signIn(alice, "alice", "#sentence")
	if txt := alice.Text("p.bad"); !strings.Contains(txt, "You requested this withdrawal") || alice.Has("#approve") {
		t.Fatalf("a requester on her own withdrawal: %q", txt)
	}
	if code, _ := s.approve("alice", w3.ID); code != 403 {
		t.Fatalf("the core let the requester approve: %d", code)
	}
	s.reconcileClean()
}
