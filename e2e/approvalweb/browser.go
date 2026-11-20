// Package approvalweb drives the approval page (web/approval) in a real headless Chromium, for the e2e tests.
//
// SIMULATED: the passkey is a virtual authenticator of the DevTools protocol (the WebAuthn domain), a software key that Chromium makes, holds and
// "touches" by itself: no hardware, no person. Everything else is real: the page, its static server, the identity provider's login page, the core's
// CORS rules, the signing zone's check of the assertion.
//
// Which browser: QV_E2E_CHROME_URL (the DevTools address of a Chromium that is already running, e.g. http://127.0.0.1:9222: CI runs the pinned
// chromedp/headless-shell image next to the job), else QV_E2E_CHROME (a binary), else Google Chrome or Chromium found on this machine. With none,
// the test is skipped, except when QV_REQUIRE_BROWSER=1 (CI), where it fails.
package approvalweb

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/webauthn"
	"github.com/chromedp/chromedp"
)

// Browser is one Chromium and the context its tabs are made from.
type Browser struct {
	t    testing.TB
	root context.Context // the started browser; every person's tab is made from it
}

// Start finds or starts a Chromium for the test and stops it at the end.
func Start(t testing.TB) *Browser {
	t.Helper()
	root, stop := context.WithCancel(context.Background())
	t.Cleanup(stop)
	if u := os.Getenv("QV_E2E_CHROME_URL"); u != "" {
		alloc, cancel := chromedp.NewRemoteAllocator(root, u)
		t.Cleanup(cancel)
		return open(t, alloc)
	}
	bin := os.Getenv("QV_E2E_CHROME")
	if bin == "" {
		for _, c := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome-headless-shell",
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "/Applications/Chromium.app/Contents/MacOS/Chromium"} {
			if p, err := exec.LookPath(c); err == nil {
				bin = p
				break
			}
		}
	}
	if bin == "" {
		if os.Getenv("QV_REQUIRE_BROWSER") == "1" {
			t.Fatal("QV_REQUIRE_BROWSER=1 but there is no Chromium (QV_E2E_CHROME_URL, QV_E2E_CHROME)")
		}
		t.Skip("no Chromium (QV_E2E_CHROME_URL, QV_E2E_CHROME): the approval page is not tested")
	}
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(bin),
		chromedp.Flag("ignore-certificate-errors", true), // the dev Keycloak and the core use the test authority's certificates, which the browser does not trust
		chromedp.Flag("no-sandbox", os.Getenv("QV_E2E_CHROME_NO_SANDBOX") == "1"),
	)
	alloc, cancel := chromedp.NewExecAllocator(root, opts...)
	t.Cleanup(cancel)
	return open(t, alloc)
}

// open starts the browser itself (a person's separate context can only be made once it runs).
func open(t testing.TB, alloc context.Context) *Browser {
	t.Helper()
	ctx, cancel := chromedp.NewContext(alloc)
	t.Cleanup(cancel)
	if err := chromedp.Run(ctx); err != nil {
		t.Fatalf("browser: start: %v", err)
	}
	return &Browser{t: t, root: ctx}
}

// Person is one tab with its own virtual passkey device. Tabs share the browser's cookies, so a test that changes who is signed in at the identity
// provider calls ClearCookies first.
type Person struct {
	t   testing.TB
	Ctx context.Context
}

// NewPerson opens a tab with a virtual authenticator that holds discoverable credentials and verifies the user.
func (b *Browser) NewPerson() *Person {
	b.t.Helper()
	ctx, cancel := chromedp.NewContext(b.root)
	b.t.Cleanup(cancel)
	ctx, cancel2 := context.WithTimeout(ctx, 6*time.Minute)
	b.t.Cleanup(cancel2)
	err := chromedp.Run(ctx,
		webauthn.Enable(),
		chromedp.ActionFunc(func(ctx context.Context) error {
			_, err := webauthn.AddVirtualAuthenticator(&webauthn.VirtualAuthenticatorOptions{
				Protocol: webauthn.AuthenticatorProtocolCtap2, Transport: webauthn.AuthenticatorTransportInternal,
				HasResidentKey: true, HasUserVerification: true, IsUserVerified: true, AutomaticPresenceSimulation: true,
			}).Do(ctx)
			return err
		}),
	)
	if err != nil {
		b.t.Fatalf("browser: virtual authenticator: %v", err)
	}
	return &Person{t: b.t, Ctx: ctx}
}

// ClearCookies forgets every cookie of the browser, the identity provider's session included.
func (p *Person) ClearCookies() {
	p.t.Helper()
	p.Run("clear cookies", network.ClearBrowserCookies())
}

// T is the test the person belongs to.
func (p *Person) T() testing.TB { return p.t }

// Run runs actions in the person's tab; a failure ends the test with the page's text for the log.
func (p *Person) Run(what string, actions ...chromedp.Action) {
	p.t.Helper()
	if err := chromedp.Run(p.Ctx, actions...); err != nil {
		p.t.Fatalf("browser: %s: %v\n---- page ----\n%s", what, err, p.body())
	}
}

// body is the visible text of the page, for a failure message.
func (p *Person) body() string {
	var body string
	ctx, cancel := context.WithTimeout(p.Ctx, 5*time.Second)
	defer cancel()
	_ = chromedp.Run(ctx, chromedp.Text("body", &body, chromedp.ByQuery))
	return strings.TrimSpace(body)
}

// Text is the text of the first element that matches selector.
func (p *Person) Text(selector string) string {
	p.t.Helper()
	var s string
	p.Run("read "+selector, chromedp.Text(selector, &s, chromedp.ByQuery))
	return s
}

// Has reports whether an element matches the selector now.
func (p *Person) Has(selector string) bool {
	var ok bool
	p.Run("look for "+selector, chromedp.Evaluate(`document.querySelector(`+quote(selector)+`) !== null`, &ok))
	return ok
}

// Eval evaluates an expression in the page.
func (p *Person) Eval(js string, res any) {
	p.t.Helper()
	p.Run("evaluate", chromedp.Evaluate(js, res))
}

// WaitFor waits until one of the selectors exists and returns which (the index), so a step can wait for "the result or the login form".
func (p *Person) WaitFor(timeout time.Duration, selectors ...string) int {
	p.t.Helper()
	var js strings.Builder
	js.WriteString("[")
	for i, s := range selectors {
		if i > 0 {
			js.WriteString(",")
		}
		js.WriteString(quote(s))
	}
	js.WriteString("].findIndex(s => document.querySelector(s) !== null)")
	deadline := time.Now().Add(timeout)
	for {
		var idx int
		if err := chromedp.Run(p.Ctx, chromedp.Evaluate(js.String(), &idx)); err == nil && idx >= 0 {
			return idx
		}
		if time.Now().After(deadline) {
			p.t.Fatalf("browser: timed out waiting for %v\n---- page ----\n%s", selectors, p.body())
		}
		time.Sleep(150 * time.Millisecond)
	}
}

func quote(s string) string { return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s) + "'" }
