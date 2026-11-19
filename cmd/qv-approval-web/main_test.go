package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestPageIsServedUnderAStrictPolicy(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "index.html"), []byte("<!doctype html>"), 0o600)
	h := Handler(dir, pageConfig{Issuer: "https://idp.example/realms/qv", ClientID: "qv-approval", API: "https://core.example", MaxLoginAge: 240})
	get := func(method, path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(method, path, nil))
		return w
	}
	for _, path := range []string{"/", "/config.json", "/missing"} {
		w := get("GET", path)
		csp := w.Header().Get("Content-Security-Policy")
		for _, want := range []string{"default-src 'none'", "script-src 'self'", "frame-ancestors 'none'", "base-uri 'none'", "form-action 'none'", "connect-src 'self' https://idp.example https://core.example"} {
			if !strings.Contains(csp, want) {
				t.Errorf("%s: CSP %q lacks %q", path, csp, want)
			}
		}
		if regexp.MustCompile(`unsafe-|\*|data:|http:`).MatchString(csp) {
			t.Errorf("%s: CSP is not strict: %q", path, csp)
		}
		if w.Header().Get("X-Frame-Options") != "DENY" || w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: headers %v", path, w.Header())
		}
	}
	if w := get("GET", "/config.json"); !strings.Contains(w.Body.String(), `"client_id":"qv-approval"`) || !strings.Contains(w.Body.String(), `"api":"https://core.example"`) {
		t.Errorf("config.json: %s", w.Body)
	}
	if w := get("POST", "/"); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", w.Code)
	}
}

func TestPageFilesHaveNoInlineScriptOrOutsideSource(t *testing.T) {
	// The files the server serves (web/approval): no inline script, no handler attribute, nothing loaded from another site.
	for _, name := range []string{"index.html", "app.js", "intent.js", "style.css"} {
		b, err := os.ReadFile(filepath.Join("..", "..", "web", "approval", name))
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		if name == "index.html" {
			inline := false
			for _, tag := range regexp.MustCompile(`(?i)<script[^>]*>`).FindAllString(s, -1) {
				inline = inline || !strings.Contains(tag, "src=")
			}
			if inline || regexp.MustCompile(`(?i)\son[a-z]+\s*=`).MatchString(s) || regexp.MustCompile(`(?i)(src|href)\s*=\s*"(https?:)?//`).MatchString(s) {
				t.Errorf("index.html has inline script or an outside source")
			}
		}
		if regexp.MustCompile(`(?i)innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function|localStorage|document\.cookie|https?://[a-z]`).MatchString(s) {
			t.Errorf("%s uses something the page must not: %v", name, regexp.MustCompile(`(?i)innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function|localStorage|document\.cookie|https?://[a-z]`).FindString(s))
		}
	}
}
