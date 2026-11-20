package custody

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func resetCORS(t *testing.T, list string) {
	t.Helper()
	corsMu.Lock()
	corsOrigins = nil
	corsMu.Unlock()
	t.Setenv("QV_APPROVAL_ORIGINS", "")
	if err := AllowApprovalOrigins(list); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { corsMu.Lock(); corsOrigins = nil; corsMu.Unlock() })
}

func serve(h http.Handler, method, path string, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, nil)
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestApprovalCORS(t *testing.T) {
	resetCORS(t, "https://approve.example.com")
	h := approvalCORS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTeapot) }))
	const origin = "https://approve.example.com"

	// Preflight of the approval route from the listed origin: answered, exact origin, the route's one method, no credentials.
	w := serve(h, "OPTIONS", "/v2/withdrawals/w1/approvals", map[string]string{"Origin": origin, "Access-Control-Request-Method": "POST"})
	if w.Code != 204 || w.Header().Get("Access-Control-Allow-Origin") != origin || w.Header().Get("Access-Control-Allow-Methods") != "POST" {
		t.Fatalf("preflight: %d %v", w.Code, w.Header())
	}
	if w.Header().Get("Access-Control-Allow-Credentials") != "" || w.Header().Get("Access-Control-Allow-Headers") != "Authorization, Content-Type" {
		t.Fatalf("preflight headers: %v", w.Header())
	}
	// The call itself carries the origin and exposes the step-up challenge.
	w = serve(h, "GET", "/v2/withdrawals/w1/intent", map[string]string{"Origin": origin})
	if w.Code != http.StatusTeapot || w.Header().Get("Access-Control-Allow-Origin") != origin || w.Header().Get("Access-Control-Expose-Headers") != "WWW-Authenticate" {
		t.Fatalf("call: %d %v", w.Code, w.Header())
	}
	// Refused: another origin, another method on the route, other routes, a prefix of the listed origin.
	for name, c := range map[string]struct {
		method, path string
		hdr          map[string]string
	}{
		"other origin":     {"OPTIONS", "/v2/withdrawals/w1/approvals", map[string]string{"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"}},
		"origin as suffix": {"OPTIONS", "/v2/withdrawals/w1/approvals", map[string]string{"Origin": origin + ".evil.example", "Access-Control-Request-Method": "POST"}},
		"wrong method":     {"OPTIONS", "/v2/withdrawals/w1/intent", map[string]string{"Origin": origin, "Access-Control-Request-Method": "POST"}},
		"other route":      {"OPTIONS", "/v2/cold/actions", map[string]string{"Origin": origin, "Access-Control-Request-Method": "POST"}},
		"rejections route": {"OPTIONS", "/v2/withdrawals/w1/rejections", map[string]string{"Origin": origin, "Access-Control-Request-Method": "POST"}},
		"nested path":      {"OPTIONS", "/v2/withdrawals/w1/intent/x", map[string]string{"Origin": origin, "Access-Control-Request-Method": "GET"}},
	} {
		w := serve(h, c.method, c.path, c.hdr)
		if w.Header().Get("Access-Control-Allow-Origin") != "" || w.Code == 204 {
			t.Errorf("%s: %d %v", name, w.Code, w.Header())
		}
	}
	// A call from another origin is served as before but gets no permission header; the other routes get none even from the listed origin.
	if w := serve(h, "POST", "/v2/withdrawals/w1/approvals", map[string]string{"Origin": "https://evil.example"}); w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("evil call: %v", w.Header())
	}
	if w := serve(h, "POST", "/v2/cold/actions", map[string]string{"Origin": origin}); w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("other route: %v", w.Header())
	}
}

func TestApprovalCORSOffByDefaultAndStrictList(t *testing.T) {
	resetCORS(t, "")
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	w := serve(approvalCORS(next), "OPTIONS", "/v2/withdrawals/w1/approvals", map[string]string{"Origin": "https://a.example", "Access-Control-Request-Method": "POST"})
	if w.Header().Get("Access-Control-Allow-Origin") != "" || w.Header().Get("Vary") != "" {
		t.Fatalf("off: %v", w.Header())
	}
	for _, bad := range []string{"*", "https://*.example.com", "https://a.example/", "https://a.example/x", "ftp://a.example", "a.example", "https://u@a.example"} {
		if err := AllowApprovalOrigins(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
