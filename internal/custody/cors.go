package custody

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
)

// The approval page (web/approval) is served from its own origin, so the browser asks the core's permission before it lets the page read a
// reply. The permission is narrow: the origins named by -approval-origins (or QV_APPROVAL_ORIGINS), only the three routes the page uses,
// only the headers it sends, and never credentials (the page sends a bearer token it holds in memory; there are no cookies). With no origin
// configured the core adds no CORS header at all, so a browser keeps refusing every cross-origin page.
var (
	corsMu      sync.Mutex
	corsOrigins []string
)

// AllowApprovalOrigins adds the comma separated origins (scheme://host[:port], nothing else) that may call the approval routes from a browser.
// It is the function behind the -approval-origins flag, so a bad value stops qv-core at start.
func AllowApprovalOrigins(list string) error {
	var add []string
	for _, o := range strings.Split(list, ",") {
		if o = strings.TrimSpace(o); o == "" {
			continue
		}
		u, err := url.Parse(o)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil || strings.Contains(o, "*") {
			return fmt.Errorf("approval origin %q: want scheme://host[:port] with no path and no wildcard", o)
		}
		add = append(add, u.Scheme+"://"+u.Host)
	}
	corsMu.Lock()
	corsOrigins = append(corsOrigins, add...)
	corsMu.Unlock()
	return nil
}

// corsRoutes are the routes the page calls and the one method each takes. The same rules that guard them (routeRules) still apply to the call itself.
var corsRoutes = []struct {
	re     *regexp.Regexp
	method string
}{
	{regexp.MustCompile(`^/v2/withdrawals/[^/]+$`), http.MethodGet},
	{regexp.MustCompile(`^/v2/withdrawals/[^/]+/intent$`), http.MethodGet},
	{regexp.MustCompile(`^/v2/withdrawals/[^/]+/approvals$`), http.MethodPost},
}

func corsMethod(path string) string {
	for _, r := range corsRoutes {
		if r.re.MatchString(path) {
			return r.method
		}
	}
	return ""
}

// approvalCORS wraps the API handler. A request from a listed origin to one of the three routes gets the exact origin echoed back (never "*"),
// with Vary: Origin; a preflight for one of them is answered here without reaching the routes. Anything else passes through untouched.
func approvalCORS(next http.Handler) http.Handler {
	if env := os.Getenv("QV_APPROVAL_ORIGINS"); env != "" {
		if err := AllowApprovalOrigins(env); err != nil {
			panic(err) // a bad value must stop the start, not widen or silently drop the policy
		}
	}
	corsMu.Lock()
	origins := append([]string(nil), corsOrigins...)
	corsMu.Unlock()
	if len(origins) == 0 {
		return next
	}
	allowed := map[string]bool{}
	for _, o := range origins {
		allowed[o] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		method := corsMethod(r.URL.Path)
		if origin == "" || method == "" {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Add("Vary", "Origin")
		if !allowed[origin] {
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r) // served as before; the browser refuses the reply for lack of the header
			return
		}
		if r.Method == http.MethodOptions {
			if r.Header.Get("Access-Control-Request-Method") != method {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			h := w.Header()
			h.Add("Vary", "Access-Control-Request-Method")
			h.Add("Vary", "Access-Control-Request-Headers")
			h.Set("Access-Control-Allow-Origin", origin)
			h.Set("Access-Control-Allow-Methods", method)
			h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			h.Set("Access-Control-Max-Age", "600")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Expose-Headers", "WWW-Authenticate") // the page reads the step-up challenge from it
		next.ServeHTTP(w, r)
	})
}
