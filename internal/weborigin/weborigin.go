// Package weborigin holds the rule for a WebAuthn approver origin, shared by the signing zone (internal/gateway, which enforces it)
// and the approver tool (internal/approvecli, which refuses at enrolment what the zone would refuse). It has no dependencies, so the
// approver tool does not pull in the gateway.
package weborigin

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Check enforces the origin rule. The zone compares origins byte for byte with what the browser writes into clientDataJSON, so an
// origin is accepted only in that canonical form: scheme://host[:port] with a lowercase scheme and host, an ASCII host (punycode,
// xn--, for an international name), no trailing dot, no empty or default port (443 for https, 80 for http), an IP literal in its
// shortest form, and no path, query, fragment or userinfo. https is always allowed. http is allowed only for the exact hosts
// localhost, 127.0.0.1 and [::1], and only when allowHTTPLoopback is true: callers pass true only when QV_ENV is dev or test
// (auth.EnvironmentFromEnv; unset or anything else is production). Errors name the rule and, where there is one, the canonical form.
func Check(origin string, allowHTTPLoopback bool) error {
	for _, r := range origin {
		if r > 0x7e || r < 0x21 {
			return fmt.Errorf("origin %q: the host must be ASCII; write an international name in its punycode (xn--) form, as the browser sends it", origin)
		}
	}
	if strings.Contains(origin, "%") {
		return fmt.Errorf("origin %q: no percent-encoding; write the host as the browser sends it", origin)
	}
	u, err := url.Parse(origin)
	if err != nil || u.Opaque != "" || u.Host == "" || u.Hostname() == "" {
		return fmt.Errorf("origin %q must be exactly scheme://host[:port], e.g. https://approve.example.com", origin)
	}
	canon, perr := canonical(u)
	if perr != nil {
		return fmt.Errorf("origin %q: %v", origin, perr)
	}
	if origin != canon {
		return fmt.Errorf("origin %q is not in the form the browser sends (lowercase, no path, query, fragment or userinfo, no default or empty port, no trailing dot): write %q", origin, canon)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		switch u.Hostname() {
		case "localhost", "127.0.0.1", "::1":
			if !allowHTTPLoopback {
				return fmt.Errorf("origin %q: http is refused in production (QV_ENV unset or not dev/test); use https", origin)
			}
			return nil
		}
	}
	return fmt.Errorf("origin %q must be https, or http on exactly localhost, 127.0.0.1 or [::1] when QV_ENV is dev or test", origin)
}

// canonical is the origin as a browser serializes it.
func canonical(u *url.URL) (string, error) {
	scheme := strings.ToLower(u.Scheme)
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if ip := net.ParseIP(host); ip != nil && strings.Contains(host, ":") {
		host = "[" + ip.String() + "]"
	}
	port := u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", fmt.Errorf("port %q is not a port number (1-65535)", port)
		}
		port = strconv.Itoa(n)
		if scheme == "https" && n == 443 || scheme == "http" && n == 80 {
			port = ""
		}
	}
	if port != "" {
		host += ":" + port
	}
	return scheme + "://" + host, nil
}
