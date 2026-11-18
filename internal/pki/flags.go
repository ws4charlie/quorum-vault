package pki

import (
	"errors"
	"flag"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"
)

// PlaintextAllowed is the one switch that lets a service run without TLS: QV_ALLOW_PLAINTEXT=1 together with QV_ENV=dev or test.
// Anything else, including an unset QV_ENV (production is the default), refuses, like the X-Actor header.
func PlaintextAllowed() bool {
	env := strings.ToLower(strings.TrimSpace(os.Getenv("QV_ENV")))
	return os.Getenv("QV_ALLOW_PLAINTEXT") == "1" && (env == "dev" || env == "test")
}

// Flags registers the TLS file flags of one identity on fs (-<prefix>tls-cert, -tls-key, -tls-ca, -tls-reload; environment QV_<PREFIX>TLS_CERT and so on,
// with prefix "" for the service's main identity) and returns the function that builds the Source after fs.Parse.
//
// The Source is nil, with no error, only when no file is configured and PlaintextAllowed says so; otherwise missing TLS is an error.
func Flags(fs *flag.FlagSet, prefix string) func(name, zone string, log *slog.Logger) (*Source, error) {
	env := func(s string) string { return "QV_" + upper(prefix) + "TLS_" + s }
	cert := fs.String(prefix+"tls-cert", os.Getenv(env("CERT")), "TLS certificate file (PEM), reloaded while running (env "+env("CERT")+")")
	key := fs.String(prefix+"tls-key", os.Getenv(env("KEY")), "TLS private key file (env "+env("KEY")+")")
	ca := fs.String(prefix+"tls-ca", os.Getenv(env("CA")), "CA bundle (PEM) this identity trusts (env "+env("CA")+")")
	reload := fs.Duration(prefix+"tls-reload", durEnv(env("RELOAD"), DefaultReloadInterval), "how often the TLS files are re-read (env "+env("RELOAD")+")")
	return func(name, zone string, log *slog.Logger) (*Source, error) {
		if *cert == "" && *key == "" && *ca == "" {
			if PlaintextAllowed() {
				return nil, nil
			}
			return nil, errors.New(name + ": TLS is required: set -" + prefix + "tls-cert, -" + prefix + "tls-key and -" + prefix + "tls-ca (certificates: docs/runbooks/certificates.md); plain text needs QV_ALLOW_PLAINTEXT=1 and QV_ENV=dev, and production refuses it")
		}
		if *cert == "" || *key == "" || *ca == "" {
			return nil, errors.New(name + ": -" + prefix + "tls-cert, -" + prefix + "tls-key and -" + prefix + "tls-ca must all be set")
		}
		return NewSource(SourceConfig{Name: name, Zone: zone, CertFile: *cert, KeyFile: *key, CAFile: *ca, Interval: *reload, Log: log})
	}
}

func upper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 32
		} else if c == '-' {
			b[i] = '_'
		}
	}
	if len(b) > 0 {
		b = append(b, '_')
	}
	return string(b)
}

func durEnv(k string, d time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if x, err := time.ParseDuration(v); err == nil && x > 0 {
			return x
		}
	}
	return d
}

// RequireLoopback refuses a listen address that is not on the loopback interface. Metrics are served in plain http on this machine only; a
// scraper elsewhere reaches them through the host's own agent or a tunnel, not an open port (docs/runbooks/certificates.md).
func RequireLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return errors.New("metrics are plain http and are served on a loopback address only (127.0.0.1 or ::1), not " + addr)
}
