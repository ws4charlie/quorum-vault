package db

import (
	"net/url"
)

// Rewrite returns base with another user and/or database name (an empty argument keeps what base has). The query, which carries
// sslmode and the certificate files, is kept: a DSN made by string formatting would silently drop it.
func Rewrite(base, user, database string) string {
	u, err := url.Parse(base)
	if err != nil {
		return base
	}
	if user != "" {
		u.User = url.User(user)
	}
	if database != "" {
		u.Path = "/" + database
	}
	return u.String()
}

// WithClientCert returns base with another client certificate and key (and the CA that verifies the server, when serverCA is not empty).
func WithClientCert(base, certFile, keyFile, serverCA string) string {
	u, err := url.Parse(base)
	if err != nil {
		return base
	}
	q := u.Query()
	q.Set("sslmode", "verify-full")
	q.Set("sslcert", certFile)
	q.Set("sslkey", keyFile)
	if serverCA != "" {
		q.Set("sslrootcert", serverCA)
	}
	u.RawQuery = q.Encode()
	return u.String()
}
