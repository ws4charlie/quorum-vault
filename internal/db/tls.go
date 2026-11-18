package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ws4charlie/quorum-vault/internal/pki"
)

// PoolConfig parses a DSN for a QuorumVault service and applies the transport rule: the connection must be TLS with the server's certificate
// and host name verified (sslmode=verify-full). Anything weaker (disable, allow, prefer, require, verify-ca) is refused, except with
// pki.PlaintextAllowed (QV_ALLOW_PLAINTEXT=1 and QV_ENV=dev), which production never has.
//
// With src, every new connection (the pool opens new ones as old ones age out) presents src's CURRENT certificate and checks the server
// against src's CURRENT CA pool, so a rotated certificate needs no restart; serverAllow, when not empty, is the list of names the server's
// certificate may have. Without src the certificate files named in the DSN (sslcert, sslkey, sslrootcert) are used as pgx loads them, once.
//
// Postgres cannot check a URI name; it maps the certificate's CN to a role (pg_ident) and trusts one CA per server. See docs/runbooks/certificates.md.
func PoolConfig(dsn string, src *pki.Source, serverAllow pki.Allow) (*pgxpool.Config, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("db: %w", redact(err))
	}
	if !pki.PlaintextAllowed() {
		tc := cfg.ConnConfig.TLSConfig
		if tc == nil || tc.InsecureSkipVerify || len(cfg.ConnConfig.Fallbacks) > 0 {
			return nil, errors.New("db: the DSN must use sslmode=verify-full with the server's CA (production never connects to Postgres without TLS; QV_ALLOW_PLAINTEXT=1 with QV_ENV=dev is the development switch)")
		}
	}
	if src != nil {
		host := cfg.ConnConfig.Host
		cfg.BeforeConnect = func(_ context.Context, cc *pgx.ConnConfig) error {
			cc.TLSConfig = src.ClientConfig(host, serverAllow)
			return nil
		}
		// the stored config is only the starting point: replace it now so the first connection already follows src
		cfg.ConnConfig.TLSConfig = src.ClientConfig(host, serverAllow)
		cfg.ConnConfig.Fallbacks = nil
	}
	return cfg, nil
}

// NewPool opens a pool with PoolConfig's rules (no ping).
func NewPool(ctx context.Context, dsn string, src *pki.Source, serverAllow pki.Allow) (*pgxpool.Pool, error) {
	cfg, err := PoolConfig(dsn, src, serverAllow)
	if err != nil {
		return nil, err
	}
	return pgxpool.NewWithConfig(ctx, cfg)
}

// OpenTLS is Open with PoolConfig's rules.
func OpenTLS(ctx context.Context, dsn string, src *pki.Source, serverAllow pki.Allow) (*pgxpool.Pool, error) {
	pool, err := NewPool(ctx, dsn, src, serverAllow)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("db: ping: %w", err)
	}
	return pool, nil
}

// redact keeps a DSN's password out of a parse error (pgx puts the DSN in it).
func redact(error) error { return errors.New("cannot parse the DSN") }
