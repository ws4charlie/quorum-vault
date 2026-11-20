package broker

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

// ServeListener serves the mutual-TLS API on an existing listener until ctx ends (an in-process broker for tests of its clients, which need the
// port the listener picked). Serve is the same on cfg.Listen.
func (s *Server) ServeListener(ctx context.Context, ln net.Listener) error {
	tc, err := s.cfg.tlsConfig(s.set)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: s.Handler(), TLSConfig: tc, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second}
	go func() { <-ctx.Done(); srv.Close() }()
	err = srv.Serve(tls.NewListener(ln, tc))
	if ctx.Err() != nil {
		return nil
	}
	return err
}
