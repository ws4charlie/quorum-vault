package gen

import (
	"net"
	"net/http"
)

func serve(addr string, h http.Handler) (string, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", err
	}
	go func() { _ = http.Serve(ln, h) }()
	return ln.Addr().String(), nil
}
