//go:build !unix

package server

import "errors"

// secretBuf on a platform without mlock: not supported. The attested sealer refuses to start here.
type secretBuf struct{ b []byte }

func newSecretBuf(int) (*secretBuf, error) {
	return nil, errors.New("sealer attested: locked memory is not available on this platform")
}
func (s *secretBuf) bytes() []byte { return nil }
func (s *secretBuf) wipe()         {}
