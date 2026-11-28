package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

// The party's TLS identity when its private key is sealed (config tls_sealed, attested sealer only; docs/enclaves.md). The key is made INSIDE the party by `mpc-party tls-init` (the enrolment step), sealed under the party's local data key, and exported
// only as a certificate and a pin (the pins of every pinned link are by public key). The key never exists on disk in the clear: the data directory
// holds tls-key.sealed.json (ciphertext) and tls-cert.pem (public). At start the party loads the key only after the broker released the data keys;
// until then every TLS handshake fails (the party is not ready anyway).
//
// What this does not do: the link to the broker (sealer.broker_cert_file, broker_key_file) needs a key BEFORE any data key exists, so it stays a
// file. It is a different key, it only authenticates the link to the broker, and the broker releases nothing without passing evidence.

const (
	tlsSealedKeyFile = "tls-key.sealed.json"
	tlsCertPEMFile   = "tls-cert.pem"
)

// tlsHolder is the loaded certificate of a sealed identity; empty until the data keys are here.
type tlsHolder struct {
	p atomic.Pointer[tls.Certificate]
}

var errTLSNotReleased = errors.New("the party's TLS key is sealed and not released yet")

func (h *tlsHolder) get() (*tls.Certificate, error) {
	c := h.p.Load()
	if c == nil {
		return nil, errTLSNotReleased
	}
	return c, nil
}

// serverTLSFrom is ServerTLS with a certificate that may arrive after start.
func serverTLSFrom(h *tlsHolder, pins map[Pin]bool) *tls.Config {
	c := ServerTLS(tls.Certificate{}, pins)
	c.Certificates = nil
	c.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return h.get() }
	return c
}

// clientTLSFrom is ClientTLS with a certificate that may arrive after start.
func clientTLSFrom(h *tlsHolder, pins map[Pin]bool) *tls.Config {
	c := ClientTLS(tls.Certificate{}, pins)
	c.Certificates = nil
	c.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return h.get() }
	return c
}

// IdentityAware is implemented by an Authorizer that dials with the party's TLS identity (the cosigner channel): the server hands it the sealed
// identity's source once it exists.
type IdentityAware interface {
	SetIdentity(get func() (*tls.Certificate, error))
}

func (s *Server) tlsServer(pins map[Pin]bool) *tls.Config {
	if s.ident != nil {
		return serverTLSFrom(s.ident, pins)
	}
	return ServerTLS(s.cert, pins)
}

func (s *Server) tlsClient(pins map[Pin]bool) *tls.Config {
	if s.ident != nil {
		return clientTLSFrom(s.ident, pins)
	}
	return ClientTLS(s.cert, pins)
}

// certNow is the party's certificate (empty while a sealed key is not released).
func (s *Server) certNow() tls.Certificate {
	if s.ident != nil {
		if c := s.ident.p.Load(); c != nil {
			return *c
		}
		return tls.Certificate{}
	}
	return s.cert
}

// PutTLSKey seals the DER (PKCS#8) private key and writes it with the certificate. It refuses to overwrite an existing sealed key.
func (s *FileStore) putTLSIdentity(ctx context.Context, keyDER, certPEM []byte) error {
	if s.scoped == nil {
		return errors.New("a sealed TLS key needs the attested sealer")
	}
	p := filepath.Join(s.dir, tlsSealedKeyFile)
	if _, err := os.Stat(p); err == nil {
		return fmt.Errorf("%s exists: the party's TLS key is already enrolled", p)
	}
	sealed, err := s.sealLocal(ctx, "tls", "key", keyDER)
	if err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(s.dir, tlsCertPEMFile), certPEM); err != nil {
		return err
	}
	return writeAtomic(p, sealed)
}

// LoadTLSIdentity opens the sealed key and pairs it with the certificate; the pair must match.
func (s *FileStore) LoadTLSIdentity(ctx context.Context) (*tls.Certificate, error) {
	raw, err := os.ReadFile(filepath.Join(s.dir, tlsSealedKeyFile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("the TLS key is not enrolled (%s is missing): run `mpc-party tls-init` (docs/runbooks/tee-broker.md)", tlsSealedKeyFile)
		}
		return nil, err
	}
	der, err := s.openLocal(ctx, "tls", "key", raw)
	if err != nil {
		return nil, fmt.Errorf("sealed TLS key: %w", err)
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	for i := range der {
		der[i] = 0
	}
	if err != nil {
		return nil, fmt.Errorf("sealed TLS key: %w", err)
	}
	pemBytes, err := os.ReadFile(filepath.Join(s.dir, tlsCertPEMFile))
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		return nil, fmt.Errorf("%s holds no certificate", tlsCertPEMFile)
	}
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(*ecdsa.PrivateKey)
	if !ok || !signer.PublicKey.Equal(leaf.PublicKey) {
		return nil, errors.New("the sealed TLS key does not match tls-cert.pem")
	}
	return &tls.Certificate{Certificate: [][]byte{blk.Bytes}, PrivateKey: signer, Leaf: leaf}, nil
}

// EnrollTLS makes the party's TLS key inside this process, seals it, writes the certificate and returns the pin. It runs once per party, offline
// (`mpc-party tls-init`), after the sealer holds its local key. The certificate is self-signed: pins replace the CA check on every link.
func EnrollTLS(ctx context.Context, fs *FileStore, role string, valid time.Duration) (Pin, error) {
	var zero Pin
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return zero, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	now := time.Now()
	tpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "mpc-party-" + role},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(valid), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return zero, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return zero, err
	}
	if err := fs.putTLSIdentity(ctx, keyDER, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); err != nil {
		return zero, err
	}
	for i := range keyDER {
		keyDER[i] = 0
	}
	return PinOf(der)
}

// TLSPin reads the pin of the enrolled certificate (public data: no key needed).
func TLSPin(dataDir string) (Pin, error) {
	var zero Pin
	b, err := os.ReadFile(filepath.Join(dataDir, tlsCertPEMFile))
	if err != nil {
		return zero, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return zero, fmt.Errorf("%s holds no certificate", tlsCertPEMFile)
	}
	return PinOf(blk.Bytes)
}

// LoadEnrollConfig reads the config of the enrolment step: role, data_dir, tls_sealed and the sealer are what it needs; the rest (peer pins,
// listeners) cannot be known before the keys exist and is not checked. Because the measurement covers the config file, the enrolment config is a
// different measurement than the running party's: the allowlist holds both while the ceremony runs (docs/runbooks/tee-broker.md).
func LoadEnrollConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	c := new(Config)
	if err := dec.Decode(c); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	var errs []error
	if c.Role != "A" && c.Role != "B" && c.Role != "C" {
		errs = append(errs, errors.New("role must be A, B or C"))
	}
	if c.DataDir == "" {
		errs = append(errs, errors.New("data_dir is required"))
	}
	if !c.TLSSealed {
		errs = append(errs, errors.New("tls_sealed must be true"))
	}
	if c.Sealer.Type != AttestedSealerType {
		errs = append(errs, errors.New("sealer.type must be \"attested\""))
	} else if err := c.Sealer.validateAttested(); err != nil {
		errs = append(errs, err)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return c, nil
}

// TLSInit is `mpc-party tls-init`: the party proves itself to the broker (the same exchange as a start), makes its TLS key, seals it and returns the
// pin. Run again on an enrolled data directory it returns the same pin and changes nothing.
func TLSInit(ctx context.Context, c *Config, valid time.Duration) (Pin, bool, error) {
	var zero Pin
	lock, err := acquireDataLock(c.DataDir)
	if err != nil {
		return zero, false, err
	}
	defer lock.release()
	sealer, err := NewSealerForRole(c.Role, c.Sealer)
	if err != nil {
		return zero, false, err
	}
	fs, err := NewFileStore(c.DataDir, c.Role, sealer)
	if err != nil {
		return zero, false, err
	}
	if as, ok := sealer.(*AttestedSealer); ok {
		defer as.Close()
	}
	if _, err := os.Stat(filepath.Join(c.DataDir, tlsSealedKeyFile)); err == nil {
		p, err := TLSPin(c.DataDir)
		return p, false, err
	}
	if err := fs.PrepareSealer(ctx); err != nil {
		return zero, false, err
	}
	p, err := EnrollTLS(ctx, fs, c.Role, valid)
	return p, true, err
}
