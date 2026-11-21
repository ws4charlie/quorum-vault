//go:build teesim

package kmsrelease_test

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func parseRSAKey(t *testing.T, pemBytes []byte) *rsa.PrivateKey {
	t.Helper()
	b, _ := pem.Decode(pemBytes)
	if b == nil {
		t.Fatal("no PEM block")
	}
	k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return k.(*rsa.PrivateKey)
}
