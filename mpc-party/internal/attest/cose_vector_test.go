package attest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"testing"
)

// Known-answer test from an independent source: cose-wg/Examples, ecdsa-examples/ecdsa-sig-02.json ("ECDSA-sig-02: ECDSA - P-384 - sign1"),
// https://github.com/cose-wg/Examples/blob/master/ecdsa-examples/ecdsa-sig-02.json . Our Sig_structure and signature code must reproduce
// the vector's ToBeSign bytes and accept its signature; the mock attester plays no part here.
const (
	vecToBeSign = "846A5369676E61747572653144A10138224054546869732069732074686520636F6E74656E742E"
	vecCOSE     = "D28444A1013822A104445033383454546869732069732074686520636F6E74656E742E58605F150ABD1C7D25B32065A14E05D6CB1F665D10769FF455EA9A2E0ADAB5DE63838DB257F0949C41E13330E110EBA7B912F34E1546FB1366A2568FAA91EC3E6C8D42F4A67A0EDF731D88C9AEAD52258B2E2C4740EF614F02E9D91E9B7B59622A3C"
	vecX        = "kTJyP2KSsBBhnb4kjWmMF7WHVsY55xUPgb7k64rDcjatChoZ1nvjKmYmPh5STRKc"
	vecY        = "mM0weMVU2DKsYDxDJkEP9hZiRZtB8fPfXbzINZj_fF7YQRynNWedHEyzAJOX2e8s"
)

func TestCOSEKnownAnswer(t *testing.T) {
	b64 := func(s string) *big.Int {
		d, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return new(big.Int).SetBytes(d)
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P384(), X: b64(vecX), Y: b64(vecY)}
	raw, _ := hex.DecodeString(vecCOSE)
	s, err := parseSign1(raw)
	if err != nil {
		t.Fatal(err)
	}
	tbs, err := sigStructure(s.Protected, s.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(tbs); got != hex.EncodeToString(mustHex(t, vecToBeSign)) {
		t.Fatalf("Sig_structure differs from the vector:\n got %s", got)
	}
	if err := verifySign1(pub, s.Protected, s.Payload, s.Signature); err != nil {
		t.Fatalf("vector signature refused: %v", err)
	}
	// negative controls: another payload, a flipped signature bit
	if verifySign1(pub, s.Protected, []byte("This is the content!"), s.Signature) == nil {
		t.Fatal("wrong payload verified")
	}
	bad := append([]byte{}, s.Signature...)
	bad[5] ^= 1
	if verifySign1(pub, s.Protected, s.Payload, bad) == nil {
		t.Fatal("flipped signature verified")
	}
}

func mustHex(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
