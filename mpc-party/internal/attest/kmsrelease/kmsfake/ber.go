//go:build teesim

package kmsfake

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
)

// An encoder for the CiphertextForRecipient that KMS emits: CMS EnvelopedData as BER, with indefinite lengths and a chunked content octet string
// (the layout aws-nitro-enclaves-sdk-c's parser, source/cms.c, handles). Written from RFC 5652 and that parser, not from the decoder under test.

func tlv(tag byte, content ...[]byte) []byte {
	var body []byte
	for _, c := range content {
		body = append(body, c...)
	}
	out := []byte{tag}
	switch n := len(body); {
	case n < 0x80:
		out = append(out, byte(n))
	case n < 0x100:
		out = append(out, 0x81, byte(n))
	default:
		out = append(out, 0x82, byte(n>>8), byte(n))
	}
	return append(out, body...)
}

func indef(tag byte, content ...[]byte) []byte {
	out := []byte{tag, 0x80}
	for _, c := range content {
		out = append(out, c...)
	}
	return append(out, 0, 0)
}

var (
	oidEnveloped = []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x03}
	oidData      = []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01}
	oidOAEP      = []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x07}
	oidSHA256    = []byte{0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01}
	oidAES256CBC = []byte{0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a}
)

// Envelope encrypts plaintext to pub the way KMS does. indefinite selects BER indefinite lengths (what KMS sends) or plain DER.
func Envelope(pub *rsa.PublicKey, plaintext []byte, indefinite bool) ([]byte, error) {
	key, iv := make([]byte, 32), make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	encKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, key, nil)
	if err != nil {
		return nil, err
	}
	pad := aes.BlockSize - len(plaintext)%aes.BlockSize
	padded := append(append([]byte(nil), plaintext...), make([]byte, pad)...)
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = byte(pad)
	}
	blk, _ := aes.NewCipher(key)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(blk, iv).CryptBlocks(ct, padded)

	skiBytes := sha1.Sum(pub.N.Bytes())
	oaepParams := tlv(0x30, oidSHA256) // hashAlgorithm is context [0] in RFC 4055; a SEQUENCE holding the hash OID is enough for the parser under test
	ri := tlv(0x30, tlv(0x02, []byte{2}), tlv(0x80, skiBytes[:]), tlv(0x30, oidOAEP, oaepParams), tlv(0x04, encKey))
	calg := tlv(0x30, oidAES256CBC, tlv(0x04, iv))
	var content, outer func(tag byte, c ...[]byte) []byte
	if indefinite {
		outer = indef
		content = indef
	} else {
		outer, content = tlv, tlv
	}
	// content as KMS sends it: [0] constructed, split into two chunks
	half := len(ct) / 2 / aes.BlockSize * aes.BlockSize
	var eContent []byte
	if indefinite && half > 0 {
		eContent = indef(0xA0, tlv(0x04, ct[:half]), tlv(0x04, ct[half:]))
	} else {
		eContent = tlv(0x80, ct)
	}
	eci := content(0x30, oidData, calg, eContent)
	ed := outer(0x30, tlv(0x02, []byte{2}), tlv(0x31, ri), eci)
	return outer(0x30, oidEnveloped, outer(0xA0, ed)), nil
}
