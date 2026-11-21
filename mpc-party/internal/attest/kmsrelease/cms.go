package kmsrelease

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
)

// The answer of an attested KMS call, CiphertextForRecipient, is a CMS EnvelopedData (RFC 5652 section 6): one KeyTransRecipientInfo (version 2,
// subjectKeyIdentifier) holding the content key encrypted with RSAES-OAEP/SHA-256, and the content encrypted with AES-256-CBC.
// [KMS-API] https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html (CiphertextForRecipient; KeyEncryptionAlgorithm RSAES_OAEP_SHA_256 is the only
// value). The exact layout is what AWS's own client parses: aws-nitro-enclaves-sdk-c source/cms.c ("Always assumes RecipientInfo to have RSA-OAEP with
// SHA256 for envelope encryption and AES-256-CBC for content encryption"; it reads BER, including indefinite lengths and a constructed, chunked
// content octet string, because that is what KMS emits). This file does the same in Go, strictly: any other algorithm is refused.

var (
	oidEnvelopedData = []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x03} // 1.2.840.113549.1.7.3
	oidData          = []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01} // 1.2.840.113549.1.7.1
	oidRSAOAEP       = []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x07} // 1.2.840.113549.1.1.7
	oidSHA256        = []byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01} // 2.16.840.1.101.3.4.2.1
	oidAES256CBC     = []byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a} // 2.16.840.1.101.3.4.1.42
)

const (
	maxCMS     = 64 << 10
	maxBERDeep = 8
)

type tlv struct {
	tag         byte // identifier octet (single-byte tags only)
	constructed bool
	content     []byte // without the end-of-contents of an indefinite length
}

// readTLV reads one BER element: definite or indefinite length (constructed only), single-byte identifier. rest is what follows it.
func readTLV(b []byte, depth int) (t tlv, rest []byte, err error) {
	if depth > maxBERDeep {
		return t, nil, errors.New("cms: nesting too deep")
	}
	if len(b) < 2 {
		return t, nil, errors.New("cms: truncated")
	}
	t.tag, t.constructed = b[0], b[0]&0x20 != 0
	if b[0]&0x1f == 0x1f {
		return t, nil, errors.New("cms: multi-byte tag")
	}
	l := b[1]
	b = b[2:]
	switch {
	case l < 0x80:
		if int(l) > len(b) {
			return t, nil, errors.New("cms: truncated")
		}
		t.content, rest = b[:l], b[l:]
	case l == 0x80: // indefinite
		if !t.constructed {
			return t, nil, errors.New("cms: indefinite length on a primitive element")
		}
		rem := b
		for {
			if len(rem) >= 2 && rem[0] == 0 && rem[1] == 0 {
				t.content = b[:len(b)-len(rem)]
				return t, rem[2:], nil
			}
			_, r, err := readTLV(rem, depth+1)
			if err != nil {
				return t, nil, err
			}
			rem = r
		}
	default:
		n := int(l & 0x7f)
		if n > 3 || len(b) < n {
			return t, nil, errors.New("cms: bad length")
		}
		size := 0
		for _, x := range b[:n] {
			size = size<<8 | int(x)
		}
		b = b[n:]
		if size > len(b) {
			return t, nil, errors.New("cms: truncated")
		}
		t.content, rest = b[:size], b[size:]
	}
	return t, rest, nil
}

// children reads every element of a constructed element's content.
func children(b []byte, depth int) ([]tlv, error) {
	var out []tlv
	for len(b) > 0 {
		t, r, err := readTLV(b, depth)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
		b = r
	}
	return out, nil
}

func expect(t tlv, tag byte, what string) error {
	if t.tag != tag {
		return fmt.Errorf("cms: %s: tag %#x, want %#x", what, t.tag, tag)
	}
	return nil
}

// octets returns the bytes of an OCTET STRING (primitive, or constructed of chunks) or of an implicit [0] content of either kind.
func octets(t tlv) ([]byte, error) {
	if !t.constructed {
		return t.content, nil
	}
	parts, err := children(t.content, 1)
	if err != nil {
		return nil, err
	}
	var out []byte
	for _, p := range parts {
		if p.constructed || p.tag != 0x04 {
			return nil, errors.New("cms: chunk of the content is not an octet string")
		}
		out = append(out, p.content...)
	}
	return out, nil
}

// OpenEnvelope decrypts a CiphertextForRecipient with the recipient's private key.
func OpenEnvelope(priv *rsa.PrivateKey, cms []byte) ([]byte, error) {
	if len(cms) == 0 || len(cms) > maxCMS {
		return nil, errors.New("cms: bad size")
	}
	ci, rest, err := readTLV(cms, 0)
	if err != nil || len(rest) != 0 || ci.tag != 0x30 {
		return nil, errors.New("cms: not a ContentInfo")
	}
	top, err := children(ci.content, 1)
	if err != nil || len(top) != 2 || top[0].tag != 0x06 || !bytes.Equal(top[0].content, oidEnvelopedData) || top[1].tag != 0xA0 {
		return nil, errors.New("cms: not EnvelopedData")
	}
	inner, err := children(top[1].content, 2)
	if err != nil || len(inner) != 1 || inner[0].tag != 0x30 {
		return nil, errors.New("cms: EnvelopedData is not one sequence")
	}
	ed, err := children(inner[0].content, 3)
	if err != nil || len(ed) < 3 {
		return nil, errors.New("cms: EnvelopedData is malformed")
	}
	if ed[0].tag != 0x02 || len(ed[0].content) != 1 || ed[0].content[0] != 2 {
		return nil, errors.New("cms: EnvelopedData version is not 2")
	}
	ed = ed[1:]
	if ed[0].tag == 0xA0 { // originatorInfo: not used
		ed = ed[1:]
	}
	if len(ed) != 2 || ed[0].tag != 0x31 || ed[1].tag != 0x30 {
		return nil, errors.New("cms: expected recipientInfos and encryptedContentInfo")
	}
	ris, err := children(ed[0].content, 4)
	if err != nil || len(ris) != 1 || ris[0].tag != 0x30 {
		return nil, errors.New("cms: expected exactly one recipient")
	}
	ri, err := children(ris[0].content, 5)
	if err != nil || len(ri) != 4 {
		return nil, errors.New("cms: recipient info is malformed")
	}
	if ri[0].tag != 0x02 || len(ri[0].content) != 1 || ri[0].content[0] != 2 { // subjectKeyIdentifier form
		return nil, errors.New("cms: recipient info version is not 2")
	}
	if err := expect(ri[2], 0x30, "key encryption algorithm"); err != nil {
		return nil, err
	}
	alg, err := children(ri[2].content, 6)
	if err != nil || len(alg) < 1 || alg[0].tag != 0x06 || !bytes.Equal(alg[0].content, oidRSAOAEP) {
		return nil, errors.New("cms: key encryption algorithm is not RSAES-OAEP")
	}
	if len(alg) > 1 { // parameters: hash algorithm must be SHA-256 (the only one KMS uses)
		if !bytes.Contains(alg[1].content, oidSHA256) {
			return nil, errors.New("cms: RSAES-OAEP parameters do not name SHA-256")
		}
	}
	if err := expect(ri[3], 0x04, "encrypted key"); err != nil {
		return nil, err
	}
	eci, err := children(ed[1].content, 3)
	if err != nil || len(eci) != 3 || eci[0].tag != 0x06 || !bytes.Equal(eci[0].content, oidData) || eci[1].tag != 0x30 || (eci[2].tag != 0x80 && eci[2].tag != 0xA0) {
		return nil, errors.New("cms: encryptedContentInfo is malformed")
	}
	calg, err := children(eci[1].content, 4)
	if err != nil || len(calg) != 2 || calg[0].tag != 0x06 || !bytes.Equal(calg[0].content, oidAES256CBC) || calg[1].tag != 0x04 || len(calg[1].content) != aes.BlockSize {
		return nil, errors.New("cms: content encryption is not AES-256-CBC with a 16-byte IV")
	}
	ct, err := octets(eci[2])
	if err != nil {
		return nil, err
	}
	if len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
		return nil, errors.New("cms: ciphertext is not a whole number of blocks")
	}
	key, err := rsa.DecryptOAEP(sha256.New(), nil, priv, ri[3].content, nil)
	if err != nil || len(key) != 32 {
		return nil, errors.New("cms: the content key does not open under this recipient key")
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(blk, calg[1].content).CryptBlocks(pt, ct)
	for i := range key {
		key[i] = 0
	}
	pad := int(pt[len(pt)-1])
	if pad < 1 || pad > aes.BlockSize || pad > len(pt) {
		return nil, errors.New("cms: bad padding")
	}
	for _, p := range pt[len(pt)-pad:] {
		if int(p) != pad {
			return nil, errors.New("cms: bad padding")
		}
	}
	return pt[:len(pt)-pad], nil
}
