package attest

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

type fakeNSM struct {
	got  []byte
	resp []byte
	err  error
}

func (f *fakeNSM) Exchange(req []byte) ([]byte, error) { f.got = req; return f.resp, f.err }
func (f *fakeNSM) Close() error                        { return nil }

func nsmReply(t *testing.T, v any) []byte {
	t.Helper()
	b, err := encMode.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The request is exactly the serde encoding of Request::Attestation: one map key, three fields, null for an absent one.
func TestNSMRequestEncoding(t *testing.T) {
	f := &fakeNSM{resp: nsmReply(t, map[string]map[string][]byte{"Attestation": {"document": []byte("DOC")}})}
	doc, err := NewNSMAttester(f).Attest([]byte("nonce"), []byte("pub"), nil)
	if err != nil || string(doc) != "DOC" {
		t.Fatalf("%q %v", doc, err)
	}
	var req map[string]map[string]cbor.RawMessage
	if err := strictDec.Unmarshal(f.got, &req); err != nil {
		t.Fatal(err)
	}
	inner := req["Attestation"]
	if len(req) != 1 || len(inner) != 3 {
		t.Fatalf("request %x", f.got)
	}
	var n, p []byte
	_ = strictDec.Unmarshal(inner["nonce"], &n)
	_ = strictDec.Unmarshal(inner["public_key"], &p)
	if string(n) != "nonce" || string(p) != "pub" || !bytes.Equal(inner["user_data"], []byte{0xf6}) {
		t.Fatalf("fields: nonce %q pub %q user_data %x (want CBOR null f6)", n, p, inner["user_data"])
	}
	// a fixed byte string: map(1) "Attestation" map(3) "user_data" null "nonce" 45.. "public_key" 43..
}

func TestNSMRefusals(t *testing.T) {
	big := func(n int) []byte { return make([]byte, n) }
	a := NewNSMAttester(&fakeNSM{})
	for name, tc := range map[string]struct{ n, p, u []byte }{
		"nonce":      {big(maxNonce + 1), nil, nil},
		"public key": {nil, big(maxPublicKey + 1), nil},
		"user data":  {nil, nil, big(maxUserData + 1)},
	} {
		if _, err := a.Attest(tc.n, tc.p, tc.u); err == nil || !strings.Contains(err.Error(), name) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// the three limits together still fit the device's request limit, so the largest legal call reaches the device
	f := &fakeNSM{resp: nsmReply(t, map[string]map[string][]byte{"Attestation": {"document": {1}}})}
	if _, err := NewNSMAttester(f).Attest(big(maxNonce), big(maxPublicKey), big(maxUserData)); err != nil || len(f.got) > nsmRequestMax {
		t.Fatalf("largest legal request: %v (%d bytes)", err, len(f.got))
	}
	for name, f := range map[string]*fakeNSM{
		"device error":   {err: errors.New("ioctl: boom")},
		"module error":   {resp: nsmReply(t, map[string]string{"Error": "InvalidArgument"})},
		"empty":          {resp: nil},
		"not a map":      {resp: []byte{0x01}},
		"two variants":   {resp: nsmReply(t, map[string]any{"Attestation": map[string][]byte{"document": {1}}, "Error": "x"})},
		"other variant":  {resp: nsmReply(t, map[string]any{"GetRandom": map[string][]byte{"random": {1}}})},
		"no document":    {resp: nsmReply(t, map[string]any{"Attestation": map[string][]byte{}})},
		"empty document": {resp: nsmReply(t, map[string]any{"Attestation": map[string][]byte{"document": {}}})},
		"oversized":      {resp: make([]byte, nsmResponseMax+1)},
		"truncated cbor": {resp: []byte{0xa1, 0x6b, 'A'}},
	} {
		if d, err := NewNSMAttester(f).Attest([]byte("n"), []byte("p"), []byte("u")); err == nil || d != nil {
			t.Fatalf("%s: got %q, %v", name, d, err)
		}
	}
	if _, err := NewNSMAttester(&fakeNSM{resp: nsmReply(t, map[string]string{"Error": "InvalidArgument"})}).Attest([]byte("n"), nil, nil); err == nil || !strings.Contains(err.Error(), "InvalidArgument") {
		t.Fatalf("the module's error code must reach the log: %v", err)
	}
}
