package admin

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

// adminRequests finds, from the service definition, every request message of an RPC that carries an AdminAuth. A new admin RPC shows up here by
// itself: the tests below then fail until the operation is known to BodyOf and the party rebuilds its body.
func adminRequests(t *testing.T) []protoreflect.MessageDescriptor {
	t.Helper()
	var out []protoreflect.MessageDescriptor
	ms := pb.File_mpcparty_v1_mpcparty_proto.Services().ByName("MpcParty").Methods()
	for i := 0; i < ms.Len(); i++ {
		in := ms.Get(i).Input()
		for j := 0; j < in.Fields().Len(); j++ {
			if f := in.Fields().Get(j); f.Message() != nil && f.Message().FullName() == authMessageName {
				out = append(out, in)
			}
		}
	}
	return out
}

func opOf(t *testing.T, d protoreflect.MessageDescriptor) string {
	t.Helper()
	switch d.Name() {
	case "DKGRequest":
		return OpDKG
	case "RefreshRequest":
		return OpRefresh
	case "UnfreezeRequest":
		return OpUnfreeze
	}
	t.Fatalf("admin request %s is not known to this package: add its operation to BodyOf, Request.body and the parties' check, and extend this test", d.FullName())
	return ""
}

// fill sets a field to a value other than its zero value (and, with alt, to a different one).
func fill(m protoreflect.Message, fd protoreflect.FieldDescriptor, alt bool) {
	n := int64(7)
	if alt {
		n = 9
	}
	var v protoreflect.Value
	switch fd.Kind() {
	case protoreflect.StringKind:
		v = protoreflect.ValueOfString(map[bool]string{false: "x", true: "y"}[alt])
	case protoreflect.BytesKind:
		v = protoreflect.ValueOfBytes([]byte{byte(n)})
	case protoreflect.BoolKind:
		v = protoreflect.ValueOfBool(true)
	case protoreflect.EnumKind:
		vals := fd.Enum().Values()
		i := 1
		if alt && vals.Len() > 2 {
			i = 2
		}
		v = protoreflect.ValueOfEnum(vals.Get(i).Number())
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		v = protoreflect.ValueOfInt32(int32(n))
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		v = protoreflect.ValueOfInt64(n)
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		v = protoreflect.ValueOfUint32(uint32(n))
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		v = protoreflect.ValueOfUint64(uint64(n))
	case protoreflect.MessageKind:
		sub := m.NewField(fd).Message()
		for i := 0; i < sub.Descriptor().Fields().Len(); i++ {
			fill(sub, sub.Descriptor().Fields().Get(i), alt)
		}
		v = protoreflect.ValueOfMessage(sub)
	default:
		panic("test cannot fill " + fd.Kind().String())
	}
	switch {
	case fd.IsMap():
		panic("map in an admin request")
	case fd.IsList():
		m.Mutable(fd).List().Append(v)
	default:
		m.Set(fd, v)
	}
}

// Every field of every admin request is inside the hash the admins sign: changing any one of them (to any other value) changes the hash. A field
// added to DKGRequest, RefreshRequest or UnfreezeRequest later is picked up here at once; one that BodyHash cannot cover makes it fail.
func TestEveryAdminRequestFieldIsSigned(t *testing.T) {
	reqs := adminRequests(t)
	if len(reqs) < 3 {
		t.Fatalf("found %d admin requests, want at least DKG, Refresh and Unfreeze", len(reqs))
	}
	for _, d := range reqs {
		op := opOf(t, d)
		base := proto.Clone(dynNew(d)).(proto.Message)
		h0, err := BodyHash(op, base)
		if err != nil {
			t.Fatal(err)
		}
		covered := 0
		for i := 0; i < d.Fields().Len(); i++ {
			fd := d.Fields().Get(i)
			if fd.Message() != nil && fd.Message().FullName() == authMessageName {
				continue
			}
			var hs [2][32]byte
			for k := range 2 {
				m := dynNew(d)
				fill(m.ProtoReflect(), fd, k == 1)
				if hs[k], err = BodyHash(op, m); err != nil {
					t.Fatalf("%s.%s cannot be hashed: %v", d.Name(), fd.Name(), err)
				}
				if hs[k] == h0 {
					t.Errorf("%s.%s is NOT covered by the signed hash", d.Name(), fd.Name())
				}
			}
			if fd.Kind() == protoreflect.StringKind || fd.Kind() == protoreflect.BytesKind || fd.Kind() == protoreflect.EnumKind {
				if hs[0] == hs[1] {
					t.Errorf("%s.%s: two different values hash the same", d.Name(), fd.Name())
				}
			}
			covered++
		}
		if covered == 0 {
			t.Errorf("%s has no field but the AdminAuth", d.Name())
		}
		// the AdminAuth itself is outside the hash (it carries the signatures)
		withAuth := dynNew(d)
		withAuth.ProtoReflect().Set(d.Fields().ByName("admin"), protoreflect.ValueOfMessage((&pb.AdminAuth{V2: &pb.AdminAuthV2{Nonce: []byte("n")}}).ProtoReflect()))
		if h, _ := BodyHash(op, withAuth); h != h0 {
			t.Errorf("%s: the admin field changed the hash", d.Name())
		}
		// the operation is bound too
		if h, _ := BodyHash("other", base); h == h0 {
			t.Errorf("%s: the hash does not depend on the operation", d.Name())
		}
	}
}

func dynNew(d protoreflect.MessageDescriptor) proto.Message {
	switch d.Name() {
	case "DKGRequest":
		return &pb.DKGRequest{}
	case "RefreshRequest":
		return &pb.RefreshRequest{}
	case "UnfreezeRequest":
		return &pb.UnfreezeRequest{}
	}
	return nil
}

// The followers rebuild the body from the peer's Open message: every field of an admin request must have a field of the same name and type there,
// or the follower could not check what it was asked to do.
func TestEveryAdminRequestFieldTravelsInOpen(t *testing.T) {
	open := (&pb.Open{}).ProtoReflect().Descriptor()
	for _, d := range adminRequests(t) {
		for i := 0; i < d.Fields().Len(); i++ {
			fd := d.Fields().Get(i)
			if fd.Message() != nil && fd.Message().FullName() == authMessageName {
				continue
			}
			o := open.Fields().ByName(fd.Name())
			if o == nil || o.Kind() != fd.Kind() || o.IsList() != fd.IsList() {
				t.Errorf("%s.%s has no matching field in Open: the followers cannot rebuild the body they must check", d.Name(), fd.Name())
			}
		}
	}
}

func TestDKGBodyCurveIsFixedByTheScheme(t *testing.T) {
	a, _ := BodyHash(OpDKG, DKGBody("k", pb.Scheme_SCHEME_ECDSA_2OF3, pb.Curve_CURVE_UNSPECIFIED))
	b, _ := BodyHash(OpDKG, DKGBody("k", pb.Scheme_SCHEME_ECDSA_2OF3, pb.Curve_CURVE_SECP256K1))
	if a != b {
		t.Error("a 2-of-3 DKG with the curve left out and with the scheme's curve must hash the same")
	}
	c, _ := BodyHash(OpDKG, DKGBody("k", pb.Scheme_SCHEME_UNSPECIFIED, pb.Curve_CURVE_SECP256K1))
	d, _ := BodyHash(OpDKG, DKGBody("k", pb.Scheme_SCHEME_UNSPECIFIED, pb.Curve_CURVE_ED25519))
	if c == d || c == a {
		t.Error("hd curves, and hd against 2-of-3, must hash differently")
	}
}

func newKeys(n int) []ed25519.PrivateKey {
	var l []ed25519.PrivateKey
	for range n {
		_, k, _ := ed25519.GenerateKey(rand.Reader)
		l = append(l, k)
	}
	return l
}

func pol(keys []ed25519.PrivateKey, m int) Policy {
	p := Policy{Threshold: m, MaxValidity: time.Hour, Skew: 5 * time.Minute}
	for _, k := range keys {
		p.Keys = append(p.Keys, k.Public().(ed25519.PublicKey))
	}
	return p
}

func TestRequestFileCoSigning(t *testing.T) {
	keys := newKeys(3)
	now := time.Now()
	r, err := NewRequest(OpDKG, "ks", "prod", pb.Scheme_SCHEME_ECDSA_2OF3, 0, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	p := pol(keys, 2)
	p.Domain = "prod"
	if err := r.Check(p, now); err == nil {
		t.Fatal("an unsigned file passed")
	}
	if err := r.Sign(keys[2]); err != nil {
		t.Fatal(err)
	}
	if err := r.Check(p, now); err == nil || !strings.Contains(err.Error(), "1 signature(s), 2 needed") {
		t.Fatalf("one of two: %v", err)
	}
	if err := r.Sign(keys[2]); err == nil {
		t.Fatal("the same key signed twice")
	}
	// the file travels: signing does not change what is signed
	before := r.Body
	if err := r.Sign(keys[0]); err != nil {
		t.Fatal(err)
	}
	if string(before) != string(r.Body) {
		t.Fatal("signing changed the body")
	}
	back, err := ParseRequest(r.JSON())
	if err != nil {
		t.Fatal(err)
	}
	if err := back.Check(p, now); err != nil {
		t.Fatalf("two of three: %v", err)
	}
	// edits are caught: body, keyset, time, domain
	for name, edit := range map[string]func(*Request){
		"scheme": func(x *Request) {
			x.Body = []byte(strings.Replace(string(x.Body), "SCHEME_ECDSA_2OF3", "SCHEME_ED25519_2OF3", 1))
		},
		"keyset":  func(x *Request) { x.Keyset = "other" },
		"expires": func(x *Request) { x.ExpiresUnix += 60 },
		"domain":  func(x *Request) { x.Domain = "staging" },
	} {
		c := back
		edit(&c)
		if parsed, err := ParseRequest(c.JSON()); err == nil {
			if _, err := parsed.Auth(); err == nil {
				t.Errorf("an edited %s was accepted", name)
			}
		}
	}
	// policy: unknown key, expired, too long, wrong domain
	other := newKeys(1)[0]
	x, _ := NewRequest(OpRefresh, "ks", "prod", 0, 0, now, time.Hour)
	x.Sign(keys[0])
	x.Sign(other)
	if err := x.Check(p, now); err == nil || !strings.Contains(err.Error(), "not a configured admin key") {
		t.Errorf("unknown key: %v", err)
	}
	if err := back.Check(p, now.Add(2*time.Hour)); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("expired: %v", err)
	}
	p2 := p
	p2.MaxValidity = time.Minute
	if err := back.Check(p2, now); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Errorf("too long: %v", err)
	}
	p3 := p
	p3.Domain = ""
	if err := back.Check(p3, now); err == nil || !strings.Contains(err.Error(), "domain") {
		t.Errorf("domain: %v", err)
	}
}

func TestFileVersion(t *testing.T) {
	v1, _ := NewFile(newKeys(1)[0], OpRefresh, "k", time.Now())
	v2, _ := NewRequest(OpRefresh, "k", "", 0, 0, time.Now(), time.Hour)
	if FileVersion(v1.JSON()) != 1 || FileVersion(v2.JSON()) != 2 || FileVersion([]byte("{}")) != 0 || FileVersion([]byte("x")) != 0 {
		t.Error("file version detection")
	}
}
