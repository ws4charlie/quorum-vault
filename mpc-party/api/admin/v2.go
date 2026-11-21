package admin

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

// Version2 is the version of the message layout below.
const Version2 = 2

const (
	messageMagic = "qv-mpc-admin-v2\n"
	bodyMagic    = "qv-mpc-admin-v2-body\n"
	// NonceSize is the size of the random nonce every authorization carries.
	NonceSize = 16
	// MaxSignatures bounds the signatures one authorization may carry (a party refuses more before it checks any).
	MaxSignatures = 32
)

const authMessageName protoreflect.FullName = "qv.mpcparty.v1.AdminAuth"

// Canonical is the body a signature covers, made from a request as a party received it: a copy without its AdminAuth, and a 2-of-3 DKG's
// curve set to the scheme's (the caller may leave it unspecified and the servers accept both, so the signed hash is the same either way).
// Every other field is kept as it is: the body is the request, not a list of the fields somebody remembered.
func Canonical(req proto.Message) proto.Message {
	c := proto.Clone(req)
	m := c.ProtoReflect()
	fds := m.Descriptor().Fields()
	for i := 0; i < fds.Len(); i++ {
		if fd := fds.Get(i); isAuthField(fd) {
			m.Clear(fd)
		}
	}
	if d, ok := c.(*pb.DKGRequest); ok {
		switch d.Scheme {
		case pb.Scheme_SCHEME_ECDSA_2OF3:
			d.Curve = pb.Curve_CURVE_SECP256K1
		case pb.Scheme_SCHEME_ED25519_2OF3:
			d.Curve = pb.Curve_CURVE_ED25519
		}
	}
	return c
}

func isAuthField(fd protoreflect.FieldDescriptor) bool {
	return fd.Message() != nil && fd.Message().FullName() == authMessageName
}

func newBody(op string) (proto.Message, error) {
	switch op {
	case OpDKG:
		return &pb.DKGRequest{}, nil
	case OpRefresh:
		return &pb.RefreshRequest{}, nil
	case OpUnfreeze:
		return &pb.UnfreezeRequest{}, nil
	case OpAdminSet:
		return &pb.AdminSetRequest{}, nil
	case OpRecoveryKey:
		return &pb.RecoveryKeyRequest{}, nil
	}
	return nil, fmt.Errorf("unknown operation %q: want dkg, refresh, unfreeze, admin-set or recovery-key", op)
}

// copyByName copies every field of the request message req (except the AdminAuth) to or from the field of other with the same name: to other
// when toOther, else from it. A request field other does not have, or has with another kind, is an error: nothing is dropped silently. Fields of
// other that are not request fields are never read or written.
func copyByName(req, other protoreflect.Message, toOther bool) error {
	rf, of := req.Descriptor().Fields(), other.Descriptor().Fields()
	for i := 0; i < rf.Len(); i++ {
		fd := rf.Get(i)
		if isAuthField(fd) {
			continue
		}
		o := of.ByName(fd.Name())
		if o == nil || o.Kind() != fd.Kind() || o.IsList() != fd.IsList() || o.IsMap() != fd.IsMap() {
			return fmt.Errorf("%s.%s has no matching field in %s", req.Descriptor().Name(), fd.Name(), other.Descriptor().Name())
		}
		src, sfd, dst, dfd := req, fd, other, o
		if !toOther {
			src, sfd, dst, dfd = other, o, req, fd
		}
		if !src.Has(sfd) {
			continue
		}
		v := src.Get(sfd)
		switch {
		case sfd.IsList():
			l := dst.Mutable(dfd).List()
			for j := 0; j < v.List().Len(); j++ {
				l.Append(v.List().Get(j))
			}
		case sfd.Message() != nil:
			dst.Set(dfd, protoreflect.ValueOfMessage(proto.Clone(v.Message().Interface()).ProtoReflect()))
		default:
			dst.Set(dfd, v)
		}
	}
	return nil
}

// OpenOf is the peer message a caller forwards for an admin request: Op set, every request field copied by name (the AdminAuth too). It panics
// when the request has a field Open does not (TestEveryAdminRequestFieldTravelsInOpen keeps that from shipping).
func OpenOf(req proto.Message) *pb.Open {
	op := pb.Op_OP_UNSPECIFIED
	switch req.(type) {
	case *pb.DKGRequest:
		op = pb.Op_OP_DKG
	case *pb.RefreshRequest:
		op = pb.Op_OP_REFRESH
	case *pb.UnfreezeRequest:
		op = pb.Op_OP_UNFREEZE
	case *pb.AdminSetRequest:
		op = pb.Op_OP_ADMIN_SET
	case *pb.RecoveryKeyRequest:
		op = pb.Op_OP_RECOVERY_KEY
	default:
		panic(fmt.Sprintf("OpenOf: %T is not an admin request", req))
	}
	o := &pb.Open{Op: op}
	if err := copyByName(req.ProtoReflect(), o.ProtoReflect(), true); err != nil {
		panic("OpenOf: " + err.Error())
	}
	if a := req.ProtoReflect().Descriptor().Fields().ByName("admin"); a != nil && req.ProtoReflect().Has(a) {
		o.Admin = proto.Clone(req.ProtoReflect().Get(a).Message().Interface()).(*pb.AdminAuth)
	}
	return o
}

// BodyFromOpen is what a follower rebuilds from the Open it received: the request of operation op, every field copied by name, in canonical form.
// It is what the follower checks the signature against, so a field the caller sent that is not part of the request cannot be used, and one that
// is cannot be left out.
func BodyFromOpen(op string, open *pb.Open) (proto.Message, error) {
	b, err := newBody(op)
	if err != nil {
		return nil, err
	}
	if err := copyByName(b.ProtoReflect(), open.ProtoReflect(), false); err != nil {
		return nil, err
	}
	return Canonical(b), nil
}

// DKGBody is the request body of a DKG in canonical form (see Canonical).
func DKGBody(keyset string, scheme pb.Scheme, curve pb.Curve) *pb.DKGRequest {
	return Canonical(&pb.DKGRequest{KeysetId: keyset, Scheme: scheme, Curve: curve}).(*pb.DKGRequest)
}

// RefreshBody and UnfreezeBody are the request bodies of the other two admin operations.
func RefreshBody(keyset string) *pb.RefreshRequest   { return &pb.RefreshRequest{KeysetId: keyset} }
func UnfreezeBody(keyset string) *pb.UnfreezeRequest { return &pb.UnfreezeRequest{KeysetId: keyset} }

// BodyOf returns the canonical request body of an operation. For dkg it needs the scheme and the curve; the others ignore them.
func BodyOf(op, keyset string, scheme pb.Scheme, curve pb.Curve) (proto.Message, error) {
	switch op {
	case OpDKG:
		return DKGBody(keyset, scheme, curve), nil
	case OpRefresh:
		return RefreshBody(keyset), nil
	case OpUnfreeze:
		return UnfreezeBody(keyset), nil
	case OpAdminSet, OpRecoveryKey:
		return nil, fmt.Errorf("%s has its own body constructor (AdminSetBody, RecoveryKeyBody)", op)
	}
	return nil, fmt.Errorf("unknown operation %q: want dkg, refresh, unfreeze, admin-set or recovery-key", op)
}

// BodyHash is the SHA-256 of the complete request body in a canonical encoding, for the operation op. It walks the message by reflection in
// field-number order and encodes every field except the AdminAuth one (field number, kind, presence, value), so a field added to a request is
// covered without anyone remembering to add it here. It refuses what it cannot encode in one way only (maps, floats, unknown fields) instead of
// skipping it.
func BodyHash(op string, body proto.Message) ([32]byte, error) {
	m := body.ProtoReflect()
	h := sha256.New()
	h.Write([]byte(bodyMagic))
	putString(h, op)
	putString(h, string(m.Descriptor().FullName()))
	if err := encodeMessage(h, m); err != nil {
		return [32]byte{}, err
	}
	var out [32]byte
	h.Sum(out[:0])
	return out, nil
}

type writer interface{ Write([]byte) (int, error) }

func putUvarint(w writer, v uint64) {
	var b [binary.MaxVarintLen64]byte
	w.Write(b[:binary.PutUvarint(b[:], v)])
}
func putBytes(w writer, b []byte)  { putUvarint(w, uint64(len(b))); w.Write(b) }
func putString(w writer, s string) { putBytes(w, []byte(s)) }

func encodeMessage(w writer, m protoreflect.Message) error {
	if len(m.GetUnknown()) > 0 {
		return errors.New("the request has fields this version does not know")
	}
	fds := m.Descriptor().Fields()
	list := make([]protoreflect.FieldDescriptor, 0, fds.Len())
	for i := 0; i < fds.Len(); i++ {
		list = append(list, fds.Get(i))
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Number() < list[j].Number() })
	for _, fd := range list {
		if fd.Message() != nil && fd.Message().FullName() == authMessageName {
			continue // the authorization itself is not part of what it signs
		}
		putUvarint(w, uint64(fd.Number()))
		switch {
		case fd.IsMap():
			return fmt.Errorf("field %s is a map: not supported in a signed body", fd.FullName())
		case fd.IsList():
			l := m.Get(fd).List()
			putUvarint(w, uint64(l.Len()))
			for i := 0; i < l.Len(); i++ {
				if err := encodeValue(w, fd, l.Get(i)); err != nil {
					return err
				}
			}
		default:
			if fd.HasPresence() {
				if !m.Has(fd) {
					w.Write([]byte{0})
					continue
				}
				w.Write([]byte{1})
			}
			if err := encodeValue(w, fd, m.Get(fd)); err != nil {
				return err
			}
		}
	}
	return nil
}

func encodeValue(w writer, fd protoreflect.FieldDescriptor, v protoreflect.Value) error {
	w.Write([]byte{byte(fd.Kind())})
	switch fd.Kind() {
	case protoreflect.BoolKind:
		if v.Bool() {
			w.Write([]byte{1})
		} else {
			w.Write([]byte{0})
		}
	case protoreflect.EnumKind:
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(v.Enum()))
		w.Write(b[:])
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind, protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(v.Int()))
		w.Write(b[:])
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind, protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], v.Uint())
		w.Write(b[:])
	case protoreflect.StringKind:
		putString(w, v.String())
	case protoreflect.BytesKind:
		putBytes(w, v.Bytes())
	case protoreflect.MessageKind, protoreflect.GroupKind:
		return encodeMessage(w, v.Message())
	default:
		return fmt.Errorf("field %s has a kind (%s) that is not supported in a signed body", fd.FullName(), fd.Kind())
	}
	return nil
}

// Message2 is what every admin signs: version, operation, domain, keyset, the body hash, issue and expiry time and the nonce, each field
// length-prefixed, after a magic line that no v1 message (which starts "qv-mpc-admin-v1") can equal.
func Message2(op, keyset, domain string, body [32]byte, issued, expires int64, nonce []byte) []byte {
	b := []byte(messageMagic)
	b = binary.AppendUvarint(b, Version2)
	for _, s := range []string{op, domain, keyset} {
		b = binary.AppendUvarint(b, uint64(len(s)))
		b = append(b, s...)
	}
	b = append(b, body[:]...)
	b = binary.BigEndian.AppendUint64(b, uint64(issued))
	b = binary.BigEndian.AppendUint64(b, uint64(expires))
	b = binary.AppendUvarint(b, uint64(len(nonce)))
	return append(b, nonce...)
}

// MessageID is what a party remembers to refuse a second use: the hash of the signed message. It does not depend on which admins signed or in
// which order, so one authorization is spent once however its signatures are arranged.
func MessageID(msg []byte) [32]byte { return sha256.Sum256(msg) }

// SignatureCheck is the result of Verify2.
type SignatureCheck struct {
	Message []byte   // the message the signatures cover
	Signers [][]byte // the distinct public keys, in the order they appear
}

// Verify2 rebuilds the signed message from the request the caller holds (operation, keyset, body hash) and the fields of a, and checks every
// signature on it. It refuses an authorization with a malformed nonce, no signature, too many, the same key twice, a malformed key or a
// signature that does not verify: one bad entry spoils the whole authorization. It does not look at the clock or at which keys are allowed.
func Verify2(op, keyset string, body [32]byte, a *pb.AdminAuthV2) (SignatureCheck, error) {
	var c SignatureCheck
	switch {
	case a == nil:
		return c, errors.New("no v2 authorization")
	case len(a.Nonce) != NonceSize:
		return c, fmt.Errorf("the nonce must be %d bytes", NonceSize)
	case len(a.Signatures) == 0:
		return c, errors.New("no signatures")
	case len(a.Signatures) > MaxSignatures:
		return c, fmt.Errorf("more than %d signatures", MaxSignatures)
	}
	c.Message = Message2(op, keyset, a.Domain, body, a.IssuedUnix, a.ExpiresUnix, a.Nonce)
	seen := map[string]bool{}
	for i, s := range a.Signatures {
		if len(s.GetPublicKey()) != ed25519.PublicKeySize || len(s.GetSignature()) != ed25519.SignatureSize {
			return c, fmt.Errorf("signature %d: public key and signature must be 32 and 64 bytes", i+1)
		}
		if seen[string(s.PublicKey)] {
			return c, fmt.Errorf("signature %d: the same admin key signed twice (a key counts once)", i+1)
		}
		seen[string(s.PublicKey)] = true
		if !ed25519.Verify(ed25519.PublicKey(s.PublicKey), c.Message, s.Signature) {
			return c, fmt.Errorf("signature %d (key %x...): does not verify for (%s, %s): the request, its keyset or its time differs from what was signed", i+1, s.PublicKey[:4], op, keyset)
		}
		c.Signers = append(c.Signers, s.PublicKey)
	}
	return c, nil
}

// KeysetOf is the keyset a request body names.
func KeysetOf(body proto.Message) string {
	switch r := body.(type) {
	case *pb.DKGRequest:
		return r.KeysetId
	case *pb.RefreshRequest:
		return r.KeysetId
	case *pb.UnfreezeRequest:
		return r.KeysetId
	}
	return "" // admin-set and recovery-key name no keyset
}

// Authorize signs a v2 authorization for (op, body) with every key in keys, valid from issued until expires, with a random nonce: what the
// request/sign flow of qv-party-admin produces, in one step, for code that holds the keys (tests, drills). body is the request as the
// caller sends it (without its AdminAuth); a 2-of-3 DKG's curve is normalized as the parties do.
func Authorize(op string, body proto.Message, domain string, issued, expires time.Time, keys ...ed25519.PrivateKey) (*pb.AdminAuth, error) {
	body = Canonical(body)
	hash, err := BodyHash(op, body)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return AuthorizeWithNonce(op, body, domain, issued, expires, nonce, hash, keys...), nil
}

// AuthorizeWithNonce is Authorize with the nonce (and the body hash) chosen by the caller, for tests of replay.
func AuthorizeWithNonce(op string, body proto.Message, domain string, issued, expires time.Time, nonce []byte, hash [32]byte, keys ...ed25519.PrivateKey) *pb.AdminAuth {
	msg := Message2(op, KeysetOf(body), domain, hash, issued.Unix(), expires.Unix(), nonce)
	a := &pb.AdminAuthV2{Domain: domain, IssuedUnix: issued.Unix(), ExpiresUnix: expires.Unix(), Nonce: nonce}
	for _, k := range keys {
		a.Signatures = append(a.Signatures, &pb.AdminSignature{PublicKey: k.Public().(ed25519.PublicKey), Signature: ed25519.Sign(k, msg)})
	}
	return &pb.AdminAuth{V2: a}
}
