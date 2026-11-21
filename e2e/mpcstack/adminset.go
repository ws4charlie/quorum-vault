package mpcstack

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ws4charlie/quorum-vault/mpc-party/api/admin"
	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

// AdminThreshold is the admin_threshold every stack's parties are configured with: two of the three admin keys must sign.
const AdminThreshold = 2

// AdminSet is the three admin keys of one stack, generated at setup (nothing is stored in the repo). The parties are configured with the public
// keys and AdminThreshold.
type AdminSet struct{ keys []ed25519.PrivateKey }

func newAdminSet() AdminSet {
	var s AdminSet
	for range 3 {
		_, k, _ := ed25519.GenerateKey(rand.Reader)
		s.keys = append(s.keys, k)
	}
	return s
}

// PublicHex are the parties' admin_keys.
func (s AdminSet) PublicHex() []string {
	var l []string
	for _, k := range s.keys {
		l = append(l, hex.EncodeToString(k.Public().(ed25519.PublicKey)))
	}
	return l
}

// SeedHex is the i-th admin's key (the seed, hex), for a key file of `qv-party-admin sign`.
func (s AdminSet) SeedHex(i int) string { return hex.EncodeToString(s.keys[i].Seed()) }

// Key is the i-th admin's private key.
func (s AdminSet) Key(i int) ed25519.PrivateKey { return s.keys[i] }

// Auth is a v2 authorization of (op, body) signed by the first AdminThreshold admins: fresh nonce, valid for ten minutes. body is the request as it
// is sent, without its Admin field.
func (s AdminSet) Auth(op string, body proto.Message) *pb.AdminAuth {
	now := time.Now()
	a, err := admin.Authorize(op, body, "", now, now.Add(10*time.Minute), s.keys[:AdminThreshold]...)
	if err != nil {
		panic(err)
	}
	return a
}

// DKGRequestFile writes a v2 request for a DKG of keyset, signed by the first AdminThreshold admins, into dir: the file `qv-rekey dkg -admin-auth` takes.
func (s AdminSet) DKGRequestFile(t testing.TB, dir, keyset string, scheme pb.Scheme, curve pb.Curve) string {
	t.Helper()
	r, err := admin.NewRequest(admin.OpDKG, keyset, "", scheme, curve, time.Now(), 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range s.keys[:AdminThreshold] {
		if err := r.Sign(k); err != nil {
			t.Fatal(err)
		}
	}
	f := filepath.Join(dir, "party-auth-"+keyset+".json")
	if err := os.WriteFile(f, r.JSON(), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

// DKG, Refresh and Unfreeze sign the request they are given (its body as it stands) and return it.
func (s AdminSet) DKG(r *pb.DKGRequest) *pb.DKGRequest {
	r.Admin = s.Auth(admin.OpDKG, r)
	return r
}
func (s AdminSet) Refresh(r *pb.RefreshRequest) *pb.RefreshRequest {
	r.Admin = s.Auth(admin.OpRefresh, r)
	return r
}
func (s AdminSet) Unfreeze(r *pb.UnfreezeRequest) *pb.UnfreezeRequest {
	r.Admin = s.Auth(admin.OpUnfreeze, r)
	return r
}
