package server

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

// AdminMessage is what an operator signs: the operation, the keyset and a fresh timestamp.
func AdminMessage(op, keysetID string, unixSeconds int64) []byte {
	return []byte(fmt.Sprintf("qv-mpc-admin-v1\n%s\n%s\n%d", op, keysetID, unixSeconds))
}

// SignAdmin builds an AdminAuth with an operator key (used by tooling and tests).
func SignAdmin(priv ed25519.PrivateKey, op, keysetID string, now time.Time) *pb.AdminAuth {
	ts := now.Unix()
	return &pb.AdminAuth{UnixSeconds: ts, PublicKey: priv.Public().(ed25519.PublicKey), Signature: ed25519.Sign(priv, AdminMessage(op, keysetID, ts))}
}

// adminVerifier checks AdminAuth against this party's own configured keys. A signature is accepted once.
type adminVerifier struct {
	keys   []ed25519.PublicKey
	maxAge time.Duration
	now    func() time.Time
	mu     sync.Mutex
	seen   map[string]time.Time
}

func newAdminVerifier(c *Config) (*adminVerifier, error) {
	v := &adminVerifier{maxAge: time.Duration(c.AdminMaxAgeSeconds) * time.Second, now: time.Now, seen: map[string]time.Time{}}
	for _, k := range c.AdminKeys {
		b, err := hex.DecodeString(k)
		if err != nil || len(b) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("admin key %q", k)
		}
		v.keys = append(v.keys, ed25519.PublicKey(b))
	}
	return v, nil
}

var errAdmin = errors.New("admin authorization")

// check verifies a for (op, keyset): configured key, valid signature, fresh timestamp, not used before.
func (v *adminVerifier) check(op, keysetID string, a *pb.AdminAuth) (key string, err error) {
	if a == nil || len(a.Signature) != ed25519.SignatureSize || len(a.PublicKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("%w: missing or malformed signature", errAdmin)
	}
	known := false
	for _, k := range v.keys {
		if string(k) == string(a.PublicKey) {
			known = true
		}
	}
	if !known {
		return "", fmt.Errorf("%w: not a configured admin key", errAdmin)
	}
	now := v.now()
	age := now.Sub(time.Unix(a.UnixSeconds, 0))
	if age > v.maxAge || age < -v.maxAge {
		return "", fmt.Errorf("%w: timestamp %d is outside the accepted window of %s", errAdmin, a.UnixSeconds, v.maxAge)
	}
	if !ed25519.Verify(ed25519.PublicKey(a.PublicKey), AdminMessage(op, keysetID, a.UnixSeconds), a.Signature) {
		return "", fmt.Errorf("%w: bad signature for (%s, %s)", errAdmin, op, keysetID)
	}
	sig := hex.EncodeToString(a.Signature)
	v.mu.Lock()
	defer v.mu.Unlock()
	for k, t := range v.seen { // forget old entries
		if now.Sub(t) > 2*v.maxAge {
			delete(v.seen, k)
		}
	}
	if _, dup := v.seen[sig]; dup {
		return "", fmt.Errorf("%w: signature already used", errAdmin)
	}
	v.seen[sig] = now
	return hex.EncodeToString(a.PublicKey), nil
}
