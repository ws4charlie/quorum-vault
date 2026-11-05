// Package admin builds the operator authorization that DKG, Refresh and Unfreeze need on BOTH mpc-party processes.
package admin

import (
	"crypto/ed25519"
	"fmt"
	"time"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

// Message is what an operator signs: the operation ("dkg", "refresh", "unfreeze"), the keyset and a fresh timestamp.
func Message(op, keysetID string, unixSeconds int64) []byte {
	return []byte(fmt.Sprintf("qv-mpc-admin-v1\n%s\n%s\n%d", op, keysetID, unixSeconds))
}

// Sign builds an AdminAuth with an operator key.
func Sign(priv ed25519.PrivateKey, op, keysetID string, now time.Time) *pb.AdminAuth {
	ts := now.Unix()
	return &pb.AdminAuth{UnixSeconds: ts, PublicKey: priv.Public().(ed25519.PublicKey), Signature: ed25519.Sign(priv, Message(op, keysetID, ts))}
}
