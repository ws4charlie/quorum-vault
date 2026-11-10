package sol

import (
	"context"
	"fmt"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

// AccountNode asks party A of mpc-party for the account node m/44'/501'/0' of an Ed25519 HD keyset. Only public values come back (a
// public key and a chain code); the two parties run the hardened step together, and no share leaves either of them.
func AccountNode(ctx context.Context, cl pb.MpcPartyClient, keysetID string) (Node, error) {
	r, err := cl.Node(ctx, &pb.NodeRequest{KeysetId: keysetID, HardenedPath: AccountPath()})
	if err != nil {
		return Node{}, fmt.Errorf("sol: party A Node %v: %w", AccountPath(), err)
	}
	var n Node
	if len(r.PublicKey) != 32 || len(r.ChainCode) != 32 {
		return Node{}, fmt.Errorf("sol: party A returned a node of %d + %d bytes (is %q an Ed25519 keyset?)", len(r.PublicKey), len(r.ChainCode), keysetID)
	}
	copy(n.PublicKey[:], r.PublicKey)
	copy(n.ChainCode[:], r.ChainCode)
	return n, nil
}
