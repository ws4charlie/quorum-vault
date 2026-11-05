package server

import (
	"context"
	"errors"
	"fmt"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

// AuthRequest is everything an Authorizer may judge. IntentPackage is opaque to this service: P5b-3's implementation
// verifies approver signatures and policy and checks that Digest matches the decoded intent.
type AuthRequest struct {
	Role          string // "A" or "B": who is asking
	JobID         string
	KeyID         string
	KeysetID      string
	Algorithm     pb.Algorithm
	Digest        []byte
	IntentPackage []byte
	PublicKey     []byte // the derived key's public key
}

// Authorizer decides whether a signature may be produced. It is called on A before A starts, and on B before B joins
// the protocol; a non-nil error means refusal and nothing runs.
type Authorizer interface {
	Authorize(ctx context.Context, r AuthRequest) error
}

// ErrNoAuthorizer: the server was built without an Authorizer.
var ErrNoAuthorizer = errors.New("no authorizer configured: refusing to run (a party must never sign without policy checks)")

// DenyAll refuses everything. It is the only authorizer in a default build.
type DenyAll struct{}

func (DenyAll) Authorize(context.Context, AuthRequest) error {
	return fmt.Errorf("deny-all authorizer: no production authorizer is configured yet")
}
