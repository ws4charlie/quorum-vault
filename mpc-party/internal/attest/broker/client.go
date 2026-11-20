package broker

import "github.com/ws4charlie/quorum-vault/mpc-party/internal/attest/brokerclient"

// The client lives in package brokerclient so that a party links it without the broker server (and its HSM code). These names keep the broker's
// own tests and tools unchanged.
type (
	Client       = brokerclient.Client
	RefusedError = brokerclient.RefusedError
)

var NewClient = brokerclient.NewClient
