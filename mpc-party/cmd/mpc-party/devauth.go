//go:build devauth

// Compiled only with -tags devauth (the tests build the binary this way). A production build cannot contain it.
package main

import (
	"context"
	"errors"

	"github.com/ws4charlie/quorum-vault/mpc-party/internal/server"
)

type devAllowAll struct{}

func (devAllowAll) Authorize(context.Context, server.AuthRequest) error { return nil }

func init() {
	extraAuthorizers["dev-allow-all"] = func(c server.AuthorizerConfig) (server.Authorizer, error) {
		if c.AcceptRisk != server.DevAllowAllRiskPhrase {
			return nil, errors.New(`dev-allow-all needs authorizer.accept_risk = "` + server.DevAllowAllRiskPhrase + `"`)
		}
		return devAllowAll{}, nil
	}
}
