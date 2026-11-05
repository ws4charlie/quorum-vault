// Package deps pins every third-party dependency the project needs.
//
// T0 resolves all modules up front so that the parallel tasks (T1 HSM,
// T2 policy/audit, T3 MPC) never edit go.mod/go.sum and never fight over
// transitive version clashes (go-ethereum and the other modules pull overlapping crypto deps). Without these blank imports `go mod tidy` would
// drop modules that no package imports yet. Remove a line only via the lead,
// once a real package imports it.
package deps

import (
	_ "github.com/ethereum/go-ethereum/core/types"
	_ "github.com/ethereum/go-ethereum/crypto"
	_ "github.com/ethereum/go-ethereum/ethclient"
	_ "github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/miekg/pkcs11"
)
