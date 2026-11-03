// Package deps pins every third-party dependency the project needs.
//
// T0 resolves all modules up front so that the parallel tasks (T1 HSM,
// T2 policy/audit, T3 MPC) never edit go.mod/go.sum and never fight over
// transitive version clashes (tss-lib and go-ethereum both pull secp256k1 /
// btcec / crypto deps). Without these blank imports `go mod tidy` would
// drop modules that no package imports yet. Remove a line only via the lead,
// once a real package imports it.
package deps

import (
	_ "github.com/bnb-chain/tss-lib/v4/common"
	_ "github.com/bnb-chain/tss-lib/v4/ecdsa/keygen"
	_ "github.com/bnb-chain/tss-lib/v4/ecdsa/signing"
	_ "github.com/bnb-chain/tss-lib/v4/tss"
	_ "github.com/ethereum/go-ethereum/core/types"
	_ "github.com/ethereum/go-ethereum/crypto"
	_ "github.com/ethereum/go-ethereum/ethclient"
	_ "github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/miekg/pkcs11"
)
