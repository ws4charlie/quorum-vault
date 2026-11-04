// Separate module on purpose: cb-mpc vendors its own libsecp256k1, which collides with go-ethereum's cgo copy at link
// time, and the repository root must keep building without a C++ toolchain. This module must never import go-ethereum
// (directly or through the root module).
module github.com/ws4charlie/quorum-vault/mpc-party

go 1.26.10

require (
	filippo.io/edwards25519 v1.1.0
	github.com/btcsuite/btcd v0.24.2
	github.com/btcsuite/btcd/btcec/v2 v2.5.1
	github.com/btcsuite/btcd/btcutil v1.2.0
)

require (
	github.com/btcsuite/btcd/chaincfg/chainhash v1.1.0 // indirect
	github.com/btcsuite/btcd/chainhash/v2 v2.0.0 // indirect
	github.com/decred/dcrd/crypto/blake256 v1.1.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1 // indirect
	github.com/kcalvinalvin/anet v0.0.0-20251112173137-d8ddc1f6dbee // indirect
	golang.org/x/crypto v0.25.0 // indirect
	golang.org/x/sys v0.22.0 // indirect
)
