package mpcsigner

import (
	"crypto/ecdsa"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/ws4charlie/quorum-vault/internal/signer"
)

func secpN() *big.Int { return crypto.S256().Params().N }

func signerParse(pub []byte) (*ecdsa.PublicKey, error) { return signer.ParseUncompressed(pub) }
