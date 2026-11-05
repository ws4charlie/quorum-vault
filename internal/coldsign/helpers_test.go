package coldsign

import (
	"crypto/ecdsa"
	"math/big"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

func signerFor(tx *types.Transaction) types.Signer { return types.LatestSignerForChainID(tx.ChainId()) }

func rsOf(tx *types.Transaction, key *ecdsa.PrivateKey) (*big.Int, *big.Int) {
	d := signerFor(tx).Hash(tx)
	sig, _ := crypto.Sign(d[:], key)
	return new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:64])
}

// mustSign signs with a throwaway key (the "attacker's"), returning (r, s) for assemble.
func mustSign(tx *types.Transaction) (*big.Int, *big.Int) {
	k, _ := crypto.GenerateKey()
	return rsOf(tx, k)
}

func types_sign(tx *types.Transaction, key *ecdsa.PrivateKey) (*types.Transaction, error) {
	return types.SignTx(tx, signerFor(tx), key)
}
