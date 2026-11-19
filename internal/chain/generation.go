package chain

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// DepositKey is one generation of a chain's deposit key tree as the registry (internal/partition) holds it: the number and the public identity the
// addresses derive from (Bitcoin: the account xpub; Solana: "<node public key hex>:<chain code hex>").
type DepositKey struct {
	Generation int
	Identity   string
}

// GenerationDeriver is implemented by the chain cells whose deposit addresses come from a key tree (Bitcoin, Solana). DeriveDepositAddressAt is
// DeriveDepositAddress under the given generation's key; for the generation the cell is configured with it is the same address, byte for byte.
type GenerationDeriver interface {
	DeriveDepositAddressAt(ctx context.Context, key DepositKey, customerID string, index uint64) (DepositAddress, error)
}

// KeyPathAt is the key reference of a deposit key of generation gen: the path of generation 1 as it always was, and "g<gen>/<path>" for a later
// generation, so a sign job names the key generation that must sign. The signing zone has to understand the prefix before it signs one (K6).
func KeyPathAt(gen int, path string) string {
	if gen <= 1 {
		return path
	}
	return "g" + strconv.Itoa(gen) + "/" + path
}

// SplitKeyPath is the inverse of KeyPathAt: the generation (1 when there is no prefix) and the path below it.
func SplitKeyPath(s string) (gen int, path string, err error) {
	rest, ok := strings.CutPrefix(s, "g")
	if !ok {
		return 1, s, nil
	}
	n, p, ok := strings.Cut(rest, "/")
	g, perr := strconv.Atoi(n)
	if !ok || perr != nil || g < 2 || strconv.Itoa(g) != n {
		return 0, "", fmt.Errorf("chain: key reference %q has a bad generation prefix", s)
	}
	return g, p, nil
}
