package btc

import (
	"fmt"
	"sync"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
)

// Account derives the keys of one account from its extended public key, with no secret: the core builds payloads with it and the
// signing zone checks them with its own copy.
type Account struct {
	Params *chaincfg.Params
	key    *hdkeychain.ExtendedKey

	// Later generations of the deposit tree (K5): the keys of generation 2 and up, by number, and where to find one that is not loaded yet. The signing
	// zone never sets either, so it derives generation 1 only until K6 gives it the later ones.
	mu     sync.Mutex
	gens   map[uint32]*hdkeychain.ExtendedKey
	loader func(gen uint32) (*hdkeychain.ExtendedKey, error)
}

// SetGenerationLoader sets how a generation above 1 is found when a payload names it.
func (a *Account) SetGenerationLoader(f func(gen uint32) (xpub string, err error)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	params := a.Params
	a.loader = func(gen uint32) (*hdkeychain.ExtendedKey, error) {
		x, err := f(gen)
		if err != nil {
			return nil, err
		}
		k, err := hdkeychain.NewKeyFromString(x)
		if err != nil {
			return nil, fmt.Errorf("btc: account xpub of generation %d: %w", gen, err)
		}
		if k.IsPrivate() || !k.IsForNet(params) {
			return nil, fmt.Errorf("btc: account xpub of generation %d is private or of another network", gen)
		}
		return k, nil
	}
}

// keyOf is the account key of a generation (0 and 1: the configured one).
func (a *Account) keyOf(gen uint32) (*hdkeychain.ExtendedKey, error) {
	if gen <= 1 {
		return a.key, nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if k, ok := a.gens[gen]; ok {
		return k, nil
	}
	if a.loader == nil {
		return nil, fmt.Errorf("btc: no account key for deposit generation %d", gen)
	}
	k, err := a.loader(gen)
	if err != nil {
		return nil, err
	}
	if a.gens == nil {
		a.gens = map[uint32]*hdkeychain.ExtendedKey{}
	}
	a.gens[gen] = k
	return k, nil
}

// NewAccount parses an account xpub for a network. A key of another network, or a private key, is an error.
func NewAccount(network, xpub string) (*Account, error) {
	params, err := Params(network)
	if err != nil {
		return nil, err
	}
	k, err := hdkeychain.NewKeyFromString(xpub)
	if err != nil {
		return nil, fmt.Errorf("btc: account xpub: %w", err)
	}
	if k.IsPrivate() {
		return nil, fmt.Errorf("btc: account xpub is a private key")
	}
	if !k.IsForNet(params) {
		return nil, fmt.Errorf("btc: account xpub is not a %s key (its version bytes belong to another network)", network)
	}
	return &Account{Params: params, key: k}, nil
}

// Pub is the compressed public key at path ([branch, index], see CheckPath).
func (a *Account) Pub(path []uint32) ([]byte, error) { return a.PubAt(1, path) }

// PubAt is Pub under the account key of deposit generation gen (0 and 1 are the configured key).
func (a *Account) PubAt(gen uint32, path []uint32) ([]byte, error) {
	if err := CheckPath(path); err != nil {
		return nil, err
	}
	k, err := a.keyOf(gen)
	if err != nil {
		return nil, err
	}
	for _, n := range path {
		var err error
		if k, err = k.Derive(n); err != nil {
			return nil, fmt.Errorf("btc: derive %v: %w", path, err)
		}
	}
	pk, err := k.ECPubKey()
	if err != nil {
		return nil, err
	}
	return pk.SerializeCompressed(), nil
}

// Address is the P2WPKH address at path.
func (a *Account) Address(path []uint32) (string, error) { return a.AddressAt(1, path) }

// AddressAt is Address under generation gen.
func (a *Account) AddressAt(gen uint32, path []uint32) (string, error) {
	pub, err := a.PubAt(gen, path)
	if err != nil {
		return "", err
	}
	return P2WPKH(pub, a.Params)
}

func hash160(b []byte) []byte { return btcutil.Hash160(b) }
