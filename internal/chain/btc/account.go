package btc

import (
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
)

// Account derives the keys of one account from its extended public key, with no secret: the core builds payloads with it and the
// signing zone checks them with its own copy.
type Account struct {
	Params *chaincfg.Params
	key    *hdkeychain.ExtendedKey
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
func (a *Account) Pub(path []uint32) ([]byte, error) {
	if err := CheckPath(path); err != nil {
		return nil, err
	}
	k := a.key
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
func (a *Account) Address(path []uint32) (string, error) {
	pub, err := a.Pub(path)
	if err != nil {
		return "", err
	}
	return P2WPKH(pub, a.Params)
}

func hash160(b []byte) []byte { return btcutil.Hash160(b) }
