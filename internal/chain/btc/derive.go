package btc

import (
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
)

// addressAt derives the P2WPKH address at account/0/index from the public key alone.
func (v *validatedConfig) addressAt(index uint32) (string, error) {
	child, err := v.branch.Derive(index)
	if err != nil {
		return "", fmt.Errorf("btc: derive index %d: %w", index, err)
	}
	pub, err := child.ECPubKey()
	if err != nil {
		return "", err
	}
	return P2WPKH(pub.SerializeCompressed(), v.params)
}

// P2WPKH is the native SegWit address of a compressed public key.
func P2WPKH(pub33 []byte, params *chaincfg.Params) (string, error) {
	a, err := btcutil.NewAddressWitnessPubKeyHash(btcutil.Hash160(pub33), params)
	if err != nil {
		return "", err
	}
	return a.EncodeAddress(), nil
}

// XpubFromNode builds the account-level xpub string from what mpc-party's Node returns for the hardened path m/84'/coin'/0'
// (33-byte public key and 32-byte chain code). parentPub33 is the public key of the parent node m/84'/coin' (another Node call);
// it only supplies the fingerprint, which does not affect derivation. An empty parentPub33 gives a zero fingerprint.
func XpubFromNode(network string, pub33, chainCode, parentPub33 []byte) (string, error) {
	params, err := Params(network)
	if err != nil {
		return "", err
	}
	var fp []byte = []byte{0, 0, 0, 0}
	if len(parentPub33) > 0 {
		fp = btcutil.Hash160(parentPub33)[:4]
	}
	k := hdkeychain.NewExtendedKey(params.HDPublicKeyID[:], pub33, chainCode, fp, 3, hdkeychain.HardenedKeyStart+0, false)
	return k.String(), nil
}

// DeriveAddress is the P2WPKH address at account/0/index of an account xpub on a network, with the same checks as the adapter's
// config (a key of another network is an error).
func DeriveAddress(network, accountXpub string, index uint32) (string, error) {
	v, err := Config{Chain: "btc", Network: network, AccountXpub: accountXpub}.validated()
	if err != nil {
		return "", err
	}
	return v.addressAt(index)
}
