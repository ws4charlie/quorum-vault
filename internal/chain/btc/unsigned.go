package btc

import (
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// Unsigned is a payload turned into a transaction, with the BIP143 sighash of every input.
type Unsigned struct {
	Tx      *wire.MsgTx
	TxID    string
	Digests [][]byte // Digests[i] is the sighash (SIGHASH_ALL) that input i is signed over
	Pubs    [][]byte // Pubs[i] is the compressed key of input i, derived from the account xpub and the input's path
	Scripts [][]byte // Scripts[i] is the P2WPKH script input i spends
}

// BuildUnsigned builds the transaction of p and the BIP143 digest of every input. Every input must be P2WPKH under a key derived
// from acct at the input's path, and p must have a version, locktime and sequences as the signing zone accepts them; nothing
// is taken from anywhere else. The business core uses it to build jobs, the signing zone to check them, so both compute the same
// digests.
//
// SIGHASH_ALL is the only type: the digest is computed with it fixed, and the signature the signer returns is over the digest with no
// type byte of its own; the assembler appends 0x01. A signature over any other sighash would be over a different digest.
func BuildUnsigned(p Payload, acct *Account) (*Unsigned, error) {
	if p.Version != PayloadVersion {
		return nil, fmt.Errorf("btc: transaction version %d, want %d", p.Version, PayloadVersion)
	}
	if p.LockTime != 0 {
		return nil, fmt.Errorf("btc: locktime %d, want 0", p.LockTime)
	}
	if len(p.Inputs) == 0 || len(p.Outputs) == 0 {
		return nil, errors.New("btc: a transaction needs inputs and outputs")
	}
	tx := wire.NewMsgTx(PayloadVersion)
	tx.LockTime = p.LockTime
	u := &Unsigned{Tx: tx}
	fetch := map[wire.OutPoint]*wire.TxOut{}
	seen := map[wire.OutPoint]bool{}
	for n, in := range p.Inputs {
		h, err := chainhash.NewHashFromStr(in.TxID)
		if err != nil || len(in.TxID) != 64 || in.TxID != h.String() {
			return nil, fmt.Errorf("btc: input %d: txid %q is not 64 lower-case hex characters", n, in.TxID)
		}
		op := wire.OutPoint{Hash: *h, Index: in.Vout}
		if seen[op] {
			return nil, fmt.Errorf("btc: input %d spends %s:%d twice", n, in.TxID, in.Vout)
		}
		seen[op] = true
		if in.Sequence != SequenceRBF {
			return nil, fmt.Errorf("btc: input %d: sequence %#x does not signal RBF (want %#x)", n, in.Sequence, SequenceRBF)
		}
		if in.Value == 0 || in.Value > maxMoney {
			return nil, fmt.Errorf("btc: input %d: value %d out of range", n, in.Value)
		}
		pub, err := acct.Pub(in.Path)
		if err != nil {
			return nil, fmt.Errorf("btc: input %d: %w", n, err)
		}
		addr, err := btcutil.NewAddressWitnessPubKeyHash(hash160(pub), acct.Params)
		if err != nil {
			return nil, err
		}
		script, err := txscript.PayToAddrScript(addr)
		if err != nil {
			return nil, err
		}
		txin := wire.NewTxIn(&op, nil, nil)
		txin.Sequence = in.Sequence
		tx.AddTxIn(txin)
		fetch[op] = wire.NewTxOut(int64(in.Value), script)
		u.Pubs = append(u.Pubs, pub)
		u.Scripts = append(u.Scripts, script)
	}
	for n, o := range p.Outputs {
		script, err := OutputScript(o.Address, acct.Params)
		if err != nil {
			return nil, fmt.Errorf("btc: output %d: %w", n, err)
		}
		if o.Value == 0 || o.Value > maxMoney {
			return nil, fmt.Errorf("btc: output %d: value %d out of range", n, o.Value)
		}
		tx.AddTxOut(wire.NewTxOut(int64(o.Value), script))
	}
	hashes := txscript.NewTxSigHashes(tx, txscript.NewMultiPrevOutFetcher(fetch))
	for i, in := range p.Inputs {
		pkh := hash160(u.Pubs[i])
		pkhAddr, err := btcutil.NewAddressPubKeyHash(pkh, acct.Params)
		if err != nil {
			return nil, err
		}
		scriptCode, err := txscript.PayToAddrScript(pkhAddr) // BIP143: the scriptCode of P2WPKH is the P2PKH script of the same hash
		if err != nil {
			return nil, err
		}
		d, err := txscript.CalcWitnessSigHash(scriptCode, hashes, txscript.SigHashAll, tx, i, int64(in.Value))
		if err != nil {
			return nil, fmt.Errorf("btc: sighash of input %d: %w", i, err)
		}
		u.Digests = append(u.Digests, d)
	}
	u.TxID = tx.TxHash().String()
	return u, nil
}

// maxMoney is the total supply in satoshis; no value is larger.
const maxMoney = 21_000_000 * 100_000_000

// OutputScript is the script of an address on a network. It refuses an address of another network and any form that is not one of
// P2WPKH, P2WSH, P2TR, P2PKH and P2SH.
func OutputScript(address string, params *chaincfg.Params) ([]byte, error) {
	k, err := DecodeAddress(address, params)
	if err != nil {
		return nil, err
	}
	return txscript.PayToAddrScript(k.Addr)
}

// Script kinds an output may have.
const (
	KindP2WPKH = "p2wpkh"
	KindP2WSH  = "p2wsh"
	KindP2TR   = "p2tr"
	KindP2PKH  = "p2pkh"
	KindP2SH   = "p2sh"
)

// Decoded is an address of an allowed form.
type Decoded struct {
	Addr      btcutil.Address
	Canonical string // the encoding the network gives it (lower-case bech32, base58 as is)
	Kind      string
}

// DecodeAddress decodes an address for a network and accepts only the allowed forms. The canonical form is the one the library
// encodes back, so letter case of a bech32 address never matters.
func DecodeAddress(address string, params *chaincfg.Params) (Decoded, error) {
	a, err := btcutil.DecodeAddress(address, params)
	if err != nil {
		return Decoded{}, fmt.Errorf("address %q is not valid on this network: %w", address, err)
	}
	if !a.IsForNet(params) {
		return Decoded{}, fmt.Errorf("address %q is not a %s address", address, params.Name)
	}
	d := Decoded{Addr: a, Canonical: a.EncodeAddress()}
	switch a.(type) {
	case *btcutil.AddressWitnessPubKeyHash:
		d.Kind = KindP2WPKH
	case *btcutil.AddressWitnessScriptHash:
		d.Kind = KindP2WSH
	case *btcutil.AddressTaproot:
		d.Kind = KindP2TR
	case *btcutil.AddressPubKeyHash:
		d.Kind = KindP2PKH
	case *btcutil.AddressScriptHash:
		d.Kind = KindP2SH
	default:
		return Decoded{}, fmt.Errorf("address %q has a form that is not allowed", address)
	}
	return d, nil
}

// DustLimit is the smallest output value the network relays at the default dust relay fee (3 sat/vB): three times the size of the
// output plus the input that would spend it.
func DustLimit(kind string) uint64 {
	switch kind {
	case KindP2WPKH:
		return 294
	case KindP2WSH, KindP2TR:
		return 330
	case KindP2PKH:
		return 546
	case KindP2SH:
		return 540
	}
	return 546
}

// EstimateVSize is the virtual size of tx once every input carries a P2WPKH witness (at most 108 bytes of it, plus the marker and
// flag), so a fee rate computed from it is never lower than the real one.
func EstimateVSize(tx *wire.MsgTx) int64 {
	weight := int64(tx.SerializeSizeStripped())*4 + 2 + 108*int64(len(tx.TxIn))
	return (weight + 3) / 4
}

// SighashOf computes the BIP143 digest of input idx of tx for a P2WPKH output with public key hash pkh worth value, given the previous output of
// every input (BIP143 hashes only their outpoints and values). It lets the published test vectors check the function BuildUnsigned
// is built on.
func SighashOf(tx *wire.MsgTx, idx int, pkh []byte, value int64, prev map[wire.OutPoint]*wire.TxOut) ([]byte, error) {
	hashes := txscript.NewTxSigHashes(tx, txscript.NewMultiPrevOutFetcher(prev))
	script := append(append([]byte{0x76, 0xa9, 0x14}, pkh...), 0x88, 0xac)
	return txscript.CalcWitnessSigHash(script, hashes, txscript.SigHashAll, tx, idx, value)
}
