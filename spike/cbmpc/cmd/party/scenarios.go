package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"

	"qvspike/cbmpc/cbmpc"
)

func runScenario(cmd string, p *Party, m *Mux, args []string) error {
	switch cmd {
	case "pubkey": // pubkey ecdsa|eddsa|schnorr KEY
		kb, ok := p.Get(args[1])
		if !ok {
			return errors.New("no such key")
		}
		pub, err := cbmpc.Pub2P(algOf(args[0]), kb)
		if err != nil {
			return err
		}
		fmt.Println(hex.EncodeToString(pub))
		return nil
	case "others":
		return othersDemo(p, m)
	case "xpub":
		return xpubDemo(p, m)
	case "bench":
		return benchCmd(p, m, args)
	case "loopsign": // loopsign KEY N : sign repeatedly, print each result (crash tests)
		return loopSign(p, m, args)
	case "crash": // crash KIND  (asks the PEER process to crash inside C++/Go)
		return crashPeer(p, m, args)
	case "fuzz":
		return fuzzPeer(p, m, args)
	}
	return fmt.Errorf("unknown command %q", cmd)
}

// ---------- Ed25519 + BIP340 ----------

func othersDemo(p *Party, m *Mux) error {
	// Ed25519: HD keyset -> derived key -> standard library verifier
	if _, err := p.call(m, Req{Op: "hd-dkg", Ecdsa: false, Curve: cbmpc.Ed25519, Name: "ks-ed"}); err != nil {
		return err
	}
	if _, err := p.call(m, Req{Op: "hd-derive", Ecdsa: false, KS: "ks-ed", Name: "sol-child", HP: []uint32{44, 501}, NHP: []uint32{0, 3}}); err != nil {
		return err
	}
	kb, _ := p.Get("sol-child")
	pub, err := cbmpc.Pub2P(1, kb)
	if err != nil {
		return err
	}
	msg := []byte("solana message bytes")
	sig, err := signWith(p, m, 1, "sol-child", msg)
	if err != nil {
		return err
	}
	fmt.Printf("Ed25519 HD child pub %x\n  sig %x\n  crypto/ed25519.Verify = %v\n", pub, sig, ed25519.Verify(pub, msg, sig))
	sig2, _ := signWith(p, m, 1, "sol-child", msg)
	fmt.Printf("  second signature over same message identical = %v (randomized)\n", bytes.Equal(sig, sig2))

	// BIP340 Schnorr: separate (non-HD) 2PC key, btcec schnorr verifier
	if _, err := p.call(m, Req{Op: "dkg2p", Alg: cbmpc.AlgSchnorr, Name: "btc-schnorr"}); err != nil {
		return err
	}
	sk, _ := p.Get("btc-schnorr")
	xonly, err := cbmpc.SchnorrXOnly(sk)
	if err != nil {
		return err
	}
	h := sha256.Sum256([]byte("bip340 message"))
	ssig, err := signWith(p, m, 2, "btc-schnorr", h[:])
	if err != nil {
		return err
	}
	pk, err := schnorr.ParsePubKey(xonly)
	if err != nil {
		return err
	}
	s, err := schnorr.ParseSignature(ssig)
	if err != nil {
		return err
	}
	fmt.Printf("BIP340 x-only pub %x\n  sig %x\n  btcec schnorr.Verify = %v\n", xonly, ssig, s.Verify(h[:], pk))

	// ECDSA verify with a standard verifier too (btcec)
	if _, err := p.call(m, Req{Op: "dkg2p", Alg: cbmpc.AlgECDSA, Name: "plain-ecdsa"}); err != nil {
		return err
	}
	ek, _ := p.Get("plain-ecdsa")
	epub, _ := cbmpc.Pub2P(0, ek)
	der, err := signWith(p, m, 0, "plain-ecdsa", h[:])
	if err != nil {
		return err
	}
	ep, _ := btcec.ParsePubKey(epub)
	es, err := ecdsa.ParseDERSignature(der)
	if err != nil {
		return err
	}
	fmt.Printf("ECDSA secp256k1 (plain 2PC key) btcec Verify = %v\n", es.Verify(h[:], ep))
	return nil
}

// ---------- BIP32 compatibility ----------

func xpubDemo(p *Party, m *Mux) error {
	if _, ok := p.Get("ks-ecdsa"); !ok {
		if _, err := p.call(m, Req{Op: "hd-dkg", Ecdsa: true, Name: "ks-ecdsa"}); err != nil {
			return err
		}
	}
	hp := []uint32{44, 0, 0}
	res, err := p.call(m, Req{Op: "hd-node", KS: "ks-ecdsa", HP: hp})
	if err != nil {
		return err
	}
	parts := strings.Split(res, ":")
	q, _ := hex.DecodeString(parts[0])
	cc, _ := hex.DecodeString(parts[1])
	fmt.Printf("account node (hardened step via VRF): pub %s\n                                      chain code %s\n", parts[0], parts[1])
	// An "xpub" built from (Q, chain code) and handed to a stock BIP32 library.
	xpub := hdkeychain.NewExtendedKey(chaincfg.MainNetParams.HDPublicKeyID[:], q, cc, []byte{0, 0, 0, 0}, 3, 0, false)
	fmt.Println("xpub:", xpub.String())
	ok := true
	for _, path := range [][]uint32{{0}, {1}, {0, 0}, {1, 5}, {0, 4242}} {
		// third party: stock BIP32 CKDpub steps from the xpub
		node := xpub
		for _, i := range path {
			node, err = node.Derive(i)
			if err != nil {
				return err
			}
		}
		want, _ := node.ECPubKey()
		// cb-mpc: derive the 2PC key for the same hardened path + this non-hardened path
		name := fmt.Sprintf("x-%v", path)
		if _, err := p.call(m, Req{Op: "hd-derive", Ecdsa: true, KS: "ks-ecdsa", Name: name, HP: hp, NHP: path}); err != nil {
			return err
		}
		kb, _ := p.Get(name)
		got, _ := cbmpc.Pub2P(0, kb)
		match := bytes.Equal(got, want.SerializeCompressed())
		ok = ok && match
		fmt.Printf("path %-10v cb-mpc %x...  stock BIP32 %x...  match=%v\n", path, got[:6], want.SerializeCompressed()[:6], match)
	}
	if !ok {
		return errors.New("FAIL: BIP32 mismatch")
	}
	fmt.Println("PASS: non-hardened children from (Q, chain code) agree with stock BIP32 CKDpub")
	return nil
}
