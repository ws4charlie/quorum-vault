package ethtest_test

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/ws4charlie/quorum-vault/internal/chain/eth"
	"github.com/ws4charlie/quorum-vault/internal/chain/eth/ethtest"
	"github.com/ws4charlie/quorum-vault/internal/signer"
)

func params() eth.TxParams {
	return eth.TxParams{
		ChainID:   big.NewInt(eth.SepoliaChainID),
		Nonce:     7,
		To:        common.HexToAddress("0x000000000000000000000000000000000000dEaD"),
		Value:     big.NewInt(12345),
		Gas:       eth.DefaultGasLimit,
		GasTipCap: big.NewInt(eth.DefaultTipWei),
		GasFeeCap: big.NewInt(eth.DefaultFeeCapWei),
	}
}

// softSign signs digest with a software key and returns (r, s) like a backend.
func softSign(t *testing.T, k *ecdsa.PrivateKey, d [32]byte) signer.Signature {
	t.Helper()
	sig, err := crypto.Sign(d[:], k)
	if err != nil {
		t.Fatal(err)
	}
	return signer.Signature{R: new(big.Int).SetBytes(sig[:32]), S: new(big.Int).SetBytes(sig[32:64])}
}

func TestBuildSignAssembleRoundTrip(t *testing.T) {
	for i := 0; i < 16; i++ { // both recovery ids get exercised
		k, _ := crypto.GenerateKey()
		tx, d, err := eth.BuildTx(params())
		if err != nil {
			t.Fatal(err)
		}
		if tx.Type() != 2 || tx.ChainId().Int64() != eth.SepoliaChainID {
			t.Fatalf("type %d chain %v", tx.Type(), tx.ChainId())
		}
		s, err := ethtest.Assemble(tx, softSign(t, k, d), &k.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		from := crypto.PubkeyToAddress(k.PublicKey)
		if s.From != from {
			t.Fatalf("from %s want %s", s.From, from)
		}
		if s.Raw[0] != 0x02 {
			t.Fatalf("raw tx type byte %#x", s.Raw[0])
		}
		dec, err := eth.DecodeRaw(s.Raw)
		if err != nil {
			t.Fatal(err)
		}
		if dec.Hash() != s.Hash {
			t.Fatal("hash mismatch after decode")
		}
		if err := eth.VerifySender(dec, from); err != nil {
			t.Fatal(err)
		}
		if err := eth.VerifySender(dec, common.Address{1}); !errors.Is(err, eth.ErrSenderMismatch) {
			t.Fatalf("want ErrSenderMismatch, got %v", err)
		}
	}
}

func TestAssembleHighS(t *testing.T) {
	n := crypto.S256().Params().N
	k, _ := crypto.GenerateKey()
	tx, d, _ := eth.BuildTx(params())
	low := softSign(t, k, d) // crypto.Sign is always low-S
	high := signer.Signature{R: low.R, S: new(big.Int).Sub(n, low.S)}
	if !signer.Verify(&k.PublicKey, d, high) {
		t.Fatal("high-S form should still be a valid ECDSA signature")
	}
	sh, err := ethtest.Assemble(tx, high, &k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sl, err := ethtest.Assemble(tx, low, &k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sh.Sig65, sl.Sig65) {
		t.Fatal("high-S input must normalize to the same 65-byte signature")
	}
	_, _, s := sh.Tx.RawSignatureValues()
	if s.Cmp(new(big.Int).Rsh(n, 1)) > 0 {
		t.Fatal("signed tx carries high S")
	}
}

func TestAssembleWrongKey(t *testing.T) {
	k, _ := crypto.GenerateKey()
	other, _ := crypto.GenerateKey()
	tx, d, _ := eth.BuildTx(params())
	if _, err := ethtest.Assemble(tx, softSign(t, k, d), &other.PublicKey); err == nil {
		t.Fatal("signature from another key accepted")
	}
}
