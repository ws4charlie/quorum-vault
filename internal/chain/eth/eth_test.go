package eth

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/ws4charlie/quorum-vault/internal/signer"
)

func params() TxParams {
	return TxParams{
		ChainID:   big.NewInt(SepoliaChainID),
		Nonce:     7,
		To:        common.HexToAddress("0x000000000000000000000000000000000000dEaD"),
		Value:     big.NewInt(12345),
		Gas:       DefaultGasLimit,
		GasTipCap: big.NewInt(DefaultTipWei),
		GasFeeCap: big.NewInt(DefaultFeeCapWei),
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
		tx, d, err := BuildTx(params())
		if err != nil {
			t.Fatal(err)
		}
		if tx.Type() != 2 || tx.ChainId().Int64() != SepoliaChainID {
			t.Fatalf("type %d chain %v", tx.Type(), tx.ChainId())
		}
		s, err := Assemble(tx, softSign(t, k, d), &k.PublicKey)
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
		dec, err := DecodeRaw(s.Raw)
		if err != nil {
			t.Fatal(err)
		}
		if dec.Hash() != s.Hash {
			t.Fatal("hash mismatch after decode")
		}
		if err := VerifySender(dec, from); err != nil {
			t.Fatal(err)
		}
		if err := VerifySender(dec, common.Address{1}); !errors.Is(err, ErrSenderMismatch) {
			t.Fatalf("want ErrSenderMismatch, got %v", err)
		}
	}
}

func TestAssembleHighS(t *testing.T) {
	n := crypto.S256().Params().N
	k, _ := crypto.GenerateKey()
	tx, d, _ := BuildTx(params())
	low := softSign(t, k, d) // crypto.Sign is always low-S
	high := signer.Signature{R: low.R, S: new(big.Int).Sub(n, low.S)}
	if !signer.Verify(&k.PublicKey, d, high) {
		t.Fatal("high-S form should still be a valid ECDSA signature")
	}
	sh, err := Assemble(tx, high, &k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sl, err := Assemble(tx, low, &k.PublicKey)
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
	tx, d, _ := BuildTx(params())
	if _, err := Assemble(tx, softSign(t, k, d), &other.PublicKey); err == nil {
		t.Fatal("signature from another key accepted")
	}
}

func TestDigestCoversFields(t *testing.T) {
	_, d1, _ := BuildTx(params())
	p := params()
	p.Nonce++
	_, d2, _ := BuildTx(p)
	p = params()
	p.ChainID = big.NewInt(1)
	_, d3, _ := BuildTx(p)
	if d1 == d2 || d1 == d3 {
		t.Fatal("digest must change with nonce and chain id")
	}
}

func TestBuildTxValidation(t *testing.T) {
	bad := []func(*TxParams){
		func(p *TxParams) { p.ChainID = nil },
		func(p *TxParams) { p.ChainID = big.NewInt(0) },
		func(p *TxParams) { p.Value = big.NewInt(-1) },
		func(p *TxParams) { p.Gas = 0 },
		func(p *TxParams) { p.GasFeeCap = nil },
		func(p *TxParams) { p.GasTipCap = big.NewInt(DefaultFeeCapWei + 1) },
	}
	for i, f := range bad {
		p := params()
		f(&p)
		if _, _, err := BuildTx(p); !errors.Is(err, ErrInvalidTx) {
			t.Errorf("case %d: want ErrInvalidTx, got %v", i, err)
		}
	}
}
