package eth

import (
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
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
