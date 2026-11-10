package custody

import (
	"encoding/hex"
	"testing"

	"filippo.io/edwards25519"
)

func solFile() File {
	pk := hex.EncodeToString(edwards25519.NewGeneratorPoint().Bytes())
	return File{Chain: ChainFile{Family: "sol", Name: "sol-local", SOL: &SOLFile{Network: "localnet", RPCURL: "http://127.0.0.1:18899", AccountPublicKey: pk, AccountChainCode: hex.EncodeToString(make([]byte, 32))},
		Assets: map[string]AssetFile{
			"SOL": {Decimals: 9, MinDeposit: "1000"},
			"TKN": {Address: "So11111111111111111111111111111111111111112", Decimals: 6, MinDeposit: "1"},
		}}}
}

func TestSOLConfig(t *testing.T) {
	c, err := solFile().Build()
	if err != nil {
		t.Fatal(err)
	}
	if c.Family != FamilySOL || c.Native != "SOL" || len(c.AssetList) != 2 || c.AssetList[0] != "SOL" || c.AssetList[1] != "TKN" {
		t.Fatalf("%+v", c)
	}
	if c.Assets["TKN"].Native() || !c.Assets["SOL"].Native() || c.Assets["TKN"].Mint == "" {
		t.Fatalf("assets %+v", c.Assets)
	}
	for name, mod := range map[string]func(*File){
		"no sol section":        func(f *File) { f.Chain.SOL = nil },
		"no SOL asset":          func(f *File) { delete(f.Chain.Assets, "SOL") },
		"SOL with an address":   func(f *File) { f.Chain.Assets["SOL"] = AssetFile{Address: "x", Decimals: 9} },
		"SOL with 8 decimals":   func(f *File) { f.Chain.Assets["SOL"] = AssetFile{Decimals: 8} },
		"token without a mint":  func(f *File) { f.Chain.Assets["TKN"] = AssetFile{Decimals: 6} },
		"token mint not base58": func(f *File) { f.Chain.Assets["TKN"] = AssetFile{Address: "0xabc", Decimals: 6} },
		"unknown network":       func(f *File) { f.Chain.SOL.Network = "moon" },
		"cold addresses":        func(f *File) { f.Cold.Addresses = map[string]string{"omnibus/native": "x"} },
	} {
		f := solFile()
		sc := *f.Chain.SOL
		f.Chain.SOL = &sc
		a := map[string]AssetFile{}
		for k, v := range f.Chain.Assets {
			a[k] = v
		}
		f.Chain.Assets = a
		mod(&f)
		if _, err := f.Build(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
