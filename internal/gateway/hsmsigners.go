package gateway

import (
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/ws4charlie/quorum-vault/internal/domain"
	"github.com/ws4charlie/quorum-vault/internal/hsm"
	"github.com/ws4charlie/quorum-vault/internal/hsmsigner"
	"github.com/ws4charlie/quorum-vault/internal/signer"
)

// HSMSigners opens one signer per configured partition from the config's
// signers section. P5 replaces this backend; the Gateway only sees signer.Signer.
// Every hot partition in the chain configs must have a signer.
func HSMSigners(cfg *Config, lib *hsm.Lib, pin string) (map[string]signer.Signer, func(), error) {
	tokens := map[string]*hsm.Token{}
	closeAll := func() {
		for _, t := range tokens {
			t.Close()
		}
	}
	out := map[string]signer.Signer{}
	parts := make([]string, 0, len(cfg.Signers))
	for p := range cfg.Signers {
		parts = append(parts, p)
	}
	sort.Strings(parts)
	for _, p := range parts {
		sf := cfg.Signers[p]
		tok := tokens[sf.Token]
		if tok == nil {
			t, err := lib.OpenToken(sf.Token, pin)
			if err != nil {
				closeAll()
				return nil, nil, fmt.Errorf("gateway: open token %q: %w", sf.Token, err)
			}
			tokens[sf.Token], tok = t, t
		}
		id, err1 := hex.DecodeString(sf.KeyID)
		pub, err2 := hex.DecodeString(sf.PublicKey)
		if err1 != nil || err2 != nil || len(id) == 0 {
			closeAll()
			return nil, nil, fmt.Errorf("gateway: signer %q: key_id and public_key must be hex", p)
		}
		s, err := hsmsigner.New(tok, domain.Key{ID: p, Backend: domain.BackendHSM, Curve: domain.CurveSecp256k1, HSMKeyID: id, PublicKey: pub})
		if err != nil {
			closeAll()
			return nil, nil, err
		}
		out[p] = s
	}
	for name, cc := range cfg.Chains {
		for p := range cc.EVM.HotAddresses {
			if out[p] == nil {
				closeAll()
				return nil, nil, fmt.Errorf("gateway: chain %q: hot partition %q has no signer", name, p)
			}
			if err := (&EVMCodec{}).CheckSigner(TxInfo{Sender: cc.EVM.HotAddresses[p].Hex()}, out[p].PublicKey()); err != nil {
				closeAll()
				return nil, nil, fmt.Errorf("gateway: partition %q: %w", p, err)
			}
		}
	}
	return out, closeAll, nil
}
