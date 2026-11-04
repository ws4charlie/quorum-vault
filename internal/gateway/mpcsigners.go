package gateway

import (
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/ws4charlie/quorum-vault/internal/mpcsigner"
	"github.com/ws4charlie/quorum-vault/internal/signer"
)

// MPCSigners opens one cb-mpc signer per partition whose signers entry has backend "mpc". Every hot partition of a
// chain must have a signer, from either HSMSigners or this function; the hot address must be the key's address.
func MPCSigners(cfg *Config) (map[string]signer.Signer, func(), error) {
	out := map[string]signer.Signer{}
	var closers []func()
	closeAll := func() {
		for _, c := range closers {
			c()
		}
	}
	parts := make([]string, 0, len(cfg.Signers))
	for p, sf := range cfg.Signers {
		if sf.Backend == "mpc" {
			parts = append(parts, p)
		}
	}
	sort.Strings(parts)
	for _, p := range parts {
		sf := cfg.Signers[p]
		pub, err := hex.DecodeString(sf.PublicKey)
		if err != nil {
			closeAll()
			return nil, nil, fmt.Errorf("gateway: signer %q: public_key must be hex", p)
		}
		cert, err := tls.LoadX509KeyPair(sf.MPC.CertFile, sf.MPC.KeyFile)
		if err != nil {
			closeAll()
			return nil, nil, fmt.Errorf("gateway: signer %q: client certificate: %w", p, err)
		}
		s, err := mpcsigner.New(mpcsigner.Config{PartitionID: p, Address: sf.MPC.Address, KeyID: sf.KeyID, PublicKey: pub,
			ClientCert: cert, ServerPin: sf.MPC.ServerPin, MaxRetries: sf.MPC.MaxRetries, Timeout: cfg.SignTimeout})
		if err != nil {
			closeAll()
			return nil, nil, fmt.Errorf("gateway: signer %q: %w", p, err)
		}
		closers = append(closers, s.Close)
		out[p] = s
	}
	for name, cc := range cfg.Chains {
		for p, addr := range cc.EVM.HotAddresses {
			if s := out[p]; s != nil {
				if err := (&EVMCodec{}).CheckSigner(TxInfo{Sender: addr.Hex()}, s.PublicKey()); err != nil {
					closeAll()
					return nil, nil, fmt.Errorf("gateway: chain %q partition %q: %w", name, p, err)
				}
			}
		}
	}
	return out, closeAll, nil
}
