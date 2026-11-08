package gateway

import (
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
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
		if sf.Scheme == "ecdsa-2of3" {
			pub, err := hex.DecodeString(sf.PublicKey)
			if err != nil {
				closeAll()
				return nil, nil, fmt.Errorf("gateway: signer %q: public_key must be hex", p)
			}
			var coords []mpcsigner.Coordinator
			for _, c := range sf.Coordinators {
				cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
				if err != nil {
					closeAll()
					return nil, nil, fmt.Errorf("gateway: signer %q: coordinator %s: client certificate: %w", p, c.Name, err)
				}
				coords = append(coords, mpcsigner.Coordinator{Name: c.Name, Address: c.Address, ClientCert: cert, ServerPin: c.ServerPin})
			}
			ts, err := mpcsigner.NewThreshold(mpcsigner.ThresholdConfig{PartitionID: p, KeysetID: sf.KeysetID, PublicKey: pub, Coordinators: coords,
				MaxRetries: sf.Coordinators[0].MaxRetries, Timeout: cfg.SignTimeout})
			if err != nil {
				closeAll()
				return nil, nil, fmt.Errorf("gateway: signer %q: %w", p, err)
			}
			closers = append(closers, ts.Close)
			out[p] = ts
			continue
		}
		if sf.KeysetID != "" {
			cert, err := tls.LoadX509KeyPair(sf.MPC.CertFile, sf.MPC.KeyFile)
			if err != nil {
				closeAll()
				return nil, nil, fmt.Errorf("gateway: signer %q: client certificate: %w", p, err)
			}
			d, err := mpcsigner.NewDeriving(mpcsigner.DerivingConfig{KeysetID: sf.KeysetID, HardenedPath: sf.HardenedPath,
				Config: mpcsigner.Config{PartitionID: p, Address: sf.MPC.Address, ClientCert: cert, ServerPin: sf.MPC.ServerPin,
					MaxRetries: sf.MPC.MaxRetries, Timeout: cfg.SignTimeout}})
			if err != nil {
				closeAll()
				return nil, nil, fmt.Errorf("gateway: signer %q: %w", p, err)
			}
			closers = append(closers, d.Close)
			out[p] = d
			continue
		}
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

// CheckSigners refuses to start unless every hot partition of every chain has a signer that can sign for it: an EVM partition any signer,
// a Bitcoin partition a key-tree signer (mpc, keyset_id and hardened_path) whose hardened path is the account path of the chain's network,
// since each input's key is derived below it.
func CheckSigners(cfg *Config, signers map[string]signer.Signer) error {
	for name, cc := range cfg.Chains {
		for p := range cc.EVM.HotAddresses {
			if signers[p] == nil {
				return fmt.Errorf("chain %q: hot partition %q has no signer", name, p)
			}
		}
		for p := range cc.BTC.HotShards {
			if _, ok := signers[p].(signer.Deriver); !ok {
				return fmt.Errorf("chain %q: hot partition %q needs an mpc signer with keyset_id and hardened_path (Bitcoin signs every input under its own derived key)", name, p)
			}
			want := btc.AccountPath(cc.BTC.Network)
			got := cfg.Signers[p].HardenedPath
			if fmt.Sprint(got) != fmt.Sprint(want) {
				return fmt.Errorf("chain %q: signer of %q has hardened_path %v, the account path of %s is %v", name, p, got, cc.BTC.Network, want)
			}
		}
	}
	return nil
}
