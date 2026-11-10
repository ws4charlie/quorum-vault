package gateway

import (
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
	"github.com/ws4charlie/quorum-vault/internal/chain/sol"
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
		if sf.Backend == "mpc" && sf.Scheme != "ed25519-2of3" { // Ed25519 signers are opened by MPCMessageSigners
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

// MPCMessageSigners opens the Ed25519 signers of the partitions whose signers entry has scheme "ed25519-2of3" (Solana hot shards): per
// partition the 2-of-3 hot signer, and when the entry has a deposit section, the signer of the 2-party HD deposit key tree. Each hot signer's
// public key must be the address its chain pins for the partition (checked here, before anything is signed).
func MPCMessageSigners(cfg *Config) (hot map[string]signer.MessageSigner, deposit map[string]signer.MessageDeriver, closeAll func(), err error) {
	hot, deposit = map[string]signer.MessageSigner{}, map[string]signer.MessageDeriver{}
	var closers []func()
	closeAll = func() {
		for _, c := range closers {
			c()
		}
	}
	fail := func(format string, a ...any) (map[string]signer.MessageSigner, map[string]signer.MessageDeriver, func(), error) {
		closeAll()
		return nil, nil, nil, fmt.Errorf(format, a...)
	}
	parts := make([]string, 0, len(cfg.Signers))
	for p, sf := range cfg.Signers {
		if sf.Backend == "mpc" && sf.Scheme == "ed25519-2of3" {
			parts = append(parts, p)
		}
	}
	sort.Strings(parts)
	for _, p := range parts {
		sf := cfg.Signers[p]
		pub, err := hex.DecodeString(sf.PublicKey)
		if err != nil {
			return fail("gateway: signer %q: public_key must be hex", p)
		}
		var coords []mpcsigner.Coordinator
		for _, c := range sf.Coordinators {
			cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
			if err != nil {
				return fail("gateway: signer %q: coordinator %s: client certificate: %v", p, c.Name, err)
			}
			coords = append(coords, mpcsigner.Coordinator{Name: c.Name, Address: c.Address, ClientCert: cert, ServerPin: c.ServerPin})
		}
		ts, err := mpcsigner.NewEdThreshold(mpcsigner.ThresholdConfig{PartitionID: p, KeysetID: sf.KeysetID, PublicKey: pub, Coordinators: coords,
			MaxRetries: sf.Coordinators[0].MaxRetries, Timeout: cfg.SignTimeout})
		if err != nil {
			return fail("gateway: signer %q: %v", p, err)
		}
		closers = append(closers, ts.Close)
		hot[p] = ts
		if d := sf.Deposit; d != nil {
			cert, err := tls.LoadX509KeyPair(d.MPC.CertFile, d.MPC.KeyFile)
			if err != nil {
				return fail("gateway: signer %q: deposit: client certificate: %v", p, err)
			}
			ds, err := mpcsigner.NewEdDeriving(mpcsigner.EdDerivingConfig{PartitionID: p, Address: d.MPC.Address, ClientCert: cert, ServerPin: d.MPC.ServerPin,
				KeysetID: d.KeysetID, HardenedPath: d.HardenedPath, MaxRetries: d.MPC.MaxRetries, Timeout: cfg.SignTimeout})
			if err != nil {
				return fail("gateway: signer %q: deposit: %v", p, err)
			}
			closers = append(closers, ds.Close)
			deposit[p] = ds
		}
	}
	// A hot partition of a Solana chain signs with the key of its pinned address.
	for name, cc := range cfg.Chains {
		for p, addr := range cc.SOL.HotShards {
			s := hot[p]
			if s == nil {
				continue
			}
			want, err := sol.ParseAddress(addr)
			if err != nil || string(want[:]) != string(s.PublicKey()) {
				return fail("gateway: chain %q partition %q: the signer's key is not the pinned hot address %s", name, p, addr)
			}
		}
	}
	return hot, deposit, closeAll, nil
}

// CheckMessageSigners refuses to start unless every hot partition of every Solana chain has an Ed25519 signer, and a deposit signer when the
// chain allows sweeps.
func CheckMessageSigners(cfg *Config, hot map[string]signer.MessageSigner, deposit map[string]signer.MessageDeriver) error {
	for name, cc := range cfg.Chains {
		if cc.Family != FamilySOL {
			continue
		}
		for p := range cc.SOL.HotShards {
			if hot[p] == nil {
				return fmt.Errorf("chain %q: hot partition %q has no ed25519-2of3 signer", name, p)
			}
			if cc.SweepsPerHour > 0 && deposit[p] == nil {
				return fmt.Errorf("chain %q: sweeps are allowed but partition %q has no deposit signer", name, p)
			}
		}
	}
	return nil
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
