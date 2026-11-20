package gateway

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
	"github.com/ws4charlie/quorum-vault/internal/chain/sol"
	"github.com/ws4charlie/quorum-vault/internal/partition"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// Generations of the deposit key tree of a Bitcoin or Solana chain (K6). The signed records of keysets.go name the tree by its registry ID
// (entity/chain/deposit-tree/0) and carry, per generation, the keyset to sign with (key_ref: the MPC keyset ID of the 2-party HD keyset) and the public
// identity the addresses derive from (public_key: the account xpub on Bitcoin, "<node key hex>:<chain code hex>" on Solana). Generation 1 is what the
// config pins; every later generation exists only because operators signed it.
//
// What a state allows:
//
//	Bitcoin   one generation is one account key: its deposit addresses (branch 0) AND its hot shards (branch 1, the same partition under that key).
//	  active       what it allows without generations; a sweep of its addresses pays ITS hot shard
//	  candidate    nothing
//	  draining     a sweep of its deposit addresses, paying the hot shard of the successor named by the record (which must be active); a "drain" of its hot
//	               shard to the successor's, within the cap the record carries; a cancel, and the replacement of work it already signed. No withdrawal.
//	  compromised  the same, except the cancel and the replacement
//	  retired      nothing
//	Solana    only the deposit node is replaced here (the hot shard is another task): a sweep may spend deposit keys of any generation that is active,
//	  draining or compromised, and pays the partition's pinned hot shard; a candidate or a retired generation signs nothing.
//
// The generation an input is under is read from the zone's own derivation: the payload says which generation it claims and the zone derives the script
// from the account key of that generation, which only its own signed records can add. A core that lies about it gets a digest of another script, which
// the zone then does not recognise, or a key the state rules do not allow.

// overlay returns the codec that derives under every generation of the chain's deposit tree this view knows.
func (c *BTCCodec) overlay(v *KeysetView, cc *ChainConfig) (*BTCCodec, error) {
	var gs []btc.DepositGen
	for g, e := range v.tree(cc.Name) {
		if g >= 2 {
			gs = append(gs, btc.DepositGen{Gen: uint32(g), Xpub: e.PublicKey})
		}
	}
	if len(gs) == 0 {
		return c, nil
	}
	nv, err := c.Verifier.WithGenerations(gs)
	if err != nil {
		return nil, err
	}
	return &BTCCodec{Verifier: nv}, nil
}

// overlay is the Solana codec's: it derives under every generation of the deposit tree the view knows, and accepts the fee payer of a hot job to be any
// generation of the partition's shard (K4).
func (c *SOLCodec) overlay(v *KeysetView, cc *ChainConfig) (*SOLCodec, error) {
	var ns []sol.DepositNode
	for g, e := range v.tree(cc.Name) {
		if g < 2 {
			continue
		}
		n, err := ParseSolNode(e.PublicKey)
		if err != nil {
			return nil, err
		}
		ns = append(ns, sol.DepositNode{Gen: uint32(g), Node: n})
	}
	var hs []sol.HotGeneration
	later := false
	for _, shard := range v.Shards() {
		if shard.IsDepositTree() {
			continue
		}
		for _, e := range v.Generations(shard) {
			if e.Chain != cc.Name {
				continue
			}
			hs = append(hs, sol.HotGeneration{Shard: shard, Gen: uint32(e.Generation), Address: e.Address, Active: e.State == partition.StateActive})
			later = later || e.Generation > 1
		}
	}
	if len(ns) == 0 && !later {
		return c, nil
	}
	nv := c.Verifier
	var err error
	if len(ns) > 0 {
		if nv, err = nv.WithGenerations(ns); err != nil {
			return nil, err
		}
	}
	if later {
		if nv, err = nv.WithHotGenerations(hs); err != nil {
			return nil, err
		}
	}
	return &SOLCodec{Verifier: nv}, nil
}

// overlayCodec returns the codec of a chain that judges by the keyset view v.
func overlayCodec(codec ChainCodec, v *KeysetView, cc *ChainConfig) (ChainCodec, error) {
	switch c := codec.(type) {
	case *EVMCodec:
		if v.Seq > 0 {
			return c.overlay(v, cc), nil
		}
	case *BTCCodec:
		return c.overlay(v, cc)
	case *SOLCodec:
		return c.overlay(v, cc)
	}
	return codec, nil
}

// btcGenRules is the state rule of one Bitcoin job, run inside the guard transaction: what the generation of the inputs may sign, and where.
func (d *Decider) btcGenRules(ctx context.Context, gt *GuardTx, kv *KeysetView, cc *ChainConfig, i signjob.Intent, info TxInfo, amount *big.Int, known bool, now time.Time) error {
	tree := kv.tree(cc.Name)
	if tree == nil {
		if i.Kind == signjob.KindDrain {
			return reject(ReasonKeyset, "chain %q has no keysets: a drain is for key replacements", i.Chain)
		}
		return nil
	}
	e := tree[int(info.Gen)]
	if e == nil {
		return reject(ReasonKeyset, "deposit generation %d of %s is unknown to this zone", info.Gen, cc.Name)
	}
	label := fmt.Sprintf("generation %d of the %s account key", e.Generation, cc.Name)
	// successor is the generation a draining or compromised one pays, and it must be active.
	successor := func() (*KeysetEntry, error) {
		if e.Successor == 0 {
			return nil, reject(ReasonKeyset, "%s is %s with no successor named: there is nowhere to move it", label, e.State)
		}
		s := tree[e.Successor]
		switch {
		case s == nil:
			return nil, reject(ReasonKeyset, "successor generation %d of %s is unknown", e.Successor, cc.Name)
		case s.State != partition.StateActive:
			return nil, reject(ReasonKeyset, "successor generation %d of %s is %s: only an active one is paid", s.Generation, cc.Name, s.State)
		}
		return s, nil
	}
	switch i.Kind {
	case "sweep":
		switch e.State {
		case partition.StateActive:
			if info.DestGen != info.Gen {
				return reject(ReasonKeyset, "%s is active: its deposit addresses are swept to its own hot shard, not to generation %d's", label, info.DestGen)
			}
		case partition.StateDraining, partition.StateCompromised:
			s, err := successor()
			if err != nil {
				return err
			}
			if info.DestGen != uint32(s.Generation) {
				return reject(ReasonKeyset, "%s is %s: its deposit addresses are swept only to the hot shard of its successor, generation %d (the output is generation %d's)", label, e.State, s.Generation, info.DestGen)
			}
		default:
			return reject(ReasonKeyset, "%s is %s: it signs nothing", label, e.State)
		}
		return nil
	case signjob.KindDrain:
		if d.cfg.Operators == nil {
			return reject(ReasonKeyset, "this zone's config has no operators section: keyset states, and so drains, are off")
		}
		if !known {
			switch n := now.Unix(); {
			case i.NotAfter == 0:
				return reject(ReasonExpired, "intent has no not_after")
			case i.NotAfter <= n:
				return reject(ReasonExpired, "intent expired at %d, now %d", i.NotAfter, n)
			case i.NotAfter > n+int64(d.cfg.MaxIntentAge/time.Second):
				return reject(ReasonExpired, "not_after %d is more than %s ahead", i.NotAfter, d.cfg.MaxIntentAge)
			}
		}
		switch e.State {
		case partition.StateDraining, partition.StateCompromised:
		case partition.StateActive, partition.StateCandidate:
			return d.keysetLag(i, now, "%s is %s here, a drain needs it draining or compromised", label, e.State)
		default:
			return reject(ReasonKeyset, "%s is %s: nothing moves out of it", label, e.State)
		}
		if e.Successor == 0 {
			return reject(ReasonKeyset, "%s is %s with no successor named: there is nowhere to drain it", label, e.State)
		}
		s := tree[e.Successor]
		if s == nil {
			return reject(ReasonKeyset, "successor generation %d of %s is unknown", e.Successor, cc.Name)
		}
		switch s.State {
		case partition.StateActive:
		case partition.StateCandidate:
			return d.keysetLag(i, now, "successor generation %d of %s is a candidate here, a drain needs it active", s.Generation, cc.Name)
		default:
			return reject(ReasonKeyset, "successor generation %d of %s is %s: a drain pays an active generation", s.Generation, cc.Name, s.State)
		}
		if info.DestGen != uint32(s.Generation) {
			return reject(ReasonKeyset, "the drain pays the hot shard of generation %d, not the successor's (generation %d)", info.DestGen, s.Generation)
		}
		if known {
			return nil
		}
		return d.drainLimits(ctx, gt, cc, e, partition.ShardID(label), info.Sender, i.Asset, amount, now)
	case "cancel":
		switch e.State {
		case partition.StateActive, partition.StateDraining:
			return nil // the cancel of work already signed
		}
		return reject(ReasonKeyset, "%s is %s: it signs no cancel", label, e.State)
	}
	// withdrawal, to-cold, consolidate, cpfp, batch: the hot shard of an active generation.
	switch e.State {
	case partition.StateActive:
		return nil
	case partition.StateDraining:
		if known {
			return nil // the replacement of a send this generation signed while it was active
		}
		return reject(ReasonKeyset, "%s is draining: its hot shard signs only a drain to the successor, and the replacement or cancel of work already signed", label)
	}
	return reject(ReasonKeyset, "%s is %s: it signs nothing", label, e.State)
}

// solGenRules is the state rule of one Solana job: the deposit keys of a sweep (generations of the deposit tree that are active, draining or compromised),
// and the generation of the hot shard that pays (K4).
//
//	Solana hot shard   the fee payer of a job is a generation of the partition's shard; what its state allows:
//	  active       everything a hot shard signs
//	  candidate    only the creation of its own nonce pool (nonce-setup): the pool exists before the generation is switched on
//	  draining     a drain to its successor, the closing of its nonce accounts to itself (nonce-close), the cancel and the replacement of work it already signed
//	  compromised  a drain to its successor, nothing else
//	  retired      nothing
func (d *Decider) solGenRules(ctx context.Context, gt *GuardTx, kv *KeysetView, cc *ChainConfig, i signjob.Intent, info TxInfo, amount *big.Int, known bool, now time.Time) error {
	if kv == nil {
		if i.Kind == signjob.KindDrain {
			return reject(ReasonKeyset, "chain %q has no keysets: a drain is for key replacements", i.Chain)
		}
		return nil
	}
	if i.Kind == "sweep" {
		if err := d.solDepositRules(kv, cc, info); err != nil {
			return err
		}
	}
	shard, managed := kv.shardOf(i.PartitionID)
	if !managed {
		if i.Kind == signjob.KindDrain {
			return reject(ReasonKeyset, "partition %q is not a hot shard with keysets: nothing to drain", i.PartitionID)
		}
		return nil
	}
	if i.Kind == signjob.KindDrain {
		return d.drainRule(ctx, gt, kv, cc, shard, i, info, amount, known, now)
	}
	e := kv.byAddress(shard, info.Sender)
	if e == nil {
		return reject(ReasonKeyset, "%s is no generation of %s", info.Sender, shard)
	}
	switch e.State {
	case partition.StateActive:
		return nil
	case partition.StateCandidate:
		if i.Kind == sol.KindNonceSetup {
			return nil
		}
		return reject(ReasonKeyset, "generation %d of %s is a candidate: it signs only the creation of its own nonce pool until it is activated", e.Generation, shard)
	case partition.StateDraining:
		if i.Kind == "cancel" || i.Kind == sol.KindNonceClose || known {
			return nil // finishing work already signed, or closing its own nonce accounts
		}
		return reject(ReasonKeyset, "generation %d of %s is draining: it signs only a drain to its successor, the closing of its nonce accounts, and the replacement or cancel of work already signed", e.Generation, shard)
	}
	return reject(ReasonKeyset, "generation %d of %s is %s: it signs nothing", e.Generation, shard, e.State)
}

// solDepositRules: a sweep may spend the deposit keys of generations that are active, draining or compromised.
func (d *Decider) solDepositRules(kv *KeysetView, cc *ChainConfig, info TxInfo) error {
	tree := kv.tree(cc.Name)
	if tree == nil {
		return nil
	}
	gens := info.DepositGens
	if len(gens) == 0 {
		gens = []uint32{1}
	}
	for _, g := range gens {
		e := tree[int(g)]
		if e == nil {
			return reject(ReasonKeyset, "deposit generation %d of %s is unknown to this zone", g, cc.Name)
		}
		switch e.State {
		case partition.StateActive, partition.StateDraining, partition.StateCompromised:
		default:
			return reject(ReasonKeyset, "generation %d of the %s deposit node is %s: its deposit keys sign nothing", g, cc.Name, e.State)
		}
	}
	return nil
}
