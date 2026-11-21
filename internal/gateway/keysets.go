package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math/big"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/ws4charlie/quorum-vault/internal/audit"
	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
	"github.com/ws4charlie/quorum-vault/internal/chain/sol"
	"github.com/ws4charlie/quorum-vault/internal/domain"
	"github.com/ws4charlie/quorum-vault/internal/partition"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// The zone's own view of the keysets of its EVM hot shards. The business side keeps a registry of keyset generations (internal/partition/keyset.go) but
// only ASKS: what the zone signs follows what the zone itself knows, and that comes from two places: the static config file (every pinned hot address
// is generation 1 of its shard, active) and a signed change log in each guard database (this file). The effective view is the config with the verified
// log applied in order. It is built the same way as the approver registry (approvers.go) and shares its key set: the "operators" section of the config,
// min_operators distinct operators per change, a signing time within max_change_age when applied, a sequence number higher than the current one, append-only
// storage in the guard database of the gateway and of every cosigner with an audit event naming the operators, a re-check of every row on every read.
// Approver signatures never count: an approver cannot change a keyset state, and nothing the core or the business database says can.
//
// A change names a shard (the stable shard ID of internal/partition), a generation and one of five actions:
//
//	register-candidate  adds generation N+1 with its address: it signs nothing yet
//	activate            candidate -> active, only when the shard has no other active generation
//	start-draining      active -> draining, naming the successor generation (a candidate or active one, higher) and, per asset, the most the drain may move
//	retire              draining -> retired
//	mark-compromised    candidate, active or draining -> compromised, final; it may name the successor and caps as start-draining does (once)
//
// What a state allows, enforced for every EVM job from the sender's generation (Decider.keysetRules):
//
//	active       what it allows without generations
//	candidate    nothing (the bounded self-test is a later step)
//	draining     only a "drain" to its successor, and work already signed: the replacement of an intent it signed, and cancels
//	retired      nothing
//	compromised  nothing, except a "drain" to its successor
//
// A destination of a rebalance must be the address of an ACTIVE generation of another shard; the sweep destination must not be the address of a
// generation that is not active.
//
// The drain. A "drain" intent names the shard (partition_id), the asset, the source address (from) and the successor's address (to); the transaction
// is a plain transfer from the source to that address. It needs no approval: the operator-signed record that made the source draining is the
// authorisation, and the zone signs a drain only from a draining (or compromised) generation to the successor that record names, once the successor
// is active. What the zone cannot check is "everything": it has no chain access, so it cannot read the balance. It bounds the amount instead: the total
// of all drains from one address and asset may not exceed the cap the signed record carries for that asset, and drains_per_hour limits their rate.
// A drain of less than everything is harmless (the rest stays on the draining key and is drained again); a drain of more is impossible.
//
// When the gateway and a cosigner are on different sequence numbers each judges by its own verified log. A drain whose state does not hold here yet
// (the source not draining, the successor not active) is not refused finally: the decision is a retry (ErrKeysetLag) until the intent's not_after,
// with an ALERT, like ErrApproverLag. A drain that cannot become valid (a retired source, a wrong destination in a ready state) is a refusal.
//
// The emergency. mark-compromised is the one signed event of a suspected theft. In the same record it (1) ends ordinary signing for the generation in
// this zone (the next decision reads the log: nothing is cached), (2) leaves the generation one thing to sign, a drain to the successor the record names,
// (3) carries the emergency caps for that drain (the record's caps are the only ones: no second setting that could be forgotten), and (4) takes the
// drains_per_hour limit off that source. What bounds the gas the drains burn is max_drains_per_source (drainLimits), for every drain. The business core mirrors the flag (qv-rekey emergency) and then stops paying from the generation and sweeping
// into it. The record also says nothing is retired: compromised is final.
//
// An old binary (before this file) does not know the kind "drain": it refuses the job with a normal refusal ("intent kind"). Until every replica is
// upgraded, the planner must expect refusals from the old ones (docs/runbooks/key-replacement.md).

// Actions of a keyset change.
const (
	KeysetRegisterCandidate = "register-candidate"
	KeysetActivate          = "activate"
	KeysetStartDraining     = "start-draining"
	KeysetRetire            = "retire"
	KeysetMarkCompromised   = "mark-compromised"
	KeysetSetDrainCaps      = "set-drain-caps"
)

// EventKeysetChanged is the audit event of an applied keyset change.
const EventKeysetChanged = "zone.keyset.changed"

// ReasonKeyset is the refusal code of a job a keyset state does not allow. The drain's own limits have codes of their own.
const (
	ReasonKeyset    = "keyset_state"
	ReasonDrainRate = "policy_drain_rate" // 4 too many drains in the last hour
	ReasonDrainCap  = "policy_drain_cap"  // 4 the drains of this source and asset would exceed the cap of the signed record
	// ReasonDrainGas: this source has had the most drains the zone allows in all (the gas bound).
	ReasonDrainGas = "policy_drain_gas"
)

// KeysetLagNote ends the reason of a decision that waits because this zone's keyset view may be behind the other side's.
const KeysetLagNote = "this zone's keyset view may be behind: apply the same signed keyset changes to the gateway and every cosigner (docs/runbooks/key-replacement.md)"

// ErrKeysetLag marks a decision that is a retry, not a refusal: see the comment above.
var ErrKeysetLag = errors.New("keyset view may be behind")

// KeysetChange is a signed change of a keyset state.
type KeysetChange struct {
	Action     string            `json:"action"`
	Shard      string            `json:"shard"`
	Generation int               `json:"generation"`
	Address    string            `json:"address,omitempty"`   // register-candidate
	Successor  int               `json:"successor,omitempty"` // start-draining, mark-compromised
	Caps       map[string]string `json:"caps,omitempty"`      // asset -> most the drains may move in all, base units; with Successor, and set-drain-caps
	// KeyRef and PublicKey (register-candidate, together or not at all) tell the zone how to sign with the generation: the reference of the key in
	// its signer (an MPC keyset ID, or an HSM key's CKA_ID in hex) and the 65-byte uncompressed secp256k1 public key in hex, which must hash to Address.
	KeyRef    string `json:"key_ref,omitempty"`
	PublicKey string `json:"public_key,omitempty"`
	// Window (start-draining of a deposit tree, seconds, optional) is how long after this record the generation's deposit addresses
	// stay swept before it may retire: a retire record of a deposit tree is valid only when its signing time is at least that much later. Zero: no window.
	Window   int64 `json:"window_seconds,omitempty"`
	Seq      int64 `json:"seq"`       // must be higher than the current one
	SignedAt int64 `json:"signed_at"` // unix seconds
	// Signatures of the operators over KeysetChangeMessage.
	Signatures []OperatorSignature `json:"signatures"`
}

// KeysetChangeMessage is what the operators sign: a domain prefix and the change without its signatures, as JSON of a fixed field order (map keys are
// sorted by encoding/json).
func KeysetChangeMessage(c KeysetChange) []byte {
	body, _ := json.Marshal(struct {
		Action     string            `json:"action"`
		Shard      string            `json:"shard"`
		Generation int               `json:"generation"`
		Address    string            `json:"address,omitempty"`
		Successor  int               `json:"successor,omitempty"`
		Caps       map[string]string `json:"caps,omitempty"`
		KeyRef     string            `json:"key_ref,omitempty"`
		PublicKey  string            `json:"public_key,omitempty"`
		Seq        int64             `json:"seq"`
		SignedAt   int64             `json:"signed_at"`
	}{c.Action, c.Shard, c.Generation, c.Address, c.Successor, c.Caps, c.KeyRef, c.PublicKey, c.Seq, c.SignedAt})
	return append([]byte("qv-keyset-change-v1\n"), body...)
}

// SignKeysetChange adds one operator's signature to c (whose Signatures it replaces).
func SignKeysetChange(priv ed25519.PrivateKey, operator string, c KeysetChange) KeysetChange {
	c.Signatures = []OperatorSignature{{Operator: operator, Signature: hex.EncodeToString(ed25519.Sign(priv, KeysetChangeMessage(c)))}}
	return c
}

// MergeKeysetChanges joins the signatures of several operators over the same change.
func MergeKeysetChanges(parts ...KeysetChange) (KeysetChange, error) {
	if len(parts) == 0 {
		return KeysetChange{}, errors.New("no signatures")
	}
	out := parts[0]
	out.Signatures = slices.Clone(parts[0].Signatures)
	for _, p := range parts[1:] {
		if !bytes.Equal(KeysetChangeMessage(p), KeysetChangeMessage(out)) {
			return KeysetChange{}, errors.New("the signatures are over different changes (action, shard, generation, address, key, successor, caps, seq or time differ)")
		}
		out.Signatures = append(out.Signatures, p.Signatures...)
	}
	return out, nil
}

// shape checks what no state is needed for.
func (c KeysetChange) shape() error {
	if c.Seq < 1 {
		return errors.New("a change has a sequence number of at least 1")
	}
	tree := partition.ShardID(c.Shard).IsDepositTree()
	if !tree {
		if _, err := partition.ParseShardID(c.Shard); err != nil {
			return err
		}
	}
	if c.Generation < 1 {
		return errors.New("a change names a generation of at least 1")
	}
	if c.Window < 0 || (c.Window > 0 && !(tree && c.Action == KeysetStartDraining)) {
		return errors.New("window_seconds is for the start-draining of a deposit tree, and not negative")
	}
	switch c.Action {
	case KeysetRegisterCandidate:
		if tree {
			// A deposit tree has no address: the record carries the keyset to sign with (key_ref) and the public identity addresses derive from
			// (public_key: the account xpub on Bitcoin, "<node key hex>:<chain code hex>" on Solana), which apply checks against the chain.
			if c.Address != "" || c.Successor != 0 || len(c.Caps) != 0 || c.KeyRef == "" || c.PublicKey == "" {
				return errors.New("register-candidate of a deposit tree carries its key reference and public key, and no address, successor or caps")
			}
			break
		}
		if c.Address == "" || c.Successor != 0 || len(c.Caps) != 0 {
			return errors.New("register-candidate carries the address (and its key reference and public key), and no successor or caps")
		}
		if common.IsHexAddress(c.Address) {
			if err := c.checkKey(); err != nil {
				return err
			}
		} else if err := c.checkEdKey(); err != nil {
			return err
		}
	case KeysetActivate, KeysetRetire:
		if c.Address != "" || c.Successor != 0 || len(c.Caps) != 0 || c.KeyRef != "" || c.PublicKey != "" {
			return fmt.Errorf("%s carries only the shard and the generation", c.Action)
		}
	case KeysetSetDrainCaps:
		if c.Address != "" || c.Successor != 0 || len(c.Caps) == 0 || c.KeyRef != "" || c.PublicKey != "" {
			return errors.New("set-drain-caps carries the shard, the generation and the new caps per asset, nothing else")
		}
	case KeysetStartDraining:
		if c.Address != "" || c.Successor < 1 || (len(c.Caps) == 0 && !tree) || c.KeyRef != "" || c.PublicKey != "" {
			return errors.New("start-draining names the successor generation and the drain caps per asset, and no address")
		}
	case KeysetMarkCompromised:
		if c.Address != "" || ((c.Successor > 0) != (len(c.Caps) > 0) && !(tree && c.Successor > 0)) || c.KeyRef != "" || c.PublicKey != "" {
			return errors.New("mark-compromised names a successor generation together with its drain caps, or neither, and no address")
		}
	default:
		return fmt.Errorf("action %q is none of %s, %s, %s, %s, %s, %s", c.Action, KeysetRegisterCandidate, KeysetActivate, KeysetStartDraining, KeysetRetire, KeysetMarkCompromised, KeysetSetDrainCaps)
	}
	return nil
}

// checkKey checks the key reference and public key of a register-candidate: both or neither, and the public key hashes to the address.
func (c KeysetChange) checkKey() error {
	if c.KeyRef == "" && c.PublicKey == "" {
		return nil
	}
	if c.KeyRef == "" || c.PublicKey == "" {
		return errors.New("a candidate's key reference and public key come together")
	}
	raw, err := hex.DecodeString(c.PublicKey)
	if err != nil || len(raw) != 65 || raw[0] != 4 {
		return errors.New("public_key is the 65-byte uncompressed secp256k1 key in hex")
	}
	pub, err := crypto.UnmarshalPubkey(raw)
	if err != nil {
		return fmt.Errorf("public_key is not a secp256k1 point: %w", err)
	}
	if !common.IsHexAddress(c.Address) || crypto.PubkeyToAddress(*pub) != common.HexToAddress(c.Address) {
		return fmt.Errorf("the public key is the key of %s, not of %s", crypto.PubkeyToAddress(*pub).Hex(), c.Address)
	}
	return nil
}

// checkEdKey is checkKey for a Solana hot shard: the address is base58 of 32 bytes, and the public key (32 bytes of hex) is those same bytes.
func (c KeysetChange) checkEdKey() error {
	raw, err := sol.ParseAddress(c.Address)
	if err != nil || raw == ([32]byte{}) {
		return fmt.Errorf("%q is neither an EVM address nor a Solana address: %v", c.Address, err)
	}
	if c.KeyRef == "" && c.PublicKey == "" {
		return nil
	}
	if c.KeyRef == "" || c.PublicKey == "" {
		return errors.New("a candidate's key reference and public key come together")
	}
	pub, err := hex.DecodeString(c.PublicKey)
	if err != nil || len(pub) != 32 {
		return errors.New("public_key of a Solana hot shard is the 32-byte Ed25519 key in hex")
	}
	if !bytes.Equal(pub, raw[:]) {
		return fmt.Errorf("the public key is the key of %s, not of %s", sol.Address([32]byte(pub)), c.Address)
	}
	return nil
}

// ---- the effective view ----

// KeysetEntry is one generation of a shard's key as the zone sees it.
type KeysetEntry struct {
	Shard      partition.ShardID
	Chain      string // the config's chain name
	Generation int
	Address    string // EIP-55
	State      string
	// Successor is the generation a drain from this one pays (0: none named). Caps is the most all drains of an asset from this address may move.
	Successor int
	Caps      map[string]*big.Int
	// KeyRef and PublicKey say how to sign with this generation (empty for generation 1, which the signers section of the config pins, and for a
	// candidate registered without them: it can receive, but the zone cannot sign from it).
	KeyRef    string
	PublicKey string
	// RetireAfter (deposit trees, unix seconds): a retire record must be signed at or after it (the draining record's signing time plus its window).
	RetireAfter int64
}

func (e *KeysetEntry) clone() *KeysetEntry {
	c := *e
	c.Caps = maps.Clone(e.Caps)
	return &c
}

// KeysetView is the keysets in force at one moment: the config's pinned hot addresses as generation 1, with the verified change log applied.
type KeysetView struct {
	// Seq is the sequence number of the last change applied (0: none, the config alone).
	Seq int64
	// Ignored counts the rows of the log that did not verify (signatures, order, content) and were skipped.
	Ignored int

	gens    map[partition.ShardID]map[int]*KeysetEntry
	applied map[int64][]byte
}

func (v *KeysetView) clone() *KeysetView {
	n := &KeysetView{Seq: v.Seq, Ignored: v.Ignored, gens: map[partition.ShardID]map[int]*KeysetEntry{}, applied: maps.Clone(v.applied)}
	for s, g := range v.gens {
		m := map[int]*KeysetEntry{}
		for k, e := range g {
			m[k] = e.clone()
		}
		n.gens[s] = m
	}
	return n
}

// checkShardAddresses refuses a config in which the partitions of one shard name different hot addresses: a shard has one key. Partitions whose ID is
// not a hot partition ID are not shards of the registry and are skipped.
func checkShardAddresses(chainName string, hot map[string]common.Address) error {
	seen := map[partition.ShardID]common.Address{}
	for p, a := range hot {
		k, err := partition.Parse(p)
		if err != nil || k.Tier != partition.TierHot {
			continue
		}
		if prev, ok := seen[k.ShardID()]; ok && prev != a {
			return fmt.Errorf("gateway: config: chain %q: the partitions of shard %s name two hot addresses, %s and %s", chainName, k.ShardID(), prev.Hex(), a.Hex())
		}
		seen[k.ShardID()] = a
	}
	return nil
}

// StaticKeysets is the view of the config file alone: generation 1, active, of every hot shard of an EVM chain.
func (c *Config) StaticKeysets() *KeysetView {
	v := &KeysetView{gens: map[partition.ShardID]map[int]*KeysetEntry{}, applied: map[int64][]byte{}}
	for name, cc := range c.Chains {
		// The deposit key tree of a Bitcoin or Solana chain: generation 1 is the key the config pins.
		if id, ok := cc.depositTreeID(name); ok {
			v.gens[id] = map[int]*KeysetEntry{1: {Shard: id, Chain: name, Generation: 1, State: partition.StateActive}}
		}
		if cc.Family == FamilySOL {
			// A Solana hot shard is a shard of the registry like an EVM one: generation 1 is the address the config pins, in the canonical base58 form.
			for p, a := range cc.SOL.HotShards {
				k, err := partition.Parse(p)
				if err != nil || k.Tier != partition.TierHot {
					continue
				}
				raw, err := sol.ParseAddress(a)
				if err != nil {
					continue // the verifier refused it at load
				}
				if _, ok := v.gens[k.ShardID()]; !ok {
					v.gens[k.ShardID()] = map[int]*KeysetEntry{1: {Shard: k.ShardID(), Chain: name, Generation: 1, Address: sol.Address(raw), State: partition.StateActive}}
				}
			}
			continue
		}
		if cc.Family != FamilyEVM {
			continue
		}
		for p, a := range cc.EVM.HotAddresses {
			k, err := partition.Parse(p)
			if err != nil || k.Tier != partition.TierHot {
				continue
			}
			s := k.ShardID()
			if _, ok := v.gens[s]; !ok {
				v.gens[s] = map[int]*KeysetEntry{1: {Shard: s, Chain: name, Generation: 1, Address: a.Hex(), State: partition.StateActive}}
			}
		}
	}
	return v
}

// depositTreeID is the registry ID of the deposit key tree of a Bitcoin or Solana chain: the entity comes from the chain's pinned hot partitions.
func (cc *ChainConfig) depositTreeID(name string) (partition.ShardID, bool) {
	var parts []string
	switch cc.Family {
	case FamilyBTC:
		for p := range cc.BTC.HotShards {
			parts = append(parts, p)
		}
	case FamilySOL:
		for p := range cc.SOL.HotShards {
			parts = append(parts, p)
		}
	default:
		return "", false
	}
	slices.Sort(parts)
	for _, p := range parts {
		if k, err := partition.Parse(p); err == nil && k.Tier == partition.TierHot {
			if id, err := partition.DepositTreeID(k.Entity, name); err == nil {
				return id, true
			}
		}
	}
	return "", false
}

// tree returns the generations of the deposit key tree of a chain (nil: the chain has none), by number.
func (v *KeysetView) tree(chainName string) map[int]*KeysetEntry {
	for id, g := range v.gens {
		if id.IsDepositTree() && g[1] != nil && g[1].Chain == chainName {
			return g
		}
	}
	return nil
}

// Generations lists the generations of a shard, oldest first (nil for a shard the view does not know).
func (v *KeysetView) Generations(shard partition.ShardID) []*KeysetEntry {
	var out []*KeysetEntry
	for _, e := range v.gens[shard] {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Generation < out[j].Generation })
	return out
}

// Shards lists the shards the view knows.
func (v *KeysetView) Shards() []partition.ShardID {
	var out []partition.ShardID
	for s := range v.gens {
		out = append(out, s)
	}
	slices.Sort(out)
	return out
}

func (v *KeysetView) entry(shard partition.ShardID, gen int) *KeysetEntry { return v.gens[shard][gen] }

func (v *KeysetView) active(shard partition.ShardID) *KeysetEntry {
	for _, e := range v.gens[shard] {
		if e.State == partition.StateActive {
			return e
		}
	}
	return nil
}

func (v *KeysetView) byAddress(shard partition.ShardID, addr string) *KeysetEntry {
	for _, e := range v.gens[shard] {
		if e.Address == addr {
			return e
		}
	}
	return nil
}

// notActive reports whether addr is the address of a generation of a shard of this chain and no generation of any shard has it as an active address.
func (v *KeysetView) notActive(chainName, addr string) (state string, bad bool) {
	for _, g := range v.gens {
		for _, e := range g {
			if e.Chain != chainName || e.Address != addr {
				continue
			}
			if e.State == partition.StateActive {
				return "", false
			}
			state, bad = e.State, true
		}
	}
	return state, bad
}

// addressUsed reports whether any generation of any shard of the chain has the address.
func (v *KeysetView) addressUsed(chainName, addr string) bool {
	for _, g := range v.gens {
		for _, e := range g {
			if e.Chain == chainName && e.Address == addr {
				return true
			}
		}
	}
	return false
}

// shardOf returns the shard a partition belongs to when the view manages it (a well-formed hot partition ID of a known shard).
func (v *KeysetView) shardOf(partitionID string) (partition.ShardID, bool) {
	k, err := partition.Parse(partitionID)
	if err != nil || k.Tier != partition.TierHot {
		return "", false
	}
	_, ok := v.gens[k.ShardID()]
	return k.ShardID(), ok
}

// hotView is what the EVM verifier and codec need for one decision: per partition of the chain the addresses that may send (every generation) and the
// active address (the destinations a rebalance may pay), and every address that is a hot address of the zone.
func (v *KeysetView) hotView(cc *ChainConfig) (active map[string]common.Address, senders map[string][]common.Address, owned map[common.Address]bool) {
	active, senders, owned = map[string]common.Address{}, map[string][]common.Address{}, map[common.Address]bool{}
	for p, a := range cc.EVM.HotAddresses {
		owned[a] = true
		shard, ok := v.shardOf(p)
		if !ok {
			active[p] = a
			continue
		}
		for _, e := range v.Generations(shard) {
			ad := common.HexToAddress(e.Address)
			senders[p] = append(senders[p], ad)
			owned[ad] = true
		}
		if e := v.active(shard); e != nil {
			active[p] = common.HexToAddress(e.Address)
		}
	}
	return active, senders, owned
}

// capsOf validates the caps of a change against the chain's assets.
func capsOf(cc *ChainConfig, in map[string]string) (map[string]*big.Int, error) {
	out := map[string]*big.Int{}
	for asset, s := range in {
		if _, ok := cc.Assets[asset]; !ok {
			return nil, fmt.Errorf("cap for %q: no such asset on chain %q", asset, cc.Name)
		}
		n, err := amount("cap "+asset, s)
		if err != nil || n.Sign() == 0 {
			return nil, fmt.Errorf("cap for %q is %q: want a canonical positive decimal in base units", asset, s)
		}
		out[asset] = n
	}
	return out, nil
}

// apply puts one change into the view, or says why it does not fit. The same rules hold when a change is applied and when the log is read back; a
// change that breaks them is refused at the first and ignored at the second. A refused change leaves the view as it was.
//
// fresh is true when the change is being applied now and false when it is read back from the log. The sweep destination is checked only when fresh: after
// a replacement the operators set the config's sweep_destination to the new generation's address (the runbook's manual edit), and the record that
// registered that very address must keep holding.
func (v *KeysetView) apply(cfg *Config, c KeysetChange, fresh bool) error {
	if err := c.shape(); err != nil {
		return err
	}
	shard := partition.ShardID(c.Shard)
	if _, ok := v.gens[shard]; !ok {
		return fmt.Errorf("shard %q is not a hot shard of an EVM chain, or the deposit tree of a Bitcoin or Solana chain, in this zone's config", c.Shard)
	}
	next := v.clone()
	gens := next.gens[shard]
	cur := gens[c.Generation]
	cc := cfg.Chains[gens[1].Chain]
	illegal := func(want string) error {
		if cur == nil {
			return fmt.Errorf("%w: %s generation %d does not exist", partition.ErrKeysetNotFound, c.Shard, c.Generation)
		}
		return fmt.Errorf("%w: %s generation %d is %s, %s needs %s", partition.ErrIllegalTransition, c.Shard, c.Generation, cur.State, c.Action, want)
	}
	// successor checks the generation a drain will pay.
	successor := func() error {
		s := gens[c.Successor]
		switch {
		case s == nil:
			return fmt.Errorf("successor generation %d of %s does not exist", c.Successor, c.Shard)
		case c.Successor <= c.Generation:
			return fmt.Errorf("the successor generation %d is not higher than %d", c.Successor, c.Generation)
		case s.State != partition.StateCandidate && s.State != partition.StateActive:
			return fmt.Errorf("the successor generation %d is %s: it must be a candidate or active", c.Successor, s.State)
		}
		caps, err := capsOf(cc, c.Caps)
		if err != nil {
			return err
		}
		if shard.IsDepositTree() {
			// Bitcoin drains the hot shard of the generation (its coins move to the successor's), so it names the cap; Solana moves no hot shard here.
			if (cc.Family == FamilyBTC) != (len(caps) > 0) {
				return fmt.Errorf("a %s deposit tree's drain caps are %s", cc.Family, map[bool]string{true: "required (the hot shard of the generation drains)", false: "none (only sweeps move)"}[cc.Family == FamilyBTC])
			}
		}
		cur.Successor, cur.Caps = c.Successor, caps
		return nil
	}
	switch c.Action {
	case KeysetRegisterCandidate:
		if shard.IsDepositTree() {
			top := 0
			for g := range gens {
				top = max(top, g)
			}
			if c.Generation != top+1 {
				return fmt.Errorf("the next generation of %s is %d, not %d", c.Shard, top+1, c.Generation)
			}
			if err := checkTreeIdentity(cc, c.PublicKey); err != nil {
				return err
			}
			for _, e := range gens {
				if e.PublicKey == c.PublicKey || e.KeyRef == c.KeyRef {
					return fmt.Errorf("generation %d of %s already has that key", e.Generation, c.Shard)
				}
			}
			if first := cc.treeIdentity(); first == c.PublicKey {
				return fmt.Errorf("that key is the one the config pins as generation 1")
			}
			gens[c.Generation] = &KeysetEntry{Shard: shard, Chain: cc.Name, Generation: c.Generation, State: partition.StateCandidate, KeyRef: c.KeyRef, PublicKey: c.PublicKey}
			break
		}
		if cc.Family == FamilySOL {
			raw, err := sol.ParseAddress(c.Address)
			if err != nil || raw == ([32]byte{}) {
				return fmt.Errorf("%q is not a Solana address", c.Address)
			}
			addr := sol.Address(raw)
			top := 0
			for g := range gens {
				top = max(top, g)
			}
			switch {
			case c.Generation != top+1:
				return fmt.Errorf("the next generation of %s is %d, not %d", c.Shard, top+1, c.Generation)
			case next.addressUsed(cc.Name, addr):
				return fmt.Errorf("address %s is already a generation of a shard of %s", addr, cc.Name)
			}
			for pool, cold := range cc.SOL.ColdAddresses {
				if c, err := sol.ParseAddress(cold); err == nil && c == raw {
					return fmt.Errorf("address %s is the cold address of pool %q", addr, pool)
				}
			}
			gens[c.Generation] = &KeysetEntry{Shard: shard, Chain: cc.Name, Generation: c.Generation, Address: addr, State: partition.StateCandidate,
				KeyRef: c.KeyRef, PublicKey: c.PublicKey}
			break
		}
		if !common.IsHexAddress(c.Address) || common.HexToAddress(c.Address) == (common.Address{}) {
			return fmt.Errorf("%q is not an address", c.Address)
		}
		addr := common.HexToAddress(c.Address)
		top := 0
		for g := range gens {
			top = max(top, g)
		}
		switch {
		case c.Generation != top+1:
			return fmt.Errorf("the next generation of %s is %d, not %d", c.Shard, top+1, c.Generation)
		case next.addressUsed(cc.Name, addr.Hex()):
			return fmt.Errorf("address %s is already a generation of a shard of %s", addr.Hex(), cc.Name)
		case addr == cc.EVM.Factory || (fresh && addr == cc.EVM.SweepDestination):
			return fmt.Errorf("address %s is the factory or the sweep destination", addr.Hex())
		}
		for k, cold := range cc.EVM.ColdAddresses {
			if cold == addr {
				return fmt.Errorf("address %s is the cold address %q", addr.Hex(), k)
			}
		}
		gens[c.Generation] = &KeysetEntry{Shard: shard, Chain: cc.Name, Generation: c.Generation, Address: addr.Hex(), State: partition.StateCandidate,
			KeyRef: c.KeyRef, PublicKey: c.PublicKey}
	case KeysetActivate:
		if cur == nil || cur.State != partition.StateCandidate {
			return illegal(partition.StateCandidate)
		}
		if a := next.active(shard); a != nil {
			return fmt.Errorf("%w: %s generation %d is active", partition.ErrActiveExists, c.Shard, a.Generation)
		}
		cur.State = partition.StateActive
	case KeysetStartDraining:
		if cur == nil || cur.State != partition.StateActive {
			return illegal(partition.StateActive)
		}
		for _, e := range gens {
			if e.Successor == c.Generation && (e.State == partition.StateDraining || e.State == partition.StateCompromised) {
				return fmt.Errorf("generation %d of %s still has to drain into generation %d, which cannot leave active before it is retired", e.Generation, c.Shard, c.Generation)
			}
		}
		if err := successor(); err != nil {
			return err
		}
		cur.State = partition.StateDraining
		if shard.IsDepositTree() {
			cur.RetireAfter = c.SignedAt + c.Window
		}
	case KeysetRetire:
		if cur == nil || cur.State != partition.StateDraining {
			return illegal(partition.StateDraining)
		}
		if shard.IsDepositTree() && c.SignedAt < cur.RetireAfter {
			return fmt.Errorf("the deposit addresses of %s generation %d stay swept until %s (the window of its signed draining record); this record is signed earlier",
				c.Shard, c.Generation, time.Unix(cur.RetireAfter, 0).UTC().Format(time.RFC3339))
		}
		cur.State = partition.StateRetired
	case KeysetSetDrainCaps:
		if cur == nil || (cur.State != partition.StateDraining && cur.State != partition.StateCompromised) || cur.Successor == 0 {
			return fmt.Errorf("%w: %s generation %d must be draining or compromised with a successor to have its drain caps set", partition.ErrIllegalTransition, c.Shard, c.Generation)
		}
		caps, err := capsOf(cc, c.Caps)
		if err != nil {
			return err
		}
		merged := maps.Clone(cur.Caps)
		if merged == nil {
			merged = map[string]*big.Int{}
		}
		for a, n := range caps {
			merged[a] = n
		}
		cur.Caps = merged
	case KeysetMarkCompromised:
		if cur == nil || (cur.State != partition.StateCandidate && cur.State != partition.StateActive && cur.State != partition.StateDraining) {
			return illegal(partition.StateCandidate + ", " + partition.StateActive + " or " + partition.StateDraining)
		}
		if c.Successor > 0 {
			if cur.Successor != 0 {
				return fmt.Errorf("generation %d of %s already has the successor %d: it is named once", c.Generation, c.Shard, cur.Successor)
			}
			if err := successor(); err != nil {
				return err
			}
		}
		cur.State = partition.StateCompromised
	}
	next.Seq = c.Seq
	next.applied[c.Seq] = KeysetChangeMessage(c)
	*v = *next
	return nil
}

// foldKeysets is the effective view: the config's with every row of the log that verifies applied in sequence order. A row is ignored (and counted)
// when its signatures do not satisfy the operators of the config, its sequence number is not higher than the last one applied, or its content breaks
// the state machine.
func (c *Config) foldKeysets(rows []KeysetChange) *KeysetView {
	v := c.StaticKeysets()
	for _, r := range rows {
		if _, err := c.Operators.verifyMsg(KeysetChangeMessage(r), r.Signatures); err != nil || r.Seq <= v.Seq {
			v.Ignored++
			continue
		}
		if err := v.apply(c, r, false); err != nil {
			v.Ignored++
		}
	}
	return v
}

// ---- storage ----

// loadKeysetRows reads the whole log, oldest first.
func loadKeysetRows(ctx context.Context, q queryer) ([]KeysetChange, error) {
	rows, err := q.Query(ctx, `SELECT seq, action, shard, generation, address, successor, caps, signed_at, signatures, key_ref, public_key, window_seconds FROM keyset_changes ORDER BY seq, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []KeysetChange
	for rows.Next() {
		var c KeysetChange
		var caps, sigs []byte
		if err := rows.Scan(&c.Seq, &c.Action, &c.Shard, &c.Generation, &c.Address, &c.Successor, &caps, &c.SignedAt, &sigs, &c.KeyRef, &c.PublicKey, &c.Window); err != nil {
			return nil, err
		}
		// A row that does not parse stays in the list as a change nothing can verify, so it is counted.
		if len(caps) > 0 && json.Unmarshal(caps, &c.Caps) != nil {
			c.Action = "unreadable"
		}
		if json.Unmarshal(sigs, &c.Signatures) != nil {
			c.Signatures = nil
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// EffectiveKeysets reads the guard database's log and returns the view in force. Without an operators section the config's view is the whole view and
// the database is not read. An error is an outage: the caller retries.
func (g *Guard) EffectiveKeysets(ctx context.Context, cfg *Config) (*KeysetView, error) {
	if cfg.Operators == nil || g == nil {
		return cfg.StaticKeysets(), nil
	}
	rows, err := loadKeysetRows(ctx, g.pool)
	if err != nil {
		return nil, fmt.Errorf("gateway: read keyset changes: %w", err)
	}
	v := cfg.foldKeysets(rows)
	if v.Ignored > 0 && g.keysetIgnored.Swap(int64(v.Ignored)) != int64(v.Ignored) {
		slog.Error("ALERT keyset registry: rows of the keyset_changes table do not carry valid operator signatures (or do not fit) and are ignored", "rows", v.Ignored)
	}
	return v, nil
}

// ApplyKeysetChange checks a signed change and records it, with its audit event, in one transaction. A change signed by too few operators (or by one
// operator twice, or by approvers), stale, not newer than the log, or one the state machine does not allow is refused and nothing changes. The same
// change applied twice is not an error (so an operator can finish applying it to the other databases). actor names the zone process in the audit
// event (gateway, cosigner).
func (g *Guard) ApplyKeysetChange(ctx context.Context, cfg *Config, c KeysetChange, now time.Time, actor string) error {
	refuse := func(err error) error { return fmt.Errorf("gateway: keyset change refused: %w", err) }
	if err := c.shape(); err != nil {
		return refuse(err)
	}
	operators, err := cfg.Operators.verifyMsg(KeysetChangeMessage(c), c.Signatures)
	if err != nil {
		return refuse(err)
	}
	if age := now.Sub(time.Unix(c.SignedAt, 0)); age > cfg.Operators.MaxAge || age < -cfg.Operators.MaxAge {
		return refuse(fmt.Errorf("signed %s from now, the limit is %s", age.Round(time.Second), cfg.Operators.MaxAge))
	}
	tx, err := g.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('qv-keyset-registry'))`); err != nil {
		return err
	}
	rows, err := loadKeysetRows(ctx, tx)
	if err != nil {
		return err
	}
	cur := cfg.foldKeysets(rows)
	if msg, done := cur.applied[c.Seq]; done && bytes.Equal(msg, KeysetChangeMessage(c)) {
		return nil // already applied
	}
	if c.Seq <= cur.Seq {
		return refuse(fmt.Errorf("sequence %d is not higher than the current %d", c.Seq, cur.Seq))
	}
	next := cur.clone()
	if err := next.apply(cfg, c, true); err != nil {
		return refuse(err)
	}
	sigs, _ := json.Marshal(c.Signatures)
	var caps []byte
	if len(c.Caps) > 0 {
		caps, _ = json.Marshal(c.Caps)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO keyset_changes (seq, action, shard, generation, address, successor, caps, signed_at, signatures, key_ref, public_key, window_seconds) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		c.Seq, c.Action, c.Shard, c.Generation, c.Address, c.Successor, caps, c.SignedAt, sigs, c.KeyRef, c.PublicKey, c.Window); err != nil {
		return err
	}
	payload := map[string]any{"action": c.Action, "shard": c.Shard, "generation": c.Generation, "seq": c.Seq, "operators": operators, "signed_at": c.SignedAt,
		"state_after": next.entry(partition.ShardID(c.Shard), c.Generation).State}
	if c.Address != "" {
		payload["address"] = next.entry(partition.ShardID(c.Shard), c.Generation).Address
	}
	if c.Successor > 0 {
		payload["successor"], payload["caps"] = c.Successor, c.Caps
	}
	if c.Action == KeysetSetDrainCaps {
		payload["caps"] = c.Caps
	}
	if c.KeyRef != "" {
		payload["key_ref"], payload["public_key"] = c.KeyRef, c.PublicKey
	}
	if c.Window > 0 {
		payload["window_seconds"] = c.Window
	}
	pj, _ := json.Marshal(payload)
	if _, err := audit.AppendTx(ctx, tx, domain.AuditEvent{Actor: actor, Type: EventKeysetChanged, Payload: pj}, ""); err != nil {
		return fmt.Errorf("gateway: audit %s: %w", EventKeysetChanged, err)
	}
	return tx.Commit(ctx)
}

// ---- use in a decision ----

// keysetView is the view in force for the decision about to be made: read from the guard database at every decision, so a signed change applies to
// the next one without a restart. Only an EVM chain has one.
func (d *Decider) keysetView(ctx context.Context) (*KeysetView, error) {
	return d.guard.EffectiveKeysets(ctx, d.cfg)
}

// overlay returns the codec that judges by this view: every generation of a shard may send, only an active one is a destination.
func (c *EVMCodec) overlay(v *KeysetView, cc *ChainConfig) *EVMCodec {
	active, senders, owned := v.hotView(cc)
	return &EVMCodec{Verifier: c.Verifier.WithHot(active, senders), hot: owned}
}

// keysetLag turns a state that does not hold here yet, but may on the other side, into a retry until the intent's not_after, with an ALERT.
func (d *Decider) keysetLag(i signjob.Intent, now time.Time, format string, args ...any) error {
	why := fmt.Sprintf(format, args...)
	if i.NotAfter <= now.Unix() {
		return reject(ReasonKeyset, "%s, and the intent has expired", why)
	}
	slog.Error("ALERT keyset registry: a drain waits because the keyset state it needs does not hold in this zone yet; apply the same signed keyset changes to the gateway and every cosigner (docs/runbooks/key-replacement.md)",
		"intent", i.ID, "mode", d.mode.actor(), "waiting_for", why)
	return fmt.Errorf("%w: %s: %s", ErrKeysetLag, KeysetLagNote, why)
}

// keysetRules is the state rule of one EVM job, run inside the guard transaction: what the sender's generation may sign, and the drain itself. kv is
// nil for a chain without keysets.
func (d *Decider) keysetRules(ctx context.Context, gt *GuardTx, kv *KeysetView, cc *ChainConfig, i signjob.Intent, info TxInfo, amount *big.Int, known bool, now time.Time) error {
	switch cc.Family {
	case FamilyBTC:
		return d.btcGenRules(ctx, gt, kv, cc, i, info, amount, known, now)
	case FamilySOL:
		return d.solGenRules(ctx, gt, kv, cc, i, info, amount, known, now)
	}
	if kv == nil {
		if i.Kind == signjob.KindDrain {
			return reject(ReasonKeyset, "chain %q has no keysets: a drain is for EVM hot shards", i.Chain)
		}
		return nil
	}
	if i.Kind == "sweep" {
		if st, bad := kv.notActive(cc.Name, cc.EVM.SweepDestination.Hex()); bad {
			return reject(ReasonKeyset, "the sweep destination %s is the address of a %s generation: forwarders may only pay an active one", cc.EVM.SweepDestination.Hex(), st)
		}
	}
	shard, managed := kv.shardOf(i.PartitionID)
	if i.Kind == signjob.KindDrain {
		if !managed {
			return reject(ReasonKeyset, "partition %q is not a hot shard with keysets: nothing to drain", i.PartitionID)
		}
		return d.drainRule(ctx, gt, kv, cc, shard, i, info, amount, known, now)
	}
	if !managed {
		return nil
	}
	e := kv.byAddress(shard, info.Sender)
	if e == nil {
		return reject(ReasonKeyset, "%s is no generation of %s", info.Sender, shard)
	}
	switch e.State {
	case partition.StateActive:
		return nil
	case partition.StateCandidate:
		return reject(ReasonKeyset, "generation %d of %s is a candidate: it signs nothing until it is activated", e.Generation, shard)
	case partition.StateDraining:
		if i.Kind == "cancel" || known {
			return nil // finishing work already signed: the cancel of a nonce, the replacement of an intent this key signed
		}
		return reject(ReasonKeyset, "generation %d of %s is draining: it signs only a drain to its successor, and the replacement or cancel of work already signed", e.Generation, shard)
	}
	return reject(ReasonKeyset, "generation %d of %s is %s: it signs nothing", e.Generation, shard, e.State)
}

// pendingSince is how far back a reserved, unsigned drain still counts as in progress: the gateway's sign timeout (after that the signer has given up or
// a cosigner refused). The cosigner never sees a signature, so every drain it authorised counts.
func (d *Decider) pendingSince(now time.Time) time.Time {
	if d.mode == ModeCosigner {
		return time.Time{}
	}
	return now.Add(-d.cfg.SignTimeout)
}

// noteDrainRefusal counts a refused drain and raises an ALERT, so a storm of refusals (a broken planner, or the business zone probing) is visible although
// refusals use up neither the rate nor the cap.
func (d *Decider) noteDrainRefusal(job signjob.Job, reason string) {
	i, err := parseIntent(job)
	if err != nil || i.Kind != signjob.KindDrain {
		return
	}
	n := d.guard.drainRefused.Add(1)
	d.noteDrainMetric(i.Chain, reason)
	slog.Error("ALERT drain refused: the zone refused a drain; refusals do not count against the drain rate or cap, so a repeating one is a stuck planner or an attack by the business zone",
		"intent", i.ID, "mode", d.mode.actor(), "source", i.From, "asset", i.Asset, "refused_total", n, "reason", reason)
}

// DrainRefusals is the number of drains this process refused since it started (the alert's counter).
func (g *Guard) DrainRefusals() int64 { return g.drainRefused.Load() }

// drainRule judges a drain by this zone's own view: nothing the intent says about states is believed.
func (d *Decider) drainRule(ctx context.Context, gt *GuardTx, kv *KeysetView, cc *ChainConfig, shard partition.ShardID, i signjob.Intent, info TxInfo, amount *big.Int, known bool, now time.Time) error {
	canon := func(a string) (string, error) { return (&EVMCodec{}).Canonical(a) }
	if cc.Family == FamilySOL {
		canon = func(a string) (string, error) { raw, err := sol.ParseAddress(a); return sol.Address(raw), err }
	}
	if d.cfg.Operators == nil {
		return reject(ReasonKeyset, "this zone's config has no operators section: keyset states, and so drains, are off")
	}
	if !known { // a drain's wait for the other side ends at its not_after, so it needs one
		switch n := now.Unix(); {
		case i.NotAfter == 0:
			return reject(ReasonExpired, "intent has no not_after")
		case i.NotAfter <= n:
			return reject(ReasonExpired, "intent expired at %d, now %d", i.NotAfter, n)
		case i.NotAfter > n+int64(d.cfg.MaxIntentAge/time.Second):
			return reject(ReasonExpired, "not_after %d is more than %s ahead", i.NotAfter, d.cfg.MaxIntentAge)
		}
	}
	src := kv.byAddress(shard, info.Sender)
	if src == nil {
		return reject(ReasonKeyset, "%s is no generation of %s", info.Sender, shard)
	}
	switch src.State {
	case partition.StateDraining, partition.StateCompromised:
	case partition.StateActive, partition.StateCandidate:
		return d.keysetLag(i, now, "generation %d of %s is %s here, a drain needs it draining or compromised", src.Generation, shard, src.State)
	default:
		return reject(ReasonKeyset, "generation %d of %s is %s: nothing moves out of it", src.Generation, shard, src.State)
	}
	if src.Successor == 0 {
		return reject(ReasonKeyset, "generation %d of %s is %s with no successor named: there is nowhere to drain it", src.Generation, shard, src.State)
	}
	succ := kv.entry(shard, src.Successor)
	if succ == nil {
		return reject(ReasonKeyset, "successor generation %d of %s is unknown", src.Successor, shard)
	}
	switch succ.State {
	case partition.StateActive:
	case partition.StateCandidate:
		return d.keysetLag(i, now, "successor generation %d of %s is a candidate here, a drain needs it active", succ.Generation, shard)
	default:
		return reject(ReasonKeyset, "successor generation %d of %s is %s: a drain pays an active generation", succ.Generation, shard, succ.State)
	}
	dest, err := canon(i.To)
	if err != nil || dest != succ.Address {
		return reject(ReasonKeyset, "drain destination %s is not the successor %s (generation %d of %s)", i.To, succ.Address, succ.Generation, shard)
	}
	if info.Destination != succ.Address {
		return reject(ReasonKeyset, "the transaction pays %s, not the successor %s", info.Destination, succ.Address)
	}
	if known {
		return nil // a replacement of a drain already admitted: its rate and amount were counted then
	}
	return d.drainLimits(ctx, gt, cc, src, shard, info.Sender, i.Asset, amount, now)
}

// drainLimits is the rate and the cap of a new drain: the signed record's cap for the asset on the source, and the zone's drains per hour.
func (d *Decider) drainLimits(ctx context.Context, gt *GuardTx, cc *ChainConfig, src *KeysetEntry, shard partition.ShardID, sender, asset string, amount *big.Int, now time.Time) error {
	limit, ok := src.Caps[asset]
	if !ok {
		return reject(ReasonDrainCap, "the signed record names no cap for %s on generation %d of %s", asset, src.Generation, shard)
	}
	pending := d.pendingSince(now)
	// The gas of a drain. The cap counts value moved, not what each transaction costs the source in gas: many one-unit drains to the right successor
	// would burn its native balance (each costs up to the zone's fee cap) and strand its tokens. So the number of drains signed from one source in all is
	// bounded, planned or emergency, and each drain's fee is bounded by the fee cap, which makes the burn at most count times that cap. The bound is the
	// zone's own config (max_drains_per_source, default 40) and both the gateway and the cosigners read it, which is why it is not a field of the signed
	// record: a new field would change the signed message that deployed binaries verify. A drain moves one asset, so 40 is room for every asset, repeats and
	// retries, and far below what would drain the balance in gas.
	made, err := gt.SignedDrainCountFrom(ctx, sender, pending)
	if err != nil {
		return err
	}
	if made >= cc.maxDrainsPerSource() {
		return reject(ReasonDrainGas, "%d drains already signed from %s, the most the zone allows in all (max_drains_per_source %d): each costs gas, so more would burn the balance the drain is moving", made, sender, cc.maxDrainsPerSource())
	}
	// The hourly rate is for a planned drain: it slows a business zone that drains by many small steps. A compromised source is the emergency: the
	// operators' record names the successor and the cap together, which already bound where and how much, and a rate would only give the thief the time
	// the limit takes (keysets.go, "The emergency").
	if src.State != partition.StateCompromised {
		n, err := gt.SignedDrainsSince(ctx, now.Add(-time.Hour), pending)
		if err != nil {
			return err
		}
		if n >= cc.DrainsPerHour {
			return reject(ReasonDrainRate, "%d drains in the last hour, limit %d", n, cc.DrainsPerHour)
		}
	}
	sum, err := gt.SignedDrainAmountFrom(ctx, sender, asset, pending)
	if err != nil {
		return err
	}
	if total := new(big.Int).Add(sum, amount); total.Cmp(limit) > 0 {
		return reject(ReasonDrainCap, "%s already drained from %s plus %s exceeds the cap %s of the signed record", sum, sender, amount, limit)
	}
	return nil
}

// ---- deposit key trees (Bitcoin account key, Solana deposit node) ----

// checkTreeIdentity checks the public identity a register-candidate of a deposit tree carries against the chain: the account xpub of its network (Bitcoin),
// or "<node public key hex>:<chain code hex>" of a node the Ed25519 derivation accepts (Solana).
func checkTreeIdentity(cc *ChainConfig, identity string) error {
	switch cc.Family {
	case FamilyBTC:
		if _, err := btc.NewAccount(cc.BTC.Network, identity); err != nil {
			return fmt.Errorf("public_key of a Bitcoin deposit tree is the account xpub of %s: %w", cc.BTC.Network, err)
		}
		return nil
	case FamilySOL:
		n, err := ParseSolNode(identity)
		if err != nil {
			return err
		}
		if _, err := n.Derive(sol.BranchExternal, 0); err != nil {
			return fmt.Errorf("public_key of a Solana deposit tree is not a usable node: %w", err)
		}
		return nil
	}
	return fmt.Errorf("chain %q has no deposit tree", cc.Name)
}

// ParseSolNode reads the identity of a Solana deposit node: "<32-byte public key hex>:<32-byte chain code hex>".
func ParseSolNode(identity string) (sol.Node, error) {
	pub, cc, ok := strings.Cut(identity, ":")
	var n sol.Node
	if !ok {
		return n, errors.New("public_key of a Solana deposit tree is <32-byte node key hex>:<32-byte chain code hex>")
	}
	a, err1 := hex.DecodeString(pub)
	b, err2 := hex.DecodeString(cc)
	if err1 != nil || err2 != nil || len(a) != 32 || len(b) != 32 {
		return n, errors.New("public_key of a Solana deposit tree is <32-byte node key hex>:<32-byte chain code hex>")
	}
	copy(n.PublicKey[:], a)
	copy(n.ChainCode[:], b)
	return n, nil
}

// treeIdentity is the identity of the deposit tree the config pins (generation 1).
func (cc *ChainConfig) treeIdentity() string {
	switch cc.Family {
	case FamilyBTC:
		return cc.BTC.AccountXpub
	case FamilySOL:
		return hex.EncodeToString(cc.SOL.AccountPublicKey[:]) + ":" + hex.EncodeToString(cc.SOL.AccountChainCode[:])
	}
	return ""
}
