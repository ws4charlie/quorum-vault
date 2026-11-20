package btc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcd/chaincfg"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/partition"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// ErrRejected wraps every Verify rejection.
var ErrRejected = errors.New("btc: transaction does not match intent")

// HotShard is a pinned hot address of the signing zone and where it derives from.
type HotShard struct {
	Address string
	Path    []uint32 // [BranchHot, index]
}

// SigningConfig is everything the signing zone knows about a Bitcoin chain: no RPC, no database. It is the trust root of Verifier.
type SigningConfig struct {
	Chain       string
	Network     string
	AccountXpub string
	// HotShards maps a partition ID (entity/chain/BTC/hot/pool/shard) to its pinned hot address. Each must derive from AccountXpub at its
	// stated path. Every intent is bound to its own partition's shard.
	HotShards map[string]HotShard
	// ColdAddresses are the only addresses a hot-to-cold move may pay, by the pool of the partition: "<pool>/native" -> address.
	ColdAddresses map[string]string
	MaxTxFeeSats  uint64 // the most a transaction may pay in fee
	MaxFeeRate    uint64 // the most it may pay per virtual byte, in satoshis
	MaxInputs     int    // the most inputs a transaction may have
	// MaxBatchOutputs is the zone's own ceiling on the payments of one batch, and MaxBatchValue its ceiling on their total in satoshis. Neither
	// comes from the core and the core cannot raise them. 0 and 0: the zone signs no batches. When the first is set the second must be too, and the
	// fee caps must reach max_fee_rate for the largest batch (CheckFeeCaps).
	MaxBatchOutputs int
	MaxBatchValue   uint64
	// FeeCaps, when set, lets the zone's approvers change the two fee caps with signatures within these bounds (feecaps.go). Nil: the caps above are
	// the caps and no change is accepted.
	FeeCaps *FeeCapsPolicy
}

// FeeCapsPolicy is the zone's static rules for signed fee-cap changes: how many approvers, how old a change may be, and the bounds no signature can lift.
type FeeCapsPolicy struct {
	MinApprovers int
	MaxAge       time.Duration
	Bounds       FeeCapsBounds
}

// Verifier implements chain.TxVerifier from SigningConfig alone.
type Verifier struct {
	cfg    SigningConfig
	params *chaincfg.Params
	acct   *Account
	shard  map[string]shardInfo // partition ID -> its own shard
	cold   map[string]string    // pool -> canonical cold address
	view   *FeeCapsView         // the fee caps in force (feecaps.go); the static ones until BindFeeCaps
	// gens are the later generations of the account key this verifier knows (WithGenerations), sorted; generation 1 is the configured xpub.
	gens []uint32
}

type shardInfo struct {
	addr string // canonical
	path []uint32
	key  partition.Key
}

var _ chain.TxVerifier = (*Verifier)(nil)

// NewVerifier validates cfg: the network, the xpub, every pinned address (it must belong to the network, and a hot shard must derive
// from the xpub at its stated path), and the caps (all required).
func NewVerifier(cfg SigningConfig) (*Verifier, error) {
	acct, err := NewAccount(cfg.Network, cfg.AccountXpub)
	if err != nil {
		return nil, err
	}
	v := &Verifier{cfg: cfg, params: acct.Params, acct: acct, shard: map[string]shardInfo{}, cold: map[string]string{},
		view: NewFeeCapsView(FeeCaps{MaxTxFeeSats: cfg.MaxTxFeeSats, MaxFeeRate: cfg.MaxFeeRate}, nil, nil, nil)}
	if cfg.MaxTxFeeSats == 0 || cfg.MaxFeeRate == 0 || cfg.MaxInputs <= 0 {
		return nil, errors.New("btc: max_tx_fee_sats, max_fee_rate and max_inputs are required and must be positive")
	}
	if cfg.MaxBatchOutputs < 0 || (cfg.MaxBatchOutputs == 0) != (cfg.MaxBatchValue == 0) {
		return nil, errors.New("btc: max_batch_outputs and max_batch_value_sats are both set (batches allowed) or both unset (none)")
	}
	// The largest transaction the zone signs sets the size the caps must reach: one payment, or a full batch.
	if err := CheckFeeCaps("signing zone", cfg.MaxTxFeeSats, cfg.MaxFeeRate, cfg.MaxInputs, max(1, cfg.MaxBatchOutputs)); err != nil {
		return nil, err
	}
	if len(cfg.HotShards) == 0 {
		return nil, errors.New("btc: no hot shards")
	}
	parts := make([]string, 0, len(cfg.HotShards))
	for part := range cfg.HotShards {
		parts = append(parts, part)
	}
	sort.Strings(parts)
	if err := OneShardPerPool(parts); err != nil {
		return nil, err
	}
	for part, h := range cfg.HotShards {
		if len(h.Path) != 2 || h.Path[0] != BranchHot {
			return nil, fmt.Errorf("btc: hot shard of %q: path %v is not on the hot branch [%d, index]", part, h.Path, BranchHot)
		}
		k, err := partition.Parse(part)
		if err != nil || k.Tier != partition.TierHot || k.Chain != cfg.Chain || k.Asset != Native {
			return nil, fmt.Errorf("btc: hot shard key %q is not a hot %s partition of chain %q (%v)", part, Native, cfg.Chain, err)
		}
		d, err := DecodeAddress(h.Address, v.params)
		if err != nil {
			return nil, fmt.Errorf("btc: hot shard of %q: %w", part, err)
		}
		want, err := acct.Address(h.Path)
		if err != nil {
			return nil, err
		}
		if d.Canonical != want {
			return nil, fmt.Errorf("btc: hot shard of %q: address %s is not the key at path %s of the account (that is %s)", part, h.Address, PathString(h.Path), want)
		}
		v.shard[part] = shardInfo{addr: d.Canonical, path: h.Path, key: k}
	}
	for k, a := range cfg.ColdAddresses {
		pool, ok := strings.CutSuffix(k, "/native")
		if !ok || pool == "" {
			return nil, fmt.Errorf("btc: cold address key %q is not <pool>/native", k)
		}
		d, err := DecodeAddress(a, v.params)
		if err != nil {
			return nil, fmt.Errorf("btc: cold address %q: %w", k, err)
		}
		v.cold[pool] = d.Canonical
	}
	return v, nil
}

// OneShardPerPool refuses a list of hot partition IDs in which two belong to the same pool (and asset, entity and chain): Bitcoin keeps
// one hot shard per pool, since there is no move between shards. An ID that does not parse is not judged here; the callers check it.
func OneShardPerPool(partitions []string) error {
	seen := map[string]string{}
	for _, part := range partitions {
		k, err := partition.Parse(part)
		if err != nil {
			continue
		}
		id := strings.Join([]string{k.Entity, k.Chain, k.Asset, k.Tier, k.Pool}, "/")
		if first, dup := seen[id]; dup {
			return fmt.Errorf("btc: pool %q has two hot shards (%q and %q): Bitcoin keeps one hot shard per pool", k.Pool, first, part)
		}
		seen[id] = part
	}
	return nil
}

// DepositGen is a later generation of the account key (deposit tree and the hot shards derived from it) as the zone's signed records give it.
type DepositGen struct {
	Gen  uint32
	Xpub string
}

// WithGenerations returns a copy of v that also derives under the given generations (2 and up; the same fee caps view, the same pinned shards). A
// payload that names a generation v does not know is refused, because its input scripts cannot be derived. v itself is not changed.
func (v *Verifier) WithGenerations(gs []DepositGen) (*Verifier, error) {
	acct, err := NewAccount(v.cfg.Network, v.cfg.AccountXpub)
	if err != nil {
		return nil, err
	}
	by := map[uint32]string{}
	var list []uint32
	for _, g := range gs {
		if g.Gen < 2 {
			return nil, fmt.Errorf("btc: generation %d: the configured xpub is generation 1", g.Gen)
		}
		if _, dup := by[g.Gen]; dup {
			return nil, fmt.Errorf("btc: generation %d given twice", g.Gen)
		}
		by[g.Gen] = g.Xpub
		list = append(list, g.Gen)
	}
	sort.Slice(list, func(i, j int) bool { return list[i] < list[j] })
	acct.SetGenerationLoader(func(gen uint32) (string, error) {
		x, ok := by[gen]
		if !ok {
			return "", fmt.Errorf("btc: this zone knows no account key for deposit generation %d", gen)
		}
		return x, nil
	})
	nv := *v
	nv.acct, nv.gens = acct, list
	return &nv, nil
}

// genOf normalizes the generation of a payload input: absent (0) is generation 1.
func genOf(g uint32) uint32 {
	if g == 0 {
		return 1
	}
	return g
}

// ShardAddressAt is the address of the hot shard of partition under generation gen of the account key: the pinned address for generation 1, derived
// from the generation's xpub after.
func (v *Verifier) ShardAddressAt(partitionID string, gen uint32) (string, error) {
	own, ok := v.shard[partitionID]
	if !ok {
		return "", fmt.Errorf("btc: partition %q has no pinned hot shard", partitionID)
	}
	return v.shardAt(own, gen)
}

func (v *Verifier) shardAt(own shardInfo, gen uint32) (string, error) {
	if gen <= 1 {
		return own.addr, nil
	}
	return v.acct.AddressAt(gen, own.path)
}

// genOfHot says which generation's hot shard address addr is (0: none of the generations this verifier knows).
func (v *Verifier) genOfHot(own shardInfo, addr string) uint32 {
	if addr == own.addr {
		return 1
	}
	for _, g := range v.gens {
		if a, err := v.shardAt(own, g); err == nil && a == addr {
			return g
		}
	}
	return 0
}

func reject(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrRejected}, args...)...)
}

// Parsed is a payload that passed every check that needs no intent.
type Parsed struct {
	Payload Payload
	Built   *Unsigned
	Index   int // the input the job signs
	Gen     uint32 // the generation of the account key every input is under (1: the configured one)
	Fee     uint64
	Sum     uint64 // the sum of the inputs
	outs    []Decoded
}

// Parse checks everything about a payload that does not depend on the intent, and finds the input the job signs.
func (v *Verifier) Parse(u chain.UnsignedTx) (*Parsed, error) {
	if u.Chain != v.cfg.Chain {
		return nil, reject("chain %q, want %q", u.Chain, v.cfg.Chain)
	}
	p, err := DecodePayload(u.Payload)
	if err != nil {
		return nil, reject("%v", err)
	}
	if p.Version != PayloadVersion {
		return nil, reject("transaction version %d, want %d", p.Version, PayloadVersion)
	}
	if p.LockTime != 0 {
		return nil, reject("locktime %d, want 0", p.LockTime)
	}
	if len(p.Inputs) == 0 || len(p.Inputs) > v.cfg.MaxInputs {
		return nil, reject("%d inputs, the limit is %d", len(p.Inputs), v.cfg.MaxInputs)
	}
	if len(p.Outputs) == 0 {
		return nil, reject("no outputs")
	}
	for n, in := range p.Inputs {
		if in.Sequence != SequenceRBF {
			return nil, reject("input %d: sequence %#x does not signal RBF (want %#x)", n, in.Sequence, SequenceRBF)
		}
		if err := CheckPath(in.Path); err != nil {
			return nil, reject("input %d: %v", n, err)
		}
		if in.Gen == 1 {
			return nil, reject("input %d: generation 1 is written as no generation", n)
		}
		if in.Gen != p.Inputs[0].Gen {
			return nil, reject("input %d is under deposit generation %d, input 0 under %d: one transaction spends one generation", n, genOf(in.Gen), genOf(p.Inputs[0].Gen))
		}
	}
	built, err := BuildUnsigned(p, v.acct)
	if err != nil {
		return nil, reject("%v", err)
	}
	pr := &Parsed{Payload: p, Built: built, Index: -1, Gen: genOf(p.Inputs[0].Gen)}
	for i, d := range built.Digests {
		if bytes.Equal(d, u.Digest) {
			pr.Index = i
			break
		}
	}
	if pr.Index < 0 {
		return nil, reject("digest %x is the sighash of none of the %d inputs", u.Digest, len(p.Inputs))
	}
	if want := chain.KeyPathAt(int(pr.Gen), PathString(p.Inputs[pr.Index].Path)); u.KeyRef.Path != want {
		return nil, reject("the digest is for input %d, which is signed under key path %s, not %q", pr.Index, want, u.KeyRef.Path)
	}
	for _, in := range p.Inputs {
		pr.Sum += in.Value
	}
	var out uint64
	for n, o := range p.Outputs {
		d, err := DecodeAddress(o.Address, v.params)
		if err != nil {
			return nil, reject("output %d: %v", n, err)
		}
		if o.Value < DustLimit(d.Kind) {
			return nil, reject("output %d: %d sats is below the dust limit %d of %s", n, o.Value, DustLimit(d.Kind), d.Kind)
		}
		out += o.Value
		pr.outs = append(pr.outs, d)
	}
	if out > pr.Sum {
		return nil, reject("outputs (%d) exceed inputs (%d)", out, pr.Sum)
	}
	pr.Fee = pr.Sum - out
	caps, seq := v.view.Now()
	if p.FeeCapsSeq != seq {
		return nil, reject("the transaction was built under fee-cap change %d, the zone is on %d: %s", p.FeeCapsSeq, seq, FeeCapsSeqNote)
	}
	if pr.Fee > caps.MaxTxFeeSats {
		return nil, reject("fee %d sats exceeds the cap %d", pr.Fee, caps.MaxTxFeeSats)
	}
	if vs := uint64(EstimateVSize(built.Tx)); pr.Fee > caps.MaxFeeRate*vs {
		return nil, reject("fee %d sats over %d vbytes is above %d sat/vB", pr.Fee, vs, caps.MaxFeeRate)
	}
	return pr, nil
}

// Verify checks that the job's digest is the sighash of one input of the payload under that input's derived key, and that the
// transaction does exactly what the intent says.
func (v *Verifier) Verify(u chain.UnsignedTx, i signjob.Intent) error {
	if i.Chain != v.cfg.Chain {
		return reject("intent chain %q, want %q", i.Chain, v.cfg.Chain)
	}
	pr, err := v.Parse(u)
	if err != nil {
		return err
	}
	p := pr.Payload
	amount, ok := new(big.Int).SetString(i.Amount, 10)
	if !ok || amount.Sign() < 0 || !amount.IsUint64() || amount.String() != i.Amount {
		return reject("intent amount %q", i.Amount)
	}
	to, err := DecodeAddress(i.To, v.params)
	if err != nil {
		return reject("intent destination: %v", err)
	}
	branch := func(want uint32, what string) error {
		for n, in := range p.Inputs {
			if in.Path[0] != want {
				return reject("%s: input %d is at path %s, which is not on branch %d", what, n, PathString(in.Path), want)
			}
		}
		return nil
	}
	// Every kind is bound to the partition the intent names: its own shard, its own pool.
	if u.KeyRef.PartitionID != i.PartitionID {
		return reject("key partition %q, intent partition %q", u.KeyRef.PartitionID, i.PartitionID)
	}
	own, ok := v.shard[i.PartitionID]
	if !ok {
		return reject("partition %q has no pinned hot shard", i.PartitionID)
	}
	ownA, err := v.shardAt(own, pr.Gen) // the partition's shard under the generation the inputs are under
	if err != nil {
		return reject("%v", err)
	}
	ownInputs := func(what string) error {
		for n, in := range p.Inputs {
			if PathString(in.Path) != PathString(own.path) {
				return reject("%s: input %d is at path %s, not the partition's own shard %s", what, n, PathString(in.Path), PathString(own.path))
			}
		}
		return nil
	}
	switch i.Kind {
	case "withdrawal", "to-cold":
		if err := ownInputs(i.Kind); err != nil {
			return err
		}
		if len(p.Outputs) > 2 {
			return reject("%s has %d outputs, at most the payment and one change", i.Kind, len(p.Outputs))
		}
		// The payment is the first output, exactly as intended; the optional second is change, to this partition's own shard only.
		if pr.outs[0].Canonical != to.Canonical || p.Outputs[0].Value != amount.Uint64() {
			return reject("the first output pays %d to %s, the intent is %s to %s", p.Outputs[0].Value, pr.outs[0].Canonical, i.Amount, to.Canonical)
		}
		if len(p.Outputs) == 2 && pr.outs[1].Canonical != ownA {
			return reject("change goes to %s, not the partition's own shard %s", pr.outs[1].Canonical, ownA)
		}
		if i.Kind == "to-cold" {
			pool := own.key.Pool
			if cold, ok := v.cold[pool]; !ok || cold != to.Canonical {
				return reject("%s is not the cold address of pool %q", to.Canonical, pool)
			}
		}
	case "sweep":
		// The intent's amount is the sum of the inputs: what leaves the deposit address, before the fee. The output is that minus the
		// fee, so the ledger moves Amount and books the difference to the fee account.
		if err := branch(BranchDeposit, "sweep"); err != nil {
			return err
		}
		from, err := DecodeAddress(i.From, v.params)
		if err != nil {
			return reject("intent source: %v", err)
		}
		for n, in := range p.Inputs {
			if a, _ := v.acct.AddressAt(in.Gen, in.Path); a != from.Canonical {
				return reject("sweep: input %d is address %s, not the intent's source %s", n, a, from.Canonical)
			}
		}
		if len(p.Outputs) != 1 {
			return reject("a sweep has one output, not %d", len(p.Outputs))
		}
		// The partition's shard under any generation this zone knows; which one a sweep of this generation may pay is the state rule of the zone
		// (the gateway's keyset view), not of this chain code.
		if to.Canonical != pr.outs[0].Canonical || v.genOfHot(own, to.Canonical) == 0 {
			return reject("a sweep pays the partition's own shard %s (under a generation this zone knows); the intent says %s and the output is %s", own.addr, to.Canonical, pr.outs[0].Canonical)
		}
		if pr.Sum != amount.Uint64() {
			return reject("sweep amount %s is not the sum of the inputs, %d", i.Amount, pr.Sum)
		}
	case OwnerKindConsolidate:
		// The money stays where it is: at least two outputs of this partition's own shard (nothing from a deposit address, a cold address or another
		// partition) go back to the same shard in one output. The intent's amount is the sum of the inputs, as for a sweep, so the only thing a compromised
		// business zone can change is the fee, which the caps bound.
		if err := ownInputs("consolidate"); err != nil {
			return err
		}
		if len(p.Inputs) < 2 {
			return reject("a consolidation spends at least two outputs, not %d", len(p.Inputs))
		}
		if len(p.Outputs) != 1 {
			return reject("a consolidation has one output, not %d", len(p.Outputs))
		}
		if to.Canonical != ownA || pr.outs[0].Canonical != ownA {
			return reject("a consolidation pays the partition's own shard %s; the intent says %s and the output is %s", ownA, to.Canonical, pr.outs[0].Canonical)
		}
		if pr.Sum != amount.Uint64() {
			return reject("consolidation amount %s is not the sum of the inputs, %d", i.Amount, pr.Sum)
		}
	case KindCPFP:
		// A child that pulls a stuck send in: coins of this partition's own shard (the guard checks that one of them is the change of a send it signed,
		// and the package fee), back to the same shard in one output. No payment, nothing for anyone else.
		if err := ownInputs("cpfp"); err != nil {
			return err
		}
		if len(p.Outputs) != 1 {
			return reject("a cpfp child has one output, not %d", len(p.Outputs))
		}
		if to.Canonical != ownA || pr.outs[0].Canonical != ownA {
			return reject("a cpfp child pays the partition's own shard %s; the intent says %s and the output is %s", ownA, to.Canonical, pr.outs[0].Canonical)
		}
		if amount.Sign() != 0 {
			return reject("a cpfp intent has amount 0, not %s", i.Amount)
		}
	case signjob.KindDrain:
		// A key replacement: the coins of this partition's own shard under generation G go, in one output, to the same partition's shard under another
		// generation this zone knows. Which one (the successor the signed record names) and whether the source may be drained is the zone's state rule.
		if err := ownInputs("drain"); err != nil {
			return err
		}
		if len(p.Outputs) != 1 {
			return reject("a drain has one output, not %d", len(p.Outputs))
		}
		if to.Canonical != pr.outs[0].Canonical {
			return reject("the drain output pays %s, the intent says %s", pr.outs[0].Canonical, to.Canonical)
		}
		if d := v.genOfHot(own, to.Canonical); d == 0 || d == pr.Gen {
			return reject("a drain pays the partition's shard under another generation than its own (%d), not %s", pr.Gen, to.Canonical)
		}
		if from, err := DecodeAddress(i.From, v.params); err != nil || from.Canonical != ownA {
			return reject("a drain's source is the partition's shard %s under generation %d, the intent says %q", ownA, pr.Gen, i.From)
		}
		if pr.Sum != amount.Uint64() {
			return reject("drain amount %s is not the sum of the inputs, %d", i.Amount, pr.Sum)
		}
	case "cancel":
		// Every input as it was claimed (the guard checks that), back to the partition's own shard. Nothing else.
		if len(p.Outputs) != 1 {
			return reject("a cancel has one output, not %d", len(p.Outputs))
		}
		if to.Canonical != ownA || pr.outs[0].Canonical != ownA {
			return reject("a cancel pays the partition's own shard %s; the intent says %s and the output is %s", ownA, to.Canonical, pr.outs[0].Canonical)
		}
	default:
		return reject("intent kind %q", i.Kind)
	}
	return nil
}

// CapMismatchNote ends the zone's refusal of a first send whose change is too small for the zone's caps. The gateway and the cosigner raise an ALERT
// when a refusal carries it: the usual cause is a core and a zone with different fee caps.
const CapMismatchNote = "core and zone fee caps differ: they must be equal"

// CheckFirstSend is the zone's own fee-bump reserve rule (reserve.go) for the first send of a withdrawal or a hot-to-cold move: the change must be
// large enough to bump the transaction to the zone's own fee cap, change >= zoneFeeCap(vs) - fee + dust, whatever the core reserved. A core that is
// buggy or compromised cannot then build sends that can never be bumped. Replacements and cancels are not judged here (they keep Verify's checks:
// same inputs, smaller change, fee under the cap); the caller decides which send is the first, by the intent not being known yet. Other kinds pass.
// The last output is the change to the partition's own shard and the ones before it are payments, so a list of k payments uses it unchanged.
func (v *Verifier) CheckFirstSend(u chain.UnsignedTx, i signjob.Intent) error {
	if i.Kind != "withdrawal" && i.Kind != "to-cold" && i.Kind != signjob.KindBatch {
		return nil
	}
	pr, err := v.Parse(u)
	if err != nil {
		return err
	}
	own, ok := v.shard[i.PartitionID]
	if !ok {
		return reject("partition %q has no pinned hot shard", i.PartitionID)
	}
	n := len(pr.Payload.Outputs)
	ownA, err := v.shardAt(own, pr.Gen)
	if err != nil {
		return reject("%v", err)
	}
	if n < 2 || pr.outs[n-1].Canonical != ownA {
		return reject("%s has no change output to the partition's own shard: it could not be bumped to the fee cap", i.Kind)
	}
	var payments uint64
	for _, o := range pr.Payload.Outputs[:n-1] {
		payments += o.Value
	}
	vs := uint64(EstimateVSize(pr.Built.Tx))
	caps, _ := v.view.Now()
	if short := ReserveShortfall(pr.Sum, payments, pr.Fee, vs, caps.MaxTxFeeSats, caps.MaxFeeRate); short > 0 {
		change := pr.Payload.Outputs[n-1].Value
		return reject("%s keeps %d sats of change; the zone needs at least %d for its fee cap of %d sats over %d vbytes (fee %d, dust %d): the core reserved less than the zone's caps need, %s",
			i.Kind, change, change+short, FeeCap(caps.MaxTxFeeSats, caps.MaxFeeRate, vs), vs, pr.Fee, DustLimit(KindP2WPKH), CapMismatchNote)
	}
	return nil
}

// KindCPFP is the intent kind of a child that pulls in a stuck send of the same hot shard.
const KindCPFP = "cpfp"

// Parent is what the zone records about a send it signed that has a change output to the partition's own shard: the facts a CPFP child is judged
// against. They come from the zone's own parse of the payload it signed, never from the core's word later.
type Parent struct {
	VSize       uint64
	Fee         uint64
	ChangeVout  uint32
	ChangeValue uint64
}

// ParentRecord is a Parent as the guard remembers it: with the partition and the intent it was signed for.
type ParentRecord struct {
	Parent
	PartitionID string
	IntentID    string
}

// CheckCPFP is the zone's rule for a child, on top of Verify: exactly one of its inputs spends a recorded send (parents, by txid), that input is
// exactly the send's change (its vout and its value), the send was signed for the child's own partition, and the two together stay within the zone's
// caps: the child's fee is at most CPFPRoom, which the zone computes from its own record of the send. Any other input is a coin of the shard; it
// cannot be the change of a second recorded send (a child has one parent, and the chain of unconfirmed ancestors stays short).
func (v *Verifier) CheckCPFP(u chain.UnsignedTx, i signjob.Intent, parents map[string]ParentRecord) error {
	if i.Kind != KindCPFP {
		return reject("intent kind %q is not a cpfp child", i.Kind)
	}
	pr, err := v.Parse(u)
	if err != nil {
		return err
	}
	var parent *ParentRecord
	for n, in := range pr.Payload.Inputs {
		rec, ok := parents[in.TxID]
		if !ok {
			continue
		}
		if parent != nil {
			return reject("input %d also spends a signed transaction: a child has one parent", n)
		}
		if in.Vout != rec.ChangeVout || in.Value != rec.ChangeValue {
			return reject("input %d spends output %d (%d sats) of %s, which is not its change (output %d, %d sats)", n, in.Vout, in.Value, in.TxID, rec.ChangeVout, rec.ChangeValue)
		}
		r := rec
		parent = &r
	}
	if parent == nil {
		return reject("no input spends the change of a transaction this zone signed: a cpfp child pulls in one of its own sends")
	}
	if parent.PartitionID != i.PartitionID {
		return reject("the parent was signed for partition %q, the child is for %q", parent.PartitionID, i.PartitionID)
	}
	vc := uint64(EstimateVSize(pr.Built.Tx))
	caps, _ := v.view.Now()
	if room := CPFPRoom(caps.MaxTxFeeSats, caps.MaxFeeRate, parent.Fee, parent.VSize, vc); pr.Fee > room {
		return reject("the child pays %d sats; with the parent's %d over %d vbytes the package (%d vbytes) may pay at most %d more under the fee caps (%d sats, %d sat/vB)",
			pr.Fee, parent.Fee, parent.VSize, parent.VSize+vc, room, caps.MaxTxFeeSats, caps.MaxFeeRate)
	}
	return nil
}

// Info is what the gateway's guard reads from a verified job.
type Info struct {
	Sender      string
	Destination string
	Claims      []string
	Pins        []string
	Identity    string
	SignerKey   []byte
	Fee         uint64
	// Gen is the generation of the account key the inputs are under (1: the configured one). DestGen is the generation of the partition's hot shard the
	// first output pays, 0 when that output is no hot shard of the partition under a generation this zone knows (a payment, a cold address).
	Gen, DestGen uint32
	// Parent is set when the last output goes to the shard of the job's own partition after at least one payment: the change a CPFP child may spend.
	Parent *Parent
}

// Decode reads the guard's view of a job that Verify accepted: what the transaction consumes (outpoints, pinned to their values), its
// identity (the txid), the fee, and the key that must sign this job.
func (v *Verifier) Decode(u chain.UnsignedTx) (Info, error) {
	pr, err := v.Parse(u)
	if err != nil {
		return Info{}, err
	}
	info := Info{Sender: chain.KeyPathAt(int(pr.Gen), PathString(pr.Payload.Inputs[0].Path)), Destination: pr.outs[0].Canonical, Identity: pr.Built.TxID,
		SignerKey: pr.Built.Pubs[pr.Index], Fee: pr.Fee, Gen: pr.Gen}
	if own, ok := v.shard[u.KeyRef.PartitionID]; ok {
		info.DestGen = v.genOfHot(own, pr.outs[0].Canonical)
	}
	for _, in := range pr.Payload.Inputs {
		info.Claims = append(info.Claims, in.TxID+":"+strconv.FormatUint(uint64(in.Vout), 10))
		info.Pins = append(info.Pins, strconv.FormatUint(in.Value, 10))
	}
	if n := len(pr.Payload.Outputs); n >= 2 {
		if own, ok := v.shard[u.KeyRef.PartitionID]; ok && v.genOfHot(own, pr.outs[n-1].Canonical) == pr.Gen {
			info.Parent = &Parent{VSize: uint64(EstimateVSize(pr.Built.Tx)), Fee: pr.Fee, ChangeVout: uint32(n - 1), ChangeValue: pr.Payload.Outputs[n-1].Value}
		}
	}
	return info, nil
}

// OwnsPath reports whether a path (as a key reference or sender string) is one of the allowed branches: ownership follows from
// derivation, not from a list of addresses.
func (v *Verifier) OwnsPath(s string) bool {
	_, _, err := ParseKeyRef(s)
	return err == nil
}

// Canonical decodes an address for the configured network and returns its canonical encoding; another network's address is an error.
func (v *Verifier) Canonical(address string) (string, error) {
	d, err := DecodeAddress(address, v.params)
	if err != nil {
		return "", err
	}
	return d.Canonical, nil
}

// BindFeeCaps lets signed changes (feecaps.go) set the zone's caps: the verifier reads the newest valid record from q at each Refresh, judged by
// rules, and the static caps of its configuration stand until there is one. onSkip is called when rows that do not verify are ignored.
func (v *Verifier) BindFeeCaps(rules *FeeCapsRules, q Queryer, onSkip func(skipped int)) {
	v.view = NewFeeCapsView(FeeCaps{MaxTxFeeSats: v.cfg.MaxTxFeeSats, MaxFeeRate: v.cfg.MaxFeeRate}, rules, q, onSkip)
}

// SetFeeCapsRules replaces the rules the bound view judges signed changes by (the approvers in force now).
func (v *Verifier) SetFeeCapsRules(rules *FeeCapsRules) { v.view.SetRules(rules) }

// RefreshFeeCaps reads the current record; call it before deciding on a transaction.
func (v *Verifier) RefreshFeeCaps(ctx context.Context) error { return v.view.Refresh(ctx) }

// FeeCapsNow is the caps and the sequence number the zone judges by now.
func (v *Verifier) FeeCapsNow() (FeeCaps, int64) { return v.view.Now() }
