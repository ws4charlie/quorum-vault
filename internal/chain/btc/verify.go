package btc

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"

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
}

// Verifier implements chain.TxVerifier from SigningConfig alone.
type Verifier struct {
	cfg    SigningConfig
	params *chaincfg.Params
	acct   *Account
	shard  map[string]shardInfo // partition ID -> its own shard
	cold   map[string]string    // pool -> canonical cold address
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
	v := &Verifier{cfg: cfg, params: acct.Params, acct: acct, shard: map[string]shardInfo{}, cold: map[string]string{}}
	if cfg.MaxTxFeeSats == 0 || cfg.MaxFeeRate == 0 || cfg.MaxInputs <= 0 {
		return nil, errors.New("btc: max_tx_fee_sats, max_fee_rate and max_inputs are required and must be positive")
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

func reject(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrRejected}, args...)...)
}

// Parsed is a payload that passed every check that needs no intent.
type Parsed struct {
	Payload Payload
	Built   *Unsigned
	Index   int // the input the job signs
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
	}
	built, err := BuildUnsigned(p, v.acct)
	if err != nil {
		return nil, reject("%v", err)
	}
	pr := &Parsed{Payload: p, Built: built, Index: -1}
	for i, d := range built.Digests {
		if bytes.Equal(d, u.Digest) {
			pr.Index = i
			break
		}
	}
	if pr.Index < 0 {
		return nil, reject("digest %x is the sighash of none of the %d inputs", u.Digest, len(p.Inputs))
	}
	if want := PathString(p.Inputs[pr.Index].Path); u.KeyRef.Path != want {
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
	if pr.Fee > v.cfg.MaxTxFeeSats {
		return nil, reject("fee %d sats exceeds the cap %d", pr.Fee, v.cfg.MaxTxFeeSats)
	}
	if vs := uint64(EstimateVSize(built.Tx)); pr.Fee > v.cfg.MaxFeeRate*vs {
		return nil, reject("fee %d sats over %d vbytes is above %d sat/vB", pr.Fee, vs, v.cfg.MaxFeeRate)
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
		if len(p.Outputs) == 2 && pr.outs[1].Canonical != own.addr {
			return reject("change goes to %s, not the partition's own shard %s", pr.outs[1].Canonical, own.addr)
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
			if a, _ := v.acct.Address(in.Path); a != from.Canonical {
				return reject("sweep: input %d is address %s, not the intent's source %s", n, a, from.Canonical)
			}
		}
		if len(p.Outputs) != 1 {
			return reject("a sweep has one output, not %d", len(p.Outputs))
		}
		if to.Canonical != own.addr || pr.outs[0].Canonical != own.addr {
			return reject("a sweep pays the partition's own shard %s; the intent says %s and the output is %s", own.addr, to.Canonical, pr.outs[0].Canonical)
		}
		if pr.Sum != amount.Uint64() {
			return reject("sweep amount %s is not the sum of the inputs, %d", i.Amount, pr.Sum)
		}
	case "cancel":
		// Every input as it was claimed (the guard checks that), back to the partition's own shard. Nothing else.
		if len(p.Outputs) != 1 {
			return reject("a cancel has one output, not %d", len(p.Outputs))
		}
		if to.Canonical != own.addr || pr.outs[0].Canonical != own.addr {
			return reject("a cancel pays the partition's own shard %s; the intent says %s and the output is %s", own.addr, to.Canonical, pr.outs[0].Canonical)
		}
	default:
		return reject("intent kind %q", i.Kind)
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
}

// Decode reads the guard's view of a job that Verify accepted: what the transaction consumes (outpoints, pinned to their values), its
// identity (the txid), the fee, and the key that must sign this job.
func (v *Verifier) Decode(u chain.UnsignedTx) (Info, error) {
	pr, err := v.Parse(u)
	if err != nil {
		return Info{}, err
	}
	info := Info{Sender: PathString(pr.Payload.Inputs[0].Path), Destination: pr.outs[0].Canonical, Identity: pr.Built.TxID,
		SignerKey: pr.Built.Pubs[pr.Index], Fee: pr.Fee}
	for _, in := range pr.Payload.Inputs {
		info.Claims = append(info.Claims, in.TxID+":"+strconv.FormatUint(uint64(in.Vout), 10))
		info.Pins = append(info.Pins, strconv.FormatUint(in.Value, 10))
	}
	return info, nil
}

// OwnsPath reports whether a path (as a key reference or sender string) is one of the allowed branches: ownership follows from
// derivation, not from a list of addresses.
func (v *Verifier) OwnsPath(s string) bool {
	_, err := ParsePath(s)
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
