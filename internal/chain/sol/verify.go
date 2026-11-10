package sol

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/partition"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// The signing zone's judgement of a Solana transaction. Ed25519 signs the whole message, so the message IS the digest: the payload carries
// it, and Verify decodes it and requires it to be exactly one of the shapes below, built from the approved intent and the zone's own
// config, and nothing else. The recent blockhash is not part of the judgement: its age cannot be checked offline, and a stale one only
// makes the network refuse the transaction.
//
// What bounds a withdrawal is its nonce. A withdrawal (and the cancel that frees it) signs the value of a nonce account of the hot shard's own
// pool as its blockhash and advances that nonce first, so at most one message of all the versions of one withdrawal can ever land. The zone
// signs a second message for an intent only when it has the same nonce account and value and a higher priority price (see FeesRaised in the
// gateway codec). A sweep still signs a recent blockhash, and the zone signs one message per intent for it.
//
// Allowed shapes (a withdrawal or cancel starts with AdvanceNonceAccount; then compute-budget instructions: one limit, required; one price,
// optional):
//
//	withdrawal SOL    advance nonce; system transfer hot shard -> destination      signers: hot shard
//	withdrawal token  advance nonce; [create destination ATA, idempotent, paid by the hot shard]
//	                  transferChecked hot ATA -> destination ATA (mint, decimals)
//	cancel            advance nonce, nothing else (frees the nonce of a withdrawal that must not land)
//	nonce setup       pairs of CreateAccountWithSeed + InitializeNonceAccount for pool accounts i of the hot shard, rent from the hot shard
//	                  (a normal recent blockhash; needs an operator approval)
//	sweep SOL         system transfer deposit address -> hot shard                 signers: hot shard (fee payer), deposit address
//	sweep token       [create hot ATA, idempotent] transferChecked deposit ATA -> hot ATA
//	                  [closeAccount deposit ATA, rent to the hot shard]            signers: hot shard (fee payer), deposit address
//
// A sweep's amount is the intent's amount exactly. Whether a SOL sweep leaves the rent-exempt minimum behind depends on the account's
// balance, which the zone cannot see: it cannot be checked here. A transfer that would leave a system account between zero and the minimum
// fails on the chain; one that empties it closes it, and the funds are still the hot shard's.

// ErrRejected wraps every Verify rejection.
var ErrRejected = errors.New("sol: transaction does not match intent")

func reject(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrRejected, fmt.Sprintf(format, args...))
}

// Program ids the zone knows.
const (
	ComputeBudgetProgram = "ComputeBudget111111111111111111111111111111" // public program id, not a secret; ggignore
)

// Token is a configured SPL token.
type Token struct {
	Mint     string
	Decimals uint8
}

// SigningConfig is everything the signing zone knows about a Solana chain: no RPC, no database. It is the trust root of Verifier.
type SigningConfig struct {
	Chain string
	// AccountPublicKey and AccountChainCode are the account node of the 2-party HD keyset; deposit keys derive from it, offline.
	AccountPublicKey [32]byte
	AccountChainCode [32]byte
	// HotShards maps a partition ID (entity/chain/ASSET/hot/pool/shard) to the address of its hot shard (a 2-of-3 keyset). The SOL partition and the
	// token partition of one shard share its address.
	HotShards map[string]string
	// Tokens maps the ledger symbol of a token to its mint and decimals.
	Tokens map[string]Token
	// MaxComputeUnits caps SetComputeUnitLimit; MaxMicroLamportsPerUnit caps SetComputeUnitPrice; MaxPriorityFeeLamports caps their product
	// (limit x price / 1,000,000). All required.
	MaxComputeUnits         uint32
	MaxMicroLamportsPerUnit uint64
	MaxPriorityFeeLamports  uint64
	// NoncePool is how many nonce accounts each hot shard owns (accounts 0..NoncePool-1, at NonceAddress); NonceRent is the lamports a nonce
	// account is created with (the rent-exempt minimum of 80 bytes). Both required.
	NoncePool int
	NonceRent uint64
}

// Payload is what the core puts in a job: the message to sign and, for a sweep, the index of the deposit address that signs as owner.
type Payload struct {
	Message      []byte  `json:"message"`
	DepositIndex *uint32 `json:"deposit_index,omitempty"`
}

// KeyRef paths of a job: the hot shard (the fee payer) or a deposit key.
const (
	PathHot     = ""
	depositPref = "d/"
)

// DepositPath is the key reference of the job that signs as the owner of the deposit address at index.
func DepositPath(index uint32) string { return depositPref + strconv.FormatUint(uint64(index), 10) }

// ParseKeyPath reads a key reference: PathHot, or DepositPath(index).
func ParseKeyPath(s string) (deposit bool, index uint32, err error) {
	if s == PathHot {
		return false, 0, nil
	}
	n, ok := strings.CutPrefix(s, depositPref)
	if !ok {
		return false, 0, fmt.Errorf("key reference %q is neither the hot shard nor d/<index>", s)
	}
	v, err := strconv.ParseUint(n, 10, 32)
	if err != nil || v >= 1<<31 || strconv.FormatUint(v, 10) != n {
		return false, 0, fmt.Errorf("key reference %q: bad deposit index", s)
	}
	return true, uint32(v), nil
}

// Verifier implements chain.TxVerifier from SigningConfig alone.
type Verifier struct {
	cfg  SigningConfig
	node Node
	hot  map[string][32]byte // partition ID -> hot shard key
	own  map[string]bool     // hot shard addresses
	tok  map[string]tokenInfo
	cb   [32]byte
	sys  [32]byte
	tokp [32]byte
	atap [32]byte
	bh   [32]byte // RecentBlockhashes sysvar
	rent [32]byte // Rent sysvar
	// nonces maps a hot shard key to the index of each account of its pool.
	nonces map[[32]byte]map[[32]byte]int
}

type tokenInfo struct {
	mint     [32]byte
	decimals uint8
}

var _ chain.TxVerifier = (*Verifier)(nil)

// NewVerifier validates cfg: the account node, every pinned address and token, and the caps (all required).
func NewVerifier(cfg SigningConfig) (*Verifier, error) {
	v := &Verifier{cfg: cfg, node: Node{PublicKey: cfg.AccountPublicKey, ChainCode: cfg.AccountChainCode}, hot: map[string][32]byte{}, own: map[string]bool{}, tok: map[string]tokenInfo{}}
	if !onCurve(cfg.AccountPublicKey[:]) {
		return nil, errors.New("sol: the account public key is not a point of the Ed25519 curve")
	}
	var err error
	for _, p := range []struct {
		dst *[32]byte
		id  string
	}{{&v.cb, ComputeBudgetProgram}, {&v.sys, SystemProgram}, {&v.tokp, TokenProgram}, {&v.atap, AssociatedTokenProg},
		{&v.bh, SysvarRecentBlockhashes}, {&v.rent, SysvarRent}} {
		if *p.dst, err = ParseAddress(p.id); err != nil {
			return nil, err
		}
	}
	if cfg.MaxComputeUnits == 0 || cfg.MaxMicroLamportsPerUnit == 0 || cfg.MaxPriorityFeeLamports == 0 {
		return nil, errors.New("sol: max_compute_units, max_micro_lamports_per_unit and max_priority_fee_lamports are required and must be positive")
	}
	if len(cfg.HotShards) == 0 {
		return nil, errors.New("sol: no hot shards")
	}
	if cfg.NoncePool < 1 || cfg.NoncePool > 64 || cfg.NonceRent == 0 {
		return nil, errors.New("sol: nonce_pool (1 to 64 accounts per hot shard) and nonce_rent_lamports are required")
	}
	v.nonces = map[[32]byte]map[[32]byte]int{}
	for sym, t := range cfg.Tokens {
		raw, err := ParseAddress(t.Mint)
		if err != nil || sym == "" || sym == Native {
			return nil, fmt.Errorf("sol: token %q: bad symbol or mint", sym)
		}
		v.tok[sym] = tokenInfo{raw, t.Decimals}
	}
	for part, addr := range cfg.HotShards {
		k, err := partition.Parse(part)
		if err != nil || k.Tier != partition.TierHot || k.Chain != cfg.Chain {
			return nil, fmt.Errorf("sol: hot shard key %q is not a hot partition of chain %q (%v)", part, cfg.Chain, err)
		}
		if _, isTok := v.tok[k.Asset]; k.Asset != Native && !isTok {
			return nil, fmt.Errorf("sol: hot shard key %q: asset %q is not SOL or a configured token", part, k.Asset)
		}
		raw, err := ParseAddress(addr)
		if err != nil {
			return nil, fmt.Errorf("sol: hot shard of %q: %w", part, err)
		}
		if !onCurve(raw[:]) {
			return nil, fmt.Errorf("sol: hot shard of %q: %s is not an Ed25519 public key", part, addr)
		}
		v.hot[part] = raw
		v.own[addr] = true
		if v.nonces[raw] == nil {
			v.nonces[raw] = map[[32]byte]int{}
			for i := 0; i < cfg.NoncePool; i++ {
				v.nonces[raw][NonceAddress(raw, i)] = i
			}
		}
	}
	return v, nil
}

// Canonical implements the gateway's address canonicalization: base58 of 32 bytes, case matters.
func (v *Verifier) Canonical(address string) (string, error) {
	raw, err := ParseAddress(address)
	if err != nil {
		return "", err
	}
	return Address(raw), nil
}

// OwnsSender reports whether sender is a hot shard address of the zone.
func (v *Verifier) OwnsSender(sender string) bool { return v.own[sender] }

// HotKey is the key of the hot shard of a partition.
func (v *Verifier) HotKey(partitionID string) ([32]byte, bool) {
	k, ok := v.hot[partitionID]
	return k, ok
}

// DepositKey is the key of the deposit address at index, derived from the zone's own account node.
func (v *Verifier) DepositKey(index uint32) ([32]byte, error) {
	c, err := v.node.Derive(BranchExternal, index)
	return c.PublicKey, err
}

// Info is what the gateway's guard needs from a verified job.
type Info struct {
	Sender      string // the fee payer: the hot shard; the same for every job of one transaction
	Destination string // who is paid (a withdrawal's destination, a sweep's hot shard)
	// SignerKey is the key that must sign THIS job: the hot shard's, or the derived deposit key.
	SignerKey []byte
	Claims    []string
	// Fee is the most the transaction can cost in lamports: base fee for its signatures plus the priority fee.
	Fee *big.Int
	// Fees are what the guard compares between versions of one intent: [price, limit] for a nonce message (a version may raise the price and
	// nothing else), [Fee] alone for a sweep (never replaced).
	Fees []*big.Int
}

func parsePayload(raw []byte) (Payload, error) {
	var p Payload
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return p, reject("payload: %v", err)
	}
	if dec.More() {
		return p, reject("payload: trailing data")
	}
	return p, nil
}

type shape struct {
	msg       *Message
	hot       [32]byte
	hotAddr   string
	dest      string
	kind      string
	deposit   [32]byte
	feeLamp   *big.Int
	amount    uint64
	asset     string
	signerKey [32]byte
	claims    []string
	fees      []*big.Int
}

func u64(n *big.Int) (uint64, bool) {
	if n.Sign() <= 0 || !n.IsUint64() {
		return 0, false
	}
	return n.Uint64(), true
}

// check decodes the job's message and requires it to be exactly the shape the intent asks for.
func (v *Verifier) check(u chain.UnsignedTx, i signjob.Intent) (*shape, error) {
	p, err := parsePayload(u.Payload)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(u.Digest, p.Message) {
		return nil, reject("the digest is not the message of the payload")
	}
	m, err := DecodeMessage(p.Message)
	if err != nil {
		return nil, reject("%v", err)
	}
	switch i.Kind {
	case "withdrawal", "sweep", "cancel", KindNonceSetup:
	default:
		return nil, reject("intent kind %q is not signed on this chain", i.Kind)
	}
	if i.Chain != v.cfg.Chain || u.Chain != v.cfg.Chain {
		return nil, reject("chain %q/%q, this zone signs %q", i.Chain, u.Chain, v.cfg.Chain)
	}
	if i.PartitionID != u.KeyRef.PartitionID {
		return nil, reject("intent partition %q, job partition %q", i.PartitionID, u.KeyRef.PartitionID)
	}
	hot, ok := v.hot[i.PartitionID]
	if !ok {
		return nil, reject("partition %q has no hot shard in this zone", i.PartitionID)
	}
	pk, _ := partition.Parse(i.PartitionID)
	if i.Kind == "cancel" || i.Kind == KindNonceSetup {
		// Both move no asset: they are about the shard, whichever of its partitions the owner is in. They are paid in SOL.
		if i.Asset != Native {
			return nil, reject("a %s is in SOL, the intent says %q", i.Kind, i.Asset)
		}
	} else if pk.Asset != i.Asset {
		return nil, reject("intent asset %q, partition asset %q", i.Asset, pk.Asset)
	}
	amt, ok := new(big.Int).SetString(i.Amount, 10)
	if !ok || i.Amount != amt.String() {
		return nil, reject("amount %q is not a canonical decimal", i.Amount)
	}
	var amount uint64
	if i.Kind == "cancel" {
		if amt.Sign() != 0 {
			return nil, reject("a cancel moves nothing: its amount is 0, not %s", i.Amount)
		}
	} else if amount, ok = u64(amt); !ok {
		return nil, reject("amount %s is not between 1 and 2^64-1", i.Amount)
	}
	s := &shape{msg: m, hot: hot, hotAddr: Address(hot), kind: i.Kind, amount: amount, asset: i.Asset}

	// A withdrawal and its cancel start by advancing the nonce of one account of the hot shard's pool, and sign the value that nonce holds.
	idx := 0
	if i.Kind == "withdrawal" || i.Kind == "cancel" {
		if err := v.advance(s, m); err != nil {
			return nil, err
		}
		idx = 1
	}

	// Compute budget next: one limit (required), one price (optional), within the caps.
	var limit uint32
	var price uint64
	haveLimit, havePrice := false, false
	for ; idx < len(m.Instructions); idx++ {
		in := m.Instructions[idx]
		if in.Program != v.cb {
			break
		}
		if len(in.Accts) != 0 || len(in.Data) == 0 {
			return nil, reject("compute budget instruction %d has accounts or no data", idx)
		}
		switch in.Data[0] {
		case 2:
			if haveLimit || len(in.Data) != 5 {
				return nil, reject("compute unit limit twice or malformed")
			}
			limit, haveLimit = binary.LittleEndian.Uint32(in.Data[1:]), true
		case 3:
			if havePrice || len(in.Data) != 9 {
				return nil, reject("compute unit price twice or malformed")
			}
			price, havePrice = binary.LittleEndian.Uint64(in.Data[1:]), true
		default:
			return nil, reject("compute budget instruction type %d is not allowed (only SetComputeUnitLimit and SetComputeUnitPrice)", in.Data[0])
		}
	}
	if !haveLimit {
		return nil, reject("no compute unit limit: the cap cannot be checked")
	}
	if limit == 0 || limit > v.cfg.MaxComputeUnits {
		return nil, reject("compute unit limit %d is above the cap %d", limit, v.cfg.MaxComputeUnits)
	}
	if price > v.cfg.MaxMicroLamportsPerUnit {
		return nil, reject("compute unit price %d is above the cap %d", price, v.cfg.MaxMicroLamportsPerUnit)
	}
	prio := new(big.Int).Div(new(big.Int).Mul(new(big.Int).SetUint64(uint64(limit)), new(big.Int).SetUint64(price)), big.NewInt(1_000_000))
	if prio.Cmp(new(big.Int).SetUint64(v.cfg.MaxPriorityFeeLamports)) > 0 {
		return nil, reject("priority fee %s lamports is above the cap %d", prio, v.cfg.MaxPriorityFeeLamports)
	}
	rest := m.Instructions[idx:]
	if len(rest) == 0 && i.Kind != "cancel" {
		return nil, reject("no instruction besides the compute budget")
	}

	// Who signs: the fee payer is the hot shard; a sweep adds the deposit address as the second signer.
	if m.Keys[0] != hot {
		return nil, reject("the fee payer %s is not the hot shard %s of %s", Address(m.Keys[0]), s.hotAddr, i.PartitionID)
	}
	if !m.IsWritable(0) {
		return nil, reject("the fee payer is read-only")
	}
	wantSigners := 1
	switch i.Kind {
	case "withdrawal":
		if err := v.withdrawal(s, rest, i); err != nil {
			return nil, err
		}
	case "cancel":
		if len(rest) != 0 {
			return nil, reject("a cancel is the nonce advance and the compute budget, nothing else")
		}
		s.dest = s.hotAddr
	case KindNonceSetup:
		if err := v.nonceSetup(s, rest, amount); err != nil {
			return nil, err
		}
	case "sweep":
		wantSigners = 2
		if err := v.sweep(s, rest, i, p.DepositIndex); err != nil {
			return nil, err
		}
	}
	if m.NumSigners != wantSigners {
		return nil, reject("the message has %d required signers, a %s needs %d", m.NumSigners, i.Kind, wantSigners)
	}
	if wantSigners == 2 && m.Keys[1] != s.deposit {
		return nil, reject("the second signer %s is not the deposit address %s", Address(m.Keys[1]), Address(s.deposit))
	}
	// Every account of the message is the fee payer, a signer or an account/program an accepted instruction names: nothing rides along unseen.
	used := map[int]bool{0: true}
	for _, pi := range m.ProgramIdx {
		used[pi] = true
	}
	for _, in := range m.Instructions {
		for _, ai := range in.AcctIdx {
			used[ai] = true
		}
	}
	for k := range m.Keys {
		if !used[k] {
			return nil, reject("account %s of the message is used by no instruction", Address(m.Keys[k]))
		}
	}
	s.feeLamp = new(big.Int).Add(prio, big.NewInt(5000*int64(wantSigners)))
	if s.fees == nil { // a sweep: never replaced
		s.fees = []*big.Int{s.feeLamp}
	} else {
		s.fees = []*big.Int{new(big.Int).SetUint64(price), new(big.Int).SetUint64(uint64(limit))}
	}

	// Which key does THIS job ask for?
	dep, di, err := ParseKeyPath(u.KeyRef.Path)
	if err != nil {
		return nil, reject("%v", err)
	}
	if !dep {
		s.signerKey = hot
	} else {
		if wantSigners != 2 || p.DepositIndex == nil || di != *p.DepositIndex {
			return nil, reject("key %s is not the deposit key of this transaction", u.KeyRef.Path)
		}
		s.signerKey = s.deposit
	}
	return s, nil
}

// KindNonceSetup is the intent kind of the creation of nonce accounts.
const KindNonceSetup = "nonce-setup"

// advance requires the first instruction of m to be AdvanceNonceAccount on an account of the hot shard's pool, authority the hot shard, and
// takes the claim from it: the nonce account and the value the message signs.
func (v *Verifier) advance(s *shape, m *Message) error {
	in := m.Instructions[0]
	pool := v.nonces[s.hot]
	if in.Program != v.sys || !bytes.Equal(in.Data, AdvanceNonceData()) || len(in.Accts) != 3 {
		return reject("the first instruction is not AdvanceNonceAccount: a %s signs a durable nonce, never a recent blockhash", s.kind)
	}
	if _, ok := pool[in.Accts[0]]; !ok {
		return reject("the nonce account %s is not in the pool of hot shard %s", Address(in.Accts[0]), s.hotAddr)
	}
	if in.Accts[1] != v.bh || in.Accts[2] != s.hot {
		return reject("the nonce advance names the wrong sysvar or an authority other than the hot shard")
	}
	s.claims = []string{Address(in.Accts[0]) + "#" + Address(m.Blockhash)}
	s.fees = []*big.Int{} // set below, a nonce message
	return nil
}

// nonceSetup requires pairs of CreateAccountWithSeed and InitializeNonceAccount, each for another account of the hot shard's pool, the rent the
// config names, the hot shard as base, payer and authority; and the amount of the intent to be the sum of the rent.
func (v *Verifier) nonceSetup(s *shape, rest []MsgInstruction, amount uint64) error {
	if len(rest)%2 != 0 || len(rest) == 0 || len(rest)/2 > v.cfg.NoncePool {
		return reject("a nonce setup is pairs of create and initialize for 1 to %d accounts, the message has %d instructions after the compute budget", v.cfg.NoncePool, len(rest))
	}
	pool := v.nonces[s.hot]
	seen := map[[32]byte]bool{}
	for k := 0; k < len(rest); k += 2 {
		cr, in := rest[k], rest[k+1]
		if cr.Program != v.sys || len(cr.Accts) != 2 || cr.Accts[0] != s.hot {
			return reject("instruction %d is not a CreateAccountWithSeed paid by the hot shard (the shard is its own base)", k)
		}
		acct := cr.Accts[1]
		i, ok := pool[acct]
		if !ok || seen[acct] {
			return reject("instruction %d creates %s, which is not (or not again) an account of the hot shard's pool", k, Address(acct))
		}
		seen[acct] = true
		if !bytes.Equal(cr.Data, CreateWithSeedData(s.hot, NonceSeed(i), v.cfg.NonceRent, NonceAccountSize)) {
			return reject("instruction %d is not a creation of pool account %d with seed %s, %d lamports, %d bytes, owned by the system program", k, i, NonceSeed(i), v.cfg.NonceRent, NonceAccountSize)
		}
		if in.Program != v.sys || !bytes.Equal(in.Data, InitNonceData(s.hot)) || !eqAccts(in.Accts, acct, v.bh, v.rent) {
			return reject("instruction %d is not an InitializeNonceAccount of %s with the hot shard as authority", k+1, Address(acct))
		}
	}
	if want := uint64(len(rest)/2) * v.cfg.NonceRent; amount != want {
		return reject("the intent amount %d is not the rent of %d accounts (%d)", amount, len(rest)/2, want)
	}
	s.dest = s.hotAddr
	return nil
}

func eqAccts(got [][32]byte, want ...[32]byte) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func (v *Verifier) transferData(amount uint64) []byte {
	return append(binary.LittleEndian.AppendUint32(nil, 2), binary.LittleEndian.AppendUint64(nil, amount)...)
}

func (v *Verifier) checkedData(amount uint64, decimals uint8) []byte {
	return append(append([]byte{12}, binary.LittleEndian.AppendUint64(nil, amount)...), decimals)
}

func (v *Verifier) withdrawal(s *shape, rest []MsgInstruction, i signjob.Intent) error {
	if i.To == "" {
		return reject("a withdrawal has no destination")
	}
	dest, err := ParseAddress(i.To)
	if err != nil {
		return reject("destination: %v", err)
	}
	if dest == s.hot {
		return reject("the destination is the hot shard itself")
	}
	s.dest = Address(dest)
	if i.Asset == Native {
		if len(rest) != 1 {
			return reject("a SOL withdrawal is one system transfer, the message has %d instructions after the compute budget", len(rest))
		}
		in := rest[0]
		if in.Program != v.sys || !eqAccts(in.Accts, s.hot, dest) || !bytes.Equal(in.Data, v.transferData(s.amount)) {
			return reject("the instruction is not a system transfer of %d lamports from the hot shard to %s", s.amount, s.dest)
		}
		return nil
	}
	t, ok := v.tok[i.Asset]
	if !ok {
		return reject("asset %q is not configured", i.Asset)
	}
	src, err := ATA(s.hot, t.mint)
	if err != nil {
		return err
	}
	dst, err := ATA(dest, t.mint)
	if err != nil {
		return err
	}
	if len(rest) == 2 {
		in := rest[0]
		if in.Program != v.atap || !eqAccts(in.Accts, s.hot, dst, dest, t.mint, v.sys, v.tokp) || !bytes.Equal(in.Data, []byte{1}) {
			return reject("the first instruction is not an idempotent create of the destination's associated token account, paid by the hot shard")
		}
		rest = rest[1:]
	}
	if len(rest) != 1 {
		return reject("a token withdrawal is [create destination account] and one transferChecked")
	}
	in := rest[0]
	if in.Program != v.tokp || !eqAccts(in.Accts, src, t.mint, dst, s.hot) || !bytes.Equal(in.Data, v.checkedData(s.amount, t.decimals)) {
		return reject("the instruction is not a transferChecked of %d (decimals %d, mint %s) from the hot shard's token account to %s's", s.amount, t.decimals, Address(t.mint), s.dest)
	}
	return nil
}

func (v *Verifier) sweep(s *shape, rest []MsgInstruction, i signjob.Intent, depIndex *uint32) error {
	if depIndex == nil {
		return reject("a sweep names the deposit index in its payload")
	}
	dk, err := v.DepositKey(*depIndex)
	if err != nil {
		return reject("deposit index %d: %v", *depIndex, err)
	}
	if i.From != Address(dk) {
		return reject("the sweep source %q is not the deposit address %s at index %d", i.From, Address(dk), *depIndex)
	}
	if i.To != s.hotAddr {
		return reject("a sweep pays the hot shard %s, not %q", s.hotAddr, i.To)
	}
	s.deposit, s.dest = dk, s.hotAddr
	if i.Asset == Native {
		if len(rest) != 1 {
			return reject("a SOL sweep is one system transfer, the message has %d instructions after the compute budget", len(rest))
		}
		in := rest[0]
		if in.Program != v.sys || !eqAccts(in.Accts, dk, s.hot) || !bytes.Equal(in.Data, v.transferData(s.amount)) {
			return reject("the instruction is not a system transfer of %d lamports from the deposit address to the hot shard", s.amount)
		}
		return nil
	}
	t, ok := v.tok[i.Asset]
	if !ok {
		return reject("asset %q is not configured", i.Asset)
	}
	depATA, err := ATA(dk, t.mint)
	if err != nil {
		return err
	}
	hotATA, err := ATA(s.hot, t.mint)
	if err != nil {
		return err
	}
	if len(rest) > 0 && rest[0].Program == v.atap {
		in := rest[0]
		if !eqAccts(in.Accts, s.hot, hotATA, s.hot, t.mint, v.sys, v.tokp) || !bytes.Equal(in.Data, []byte{1}) {
			return reject("the create instruction is not an idempotent create of the hot shard's own associated token account")
		}
		rest = rest[1:]
	}
	if n := len(rest); n == 2 {
		in := rest[1]
		if in.Program != v.tokp || !eqAccts(in.Accts, depATA, s.hot, dk) || !bytes.Equal(in.Data, []byte{9}) {
			return reject("the last instruction is not a closeAccount of the deposit token account with its rent going to the hot shard, owner signing")
		}
		rest = rest[:1]
	}
	if len(rest) != 1 {
		return reject("a token sweep is [create hot account], one transferChecked and optionally a closeAccount")
	}
	in := rest[0]
	if in.Program != v.tokp || !eqAccts(in.Accts, depATA, t.mint, hotATA, dk) || !bytes.Equal(in.Data, v.checkedData(s.amount, t.decimals)) {
		return reject("the instruction is not a transferChecked of %d (decimals %d, mint %s) from the deposit token account to the hot shard's", s.amount, t.decimals, Address(t.mint))
	}
	return nil
}

// Verify implements chain.TxVerifier.
func (v *Verifier) Verify(u chain.UnsignedTx, i signjob.Intent) error {
	_, err := v.check(u, i)
	return err
}

// Decode reads what the guard needs from a job that Verify accepted: the sender (fee payer), the destination, the key that signs this job, the
// claim (one message per intent) and the most the transaction can cost.
func (v *Verifier) Decode(u chain.UnsignedTx, i signjob.Intent) (Info, error) {
	s, err := v.check(u, i)
	if err != nil {
		return Info{}, err
	}
	claims := s.claims
	if i.Kind == "sweep" { // one message per intent
		claims = []string{s.hotAddr + "#" + i.ID}
	}
	return Info{Sender: s.hotAddr, Destination: s.dest, SignerKey: append([]byte(nil), s.signerKey[:]...),
		Claims: claims, Fee: s.feeLamp, Fees: s.fees}, nil
}
