package coldsign

// The Bitcoin side of the offline signer. Like the rest of this package it is pure: no network client, no database, no HSM. That rules out the btcd
// packages that pull in "net" (wire, chaincfg, txscript, btcutil), so the little Bitcoin this needs (P2WPKH addresses, the segwit serialization and the
// BIP143 digest) is written here and checked against btcd in the tests, where the import graph is not under test.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"golang.org/x/crypto/ripemd160"
)

// Versions of the Bitcoin files that cross the air gap.
const (
	BTCRequestVersion = "qv-cold-btc-request-v1"
	BTCSignedVersion  = "qv-refill-btc-signed-v1"
	btcHashTag        = "qv-refill-btc-request-hash-v1\n"
	btcIntentTag      = "qv-refill-btc-intent-hash-v1\n"

	btcDust     = 294        // the dust limit of a P2WPKH output
	btcSequence = 0xfffffffd // every input signals replaceability
	btcSighash  = 1          // SIGHASH_ALL
)

// BTCInput is one output of the cold address that the transaction spends. The value is what the online side says; the signer cannot check it (see
// the record below for what that costs).
type BTCInput struct {
	TxID    string `json:"txid"`
	Vout    uint32 `json:"vout"`
	Value   uint64 `json:"value"` // satoshis
	Address string `json:"address"`
}

// BTCOutput is one output of the transaction.
type BTCOutput struct {
	Address string `json:"address"`
	Value   uint64 `json:"value"`
}

// BTCRequest is a refill of a hot shard from the cold address, as the online side exports it. The offline tool builds the transaction from these
// fields itself. Outputs[0] is the payment to a hot shard; Outputs[1], when there is one, is the change back to the cold address.
type BTCRequest struct {
	Version  string      `json:"version"`
	ID       string      `json:"id"`
	Revision int         `json:"revision"` // grows with every re-export (a higher fee)
	Network  string      `json:"network"`  // mainnet, testnet3, signet or regtest
	Chain    string      `json:"chain"`
	Pool     string      `json:"pool"`
	From     string      `json:"from"` // the cold address
	Inputs   []BTCInput  `json:"inputs"`
	Outputs  []BTCOutput `json:"outputs"`
}

// BTCRequestFile is what is carried to the offline machine.
type BTCRequestFile struct {
	Request     BTCRequest `json:"request"`
	RequestHash string     `json:"request_hash"`
}

// BTCSigned is what comes back: the signed raw transaction for one request.
type BTCSigned struct {
	Version     string `json:"version"`
	RequestID   string `json:"request_id"`
	RequestHash string `json:"request_hash"`
	RawTx       string `json:"raw_tx"` // hex, with witnesses
	TxID        string `json:"txid"`
	Signer      string `json:"signer"` // the cold address that signed
}

// IsBTCRequest reports whether a request file's JSON is a Bitcoin request.
func IsBTCRequest(raw []byte) bool {
	var v struct {
		Request struct {
			Version string `json:"version"`
		} `json:"request"`
	}
	return json.Unmarshal(raw, &v) == nil && strings.HasPrefix(v.Request.Version, "qv-cold-btc-request")
}

func (r BTCRequest) fields() []string {
	f := []string{r.Version, r.ID, strconv.Itoa(r.Revision), r.Network, r.Chain, r.Pool, strings.ToLower(r.From), strconv.Itoa(len(r.Inputs))}
	for _, in := range r.Inputs {
		f = append(f, strings.ToLower(in.TxID), strconv.FormatUint(uint64(in.Vout), 10), strconv.FormatUint(in.Value, 10), strings.ToLower(in.Address))
	}
	f = append(f, strconv.Itoa(len(r.Outputs)))
	for _, o := range r.Outputs {
		f = append(f, strings.ToLower(o.Address), strconv.FormatUint(o.Value, 10))
	}
	return f
}

// Hash is what operators approve: every field, length-prefixed, under a domain tag.
func (r BTCRequest) Hash() [32]byte {
	b := []byte(btcHashTag)
	for _, f := range r.fields() {
		b = lp(b, f)
	}
	return sha256.Sum256(b)
}

// HashHex is Hash in hex.
func (r BTCRequest) HashHex() string { h := r.Hash(); return hex.EncodeToString(h[:]) }

// File wraps the request with its hash.
func (r BTCRequest) File() BTCRequestFile {
	return BTCRequestFile{Request: r, RequestHash: r.HashHex()}
}

// Intent identifies WHAT the transaction does apart from its fee: the set of outpoints, where the payment goes and how much. A re-export with a higher
// fee has the same intent; any other transaction that spends one of its outpoints does not.
func (r BTCRequest) Intent() string {
	ops := make([]string, 0, len(r.Inputs))
	for _, in := range r.Inputs {
		ops = append(ops, fmt.Sprintf("%s:%d", strings.ToLower(in.TxID), in.Vout))
	}
	sort.Strings(ops)
	b := []byte(btcIntentTag)
	for _, f := range append([]string{r.Network, strings.ToLower(r.From)}, ops...) {
		b = lp(b, f)
	}
	if len(r.Outputs) > 0 {
		b = lp(b, strings.ToLower(r.Outputs[0].Address))
		b = lp(b, strconv.FormatUint(r.Outputs[0].Value, 10))
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Fee is inputs minus outputs, in satoshis.
func (r BTCRequest) Fee() (uint64, error) {
	var in, out uint64
	for _, i := range r.Inputs {
		if in+i.Value < in {
			return 0, errors.New("input values overflow")
		}
		in += i.Value
	}
	for _, o := range r.Outputs {
		if out+o.Value < out {
			return 0, errors.New("output values overflow")
		}
		out += o.Value
	}
	if out > in {
		return 0, fmt.Errorf("outputs (%d) are more than inputs (%d)", out, in)
	}
	return in - out, nil
}

// Summary is the statement operators check.
func (r BTCRequest) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "  request   %s (revision %d)\n", r.ID, r.Revision)
	fmt.Fprintf(&b, "  chain     %s (%s), pool %s\n", r.Chain, r.Network, r.Pool)
	fmt.Fprintf(&b, "  from      %s (the cold address), %d input(s):\n", r.From, len(r.Inputs))
	for _, in := range r.Inputs {
		fmt.Fprintf(&b, "              %s:%d  %s sats (the online side's figure: this tool cannot check it)\n", in.TxID, in.Vout, strconv.FormatUint(in.Value, 10))
	}
	for i, o := range r.Outputs {
		role := "to the hot shard"
		if i == 1 {
			role = "change, back to the cold address"
		}
		fmt.Fprintf(&b, "  output %d  %s  %d sats (%s)\n", i, o.Address, o.Value, role)
	}
	fee, err := r.Fee()
	if err == nil {
		vs := btcVSizeEstimate(len(r.Inputs), len(r.Outputs))
		fmt.Fprintf(&b, "  fee       %d sats, about %d sat/vB over about %d vbytes\n", fee, fee/uint64(max(vs, 1)), vs)
	}
	return b.String()
}

// ---- addresses ----

func btcHRP(network string) (string, error) {
	switch network {
	case "mainnet":
		return "bc", nil
	case "testnet3", "signet":
		return "tb", nil
	case "regtest":
		return "bcrt", nil
	}
	return "", fmt.Errorf("unknown network %q (mainnet, testnet3, signet, regtest)", network)
}

// p2wpkhHash decodes a native SegWit v0 key-hash address of the network.
func p2wpkhHash(network, addr string) ([20]byte, error) {
	var out [20]byte
	hrp, err := btcHRP(network)
	if err != nil {
		return out, err
	}
	if addr != strings.ToLower(addr) {
		return out, fmt.Errorf("address %q is not lowercase", addr)
	}
	got, data, err := bech32.Decode(addr)
	if err != nil {
		return out, fmt.Errorf("address %q: %v", addr, err)
	}
	if got != hrp {
		return out, fmt.Errorf("address %q is for another network (%q), this is %s (%q)", addr, got, network, hrp)
	}
	if len(data) == 0 || data[0] != 0 {
		return out, fmt.Errorf("address %q is not a SegWit v0 address", addr)
	}
	prog, err := bech32.ConvertBits(data[1:], 5, 8, false)
	if err != nil || len(prog) != 20 {
		return out, fmt.Errorf("address %q is not a pay-to-witness-key-hash address", addr)
	}
	copy(out[:], prog)
	return out, nil
}

func p2wpkhAddress(network string, h [20]byte) (string, error) {
	hrp, err := btcHRP(network)
	if err != nil {
		return "", err
	}
	conv, err := bech32.ConvertBits(h[:], 8, 5, true)
	if err != nil {
		return "", err
	}
	return bech32.Encode(hrp, append([]byte{0}, conv...))
}

func hash160(b []byte) [20]byte {
	s := sha256.Sum256(b)
	r := ripemd160.New()
	r.Write(s[:])
	var out [20]byte
	copy(out[:], r.Sum(nil))
	return out
}

// BTCAddressOf is the P2WPKH address of a compressed public key (66 hex characters) on the network.
func BTCAddressOf(network, pubHex string) (string, error) {
	pub, err := parseCompressed(pubHex)
	if err != nil {
		return "", err
	}
	return p2wpkhAddress(network, hash160(pub.SerializeCompressed()))
}

func parseCompressed(pubHex string) (*btcec.PublicKey, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(pubHex, "0x"))
	if err != nil || len(b) != 33 {
		return nil, errors.New("public_key must be a compressed secp256k1 key (33 bytes, hex)")
	}
	return btcec.ParsePubKey(b)
}

// CompressPublicKey turns the HSM's uncompressed key (65 bytes, hex) into the compressed form this config takes.
func CompressPublicKey(uncompressedHex string) (string, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(uncompressedHex, "0x"))
	if err != nil {
		return "", err
	}
	pub, err := btcec.ParsePubKey(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(pub.SerializeCompressed()), nil
}

// ---- the transaction ----

type btcTx struct {
	ins   []btcTxIn
	outs  []btcTxOut
	wit   [][][]byte // per input: the witness stack
	value []uint64   // per input: the value being spent (not serialized, used by the digest)
}

type btcTxIn struct {
	txid [32]byte // in the order bytes are serialized (reversed from the display)
	vout uint32
}

type btcTxOut struct {
	value  uint64
	script []byte
}

func varint(b []byte, n uint64) []byte {
	switch {
	case n < 0xfd:
		return append(b, byte(n))
	case n <= 0xffff:
		return binary.LittleEndian.AppendUint16(append(b, 0xfd), uint16(n))
	case n <= 0xffffffff:
		return binary.LittleEndian.AppendUint32(append(b, 0xfe), uint32(n))
	}
	return binary.LittleEndian.AppendUint64(append(b, 0xff), n)
}

func p2wpkhScript(h [20]byte) []byte { return append([]byte{0x00, 0x14}, h[:]...) }

func parseTxID(s string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 || s != strings.ToLower(s) {
		return out, fmt.Errorf("txid %q is not 32 bytes of lowercase hex", s)
	}
	for i := range b {
		out[31-i] = b[i]
	}
	return out, nil
}

// Tx builds the unsigned transaction the request describes (version 2, lock time 0, every input signalling replaceability), checking only that the
// fields parse. The rules about what may be signed are Check's.
func (r BTCRequest) Tx() (*btcTx, error) {
	if r.Version != BTCRequestVersion {
		return nil, fmt.Errorf("request version %q, want %q", r.Version, BTCRequestVersion)
	}
	t := &btcTx{}
	for _, in := range r.Inputs {
		id, err := parseTxID(in.TxID)
		if err != nil {
			return nil, err
		}
		t.ins = append(t.ins, btcTxIn{txid: id, vout: in.Vout})
		t.value = append(t.value, in.Value)
	}
	for _, o := range r.Outputs {
		h, err := p2wpkhHash(r.Network, o.Address)
		if err != nil {
			return nil, err
		}
		t.outs = append(t.outs, btcTxOut{value: o.Value, script: p2wpkhScript(h)})
	}
	return t, nil
}

func (t *btcTx) serialize(withWitness bool) []byte {
	var b []byte
	b = binary.LittleEndian.AppendUint32(b, 2)
	if withWitness {
		b = append(b, 0x00, 0x01)
	}
	b = varint(b, uint64(len(t.ins)))
	for _, in := range t.ins {
		b = append(b, in.txid[:]...)
		b = binary.LittleEndian.AppendUint32(b, in.vout)
		b = append(b, 0x00) // empty scriptSig
		b = binary.LittleEndian.AppendUint32(b, btcSequence)
	}
	b = varint(b, uint64(len(t.outs)))
	for _, o := range t.outs {
		b = binary.LittleEndian.AppendUint64(b, o.value)
		b = varint(b, uint64(len(o.script)))
		b = append(b, o.script...)
	}
	if withWitness {
		for i := range t.ins {
			st := t.wit[i]
			b = varint(b, uint64(len(st)))
			for _, item := range st {
				b = varint(b, uint64(len(item)))
				b = append(b, item...)
			}
		}
	}
	return binary.LittleEndian.AppendUint32(b, 0) // lock time
}

func dsha(b []byte) [32]byte { h := sha256.Sum256(b); return sha256.Sum256(h[:]) }

// TxID is the transaction id (witnesses do not count), in the usual display order.
func (t *btcTx) TxID() string {
	h := dsha(t.serialize(false))
	for i, j := 0, 31; i < j; i, j = i+1, j-1 {
		h[i], h[j] = h[j], h[i]
	}
	return hex.EncodeToString(h[:])
}

// sighash is the BIP143 digest of input i (SIGHASH_ALL) for a P2WPKH output of the key hash.
func (t *btcTx) sighash(i int, keyHash [20]byte) [32]byte {
	var prevouts, seqs, outs []byte
	for _, in := range t.ins {
		prevouts = append(prevouts, in.txid[:]...)
		prevouts = binary.LittleEndian.AppendUint32(prevouts, in.vout)
		seqs = binary.LittleEndian.AppendUint32(seqs, btcSequence)
	}
	for _, o := range t.outs {
		outs = binary.LittleEndian.AppendUint64(outs, o.value)
		outs = varint(outs, uint64(len(o.script)))
		outs = append(outs, o.script...)
	}
	hp, hs, ho := dsha(prevouts), dsha(seqs), dsha(outs)
	var p []byte
	p = binary.LittleEndian.AppendUint32(p, 2)
	p = append(p, hp[:]...)
	p = append(p, hs[:]...)
	p = append(p, t.ins[i].txid[:]...)
	p = binary.LittleEndian.AppendUint32(p, t.ins[i].vout)
	p = append(p, 0x19, 0x76, 0xa9, 0x14)
	p = append(p, keyHash[:]...)
	p = append(p, 0x88, 0xac)
	p = binary.LittleEndian.AppendUint64(p, t.value[i])
	p = binary.LittleEndian.AppendUint32(p, btcSequence)
	p = append(p, ho[:]...)
	p = binary.LittleEndian.AppendUint32(p, 0)
	p = binary.LittleEndian.AppendUint32(p, btcSighash)
	return dsha(p)
}

// btcVSizeEstimate is the virtual size of a transaction with n P2WPKH inputs and m P2WPKH outputs, signed (72-byte signatures: an upper bound).
func btcVSizeEstimate(n, m int) int {
	base := 4 + 1 + n*(32+4+1+4) + 1 + m*(8+1+22) + 4
	wit := 2 + n*(1+1+73+1+33) // marker and flag, then the stack of each input
	return (3*base + base + wit + 3) / 4
}

// ---- the offline config and the rules ----

// BTCConfig is the Bitcoin offline tool's own configuration: the only trust root for a signature.
type BTCConfig struct {
	Family  string `json:"family"` // "btc"
	Network string `json:"network"`
	Chain   string `json:"chain"`
	Pool    string `json:"pool"`
	// Operators and Threshold are as in the EVM config: M-of-N enforced in software with Ed25519 signatures.
	Operators map[string]string `json:"operators"`
	Threshold int               `json:"threshold"`
	// HotShards are the only addresses a refill may pay: the hot shard addresses, pinned here.
	HotShards []string `json:"hot_shards"`
	// MaxAmount is the per-ceremony cap on the payment, in satoshis. MaxFeeSats and MaxFeeRate (sat/vB) cap the fee, MaxInputs the inputs.
	MaxAmount  uint64    `json:"max_amount"`
	MaxFeeSats uint64    `json:"max_fee_sats"`
	MaxFeeRate uint64    `json:"max_fee_rate"`
	MaxInputs  int       `json:"max_inputs"`
	PublicKey  string    `json:"public_key"` // the cold key, compressed secp256k1, hex
	HSM        HSMConfig `json:"hsm"`
	RecordDir  string    `json:"record_dir"` // durable record of every outpoint ever signed
}

// IsBTCConfig reports whether a config file's JSON is a Bitcoin config.
func IsBTCConfig(raw []byte) bool {
	var v struct {
		Family string `json:"family"`
	}
	return json.Unmarshal(raw, &v) == nil && v.Family == "btc"
}

// LoadBTCConfig reads and checks a Bitcoin config. Unknown fields are errors.
func LoadBTCConfig(path string) (*BTCConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c BTCConfig
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return &c, c.Validate()
}

// Validate checks the config for the network it names: every pinned address and the cold key belong to it.
func (c *BTCConfig) Validate() error {
	if c.Family != "btc" {
		return errors.New("config: family must be btc")
	}
	if _, err := btcHRP(c.Network); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	switch {
	case c.Chain == "" || c.Pool == "":
		return errors.New("config: chain and pool are required")
	case len(c.Operators) == 0 || c.Threshold < 1 || c.Threshold > len(c.Operators):
		return fmt.Errorf("config: threshold %d with %d operators", c.Threshold, len(c.Operators))
	case len(c.HotShards) == 0:
		return errors.New("config: no hot shards: a refill has nowhere to go")
	case c.MaxAmount == 0 || c.MaxFeeSats == 0 || c.MaxFeeRate == 0:
		return errors.New("config: max_amount, max_fee_sats and max_fee_rate are required")
	case c.RecordDir == "":
		return errors.New("config: record_dir is required")
	}
	if c.MaxInputs <= 0 {
		c.MaxInputs = 20
	}
	for n, k := range c.Operators {
		if b, err := hex.DecodeString(k); err != nil || len(b) != 32 {
			return fmt.Errorf("config: operator %q: public key must be 32 hex bytes", n)
		}
	}
	cold, err := c.ColdAddress()
	if err != nil {
		return err
	}
	for _, h := range c.HotShards {
		if _, err := p2wpkhHash(c.Network, h); err != nil {
			return fmt.Errorf("config: hot shard: %w", err)
		}
		if h == cold {
			return errors.New("config: a hot shard is the cold address")
		}
	}
	return nil
}

// ColdAddress is the address of the configured cold key on the configured network.
func (c *BTCConfig) ColdAddress() (string, error) {
	a, err := BTCAddressOf(c.Network, c.PublicKey)
	if err != nil {
		return "", fmt.Errorf("config: public_key: %w", err)
	}
	return a, nil
}

// Check applies every rule that needs neither the HSM nor the approvals, and returns the request's transaction. Whatever the online side sends is
// checked here against this config alone.
func (c *BTCConfig) Check(rf BTCRequestFile) (BTCRequest, *btcTx, error) {
	r := rf.Request
	if got := r.HashHex(); got != strings.ToLower(rf.RequestHash) {
		return r, nil, refuse("the request file is damaged or was changed: its hash is %s, the file says %s", got, rf.RequestHash)
	}
	if r.Version != BTCRequestVersion {
		return r, nil, refuse("request version %q, want %q", r.Version, BTCRequestVersion)
	}
	if r.Network != c.Network {
		return r, nil, refuse("request is for network %q; this signer is configured for %q", r.Network, c.Network)
	}
	if r.Chain != c.Chain {
		return r, nil, refuse("request is for chain %q; this signer is configured for %q", r.Chain, c.Chain)
	}
	if r.Pool != c.Pool {
		return r, nil, refuse("request is for pool %q, this signer holds pool %q", r.Pool, c.Pool)
	}
	cold, err := c.ColdAddress()
	if err != nil {
		return r, nil, err
	}
	if r.From != cold {
		return r, nil, refuse("request is from %s, this signer's cold address is %s", r.From, cold)
	}
	if len(r.Inputs) == 0 || len(r.Inputs) > c.MaxInputs {
		return r, nil, refuse("%d inputs; at least one and at most %d", len(r.Inputs), c.MaxInputs)
	}
	seen := map[string]bool{}
	for i, in := range r.Inputs {
		if _, err := parseTxID(in.TxID); err != nil {
			return r, nil, refuse("input %d: %v", i, err)
		}
		if in.Address != cold {
			return r, nil, refuse("input %d spends from %s; every input must be from the cold address %s", i, in.Address, cold)
		}
		if in.Value == 0 {
			return r, nil, refuse("input %d has no value", i)
		}
		k := fmt.Sprintf("%s:%d", in.TxID, in.Vout)
		if seen[k] {
			return r, nil, refuse("input %s is named twice", k)
		}
		seen[k] = true
	}
	if len(r.Outputs) < 1 || len(r.Outputs) > 2 {
		return r, nil, refuse("%d outputs; a refill has the payment and at most one change output", len(r.Outputs))
	}
	pay := r.Outputs[0]
	pinned := false
	for _, h := range c.HotShards {
		pinned = pinned || h == pay.Address
	}
	if !pinned {
		return r, nil, refuse("the payment goes to %s, which is not one of the pinned hot shards", pay.Address)
	}
	if pay.Value < btcDust || pay.Value > c.MaxAmount {
		return r, nil, refuse("the payment of %d sats is below dust or above the per-ceremony cap %d", pay.Value, c.MaxAmount)
	}
	if len(r.Outputs) == 2 {
		ch := r.Outputs[1]
		if ch.Address != cold {
			return r, nil, refuse("the change goes to %s; it must go to the cold address %s", ch.Address, cold)
		}
		if ch.Value < btcDust {
			return r, nil, refuse("the change of %d sats is dust", ch.Value)
		}
	}
	fee, err := r.Fee()
	if err != nil {
		return r, nil, refuse("%v", err)
	}
	if fee > c.MaxFeeSats {
		return r, nil, refuse("the fee of %d sats is above the cap %d", fee, c.MaxFeeSats)
	}
	vs := uint64(btcVSizeEstimate(len(r.Inputs), len(r.Outputs)))
	if fee > c.MaxFeeRate*vs {
		return r, nil, refuse("the fee of %d sats over about %d vbytes is above the rate cap of %d sat/vB", fee, vs, c.MaxFeeRate)
	}
	tx, err := r.Tx()
	if err != nil {
		return r, nil, refuse("%v", err)
	}
	return r, tx, nil
}

// CountApprovals counts distinct configured operators with a valid signature over the request hash.
func (c *BTCConfig) CountApprovals(requestHash string, approvals []Approval) (names []string, ignored []string) {
	return (&Config{Operators: c.Operators}).CountApprovals(requestHash, approvals)
}

// Sign runs the whole ceremony: Check, the approvals, the durable record of outpoints, then the signature of every input.
func (c *BTCConfig) Sign(ctx context.Context, rf BTCRequestFile, approvals []Approval, hsm DigestSigner) (BTCSigned, []string, error) {
	r, tx, err := c.Check(rf)
	if err != nil {
		return BTCSigned{}, nil, err
	}
	names, ignored := c.CountApprovals(rf.RequestHash, approvals)
	if len(names) < c.Threshold {
		return BTCSigned{}, ignored, refuse("%d valid approval(s) from distinct configured operators, %d required%s", len(names), c.Threshold, ignoredNote(ignored))
	}
	rec, err := openOutpointRecord(c.RecordDir)
	if err != nil {
		return BTCSigned{}, names, err
	}
	defer rec.close()
	if s, ok, err := rec.signedFor(rf.RequestHash); err != nil || ok {
		return s, names, err // the same request again: the same signed file
	}
	if err := rec.admit(r); err != nil {
		return BTCSigned{}, names, err
	}
	pub, err := parseCompressed(c.PublicKey)
	if err != nil {
		return BTCSigned{}, names, err
	}
	kh := hash160(pub.SerializeCompressed())
	tx.wit = make([][][]byte, len(tx.ins))
	for i := range tx.ins {
		d := tx.sighash(i, kh)
		sr, ss, err := hsm.SignDigest(ctx, d)
		if err != nil {
			return BTCSigned{}, names, fmt.Errorf("the HSM did not sign input %d: %w", i, err)
		}
		der, err := derLowS(sr, ss)
		if err != nil {
			return BTCSigned{}, names, err
		}
		if !verifyDER(der, d, pub) {
			return BTCSigned{}, names, fmt.Errorf("the HSM signature of input %d does not verify against the cold key", i)
		}
		tx.wit[i] = [][]byte{append(der, byte(btcSighash)), pub.SerializeCompressed()}
	}
	cold, _ := c.ColdAddress()
	out := BTCSigned{Version: BTCSignedVersion, RequestID: r.ID, RequestHash: rf.RequestHash, RawTx: hex.EncodeToString(tx.serialize(true)), TxID: tx.TxID(), Signer: cold}
	if err := rec.storeSigned(rf.RequestHash, out); err != nil {
		return BTCSigned{}, names, err
	}
	return out, names, nil
}

var curveN = btcec.S256().N
var halfCurveN = new(big.Int).Rsh(curveN, 1)

func derLowS(r, s *big.Int) ([]byte, error) {
	if s.Cmp(halfCurveN) > 0 {
		s = new(big.Int).Sub(curveN, s)
	}
	var rs, ss btcec.ModNScalar
	if overflow := rs.SetByteSlice(r.FillBytes(make([]byte, 32))); overflow {
		return nil, errors.New("signature r is out of range")
	}
	if overflow := ss.SetByteSlice(s.FillBytes(make([]byte, 32))); overflow {
		return nil, errors.New("signature s is out of range")
	}
	return btcecdsa.NewSignature(&rs, &ss).Serialize(), nil
}

func verifyDER(der []byte, digest [32]byte, pub *btcec.PublicKey) bool {
	sig, err := btcecdsa.ParseDERSignature(der)
	return err == nil && sig.Verify(digest[:], pub)
}

// VerifyBTCSignedMatches is what the online side runs on an imported file: the transaction inside is exactly the one the request describes (inputs,
// outputs, version, lock time, sequences), every input carries a valid signature of the cold key over the digest the request's values give, and the
// id matches. It returns the raw transaction bytes.
func VerifyBTCSignedMatches(r BTCRequest, requestHash string, s BTCSigned) ([]byte, error) {
	if s.Version != BTCSignedVersion {
		return nil, fmt.Errorf("signed file version %q, want %q", s.Version, BTCSignedVersion)
	}
	if !strings.EqualFold(s.RequestHash, requestHash) {
		return nil, fmt.Errorf("the signed file answers request hash %s; the current request has %s (it was re-exported, or this is another request)", s.RequestHash, requestHash)
	}
	want, err := r.Tx()
	if err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(s.RawTx)
	if err != nil {
		return nil, fmt.Errorf("raw_tx: %w", err)
	}
	if !bytes.HasPrefix(raw, want.serialize(false)[:4]) || len(raw) < 6 || raw[4] != 0x00 || raw[5] != 0x01 {
		return nil, errors.New("raw_tx is not a SegWit transaction of version 2")
	}
	// Strip the witnesses: what is left must be the transaction of the request, byte for byte.
	got, wit, err := splitWitness(raw, len(want.ins))
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(got, want.serialize(false)) {
		return nil, errors.New("the transaction in the signed file is not the one the request describes")
	}
	cold := r.From
	h, err := p2wpkhHash(r.Network, cold)
	if err != nil {
		return nil, err
	}
	for i, st := range wit {
		if len(st) != 2 {
			return nil, fmt.Errorf("input %d: witness has %d items, want a signature and a key", i, len(st))
		}
		pub, err := btcec.ParsePubKey(st[1])
		if err != nil || hash160(pub.SerializeCompressed()) != h {
			return nil, fmt.Errorf("input %d: the key in the witness is not the cold address's", i)
		}
		if len(st[0]) < 2 || st[0][len(st[0])-1] != btcSighash {
			return nil, fmt.Errorf("input %d: the signature does not use SIGHASH_ALL", i)
		}
		d := want.sighash(i, h)
		if !verifyDER(st[0][:len(st[0])-1], d, pub) {
			return nil, fmt.Errorf("input %d: the signature does not verify over the request's values", i)
		}
	}
	if want.TxID() != s.TxID {
		return nil, errors.New("txid does not match the request's transaction")
	}
	return raw, nil
}

// splitWitness removes the marker, flag and witnesses from a serialized transaction and returns the legacy serialization and the witness stacks.
func splitWitness(raw []byte, nIn int) ([]byte, [][][]byte, error) {
	var body []byte
	body = append(body, raw[:4]...)
	rest := raw[6:]
	// Re-walk the inputs and outputs to find where the witness starts.
	pos := 0
	readVar := func() (uint64, error) {
		if pos >= len(rest) {
			return 0, errors.New("raw_tx is truncated")
		}
		b := rest[pos]
		pos++
		switch {
		case b < 0xfd:
			return uint64(b), nil
		case b == 0xfd && pos+2 <= len(rest):
			v := binary.LittleEndian.Uint16(rest[pos:])
			pos += 2
			return uint64(v), nil
		}
		return 0, errors.New("raw_tx: unsupported length")
	}
	start := pos
	n, err := readVar()
	if err != nil || int(n) != nIn {
		return nil, nil, errors.New("raw_tx has another number of inputs than the request")
	}
	for i := 0; i < nIn; i++ {
		pos += 36
		sl, err := readVar()
		if err != nil || sl != 0 {
			return nil, nil, errors.New("raw_tx has a script in an input")
		}
		pos += 4
	}
	no, err := readVar()
	if err != nil {
		return nil, nil, err
	}
	for i := uint64(0); i < no; i++ {
		pos += 8
		sl, err := readVar()
		if err != nil {
			return nil, nil, err
		}
		pos += int(sl)
	}
	if pos > len(rest) {
		return nil, nil, errors.New("raw_tx is truncated")
	}
	body = append(body, rest[start:pos]...)
	wit := make([][][]byte, nIn)
	for i := 0; i < nIn; i++ {
		items, err := readVar()
		if err != nil {
			return nil, nil, err
		}
		for j := uint64(0); j < items; j++ {
			l, err := readVar()
			if err != nil || pos+int(l) > len(rest) {
				return nil, nil, errors.New("raw_tx witness is truncated")
			}
			wit[i] = append(wit[i], rest[pos:pos+int(l)])
			pos += int(l)
		}
	}
	if len(rest)-pos != 4 {
		return nil, nil, errors.New("raw_tx has trailing data or no lock time")
	}
	body = append(body, rest[pos:]...)
	return body, wit, nil
}

// ---- the durable record of outpoints ----

// outpointRecord is what the signer remembers about an outpoint it has signed. A BIP143 signature commits only to the value of its own input, and the
// signer has no chain: so the first value an outpoint is signed with is pinned, and a second request that gives the same outpoint another value is
// refused (otherwise a request that understates each input's value in turn gets signatures that combine into one transaction with a fee nobody saw).
// The intent pins what else may spend it: only a replacement of the same transaction, with a higher fee.
type outpointRecord struct {
	Value    uint64   `json:"value"`
	Intent   string   `json:"intent"`
	MaxFee   uint64   `json:"max_fee"`
	Requests []string `json:"requests"` // request hashes admitted for signing
}

type recordStore struct {
	dir  string
	lock *os.File
}

func openOutpointRecord(base string) (*recordStore, error) {
	dir := filepath.Join(base, "btc")
	if err := os.MkdirAll(filepath.Join(dir, "outpoints"), 0o700); err != nil {
		return nil, fmt.Errorf("record directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "signed"), 0o700); err != nil {
		return nil, fmt.Errorf("record directory: %w", err)
	}
	lock, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		lock.Close()
		return nil, err
	}
	return &recordStore{dir: dir, lock: lock}, nil
}

func (rs *recordStore) close() {
	syscall.Flock(int(rs.lock.Fd()), syscall.LOCK_UN)
	rs.lock.Close()
}

func (rs *recordStore) path(txid string, vout uint32) string {
	return filepath.Join(rs.dir, "outpoints", fmt.Sprintf("%s-%d.json", txid, vout))
}

func (rs *recordStore) load(txid string, vout uint32) (outpointRecord, bool, error) {
	b, err := os.ReadFile(rs.path(txid, vout))
	if os.IsNotExist(err) {
		return outpointRecord{}, false, nil
	}
	if err != nil {
		return outpointRecord{}, false, err
	}
	var rec outpointRecord
	return rec, true, json.Unmarshal(b, &rec)
}

func writeFileSync(path string, b []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(b)
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return werr
	}
	return os.Rename(tmp, path)
}

// admit checks the request against what was signed before and, if it may be signed, records it BEFORE the signature exists, so that a crash between
// the two can never leave a signature that the record does not know.
func (rs *recordStore) admit(r BTCRequest) error {
	fee, _ := r.Fee()
	intent, hash := r.Intent(), r.HashHex()
	type upd struct {
		in  BTCInput
		rec outpointRecord
	}
	var updates []upd
	for _, in := range r.Inputs {
		rec, ok, err := rs.load(in.TxID, in.Vout)
		if err != nil {
			return err
		}
		if !ok {
			updates = append(updates, upd{in, outpointRecord{Value: in.Value, Intent: intent, MaxFee: fee, Requests: []string{hash}}})
			continue
		}
		if rec.Value != in.Value {
			return refuse("outpoint %s:%d was signed when its value was %d sats; this request says %d. A signature commits only to the value of its own input, so a second value for a signed outpoint is refused", in.TxID, in.Vout, rec.Value, in.Value)
		}
		already := false
		for _, h := range rec.Requests {
			already = already || h == hash
		}
		if !already {
			if rec.Intent != intent {
				return refuse("outpoint %s:%d was already signed in a transaction with a different set of inputs, destination or amount; only a replacement of that same transaction (same inputs, destination and amount, higher fee) may spend it again", in.TxID, in.Vout)
			}
			if fee <= rec.MaxFee {
				return refuse("outpoint %s:%d was already signed with a fee of %d sats; a replacement must pay more than that, this one pays %d", in.TxID, in.Vout, rec.MaxFee, fee)
			}
			rec.MaxFee = fee
			rec.Requests = append(rec.Requests, hash)
		}
		updates = append(updates, upd{in, rec})
	}
	for _, u := range updates {
		b, _ := json.Marshal(u.rec)
		if err := writeFileSync(rs.path(u.in.TxID, u.in.Vout), b); err != nil {
			return fmt.Errorf("record: %w", err)
		}
	}
	return nil
}

func (rs *recordStore) signedFor(hash string) (BTCSigned, bool, error) {
	b, err := os.ReadFile(filepath.Join(rs.dir, "signed", hash+".json"))
	if os.IsNotExist(err) {
		return BTCSigned{}, false, nil
	}
	if err != nil {
		return BTCSigned{}, false, err
	}
	var s BTCSigned
	return s, true, json.Unmarshal(b, &s)
}

func (rs *recordStore) storeSigned(hash string, s BTCSigned) error {
	b, _ := json.Marshal(s)
	return writeFileSync(filepath.Join(rs.dir, "signed", hash+".json"), b)
}
