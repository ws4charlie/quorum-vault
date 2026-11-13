package coldsign

// The Solana cold signer's files and rules. The cold key is an Ed25519 key in the offline token; its address is the owner of the pool's SOL and of its token
// accounts and the authority of the nonce accounts it signs with. Every cold transaction signs the value of one of those nonce accounts (offline signing is
// what durable nonces are for): a request fixes the account and the value, so the signature never expires, and the value can be spent only once. The offline
// tool builds the message from the request's fields itself; it takes no message from the online side.
//
// Pure like the rest of the package: it uses solmsg (addresses, the message compiler) and no network client.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/btcsuite/btcd/btcutil/base58"

	"github.com/ws4charlie/quorum-vault/internal/chain/sol/solmsg"
)

// Versions of the Solana files that cross the air gap.
const (
	SOLRequestVersion = "qv-cold-request-sol-v1"
	SOLSignedVersion  = "qv-refill-signed-sol-v1"
	solContentTag     = "qv-refill-content-hash-sol-v1\n"
	solRequestTag     = "qv-refill-request-hash-sol-v1\n"
)

// SOLRequest is a refill from the pool's cold address to one of its hot shards, as the online side exports it and the operators approve it.
type SOLRequest struct {
	Version  string `json:"version"`
	ID       string `json:"id"`
	Revision int    `json:"revision"` // grows with every re-export (a higher priority price)
	Chain    string `json:"chain"`
	Pool     string `json:"pool"`
	Asset    string `json:"asset"`
	Mint     string `json:"mint,omitempty"` // the SPL token's mint; empty for SOL
	Decimals int    `json:"decimals"`
	From     string `json:"from"`   // the cold address
	To       string `json:"to"`     // the hot shard that receives the funds
	Amount   string `json:"amount"` // base units, decimal

	// The nonce account of the cold address that carries this request and the value it holds: the message's blockhash.
	NonceAccount string `json:"nonce_account"`
	NonceValue   string `json:"nonce_value"`

	ComputeUnitLimit uint32 `json:"compute_unit_limit"`
	ComputeUnitPrice uint64 `json:"compute_unit_price"` // micro-lamports per unit; 0 for none
	// CreateDestAccount makes the cold address open the hot shard's associated token account first (rent from the cold address); for a token only.
	CreateDestAccount bool `json:"create_dest_account,omitempty"`
}

// SOLRequestFile is what is carried to the offline machine: the request and its hash.
type SOLRequestFile struct {
	Request     SOLRequest `json:"request"`
	RequestHash string     `json:"request_hash"`
}

// SOLSigned is what comes back: the signed transaction of one request.
type SOLSigned struct {
	Version     string `json:"version"`
	RequestID   string `json:"request_id"`
	RequestHash string `json:"request_hash"`
	RawTx       string `json:"raw_tx"`  // hex: one signature and the message
	TxHash      string `json:"tx_hash"` // the signature, base58
	Signer      string `json:"signer"`  // the cold address that signed
}

// IsSOLRequest reports whether a request file's JSON is a Solana request.
func IsSOLRequest(raw []byte) bool {
	var v struct {
		Request struct {
			Version string `json:"version"`
		} `json:"request"`
	}
	return json.Unmarshal(raw, &v) == nil && v.Request.Version == SOLRequestVersion
}

func (r SOLRequest) fields() []string {
	return []string{r.Version, r.ID, strconv.Itoa(r.Revision), r.Chain, r.Pool, r.Asset, r.Mint, strconv.Itoa(r.Decimals), r.From, r.To, r.Amount, r.NonceAccount,
		r.NonceValue, strconv.FormatUint(uint64(r.ComputeUnitLimit), 10), strconv.FormatUint(r.ComputeUnitPrice, 10), strconv.FormatBool(r.CreateDestAccount)}
}

// Hash is what operators approve: every field, length-prefixed, under a domain tag.
func (r SOLRequest) Hash() [32]byte {
	b := []byte(solRequestTag)
	for _, f := range r.fields() {
		b = lp(b, f)
	}
	return sha256.Sum256(b)
}

// HashHex is Hash in hex.
func (r SOLRequest) HashHex() string { h := r.Hash(); return hex.EncodeToString(h[:]) }

// File wraps the request with its hash.
func (r SOLRequest) File() SOLRequestFile {
	return SOLRequestFile{Request: r, RequestHash: r.HashHex()}
}

// ContentHash identifies WHAT the request moves at which nonce value, without the fee: two requests with the same content are the same payment on the same
// nonce (a re-export with a higher price), so signing both cannot pay twice; the nonce lets only one land anyway.
func (r SOLRequest) ContentHash() string {
	b := []byte(solContentTag)
	for _, f := range []string{r.Chain, r.Asset, r.Mint, r.From, r.To, r.Amount, r.NonceAccount, r.NonceValue, strconv.FormatBool(r.CreateDestAccount)} {
		b = lp(b, f)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func solAddr(what, s string) ([32]byte, error) {
	a, err := solmsg.ParseAddress(s)
	if err != nil {
		return a, fmt.Errorf("%s: %w", what, err)
	}
	if a == ([32]byte{}) {
		return a, fmt.Errorf("%s is the system program address", what)
	}
	return a, nil
}

// Message builds the legacy message the request describes: the nonce advance first (authority the cold address, which also pays), the compute budget, an
// optional creation of the hot shard's token account, and the transfer.
func (r SOLRequest) Message() ([]byte, error) {
	if r.Version != SOLRequestVersion {
		return nil, fmt.Errorf("request version %q, want %q", r.Version, SOLRequestVersion)
	}
	from, err := solAddr("from", r.From)
	if err != nil {
		return nil, err
	}
	to, err := solAddr("to", r.To)
	if err != nil {
		return nil, err
	}
	if from == to {
		return nil, errors.New("the cold address cannot pay itself")
	}
	nonce, err := solAddr("nonce account", r.NonceAccount)
	if err != nil {
		return nil, err
	}
	value, err := solAddr("nonce value", r.NonceValue)
	if err != nil {
		return nil, err
	}
	amount, err := parseAmt("amount", r.Amount)
	if err != nil {
		return nil, err
	}
	if amount.Sign() == 0 || !amount.IsUint64() {
		return nil, errors.New("amount is zero or above 2^64-1")
	}
	if r.ComputeUnitLimit == 0 {
		return nil, errors.New("compute unit limit is zero")
	}
	ixs := []solmsg.Ix{solmsg.AdvanceNonceIx(nonce, from), solmsg.SetLimitIx(r.ComputeUnitLimit)}
	if r.ComputeUnitPrice > 0 {
		ixs = append(ixs, solmsg.SetPriceIx(r.ComputeUnitPrice))
	}
	if r.Mint == "" {
		if r.CreateDestAccount {
			return nil, errors.New("a SOL refill opens no token account")
		}
		ixs = append(ixs, solmsg.TransferIx(from, to, amount.Uint64()))
	} else {
		mint, err := solAddr("mint", r.Mint)
		if err != nil {
			return nil, err
		}
		src, err := solmsg.ATA(from, mint)
		if err != nil {
			return nil, err
		}
		dst, err := solmsg.ATA(to, mint)
		if err != nil {
			return nil, err
		}
		if r.CreateDestAccount {
			ixs = append(ixs, solmsg.CreateATAIx(from, dst, to, mint))
		}
		if r.Decimals < 0 || r.Decimals > 18 {
			return nil, errors.New("decimals out of range")
		}
		ixs = append(ixs, solmsg.CheckedTransferIx(src, mint, dst, from, amount.Uint64(), uint8(r.Decimals)))
	}
	return solmsg.Compile(from, value, ixs...), nil
}

// Summary is the human-readable statement operators check.
func (r SOLRequest) Summary(decimals int) string {
	amt, _ := new(big.Int).SetString(r.Amount, 10)
	kind := "SOL"
	if r.Mint != "" {
		kind = r.Asset + " (token " + r.Mint + ")"
	}
	prio := new(big.Int).Div(new(big.Int).Mul(new(big.Int).SetUint64(uint64(r.ComputeUnitLimit)), new(big.Int).SetUint64(r.ComputeUnitPrice)), big.NewInt(1_000_000))
	var b strings.Builder
	fmt.Fprintf(&b, "  request   %s (revision %d)\n", r.ID, r.Revision)
	fmt.Fprintf(&b, "  chain     %s, pool %s\n", r.Chain, r.Pool)
	fmt.Fprintf(&b, "  from      %s (the cold address)\n", r.From)
	fmt.Fprintf(&b, "  to        %s (a hot shard)\n", r.To)
	fmt.Fprintf(&b, "  asset     %s\n", kind)
	fmt.Fprintf(&b, "  amount    %s (%s base units)\n", Human(amt, decimals), r.Amount)
	fmt.Fprintf(&b, "  nonce     account %s, value %s\n", r.NonceAccount, r.NonceValue)
	fmt.Fprintf(&b, "  fee       the base fee and at most %s lamports of priority (%d units at %d micro-lamports each)\n", prio, r.ComputeUnitLimit, r.ComputeUnitPrice)
	if r.CreateDestAccount {
		fmt.Fprintf(&b, "  also      opens the hot shard's token account, rent paid by the cold address\n")
	}
	return b.String()
}

// SOLAssetPolicy is what the offline config allows for one asset.
type SOLAssetPolicy struct {
	Mint      string `json:"mint,omitempty"` // empty for SOL
	Decimals  int    `json:"decimals"`
	MaxAmount string `json:"max_amount"` // the per-ceremony cap, base units
}

// SOLConfig is the offline tool's own configuration for a Solana pool: the only trust root of a signature.
type SOLConfig struct {
	Family string `json:"family"` // "sol"
	Chain  string `json:"chain"`
	Pool   string `json:"pool"`
	// Operators and Threshold: M-of-N enforced in software with Ed25519 signatures, as in the other configs.
	Operators map[string]string `json:"operators"`
	Threshold int               `json:"threshold"`
	// Destinations are the only addresses a refill may pay: the pool's hot shards.
	Destinations []string                  `json:"destinations"`
	Assets       map[string]SOLAssetPolicy `json:"assets"`
	// NoncePool is how many nonce accounts (solmsg.NonceAddress of the cold address, index 0 up) a request may name.
	NoncePool int `json:"nonce_pool"`
	// MaxComputeUnits caps the limit, MaxMicroLamports the price, MaxPriorityLamports their product.
	MaxComputeUnits     uint32    `json:"max_compute_units"`
	MaxMicroLamports    uint64    `json:"max_micro_lamports"`
	MaxPriorityLamports uint64    `json:"max_priority_lamports"`
	PublicKey           string    `json:"public_key"` // the cold key, 32 bytes, hex
	HSM                 HSMConfig `json:"hsm"`
	RecordDir           string    `json:"record_dir"` // durable record of every nonce value ever signed
}

// IsSOLConfig reports whether a config file's JSON is a Solana config.
func IsSOLConfig(raw []byte) bool {
	var v struct {
		Family string `json:"family"`
	}
	return json.Unmarshal(raw, &v) == nil && v.Family == "sol"
}

// LoadSOLConfig reads and checks a Solana config. Unknown fields are errors.
func LoadSOLConfig(path string) (*SOLConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c SOLConfig
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return &c, c.Validate()
}

// ColdAddress is the address of the configured cold key.
func (c *SOLConfig) ColdAddress() (string, error) {
	pub, err := hex.DecodeString(c.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return "", errors.New("config: public_key must be 32 bytes of hex")
	}
	return base58.Encode(pub), nil
}

// Validate checks the config is usable and sane.
func (c *SOLConfig) Validate() error {
	if c.Family != "sol" {
		return errors.New("config: family must be sol")
	}
	switch {
	case c.Chain == "" || c.Pool == "":
		return errors.New("config: chain and pool are required")
	case len(c.Operators) == 0 || c.Threshold < 1 || c.Threshold > len(c.Operators):
		return fmt.Errorf("config: threshold %d with %d operators", c.Threshold, len(c.Operators))
	case len(c.Destinations) == 0:
		return errors.New("config: no destinations: a refill has nowhere to go")
	case len(c.Assets) == 0:
		return errors.New("config: no assets")
	case c.NoncePool < 1 || c.NoncePool > 64:
		return errors.New("config: nonce_pool must be 1 to 64")
	case c.MaxComputeUnits == 0 || c.MaxMicroLamports == 0 || c.MaxPriorityLamports == 0:
		return errors.New("config: max_compute_units, max_micro_lamports and max_priority_lamports are required")
	case c.RecordDir == "":
		return errors.New("config: record_dir is required")
	}
	for n, k := range c.Operators {
		if b, err := hex.DecodeString(k); err != nil || len(b) != ed25519.PublicKeySize {
			return fmt.Errorf("config: operator %q: public key must be %d hex bytes", n, ed25519.PublicKeySize)
		}
	}
	cold, err := c.ColdAddress()
	if err != nil {
		return err
	}
	for _, d := range c.Destinations {
		if _, err := solAddr("destination", d); err != nil {
			return fmt.Errorf("config: %w", err)
		}
		if d == cold {
			return errors.New("config: a destination is the cold address")
		}
	}
	for a, p := range c.Assets {
		if _, err := parseAmt(a+" max_amount", p.MaxAmount); err != nil {
			return fmt.Errorf("config: %w", err)
		}
		if p.Mint != "" {
			if _, err := solAddr(a+" mint", p.Mint); err != nil {
				return fmt.Errorf("config: %w", err)
			}
		}
	}
	return nil
}

// Check applies every rule that needs neither the HSM nor the approvals, and returns the request's message. Whatever the online side sends is checked here
// against this config alone.
func (c *SOLConfig) Check(rf SOLRequestFile) (SOLRequest, []byte, error) {
	r := rf.Request
	if rf.RequestHash != r.HashHex() {
		return r, nil, refuse("the request file is damaged: its hash does not match its content")
	}
	if r.Version != SOLRequestVersion {
		return r, nil, refuse("request version %q, this tool signs %q", r.Version, SOLRequestVersion)
	}
	if r.Chain != c.Chain || r.Pool != c.Pool {
		return r, nil, refuse("the request is for chain %q pool %q, this tool is configured for %q %q", r.Chain, r.Pool, c.Chain, c.Pool)
	}
	cold, err := c.ColdAddress()
	if err != nil {
		return r, nil, err
	}
	if r.From != cold {
		return r, nil, refuse("the request pays from %s, this tool's cold key is %s", r.From, cold)
	}
	pinned := false
	for _, d := range c.Destinations {
		pinned = pinned || d == r.To
	}
	if !pinned {
		return r, nil, refuse("%s is not one of this pool's hot shards; a refill may only go to them", r.To)
	}
	pol, ok := c.Assets[r.Asset]
	if !ok {
		return r, nil, refuse("asset %q is not configured", r.Asset)
	}
	if r.Mint != pol.Mint || r.Decimals != pol.Decimals {
		return r, nil, refuse("asset %s is mint %q with %d decimals in the config, the request says %q and %d", r.Asset, pol.Mint, pol.Decimals, r.Mint, r.Decimals)
	}
	amount, err := parseAmt("amount", r.Amount)
	if err != nil {
		return r, nil, refuse("%v", err)
	}
	max, _ := parseAmt("max_amount", pol.MaxAmount)
	if amount.Sign() == 0 || amount.Cmp(max) > 0 {
		return r, nil, refuse("amount %s is zero or above the per-ceremony cap %s", amount, max)
	}
	coldKey, _ := solmsg.ParseAddress(cold)
	okNonce := false
	for i := 0; i < c.NoncePool; i++ {
		okNonce = okNonce || solmsg.Address(solmsg.NonceAddress(coldKey, i)) == r.NonceAccount
	}
	if !okNonce {
		return r, nil, refuse("%s is not a nonce account of the cold address (accounts 0 to %d, derived from it)", r.NonceAccount, c.NoncePool-1)
	}
	if r.ComputeUnitLimit == 0 || r.ComputeUnitLimit > c.MaxComputeUnits || r.ComputeUnitPrice > c.MaxMicroLamports {
		return r, nil, refuse("compute unit limit %d / price %d is outside the caps %d / %d", r.ComputeUnitLimit, r.ComputeUnitPrice, c.MaxComputeUnits, c.MaxMicroLamports)
	}
	prio := new(big.Int).Div(new(big.Int).Mul(new(big.Int).SetUint64(uint64(r.ComputeUnitLimit)), new(big.Int).SetUint64(r.ComputeUnitPrice)), big.NewInt(1_000_000))
	if prio.Cmp(new(big.Int).SetUint64(c.MaxPriorityLamports)) > 0 {
		return r, nil, refuse("the priority fee of %s lamports is above the cap %d", prio, c.MaxPriorityLamports)
	}
	if r.CreateDestAccount && r.Mint == "" {
		return r, nil, refuse("a SOL refill opens no token account")
	}
	msg, err := r.Message()
	if err != nil {
		return r, nil, refuse("%v", err)
	}
	return r, msg, nil
}

// CountApprovals counts the distinct configured operators whose signature over requestHash verifies.
func (c *SOLConfig) CountApprovals(requestHash string, approvals []Approval) (names []string, ignored []string) {
	return countApprovals(c.Operators, requestHash, approvals)
}

func countApprovals(ops map[string]string, requestHash string, approvals []Approval) (names []string, ignored []string) {
	seen := map[string]bool{}
	for _, a := range approvals {
		pubHex, ok := ops[a.Operator]
		switch {
		case a.RequestHash != "" && !strings.EqualFold(a.RequestHash, requestHash):
			ignored = append(ignored, a.Operator+": signed another request")
			continue
		case !ok:
			ignored = append(ignored, fmt.Sprintf("%q: not a configured operator", a.Operator))
			continue
		case seen[a.Operator]:
			ignored = append(ignored, a.Operator+": counted once already")
			continue
		}
		pub, _ := hex.DecodeString(pubHex)
		sig, err := hex.DecodeString(a.Signature)
		if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(pub), ApprovalMessage(requestHash), sig) {
			ignored = append(ignored, a.Operator+": signature does not verify")
			continue
		}
		seen[a.Operator] = true
		names = append(names, a.Operator)
	}
	return names, ignored
}

// MessageSigner signs a whole message with the cold key (the HSM, or a key in a test).
type MessageSigner interface {
	SignMessage(ctx context.Context, msg []byte) ([]byte, error)
}

// Sign runs the whole ceremony check and signs: Check, the approvals, the durable record of nonce values, the signature itself. The nonce value is the
// record's key: a value may be signed for one content only, and again for the same content only with a higher priority price (a replacement), so that
// whichever version lands, the value is spent on the one payment the operators approved.
func (c *SOLConfig) Sign(ctx context.Context, rf SOLRequestFile, approvals []Approval, hsm MessageSigner) (SOLSigned, []string, error) {
	r, msg, err := c.Check(rf)
	if err != nil {
		return SOLSigned{}, nil, err
	}
	names, ignored := c.CountApprovals(rf.RequestHash, approvals)
	if len(names) < c.Threshold {
		return SOLSigned{}, ignored, refuse("%d valid approval(s) from distinct configured operators, %d required%s", len(names), c.Threshold, ignoredNote(ignored))
	}
	rs, err := openNonceRecord(c.RecordDir)
	if err != nil {
		return SOLSigned{}, names, err
	}
	defer rs.close()
	if s, ok, err := rs.signedFor(rf.RequestHash); err != nil || ok {
		return s, names, err // the same request again: the same signed file
	}
	if err := rs.admit(r); err != nil {
		return SOLSigned{}, names, err
	}
	sig, err := hsm.SignMessage(ctx, msg)
	if err != nil {
		return SOLSigned{}, names, fmt.Errorf("the HSM did not sign: %w", err)
	}
	pub, _ := hex.DecodeString(c.PublicKey)
	if !ed25519.Verify(pub, msg, sig) {
		return SOLSigned{}, names, errors.New("the HSM signature does not verify against the cold key")
	}
	raw := append(append([]byte{1}, sig...), msg...)
	cold, _ := c.ColdAddress()
	out := SOLSigned{Version: SOLSignedVersion, RequestID: r.ID, RequestHash: rf.RequestHash, RawTx: hex.EncodeToString(raw), TxHash: base58.Encode(sig), Signer: cold}
	if err := rs.storeSigned(rf.RequestHash, out); err != nil {
		return SOLSigned{}, names, err
	}
	return out, names, nil
}

// VerifySOLSignedMatches is the online side's check of a signed file: its transaction is exactly the message the request describes, signed by the cold
// address. It returns the raw transaction to broadcast.
func VerifySOLSignedMatches(r SOLRequest, requestHash string, s SOLSigned) ([]byte, error) {
	if s.Version != SOLSignedVersion || !strings.EqualFold(s.RequestHash, requestHash) || s.RequestID != r.ID {
		return nil, errors.New("the signed file is for another request")
	}
	raw, err := hex.DecodeString(s.RawTx)
	if err != nil || len(raw) < 1+64+3 || raw[0] != 1 {
		return nil, errors.New("the signed transaction is not one signature and a message")
	}
	msg, err := r.Message()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(raw[65:], msg) {
		return nil, errors.New("the signed transaction is not the message of the request")
	}
	from, err := solmsg.ParseAddress(r.From)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(from[:], msg, raw[1:65]) {
		return nil, errors.New("the signature is not the cold address's over the message")
	}
	if s.TxHash != base58.Encode(raw[1:65]) || s.Signer != r.From {
		return nil, errors.New("the signed file names another signature or signer than its transaction")
	}
	return raw, nil
}

// ---- the record of nonce values ----

type nonceRecord struct {
	Content  string   `json:"content"`
	MaxPrice uint64   `json:"max_price"`
	Requests []string `json:"requests"`
}

type nonceStore struct {
	dir  string
	lock *os.File
}

func openNonceRecord(base string) (*nonceStore, error) {
	dir := filepath.Join(base, "sol")
	for _, d := range []string{"nonces", "signed"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
			return nil, fmt.Errorf("record directory: %w", err)
		}
	}
	lock, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		lock.Close()
		return nil, err
	}
	return &nonceStore{dir: dir, lock: lock}, nil
}

func (ns *nonceStore) close() {
	syscall.Flock(int(ns.lock.Fd()), syscall.LOCK_UN)
	ns.lock.Close()
}

func (ns *nonceStore) path(r SOLRequest) string {
	return filepath.Join(ns.dir, "nonces", r.NonceAccount+"-"+r.NonceValue+".json")
}

// admit records the request BEFORE the signature exists, so a crash between the two can never leave a signature the record does not know.
func (ns *nonceStore) admit(r SOLRequest) error {
	b, err := os.ReadFile(ns.path(r))
	hash, content := r.HashHex(), r.ContentHash()
	var rec nonceRecord
	switch {
	case os.IsNotExist(err):
		rec = nonceRecord{Content: content, MaxPrice: r.ComputeUnitPrice, Requests: []string{hash}}
	case err != nil:
		return err
	default:
		if err := json.Unmarshal(b, &rec); err != nil {
			return err
		}
		if rec.Content != content {
			return refuse("nonce account %s at value %s was already signed for a different payment; a nonce value is spent once, so only a replacement of that same payment (same amount and destination, a higher price) may use it again", r.NonceAccount, r.NonceValue)
		}
		if r.ComputeUnitPrice <= rec.MaxPrice {
			return refuse("this nonce value was already signed at a priority price of %d micro-lamports; a replacement must pay more, this one asks %d", rec.MaxPrice, r.ComputeUnitPrice)
		}
		rec.MaxPrice = r.ComputeUnitPrice
		rec.Requests = append(rec.Requests, hash)
	}
	out, _ := json.Marshal(rec)
	if err := writeFileSync(ns.path(r), out); err != nil {
		return fmt.Errorf("record: %w", err)
	}
	return nil
}

func (ns *nonceStore) signedFor(hash string) (SOLSigned, bool, error) {
	b, err := os.ReadFile(filepath.Join(ns.dir, "signed", hash+".json"))
	if os.IsNotExist(err) {
		return SOLSigned{}, false, nil
	}
	if err != nil {
		return SOLSigned{}, false, err
	}
	var s SOLSigned
	return s, true, json.Unmarshal(b, &s)
}

func (ns *nonceStore) storeSigned(hash string, s SOLSigned) error {
	b, _ := json.Marshal(s)
	return writeFileSync(filepath.Join(ns.dir, "signed", hash+".json"), b)
}
