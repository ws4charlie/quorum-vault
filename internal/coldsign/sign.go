package coldsign

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// Refusal is a request the offline tool will not sign. Its text says why, in words an operator can read.
type Refusal struct{ Reason string }

func (r *Refusal) Error() string { return "refused: " + r.Reason }

func refuse(format string, args ...any) error { return &Refusal{Reason: fmt.Sprintf(format, args...)} }

// AssetPolicy is what the offline config allows for one asset.
type AssetPolicy struct {
	Token     string `json:"token,omitempty"` // ERC-20 contract; empty for the native asset
	Decimals  int    `json:"decimals"`
	MaxAmount string `json:"max_amount"` // the per-ceremony cap, base units
}

// HSMConfig locates the cold key. The PIN is never in this file.
type HSMConfig struct {
	Lib    string `json:"lib"`
	Token  string `json:"token"`   // "qv-cold"
	PinEnv string `json:"pin_env"` // environment variable holding the user PIN
	KeyID  string `json:"key_id"`  // CKA_ID, hex
}

// Config is the offline tool's own configuration. It is the only trust root for a signature: nothing the online side sends
// can widen it.
type Config struct {
	Chain   string `json:"chain"`
	ChainID uint64 `json:"chain_id"`
	Pool    string `json:"pool"`
	// Operators are the people who may approve (name -> Ed25519 public key, hex); Threshold of them must, all different. SoftHSM
	// cannot enforce M-of-N with cards the way a real HSM does, so this tool enforces it in software with these signatures.
	Operators map[string]string `json:"operators"`
	Threshold int               `json:"threshold"`
	// Destinations are the only addresses a refill may go to: the hot addresses.
	Destinations []string               `json:"destinations"`
	Assets       map[string]AssetPolicy `json:"assets"`
	MaxFeeWei    string                 `json:"max_fee_wei"` // cap on gas x max fee per gas
	PublicKey    string                 `json:"public_key"`  // the cold key, 65-byte uncompressed, hex
	HSM          HSMConfig              `json:"hsm"`
	RecordDir    string                 `json:"record_dir"` // durable record of what was signed at which nonce
}

// LoadConfig reads and checks a config file. Unknown fields are errors.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return &c, c.Validate()
}

// Validate checks the config is usable and sane.
func (c *Config) Validate() error {
	switch {
	case c.Chain == "" || c.ChainID == 0 || c.Pool == "":
		return errors.New("config: chain, chain_id and pool are required")
	case len(c.Operators) == 0 || c.Threshold < 1 || c.Threshold > len(c.Operators):
		return fmt.Errorf("config: threshold %d with %d operators", c.Threshold, len(c.Operators))
	case len(c.Destinations) == 0:
		return errors.New("config: no destinations: a refill has nowhere to go")
	case len(c.Assets) == 0:
		return errors.New("config: no assets")
	case c.RecordDir == "":
		return errors.New("config: record_dir is required")
	}
	for n, k := range c.Operators {
		if b, err := hex.DecodeString(k); err != nil || len(b) != ed25519.PublicKeySize {
			return fmt.Errorf("config: operator %q: public key must be %d hex bytes", n, ed25519.PublicKeySize)
		}
	}
	for _, d := range c.Destinations {
		if _, err := parseAddr("destination", d); err != nil {
			return fmt.Errorf("config: %w", err)
		}
	}
	for a, p := range c.Assets {
		if _, err := parseAmt(a+" max_amount", p.MaxAmount); err != nil {
			return fmt.Errorf("config: %w", err)
		}
		if p.Token != "" {
			if _, err := parseAddr(a+" token", p.Token); err != nil {
				return fmt.Errorf("config: %w", err)
			}
		}
	}
	if _, err := parseAmt("max_fee_wei", c.MaxFeeWei); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if _, err := c.ColdAddress(); err != nil {
		return err
	}
	return nil
}

// ColdAddress is the address of the configured cold key.
func (c *Config) ColdAddress() (common.Address, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(c.PublicKey, "0x"))
	if err != nil {
		return common.Address{}, fmt.Errorf("config: public_key: %w", err)
	}
	pub, err := crypto.UnmarshalPubkey(b)
	if err != nil {
		return common.Address{}, fmt.Errorf("config: public_key: %w", err)
	}
	return crypto.PubkeyToAddress(*pub), nil
}

// Check applies every rule that does not need the HSM or the approvals, and returns the request's transaction. These are the
// rules that make the online side untrusted: whatever it sends, it is checked against this config.
func (c *Config) Check(rf RequestFile) (Request, *types.Transaction, error) {
	r := rf.Request
	if got := r.HashHex(); got != strings.ToLower(rf.RequestHash) {
		return r, nil, refuse("the request file is damaged or was changed: its hash is %s, the file says %s", got, rf.RequestHash)
	}
	if r.Version != RequestVersion {
		return r, nil, refuse("request version %q, want %q", r.Version, RequestVersion)
	}
	if r.ChainID != c.ChainID || r.Chain != c.Chain {
		return r, nil, refuse("request is for chain %q (id %d); this signer is configured for %q (id %d)", r.Chain, r.ChainID, c.Chain, c.ChainID)
	}
	if r.Pool != c.Pool {
		return r, nil, refuse("request is for pool %q, this signer holds pool %q", r.Pool, c.Pool)
	}
	cold, err := c.ColdAddress()
	if err != nil {
		return r, nil, err
	}
	if from, err := parseAddr("from", r.From); err != nil || from != cold {
		return r, nil, refuse("request is from %s, this signer's cold address is %s", r.From, cold)
	}
	to, err := parseAddr("destination", r.To)
	if err != nil {
		return r, nil, refuse("%v", err)
	}
	pinned := false
	for _, d := range c.Destinations {
		if common.HexToAddress(d) == to {
			pinned = true
		}
	}
	if !pinned {
		return r, nil, refuse("destination %s is not one of the pinned hot addresses", to)
	}
	pol, ok := c.Assets[r.Asset]
	if !ok {
		return r, nil, refuse("asset %q is not configured", r.Asset)
	}
	if !strings.EqualFold(pol.Token, r.Token) {
		return r, nil, refuse("asset %s is token %q here, the request says %q", r.Asset, pol.Token, r.Token)
	}
	amount, err := parseAmt("amount", r.Amount)
	if err != nil {
		return r, nil, refuse("%v", err)
	}
	max, _ := parseAmt("max_amount", pol.MaxAmount)
	if amount.Sign() == 0 || amount.Cmp(max) > 0 {
		return r, nil, refuse("amount %s %s is zero or above the per-ceremony cap %s", Human(amount, pol.Decimals), r.Asset, Human(max, pol.Decimals))
	}
	tx, err := r.Tx()
	if err != nil {
		return r, nil, refuse("%v", err)
	}
	maxFee, _ := parseAmt("max_fee_wei", c.MaxFeeWei)
	if worst := new(big.Int).Mul(tx.GasFeeCap(), new(big.Int).SetUint64(tx.Gas())); worst.Cmp(maxFee) > 0 {
		return r, nil, refuse("the fee could reach %s wei, above the cap %s", worst, maxFee)
	}
	return r, tx, nil
}

// CountApprovals counts distinct configured operators with a valid signature over the request hash. It reports who counted,
// and why others did not.
func (c *Config) CountApprovals(requestHash string, approvals []Approval) (names []string, ignored []string) {
	seen := map[string]bool{}
	for _, a := range approvals {
		pubHex, ok := c.Operators[a.Operator]
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
	sort.Strings(names)
	return names, ignored
}

// Approve signs requestHash with an operator's key.
func Approve(operator string, key ed25519.PrivateKey, requestHash string) Approval {
	return Approval{RequestHash: requestHash, Operator: operator, Signature: hex.EncodeToString(ed25519.Sign(key, ApprovalMessage(requestHash)))}
}

// DigestSigner signs a 32-byte digest with the cold key (the HSM, or a key in a test).
type DigestSigner interface {
	SignDigest(ctx context.Context, digest [32]byte) (r, s *big.Int, err error)
}

// Sign runs the whole ceremony check and signs: Check, the approvals, the durable nonce record, the signature itself.
func (c *Config) Sign(ctx context.Context, rf RequestFile, approvals []Approval, hsm DigestSigner) (Signed, []string, error) {
	r, tx, err := c.Check(rf)
	if err != nil {
		return Signed{}, nil, err
	}
	names, ignored := c.CountApprovals(rf.RequestHash, approvals)
	if len(names) < c.Threshold {
		return Signed{}, ignored, refuse("%d valid approval(s) from distinct configured operators, %d required%s", len(names), c.Threshold, ignoredNote(ignored))
	}
	rec, err := openRecord(c.RecordDir, c.Chain, r)
	if err != nil {
		return Signed{}, ignored, err
	}
	if s, ok, err := rec.signedFor(r); err != nil || ok {
		return s, names, err // the same request again: the same signed file, never a second signature
	}
	signer := types.LatestSignerForChainID(tx.ChainId())
	digest := signer.Hash(tx)
	sr, ss, err := hsm.SignDigest(ctx, digest)
	if err != nil {
		return Signed{}, names, fmt.Errorf("the HSM did not sign: %w", err)
	}
	cold, _ := c.ColdAddress()
	signed, err := assemble(tx, signer, digest, sr, ss, cold)
	if err != nil {
		return Signed{}, names, err
	}
	if from, err := types.Sender(signer, signed); err != nil || from != cold {
		return Signed{}, names, fmt.Errorf("the signature does not recover to the cold address %s (got %v, %v)", cold, from, err)
	}
	raw, err := signed.MarshalBinary()
	if err != nil {
		return Signed{}, names, err
	}
	out := Signed{Version: SignedVersion, RequestID: r.ID, RequestHash: rf.RequestHash, RawTx: hex.EncodeToString(raw), TxHash: signed.Hash().Hex(), Signer: cold.Hex()}
	if err := rec.store(r, out); err != nil {
		return Signed{}, names, err
	}
	return out, names, nil
}

func ignoredNote(ignored []string) string {
	if len(ignored) == 0 {
		return ""
	}
	return " (not counted: " + strings.Join(ignored, "; ") + ")"
}

var halfN = new(big.Int).Rsh(crypto.S256().Params().N, 1)

// assemble turns (r, s) into a signed transaction: low-S, and the recovery id for which the signature recovers to want.
func assemble(tx *types.Transaction, signer types.Signer, digest [32]byte, r, s *big.Int, want common.Address) (*types.Transaction, error) {
	if s.Cmp(halfN) > 0 {
		s = new(big.Int).Sub(crypto.S256().Params().N, s)
	}
	sig := make([]byte, 65)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:64])
	for v := byte(0); v < 2; v++ {
		sig[64] = v
		if pub, err := crypto.SigToPub(digest[:], sig); err == nil && crypto.PubkeyToAddress(*pub) == want {
			t, err := tx.WithSignature(signer, sig)
			if err != nil {
				return nil, err
			}
			return t, nil
		}
	}
	return nil, fmt.Errorf("the HSM signature does not recover to %s with either recovery id", want)
}

// VerifySignedMatches is what the online side runs on an imported file: the transaction inside is exactly the one the request
// describes, signed by the cold address. It returns the decoded transaction.
func VerifySignedMatches(r Request, requestHash string, s Signed) (*types.Transaction, error) {
	if s.Version != SignedVersion {
		return nil, fmt.Errorf("signed file version %q, want %q", s.Version, SignedVersion)
	}
	if !strings.EqualFold(s.RequestHash, requestHash) {
		return nil, fmt.Errorf("the signed file answers request hash %s; the current request has %s (it was re-exported, or this is another request)", s.RequestHash, requestHash)
	}
	want, err := r.Tx()
	if err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(s.RawTx, "0x"))
	if err != nil {
		return nil, fmt.Errorf("raw_tx: %w", err)
	}
	got := new(types.Transaction)
	if err := got.UnmarshalBinary(raw); err != nil {
		return nil, fmt.Errorf("raw_tx: %w", err)
	}
	if got.Type() != types.DynamicFeeTxType || got.ChainId().Cmp(want.ChainId()) != 0 || got.Nonce() != want.Nonce() || got.Gas() != want.Gas() ||
		got.GasFeeCap().Cmp(want.GasFeeCap()) != 0 || got.GasTipCap().Cmp(want.GasTipCap()) != 0 || got.Value().Cmp(want.Value()) != 0 ||
		got.To() == nil || want.To() == nil || *got.To() != *want.To() || common.Bytes2Hex(got.Data()) != common.Bytes2Hex(want.Data()) || len(got.AccessList()) != 0 {
		return nil, errors.New("the transaction in the signed file is not the one the request describes")
	}
	from, err := types.Sender(types.LatestSignerForChainID(got.ChainId()), got)
	if err != nil {
		return nil, fmt.Errorf("sender: %w", err)
	}
	if from != common.HexToAddress(r.From) {
		return nil, fmt.Errorf("the transaction is signed by %s, not by the cold address %s", from, r.From)
	}
	if !strings.EqualFold(got.Hash().Hex(), s.TxHash) {
		return nil, errors.New("tx_hash does not match raw_tx")
	}
	return got, nil
}

var _ = ecdsa.PublicKey{}

// ---- the durable record ----

// record keeps, per nonce, what content was signed there, so a second request for the same nonce with different content is
// refused even after a restart. Files are created exclusively and fsynced.
type record struct{ dir string }

func openRecord(base, chain string, r Request) (*record, error) {
	dir := filepath.Join(base, fmt.Sprintf("%s-%s-%d", chain, strings.ToLower(r.From), r.Nonce))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("record directory: %w", err)
	}
	content := r.ContentHash()
	p := filepath.Join(dir, "content")
	f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	switch {
	case err == nil:
		_, werr := f.WriteString(content)
		if werr == nil {
			werr = f.Sync()
		}
		f.Close()
		if werr != nil {
			return nil, werr
		}
	case os.IsExist(err):
		prev, rerr := os.ReadFile(p)
		if rerr != nil {
			return nil, rerr
		}
		if string(prev) != content {
			return nil, refuse("nonce %d of %s was already signed for different content (recorded %s…, this request %s…); a nonce is signed once", r.Nonce, r.From, string(prev)[:12], content[:12])
		}
	default:
		return nil, err
	}
	return &record{dir: dir}, nil
}

func (rec *record) signedFor(r Request) (Signed, bool, error) {
	b, err := os.ReadFile(filepath.Join(rec.dir, r.HashHex()+".json"))
	if os.IsNotExist(err) {
		return Signed{}, false, nil
	}
	if err != nil {
		return Signed{}, false, err
	}
	var s Signed
	return s, true, json.Unmarshal(b, &s)
}

func (rec *record) store(r Request, s Signed) error {
	b, _ := json.Marshal(s)
	f, err := os.OpenFile(filepath.Join(rec.dir, r.HashHex()+".json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
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
	return werr
}
