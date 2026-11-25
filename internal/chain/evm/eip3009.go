package evm

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/signer"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// KindEIP3009 is the intent kind of an x402 payment authorization: an EIP-3009 transferWithAuthorization, EIP-712 typed data that the hot wallet's
// key signs and a facilitator submits on chain. The payload of its job is the typed data (Payload below), not a transaction, and the digest the job
// signs is the EIP-712 digest. Nothing is spent when it is signed: it is a liability until the token's AuthorizationUsed event or validBefore.
const KindEIP3009 = "eip3009"

// X402Token is the EIP-3009 and EIP-712 side of a configured token (Config.X402, keyed by the asset symbol). The values must be what the token contract
// itself uses (for Circle's USDC: name() and version(), checked against DOMAIN_SEPARATOR(); docs/evm.md lists the Base Sepolia ones).
type X402Token struct {
	Name    string // the EIP-712 domain name, e.g. "USDC"
	Version string // the EIP-712 domain version, e.g. "2"
	// MaxWindowSeconds bounds validBefore - validAfter of every authorization, and how far ahead of the zone's clock validBefore may lie.
	MaxWindowSeconds uint64
	// PerPaymentLimit is the most one authorization may pay, in the token's base units.
	PerPaymentLimit *big.Int
}

func (c Config) validateX402() error {
	for sym, x := range c.X402 {
		if _, ok := c.Assets[sym]; !ok {
			return fmt.Errorf("evm: config: x402 entry %q is not a configured token", sym)
		}
		if x.Name == "" || x.Version == "" || x.MaxWindowSeconds == 0 || x.PerPaymentLimit == nil || x.PerPaymentLimit.Sign() <= 0 {
			return fmt.Errorf("evm: config: x402 entry %q needs name, version, max_window_seconds > 0 and per_payment_limit > 0", sym)
		}
		if x.PerPaymentLimit.BitLen() > 256 {
			return fmt.Errorf("evm: config: x402 entry %q: per_payment_limit exceeds 256 bits", sym)
		}
	}
	return nil
}

// TypedField is one member of an EIP-712 struct type.
type TypedField struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// Domain is the EIP-712 domain of the token contract.
type Domain struct {
	Name              string `json:"name"`
	Version           string `json:"version"`
	ChainID           uint64 `json:"chainId"`
	VerifyingContract string `json:"verifyingContract"`
}

// Message is the TransferWithAuthorization message, every value a string as x402 clients write them: addresses 0x hex, numbers canonical decimal,
// the nonce 0x followed by 64 hex digits.
type Message struct {
	From        string `json:"from"`
	To          string `json:"to"`
	Value       string `json:"value"`
	ValidAfter  string `json:"validAfter"`
	ValidBefore string `json:"validBefore"`
	Nonce       string `json:"nonce"`
}

// Payload3009 is UnsignedTx.Payload of an eip3009 job: the EIP-712 typed data in the form wallets and x402 clients use (eth_signTypedData_v4).
type Payload3009 struct {
	Types       map[string][]TypedField `json:"types"`
	PrimaryType string                  `json:"primaryType"`
	Domain      Domain                  `json:"domain"`
	Message     Message                 `json:"message"`
}

const primaryType3009 = "TransferWithAuthorization"

var (
	domainFields = []TypedField{{"name", "string"}, {"version", "string"}, {"chainId", "uint256"}, {"verifyingContract", "address"}}
	twaFields    = []TypedField{{"from", "address"}, {"to", "address"}, {"value", "uint256"}, {"validAfter", "uint256"}, {"validBefore", "uint256"}, {"nonce", "bytes32"}}

	domainTypeHash = crypto.Keccak256Hash([]byte("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"))
	// TransferWithAuthorizationTypeHash is keccak256 of the EIP-3009 struct type string.
	TransferWithAuthorizationTypeHash = crypto.Keccak256Hash([]byte("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"))
)

// Authorization is an EIP-3009 authorization as the zone reads it from the typed data, with the digest it recomputed.
type Authorization struct {
	Chain       string // the zone's name of the chain
	ChainID     uint64
	Asset       string // the configured symbol of the token
	Token       common.Address
	From, To    common.Address
	Value       *big.Int
	ValidAfter  uint64
	ValidBefore uint64
	Nonce       [32]byte
	// Digest is the EIP-712 digest: keccak256(0x1901 || domainSeparator || structHash). It is what the key signs.
	Digest [32]byte
}

// Claim names what the authorization consumes: the nonce of the token, for this payer. The replay guard holds one claim for one intent, so the
// same nonce is never signed twice, for any payee, amount or window.
func (a Authorization) Claim() string {
	return fmt.Sprintf("eip3009:%s:%s:%x", strings.ToLower(a.Token.Hex()), strings.ToLower(a.From.Hex()), a.Nonce)
}

// usableAt: the token accepts the authorization at block time t when ValidAfter < t < ValidBefore (both bounds exclusive).
func (a Authorization) usableAt(t uint64) bool { return t > a.ValidAfter && t < a.ValidBefore }

// UsableAt reports whether the token would accept the authorization at block time t.
func (a Authorization) UsableAt(t uint64) bool { return a.usableAt(t) }

// Digest712 computes the EIP-712 digest of a TransferWithAuthorization for the domain, by hand from the spec (EIP-712 and EIP-3009), not from
// the JSON. A unit test checks it against go-ethereum's typed-data hasher and against the DOMAIN_SEPARATOR of the Base Sepolia USDC.
func Digest712(name, version string, chainID uint64, token, from, to common.Address, value *big.Int, validAfter, validBefore uint64, nonce [32]byte) [32]byte {
	ds := DomainSeparator(name, version, chainID, token)
	sh := crypto.Keccak256(
		TransferWithAuthorizationTypeHash.Bytes(),
		common.LeftPadBytes(from.Bytes(), 32), common.LeftPadBytes(to.Bytes(), 32),
		common.LeftPadBytes(value.Bytes(), 32),
		common.LeftPadBytes(new(big.Int).SetUint64(validAfter).Bytes(), 32),
		common.LeftPadBytes(new(big.Int).SetUint64(validBefore).Bytes(), 32),
		nonce[:])
	var out [32]byte
	copy(out[:], crypto.Keccak256([]byte{0x19, 0x01}, ds[:], sh))
	return out
}

// DomainSeparator is the EIP-712 domain separator of a token (what its DOMAIN_SEPARATOR() returns).
func DomainSeparator(name, version string, chainID uint64, token common.Address) [32]byte {
	var out [32]byte
	copy(out[:], crypto.Keccak256(
		domainTypeHash.Bytes(),
		crypto.Keccak256([]byte(name)), crypto.Keccak256([]byte(version)),
		common.LeftPadBytes(new(big.Int).SetUint64(chainID).Bytes(), 32), common.LeftPadBytes(token.Bytes(), 32)))
	return out
}

// NewPayload3009 builds the typed data of an authorization for the token configured under asset. The nonce is the 32-byte EIP-3009 nonce.
func (c Config) NewPayload3009(asset string, from, to common.Address, value *big.Int, validAfter, validBefore uint64, nonce [32]byte) ([]byte, [32]byte, error) {
	c = c.withDefaults()
	tok, x, err := c.x402Token(asset)
	if err != nil {
		return nil, [32]byte{}, err
	}
	p := Payload3009{
		Types:       map[string][]TypedField{"EIP712Domain": domainFields, primaryType3009: twaFields},
		PrimaryType: primaryType3009,
		Domain:      Domain{Name: x.Name, Version: x.Version, ChainID: c.ChainID, VerifyingContract: tok.Address.Hex()},
		Message: Message{From: from.Hex(), To: to.Hex(), Value: value.String(), ValidAfter: fmt.Sprint(validAfter), ValidBefore: fmt.Sprint(validBefore),
			Nonce: "0x" + hex.EncodeToString(nonce[:])},
	}
	b, err := json.Marshal(p)
	if err != nil {
		return nil, [32]byte{}, err
	}
	return b, Digest712(x.Name, x.Version, c.ChainID, tok.Address, from, to, value, validAfter, validBefore, nonce), nil
}

func (c Config) x402Token(asset string) (Token, X402Token, error) {
	tok, native, err := c.asset(asset)
	if err != nil {
		return Token{}, X402Token{}, err
	}
	x, ok := c.X402[asset]
	if native || !ok {
		return Token{}, X402Token{}, fmt.Errorf("evm: %q has no x402 (EIP-3009) configuration on this chain", asset)
	}
	return tok, x, nil
}

func sameFields(a, b []TypedField) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func parseHexAddress(what, s string) (common.Address, error) {
	if len(s) != 42 || !strings.HasPrefix(s, "0x") || !common.IsHexAddress(s) {
		return common.Address{}, fmt.Errorf("evm: eip3009 %s %q is not a 0x address", what, s)
	}
	a := common.HexToAddress(s)
	if h := s[2:]; h != strings.ToLower(h) && h != strings.ToUpper(h) && a.Hex() != s {
		return common.Address{}, fmt.Errorf("evm: eip3009 %s %q has a bad checksum", what, s)
	}
	return a, nil
}

func parseUint64Dec(what, s string) (uint64, error) {
	n, err := parseAmount(s)
	if err != nil {
		return 0, fmt.Errorf("evm: eip3009 %s: %w", what, err)
	}
	if !n.IsUint64() {
		return 0, fmt.Errorf("evm: eip3009 %s %s does not fit 64 bits", what, s)
	}
	return n.Uint64(), nil
}

// DecodeAuthorization parses the typed data of an eip3009 job strictly and recomputes its digest. It checks the shape (no unknown field, no trailing
// data, the type definitions exactly EIP-3009's, every value canonical) and that the domain is the configured token's on the configured chain: chain
// id, verifying contract, name and version. It does not know who the payer or the payee should be: that is Verify's judgement against the intent.
func (v *Verifier) DecodeAuthorization(payload []byte) (Authorization, error) {
	cfg := v.cfg
	var p Payload3009
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return Authorization{}, fmt.Errorf("evm: decode eip3009 payload: %w", err)
	}
	if dec.More() {
		return Authorization{}, errors.New("evm: decode eip3009 payload: trailing data")
	}
	if p.PrimaryType != primaryType3009 {
		return Authorization{}, fmt.Errorf("evm: eip3009 primary type %q", p.PrimaryType)
	}
	for name, fields := range p.Types {
		switch {
		case name == primaryType3009 && sameFields(fields, twaFields):
		case name == "EIP712Domain" && sameFields(fields, domainFields):
		default:
			return Authorization{}, fmt.Errorf("evm: eip3009 type %q is not the EIP-3009 definition", name)
		}
	}
	if !sameFields(p.Types[primaryType3009], twaFields) {
		return Authorization{}, errors.New("evm: eip3009 payload lacks the TransferWithAuthorization type")
	}
	if p.Domain.ChainID != cfg.ChainID {
		return Authorization{}, fmt.Errorf("evm: eip3009 domain chain id %d, want %d", p.Domain.ChainID, cfg.ChainID)
	}
	token, err := parseHexAddress("verifying contract", p.Domain.VerifyingContract)
	if err != nil {
		return Authorization{}, err
	}
	sym, ok := cfg.symbolOf(token)
	if !ok {
		return Authorization{}, fmt.Errorf("evm: eip3009 verifying contract %s is not a configured token", token)
	}
	tok, x, err := cfg.x402Token(sym)
	if err != nil {
		return Authorization{}, err
	}
	if p.Domain.Name != x.Name || p.Domain.Version != x.Version {
		return Authorization{}, fmt.Errorf("evm: eip3009 domain is (%q, %q), the configured token's is (%q, %q)", p.Domain.Name, p.Domain.Version, x.Name, x.Version)
	}
	a := Authorization{Chain: cfg.Chain, ChainID: cfg.ChainID, Asset: sym, Token: tok.Address}
	if a.From, err = parseHexAddress("from", p.Message.From); err != nil {
		return Authorization{}, err
	}
	if a.To, err = parseHexAddress("to", p.Message.To); err != nil {
		return Authorization{}, err
	}
	if a.Value, err = parseAmount(p.Message.Value); err != nil {
		return Authorization{}, fmt.Errorf("evm: eip3009 value: %w", err)
	}
	if a.ValidAfter, err = parseUint64Dec("validAfter", p.Message.ValidAfter); err != nil {
		return Authorization{}, err
	}
	if a.ValidBefore, err = parseUint64Dec("validBefore", p.Message.ValidBefore); err != nil {
		return Authorization{}, err
	}
	n := p.Message.Nonce
	if len(n) != 66 || !strings.HasPrefix(n, "0x") {
		return Authorization{}, fmt.Errorf("evm: eip3009 nonce %q is not 0x and 32 bytes", n)
	}
	if _, err := hex.Decode(a.Nonce[:], []byte(n[2:])); err != nil {
		return Authorization{}, fmt.Errorf("evm: eip3009 nonce: %w", err)
	}
	a.Digest = Digest712(x.Name, x.Version, cfg.ChainID, tok.Address, a.From, a.To, a.Value, a.ValidAfter, a.ValidBefore, a.Nonce)
	return a, nil
}

// verifyEIP3009 judges an eip3009 job: the typed data decodes strictly, the digest the job carries is the one recomputed from it, the domain is the
// configured token's, the payer is the hot address of the job's partition, and payee, amount and token are the intent's. It also bounds the window
// and the value by the zone's own config. (Whether the window is in the future of the zone's clock, and who may order the payment, are the decider's
// policy: it knows the clock and the credential.)
func (v *Verifier) verifyEIP3009(u chain.UnsignedTx, i signjob.Intent) error {
	cfg := v.cfg
	if u.Chain != cfg.Chain || i.Chain != cfg.Chain {
		return reject("chain %q/%q, want %q", u.Chain, i.Chain, cfg.Chain)
	}
	a, err := v.DecodeAuthorization(u.Payload)
	if err != nil {
		return reject("%v", err)
	}
	if !bytes.Equal(a.Digest[:], u.Digest) {
		return reject("digest does not match the typed data")
	}
	if u.KeyRef.PartitionID != i.PartitionID {
		return reject("key partition %q, intent partition %q", u.KeyRef.PartitionID, i.PartitionID)
	}
	ok, hot, err := cfg.senderOK(i.PartitionID, a.From)
	if err != nil {
		return reject("%v", err)
	}
	if !ok {
		return reject("payer %s is not the hot address %s of partition %q", a.From, hot, i.PartitionID)
	}
	if i.From != "" {
		return reject("eip3009 intent has a source address")
	}
	if a.Asset != i.Asset {
		return reject("the typed data is for %s (%s), the intent for %s", a.Asset, a.Token, i.Asset)
	}
	dest, err := parseIntentAddress(i.To)
	if err != nil {
		return reject("%v", err)
	}
	if dest != a.To {
		return reject("typed data pays %s, the intent %s", a.To, dest)
	}
	amount, err := parseAmount(i.Amount)
	if err != nil {
		return reject("%v", err)
	}
	if amount.Sign() == 0 || amount.Cmp(a.Value) != 0 {
		return reject("typed data value %s, intent amount %s", a.Value, amount)
	}
	x := cfg.X402[a.Asset]
	if a.Value.Cmp(x.PerPaymentLimit) > 0 {
		return reject("value %s exceeds the per-payment limit %s of %s", a.Value, x.PerPaymentLimit, a.Asset)
	}
	if a.ValidBefore <= a.ValidAfter {
		return reject("the window is empty: validAfter %d, validBefore %d", a.ValidAfter, a.ValidBefore)
	}
	if a.ValidBefore-a.ValidAfter > x.MaxWindowSeconds {
		return reject("the window %d s is longer than the %d s allowed", a.ValidBefore-a.ValidAfter, x.MaxWindowSeconds)
	}
	return nil
}

// X402Limits returns the configured ceiling for the window of asset (seconds that validBefore may lie ahead of the zone clock) and its per-payment limit.
func (v *Verifier) X402Limits(asset string) (maxWindowSeconds uint64, perPayment *big.Int, ok bool) {
	x, found := v.cfg.X402[asset]
	return x.MaxWindowSeconds, x.PerPaymentLimit, found
}

// SignatureRSV turns the signature a Signer returned for digest into the form EIP-3009 and x402 expect: r and s as 32-byte big-endian values, s in the
// lower half of the curve order (the token's ECRecover refuses the upper half) and v as 27 or 28 (the token refuses 0 and 1). v is found by recovery
// against pub, and the signature is verified first, so a signature of the wrong key or digest is an error and not a wrong v.
func SignatureRSV(digest [32]byte, sig signer.Signature, pub *ecdsa.PublicKey) (r, s [32]byte, v byte, err error) {
	if sig.R == nil || sig.S == nil || pub == nil {
		return r, s, 0, errors.New("evm: nil signature or public key")
	}
	sig = signer.NormalizeLowS(sig)
	if !signer.Verify(pub, digest, sig) {
		return r, s, 0, errors.New("evm: the signature does not verify against the public key and the digest")
	}
	sig.R.FillBytes(r[:])
	sig.S.FillBytes(s[:])
	want := crypto.FromECDSAPub(pub)
	sig65 := make([]byte, 65)
	copy(sig65[0:32], r[:])
	copy(sig65[32:64], s[:])
	for rec := byte(0); rec <= 1; rec++ {
		sig65[64] = rec
		if got, err := crypto.Ecrecover(digest[:], sig65); err == nil && bytes.Equal(got, want) {
			return r, s, 27 + rec, nil
		}
	}
	return r, s, 0, errors.New("evm: no recovery id recovers the public key")
}

// SignatureRSVFor is SignatureRSV for a caller that knows the payer's address and not its public key (the core: the hot address of a shard). v is the
// recovery id for which ecrecover(digest, r, s, v) is the payer; a signature that recovers to anyone else is an error.
func SignatureRSVFor(digest [32]byte, sig signer.Signature, payer common.Address) (r, s [32]byte, v byte, err error) {
	if sig.R == nil || sig.S == nil || sig.R.Sign() <= 0 || sig.S.Sign() <= 0 {
		return r, s, 0, errors.New("evm: empty signature")
	}
	sig = signer.NormalizeLowS(sig)
	sig.R.FillBytes(r[:])
	sig.S.FillBytes(s[:])
	sig65 := make([]byte, 65)
	copy(sig65[0:32], r[:])
	copy(sig65[32:64], s[:])
	for rec := byte(0); rec <= 1; rec++ {
		sig65[64] = rec
		if pub, err := crypto.SigToPub(digest[:], sig65); err == nil && crypto.PubkeyToAddress(*pub) == payer {
			return r, s, 27 + rec, nil
		}
	}
	return r, s, 0, fmt.Errorf("evm: the signature does not recover to %s", payer)
}

// NewVerifierForTest returns a Verifier of cfg and panics on a bad config: for tests that decode typed data with the zone's own decoder.
func NewVerifierForTest(cfg Config) *Verifier {
	v, err := NewVerifier(cfg)
	if err != nil {
		panic(err)
	}
	return v
}
