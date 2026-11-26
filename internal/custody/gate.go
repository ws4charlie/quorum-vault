package custody

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"regexp"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain/evm"
	"github.com/ws4charlie/quorum-vault/internal/gatecred"
	"github.com/ws4charlie/quorum-vault/internal/partition"
	"github.com/ws4charlie/quorum-vault/internal/signer"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// The signing API for AgentGate (docs/gate-credential.md, "The signing API"). AgentGate sends {wallet_id, kind, payload, credential} and gets the
// signature or a typed refusal. The core does only the cheap checks it can (request shape, the wallet is one of its Gate-governed wallets, the credential
// parses and names this deployment and this wallet, the payload decodes); it never decides that a payment is allowed. The signing zone is the rule: the
// credential travels to it in the job's intent, and every checker verifies it against what it decodes from the bytes it signs.
//
// Idempotency by credential_id (table gate_requests): the same request again gets the stored answer, or waits for the same job; the same credential_id
// with another body is replayed (409). A signature that was made but whose answer was lost is read again from the job.

// Kinds of the signing API.
const (
	GateKindTransfer = "evm_transfer" // an EVM transfer: not served in this version (request_invalid)
	GateKindEIP3009  = "evm_eip3009"  // an EIP-3009 transferWithAuthorization (x402), as EIP-712 typed data
)

// Codes of the API beside the credential codes of gatecred. Both 503 codes are answers to a request that did not end in a signature for a reason
// outside the spec's refusal table: retry_later is not stored (nothing was decided: the same request may be sent again and gets the same job's outcome);
// signing_failed is stored (the zone's signer failed or refused for a reason the table does not name: Gate mints a new credential).
const (
	GateRetryLater    = "retry_later"
	GateSigningFailed = "signing_failed"
)

// Statuses of a gate_requests row.
const (
	gatePending = "pending"
	gateSigned  = "signed"
	gateRefused = "refused"
)

// GateFile is the gate section of the business config.
type GateFile struct {
	// Audience is this deployment's name. It must equal the audience of the signing zone's signed gate setting: the core cannot read that setting (it
	// has no path into the zone), so the operator keeps the two equal (docs/runbooks/agentgate-client.md). A credential for another audience is refused.
	Audience string `json:"audience"`
	// Skew is the clock allowance, the same as the zone's (default 30s, at most 5m). The core uses it for its cheap expiry check and for pruning.
	Skew string `json:"skew,omitempty"`
	// Wait is how long one request waits for the zone's answer before it answers retry_later (default 20s, at most 2m).
	Wait string `json:"wait,omitempty"`
	// Wallets maps each Gate-governed wallet_id (lower-case UUID) to the hot shard (partition id) that pays, the same mapping as the zone's signed gate
	// setting. A wallet not listed here is refused as wallet_not_gate_governed.
	Wallets map[string]GateWalletFile `json:"wallets"`
}

// GateWalletFile is one Gate-governed wallet.
type GateWalletFile struct {
	Partition string `json:"partition"`
}

// GateConfig is the validated GateFile.
type GateConfig struct {
	Audience string
	Skew     time.Duration
	Wait     time.Duration
	Wallets  map[string]GateWallet
}

// GateWallet is one Gate-governed wallet as the core sees it.
type GateWallet struct {
	ID        string
	Partition string // the hot shard that pays
	Asset     string // the asset of the partition
}

var (
	reGateUUID     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	reGateAudience = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
)

// GateGoverned reports whether a partition is on the hot shard of a Gate-governed wallet of gate.wallets (any asset of that shard), as the zone
// governs it. False without a gate section.
func (c *Config) GateGoverned(part string) bool {
	if c.Gate == nil {
		return false
	}
	k, err := partition.Parse(part)
	if err != nil {
		return false
	}
	for _, w := range c.Gate.Wallets {
		if w.Partition == part {
			return true
		}
		if wk, err := partition.Parse(w.Partition); err == nil && wk.Tier == partition.TierHot && k.Tier == partition.TierHot && wk.ShardID() == k.ShardID() {
			return true
		}
	}
	return false
}

func (c *Config) buildGate(f *GateFile) error {
	if f == nil {
		return nil
	}
	if c.Family != FamilyEVM {
		return fmt.Errorf("custody: config: gate: only the evm family serves the signing API")
	}
	if !reGateAudience.MatchString(f.Audience) {
		return fmt.Errorf("custody: config: gate audience %q is not 1-64 characters of [a-z0-9._-] starting with a letter or digit", f.Audience)
	}
	g := &GateConfig{Audience: f.Audience, Wallets: map[string]GateWallet{}}
	var err error
	if g.Skew, err = dur("gate skew", f.Skew, gatecred.DefaultSkew); err != nil {
		return err
	}
	if g.Skew > gatecred.MaxSkew {
		return fmt.Errorf("custody: config: gate skew %s is above %s", g.Skew, gatecred.MaxSkew)
	}
	if g.Wait, err = dur("gate wait", f.Wait, 20*time.Second); err != nil {
		return err
	}
	if g.Wait > 2*time.Minute {
		return fmt.Errorf("custody: config: gate wait %s is above 2m", g.Wait)
	}
	if len(f.Wallets) == 0 {
		return errors.New("custody: config: gate: no wallets")
	}
	seen := map[string]string{}
	for id, w := range f.Wallets {
		if !reGateUUID.MatchString(id) {
			return fmt.Errorf("custody: config: gate wallet %q is not a lower-case UUID", id)
		}
		k, err := partition.Parse(w.Partition)
		if err != nil {
			return fmt.Errorf("custody: config: gate wallet %s: %w", id, err)
		}
		if !c.isHotPartitionOf(w.Partition, k.Asset) {
			return fmt.Errorf("custody: config: gate wallet %s: %q is not a hot shard of this chain", id, w.Partition)
		}
		if _, ok := c.EVM.X402[k.Asset]; !ok {
			return fmt.Errorf("custody: config: gate wallet %s: %s has no x402 section, and EIP-3009 is the only kind this version serves", id, k.Asset)
		}
		if other, dup := seen[w.Partition]; dup {
			return fmt.Errorf("custody: config: gate wallets %s and %s name the same partition", other, id)
		}
		seen[w.Partition] = id
		g.Wallets[id] = GateWallet{ID: id, Partition: w.Partition, Asset: k.Asset}
	}
	c.Gate = g
	return nil
}

// GateRequest is one call of the signing API.
type GateRequest struct {
	WalletID   string          `json:"wallet_id"`
	Kind       string          `json:"kind"`
	Payload    json.RawMessage `json:"payload"`
	Credential json.RawMessage `json:"credential"`
}

// GateRefusal is the body of a refusal.
type GateRefusal struct {
	Code    string `json:"code"`
	Field   string `json:"field,omitempty"`
	Message string `json:"message"`
}

// GateSigned is the body of a success.
type GateSigned struct {
	CredentialID string `json:"credential_id"`
	WalletID     string `json:"wallet_id"`
	Kind         string `json:"kind"`
	// Signature is r || s || v, 65 bytes in 0x hex, the form EIP-3009 and x402 take (s low, v 27 or 28).
	Signature string `json:"signature"`
}

// GateStatus is the HTTP status of each code (docs/gate-credential.md, "The signing API").
func GateStatus(code string) int {
	switch gatecred.Code(code) {
	case gatecred.RequestInvalid, gatecred.CredentialMissing, gatecred.CredentialMalformed:
		return 400
	case gatecred.ClientNotAuthorized, gatecred.WalletNotGateGoverned, gatecred.KIDUnknown, gatecred.SignatureInvalid, gatecred.AudienceMismatch,
		gatecred.WalletMismatch, gatecred.TTLTooLong, gatecred.NotYetValid, gatecred.Expired, gatecred.PaymentMismatch, gatecred.AuthorizationWindow,
		gatecred.FastLaneCap:
		return 403
	case gatecred.Replayed:
		return 409
	case gatecred.PayloadInvalid:
		return 422
	}
	return 503 // retry_later, signing_failed, and anything unknown: never a success
}

func refusal(code gatecred.Code, field, format string, a ...any) (int, []byte) {
	return gateBody(GateStatus(string(code)), GateRefusal{Code: string(code), Field: field, Message: fmt.Sprintf(format, a...)})
}

func gateBody(status int, v any) (int, []byte) {
	b, err := json.Marshal(v)
	if err != nil { // a struct of strings: cannot happen
		return 503, []byte(`{"code":"retry_later","message":"internal error"}`)
	}
	return status, b
}

// gateZoneRefusal maps a refusal of the signing zone (the job's reject reason, "<code>: <detail>" or "<code>: field <field>: <detail>") to the API's
// code and field. A spec code is taken from the reason's code or, when a reason wraps it (e.g. "policy_payment_rule: payment_mismatch (amount): ..."), from the start of the detail, with its field.
// The zone's own refusals that have a meaning in the table map to it; anything else is signing_failed (503), never a success.
func gateZoneRefusal(reason string) GateRefusal {
	code, detail, _ := strings.Cut(reason, ": ")
	if GateStatus(code) != 503 {
		// The zone's form (internal/gateway, GateRefusal): "<code>: <detail>" or "<code>: field <field>: <detail>".
		field := ""
		if rest, ok := strings.CutPrefix(detail, "field "); ok {
			if f, _, ok := strings.Cut(rest, ": "); ok && !strings.ContainsAny(f, " :") {
				field = f
			}
		}
		return GateRefusal{Code: code, Field: field, Message: reason}
	}
	head, _, _ := strings.Cut(detail, ":")
	inner, field, hasField := strings.Cut(strings.TrimSpace(head), " (")
	if hasField {
		field = strings.TrimSuffix(field, ")")
	}
	if GateStatus(inner) != 503 {
		return GateRefusal{Code: inner, Field: field, Message: reason}
	}
	switch {
	case code == "tx_mismatch" || code == "intent_invalid":
		return GateRefusal{Code: string(gatecred.PayloadInvalid), Message: reason}
	case code == "policy_payment_window":
		return GateRefusal{Code: string(gatecred.AuthorizationWindow), Message: reason}
	case strings.HasPrefix(code, "replay_"):
		return GateRefusal{Code: string(gatecred.Replayed), Message: reason}
	}
	return GateRefusal{Code: GateSigningFailed, Message: reason}
}

// gateBodyHash is the identity of a request: wallet, kind, payload and the credential. The payload is hashed in a canonical form (members sorted, no
// insignificant space, numbers as written) and the credential as its canonical form and signature, so a copy with members in another order or other
// spacing is the same request.
func gateBodyHash(r GateRequest, cred *gatecred.Credential) ([]byte, error) {
	payload, err := canonicalJSON(r.Payload)
	if err != nil {
		return nil, err
	}
	b := []byte("qv-gate-request-v1\n")
	for _, f := range [][]byte{[]byte(r.WalletID), []byte(r.Kind), payload, cred.Wire()} {
		b = binary.BigEndian.AppendUint32(b, uint32(len(f)))
		b = append(b, f...)
	}
	h := sha256.Sum256(b)
	return h[:], nil
}

// canonicalJSON re-encodes one JSON value with object members sorted by name, no insignificant space and numbers exactly as written. It is the form
// the request hash uses; it is never sent anywhere.
func canonicalJSON(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errors.New("trailing data")
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil { // maps are written with sorted keys
		return nil, err
	}
	return bytes.TrimRight(out.Bytes(), "\n"), nil
}

// GateSign serves one request of the signing API and returns the HTTP status and body. It repeats harmlessly (see the package comment above).
//
// Order: what depends only on the request (shape, the credential parses, the body hash) comes first; then the row of the credential_id, so a request
// already answered gets its stored answer (or waits on its job) whatever the configuration, the clock or the keysets say now. Only a new request runs
// the checks that depend on the current state.
func (s *Service) GateSign(ctx context.Context, r GateRequest, log *slog.Logger) (int, []byte) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	// 1. Shape.
	switch {
	case !reGateUUID.MatchString(r.WalletID):
		return refusal(gatecred.RequestInvalid, "wallet_id", "wallet_id must be a lower-case UUID")
	case r.Kind == GateKindTransfer:
		return refusal(gatecred.RequestInvalid, "kind", "evm_transfer is not supported in this version; use evm_eip3009")
	case r.Kind != GateKindEIP3009:
		return refusal(gatecred.RequestInvalid, "kind", "kind must be evm_eip3009")
	case len(bytes.TrimSpace(r.Payload)) == 0 || bytes.Equal(bytes.TrimSpace(r.Payload), []byte("null")):
		return refusal(gatecred.RequestInvalid, "payload", "payload is required")
	}
	// The EIP-3009 nonce is Gate's: it is required, and it is signed as given (an all-zero nonce included), never drawn by Vault.
	var shape struct {
		Message map[string]json.RawMessage `json:"message"`
	}
	if err := json.Unmarshal(r.Payload, &shape); err != nil {
		return refusal(gatecred.RequestInvalid, "payload", "payload is not a JSON object: %v", err)
	}
	if _, ok := shape.Message["nonce"]; !ok {
		return refusal(gatecred.RequestInvalid, "payload", "payload.message.nonce is required")
	}
	// 2. The credential is there and parses.
	if raw := bytes.TrimSpace(r.Credential); len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return refusal(gatecred.CredentialMissing, "", "a credential is required")
	}
	cred, err := gatecred.Parse(r.Credential)
	if err != nil {
		var ce *gatecred.Error
		if errors.As(err, &ce) {
			return refusal(ce.Code, ce.Field, "%s", ce.Detail)
		}
		return refusal(gatecred.CredentialMalformed, "", "%v", err)
	}
	hash, err := gateBodyHash(r, cred)
	if err != nil {
		return refusal(gatecred.RequestInvalid, "payload", "payload is not JSON")
	}
	// 3. A credential_id seen before: another body is replayed, a stored answer is returned as it was, a placed request waits on its job.
	row, err := s.gateLookup(ctx, cred.CredentialID, hash)
	if err != nil {
		log.Error("gate request could not be read", "credential_id", cred.CredentialID, "error", err.Error())
		return refusal(GateRetryLater, "", "the request could not be read; send it again")
	}
	switch {
	case row.replayed:
		return refusal(gatecred.Replayed, "credential_id", "credential %s was used with another request", cred.CredentialID)
	case row.stored != nil:
		return row.status, row.stored
	case row.placed:
		return s.gateWait(ctx, log, cred, r)
	}
	// 4. A new request (or one recorded but not placed): the checks against the current state.
	g := s.Cfg.Gate
	var w GateWallet
	ok := false
	if g != nil {
		w, ok = g.Wallets[r.WalletID]
	}
	if !ok {
		return refusal(gatecred.WalletNotGateGoverned, "", "wallet %s is not Gate-governed in this deployment", r.WalletID)
	}
	if cred.Audience != g.Audience {
		return refusal(gatecred.AudienceMismatch, "audience", "credential is for %q", cred.Audience)
	}
	if cred.WalletID != r.WalletID {
		return refusal(gatecred.WalletMismatch, "wallet_id", "credential is for another wallet")
	}
	// A new request with an expired credential is refused (the zone would too), so a request that comes back after its row was pruned cannot bring an
	// old authorization back to life.
	if !row.found && s.Now().Unix() >= cred.ExpiresAt+int64(g.Skew/time.Second) {
		return refusal(gatecred.Expired, "expires_at", "the credential expired at %d", cred.ExpiresAt)
	}
	a, code, perr := s.gateDecode(w, r.Payload)
	if perr != "" {
		if code == GateRetryLater {
			log.Warn("gate: the wallet's address could not be read", "credential_id", cred.CredentialID, "error", perr)
		}
		return refusal(gatecred.Code(code), "", "%s", perr)
	}
	// 5. One row per credential_id.
	if err := s.gateInsert(ctx, r, cred, hash); err != nil {
		log.Error("gate request could not be recorded", "credential_id", cred.CredentialID, "error", err.Error())
		return refusal(GateRetryLater, "", "the request could not be recorded; send it again")
	}
	if row, err = s.gateLookup(ctx, cred.CredentialID, hash); err != nil { // another request may have made it first
		return refusal(GateRetryLater, "", "the request could not be read; send it again")
	}
	switch {
	case row.replayed:
		return refusal(gatecred.Replayed, "credential_id", "credential %s was used with another request", cred.CredentialID)
	case row.stored != nil:
		return row.status, row.stored
	}
	// 6. The authorization and its sign job (idempotent by id: a repeat finds the same row and job).
	_, _, err = s.RequestX402(ctx, X402Request{ID: cred.CredentialID, Asset: w.Asset, Partition: w.Partition, Payee: a.To.Hex(), Amount: a.Value,
		ValidAfter: a.ValidAfter, ValidBefore: a.ValidBefore, Nonce: a.Nonce, KeepNonce: true, Credential: r.Credential})
	switch {
	case errors.Is(err, ErrX402Amount):
		return s.gateFinish(ctx, log, cred, r, refusalOf(gatecred.FastLaneCap, "amount", err))
	case errors.Is(err, ErrX402Window):
		return s.gateFinish(ctx, log, cred, r, refusalOf(gatecred.PayloadInvalid, "", err))
	case errors.Is(err, ErrX402Payee), errors.Is(err, ErrX402NotConfigured):
		return s.gateFinish(ctx, log, cred, r, refusalOf(gatecred.PayloadInvalid, "", err))
	case errors.Is(err, ErrX402Conflict):
		return s.gateFinish(ctx, log, cred, r, refusalOf(gatecred.Replayed, "", err))
	case err != nil:
		// Nothing final happened (no funds free yet, the chain head could not be read, the database): the same request may come again.
		log.Warn("gate request not placed; the caller may retry", "credential_id", cred.CredentialID, "error", err.Error())
		return refusal(GateRetryLater, "", "%v", err)
	}
	return s.gateWait(ctx, log, cred, r)
}

func refusalOf(code gatecred.Code, field string, err error) GateRefusal {
	return GateRefusal{Code: string(code), Field: field, Message: err.Error()}
}

// gateDecode reads the typed data strictly (the zone's own decoder) and checks what the core can: the token is the wallet's asset and the payer is
// the wallet's address. It returns a code and a reason when it cannot accept: payload_invalid when the payload is wrong, retry_later when what it is
// compared with (the configuration's verifier, the wallet's active address) could not be read.
func (s *Service) gateDecode(w GateWallet, payload []byte) (evm.Authorization, string, string) {
	v, err := evm.NewVerifier(s.Cfg.EVM)
	if err != nil {
		return evm.Authorization{}, GateRetryLater, err.Error()
	}
	a, err := v.DecodeAuthorization(payload)
	if err != nil {
		return a, string(gatecred.PayloadInvalid), err.Error()
	}
	if a.Asset != w.Asset {
		return a, string(gatecred.PayloadInvalid), fmt.Sprintf("the authorization is for %s; wallet %s pays %s", a.Asset, w.ID, w.Asset)
	}
	payer, _, err := s.ShardAddressOf(w.Partition)
	if err != nil {
		return a, GateRetryLater, fmt.Sprintf("the wallet's address could not be read: %v", err)
	}
	if !strings.EqualFold(payer, a.From.Hex()) {
		return a, string(gatecred.PayloadInvalid), fmt.Sprintf("from %s is not the wallet's address %s", a.From.Hex(), payer)
	}
	return a, "", ""
}

// gateRow is what gate_requests holds for a credential_id, seen against a request's body hash.
type gateRow struct {
	found    bool   // a row exists
	replayed bool   // with another body
	stored   []byte // the stored answer, when final
	status   int
	placed   bool // pending, and its authorization (and sign job) exist
}

func (s *Service) gateLookup(ctx context.Context, id string, hash []byte) (gateRow, error) {
	var out gateRow
	var same, placed bool
	var st string
	var hs *int
	var res *string
	err := s.Pool.QueryRow(ctx, `SELECT g.body_hash=$2, g.status, g.http_status, g.result, EXISTS (SELECT 1 FROM x402_authorizations x WHERE x.id=g.credential_id)
		FROM gate_requests g WHERE g.credential_id=$1`, id, hash).Scan(&same, &st, &hs, &res, &placed)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	out.found = true
	switch {
	case !same:
		out.replayed = true
	case st != gatePending && hs != nil && res != nil:
		out.stored, out.status = []byte(*res), *hs
	case st == gatePending:
		out.placed = placed
	}
	return out, nil
}

func (s *Service) gateInsert(ctx context.Context, r GateRequest, cred *gatecred.Credential, hash []byte) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO gate_requests (credential_id, body_hash, wallet_id, kind, job_id, status, expires_at)
		VALUES ($1,$2,$3,$4,$5,'pending',$6) ON CONFLICT (credential_id) DO NOTHING`,
		cred.CredentialID, hash, r.WalletID, r.Kind, "x402:"+cred.CredentialID, time.Unix(cred.ExpiresAt, 0).UTC())
	return err
}

// gateWait waits for the zone's answer on the job, at most the configured wait, and stores a final one.
func (s *Service) gateWait(ctx context.Context, log *slog.Logger, cred *gatecred.Credential, r GateRequest) (int, []byte) {
	ctx, cancel := context.WithTimeout(ctx, s.Cfg.Gate.Wait)
	defer cancel()
	jobID := "x402:" + cred.CredentialID
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		job, err := signjob.Get(ctx, s.Pool, jobID)
		if err == nil {
			switch job.Status {
			case signjob.StatusDone:
				sig, err := s.gateSignature(ctx, cred.CredentialID, job)
				if err != nil {
					log.Error("gate: signed job, but the signature could not be read", "credential_id", cred.CredentialID, "error", err.Error())
					return refusal(GateRetryLater, "", "the signature could not be read; send the request again")
				}
				_, _ = s.X402(ctx, cred.CredentialID) // moves the authorization to signed; the worker does it too
				return s.gateFinish(ctx, log, cred, r, GateSigned{CredentialID: cred.CredentialID, WalletID: r.WalletID, Kind: r.Kind, Signature: sig})
			case signjob.StatusRejected:
				_, _ = s.X402(ctx, cred.CredentialID) // releases the hold; the worker does it too
				return s.gateFinish(ctx, log, cred, r, gateZoneRefusal(job.RejectReason))
			case signjob.StatusFailed:
				_, _ = s.X402(ctx, cred.CredentialID)
				return s.gateFinish(ctx, log, cred, r, GateRefusal{Code: GateSigningFailed, Message: "the signer failed: " + job.RejectReason})
			}
		}
		select {
		case <-ctx.Done():
			return refusal(GateRetryLater, "", "the signing zone has not answered yet; send the same request again")
		case <-tick.C:
		}
	}
}

// gateSignature is the job's signature in the form EIP-3009 takes: r || s || v, v recovered against the payer of the authorization.
func (s *Service) gateSignature(ctx context.Context, id string, job signjob.Job) (string, error) {
	var payer string
	if err := s.Pool.QueryRow(ctx, `SELECT payer FROM x402_authorizations WHERE id=$1`, id).Scan(&payer); err != nil {
		return "", err
	}
	if len(job.Signature) != 64 || len(job.Digest) != 32 {
		return "", fmt.Errorf("job %s: signature of %d bytes, digest of %d", job.ID, len(job.Signature), len(job.Digest))
	}
	var digest [32]byte
	copy(digest[:], job.Digest)
	rr, ss, v, err := evm.SignatureRSVFor(digest, signer.Signature{R: new(big.Int).SetBytes(job.Signature[:32]), S: new(big.Int).SetBytes(job.Signature[32:])},
		common.HexToAddress(payer))
	if err != nil {
		return "", err
	}
	return "0x" + hex.EncodeToString(rr[:]) + hex.EncodeToString(ss[:]) + hex.EncodeToString([]byte{v}), nil
}

// gateFinish stores a final answer once, with its audit event, and returns the stored one (which is this one unless another request stored first).
func (s *Service) gateFinish(ctx context.Context, log *slog.Logger, cred *gatecred.Credential, r GateRequest, answer any) (int, []byte) {
	st, code, out := gateSigned, "", answer
	status := 200
	if rf, ok := answer.(GateRefusal); ok {
		st, code, status = gateRefused, rf.Code, GateStatus(rf.Code)
	}
	_, body := gateBody(status, out)
	var stored *string
	var storedStatus int
	err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		stored, storedStatus = nil, 0
		tag, err := tx.Exec(ctx, `UPDATE gate_requests SET status=$2, http_status=$3, result=$4, updated_at=now() WHERE credential_id=$1 AND status='pending'`,
			cred.CredentialID, st, status, string(body))
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return tx.QueryRow(ctx, `SELECT http_status, result FROM gate_requests WHERE credential_id=$1`, cred.CredentialID).Scan(&storedStatus, &stored)
		}
		return auditEvent(ctx, tx, "gate:"+cred.CredentialID, "gate.request", map[string]any{
			"credential_id": cred.CredentialID, "obligation_id": cred.ObligationID, "policy_version": cred.PolicyVersion,
			"decision_reason": cred.DecisionReason, "wallet_id": r.WalletID, "kind": r.Kind, "payee": cred.Payee, "amount": cred.Amount,
			"asset": cred.Asset, "chain": cred.Chain, "outcome": st, "code": code, "http_status": status})
	})
	if err != nil {
		log.Error("gate: the answer could not be stored", "credential_id", cred.CredentialID, "error", err.Error())
		return refusal(GateRetryLater, "", "the answer could not be stored; send the same request again")
	}
	if stored != nil {
		return storedStatus, []byte(*stored)
	}
	return status, body
}

// PruneGateRequests removes the rows whose credential expired more than skew + 1 day ago: no checker can accept the credential any more, and the day
// is for troubleshooting. It returns how many rows it removed.
func (s *Service) PruneGateRequests(ctx context.Context) (int64, error) {
	if s.Cfg.Gate == nil {
		return 0, nil
	}
	cut := s.Now().Add(-s.Cfg.Gate.Skew - 24*time.Hour)
	tag, err := s.Pool.Exec(ctx, `DELETE FROM gate_requests WHERE expires_at < $1`, cut)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
