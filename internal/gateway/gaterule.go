package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain/evm"
	"github.com/ws4charlie/quorum-vault/internal/gatecred"
	"github.com/ws4charlie/quorum-vault/internal/partition"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// The Gate credential rule (docs/gate-credential.md, "Checks at the signing zone"): the one PaymentRule of the zone. NewDecider installs it, so the
// gateway, every cosigner and any later binary that decides has it; there is no flag, setting or build that leaves it out.
//
// A job pays from a Gate-governed wallet when its partition is the wallet's hot shard (any asset of it) or its sender, as the zone decoded it, is an
// address of that shard (any generation). For such a wallet the payment kinds (withdrawal: an EVM native or token transfer; eip3009) need a
// credential that passes checks 1 to 13; approvals are ignored. Every other kind is internal and unchanged, except that it may not carry a credential.
// A credential for a wallet that is not Gate-governed, and an EIP-3009 authorization from one, are refused (check 0).
//
// A refusal's reason is "<code>: <detail>", or "<code>: field <field>: <detail>" when the spec names a field: the codes of the spec unchanged, so the
// signing API can map them to statuses (GateRefusal parses it).

// PaymentScope is what a decision knows about the wallet a job pays from, before any check: WalletID is Gate's id of the Gate-governed wallet ("": not
// Gate-governed). The rule fills the audit facts as it checks.
type PaymentScope struct {
	WalletID string

	setting *GateSetting
	wallet  *GateWallet
	facts   map[string]any
}

// Governed reports whether the job pays from a Gate-governed wallet.
func (s *PaymentScope) Governed() bool { return s != nil && s.WalletID != "" }

// fact records a fact for the audit trail of the decision.
func (s *PaymentScope) fact(k string, v any) {
	if s.facts == nil {
		s.facts = map[string]any{}
	}
	s.facts[k] = v
}

// GateRule is the credential rule. It reads the gate setting from the decider's own guard database at every decision.
type GateRule struct {
	cfg   *Config
	guard *Guard
	mode  Mode
	now   func() time.Time
}

// NewGateRule builds the rule of a decider (NewDecider does).
func NewGateRule(cfg *Config, guard *Guard, mode Mode, now func() time.Time) *GateRule {
	if now == nil {
		now = time.Now
	}
	return &GateRule{cfg: cfg, guard: guard, mode: mode, now: now}
}

// gateReject is the refusal of a spec code, its field and a detail.
func gateReject(code gatecred.Code, field, format string, a ...any) error {
	detail := fmt.Sprintf(format, a...)
	if field != "" {
		detail = "field " + field + ": " + detail
	}
	return reject(string(code), "%s", detail)
}

// GateRefusal reads a refusal reason the rule wrote: the spec's code and field. ok is false for any other reason.
func GateRefusal(reason string) (code gatecred.Code, field string, ok bool) {
	c, rest, found := strings.Cut(reason, ": ")
	if !found {
		return "", "", false
	}
	switch gatecred.Code(c) {
	case gatecred.CredentialMissing, gatecred.CredentialMalformed, gatecred.KIDUnknown, gatecred.SignatureInvalid, gatecred.AudienceMismatch,
		gatecred.WalletMismatch, gatecred.TTLTooLong, gatecred.NotYetValid, gatecred.Expired, gatecred.PaymentMismatch, gatecred.AuthorizationWindow,
		gatecred.Replayed, gatecred.WalletNotGateGoverned, gatecred.FastLaneCap, gatecred.PayloadInvalid:
	default:
		return "", "", false
	}
	if f, ok2 := strings.CutPrefix(rest, "field "); ok2 {
		if name, _, ok3 := strings.Cut(f, ": "); ok3 {
			field = name
		}
	}
	return gatecred.Code(c), field, true
}

// Scope reads the setting in force and finds the Gate-governed wallet the job pays from, if any.
// The facts of the audit trail are filled here, before any check that can refuse, so every refusal of a governed payment (or of a job that carries
// a credential) has them, whichever check refuses: the zone's own withdrawal rules too.
func (r *GateRule) Scope(ctx context.Context, cc *ChainConfig, kv *KeysetView, job signjob.Job, i signjob.Intent, info TxInfo) (*PaymentScope, error) {
	s, err := r.guard.EffectiveGate(ctx, r.cfg)
	if err != nil {
		return nil, err
	}
	sc := &PaymentScope{setting: s}
	if w := s.walletFor(cc, kv, i.PartitionID, info.Sender); w != nil {
		sc.WalletID, sc.wallet = w.WalletID, w
	}
	if !sc.Governed() && i.Credential == "" {
		return sc, nil
	}
	sc.fact("checker", r.mode.actor())
	if sc.Governed() {
		sc.fact("wallet_id", sc.WalletID)
	}
	if i.Credential != "" {
		sc.credentialFacts([]byte(i.Credential))
	}
	var p *PaymentFacts
	switch {
	case i.Kind == evm.KindEIP3009:
		p = info.Payment
	case i.Kind == "withdrawal":
		if f, err := transferPayment(cc, job.Payload); err == nil {
			p = &f
		}
	}
	if p != nil && p.Amount != nil {
		sc.paymentFacts(p)
	}
	return sc, nil
}

// credentialFacts records a credential as received: its fields (opaque ones unchanged) when it parses, else only its size and hash, since its text
// is not trusted.
func (s *PaymentScope) credentialFacts(raw []byte) {
	if parsed, perr := gatecred.Parse(raw); perr == nil {
		s.fact("credential_id", parsed.CredentialID)
		s.fact("obligation_id", parsed.ObligationID)
		s.fact("policy_version", parsed.PolicyVersion)
		s.fact("decision_reason", parsed.DecisionReason)
		s.fact("kid", parsed.KID)
		s.fact("credential_wallet_id", parsed.WalletID)
		s.fact("expires_at", parsed.ExpiresAt)
		return
	}
	h := sha256.Sum256(raw)
	s.fact("credential_size", len(raw))
	s.fact("credential_sha256", hex.EncodeToString(h[:]))
}

// payment is a decoded payment in the credential's terms (lower-case addresses, "native").
func (s *PaymentScope) payment(i signjob.Intent, p *PaymentFacts) gatecred.Payment {
	pay := gatecred.Payment{WalletID: s.WalletID, Chain: p.Chain, Asset: gatecred.NativeAsset, Payee: strings.ToLower(p.Payee), Amount: p.Amount.String()}
	if p.Asset != gatecred.NativeAsset {
		pay.Asset = strings.ToLower(p.Asset)
	}
	if i.Kind == evm.KindEIP3009 {
		va, vb := int64(min(p.ValidAfter, uint64(gatecred.MaxTimestamp))), int64(min(p.ValidBefore, uint64(gatecred.MaxTimestamp)))
		pay.ValidAfter, pay.ValidBefore = &va, &vb
	}
	return pay
}

func (s *PaymentScope) paymentFacts(p *PaymentFacts) {
	asset := gatecred.NativeAsset
	if p.Asset != gatecred.NativeAsset {
		asset = strings.ToLower(p.Asset)
	}
	s.fact("payment", map[string]any{"chain": p.Chain, "asset": asset, "payee": strings.ToLower(p.Payee), "amount": p.Amount.String()})
}

// walletFor returns the Gate-governed wallet a job of partitionID sent from sender pays from, or nil. A wallet covers its hot shard: every partition
// of the shard (every asset), every address the config gives those partitions on the chain, and every generation's address the keyset view knows.
func (s *GateSetting) walletFor(cc *ChainConfig, kv *KeysetView, partitionID, sender string) *GateWallet {
	jobShard := ""
	if k, err := partition.Parse(partitionID); err == nil && k.Tier == partition.TierHot {
		jobShard = string(k.ShardID())
	}
	for i := range s.Wallets {
		w := &s.Wallets[i]
		wShard := ""
		if k, err := partition.Parse(w.Partition); err == nil && k.Tier == partition.TierHot {
			wShard = string(k.ShardID())
		}
		if partitionID == w.Partition || (wShard != "" && wShard == jobShard) {
			return w
		}
		if sender == "" || cc == nil || (cc.Family != "" && cc.Family != FamilyEVM) {
			continue
		}
		if _, onChain := cc.EVM.HotAddresses[w.Partition]; !onChain {
			continue // the wallet is on another chain: the same address there is another account
		}
		for p, a := range cc.EVM.HotAddresses {
			same := p == w.Partition
			if k, err := partition.Parse(p); err == nil && wShard != "" && k.Tier == partition.TierHot && string(k.ShardID()) == wShard {
				same = true
			}
			if same && strings.EqualFold(a.Hex(), sender) {
				return w
			}
		}
		if kv != nil && wShard != "" {
			for _, e := range kv.Generations(partition.ShardID(wShard)) {
				if e.Chain == cc.Name && strings.EqualFold(e.Address, sender) {
					return w
				}
			}
		}
	}
	return nil
}

// CheckPayment runs checks 1 to 13 for a job of a Gate-governed wallet (s.Governed()), inside the guard transaction gt: the pure checks of gatecred
// against what the zone decoded (p), then the replay record and the fast lane from this guard's own records. It writes the record of an accepted
// credential; a retry of the same digest writes nothing and is not counted again.
func (r *GateRule) CheckPayment(ctx context.Context, gt *GuardTx, job signjob.Job, i signjob.Intent, p PaymentFacts, s *PaymentScope) error {
	now := r.now()
	s.fact("checker", r.mode.actor())
	if !s.Governed() {
		s.fact("code", string(gatecred.WalletNotGateGoverned))
		return gateReject(gatecred.WalletNotGateGoverned, "", "the paying wallet is not Gate-governed in this zone")
	}
	s.fact("wallet_id", s.WalletID)
	set := s.setting
	pay := s.payment(i, &p)
	s.paymentFacts(&p)
	if i.Credential == "" {
		s.fact("code", string(gatecred.CredentialMissing))
		return gateReject(gatecred.CredentialMissing, "", "a payment from Gate-governed wallet %s needs a Gate credential; approvals do not replace it", s.WalletID)
	}
	raw := []byte(i.Credential)
	s.credentialFacts(raw)
	refuse := func(err error) error {
		var ge *gatecred.Error
		if !errors.As(err, &ge) {
			return err
		}
		s.fact("code", string(ge.Code))
		if ge.Field != "" {
			s.fact("field", ge.Field)
		}
		return gateReject(ge.Code, ge.Field, "%s", ge.Detail)
	}

	// A decision this checker already made: the same credential_id with the same payload digest and wallet in its own records. It is a retry of that
	// signing (the gateway returns the stored signature, a cosigner allows the same digest again), so the time checks (7 to 9) and the fast lane do not
	// run again: the credential may have expired since, and the payment is already counted. Signature, audience, wallet and payment are checked again
	// (they cannot differ for the same digest, and cost nothing). Nothing is written.
	var prevDigest []byte
	var prevWallet string
	used := false
	if parsed, perr := gatecred.Parse(raw); perr == nil {
		err := gt.tx.QueryRow(ctx, `SELECT payload_digest, wallet_id FROM gate_credentials_used WHERE credential_id=$1`, parsed.CredentialID).Scan(&prevDigest, &prevWallet)
		switch {
		case err == nil:
			used = true
		case !errors.Is(err, pgx.ErrNoRows):
			return fmt.Errorf("gateway: read gate credential: %w", err)
		}
		if used && bytes.Equal(prevDigest, job.Digest) && prevWallet == s.WalletID {
			check := &gatecred.Config{Audience: set.Audience, Keys: set.KeysAt(now), Skew: set.Skew, MaxTTL: set.MaxTTL}
			if _, err := check.Verify(raw, pay, time.Unix(parsed.IssuedAt, 0)); err != nil { // the clock of the first decision's window
				return refuse(err)
			}
			s.fact("retry", true)
			s.fact("code", "accepted")
			return nil
		}
	}

	// 1 to 11, every check, at this checker's clock.
	gc := &gatecred.Config{Audience: set.Audience, Keys: set.KeysAt(now), Skew: set.Skew, MaxTTL: set.MaxTTL}
	cred, err := gc.Verify(raw, pay, now)
	if err != nil {
		return refuse(err)
	}

	// 12. Replay: the first use wins at this checker; any other payload under a used credential_id is refused.
	if used {
		s.fact("code", string(gatecred.Replayed))
		return gateReject(gatecred.Replayed, "", "credential %s was already used at this checker for another payload", cred.CredentialID)
	}

	// 13. Fast lane, from this guard's own records at signing time. A replacement of the same intent under a new credential is not counted twice.
	asset := p.AssetSymbol
	lim := s.wallet.limits(asset)
	if p.Amount.Cmp(lim.PerPayment) > 0 {
		s.fact("code", string(gatecred.FastLaneCap))
		return gateReject(gatecred.FastLaneCap, "", "amount %s of %s exceeds the per-payment limit %s of wallet %s", p.Amount, asset, lim.PerPayment, s.WalletID)
	}
	for _, w := range []struct {
		name  string
		since time.Duration
		limit *big.Int
	}{{"per-hour", time.Hour, lim.PerHour}, {"per-day", 24 * time.Hour, lim.PerDay}} {
		var sum string
		if err := gt.tx.QueryRow(ctx, `SELECT coalesce(sum(amount), 0)::text FROM (SELECT DISTINCT ON (intent_id) amount FROM gate_credentials_used
			WHERE wallet_id=$1 AND asset_symbol=$2 AND signed_at > $3 AND intent_id <> $4 ORDER BY intent_id, amount DESC) s`,
			s.WalletID, asset, now.Add(-w.since), i.ID).Scan(&sum); err != nil {
			return fmt.Errorf("gateway: count gate payments: %w", err)
		}
		if total := new(big.Int).Add(parseBig(sum), p.Amount); total.Cmp(w.limit) > 0 {
			s.fact("code", string(gatecred.FastLaneCap))
			return gateReject(gatecred.FastLaneCap, "", "%s of %s already paid in the %s window plus %s exceeds the %s limit %s of wallet %s",
				sum, asset, w.name, p.Amount, w.name, w.limit, s.WalletID)
		}
	}

	keep := time.Unix(cred.ExpiresAt, 0).Add(set.Skew).Add(24 * time.Hour)
	if floor := now.Add(24 * time.Hour); keep.Before(floor) {
		keep = floor
	}
	tag, err := gt.tx.Exec(ctx, `INSERT INTO gate_credentials_used (credential_id, payload_digest, intent_id, wallet_id, chain, asset, asset_symbol, payee, amount,
		decision, checker, expires_at, signed_at, keep_until) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'accepted',$10,$11,$12,$13) ON CONFLICT (credential_id) DO NOTHING`,
		cred.CredentialID, job.Digest, i.ID, s.WalletID, pay.Chain, pay.Asset, asset, pay.Payee, p.Amount.String(), r.mode.actor(), cred.ExpiresAt, now, keep)
	if err != nil {
		return fmt.Errorf("gateway: record gate credential: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// Taken in the meantime under another chain's lock: the first use won.
		s.fact("code", string(gatecred.Replayed))
		return gateReject(gatecred.Replayed, "", "credential %s was used at this checker at the same moment", cred.CredentialID)
	}
	s.fact("code", "accepted")
	return nil
}

// transferPayment decodes an EVM withdrawal's payload into the payment a credential names (docs/gate-credential.md, "What a credential is bound to"):
// a native transfer (no calldata: payee to, amount value) or a token transfer (to a token of this chain's config, value 0, calldata exactly
// transfer(address,uint256): payee and amount from the call). Anything else is not payable with a credential. It reads the payload itself, apart from
// the chain verifier that accepted it, and is called only after that verifier did (the digest is the payload's).
func transferPayment(cc *ChainConfig, payload []byte) (PaymentFacts, error) {
	if cc == nil || (cc.Family != "" && cc.Family != FamilyEVM) {
		return PaymentFacts{}, errors.New("a Gate credential pays EVM transfers only")
	}
	var pl evm.Payload
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&pl); err != nil {
		return PaymentFacts{}, fmt.Errorf("evm payload: %v", err)
	}
	if pl.ChainID != cc.EVM.ChainID || !common.IsHexAddress(pl.To) {
		return PaymentFacts{}, errors.New("evm payload: chain id or destination")
	}
	to := common.HexToAddress(pl.To)
	value, ok := new(big.Int).SetString(pl.Value, 10)
	if !ok || value.Sign() < 0 {
		return PaymentFacts{}, errors.New("evm payload: value")
	}
	var data []byte
	if pl.Data != "" && pl.Data != "0x" {
		var err error
		if data, err = hexutil.Decode(pl.Data); err != nil {
			return PaymentFacts{}, errors.New("evm payload: data")
		}
	}
	f := PaymentFacts{Chain: fmt.Sprintf("eip155:%d", pl.ChainID), ChainName: cc.Name, Payer: pl.From}
	if len(data) == 0 {
		if value.Sign() == 0 {
			return PaymentFacts{}, errors.New("a native transfer of zero")
		}
		native := cc.EVM.NativeAsset
		if native == "" {
			native = evm.DefaultNativeAsset
		}
		f.Asset, f.AssetSymbol, f.Payee, f.Amount = gatecred.NativeAsset, native, to.Hex(), value
		return f, nil
	}
	symbol := ""
	for sym, t := range cc.EVM.Assets {
		if t.Address == to {
			symbol = sym
		}
	}
	transferSel := []byte{0xa9, 0x05, 0x9c, 0xbb}
	switch {
	case symbol == "":
		return PaymentFacts{}, fmt.Errorf("calldata to %s, which is not a token of this chain", to.Hex())
	case value.Sign() != 0:
		return PaymentFacts{}, errors.New("a token transfer that also carries value")
	case len(data) != 68 || !bytes.Equal(data[:4], transferSel) || !bytes.Equal(data[4:16], make([]byte, 12)):
		return PaymentFacts{}, errors.New("calldata is not exactly transfer(address,uint256)")
	}
	amt := new(big.Int).SetBytes(data[36:68])
	if amt.Sign() == 0 {
		return PaymentFacts{}, errors.New("a token transfer of zero")
	}
	f.Asset, f.AssetSymbol, f.Payee, f.Amount = to.Hex(), symbol, common.BytesToAddress(data[16:36]).Hex(), amt
	return f, nil
}

// PruneGateCredentials removes the replay records whose keep_until has passed (expires_at + skew + 1 day, never sooner than a day after signing):
// none of them can verify any more, and the fast lane counts at most a day back. It returns how many it removed.
func (g *Guard) PruneGateCredentials(ctx context.Context, now time.Time) (int64, error) {
	tag, err := g.pool.Exec(ctx, `DELETE FROM gate_credentials_used WHERE keep_until < $1`, now)
	if err != nil {
		return 0, fmt.Errorf("gateway: prune gate credentials: %w", err)
	}
	return tag.RowsAffected(), nil
}

// RunGatePruner prunes the replay records of the guard every interval until ctx ends: the small loop qv-gateway and qv-cosigner run (the zone has no
// other periodic cleanup). A failure is logged and tried again at the next tick.
func RunGatePruner(ctx context.Context, g *Guard, every time.Duration, log *slog.Logger) {
	for {
		if n, err := g.PruneGateCredentials(ctx, time.Now()); err != nil {
			if ctx.Err() == nil {
				log.Error("cannot prune the gate credential records", "error", err.Error())
			}
		} else if n > 0 {
			log.Info("pruned gate credential records", "rows", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}
