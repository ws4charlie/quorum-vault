// Package signing is the sign-path orchestrator:
//
//	request -> policy -> (approval) -> sign (HSM, or MPC 2-of-3 / 3-of-3 by tier) -> verify -> store -> audit
//
// It is the only writer of sign_requests. Request state machine:
//
//	Submit:  deny -> denied            needs_approval -> pending_approval     allow -> approved
//	Vote:    pending_approval -> approved (enough approvals) | rejected (any reject)
//	sign:    approved -> signing -> signed | failed
//
// Every move is a conditional UPDATE ... WHERE status IN (allowed prior
// states) (see transition), so two callers racing on the same request cannot
// both move it, and in particular only one of them can ever start signing.
//
// Audit events are appended after the state change commits (PLAN decision:
// domain.Auditor has no transaction). An append failure after a committed
// change is logged at error level and does not undo or fail the operation.
package signing

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ws4charlie/quorum-vault/internal/approval"
	"github.com/ws4charlie/quorum-vault/internal/chain/eth"
	"github.com/ws4charlie/quorum-vault/internal/domain"
	"github.com/ws4charlie/quorum-vault/internal/keys"
	"github.com/ws4charlie/quorum-vault/internal/policy"
	"github.com/ws4charlie/quorum-vault/internal/signer"
)

var (
	ErrNotFound = errors.New("signing: not found")
	ErrInvalid  = errors.New("signing: invalid request")
	ErrConflict = errors.New("signing: request is not in a state that allows this")
)

// SignerFunc returns a Signer for a key of one backend.
type SignerFunc func(key domain.Key) (signer.Signer, error)

// Config wires a Service.
type Config struct {
	Pool      *pgxpool.Pool
	Registry  *keys.Registry
	Policy    *policy.Engine
	Approvals *approval.Queue
	Audit     domain.Auditor
	Signers   map[domain.Backend]SignerFunc
	// RPC is optional (SEPOLIA_RPC_URL): fills nonce/fees when a request omits
	// them, and broadcasts signed txs when Broadcast is true.
	RPC         *eth.Client
	Broadcast   bool
	SignTimeout time.Duration // per signing ceremony; 0 = 2 minutes
	Logger      *slog.Logger
}

// Service runs the sign path.
type Service struct {
	pool        *pgxpool.Pool
	reg         *keys.Registry
	pol         *policy.Engine
	q           *approval.Queue
	aud         domain.Auditor
	signers     map[domain.Backend]SignerFunc
	rpc         *eth.Client
	broadcast   bool
	signTimeout time.Duration
	log         *slog.Logger

	walletMu sync.Map // wallet id -> *sync.Mutex; serializes Submit per wallet
}

func New(cfg Config) *Service {
	if cfg.SignTimeout == 0 {
		cfg.SignTimeout = 2 * time.Minute
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Service{pool: cfg.Pool, reg: cfg.Registry, pol: cfg.Policy, q: cfg.Approvals, aud: cfg.Audit,
		signers: cfg.Signers, rpc: cfg.RPC, broadcast: cfg.Broadcast && cfg.RPC != nil,
		signTimeout: cfg.SignTimeout, log: cfg.Logger}
}

// Input is a new sign request. Zero/nil fields take defaults: chain id
// Sepolia (or the RPC node's), gas 21000, fees 1 gwei tip / 30 gwei cap (or
// the node's suggestion). Nonce is required unless an RPC node is configured.
type Input struct {
	WalletID             string
	ChainID              int64
	To                   string
	ValueWei             *big.Int
	Data                 []byte
	Nonce                *uint64
	GasLimit             uint64
	MaxFeePerGas         *big.Int
	MaxPriorityFeePerGas *big.Int
}

// Result is a request after Submit or Vote.
type Result struct {
	Request   domain.SignRequest `json:"request"`
	From      string             `json:"from,omitempty"`       // recovered sender (signed only)
	Tally     *approval.Tally    `json:"tally,omitempty"`      // Vote only
	SignError string             `json:"sign_error,omitempty"` // status failed: why
	Broadcast string             `json:"broadcast,omitempty"`  // "ok" or the broadcast error
	TimingsMS map[string]float64 `json:"timings_ms,omitempty"` // sign (backend ceremony), total (this call)
}

func (s *Service) lockWallet(id string) func() {
	m, _ := s.walletMu.LoadOrStore(id, &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

// Submit validates in, binds it to the wallet's active key, evaluates policy,
// stores the request with its decision and, when policy allows, signs it.
func (s *Service) Submit(ctx context.Context, actor string, in Input) (Result, error) {
	start := time.Now()
	if actor == "" {
		return Result{}, fmt.Errorf("%w: actor is required", ErrInvalid)
	}
	w, err := s.reg.GetWallet(ctx, in.WalletID)
	if errors.Is(err, keys.ErrNotFound) {
		return Result{}, fmt.Errorf("%w: wallet %q", ErrNotFound, in.WalletID)
	}
	if err != nil {
		return Result{}, err
	}
	req, err := s.prepare(ctx, w, actor, in)
	if err != nil {
		return Result{}, err
	}

	// Serialize evaluate+insert per wallet so concurrent requests see each
	// other in the velocity and daily-spend windows. In-process only: a
	// multi-instance deployment would take a per-wallet DB lock instead.
	unlock := s.lockWallet(w.ID)
	d, err := s.pol.Evaluate(ctx, req, w)
	if err != nil {
		unlock()
		return Result{}, fmt.Errorf("signing: policy: %w", err)
	}
	req.Decision = &d
	switch d.Outcome {
	case domain.OutcomeDeny:
		req.Status = domain.StatusDenied
	case domain.OutcomeNeedsApproval:
		req.Status = domain.StatusPendingApproval
	case domain.OutcomeAllow:
		req.Status = domain.StatusApproved // cleared to sign; counts toward daily spend
	default:
		unlock()
		return Result{}, fmt.Errorf("signing: unknown policy outcome %q", d.Outcome)
	}
	err = s.insert(ctx, &req)
	unlock()
	if err != nil {
		return Result{}, err
	}

	s.audit(ctx, actor, domain.EventRequestCreated, req, map[string]any{
		"to": req.To, "value_wei": req.ValueWei.String(), "chain_id": req.ChainID, "nonce": req.Nonce,
		"gas_limit": req.GasLimit, "max_fee_per_gas": req.MaxFeePerGas.String(),
		"max_priority_fee_per_gas": req.MaxPriorityFeePerGas.String(), "data": hexOrEmpty(req.Data),
		"tier": w.Tier, "backend": w.Backend})
	s.audit(ctx, actor, domain.EventPolicyDecision, req, map[string]any{
		"outcome": d.Outcome, "reasons": d.Reasons, "required_approvals": d.RequiredApprovals, "status": req.Status})

	res := Result{Request: req}
	if req.Status == domain.StatusApproved {
		res = s.sign(ctx, actor, req)
	}
	res.timing("total", start)
	return res, nil
}

// prepare validates in and fills defaults.
func (s *Service) prepare(ctx context.Context, w domain.Wallet, actor string, in Input) (domain.SignRequest, error) {
	to, err := policy.NormalizeAddress(in.To)
	if err != nil {
		return domain.SignRequest{}, fmt.Errorf("%w: to: %v", ErrInvalid, err)
	}
	if in.ValueWei == nil || in.ValueWei.Sign() < 0 {
		return domain.SignRequest{}, fmt.Errorf("%w: value_wei must be >= 0", ErrInvalid)
	}
	if in.ChainID < 0 {
		return domain.SignRequest{}, fmt.Errorf("%w: chain_id must be > 0", ErrInvalid)
	}
	for _, f := range []*big.Int{in.MaxFeePerGas, in.MaxPriorityFeePerGas} {
		if f != nil && f.Sign() < 0 {
			return domain.SignRequest{}, fmt.Errorf("%w: fees must be >= 0", ErrInvalid)
		}
	}
	req := domain.SignRequest{
		ID: uuid.NewString(), WalletID: w.ID, ChainID: in.ChainID, To: common.HexToAddress(to).Hex(),
		ValueWei: new(big.Int).Set(in.ValueWei), Data: in.Data, GasLimit: in.GasLimit,
		MaxFeePerGas: in.MaxFeePerGas, MaxPriorityFeePerGas: in.MaxPriorityFeePerGas, Requester: actor,
	}
	if in.Nonce != nil {
		req.Nonce = *in.Nonce
	}
	needNode := in.Nonce == nil || req.MaxFeePerGas == nil || req.MaxPriorityFeePerGas == nil
	if s.rpc != nil && needNode {
		k, err := s.reg.ActiveKey(ctx, w.ID)
		if err != nil {
			return domain.SignRequest{}, fmt.Errorf("%w: wallet %s has no active key", ErrInvalid, w.ID)
		}
		nonce, tip, feeCap, err := s.rpc.Suggest(ctx, common.HexToAddress(k.Address))
		if err != nil {
			return domain.SignRequest{}, fmt.Errorf("signing: rpc: %w", err)
		}
		if in.Nonce == nil {
			req.Nonce = nonce
		}
		if req.MaxPriorityFeePerGas == nil {
			req.MaxPriorityFeePerGas = tip
		}
		if req.MaxFeePerGas == nil {
			req.MaxFeePerGas = feeCap
		}
		if req.ChainID == 0 {
			req.ChainID = s.rpc.ChainID().Int64()
		}
	} else if in.Nonce == nil {
		return domain.SignRequest{}, fmt.Errorf("%w: nonce is required (no RPC node configured)", ErrInvalid)
	}
	if req.ChainID == 0 {
		req.ChainID = eth.SepoliaChainID
	}
	if req.GasLimit == 0 {
		req.GasLimit = eth.DefaultGasLimit
	}
	if req.MaxPriorityFeePerGas == nil {
		req.MaxPriorityFeePerGas = big.NewInt(eth.DefaultTipWei)
	}
	if req.MaxFeePerGas == nil {
		req.MaxFeePerGas = big.NewInt(eth.DefaultFeeCapWei)
	}
	if req.MaxPriorityFeePerGas.Cmp(req.MaxFeePerGas) > 0 {
		return domain.SignRequest{}, fmt.Errorf("%w: max_priority_fee_per_gas exceeds max_fee_per_gas", ErrInvalid)
	}
	return req, nil
}

// Vote records an approve/reject vote. When the vote completes the tally the
// request moves to approved (and is signed) or rejected.
func (s *Service) Vote(ctx context.Context, actor, requestID string, approve bool, comment string) (Result, error) {
	start := time.Now()
	if actor == "" {
		return Result{}, fmt.Errorf("%w: actor is required", ErrInvalid)
	}
	req, err := s.Get(ctx, requestID)
	if err != nil {
		return Result{}, err
	}
	t, err := s.q.Vote(ctx, req, actor, approve, comment)
	if err != nil && strings.HasPrefix(err.Error(), "approval: audit") {
		// The vote is stored; only its audit event failed. Carry on with a
		// recount so the request does not get stuck pending.
		s.log.Error("AUDIT APPEND FAILED after committed vote", "request_id", req.ID, "approver", actor, "err", err)
		t, err = s.tally(ctx, req)
	}
	if err != nil {
		return Result{}, err
	}
	res := Result{Request: req, Tally: &t}
	if t.Done {
		to, typ := domain.StatusApproved, domain.EventRequestApproved
		if t.Rejected {
			to, typ = domain.StatusRejected, domain.EventRequestRejected
		}
		moved, ok, err := s.transition(ctx, req.ID, to, domain.StatusPendingApproval)
		if err != nil {
			return Result{}, err
		}
		if ok {
			s.audit(ctx, actor, typ, moved, map[string]any{"tally": t, "last_vote_by": actor})
			res.Request = moved
			if to == domain.StatusApproved {
				signed := s.sign(ctx, actor, moved)
				signed.Tally = &t
				res = signed
			}
		} else if res.Request, err = s.Get(ctx, req.ID); err != nil {
			// A concurrent vote completed the request first; report its state.
			return Result{}, err
		}
	}
	res.timing("total", start)
	return res, nil
}

func (s *Service) tally(ctx context.Context, req domain.SignRequest) (approval.Tally, error) {
	t := approval.Tally{Required: 1}
	if req.Decision != nil && req.Decision.RequiredApprovals > 1 {
		t.Required = req.Decision.RequiredApprovals
	}
	err := s.pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE approve), bool_or(NOT approve) IS TRUE
		FROM approvals WHERE request_id = $1`, req.ID).Scan(&t.Approvals, &t.Rejected)
	t.Done = t.Rejected || t.Approvals >= t.Required
	return t, err
}

// sign runs approved -> signing -> signed | failed. It never returns an error:
// failures end in status failed with Result.SignError set. It runs detached
// from the caller's cancellation (with its own timeout) so a client hanging
// up mid-ceremony cannot leave the request stuck in signing.
func (s *Service) sign(ctx context.Context, actor string, req domain.SignRequest) Result {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.signTimeout)
	defer cancel()
	res := Result{Request: req}

	r, ok, err := s.transition(ctx, req.ID, domain.StatusSigning, domain.StatusApproved)
	if err != nil || !ok {
		if err == nil {
			err = fmt.Errorf("%w: request %s is no longer approved", ErrConflict, req.ID)
		}
		res.SignError = err.Error()
		if cur, gerr := s.Get(ctx, req.ID); gerr == nil {
			res.Request = cur
		}
		return res
	}
	res.Request = r
	fail := func(stage string, err error) Result {
		s.log.Warn("sign failed", "request_id", r.ID, "stage", stage, "err", err)
		if failed, ok, uerr := s.transition(ctx, r.ID, domain.StatusFailed, domain.StatusSigning); uerr == nil && ok {
			res.Request = failed
		}
		s.audit(ctx, actor, domain.EventSignFailed, r, map[string]any{"stage": stage, "error": err.Error()})
		res.SignError = err.Error()
		return res
	}

	key, err := s.reg.Get(ctx, r.KeyID)
	if err != nil {
		return fail("load_key", err)
	}
	if err := s.reg.AuthorizeSign(key, r); err != nil {
		return fail("authorize", err)
	}
	w, err := s.reg.GetWallet(ctx, r.WalletID)
	if err != nil {
		return fail("load_wallet", err)
	}
	mk, ok := s.signers[key.Backend]
	if !ok {
		return fail("signer", fmt.Errorf("no signer for backend %q", key.Backend))
	}
	sg, err := mk(key)
	if err != nil {
		return fail("signer", err)
	}
	quorum := Quorum(w.Tier)
	params, err := eth.FromRequest(r)
	if err != nil {
		return fail("build_tx", err)
	}
	tx, digest, err := eth.BuildTx(params)
	if err != nil {
		return fail("build_tx", err)
	}
	s.audit(ctx, actor, domain.EventSignStarted, r, map[string]any{
		"backend": key.Backend, "tier": w.Tier, "quorum": quorum, "key_version": key.Version,
		"address": key.Address, "digest": "0x" + hex.EncodeToString(digest[:])})

	t0 := time.Now()
	out, err := sg.SignDigest(ctx, digest, signer.SignOptions{Quorum: quorum})
	res.timing("sign", t0)
	if err != nil {
		return fail("sign", err)
	}
	// Verify before store: the signature must recover to the wallet address,
	// or nothing is written and the request fails.
	st, err := eth.Assemble(tx, out.Sig, sg.PublicKey())
	if err != nil {
		return fail("verify", err)
	}
	if st.From != common.HexToAddress(key.Address) {
		return fail("verify", fmt.Errorf("%w: got %s, key address %s", eth.ErrSenderMismatch, st.From.Hex(), key.Address))
	}
	r, err = s.storeSigned(ctx, r.ID, st.Sig65, st.Raw, st.Hash.Hex())
	if err != nil {
		return fail("store", err)
	}
	res.Request, res.From = r, st.From.Hex()
	s.audit(ctx, actor, domain.EventSignCompleted, r, map[string]any{
		"backend": key.Backend, "participants": out.Participants, "quorum": quorum, "meta": out.Meta,
		"signature": "0x" + hex.EncodeToString(st.Sig65), "tx_hash": st.Hash.Hex(), "from": st.From.Hex(),
		"sign_ms": res.TimingsMS["sign"]})

	if s.broadcast {
		h, err := s.rpc.Broadcast(ctx, st.Raw)
		p := map[string]any{"tx_hash": st.Hash.Hex(), "ok": err == nil}
		res.Broadcast = "ok"
		if err != nil {
			p["error"], res.Broadcast = err.Error(), err.Error()
		} else {
			p["tx_hash"] = h.Hex()
		}
		s.audit(ctx, actor, domain.EventTxBroadcast, r, p)
	}
	return res
}

// Quorum is the MPC signing quorum for a tier: hot 0 (threshold, 2 of 3),
// cold 3 (all parties). HSM signers ignore it.
func Quorum(t domain.Tier) int {
	if t == domain.TierCold {
		return 3
	}
	return 0
}

// audit appends an event for req. Failures are logged loudly, never returned:
// the state change it describes has already committed.
func (s *Service) audit(ctx context.Context, actor, typ string, req domain.SignRequest, payload map[string]any) {
	b, err := json.Marshal(payload)
	if err == nil {
		_, err = s.aud.Append(context.WithoutCancel(ctx), domain.AuditEvent{Actor: actor, Type: typ,
			RequestID: req.ID, WalletID: req.WalletID, KeyID: req.KeyID, Payload: b})
	}
	if err != nil {
		s.log.Error("AUDIT APPEND FAILED after committed change", "type", typ, "request_id", req.ID, "err", err)
	}
}

func (r *Result) timing(name string, since time.Time) {
	if r.TimingsMS == nil {
		r.TimingsMS = map[string]float64{}
	}
	r.TimingsMS[name] = float64(time.Since(since).Microseconds()) / 1000
}

func hexOrEmpty(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return "0x" + hex.EncodeToString(b)
}
