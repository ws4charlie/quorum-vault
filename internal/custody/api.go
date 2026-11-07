package custody

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"

	"github.com/google/uuid"

	"github.com/ws4charlie/quorum-vault/internal/audit"
	"github.com/ws4charlie/quorum-vault/internal/coldsign"
	"github.com/ws4charlie/quorum-vault/internal/ledger"
)

// Orchestrator starts and wakes the withdrawal workflow. internal/workflow
// implements it; the API treats both calls as best effort because the
// reconciler workflow starts any open withdrawal that has no workflow, and the
// workflow re-reads approvals from the database on a timer.
type Orchestrator interface {
	StartWithdrawal(ctx context.Context, id string) error
	SignalWithdrawal(ctx context.Context, id string) error
}

// API is the /v2 HTTP handler. There is no real authentication: the X-Actor
// header names the caller, as in the demo.
type API struct {
	svc  *Service
	orch Orchestrator
	log  *slog.Logger
}

// NewAPI returns the handler. orch may be nil (tests).
func NewAPI(svc *Service, orch Orchestrator, log *slog.Logger) *API {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &API{svc: svc, orch: orch, log: log}
}

// Handler returns the routed handler.
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v2/customers", a.createCustomer)
	mux.HandleFunc("POST /v2/customers/{id}/deposit-addresses", a.depositAddress)
	mux.HandleFunc("GET /v2/customers/{id}/balances", a.balances)
	mux.HandleFunc("POST /v2/withdrawals", a.requestWithdrawal)
	mux.HandleFunc("GET /v2/withdrawals/{id}", a.getWithdrawal)
	mux.HandleFunc("POST /v2/withdrawals/{id}/approvals", a.approve)
	mux.HandleFunc("POST /v2/withdrawals/{id}/rejections", a.reject)
	mux.HandleFunc("GET /v2/withdrawals/{id}/intent", a.intent)
	mux.HandleFunc("GET /v2/reconcile", a.reconcile)
	mux.HandleFunc("GET /v2/refills", a.listRefills)
	mux.HandleFunc("GET /v2/refills/{id}", a.getRefill)
	mux.HandleFunc("POST /v2/refills/{id}/export", a.exportRefill)
	mux.HandleFunc("POST /v2/refills/{id}/import", a.importRefill)
	mux.HandleFunc("POST /v2/cold/fundings", a.fundCold)
	mux.HandleFunc("POST /v2/cold/spends", a.spendCold)
	mux.HandleFunc("POST /v2/cold/actions", a.requestAction)
	mux.HandleFunc("POST /v2/refills/{id}/close", a.closeRefill)
	mux.HandleFunc("POST /v2/guardian/freezes", a.guardianFreeze)
	mux.HandleFunc("GET /v2/audit/verify", a.auditVerify)
	// Whoever the X-Actor header names is the actor of everything the request causes, in the audit trail.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if actor := r.Header.Get("X-Actor"); ValidID(actor) {
			r = r.WithContext(WithActor(r.Context(), actor))
		}
		mux.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (a *API) fail(w http.ResponseWriter, err error) {
	code, msg := http.StatusInternalServerError, "internal error"
	switch {
	case errors.Is(err, ErrInvalid):
		code, msg = http.StatusBadRequest, err.Error()
	case errors.Is(err, ErrNotFound):
		code, msg = http.StatusNotFound, err.Error()
	case errors.Is(err, ledger.ErrInsufficientFunds):
		code, msg = http.StatusConflict, "insufficient funds"
	case errors.Is(err, ErrIdempotencyConflict):
		code, msg = http.StatusConflict, err.Error()
	case errors.Is(err, ErrSelfApproval):
		code, msg = http.StatusForbidden, err.Error()
	case errors.Is(err, ErrNotPending):
		code, msg = http.StatusConflict, err.Error()
	default:
		a.log.Error("request failed", "error", err.Error())
	}
	writeJSON(w, code, map[string]string{"error": msg})
}

func (a *API) actor(w http.ResponseWriter, r *http.Request) (string, bool) {
	actor := r.Header.Get("X-Actor")
	if !ValidID(actor) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "X-Actor header is required"})
		return "", false
	}
	return actor, true
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return nil
}

func (a *API) createCustomer(w http.ResponseWriter, r *http.Request) {
	actor, ok := a.actor(w, r)
	if !ok {
		return
	}
	var body struct {
		ID      string `json:"id"`
		USState string `json:"us_state"`
	}
	if err := decode(r, &body); err != nil {
		a.fail(w, err)
		return
	}
	if body.ID == "" {
		// Without an ID, the Idempotency-Key makes the request repeatable.
		if k := r.Header.Get("Idempotency-Key"); k != "" {
			body.ID = "c-" + uuid.NewSHA1(uuid.NameSpaceOID, []byte(actor+"\x00"+k)).String()
		} else {
			body.ID = "c-" + uuid.NewString()
		}
	}
	c, created, err := a.svc.CreateCustomer(r.Context(), actor, body.ID, body.USState)
	if err != nil {
		a.fail(w, err)
		return
	}
	code := http.StatusOK
	if created {
		code = http.StatusCreated
	}
	writeJSON(w, code, c)
}

func (a *API) depositAddress(w http.ResponseWriter, r *http.Request) {
	actor, ok := a.actor(w, r)
	if !ok {
		return
	}
	var body struct {
		Chain string `json:"chain"`
	}
	if err := decode(r, &body); err != nil {
		a.fail(w, err)
		return
	}
	d, err := a.svc.EnsureDepositAddress(r.Context(), actor, r.PathValue("id"), body.Chain)
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (a *API) balances(w http.ResponseWriter, r *http.Request) {
	b, err := a.svc.Balances(r.Context(), r.PathValue("id"))
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"customer": r.PathValue("id"), "balances": b})
}

func (a *API) requestWithdrawal(w http.ResponseWriter, r *http.Request) {
	actor, ok := a.actor(w, r)
	if !ok {
		return
	}
	key := r.Header.Get("Idempotency-Key")
	if key == "" || len(key) > 128 {
		a.fail(w, fmt.Errorf("%w: Idempotency-Key header is required", ErrInvalid))
		return
	}
	var body struct {
		Customer string `json:"customer"`
		Asset    string `json:"asset"`
		To       string `json:"to"`
		Amount   string `json:"amount"`
	}
	if err := decode(r, &body); err != nil {
		a.fail(w, err)
		return
	}
	amt, okAmt := new(big.Int).SetString(body.Amount, 10)
	if !okAmt || amt.String() != body.Amount {
		a.fail(w, fmt.Errorf("%w: amount must be a canonical decimal string of base units", ErrInvalid))
		return
	}
	wd, created, err := a.svc.RequestWithdrawal(r.Context(), WithdrawalRequest{
		Actor: actor, IdempotencyKey: key, Customer: body.Customer, Asset: body.Asset, To: body.To, Amount: amt})
	if err != nil {
		a.fail(w, err)
		return
	}
	// The hold is committed. Starting the workflow is best effort: a crash here
	// is repaired by the reconciler workflow, which starts every open withdrawal.
	if a.orch != nil && wd.Status == WdRequested {
		if err := a.orch.StartWithdrawal(r.Context(), wd.ID); err != nil {
			a.log.Warn("could not start the withdrawal workflow; the reconciler will", "withdrawal", wd.ID, "error", err.Error())
		}
	}
	code := http.StatusOK
	if created {
		code = http.StatusCreated
	}
	writeJSON(w, code, wd)
}

func (a *API) getWithdrawal(w http.ResponseWriter, r *http.Request) {
	wd, err := a.svc.GetWithdrawal(r.Context(), r.PathValue("id"))
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, wd)
}

func (a *API) approve(w http.ResponseWriter, r *http.Request) {
	actor, ok := a.actor(w, r)
	if !ok {
		return
	}
	var body struct {
		Actor     string `json:"actor"`
		Signature string `json:"signature"` // hex Ed25519 signature over the intent hash
	}
	if err := decode(r, &body); err != nil {
		a.fail(w, err)
		return
	}
	if body.Actor != actor {
		a.fail(w, fmt.Errorf("%w: body actor %q differs from X-Actor %q", ErrInvalid, body.Actor, actor))
		return
	}
	sig, err := hex.DecodeString(body.Signature)
	if err != nil {
		a.fail(w, fmt.Errorf("%w: signature is not hex", ErrInvalid))
		return
	}
	id := r.PathValue("id")
	n, err := a.svc.AddApproval(r.Context(), id, actor, sig)
	if err != nil {
		a.fail(w, err)
		return
	}
	if a.orch != nil {
		if err := a.orch.SignalWithdrawal(r.Context(), id); err != nil {
			a.log.Warn("could not signal the withdrawal workflow; it re-reads approvals on a timer", "withdrawal", id, "error", err.Error())
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"withdrawal": id, "approvals": n})
}

func (a *API) intent(w http.ResponseWriter, r *http.Request) {
	wd, err := a.svc.GetWithdrawal(r.Context(), r.PathValue("id"))
	if err != nil {
		a.fail(w, err)
		return
	}
	in := a.svc.IntentOf(wd)
	h := in.Hash()
	need, _ := a.svc.Cfg.Required(wd.Asset, wd.Amount)
	writeJSON(w, http.StatusOK, map[string]any{"intent": in, "hash": hex.EncodeToString(h[:]), "canonical": hex.EncodeToString(in.Canonical()),
		"approvals_required": need})
}

func (a *API) reconcile(w http.ResponseWriter, r *http.Request) {
	rep, err := a.svc.Reconcile(r.Context())
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

// rejecter is implemented by orchestrators that can deliver a human rejection.
type rejecter interface {
	RejectWithdrawal(ctx context.Context, id, reason string) error
}

func (a *API) reject(w http.ResponseWriter, r *http.Request) {
	actor, ok := a.actor(w, r)
	if !ok {
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	if err := decode(r, &body); err != nil {
		a.fail(w, err)
		return
	}
	id := r.PathValue("id")
	wd, err := a.svc.GetWithdrawal(r.Context(), id)
	if err != nil {
		a.fail(w, err)
		return
	}
	if wd.Status != WdRequested && wd.Status != WdApproved {
		a.fail(w, ErrNotPending)
		return
	}
	rj, ok := a.orch.(rejecter)
	if !ok {
		a.fail(w, fmt.Errorf("%w: rejections are not available", ErrInvalid))
		return
	}
	if err := a.svc.RecordRejection(r.Context(), id, actor, body.Reason); err != nil {
		a.fail(w, err)
		return
	}
	// Signal-with-start: delivered even if the workflow has not started yet.
	if err := rj.RejectWithdrawal(r.Context(), id, actor+": "+body.Reason); err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"withdrawal": id, "rejected_by": actor})
}

// ---- refills (cold to hot) ----

func refillJSON(r Refill) map[string]any {
	return map[string]any{"id": r.ID, "asset": r.Asset, "partition": r.PartitionID, "cold_address": r.ColdAddress, "to": r.To, "amount": r.Amount.String(),
		"kind": r.Kind, "param": r.Param, "status": r.Status, "revision": r.Revision, "request_hash": r.RequestHash, "tx_hash": r.TxHash, "failure_reason": r.Reason}
}

func (a *API) listRefills(w http.ResponseWriter, r *http.Request) {
	rs, err := a.svc.ListRefills(r.Context())
	if err != nil {
		a.fail(w, err)
		return
	}
	out := make([]map[string]any, 0, len(rs))
	for _, x := range rs {
		out = append(out, refillJSON(x))
	}
	writeJSON(w, http.StatusOK, map[string]any{"refills": out})
}

func (a *API) getRefill(w http.ResponseWriter, r *http.Request) {
	x, err := a.svc.GetRefill(r.Context(), r.PathValue("id"))
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, refillJSON(x))
}

// exportRefill returns the request file for the offline ceremony (nonce and fees read from the node now).
func (a *API) exportRefill(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.actor(w, r); !ok {
		return
	}
	if a.svc.Cfg.Family == FamilyBTC {
		f, err := a.svc.ExportBTCRefill(r.Context(), r.PathValue("id"))
		if err != nil {
			a.fail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, f)
		return
	}
	f, err := a.svc.ExportRefill(r.Context(), r.PathValue("id"))
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, f)
}

// importRefill takes the signed file that came back from the ceremony.
func (a *API) importRefill(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.actor(w, r); !ok {
		return
	}
	if a.svc.Cfg.Family == FamilyBTC {
		var bs coldsign.BTCSigned
		if err := decode(r, &bs); err != nil {
			a.fail(w, err)
			return
		}
		x, err := a.svc.ImportBTCRefill(r.Context(), r.PathValue("id"), bs)
		if err != nil {
			a.fail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, refillJSON(x))
		return
	}
	var signed coldsign.Signed
	if err := decode(r, &signed); err != nil {
		a.fail(w, err)
		return
	}
	x, err := a.svc.ImportRefill(r.Context(), r.PathValue("id"), signed)
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, refillJSON(x))
}

// fundCold books operator funding of the cold address.
func (a *API) fundCold(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.actor(w, r); !ok {
		return
	}
	var body struct {
		ID     string `json:"id"`
		Asset  string `json:"asset"`
		Shard  int    `json:"shard"`
		Amount string `json:"amount"`
	}
	if err := decode(r, &body); err != nil {
		a.fail(w, err)
		return
	}
	amt, ok := new(big.Int).SetString(body.Amount, 10)
	if !ok || body.ID == "" {
		a.fail(w, fmt.Errorf("%w: id and a decimal amount are required", ErrInvalid))
		return
	}
	if err := a.svc.FundCold(r.Context(), body.ID, body.Shard, body.Asset, amt); err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": body.ID, "booked": body.Amount})
}

// spendCold books an operator spend out of the cold address.
func (a *API) spendCold(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.actor(w, r); !ok {
		return
	}
	var body struct {
		ID     string `json:"id"`
		Asset  string `json:"asset"`
		Shard  int    `json:"shard"`
		Amount string `json:"amount"`
	}
	if err := decode(r, &body); err != nil {
		a.fail(w, err)
		return
	}
	amt, ok := new(big.Int).SetString(body.Amount, 10)
	if !ok || body.ID == "" {
		a.fail(w, fmt.Errorf("%w: id and a decimal amount are required", ErrInvalid))
		return
	}
	if err := a.svc.SpendCold(r.Context(), body.ID, body.Shard, body.Asset, amt); err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": body.ID, "booked": body.Amount})
}

// requestAction opens a request for a factory call (set-destination, freeze, set-guardian, transfer-admin, accept-admin).
func (a *API) requestAction(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.actor(w, r); !ok {
		return
	}
	var body struct {
		Kind   string `json:"kind"`
		Param  string `json:"param"`
		Signer string `json:"signer"`
	}
	if err := decode(r, &body); err != nil {
		a.fail(w, err)
		return
	}
	x, err := a.svc.RequestAction(r.Context(), body.Kind, body.Param, body.Signer)
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, refillJSON(x))
}

// closeRefill ends a parked request on an operator's say-so.
func (a *API) closeRefill(w http.ResponseWriter, r *http.Request) {
	actor, ok := a.actor(w, r)
	if !ok {
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	if err := decode(r, &body); err != nil {
		a.fail(w, err)
		return
	}
	if err := a.svc.CloseRefill(r.Context(), r.PathValue("id"), actor, body.Reason); err != nil {
		a.fail(w, err)
		return
	}
	x, err := a.svc.GetRefill(r.Context(), r.PathValue("id"))
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, refillJSON(x))
}

// guardianFreeze books the gas of a guardian freeze transaction against the fee account.
func (a *API) guardianFreeze(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.actor(w, r); !ok {
		return
	}
	var body struct {
		Tx string `json:"tx"`
	}
	if err := decode(r, &body); err != nil {
		a.fail(w, err)
		return
	}
	fee, err := a.svc.BookGuardianFee(r.Context(), body.Tx)
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"tx": body.Tx, "fee": fee.String()})
}

// auditVerify walks the core audit chain from genesis and reports whether it is intact, with its head.
func (a *API) auditVerify(w http.ResponseWriter, r *http.Request) {
	ok, bad, err := audit.VerifyChain(r.Context(), a.svc.Pool)
	if err != nil {
		a.fail(w, err)
		return
	}
	head, err := audit.Head(r.Context(), a.svc.Pool, "core")
	if err != nil {
		a.fail(w, err)
		return
	}
	out := map[string]any{"ok": ok, "head_seq": head.Seq, "head_hash": head.Hash}
	if !ok {
		out["first_bad_seq"] = bad
	}
	writeJSON(w, http.StatusOK, out)
}
