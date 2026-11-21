package custody

import (
	"context"
	"encoding/base64"
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
	"github.com/ws4charlie/quorum-vault/internal/auth"
	"github.com/ws4charlie/quorum-vault/internal/coldsign"
	"github.com/ws4charlie/quorum-vault/internal/ledger"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// Orchestrator starts and wakes the withdrawal workflow. internal/workflow
// implements it; the API treats both calls as best effort because the
// reconciler workflow starts any open withdrawal that has no workflow, and the
// workflow re-reads approvals from the database on a timer.
type Orchestrator interface {
	StartWithdrawal(ctx context.Context, id string) error
	SignalWithdrawal(ctx context.Context, id string) error
}

// API is the /v2 HTTP handler. Every route sits behind authn: a verified bearer token names the caller (its sub is the actor), and
// routeRules says which roles a route needs and whether it needs a fresh login.
type API struct {
	svc   *Service
	orch  Orchestrator
	log   *slog.Logger
	authn *auth.Authenticator
}

// NewAPI returns the handler. orch may be nil (tests). A nil authn answers 401 to everything.
func NewAPI(svc *Service, orch Orchestrator, log *slog.Logger, authn *auth.Authenticator) *API {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &API{svc: svc, orch: orch, log: log, authn: authn}
}

// Handler returns the routed handler.
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	a.handle(mux, "POST /v2/customers", a.createCustomer)
	a.handle(mux, "POST /v2/customers/{id}/deposit-addresses", a.depositAddress)
	a.handle(mux, "GET /v2/customers/{id}/balances", a.balances)
	a.handle(mux, "POST /v2/withdrawals", a.requestWithdrawal)
	a.handle(mux, "GET /v2/withdrawals/{id}", a.getWithdrawal)
	a.handle(mux, "POST /v2/withdrawals/{id}/approvals", a.approve)
	a.handle(mux, "POST /v2/withdrawals/{id}/rejections", a.reject)
	a.handle(mux, "GET /v2/withdrawals/{id}/intent", a.intent)
	a.handle(mux, "POST /v2/withdrawals/{id}/cpfp", a.startCPFP)
	a.handle(mux, "GET /v2/batches/{id}", a.getBatch)
	a.handle(mux, "POST /v2/batches/{id}/cancel", a.cancelBatch)
	a.handle(mux, "GET /v2/reconcile", a.reconcile)
	a.handle(mux, "GET /v2/refills", a.listRefills)
	a.handle(mux, "GET /v2/refills/{id}", a.getRefill)
	a.handle(mux, "POST /v2/refills/{id}/export", a.exportRefill)
	a.handle(mux, "POST /v2/refills/{id}/import", a.importRefill)
	a.handle(mux, "POST /v2/cold/fundings", a.fundCold)
	a.handle(mux, "POST /v2/cold/spends", a.spendCold)
	a.handle(mux, "POST /v2/cold/actions", a.requestAction)
	a.handle(mux, "POST /v2/cold/moves", a.requestColdMove)
	a.handle(mux, "POST /v2/refills/{id}/close", a.closeRefill)
	a.handle(mux, "POST /v2/cold-setup/export", a.exportColdSetup)
	a.handle(mux, "POST /v2/cold-setup/submit", a.submitColdSetup)
	a.handle(mux, "POST /v2/cold-nonces/retire", a.retireColdNonce)
	a.handle(mux, "POST /v2/cold-close/export", a.exportColdClose)
	a.handle(mux, "POST /v2/cold-close/submit", a.submitColdSetup)
	a.handle(mux, "POST /v2/guardian/freezes", a.guardianFreeze)
	a.handle(mux, "GET /v2/audit/verify", a.auditVerify)
	a.handle(mux, "GET /v2/keysets", a.listKeysets)
	a.handle(mux, "POST /v2/keysets/candidates", a.registerKeysetCandidate)
	a.handle(mux, "POST /v2/keysets/activations", a.activateKeyset)
	a.handle(mux, "POST /v2/keysets/drains", a.startDrainingKeyset)
	a.handle(mux, "POST /v2/keysets/retirements", a.retireKeyset)
	a.handle(mux, "POST /v2/keysets/compromises", a.compromiseKeyset)
	return approvalCORS(mux)
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
	case errors.Is(err, ErrNotPending), errors.Is(err, ErrBatchLocked):
		code, msg = http.StatusConflict, err.Error()
	default:
		a.log.Error("request failed", "error", err.Error())
	}
	writeJSON(w, code, map[string]string{"error": msg})
}

func (a *API) actor(w http.ResponseWriter, r *http.Request) (string, bool) {
	// handle has already verified the caller; the actor is the token's sub.
	if p, ok := auth.FromContext(r.Context()); ok {
		return p.Sub, true
	}
	writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
	return "", false
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
		WebAuthn  *struct {
			CredentialID      string `json:"credential_id"`      // base64url
			AuthenticatorData string `json:"authenticator_data"` // base64url
			ClientDataJSON    string `json:"client_data_json"`   // base64url
			Signature         string `json:"signature"`          // base64url
		} `json:"webauthn"`
	}
	if err := decode(r, &body); err != nil {
		a.fail(w, err)
		return
	}
	if body.Actor != actor {
		a.fail(w, fmt.Errorf("%w: body actor %q differs from the token subject %q", ErrInvalid, body.Actor, actor))
		return
	}
	if (body.Signature == "") == (body.WebAuthn == nil) {
		a.fail(w, fmt.Errorf("%w: give exactly one of signature (Ed25519) or webauthn (an assertion)", ErrInvalid))
		return
	}
	id := r.PathValue("id")
	var n int
	var err error
	if body.WebAuthn == nil {
		var sig []byte
		if sig, err = hex.DecodeString(body.Signature); err != nil {
			a.fail(w, fmt.Errorf("%w: signature is not hex", ErrInvalid))
			return
		}
		n, err = a.svc.AddApproval(r.Context(), id, actor, sig)
	} else {
		var as signjob.WebAuthnAssertion
		for _, f := range []struct {
			name string
			in   string
			out  *[]byte
		}{{"credential_id", body.WebAuthn.CredentialID, &as.CredentialID}, {"authenticator_data", body.WebAuthn.AuthenticatorData, &as.AuthenticatorData},
			{"client_data_json", body.WebAuthn.ClientDataJSON, &as.ClientDataJSON}, {"signature", body.WebAuthn.Signature, &as.Signature}} {
			if *f.out, err = base64.RawURLEncoding.DecodeString(f.in); err != nil {
				a.fail(w, fmt.Errorf("%w: webauthn.%s is not unpadded base64url", ErrInvalid, f.name))
				return
			}
		}
		n, err = a.svc.AddWebAuthnApproval(r.Context(), id, actor, as)
	}
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
	// A withdrawal in the batch queue is cancelled here, at once: out of the queue, or with its unsigned batch discarded; refused (409) once its batch is signed.
	if queued, err := a.svc.InBatchQueue(r.Context(), id); err != nil {
		a.fail(w, err)
		return
	} else if queued && wd.Status != WdConfirmed && wd.Status != WdFailed {
		if err := a.svc.RecordRejection(r.Context(), id, actor, body.Reason); err != nil {
			a.fail(w, err)
			return
		}
		if err := a.svc.CancelWithdrawal(r.Context(), id, actor+": "+body.Reason, a.log); err != nil {
			a.fail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"withdrawal": id, "rejected_by": actor, "cancelled": true})
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
	if a.svc.Cfg.Family == FamilySOL {
		f, err := a.svc.ExportSOLRefill(r.Context(), r.PathValue("id"))
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
	if a.svc.Cfg.Family == FamilySOL {
		var ss coldsign.SOLSigned
		if err := decode(r, &ss); err != nil {
			a.fail(w, err)
			return
		}
		x, err := a.svc.ImportSOLRefill(r.Context(), r.PathValue("id"), ss)
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

// exportColdSetup returns the request file of the one-time setup of a pool's cold address (Solana): the nonce accounts and token accounts it lacks.
func (a *API) exportColdSetup(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.actor(w, r); !ok {
		return
	}
	var body struct {
		Pool string `json:"pool"`
	}
	if err := decode(r, &body); err != nil {
		a.fail(w, err)
		return
	}
	f, need, err := a.svc.ExportColdSetup(r.Context(), body.Pool)
	if err != nil {
		a.fail(w, err)
		return
	}
	if !need {
		writeJSON(w, http.StatusOK, map[string]any{"nothing_to_do": true})
		return
	}
	writeJSON(w, http.StatusOK, f)
}

// retireColdNonce takes a nonce account of a pool's cold address out of the pool, ahead of closing it.
func (a *API) retireColdNonce(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.actor(w, r); !ok {
		return
	}
	var body struct {
		Pool  string `json:"pool"`
		Index int    `json:"index"`
	}
	if err := decode(r, &body); err != nil {
		a.fail(w, err)
		return
	}
	if err := a.svc.RetireColdNonce(r.Context(), body.Pool, body.Index); err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"retired": body.Index})
}

// exportColdClose returns the request file that closes retired, idle nonce accounts of a pool's cold address.
func (a *API) exportColdClose(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.actor(w, r); !ok {
		return
	}
	var body struct {
		Pool    string `json:"pool"`
		Indexes []int  `json:"indexes"`
	}
	if err := decode(r, &body); err != nil {
		a.fail(w, err)
		return
	}
	f, err := a.svc.ExportColdClose(r.Context(), body.Pool, body.Indexes)
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, f)
}

// submitColdSetup sends the signed setup that came back from the ceremony and books its cost.
func (a *API) submitColdSetup(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.actor(w, r); !ok {
		return
	}
	var body struct {
		Request coldsign.SOLRequest `json:"request"`
		Signed  coldsign.SOLSigned  `json:"signed"`
	}
	if err := decode(r, &body); err != nil {
		a.fail(w, err)
		return
	}
	sig, err := a.svc.SubmitColdSetup(r.Context(), body.Request, body.Signed, a.svc.waitFinal)
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tx_hash": sig})
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

// requestColdMove opens (or returns) the next cold-to-cold request of a cold key replacement; {"done":true} when the old address holds nothing more.
func (a *API) requestColdMove(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.actor(w, r); !ok {
		return
	}
	x, found, err := a.svc.RequestColdMove(r.Context())
	if err != nil {
		a.fail(w, err)
		return
	}
	if !found {
		writeJSON(w, http.StatusOK, map[string]any{"done": true})
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

// ---- batches (Bitcoin) ----

func (a *API) getBatch(w http.ResponseWriter, r *http.Request) {
	b, err := a.svc.GetBatch(r.Context(), r.PathValue("id"))
	if err != nil {
		a.fail(w, err)
		return
	}
	items, err := a.svc.BatchItems(r.Context(), b.ID)
	if err != nil {
		a.fail(w, err)
		return
	}
	members := []map[string]any{}
	for _, it := range items {
		m := map[string]any{"withdrawal": it.WithdrawalID, "position": it.Position, "vout": it.Vout, "amount": it.Amount.String()}
		if it.FeeShare != nil {
			m["fee_share"] = it.FeeShare.String()
		}
		members = append(members, m)
	}
	out := map[string]any{"id": b.ID, "partition": b.PartitionID, "status": b.Status, "tx_hash": b.TxHash, "cancel_tx": b.CancelTx, "reason": b.Reason, "members": members}
	if b.Fee != nil {
		out["fee"] = b.Fee.String()
	}
	writeJSON(w, http.StatusOK, out)
}

// cancelBatch asks to cancel a whole batch: unsigned, it is discarded at once; signed, its workflow cancels it (the same coins back to the hot wallet) and
// the members return to the queue.
func (a *API) cancelBatch(w http.ResponseWriter, r *http.Request) {
	actor, ok := a.actor(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if err := a.svc.CancelBatch(r.Context(), id, a.log); err != nil {
		a.fail(w, err)
		return
	}
	a.log.Info("batch cancel requested", "batch", id, "actor", actor)
	writeJSON(w, http.StatusAccepted, map[string]any{"batch": id, "requested_by": actor})
}
