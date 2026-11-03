// Package api is the HTTP/JSON API (net/http method+path patterns).
//
// Auth is a demo stand-in: every mutating call must carry an X-Actor header
// naming the caller (401 without it). Errors are {"error": "..."} with
// 400 (malformed body), 401 (no actor), 403 (self-approval), 404 (unknown id),
// 409 (state conflict / duplicate), 422 (well-formed but invalid), 500.
// Wei amounts are decimal strings. POST /wallets with backend "mpc" runs a
// distributed keygen and may take several seconds (minutes on the very first
// run, while Paillier pre-params are generated and cached).
package api

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
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ws4charlie/quorum-vault/internal/approval"
	"github.com/ws4charlie/quorum-vault/internal/audit"
	"github.com/ws4charlie/quorum-vault/internal/domain"
	"github.com/ws4charlie/quorum-vault/internal/keys"
	"github.com/ws4charlie/quorum-vault/internal/policy"
	"github.com/ws4charlie/quorum-vault/internal/signing"
)

// Config wires the API.
type Config struct {
	Registry *keys.Registry
	Policy   *policy.Engine
	Signing  *signing.Service
	Audit    *audit.Log
	Health   http.HandlerFunc // GET /healthz; nil = always ok
	Logger   *slog.Logger
}

type server struct {
	reg *keys.Registry
	pol *policy.Engine
	svc *signing.Service
	aud *audit.Log
	log *slog.Logger
}

// New returns the API handler.
func New(cfg Config) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	s := &server{reg: cfg.Registry, pol: cfg.Policy, svc: cfg.Signing, aud: cfg.Audit, log: cfg.Logger}
	health := cfg.Health
	if health == nil {
		health = func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, map[string]bool{"ok": true}) }
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", health)

	mux.HandleFunc("POST /wallets", s.mut(s.createWallet))
	mux.HandleFunc("GET /wallets", s.listWallets)
	mux.HandleFunc("GET /wallets/{id}", s.getWallet)
	mux.HandleFunc("POST /wallets/{id}/rotate", s.mut(s.rotate))
	mux.HandleFunc("PUT /wallets/{id}/policy", s.mut(s.setPolicy))
	mux.HandleFunc("POST /wallets/{id}/allowlist", s.mut(s.addAllow))
	mux.HandleFunc("DELETE /wallets/{id}/allowlist/{address}", s.mut(s.removeAllow))

	mux.HandleFunc("POST /keys", s.mut(s.createKey))
	mux.HandleFunc("GET /keys", s.listKeys)
	mux.HandleFunc("POST /keys/{id}/retire", s.mut(s.retire))

	mux.HandleFunc("POST /sign-requests", s.mut(s.submit))
	mux.HandleFunc("GET /sign-requests", s.listRequests)
	mux.HandleFunc("GET /sign-requests/{id}", s.getRequest)
	mux.HandleFunc("POST /sign-requests/{id}/approve", s.mut(s.vote(true)))
	mux.HandleFunc("POST /sign-requests/{id}/reject", s.mut(s.vote(false)))

	mux.HandleFunc("GET /audit", s.listAudit)
	mux.HandleFunc("GET /audit/verify", s.verifyAudit)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, pattern := mux.Handler(r); pattern == "" {
			// The mux's own 404 / 405 replies are plain text; make them JSON.
			w = &jsonErrWriter{ResponseWriter: w}
		}
		mux.ServeHTTP(w, r)
	})
}

// jsonErrWriter rewrites the mux's plain-text error replies as {"error": ...}.
type jsonErrWriter struct {
	http.ResponseWriter
	swallow bool
}

func (j *jsonErrWriter) WriteHeader(code int) {
	if code >= 400 {
		j.swallow = true
		j.Header().Del("X-Content-Type-Options")
		writeErr(j.ResponseWriter, code, strings.ToLower(http.StatusText(code)))
		return
	}
	j.ResponseWriter.WriteHeader(code)
}

func (j *jsonErrWriter) Write(b []byte) (int, error) {
	if j.swallow {
		return len(b), nil
	}
	return j.ResponseWriter.Write(b)
}

type mutHandler func(w http.ResponseWriter, r *http.Request, actor string)

// mut requires the X-Actor header.
func (s *server) mut(h mutHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor := strings.TrimSpace(r.Header.Get("X-Actor"))
		if actor == "" {
			writeErr(w, http.StatusUnauthorized, "X-Actor header is required")
			return
		}
		h(w, r, actor)
	}
}

// ---- views (what the API returns; never any private key material) ----

type keyView struct {
	domain.Key
	PublicKeyHex string `json:"public_key_hex"`
	HSMKeyIDHex  string `json:"hsm_key_id,omitempty"` // CKA_ID: an object handle, not key material
}

func viewKey(k domain.Key) keyView {
	return keyView{Key: k, PublicKeyHex: "0x" + hex.EncodeToString(k.PublicKey), HSMKeyIDHex: hexOpt(k.HSMKeyID)}
}

func viewKeys(ks []domain.Key) []keyView {
	out := make([]keyView, len(ks))
	for i, k := range ks {
		out[i] = viewKey(k)
	}
	return out
}

// requestView is domain.SignRequest's JSON with the byte fields as 0x-hex:
// data, signature (r||s||v) and raw_tx (EIP-2718 envelope, ready for
// eth_sendRawTransaction).
type requestView struct{ domain.SignRequest }

func viewRequest(r domain.SignRequest) requestView { return requestView{r} }

func (v requestView) MarshalJSON() ([]byte, error) {
	b, err := json.Marshal(v.SignRequest) // domain's marshaller (wei as decimal strings)
	if err != nil {
		return nil, err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	for name, val := range map[string][]byte{"data": v.Data, "signature": v.Signature, "raw_tx": v.RawTx} {
		delete(m, name)
		if len(val) > 0 {
			m[name], _ = json.Marshal(hexOpt(val))
		}
	}
	return json.Marshal(m)
}

type resultView struct {
	Request   requestView        `json:"request"`
	From      string             `json:"from,omitempty"`
	Tally     *approval.Tally    `json:"tally,omitempty"`
	SignError string             `json:"sign_error,omitempty"`
	Broadcast string             `json:"broadcast,omitempty"`
	TimingsMS map[string]float64 `json:"timings_ms,omitempty"`
}

func viewResult(r signing.Result) resultView {
	return resultView{Request: viewRequest(r.Request), From: r.From, Tally: r.Tally, SignError: r.SignError,
		Broadcast: r.Broadcast, TimingsMS: r.TimingsMS}
}

type auditView struct {
	domain.AuditEvent
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
}

func hexOpt(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return "0x" + hex.EncodeToString(b)
}

// ---- wallets & keys ----

type createWalletBody struct {
	Name    string         `json:"name"`
	Tier    domain.Tier    `json:"tier"`
	Backend domain.Backend `json:"backend"`
}

func (s *server) createWallet(w http.ResponseWriter, r *http.Request, actor string) {
	var b createWalletBody
	if !decode(w, r, &b) {
		return
	}
	s.doCreateWallet(w, r.Context(), actor, b)
}

func (s *server) doCreateWallet(w http.ResponseWriter, ctx context.Context, actor string, b createWalletBody) {
	if strings.TrimSpace(b.Name) == "" {
		writeErr(w, http.StatusUnprocessableEntity, "name is required")
		return
	}
	if b.Tier != domain.TierHot && b.Tier != domain.TierCold {
		writeErr(w, http.StatusUnprocessableEntity, `tier must be "hot" or "cold"`)
		return
	}
	if b.Backend != domain.BackendHSM && b.Backend != domain.BackendMPC {
		writeErr(w, http.StatusUnprocessableEntity, `backend must be "hsm" or "mpc"`)
		return
	}
	wal, k, err := s.reg.CreateWallet(ctx, actor, b.Name, b.Tier, b.Backend)
	if err != nil && !(wal.ID != "" && s.auditOnly(err)) {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"wallet": wal, "key": viewKey(k)})
}

func (s *server) listWallets(w http.ResponseWriter, r *http.Request) {
	ws, err := s.reg.ListWallets(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	if ws == nil {
		ws = []domain.Wallet{}
	}
	writeJSON(w, http.StatusOK, ws)
}

func (s *server) getWallet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	wal, err := s.reg.GetWallet(ctx, r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	ks, err := s.reg.ListKeys(ctx, wal.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	var pol *domain.Policy
	if p, err := s.pol.GetPolicy(ctx, wal.ID); err == nil {
		pol = &p
	} else if !errors.Is(err, policy.ErrNotFound) {
		s.fail(w, err)
		return
	}
	allow, err := s.pol.ListAllowlist(ctx, wal.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"wallet": wal, "keys": viewKeys(ks), "policy": pol, "allowlist": allow})
}

// POST /keys {wallet_id?, name?, tier?}: the brief's first-light endpoint.
// Without wallet_id it creates a new HSM wallet (and its key v1); with the id
// of an HSM wallet it adds the next key version (a rotation).
func (s *server) createKey(w http.ResponseWriter, r *http.Request, actor string) {
	var b struct {
		WalletID string      `json:"wallet_id"`
		Name     string      `json:"name"`
		Tier     domain.Tier `json:"tier"`
	}
	if !decode(w, r, &b) {
		return
	}
	if b.WalletID == "" {
		if b.Name == "" {
			b.Name = "hsm-" + uuid.NewString()[:8]
		}
		if b.Tier == "" {
			b.Tier = domain.TierHot
		}
		s.doCreateWallet(w, r.Context(), actor, createWalletBody{Name: b.Name, Tier: b.Tier, Backend: domain.BackendHSM})
		return
	}
	wal, err := s.reg.GetWallet(r.Context(), b.WalletID)
	if err != nil {
		s.fail(w, err)
		return
	}
	if wal.Backend != domain.BackendHSM {
		writeErr(w, http.StatusUnprocessableEntity, "POST /keys creates HSM keys; use POST /wallets/{id}/rotate for MPC wallets")
		return
	}
	s.doRotate(w, r.Context(), actor, wal.ID)
}

func (s *server) listKeys(w http.ResponseWriter, r *http.Request) {
	ks, err := s.reg.ListKeys(r.Context(), r.URL.Query().Get("wallet_id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, viewKeys(ks))
}

func (s *server) rotate(w http.ResponseWriter, r *http.Request, actor string) {
	s.doRotate(w, r.Context(), actor, r.PathValue("id"))
}

func (s *server) doRotate(w http.ResponseWriter, ctx context.Context, actor, walletID string) {
	nk, ok, err := s.reg.Rotate(ctx, actor, walletID)
	if err != nil && !(nk.ID != "" && s.auditOnly(err)) {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"key": viewKey(nk), "previous_key": viewKey(ok)})
}

func (s *server) retire(w http.ResponseWriter, r *http.Request, actor string) {
	k, err := s.reg.Retire(r.Context(), actor, r.PathValue("id"))
	if err != nil && !(k.ID != "" && s.auditOnly(err)) {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, viewKey(k))
}

// ---- policy & allowlist ----

func (s *server) setPolicy(w http.ResponseWriter, r *http.Request, actor string) {
	wal, err := s.reg.GetWallet(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	var p domain.Policy
	if !decode(w, r, &p) {
		return
	}
	p.WalletID = wal.ID
	if err := s.pol.SetPolicy(r.Context(), actor, p); err != nil && !s.auditOnly(err) {
		s.fail(w, err)
		return
	}
	stored, err := s.pol.GetPolicy(r.Context(), wal.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, stored)
}

func (s *server) addAllow(w http.ResponseWriter, r *http.Request, actor string) {
	wal, err := s.reg.GetWallet(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	var b struct {
		Address string `json:"address"`
		Label   string `json:"label"`
	}
	if !decode(w, r, &b) {
		return
	}
	if err := s.pol.AddAllowlist(r.Context(), actor, wal.ID, b.Address, b.Label); err != nil && !s.auditOnly(err) {
		s.fail(w, err)
		return
	}
	list, err := s.pol.ListAllowlist(r.Context(), wal.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, list)
}

func (s *server) removeAllow(w http.ResponseWriter, r *http.Request, actor string) {
	wal, err := s.reg.GetWallet(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	if err := s.pol.RemoveAllowlist(r.Context(), actor, wal.ID, r.PathValue("address")); err != nil && !s.auditOnly(err) {
		s.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- sign requests ----

type submitBody struct {
	WalletID             string  `json:"wallet_id"`
	ChainID              int64   `json:"chain_id"`
	To                   string  `json:"to"`
	ValueWei             string  `json:"value_wei"`
	Data                 string  `json:"data"` // 0x-hex
	Nonce                *uint64 `json:"nonce"`
	GasLimit             uint64  `json:"gas_limit"`
	MaxFeePerGas         *string `json:"max_fee_per_gas"`
	MaxPriorityFeePerGas *string `json:"max_priority_fee_per_gas"`
}

func parseWei(field, s string) (*big.Int, error) {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok || v.Sign() < 0 {
		return nil, fmt.Errorf("%s must be a non-negative decimal string, got %q", field, s)
	}
	return v, nil
}

func (s *server) submit(w http.ResponseWriter, r *http.Request, actor string) {
	var b submitBody
	if !decode(w, r, &b) {
		return
	}
	in := signing.Input{WalletID: b.WalletID, ChainID: b.ChainID, To: b.To, Nonce: b.Nonce, GasLimit: b.GasLimit}
	var err error
	if in.ValueWei, err = parseWei("value_wei", b.ValueWei); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	for _, f := range []struct {
		name string
		src  *string
		dst  **big.Int
	}{{"max_fee_per_gas", b.MaxFeePerGas, &in.MaxFeePerGas}, {"max_priority_fee_per_gas", b.MaxPriorityFeePerGas, &in.MaxPriorityFeePerGas}} {
		if f.src != nil {
			if *f.dst, err = parseWei(f.name, *f.src); err != nil {
				writeErr(w, http.StatusUnprocessableEntity, err.Error())
				return
			}
		}
	}
	if b.Data != "" {
		if in.Data, err = hex.DecodeString(strings.TrimPrefix(b.Data, "0x")); err != nil {
			writeErr(w, http.StatusUnprocessableEntity, "data must be 0x-hex")
			return
		}
	}
	res, err := s.svc.Submit(r.Context(), actor, in)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, viewResult(res))
}

func (s *server) getRequest(w http.ResponseWriter, r *http.Request) {
	req, err := s.svc.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, viewRequest(req))
}

func (s *server) listRequests(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	reqs, err := s.svc.List(r.Context(), r.URL.Query().Get("wallet_id"), limit)
	if err != nil {
		s.fail(w, err)
		return
	}
	out := make([]requestView, len(reqs))
	for i, q := range reqs {
		out[i] = viewRequest(q)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) vote(approve bool) mutHandler {
	return func(w http.ResponseWriter, r *http.Request, actor string) {
		var b struct {
			Comment string `json:"comment"`
		}
		if !decodeOpt(w, r, &b) {
			return
		}
		res, err := s.svc.Vote(r.Context(), actor, r.PathValue("id"), approve, b.Comment)
		if err != nil {
			s.fail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, viewResult(res))
	}
}

// ---- audit ----

func (s *server) listAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := audit.Filter{RequestID: q.Get("request_id"), WalletID: q.Get("wallet_id")}
	for _, id := range []string{f.RequestID, f.WalletID} {
		if id != "" && uuid.Validate(id) != nil {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("invalid id %q", id))
			return
		}
	}
	if l := q.Get("limit"); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil || n < 0 {
			writeErr(w, http.StatusBadRequest, "limit must be a non-negative integer")
			return
		}
		f.Limit = n
	}
	evs, err := s.aud.List(r.Context(), f)
	if err != nil {
		s.fail(w, err)
		return
	}
	out := make([]auditView, len(evs))
	for i, ev := range evs {
		out[i] = auditView{AuditEvent: ev, PrevHash: hex.EncodeToString(ev.PrevHash), Hash: hex.EncodeToString(ev.Hash)}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) verifyAudit(w http.ResponseWriter, r *http.Request) {
	ok, bad, err := s.aud.Verify(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	body := map[string]any{"ok": ok}
	if !ok {
		body["first_bad_seq"] = bad
	}
	writeJSON(w, http.StatusOK, body)
}

// ---- plumbing ----

// auditOnly reports whether err says the change committed but its audit
// append failed (PLAN decision: audit follows the commit). Such calls are
// reported as successful and logged loudly.
func (s *server) auditOnly(err error) bool {
	m := err.Error()
	if strings.HasPrefix(m, "keys: audit ") || strings.HasPrefix(m, "policy: audit ") {
		s.log.Error("AUDIT APPEND FAILED after committed change", "err", err)
		return true
	}
	return false
}

func statusOf(err error) int {
	var pgErr *pgconn.PgError
	switch {
	case errors.Is(err, keys.ErrNotFound), errors.Is(err, signing.ErrNotFound), errors.Is(err, policy.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, signing.ErrInvalid), errors.Is(err, policy.ErrInvalidAddress), errors.Is(err, policy.ErrInvalidPolicy):
		return http.StatusUnprocessableEntity
	case errors.Is(err, approval.ErrSelfApproval):
		return http.StatusForbidden
	case errors.Is(err, approval.ErrDuplicateVote), errors.Is(err, approval.ErrNotPending),
		errors.Is(err, keys.ErrInvalidTransition), errors.Is(err, keys.ErrConflict), errors.Is(err, signing.ErrConflict):
		return http.StatusConflict
	case errors.As(err, &pgErr) && pgErr.Code == "23505":
		return http.StatusConflict
	}
	return http.StatusInternalServerError
}

func (s *server) fail(w http.ResponseWriter, err error) {
	code := statusOf(err)
	msg := err.Error()
	if code == http.StatusConflict && strings.Contains(msg, "23505") {
		msg = "already exists"
	}
	if code == http.StatusInternalServerError {
		s.log.Error("request failed", "err", err)
		msg = "internal error"
	}
	writeErr(w, code, msg)
}

const maxBody = 1 << 20

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed JSON body: "+err.Error())
		return false
	}
	return true
}

// decodeOpt is decode for an optional body: an empty body is fine.
func decodeOpt(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		writeErr(w, http.StatusBadRequest, "malformed JSON body: "+err.Error())
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
