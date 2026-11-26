package custody

import (
	"context"
	"net/http"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/auth"
	"github.com/ws4charlie/quorum-vault/internal/pki"
)

var (
	anyRole       = []auth.Role(nil)
	requesters    = []auth.Role{auth.Requester, auth.Operator}
	approvers     = []auth.Role{auth.Approver}
	rejecters     = []auth.Role{auth.Approver, auth.Operator}
	readers       = []auth.Role{auth.Requester, auth.Approver, auth.Operator, auth.Admin}
	operators     = []auth.Role{auth.Operator, auth.Admin}
	adminsOnly    = []auth.Role{auth.Admin}
	requesterOnly = []auth.Role{auth.Requester}
	gateOnly      = []auth.Role{auth.Gate}
)

// GateRoute is the signing API for AgentGate. It is the only route AgentGate may call, and only AgentGate may call it (handle).
const GateRoute = "POST /v2/gate/signatures"

// GateClient is the name of AgentGate's client certificate (internal/pki Catalog).
var GateClient = pki.ID(pki.ZoneBusiness, "agentgate")

// routeRules is what every route needs. A route without a rule does not start (Handler panics), so a new route cannot be open by omission.
//
//   - Step-up (a fresh auth_time and the required acr) is for approving, and for what moves the books of the cold address or changes
//     what the factory contracts do. Services have no interactive login and are exempt; HumanOnly keeps them out of approvals and admin actions.
var routeRules = map[string]auth.Rule{
	"POST /v2/customers":                        {Roles: requesters},
	"POST /v2/customers/{id}/deposit-addresses": {Roles: requesters},
	"GET /v2/customers/{id}/balances":           {Roles: readers},
	"POST /v2/withdrawals":                      {Roles: requesterOnly},
	"GET /v2/withdrawals/{id}":                  {Roles: readers},
	"POST /v2/withdrawals/{id}/approvals":       {Roles: approvers, StepUp: true, HumanOnly: true},
	"POST /v2/withdrawals/{id}/rejections":      {Roles: rejecters},
	"GET /v2/withdrawals/{id}/intent":           {Roles: readers},
	"POST /v2/withdrawals/{id}/cpfp":            {Roles: operators, StepUp: true, HumanOnly: true},
	"GET /v2/batches/{id}":                      {Roles: readers},
	"POST /v2/batches/{id}/cancel":              {Roles: operators},
	"GET /v2/reconcile":                         {Roles: operators},
	"GET /v2/refills":                           {Roles: operators},
	"GET /v2/refills/{id}":                      {Roles: operators},
	"POST /v2/refills/{id}/export":              {Roles: operators},
	"POST /v2/refills/{id}/import":              {Roles: operators},
	"POST /v2/cold/fundings":                    {Roles: operators, StepUp: true},
	"POST /v2/cold/spends":                      {Roles: operators, StepUp: true},
	"POST /v2/cold/actions":                     {Roles: adminsOnly, StepUp: true, HumanOnly: true},
	"POST /v2/cold/moves":                       {Roles: adminsOnly, StepUp: true, HumanOnly: true},
	"POST /v2/refills/{id}/rebuild":             {Roles: adminsOnly, StepUp: true, HumanOnly: true},
	"POST /v2/cold-move/export":                 {Roles: adminsOnly},
	"POST /v2/cold-move/submit":                 {Roles: adminsOnly, StepUp: true, HumanOnly: true},
	"POST /v2/refills/{id}/close":               {Roles: operators, StepUp: true},
	"POST /v2/cold-setup/export":                {Roles: operators},
	"POST /v2/cold-setup/submit":                {Roles: operators, StepUp: true},
	"POST /v2/cold-nonces/retire":               {Roles: operators, StepUp: true},
	"POST /v2/cold-close/export":                {Roles: operators},
	"POST /v2/cold-close/submit":                {Roles: operators, StepUp: true},
	"POST /v2/guardian/freezes":                 {Roles: operators},
	"GET /v2/audit/verify":                      {Roles: operators},
	"GET /v2/keysets":                           {Roles: operators},
	"POST /v2/keysets/candidates":               {Roles: adminsOnly, StepUp: true, HumanOnly: true},
	"POST /v2/keysets/activations":              {Roles: adminsOnly, StepUp: true, HumanOnly: true},
	"POST /v2/keysets/drains":                   {Roles: adminsOnly, StepUp: true, HumanOnly: true},
	"POST /v2/keysets/retirements":              {Roles: adminsOnly, StepUp: true, HumanOnly: true},
	"POST /v2/keysets/compromises":              {Roles: adminsOnly, StepUp: true, HumanOnly: true},
	GateRoute:                                   {Roles: gateOnly},
}

// handle registers a route behind its rule: the caller is authenticated, checked against the rule, recorded in the audit trail if the
// request writes, and only then the handler runs. The principal is the actor of everything the request causes.
func (a *API) handle(mux *http.ServeMux, pattern string, h http.HandlerFunc) {
	rule, ok := routeRules[pattern]
	if !ok {
		panic("custody: route without an auth rule: " + pattern)
	}
	mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		p, fail := a.authn.Authenticate(r)
		if fail == nil && !ValidID(p.Sub) {
			fail = &auth.Failure{Status: http.StatusUnauthorized, Message: "the token's sub is not usable as an actor id"}
		}
		if fail == nil {
			fail = gateAuthorize(p, pattern)
		}
		if fail == nil {
			fail = a.authn.Authorize(p, rule)
		}
		if fail != nil {
			if pattern == GateRoute && fail.Code == "" {
				fail.Code = "client_not_authorized" // the signing API answers every refusal with a code (docs/gate-credential.md)
			}
			fail.Write(w)
			return
		}
		ctx := auth.WithPrincipal(WithActor(r.Context(), p.Sub), p)
		ctx = WithIdentity(ctx, IdentityOf(p))
		if r.Method != http.MethodGet {
			// Every write leaves a row naming who sent it, before anything changes. If the row cannot be written, nothing happens.
			if err := a.auditWrite(ctx, r, p); err != nil {
				a.log.Error("could not record the request in the audit trail", "error", err.Error())
				if pattern == GateRoute { // the signing API's error shape (docs/gate-credential.md): nothing was decided, the same request may come again
					writeJSON(w, http.StatusServiceUnavailable, map[string]string{"code": GateRetryLater, "message": "audit trail unavailable; send the same request again"})
					return
				}
				writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit trail unavailable"})
				return
			}
		}
		h(w, r.WithContext(ctx))
	})
}

// gateAuthorize keeps AgentGate and the signing API to each other. A caller is AgentGate when it holds the gate role or shows AgentGate's
// certificate; such a caller is refused on every other route, whatever other roles its token carries. The signing API takes only a service that
// holds the role AND shows AgentGate's certificate (so a stolen token without the certificate's key, or another service's certificate, is refused).
// Without TLS (the dev plaintext switch) no caller has a certificate, so the API is closed.
func gateAuthorize(p *auth.Principal, pattern string) *auth.Failure {
	isGate := p.Has(auth.Gate) || p.Cert == GateClient
	if pattern != GateRoute {
		if isGate {
			return &auth.Failure{Status: http.StatusForbidden, Code: "client_not_authorized", Message: "AgentGate may call only " + GateRoute}
		}
		return nil
	}
	if !p.Service || !p.Has(auth.Gate) || p.Cert != GateClient {
		return &auth.Failure{Status: http.StatusForbidden, Code: "client_not_authorized", Message: "only AgentGate (its service token and its client certificate) may call this route"}
	}
	return nil
}

func (a *API) auditWrite(ctx context.Context, r *http.Request, p *auth.Principal) error {
	return InTx(ctx, a.svc.Pool, func(tx pgx.Tx) error {
		return auditEvent(ctx, tx, "http:"+r.Method+" "+r.Pattern, "api.write", map[string]any{"method": r.Method, "route": r.Pattern, "client": p.Client, "service": p.Service})
	})
}
