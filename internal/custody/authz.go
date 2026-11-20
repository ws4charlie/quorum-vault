package custody

import (
	"context"
	"net/http"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/auth"
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
)

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
			fail = a.authn.Authorize(p, rule)
		}
		if fail != nil {
			fail.Write(w)
			return
		}
		ctx := auth.WithPrincipal(WithActor(r.Context(), p.Sub), p)
		ctx = WithIdentity(ctx, IdentityOf(p))
		if r.Method != http.MethodGet {
			// Every write leaves a row naming who sent it, before anything changes. If the row cannot be written, nothing happens.
			if err := a.auditWrite(ctx, r, p); err != nil {
				a.log.Error("could not record the request in the audit trail", "error", err.Error())
				writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit trail unavailable"})
				return
			}
		}
		h(w, r.WithContext(ctx))
	})
}

func (a *API) auditWrite(ctx context.Context, r *http.Request, p *auth.Principal) error {
	return InTx(ctx, a.svc.Pool, func(tx pgx.Tx) error {
		return auditEvent(ctx, tx, "http:"+r.Method+" "+r.Pattern, "api.write", map[string]any{"method": r.Method, "route": r.Pattern, "client": p.Client, "service": p.Service})
	})
}
