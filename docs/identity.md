# Identity

[中文](zh/identity.md)

Every caller of the core API proves who they are with a signed token from an OpenID Connect identity provider. The verified identity is the actor everywhere: in the dual-control checks and in the audit trail.

<p align="center"><img src="images/identity.png" width="60%" alt="A person logs in at the identity provider, which signs a token. The core API checks the role and the age of the login, and the audit trail records who did it. The signing zone still checks approver keys by itself."></p>

## Who gets in
The core accepts a token only if the provider's published keys verify it and the issuer, audience and times are right. Development uses Keycloak; production uses the customer's own provider, with a map from its groups to the core's roles.

| Role | May |
|---|---|
| Requester | open customers, deposit addresses and withdrawals |
| Approver | approve or reject withdrawals |
| Operator | run refills, cold ceremonies, batches and reconcile |
| Admin | change what the factory contracts do |

Roles do not include each other: whoever requests a withdrawal never approves it. Every write first records who did it; if that cannot be written, nothing changes.

## Big actions need a fresh login
Approving a withdrawal, booking cold funds, closing a parked refill and changing the factory need a recent login at the strongest level. An older login is told to log in again. Sessions have an overall limit, checked by the core, and an idle limit, enforced by the provider, which alone sees activity.

## Services
Workers and scripts that call the core use their own service identity with a client-credentials token, not a person's. A service skips the fresh-login rule, since nobody logs in for it, and it can never approve or change the factory.

## Login does not approve a payment
The signing zone does not trust the identity provider: approvals are still signatures that it checks against keys in its own configuration ([Signing zone](signing-zone.md)). A stolen provider could queue withdrawals, but could not approve one.

## How services prove who they are

Services do not trust a network address. Each trust zone, the business side and the signing zone, has its own private certificate authority, and a certificate from one is not accepted by the other. Every service holds a certificate that lasts hours to days, with a name of the form `spiffe://quorumvault/<zone>/<service>`, and swaps in the renewed files by itself while it runs. A server does not stop at "my authority signed it": each endpoint keeps its own list of names that may call it. A service whose certificate has expired refuses to start, and an alert fires before that happens. The few links that cross the zones are explicit: the business authority issues a named visitor certificate, and the signing zone's authority is never trusted on a business endpoint.

The core API, every database connection, Kafka and Temporal use it. The business database trusts only the business authority, and the replay-guard databases sit on a separate server that trusts only the signing authority. A database maps the name in a certificate to one role, so a name it has not listed is refused. The signing zone reaches the business side through two explicit links, the job queue and the audit-head topic, with certificates that the business authority issued for the gateway and the cosigner. Kafka decides what each name may do; Temporal can check only the authority.

On the core API, people log in at the identity provider and need no certificate; a service that calls with its own token must also show a certificate whose name is on the list, so a stolen token alone is no use. The runbook for renewing certificates is [certificates](runbooks/certificates.md).

## What the audit trail records

Every write first leaves a row naming the issuer, `sub`, authentication level, login time and token id, then the change itself carries the same identity. If that row cannot be written, nothing changes.

## Development only
A plain header that names the actor, and a test issuer with a local key, work only in development and test; production refuses them. Tests log in without a passkey ([Limits](limits.md)).
