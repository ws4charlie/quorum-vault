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

## Development only
A plain header that names the actor, and a test issuer with a local key, work only in development and test; production refuses them. Tests log in without a passkey ([Limits](limits.md)).
