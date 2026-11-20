# Identity

[中文](zh/identity.md)

Every caller of the core API proves who they are with a signed token from an OpenID Connect identity provider. The verified identity is the actor everywhere: in the checks that keep duties apart, and in the audit trail.

<p align="center"><img src="images/identity.png" width="60%" alt="A person logs in at the identity provider, which signs a token. The core API checks the role and the age of the login, and the audit trail records who did it. The signing zone still checks approver keys itself."></p>

## Who gets in

The core accepts a token only if the provider's published keys verify it and the issuer, audience and times are right. Development uses Keycloak; production uses the customer's own provider, with a map from its groups to the core's roles.

| Role | May |
|:---|:---|
| Requester | Open customers, deposit addresses and withdrawals |
| Approver | Approve or reject withdrawals |
| Operator | Run refills, cold ceremonies, batches and Reconcile |
| Contract admin | Change what the factory contracts do |

Roles do not include each other: whoever requests a withdrawal never approves it. Every write first records who did it. If that cannot be written, nothing changes.

## Big actions need a fresh login

Approving a withdrawal, booking cold funds, closing a parked refill and changing the factory need a recent login at the strongest level. Someone with an older login is told to log in again. Sessions have an overall limit, checked by the core, and an idle limit, enforced by the provider, which is the only one that sees activity.

## The approval page

Approvers can approve with a security key or passkey on a small web page that has its own address, apart from the core. The page signs the person in and builds its text from the withdrawal itself. It recomputes the hash, refuses to go on if the core's hash differs, and only then asks the key to sign that hash. This protects against a lying core, not against a replaced page ([Limits](limits.md)). Setup is in the [runbook](runbooks/webauthn-approver.md).

For a high-value approval there is also a small command-line tool that runs on a separate machine, prints every field and signs with a hardware key. It has been tried only with a software key ([Limits](limits.md)).

## Services

Workers and scripts that call the core use their own service identity with a client-credentials token, not a person's. A service skips the fresh-login rule, since nobody logs in for it, and it can never approve or change the factory.

## A login does not approve a payment

The signing zone does not trust the identity provider: approvals are still signatures that it checks against keys in its own settings ([Signing zone](signing-zone.md)). A compromised provider could queue withdrawals, but could not approve one.

## How services prove who they are

Services do not trust a network address. The business side and the signing zone each have their own private certificate authority, and a certificate from one is not accepted by the other. Every service holds a short-lived certificate with a name, swaps in the renewed one while it runs, and refuses to start once it has expired. An alert fires before that.

A server does not stop at "my authority signed it": each endpoint keeps its own list of names that may call it. The core API, every database connection, Kafka and Temporal work this way. Each service has its own database role with only the rights it uses, so a hijacked relay cannot rewrite the ledger, and the gateway and a cosigner cannot open each other's databases. The signing zone reaches the business side over two explicit links: the job queue and the audit-head topic. The links between parties use pinned keys instead of names. Where all this runs is on the [Deployment](deployment.md) page; renewal is in the [certificate runbook](runbooks/certificates.md).

On the core API a person needs no certificate. A service that calls with its own token must also show a certificate whose name is on the list, so a stolen token alone is no use.

## What the audit trail records

Every write first leaves a row naming the provider, the person, the login strength, the login time and the token. The change itself then carries the same identity. If that row cannot be written, nothing changes.

## Development only

Approvers are added and removed by zone operators, not by approvers: a change needs signatures from several zone operators, is audited, and takes effect without a restart ([runbook](runbooks/approvers.md)).

A plain header that names the actor, and a test issuer with a local key, work only in development and test; production refuses them. Tests log in without a passkey ([Limits](limits.md)).
