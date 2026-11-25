# AgentGate client: certificate, token and the signing API

AgentGate asks the core to sign x402 payments (EIP-3009 authorizations) from Gate-governed wallets: `POST /v2/gate/signatures`, contract in [docs/gate-credential.md](../gate-credential.md#the-signing-api). This runbook turns it on for one deployment, issues AgentGate's identity, and checks it. Vault never calls AgentGate; nothing here gives AgentGate a key or a key share.

## What AgentGate needs

| Item | What | Where it comes from |
|:---|:---|:---|
| Client certificate | name `spiffe://quorumvault/business/agentgate`, client usage only | the business issuer (below); never made in a Vault cluster |
| Trust | the business CA bundle, to verify the core's server certificate | ConfigMap `qv-trust-business-<hash>` (qv-certs README, "Trust") |
| Token | client-credentials token of a client of Vault's identity provider, role `gate` and no other role | the identity provider (below) |
| Address | the core's passthrough ingress host (the client certificate must reach the core: TLS cannot end at a controller) | `ingress.passthrough` of `qv-business` |
| Deployment name | the `audience` it writes into every credential, e.g. `qv-staging` | the gate setting of the zone and the core's config (below); equal in both |

## 1. Issue the client certificate

The business issuer signs it, as it signs the operator certificates; the certificate goes to AgentGate's deployment and nowhere in Vault.

- **Production (Vault or OpenBao PKI).** A role on the business PKI that may sign only `spiffe://quorumvault/business/agentgate` as a URI SAN, client usage, short TTL (72 h like the services), and that AgentGate's own cert-manager or agent renews. Do not reuse the role of the in-cluster services.
- **Development and the kind lane.** `qv-pki issue` makes it with every other identity (catalog entry `business/agentgate`, an operator identity: `operatorCertificates: true` in `qv-certs` renders it in kind). Files: `data/pki/business/agentgate/{tls.crt,tls.key,ca.crt}`.

Check it: `qv-pki check -cert tls.crt -min 1h`, and that its URI SAN is exactly the name above.

## 2. The token

In the identity provider, a confidential client for AgentGate (client-credentials grant only) whose tokens carry the role `gate` in the roles claim the core reads (`-oidc-roles-claim`; map it with `-oidc-role-map` if the provider names it otherwise). Give it no other role: the core refuses a caller with the role `gate` on every other route anyway, and refuses this route unless the token holds `gate` **and** the certificate is AgentGate's. Add the client id to `oidc.serviceClients` (`QV_OIDC_SERVICE_CLIENTS`).

## 3. Turn it on in the core

1. **Custody config** (the Secret `qv-custody-config`): the token's `x402` section (runbook [x402-hot-wallet](x402-hot-wallet.md)), then a `gate` section:

   | Key | Value |
   |:---|:---|
   | `audience` | this deployment's name; must equal the `audience` of the zone's signed gate setting |
   | `wallets` | `wallet_id` (lower-case UUID) → `{"partition": "<entity>/<chain>/<asset>/hot/omnibus/<shard>"}`; the same mapping as the zone's signed gate setting; one wallet per partition |
   | `skew` | optional, default `30s`, at most `5m`: the zone's skew |
   | `wait` | optional, default `20s`, at most `2m`: how long one request waits for the zone before answering `retry_later` |

   The core cannot read the zone's signed setting (it has no path into the zone), so it cannot compare the audience and the wallets at start-up. Keep them equal by procedure: change the zone's setting first, then the core's config. A wallet only in the core's config is refused by the zone (`wallet_not_gate_governed`); a wallet only in the zone's setting is refused by the core.
2. **Chart** `qv-business`: `agentgate.enabled: true` (adds `business/agentgate` to the core's service allow-list) and `ingress.passthrough.enabled: true` with a host AgentGate can reach.
3. **Migration** `0037_gate_requests.sql` runs with the release (`qv-migrate` Job).
4. **Order.** The zone first: gateway and every cosigner have the gate setting naming the wallet (GC2). Then the core. Then point AgentGate at the wallet.

## 4. Check it

- AgentGate's call with its certificate and token: a request for an unknown wallet answers 403 `wallet_not_gate_governed` (the route is reached, nothing is signed).
- The same token on `GET /v2/reconcile`: 403 `client_not_authorized`.
- The core's audit trail has a `gate.request` event per credential, with `credential_id`, `obligation_id`, `policy_version`, `decision_reason` and the outcome.

## Answers and what to do

| Answer | Meaning | Action |
|:---|:---|:---|
| 503 `retry_later` | nothing decided yet: the zone did not answer within `wait`, the paying shard has no free funds yet, or a store was unreachable | AgentGate sends the same request again (same credential) |
| 503 `signing_failed` | the zone's signer failed, or the zone refused for a reason outside the spec's table; stored | look at the job's `reject_reason` (`sign_jobs`, id `x402:<credential_id>`) and the gateway log; AgentGate mints a new credential and a new EIP-3009 nonce |
| 403 / 409 / 422 | a refusal with its code; stored | none on the Vault side unless the code points at configuration (`wallet_not_gate_governed`, `audience_mismatch`: the two configs differ) |

Rows of `gate_requests` are removed by the worker's x402 pass after the credential's `expires_at` + skew + 1 day. The x402 authorizations themselves stay, with their books ([x402-hot-wallet](x402-hot-wallet.md)).

## Revoking AgentGate

Remove `business/agentgate` from the allow-list (`agentgate.enabled: false`) and disable the client in the identity provider; revoke the certificate at the issuer. Either one alone already stops every call. Signatures already returned stay valid until their `validBefore`: their liability is in the books until the worker sees them used or expired.
