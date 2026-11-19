# Enrolling a passkey approver

The approvers' own page is `web/approval`, served by `qv-approval-web` from its own origin. [Deploy the approval page](#deploy-the-approval-page) first; the page makes the passkey, shows the entry to enrol, and approves. The rest of this runbook is what the page does underneath, for people who build another client.

A person's passkey is a second approver entry with the same `identity` as their Ed25519 key (or alone). Set `"scheme": "webauthn"`, `alg` (`ES256` or `EdDSA`), `public_key` (hex: the 65-byte uncompressed P-256 point, or the 32-byte Ed25519 key), `credential_id` (base64url), `rp_id` and `origins` (exact, `https://`). Enrol it with an operator-signed change, with no config edit or restart: see [Approvers](approvers.md). The entry goes into the change as a JSON file (`qv-approvers sign -approver-file`).

## Submitting an approval with a passkey

The approver's client does three things, all with the approver's own login token (its subject is the approval's `actor`; step-up applies as for any approval):

1. `GET /v2/withdrawals/{id}/intent` returns `intent`, `canonical` and `hash` (hex). The `hash` is the challenge: pass its 32 bytes to `navigator.credentials.get` as `publicKey.challenge`, with the same `rpId` as the enrolled entry.
2. Send the answer to `POST /v2/withdrawals/{id}/approvals`, with exactly one of `signature` (an Ed25519 signature in hex) or `webauthn`. All four fields are base64url without padding, as a browser's `ArrayBuffer` encodes to:

   ```json
   {"actor": "alice",
    "webauthn": {"credential_id": "…", "authenticator_data": "…", "client_data_json": "…", "signature": "…"}}
   ```

3. A `400` means the request was malformed (both or neither field, bad base64url, a field too large, client data that is not JSON). `403` means the actor is the requester.

The core checks only the shape and stores the assertion, as it does for an Ed25519 signature. The signing zone does the real check when it signs: the assertion must be made for this withdrawal's hash, by a credential enrolled for the actor, with the person present. An assertion for another withdrawal is accepted by the core and refused by the zone, which voids the withdrawal.

## Deploy the approval page

The page is plain HTML, CSS and JavaScript with no build step and no third-party script. Keep it on **its own origin**, apart from the core and the identity provider: the passkey is bound to that origin, and the core lets only that origin call the approval routes from a browser.

1. **Serve it.** `qv-approval-web -listen :8443 -dir web/approval -issuer <OIDC issuer> -client-id qv-approval -api <core origin> -asset-decimals ETH=18,USDT=6`. It serves the files and `/config.json` (made from those flags), and sets a strict Content-Security-Policy (no inline script; the page may reach only itself, the issuer and the core), `frame-ancestors 'none'`, and no cookies. Put TLS in front of it (a proxy, or `-tls-cert` and `-tls-key`); a passkey needs a secure context. `http://localhost` also counts, for development. It keeps no state, so any number of replicas behind one name is fine. `-max-login-age` (default 4 minutes) makes the page ask for a fresh sign-in before a key touch; keep it under the core's `-oidc-stepup-max-age`.
2. **Register the client.** In the identity provider, a public client for the page: authorization code with PKCE (S256), redirect URI `https://<page origin>/*`, web origin `https://<page origin>`, the same audience and role mappers as `qv-cli`, and the step-up `acr` the core asks for. The dev realm has `qv-approval` for `http://localhost:8090`; change its redirect URI and web origin for any other address. `qv-approval-e2e` in the same file is for the automated tests only: it skips the identity provider's passkey step.
3. **Let the core accept the page.** Start `qv-core` with `-approval-origins https://<page origin>` (or `QV_APPROVAL_ORIGINS`, comma separated). It then answers browser preflights for exactly three routes (`GET /v2/withdrawals/{id}`, `GET /v2/withdrawals/{id}/intent`, `POST /v2/withdrawals/{id}/approvals`) from exactly those origins, allows only the `Authorization` and `Content-Type` headers, and never allows credentials. With no value the core sends no CORS header and no browser page can call it.
4. **Match the zone.** An approver entry's `rp_id` is the page's host name and `origins` holds the page's exact origin. The page prints the entry with both filled in; an entry made on another origin is refused by the zone when the job is signed.

## Enrol an approver on the page

1. The person opens the page, signs in, and opens **Enrol a passkey**. The page asks the browser for a passkey with user verification required (ES256 or EdDSA) and shows the approver entry: `scheme`, `alg`, `public_key`, `credential_id`, `rp_id`, `origins`.
2. The person sends the entry to the operators. The page cannot enrol anyone by itself. The operators check who sent it, save it as a file and sign it into the zone as in [Approvers](approvers.md) (`qv-approvers sign -action enrol -name <the person's login name> -approver-file entry.json`, then the other operators, then `apply`). The **name must equal the login's `sub`**, because the approval's actor is the token's `sub`.
3. Until the apply reaches the gateway and every cosigner, the person's approvals wait and are decided again (see Approvers).

## Approve on the page

1. Open `https://<page origin>/#/withdrawals/<id>` and sign in. The page loads the intent, reads the **canonical bytes** (not the core's JSON), recomputes their SHA-256 and compares it with the hash the core sent. A difference, a withdrawal other than the one asked for, or bytes that are not an intent: the page says REFUSED and shows no button. Otherwise it says in words who gets how much of what, on which chain, from which pool, until when, and who requested it, with the hash it will sign.
2. **Approve with my security key** asks the key to sign that hash (challenge = the hash, user verification required) and posts the assertion to the core. A requester sees their own withdrawal but gets no button, and the core refuses them anyway (403).
3. If the core answers 401 with the step-up challenge, or the login is older than `-max-login-age`, the page sends the person through a fresh sign-in and back to the same withdrawal.
4. After an approval the page shows the withdrawal's status for a short while. A zone refusal (wrong origin, wrong credential, no user verification) shows as the withdrawal turning `failed` with `gateway refused`.

## What the page cannot do

The page is what the approver sees. Recomputing the hash in the page protects against a **lying core**: it cannot show one withdrawal and have the key sign another. It does **not** protect against a **replaced or compromised page**: a page that shows one payee and signs another's hash looks the same to the key and to the zone. So the page's files and the server that gives them out are as sensitive as an approver's key: deploy them from the release you reviewed, serve them from a host that nothing else uses, and watch for changes. The only full answer is a device that shows the job itself (a mobile app, or a key with a screen), which is not built ([Limits](../limits.md)).

On Kubernetes, `qv-approval-web` is a stateless Deployment in the business cluster behind the ingress that terminates TLS; it needs outbound access to nothing (the browser calls the issuer and the core, not the server). An operator never needs to exec into it. The browser tests of this page use a virtual authenticator, which is a software key: no hardware key and no person has been tried.
