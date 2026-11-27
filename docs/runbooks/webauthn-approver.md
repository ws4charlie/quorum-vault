# Enrolling a passkey approver

The approvers' own page is `web/approval`, served by `qv-approval-web` from its own origin. [Deploy the approval page](#deploy-the-approval-page) first; the page makes the passkey, shows the entry to enrol, and approves. For high-value approvals there is a second client, [`qv-approve`](#approve-from-a-terminal-qv-approve), a command-line program for a hardware key on a small separate machine. The rest of this runbook is what the clients do underneath, for people who build another client.

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

## Approve from a terminal (`qv-approve`)

A browser is a large thing to trust: its engine, its extensions and every page it loads sit between the approver and the key. `qv-approve` is a small static Go program (`cmd/qv-approve`) for a minimal **approver machine** that has no browser except to sign in. It does what the page does, in a terminal:

- `qv-approve show <withdrawal>` fetches the intent, **recomputes SHA-256 of the canonical bytes**, refuses if it differs from the hash the core sent (or if the bytes are not this withdrawal), and prints every field in words: amount, asset, payee, chain, pool, requester, expiry, approvals needed, and the hash.
- `qv-approve approve <withdrawal>` does the same, asks you to type the first 8 characters of the hash, then asks the key for an assertion (challenge = the hash, **user verification required**: PIN and touch), and sends it to the core. The core only stores it; the zone checks it when it signs.
- `qv-approve enrol` makes a credential on the key (EdDSA if the key offers it, else ES256; user verification required), prints the attestation facts and the approver entry for the operators, and can write it to a file (`-out entry.json`). It refuses a key that does not report user verification.

### Install on the approver machine

1. Install the libfido2 tools from the system's package manager: `apt install fido2-tools` or `brew install libfido2`. `qv-approve` runs `fido2-token`, `fido2-cred` and `fido2-assert`. Why not a Go CTAP library or cgo: libfido2 is Yubico's reference code, already trusted by OpenSSH; the PIN is typed into the tool on the terminal and never enters `qv-approve`; the binary needs no C toolchain (`CGO_ENABLED=0`) and no new Go module; and it works the same on Linux and macOS. The cost is a process boundary and a text format, which the program reads strictly (every echo is compared with what was sent). On Linux the user needs access to the key's `/dev/hidraw*` (the udev rules of libfido2 or `libu2f-udev`).
2. Build `go build ./cmd/qv-approve` from the reviewed release, or take the binary from that release. It contains no test code: `cmd/qv-approve` has a test that fails if a software authenticator reaches the binary.
3. Settings (flags, or the environment variable shown): `-api` (`QV_API`) the core, `-issuer` (`QV_OIDC_ISSUER`) the identity provider, `-ca-file` (`QV_OIDC_CA_FILE`) the CA of both, `-origin` (`QV_APPROVE_ORIGIN`) below, `-client-id` (default `qv-approve`).

### Sign in

The program logs in with the OIDC authorization-code flow and PKCE, with a loopback redirect (a random port on `127.0.0.1`), as a **public client with no secret**. It prints a link; open it in a browser on the same machine and sign in (it asks for a fresh sign-in, with the strongest level, as the core wants for an approval). The token stays in memory and is never written to a file. Register the client `qv-approve` at the identity provider: authorization code with PKCE (S256), redirect URI `http://127.0.0.1:*`, the audience and role mappers of `qv-cli`, and the step-up `acr`. The dev realm has it. A machine with no browser can forward the loopback port from one that has; the device-code flow is not offered, because it cannot ask for a fresh sign-in. `qv-approve-e2e` in the dev realm is for the automated tests only (it skips the passkey step).

### The origin is a convention

A browser writes the page's origin into `clientDataJSON`, and the key signs it; that is what makes a passkey phishing-resistant. A command-line program has no origin, so **it writes the one you configure**. The approver entry lists the allowed origins, and the zone refuses any other, so the check still catches a misconfiguration and a client that was not set up for this approver. It does **not** stop a malicious program on the approver machine, which can write any origin. Pick one string per approver, such as `https://approve.example.com`, use it for every approval, and keep the relying party id equal to its host. The origin must be exactly `https://host[:port]` (no path), as the zone requires; `http://` is accepted only for the exact hosts `localhost`, `127.0.0.1` or `[::1]` and only when `QV_ENV` is `dev` or `test` (an unset `QV_ENV` is production and refuses it). `enrol` and `approve` take it from `-origin`, or from the entry file you pass with `-entry`.

### Enrol

1. `qv-approve enrol -origin https://approve.example.com -out entry.json`. Sign in, type the key's PIN where the tool asks, and touch the key when it blinks.
2. Read what it prints and **compare by hand**; the program does not check the FIDO Metadata Service:
   - AAGUID: the model. A YubiKey 5 series has a published AAGUID in Yubico's and the FIDO Alliance's metadata; the certificate carries the same value, and the two must match.
   - Attestation type `basic`, signature `valid`, and the certificate subject, issuer and SHA-256. A consumer YubiKey shares one attestation certificate across a batch, so it does not identify a single key; the serial is not in it.
   - Type `none` or `self` means the key gave no attestation: do not enrol a key you cannot identify another way.
3. Send `entry.json` to the operators with the name of the login. They check who sent it and sign it into the zone as in [Approvers](approvers.md). **The approver's name must equal the login's `sub`** (the printed command shows it), because the zone looks up the approver by the actor, and the actor is the token's `sub`. One name has one key: a second key for the same person needs its own login and name, with `-identity <the person>` so the zone counts them once, and a replaced key needs a new name (a revoked name is never used again).

### Approve

1. `qv-approve show <withdrawal> -asset-decimals ETH=18`. Check the payee and amount against the request you received through **another channel** (a ticket, a call). The program cannot do that for you.
2. `qv-approve approve <withdrawal> -entry entry.json -asset-decimals ETH=18`. The program refuses if the requester is you, if the hash or the withdrawal differs, or if you mistype the confirmation. Then PIN, then touch.
3. `Approval accepted by the core` means only that the core stored it. If the zone refuses it (wrong origin, another credential, no user verification) the withdrawal turns `failed` with `gateway refused`; look at its status. If the key does not report user verification, or touch, the program refuses to send (the zone would refuse it anyway); set a PIN on the key.
4. `the core wants a fresher sign-in`: run the command again and sign in when asked.

### What it protects against, and what it does not

| | |
|---|---|
| A lying core (wrong hash, another withdrawal, bytes that are not an intent) | Caught: the program recomputes the hash and refuses; the key is not asked |
| A compromised browser on the approver's everyday machine | Not on the path: the approval is made on a separate machine |
| A compromised **approver machine or `qv-approve` binary** | **Not caught.** It can print one payee and sign another, and write any origin. The key signs a hash it cannot read |
| A key with no PIN, or a PIN never entered | Enrol refuses; an assertion without the user-verification flag is refused by the zone |
| A stolen key | The thief needs the PIN (a few wrong tries lock the key); revoke the approver ([Approvers](approvers.md)) |

**No YubiKey has a display.** FIDO has no way to show transaction data on the key. What the separate machine buys is a smaller thing to trust: no browser engine, no page, a small amount of Go, and the libfido2 tools. Keep that machine minimal, patched, and used for nothing else; deploy the binary from the release you reviewed; the machine and the program are as sensitive as the key. Closing the gap needs a device that shows the job itself ([Limits](../limits.md)).

On Kubernetes nothing runs there: `qv-approve` runs on the approver's own machine, outside every cluster. It needs outbound access to the core API and the identity provider only, keeps no state (the token lives in memory; the entry file is public), and opens no inbound port except a loopback port during sign-in.

### Test status

The automated tests (`internal/ctap`, `internal/approvecli`, `e2e/custody/yubikey_cli_test.go`) use a **software authenticator**: enrolment, approval through the real core and zone together with an Ed25519 approver, a lying core refused by the CLI, a key without user verification refused by the zone, another origin refused by the zone, and the loopback login against the dev Keycloak. They check our reading of the libfido2 tools' output as documented in their man pages and source. **This path has not been run on a real YubiKey, or with the real `fido2-*` tools.** Do the manual test below before relying on it.

### Manual test with a real YubiKey (not yet run)

Needs: a YubiKey 5 with firmware 5.7.4 (or write what you have), `ykman` 5.x, the libfido2 tools, a built `qv-approve`, the dev stack (`docker compose up`, `scripts/pki.sh`) with Keycloak (`make keycloak-up`) and the zone config with operators, a requester login and a second approver (an Ed25519 key). Record firmware, serial and every result in the table and put the table in the pull request.

| # | Step | You should see | Result |
|---|---|---|---|
| 1 | `ykman info`; `ykman fido info` | Firmware 5.7.4 or later; write the serial. If no FIDO PIN is set: `ykman fido access change-pin`, then check again | |
| 2 | `fido2-token -L`, then `fido2-token -I <device>` | Exactly one key listed. Write down the algorithms line (does it offer eddsa?) | |
| 3 | `qv-approve enrol -origin https://approve.example.com -out entry.json` | A sign-in link; the PIN prompt; the key blinks, you touch it; the entry with `alg` `EdDSA` (or ES256 if the key lacks it); AAGUID; attestation `basic`, signature `valid`. **Write the AAGUID and compare it with Yubico's list** | |
| 4 | Operators sign `entry.json` into the zone ([Approvers](approvers.md)) | `apply` succeeds | |
| 5 | Another login requests a withdrawal of 2 ETH (two approvals). `qv-approve show <id>` | Every field in words; the hash equals `GET /v2/withdrawals/<id>/intent`'s `hash` | |
| 6 | `qv-approve approve <id> -entry entry.json`, type the 8 characters | PIN prompt, the key blinks, `Approval accepted by the core` | |
| 7 | The Ed25519 approver approves; wait | The zone signs and the withdrawal is `confirmed`; the audit trail shows both approvals | |
| 8 | **No touch:** start `approve` on a new withdrawal and do not touch | The tool times out; `the key gave no assertion`; nothing sent (the core's approvals count did not change) | |
| 9 | **Wrong PIN once** (never three times in a row: the key counts retries; `ykman fido info` shows how many are left) | The tool reports a wrong PIN; nothing sent | |
| 10 | **No origin match:** `approve ... -origin https://other.example.com` on a new withdrawal; the Ed25519 approver also approves | The core accepts, the zone refuses: `failed`, `gateway refused`; nothing paid | |
| 11 | **Lying core (optional):** run a local proxy in front of the core that changes the `hash` of the intent response; point `-api` at it | `REFUSED ... Nothing was signed`; the key is not touched | |
| 12 | **No PIN set:** reset the FIDO application of a **spare** key (`ykman fido reset`, erases its credentials) and run `enrol` | Enrol fails or says the key did not verify the user; no entry is printed. (An `approve` that reports no user verification is refused by the program: `not sent`) | |
| 13 | **Spare key:** give a second YubiKey its own login and name (for example `bob-spare`), run `enrol -identity bob` with that login, have the operators sign it. Request a withdrawal that needs two people; approve with the first key (as `bob`) and the second key (as `bob-spare`) | The zone counts one person for both keys: the withdrawal does **not** proceed on those two approvals; it proceeds when a third person approves | |
| 14 | **Revoke:** the operators revoke `bob`; try `approve` on a new withdrawal with the first key | The core accepts it, the zone ignores it; the withdrawal does not proceed on it | |

Result of the whole test, date, who ran it, firmware, serial: _______________________
