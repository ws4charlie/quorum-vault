# Enrolling a passkey approver

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
