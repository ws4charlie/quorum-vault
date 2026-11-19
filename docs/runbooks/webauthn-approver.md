# Enrolling a passkey approver

A person's passkey is a second approver entry with the same `identity` as their Ed25519 key (or alone). Set `"scheme": "webauthn"`, `alg` (`ES256` or `EdDSA`), `public_key` (hex: the 65-byte uncompressed P-256 point, or the 32-byte Ed25519 key), `credential_id` (base64url), `rp_id` and `origins` (exact, `https://`). Enrol it with an operator-signed change, with no config edit or restart: see [Approvers](approvers.md). The entry goes into the change as a JSON file (`qv-approvers sign -approver-file`).
