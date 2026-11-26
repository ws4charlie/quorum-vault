-- Requests of the signing API for AgentGate (docs/gate-credential.md, "The signing API"). One row per credential_id: it makes the API idempotent (the
-- same request again gets the stored answer or waits for the same job; the same credential_id with another body is refused as replayed) and is pruned
-- by the worker after expires_at + skew + 1 day. It is a convenience of the business side, not the rule: each checker of the signing zone keeps its own
-- record of used credentials in its own guard database.
CREATE TABLE gate_requests (
    credential_id text PRIMARY KEY CHECK (credential_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
    body_hash     bytea NOT NULL,                             -- of wallet_id, kind, payload and credential: another body under the id is replayed
    wallet_id     text NOT NULL,
    kind          text NOT NULL,
    job_id        text NOT NULL,                              -- the sign job that carries the credential to the zone
    status        text NOT NULL CHECK (status IN ('pending', 'signed', 'refused')),
    http_status   integer,                                    -- of the stored answer (signed: 200; refused: 4xx or 503 signing_failed)
    result        text,                                       -- the stored answer (JSON), returned byte for byte to a repeat
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL                        -- the credential's expires_at
);
CREATE INDEX gate_requests_expires ON gate_requests (expires_at);

GRANT SELECT, INSERT, UPDATE ON gate_requests TO qv_core;
GRANT SELECT, DELETE ON gate_requests TO qv_worker;
