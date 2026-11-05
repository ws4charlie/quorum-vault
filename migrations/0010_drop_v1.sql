-- The /v1 demo is gone; drop the tables only it used. audit_log stays (it has no foreign keys).
-- Dependents first: approvals -> sign_requests -> allowlist, policies, keys -> wallets.
DROP TABLE approvals;
DROP TABLE sign_requests;
DROP TABLE allowlist;
DROP TABLE policies;
DROP TABLE keys;
DROP TABLE wallets;
