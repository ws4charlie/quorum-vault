// Package teetest is the simulated TEE rig for tests (build tag teesim): a real attestation broker (verifier, signed allowlist, audit log, a real
// SoftHSM token), the test CA and mock attester of internal/attest, and a TLS identity per party. Only the evidence's root of trust is simulated.
package teetest
