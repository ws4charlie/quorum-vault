// Package attest produces and verifies TEE attestation evidence in the AWS Nitro Enclaves attestation document format.
//
// What is real: the Verifier (NitroVerifier) is the production code. It checks a document exactly as AWS documents it, with no network
// access and no switch that skips a rule; only the trust roots (config data passed by the caller) differ between development and production.
//
// What is simulated: under the build tag teesim only, MockAttester (with MockCA, a test root plus one intermediate) writes byte-faithful
// documents, so every other component can be tested without Nitro hardware. It proves our code handles attestation correctly (refuses wrong
// measurements, debug documents, replays, stale documents). It proves nothing about isolation, about what real hardware measures into the PCRs,
// or about AWS's own chain and revocation handling. The production build contains neither the mock attester nor any test root
// (TestProductionBuildHasNoMock).
//
// Nothing calls this package yet: the attestation broker and the attested sealer come later (research/TEE.md, tasks T2 and T3).
//
// References (cited again next to each rule in nitro.go):
//   - [AWS-DOC]  https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html  (attestation document, validation, certificate chain)
//   - [NSM-API]  https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md  (document layout)
//   - [COSE]     RFC 9052 section 4.2 (COSE_Sign1) and 4.4 (Sig_structure); RFC 9053 section 2.1 (ECDSA, ES384 = alg -35)
package attest
