# Limits

[中文](zh/limits.md)

Here's what QuorumVault can't do yet, so you don't have to find out the hard way.

- **Local chains only.** Tests run against a local EVM node, Bitcoin regtest and a local Solana validator. Nothing has met a real fee market, a deep reorganisation or a congested network.
- **No testnet or mainnet use.** Do not point it at real funds or real keys.
- **SoftHSM, not hardware.** The tokens are software with no tamper resistance. The structure is what a real HSM would need, but it is not one.
- **M-of-N is simulated.** The cold signer checks operator signatures in software; a hardware HSM would enforce it itself.
- **All parties run on one machine, run by one team.** The cryptographic separation is real. The operational separation is not.
- **cb-mpc has had no external review here.** That is why a key freezes on any cryptographic failure.
- **Login and passkeys are tested with simulated parts.** The API really requires an OpenID Connect token, but the test users and the dev Keycloak are test data, and the tests log in and approve with software authenticators. No real hardware key, no attestation and no real user verification has been tried. The approval page has run only in a headless browser with a virtual authenticator. The idle limit is enforced by the identity provider, not the core ([Identity](identity.md)).
- **What you see is what you sign is only partly solved.** A security key signs a hash and has no screen. The approval page, served from its own origin, builds its text from the job itself and recomputes the hash, so a lying core is caught. A replaced or compromised page can still show one payee and ask for a signature on another job, and the zone can only check that the signature is for the job it was given. Closing that needs a device that shows the job itself, such as a mobile app or a key with a screen, which is not built.
- **The write-once audit store used in tests, SeaweedFS, has no independent compliance assessment.** It proves our code against the storage interface, not a regulatory claim; production is meant to use AWS S3 Object Lock ([spike note](spikes/audit-worm.md)).
- **Service identity is simulated.** The two certificate authorities are made on the developer's machine by a script, their keys sit in a file, and nothing is held in an HSM or a hardware-backed PKI. SPIRE is not built; certificates are renewed by running the script again. Production must bring its own PKI (see the [certificate runbook](runbooks/certificates.md)). The links between the signing parties still use pinned certificates. The core API, the databases, Kafka and Temporal are covered (Temporal and the archive store check only that a caller's certificate is from the business authority; names are checked by a gate in front of Temporal, and the store's caller is identified by its access key). Metrics are plain http on localhost only. The MPC parties still use pinned certificates.
- **The core keeps its own copy of the approver keys for Bitcoin fee-cap changes** (`fee_caps_change.approvers` in the core config). A signed approver change reaches the signing zone only. A newly enrolled approver cannot sign a fee-cap change until the core config lists them, and a revoked one must also be removed there by hand, or the core takes their change and the zone refuses it ([runbook](runbooks/approvers.md)).
- **The operators are a short list in the zone config.** It is the root of trust for approver changes, so changing it is a config edit with a restart. Raising `min_operators` or removing an operator makes older changes that no longer meet the rule count as invalid and be ignored: `qv-approvers show` reports ignored rows.
- **No load test.** Numbers were measured on a laptop, not on target hardware ([measurements](measurements)).
- **Two-party keys need both parties.** Bitcoin and Solana deposit sweeps pause if A or B is down.
- **Bitcoin has one hot shard per pool**, so no rebalance. Taproot addresses are not supported, because the signing library cannot derive them ([spike note](spikes/btc-taproot.md)).
- **Batched Bitcoin payments are visible.** The chain shows that the recipients were paid together.
- **Solana is narrower.** Only the classic token program is credited, a very large customer base would need a different scan, and a cold ceremony that signs on a recent blockhash must finish within its short life.
- **One refill per cold address at a time** on EVM and Bitcoin (on Solana, one per asset), and hot funding on Solana is booked by an operator call, not found by the scan.
- **Restore is drilled on one machine,** not across sites.

[DESIGN_SCALE.md](../DESIGN_SCALE.md) works out what scaling would need.
