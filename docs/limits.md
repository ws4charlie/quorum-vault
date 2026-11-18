# Limits

[中文](zh/limits.md)

Here's what QuorumVault can't do yet, so you don't have to find out the hard way.

- **Local chains only.** Tests run against a local EVM node, Bitcoin regtest and a local Solana validator. Nothing has met a real fee market, a deep reorganisation or a congested network.
- **No testnet or mainnet use.** Do not point it at real funds or real keys.
- **SoftHSM, not hardware.** The tokens are software with no tamper resistance. The structure is what a real HSM would need, but it is not one.
- **M-of-N is simulated.** The cold signer checks operator signatures in software; a hardware HSM would enforce it itself.
- **All parties run on one machine, run by one team.** The cryptographic separation is real. The operational separation is not.
- **cb-mpc has had no external review here.** That is why a key freezes on any cryptographic failure.
- **Login and passkeys are tested with simulated parts.** The API really requires an OpenID Connect token, but the test users and the dev Keycloak are test data, and the tests log in and approve with software authenticators. No real hardware key, no attestation and no real user verification has been tried. There is no UI, and the idle limit is enforced by the identity provider, not the core ([Identity](identity.md)).
- **What you see is what you sign is not solved.** A security key signs a hash and has no screen. A compromised approval page could show one payee and ask for a signature on another job. The zone can only check that the signature is for the job it was given. A separate approval page that builds what it shows from the job itself is planned.
- **The write-once audit store used in tests, SeaweedFS, has no independent compliance assessment.** It proves our code against the storage interface, not a regulatory claim; production is meant to use AWS S3 Object Lock ([spike note](spikes/audit-worm.md)).
- **Service identity is simulated.** The two certificate authorities are made on the developer's machine by a script, their keys sit in a file, and nothing is held in an HSM or a hardware-backed PKI. SPIRE is not built; certificates are renewed by running the script again. Production must bring its own PKI (see the [certificate runbook](runbooks/certificates.md)). The links between the signing parties still use pinned certificates. The core API and the databases are covered; Kafka, Temporal and the rest are not yet.
- **No load test.** Numbers were measured on a laptop, not on target hardware ([measurements](measurements)).
- **Two-party keys need both parties.** Bitcoin and Solana deposit sweeps pause if A or B is down.
- **Bitcoin has one hot shard per pool**, so no rebalance. Taproot addresses are not supported, because the signing library cannot derive them ([spike note](spikes/btc-taproot.md)).
- **Batched Bitcoin payments are visible.** The chain shows that the recipients were paid together.
- **Solana is narrower.** Only the classic token program is credited, a very large customer base would need a different scan, and a cold ceremony that signs on a recent blockhash must finish within its short life.
- **One refill per cold address at a time** on EVM and Bitcoin (on Solana, one per asset), and hot funding on Solana is booked by an operator call, not found by the scan.
- **Restore is drilled on one machine,** not across sites.

[DESIGN_SCALE.md](../DESIGN_SCALE.md) works out what scaling would need.
