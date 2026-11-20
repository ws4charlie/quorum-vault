# Limits

[中文](zh/limits.md)

Here's what QuorumVault can't do yet, so you don't have to find out the hard way.

**Not run for real**
- **Local chains only.** Tests run against a local EVM node, Bitcoin regtest and a local Solana validator. Nothing has met a real fee market, a deep reorganisation or a congested network.
- **No testnet or mainnet use.** Do not point it at real funds or real keys.
- **No load test.** Numbers were measured on a laptop, not on target hardware ([measurements](measurements)).
- **No real cluster has run the charts.** The four-cluster shape is a design, checked by tests ([Deployment](deployment.md)).
- **The first image release has not been made.** Images are built and checked, not published.
- **Restore is drilled on one machine,** not across sites.

**Simulated parts**
- **CloudHSM support is untested on hardware.** The party's sealer has a profile for AWS CloudHSM, proven against its documentation and a test double. Nobody has run it on a real cluster; the first run follows [a checklist](runbooks/cloudhsm-sealer.md).
- **SoftHSM, not hardware.** The tokens are software with no tamper resistance. The structure is what a real HSM would need, but it is not one.
- **M-of-N is simulated.** The cold signer checks operator signatures in software; a hardware HSM would enforce it itself.
- **The enclave is simulated.** A stand-in produces the proof, so nobody has shown that real hardware measures what the stand-in measures ([Enclaves](enclaves.md)).
- **Revoking a program does not stop it at once.** A running party keeps its key in memory until it restarts, and nothing makes it ask again. To cut one off now, the operator stops it as well ([Enclaves](enclaves.md)).
- **Nothing has run the enclave charts on a real cluster.** The broker chart and the party's enclave mode are checked by tests and, later, a local cluster with the simulated enclave. There is no production attester yet, so the chart refuses an enclave party outside development and test.
- **Service identity is simulated.** The two certificate authorities are made by a script on a developer's machine, and their keys sit in a file. Production must bring its own PKI and a certificate manager ([certificate runbook](runbooks/certificates.md)). Metrics are plain http, reachable on the local machine only.
- **All parties run on one machine, run by one team.** The cryptographic separation is real. The operational separation is not.

**Approvals and logins**
- **Logins and approvals were tested with software parts.** The test users and the development identity provider are test data, and tests approve with software keys. No real hardware key has been tried, in the browser or in the terminal tool. The approval page has run only in a headless browser.
- **What you see is what you sign is only partly solved.** A security key signs a hash and has no screen. The approval page recomputes the hash and catches a lying core, but a replaced page can still show one payee and ask for a signature on another job. The terminal tool is the better choice for a large payment, since it prints every field on a separate machine, but no key has a display, so the person still trusts that machine ([runbook](runbooks/webauthn-approver.md)). Closing the gap needs a device that shows the job itself, which is not built.
- **One key per approver name.** A person who wants a second key needs a second name.
- **The approval end-to-end test runs with the HSM signer only.** The MPC mode does not run it.
- **The core keeps its own copy of the approver keys for Bitcoin fee-cap changes.** A newly enrolled approver cannot sign a fee-cap change until the core's settings list them, and a revoked one must be removed there by hand ([runbook](runbooks/approvers.md)).
- **The operators are a short list in the zone's settings.** They are the root of trust for approver changes, so changing the list means editing settings and restarting. Changes that no longer meet a raised rule are ignored.

**Signing and parties**
- **One administrator key is enough for a party's admin calls.** Calls such as key setup, refresh and unfreeze are signed by one key in the party's list, and the signature covers the operation, the key and the time, not the setup parameters.
- **Some rollbacks cannot be detected.** If both parties are restored to the same older generation, nothing notices. A party restored to older state of the same generation may sign a repeated job again. The broker cannot destroy the keys of old generations ([Enclaves](enclaves.md)).
- **Cosigners B and C share one certificate name.** Their keys differ, but the name on the list is the same.
- **A new key is not test-signed before it takes over.** The first real signature after activation is the first proof that it works ([Key replacement](key-replacement.md)).
- **cb-mpc has had no external review here.** That is why a key freezes on any cryptographic failure.
- **Two-party keys need both parties.** Bitcoin and Solana deposit sweeps pause if A or B is down.
- **A Solana hot wallet cannot be replaced yet.** Every other key can ([Key replacement](key-replacement.md)).
- **An emergency cannot save what a thief moves first.** The old key stays valid on chain until its funds are moved; only the signing zone refuses it. The cold ceremony that points deposits at the new key takes hours and sweeps wait meanwhile; the emergency drill has run on local chains only ([stolen hot key](runbooks/stolen-hot-key.md)).

**Chains**
- **Bitcoin has one hot shard per pool,** so no rebalance. Taproot addresses are not supported, because the signing library cannot derive them ([spike note](spikes/btc-taproot.md)).
- **Batched Bitcoin payments are visible.** The chain shows that the recipients were paid together.
- **Solana is narrower.** Only the classic token program is credited, a very large customer base would need a different scan, and a cold ceremony that signs on a recent blockhash must finish within its short life.
- **One refill per cold address at a time** on EVM and Bitcoin (on Solana, one per asset), and hot funding on Solana is booked by an operator call, not found by the scan.

**Audit**
- **The write-once store used in tests has no independent compliance assessment.** It proves our code against the storage interface, not a regulatory claim; production is meant to use AWS S3 Object Lock ([spike note](spikes/audit-worm.md)).

[DESIGN_SCALE.md](../DESIGN_SCALE.md) works out what scaling would need.
