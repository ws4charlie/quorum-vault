# Limits

[中文](zh/limits.md)

This page lists what QuorumVault cannot do yet, so you don't have to find out the hard way.

**Not run for real**
- **Local chains only.** Tests run against a local EVM node, Bitcoin regtest and a local Solana validator. Nothing has met a real fee market, a deep reorganisation or a congested network.
- **No testnet or mainnet use.** Do not point it at real funds or real keys.
- **Load tested on one laptop only.** A local load test exists ([results](measurements/load-local.md)), with local chains, SoftHSM and every process on one machine. There is no run on a cluster, with real network delay, with a hardware HSM or on a real chain, so no figure is a capacity plan.
- **No real cluster has run the charts.** The four-cluster shape is a design, checked by tests ([Deployment](deployment.md)).
- **The first image release has not been made.** Images are built and checked, not published.
- **Restore is drilled on one machine,** not across sites.

**Simulated parts**
- **CloudHSM support is untested on hardware.** The party's sealing module has a profile for AWS CloudHSM, proven against its documentation and a test double. Nobody has run it on a real cluster; the first run follows [a checklist](runbooks/cloudhsm-sealer.md).
- **SoftHSM, not hardware.** The tokens are software with no tamper resistance. The structure is what a real HSM would need, but it is not one.
- **M-of-N is simulated.** The cold signing machine checks the cold signers' signatures in software; a hardware HSM would enforce the rule itself.
- **The enclave is simulated.** A stand-in produces the proof, so nobody has shown that real hardware measures what the stand-in measures ([Enclaves](enclaves.md)).
- **The AWS Nitro path has not run on hardware.** The attester, the key release through AWS KMS and the key policy are tested against fakes and one real AWS proof document. A party cannot yet run in an enclave: it still needs a network bridge, storage over vsock and a cosigner path. A key policy has no clock, so an expired program is removed only when the policy is applied again, and the chain of the proof is checked against AWS's root without checking revocation ([Nitro first run](runbooks/nitro-first-run.md)).
- **Revoking a program does not stop it at once.** A running party keeps its key in memory until it restarts, and nothing makes it ask again. To cut one off now, the operator stops it as well ([Enclaves](enclaves.md)).
- **Nothing has run the enclave charts on a real cluster.** The broker chart and the party's enclave mode are checked by tests and, later, a local cluster with the simulated enclave. The chart still refuses an enclave party outside development and test: the Nitro attester is written but has not run on hardware.
- **Service identity is simulated.** The two certificate authorities are made by a script on a developer's machine, and their keys sit in a file. Production must bring its own PKI and a certificate manager ([certificate runbook](runbooks/certificates.md)). Metrics are plain http, reachable on the local machine only.
- **All parties run on one machine, run by one team.** The cryptographic separation is real. The operational separation is not.

**Approvals and logins**
- **Logins and approvals were tested with software parts.** The test users and the development identity provider are test data, and tests approve with software keys. No real hardware key has been tried, in the browser or in the command-line tool. The approval page has run only in a headless browser.
- **"What you see is what you sign" is only partly solved.** A security key signs a hash and has no screen. The approval page recomputes the hash and catches a lying core, but a replaced page can still show one payee and ask for a signature on another job. The command-line tool is the better choice for a large payment, since it prints every field on a separate machine, but no key has a display, so the person still trusts that machine ([runbook](runbooks/webauthn-approver.md)). Closing the gap needs a device that shows the job itself, which is not built.
- **One key per approver name.** A person who wants a second key needs a second name.
- **The approval end-to-end test runs with the HSM signer only.** The MPC mode does not run it.
- **Write access to the business database can stall withdrawals through fee-cap rows but cannot change what the zone signs.** The core follows its own fee-cap rows as a hint without checking signatures; the zone judges every payment by its own record and refuses the rest ([runbook](runbooks/btc-fee-caps.md)).
- **The zone operators are a short list in the zone's settings.** They are the root of trust for approver changes, so changing the list means editing the settings and restarting. Changes that no longer meet a raised rule are ignored.

**Signing and parties**
- **The party administrator keys are software keys.** A party's admin calls (key setup, refresh, unfreeze) need several administrators to sign one request, which names everything the call does. Each administrator keeps a key on their own machine; a hardware token is not supported yet. The list itself now changes by a request the current administrators sign, and the settings list is only the starting set. If the administrators lose their quorum, the way back needs the platform operators of all three parties together, and the outage that goes with it ([runbook](runbooks/key-ceremony.md)). The old single-signature format works only while a party's settings still allow it and no change was made.
- **Replacing the recovery key is a ceremony that the tools follow, not one they run.** The parties refuse backups under a retired key and a status shows what is left, but custodians still make the new key, refresh each keyset and destroy the old backups and key by hand. A backup copy kept outside the process is out of the tools' sight. **A new recovery key and a refresh do not protect against someone who already holds the old key and old backups:** they can still rebuild the signing key and sign outside the parties. If both may have been exposed, the wallet keys must be replaced and the funds moved ([runbook](runbooks/mpc-backup-restore.md)).
- **The wrap key can be replaced inside the HSM only for a party with its own PKCS#11 token.** It cures a changed policy or a copy of the old key, not an attacker who can still use the token. A party that takes its keys from the broker cannot replace the broker's wrapping key yet: the broker has no call for it ([runbook](runbooks/key-ceremony.md)).
- **Some rollbacks cannot be detected.** If both parties are restored to the same older generation, nothing notices. A party restored to an older state of the same generation may sign a repeated job again. The broker cannot destroy the keys of old generations ([Enclaves](enclaves.md)).
- **A new key is not test-signed before it takes over.** The first real signature after activation is the first proof that it works ([Key replacement](key-replacement.md)).
- **cb-mpc has had no external review here.** That is why a key freezes on any cryptographic failure.
- **A cosigner started against an empty guard database cannot tell it from a new install.** It starts without replay history or audit chain, so after a wrong database setting or a restore from nothing the checks are silently weaker until noticed ([Certificates](runbooks/certificates.md)).
- **Small deposits wait at their deposit addresses while fees are high.** A sweep happens only when the funds are worth more than `k` times its fee; the funds are credited and safe, and they are swept when the fee falls or more arrives. The reconcile view shows why, and an alert fires when they wait too long. There is no command to sweep them at a loss ([runbook](runbooks/unswept-deposits.md)).
- **Two-party keys need both parties.** Bitcoin and Solana deposit sweeps pause if A or B is down.
- **Replacing a Solana hot wallet pauses its withdrawals briefly.** The new key cannot create its nonce accounts before it is active and funded, so new withdrawals wait between the switch and an operator creating them. Tokens of a kind the config does not list, and token accounts that are not the standard one, are reported and never moved ([Key replacement](key-replacement.md)).
- **A Solana emergency drain moves tokens in the order of the asset list, not by value,** and has run on a local validator only; the SOL goes first among the rest, and the new nonce pool is created by an operator afterwards ([stolen hot key](runbooks/stolen-hot-key.md)).
- **An emergency cannot save what a thief moves first.** The old key stays valid on chain until its funds are moved; only the signing zone refuses it. The key ceremony that points deposits at the new key takes hours and sweeps wait meanwhile; the emergency drill has run on local chains only ([stolen hot key](runbooks/stolen-hot-key.md)).
- **A stolen Solana key's payment that may already be signed holds the emergency drain, and no command ends the wait.** The owner is parked and the drain waits until the signed message lands; to abandon it there is no operator command yet ([stolen hot key](runbooks/stolen-hot-key.md)). A payment refused before any signature, or refused by a cosigner after the zone claimed its nonce, does not hold the drain.
- **A refused payment can still block the emergency move on Bitcoin.** The signing zone keeps its claim on an input when a second signing party refuses a payment after the first claimed it. On EVM the stolen key may now cancel it; on Bitcoin the zone allows no cancel from a stolen key, so one coin could stay unmovable. Not reproduced there.

**Chains**
- **Bitcoin has one hot shard per pool,** so there is no rebalance. Taproot addresses are not supported, because the signing library cannot derive them ([spike note](spikes/btc-taproot.md)).
- **Batched Bitcoin payments are visible.** The chain shows that the recipients were paid together.
- **Solana is narrower.** Only the classic token program is credited, a very large customer base would need a different scan, and a cold ceremony that signs on a recent blockhash must finish within its short life.
- **A cold address is pinned by configuration, not by a signed setting.** Switching to a new cold key is a reviewed deployment of the zone and the core with a restart; until both are changed, hot-to-cold moves are refused and tried again. A Bitcoin cold-to-cold move has no change output, so it is not fee-bumped, and an address with many outputs takes several rounds. On Solana, a payment that reaches the old address after its last step needs a new cold setup of that address before it can be moved ([runbook](runbooks/cold-key-replacement.md)).
- **One refill per cold address at a time** on EVM and Bitcoin (on Solana, one per asset), and hot funding on Solana is booked by an operator call, not found by the scan.

**Audit**
- **The write-once store used in tests has no independent compliance assessment.** It proves our code against the storage interface, not a regulatory claim; production is meant to use AWS S3 Object Lock ([spike note](spikes/audit-worm.md)).

**Deployment**
- **The AWS reference deployment has never been applied.** It is code checked without an account (format, validation, a mocked test of the isolation rules, lint and a scan). Its first real run, its costs and what only an account can show are in the [runbook](runbooks/aws-first-deploy.md).

[DESIGN_SCALE.md](../DESIGN_SCALE.md) works out what scaling would need.
