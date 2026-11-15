# Limits

[中文](zh/limits.md)

Here's what QuorumVault can't do yet, so you don't have to find out the hard way.

- **Local chains only.** Tests run against a local EVM node, Bitcoin regtest and a local Solana validator. Nothing has met a real fee market, a deep reorganisation or a congested network.
- **No testnet or mainnet use.** Do not point it at real funds or real keys.
- **SoftHSM, not hardware.** The tokens are software with no tamper resistance. The structure is what a real HSM would need, but it is not one.
- **M-of-N is simulated.** The cold signer checks operator signatures in software; a hardware HSM would enforce it itself.
- **All parties run on one machine, run by one team.** The cryptographic separation is real. The operational separation is not.
- **cb-mpc has had no external review here.** That is why a key freezes on any cryptographic failure.
- **`X-Actor` is not authentication.** It only names the caller for dual control. There is no real identity and no UI.
- **No load test.** Numbers were measured on a laptop, not on target hardware. See [measurements](measurements).
- **Two-party keys need both parties.** Bitcoin and Solana deposit sweeps pause if A or B is down.
- **Bitcoin has one hot shard per pool**, and so no rebalance.
- **Solana is narrower.** Only the classic token program is credited, a very large customer base would need a different scan, and a cold ceremony that signs on a recent blockhash (setup, closing nonce accounts) must finish within its short life.
- **One refill per cold address at a time** on EVM and Bitcoin (on Solana, one per asset), and hot funding on Solana is booked by an operator call, not found by the scan.
- **Restore is drilled on one machine,** not across sites.

[DESIGN_SCALE.md](../DESIGN_SCALE.md) works out what scaling would need.
