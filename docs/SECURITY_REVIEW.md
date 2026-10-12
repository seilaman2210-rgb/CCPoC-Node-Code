# CCPoC Node — deeper static security review

## Status and scope

This branch is an experimental review branch, not a production-ready consensus release. It contains targeted hardening changes from a static inspection of the JavaScript node. The previous PR #10 was closed without merging; this branch has not been submitted as a new PR.

A dependency-backed GitHub Actions run installs the lockfile, runs `node --check` across the JavaScript files, and executes the repository's Node test suite. These tests do not constitute a full multi-node consensus test, a live-chain replay, or a formal cryptographic audit, and do not prove backward compatibility.

## Changes in this branch

- Replace truncating BigInt division in base-target drift checks with exact multiplicative comparisons.
- Validate plot size and total-scoop metadata consistently in plot announcements, registration, proof submission, and block winner proofs.
- Align the mining target modulus with the declared 8,192 32-byte leaves per nonce to avoid two eligible leaf slots per nonce in the CCPoC layout.
- Make plot registration idempotent and prevent the public registration endpoint from replacing an existing `(plot_id, miner)` root or capacity; peer plot caches now reject conflicting re-announcements rather than overwriting their first stored commitment.
- Fix `deriveSampleIndexes`, whose former base-10 parsing of hexadecimal hashes was biased, by using bounded rejection sampling and a unique-subset algorithm; add input bounds to avoid accidental unbounded work.
- Make Merkle proof verification reject invalid indices, malformed 32-byte hashes, missing siblings, extra siblings, and non-canonical path lengths.
- Compute cumulative scheduled issuance with BigInt arithmetic, and normalize the default maximum supply to an exact decimal string.
- Derive selected non-hashed block metadata locally rather than trusting peer-provided values for them.
- Revert EVM state checkpoints after failed execution, restore per-transaction contract snapshots on recognized reverts, avoid crediting a successful contract call's value twice, and avoid debiting the transferred value for a reverted contract transaction.
- Add Node's built-in tests for the new pure helpers.
- Remove the unused `localtunnel` dependency and remediate npm audit findings by updating the lockfile, including `axios` 1.20.0, `proxy-addr` 2.0.8, `qs` 6.16.0, and `solc` 0.8.37.
- Override `solc`'s pinned `tmp` dependency to patched version 0.2.7; preserve the resolution in the root package manifest so clean installs are reproducible.

## Validation completed

A GitHub Actions run on this branch successfully installed the locked dependencies, ran `node --check` across the JavaScript files, and ran the actual repository's `npm test` command. The latest completed run reported **31 tests passed and 0 failed**:
- Base-target ratio checks: boundary cases, over-limit ratios in both directions, malformed values.
- Plot metadata checks: canonical counts, mismatches, invalid sizes, unsafe values, non-canonical encodings.
- Plot-capacity integration checks against the canonical 1 GiB scoop count.
- Merkle checks: valid two-leaf proof, missing/extra/malformed siblings, odd-sized tree duplicate-last convention, invalid indices.
- Emission checks: block-height boundaries, halving schedule, and a deterministic grid comparing cumulative emission against the per-height reward function.
- PoC layout checks: 32-byte leaf size, 8,192 entries per nonce, 1 GiB capacity arithmetic, and one eligible slot per complete nonce.
- Plot commitment immutability checks: idempotent registration, root/size/count replacement rejection, and legacy rootless rows.
- Sample-index helper checks: determinism, uniqueness, bounds, full permutations, zero samples, invalid input handling, and oversized-sample rejection.

The dependency remediation run additionally executed `npm audit` against the final clean install and reported **0 vulnerabilities** (12 October 2026). It also ran `npm ci`, the full JavaScript syntax pass, and all 31 tests successfully.

This is meaningful unit/syntax validation, but it is **not** an integration test of a running node, multi-node consensus test, replay of a real database, or formal cryptographic audit.

## Critical unresolved protocol issue: current PoC does not prove physical storage capacity

The current PoC layout declares 8,192 32-byte leaves per nonce, but the previous sampling modulus was 4,096. That made two leaf positions per nonce eligible for a challenge. This branch aligns `MINING_SCOOP_MODULUS` with `SCOOPS_PER_NONCE` (8,192), so one fixed leaf slot is eligible in each complete nonce and miners still search that slot across all nonces. This is the core pattern used by Burst/Signum: a challenge selects a scoop slot, and candidates across nonces are evaluated. The modulo-class rule itself is therefore not the fundamental flaw; the layout and sampling parameters must agree.

This adjustment is a **consensus change**, not a drop-in production patch. It is not Burst byte-compatible: CCPoC currently treats each leaf as 32 bytes, whereas Signum/Burst scoops are 64 bytes (two 32-byte hashes) within 4,096 scoops per nonce. The new setting makes the CCPoC internal layout consistent with its own 8,192-leaf nonce, but all miners and validating nodes must activate the same version at a coordinated height.

More fundamentally, a Merkle root commits to data but does not prove that the prover physically stores a plot of the claimed size. A prover can choose arbitrary leaf contents, build a root, and announce the advertised leaf count; the verifier currently validates inclusion without recomputing each leaf from a canonical plot-generation algorithm. Registration is still local database/API state rather than a required consensus-anchored plot-commitment transaction, so a block received by a node that does not know the registration can be validated using the proof packet alone. This branch reduces local root rotation by making the registration endpoint and peer caches reject conflicting updates for an existing plot ID, but first-seen cache state is not a globally agreed, challenge-time commitment. These are the unresolved fake-capacity risks.

To establish meaningful storage-hardness, a protocol upgrade must:
1. Specify a canonical plot-generation algorithm, leaf/scoop format, nonce layout, and commitment format.
2. Anchor each immutable plot commitment in consensus-validated state before it can be challenged; reject post-challenge registrations or root replacement deterministically on every node.
3. Keep the Burst-style search across all nonces, but define exact target derivation, leaf serialization, proof encoding, and deadline calculation.
4. Select a construction whose plotting/reconstruction cost makes time-memory trade-offs uneconomical. Chia's seven-table proof-of-space construction is one reference point; simply hashing `plot_id || index` would be too cheap to regenerate.
5. Add independent reference vectors and adversarial tests for fake plots, grinding, replay, duplicate leaves, invalid commitments, registration timing, and nodes with different local databases.

The miner/plot-generation implementation is not present in this repository, so end-to-end interoperability cannot be checked here. The modulus alignment removes the two-candidates-per-nonce mismatch, but it does **not establish a sound Proof-of-Capacity protocol** or solve physical-storage proofs.

## Other important unresolved issues

### State roots can be omitted
Block validation only compares state_root and contract_state_root when the incoming field is non-empty (and contract-state validation is additionally conditional on contracts being enabled). Making these mandatory may be correct for a protocol version, but is a consensus-breaking change for existing data and must be introduced with an activation/version plan and replay tests.

### Fork validation uses mutable current state
Transaction balances are validated against the node's current users table before the candidate branch is fully applied. A candidate fork should instead execute against an isolated state rooted at that fork's parent. This is a major chain-state/reorg refactor; do not assume the current branch fixes cross-fork balance validation.

### EVM gas and RPC compatibility remain incomplete
Block gas usage is based on intrinsic transaction gas, while contract execution returns actual execution gas. Fee charging, reverted-transaction receipts/status, receipt roots, logs, and eth_estimateGas need a common deterministic accounting model before claiming Ethereum-compatible execution. This branch only changes a few value/checkpoint inconsistencies; it is not an EVM audit.

### Contract rollback needs cross-contract testing
The snapshot helpers restore direct contract addresses, but nested calls can modify other contracts. Reorg rollback and failure atomicity must be tested with multi-contract call trees, storage writes, logs, balances, successful calls followed by failures, and database transaction errors. Do not assume this area is fully fixed.

### Peer URL / SSRF defense
Peer URL validation blocks obvious local/private address literals but does not by itself prove that DNS names resolve only to public addresses, nor does lexical IP filtering cover every alternate IP representation. Defend connection-time resolution and redirects, and add tests for IPv4/IPv6, DNS rebinding, mapped addresses, and redirects before exposing peer discovery to hostile input.

## Deployment and compatibility warnings

- Strict capacity validation can reject legacy plot registrations that have zero, stale, non-canonical, or mismatched total_scoops. Existing miners may need to re-register/replot under a documented migration.
- Changes to PoC proof acceptance, root requirements, block metadata interpretation, issuance checks, and EVM execution semantics can change consensus behavior. Do not roll them out to a live network as a unilateral patch.
- Before merge or deployment, run dependency-backed tests on the supported Node version, replay a database snapshot, compare chain/state roots across at least two independent nodes, and run multi-node reorg and EVM adversarial suites.

## Recommended order for further work

1. Freeze and document the PoC protocol; build a reference plot/proof verifier with adversarial vectors.
2. Design fork-specific state execution and atomic reorganization.
3. Specify deterministic EVM gas, fees, receipts, and reverts.
4. Enforce mandatory state roots under a version/activation rule.
5. Add CI, reproducible tests, two-node consensus tests, and migration tooling before opening a production PR.
