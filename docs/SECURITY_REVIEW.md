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
- Implement the experimental v4 plot registration payload and anchor plot roots/capacity through ordinary signed transactions validated in consensus; resolve plot commitments by the requested block ancestry and require immutable plot IDs.
- Define canonical v4 leaf generation, parent-bound target selection, streaming Merkle generation and a deterministic set of 16 canonical capacity spot checks per winning proof.
- Add plot generator/proof-builder scripts and an end-to-end test covering generated root, target proof, sample proofs, and miner signature.
- Add Node's built-in tests for the new pure helpers.
- Remove the unused `localtunnel` dependency and remediate npm audit findings by updating the lockfile, including `axios` 1.20.0, `proxy-addr` 2.0.8, `qs` 6.16.0, and `solc` 0.8.37.
- Override `solc`'s pinned `tmp` dependency to patched version 0.2.7; preserve the resolution in the root package manifest so clean installs are reproducible.

## Validation completed

A GitHub Actions run on this branch successfully installed the locked dependencies, ran `node --check` across the JavaScript files, and ran the actual repository's `npm test` command. The latest completed run reported **45 tests passed and 0 failed**:
- Base-target ratio checks: boundary cases, over-limit ratios in both directions, malformed values.
- Plot metadata checks: canonical counts, mismatches, invalid sizes, unsafe values, non-canonical encodings.
- Plot-capacity integration checks against the canonical 1 GiB scoop count.
- Merkle checks: valid two-leaf proof, missing/extra/malformed siblings, odd-sized tree duplicate-last convention, invalid indices.
- Emission checks: block-height boundaries, halving schedule, and a deterministic grid comparing cumulative emission against the per-height reward function.
- PoC layout checks: 32-byte leaf size, 8,192 entries per nonce, 1 GiB capacity arithmetic, and one eligible slot per complete nonce.
- Plot commitment immutability checks: idempotent registration, root/size/count replacement rejection, and legacy rootless rows.
- Sample-index helper checks: determinism, uniqueness, bounds, full permutations, zero samples, invalid input handling, and oversized-sample rejection.
- PoC v4 checks: canonical transaction payload, chain-parent challenge slot, deterministic generation, capacity-sample selection, streaming Merkle roots/proofs, consensus ancestry and immutable registrations.
- End-to-end v4 scripts: one-nonce plot creation, proof packet construction, target/sample inclusion paths, and miner signature.

The dependency remediation run additionally executed `npm audit` against the final clean install and reported **0 vulnerabilities** (12 October 2026). It also ran `npm ci`, the full JavaScript syntax pass, and all 45 tests successfully.

This is meaningful unit/syntax validation, but it is **not** an integration test of a running node, multi-node consensus test, replay of a real database, or formal cryptographic audit.

## PoC v4 status: consensus anchors and canonical data are implemented experimentally, but storage hardness is not proven

This branch now implements the v4 pieces described in [POC_PROTOCOL_V4.md](POC_PROTOCOL_V4.md):

- A canonical 78-byte registration payload is carried in a normal signed transaction and persisted as a block event.
- Plot commitments are immutable by plot ID on each branch's ancestry. Local registration rows and peer caches are not trusted as consensus state.
- Winner proofs require a mature commitment on the parent ancestry, the correct owner/root/capacity/format, a parent-bound target slot, a leaf recomputed using the canonical generator, and a valid Merkle path.
- The winner proof also includes 16 deterministic random spot checks; each leaf is recomputed and its path checked against the root.
- Consensus difficulty/capacity accounting reads only mature on-chain plot commitments, rather than locally announced plot sizes.

This closes the earlier **local-only registration / arbitrary-leaf** validation gap within this experimental format. It does not establish that the miner physically stores every committed byte. The canonical leaves are built from a sequential SHA-256 chain; an attacker may recompute these data instead of storing them. Sixteen spot checks raise the cost of sparse-root attacks but are a probabilistic defense, not a formal Proof-of-Space security proof. Parent-hash grinding and time-memory tradeoffs still require adversarial analysis.

V4 is a consensus-breaking change and is not Burst/Signum-compatible. This branch enforces it immediately; an activation-height migration has **not** been implemented. Do not merge or deploy it on an existing network without defining an activation height, upgrading miner/plot-generator code, replaying the historical chain and checking independent nodes/forks. For stronger storage hardness, compare a purpose-built construction such as Burst/Signum's Shabal POC2 plotting or Chia's multi-table Proof of Space; neither can be substituted without new format, proof and consensus work.

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
