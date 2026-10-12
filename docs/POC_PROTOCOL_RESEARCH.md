# Proof-of-Capacity research notes

## Closest comparison: Burst/Signum

Burst/Signum is the closest architectural comparison because miners precompute plot data, a generation signature selects one scoop slot, and miners evaluate that slot across multiple nonces. Classic Burst/Signum uses 4,096 scoops of 64 bytes per nonce, and its POC2 plotting/reordering is part of the security design. CCPoC v4 does **not** use the Burst plot format or Shabal algorithm; it uses 8,192 sequential 32-byte leaves per nonce.

References:
- Signum plotting technical information: https://wiki.signum.network/signum-plotting-technical-information/index.htm
- Signum/Burst Proof of Capacity: https://wiki.signum.network/proof-of-capacity/index.htm
- Signum Java implementation: https://github.com/signum-network/signumj/blob/master/src/main/java/signumj/crypto/plot/impl/MiningPlot.java

## Alternative: Chia Proof of Space

Chia's Proof of Space has a multi-table plot construction and proof format designed around time-memory tradeoff resistance. It is a useful research baseline, not a drop-in implementation for CCPoC. Reproducing only Chia's proof interface or Merkle commitments would not reproduce its security assumptions.

References:
- Proof of Space specification: https://github.com/Chia-Network/proofofspace/blob/master/proof_of_space.md
- Chia consensus Proof of Space overview: https://docs.chia.net/chia-blockchain/consensus/proof-of-space-1.0/

## What is implemented on the review branch

See [POC_PROTOCOL_V4.md](POC_PROTOCOL_V4.md) for the current v4 wire format and validation rules. In short, this branch now includes canonical binary plot-registration transactions in consensus state, immutable plot IDs on a parent ancestry, canonical sequential SHA-256 leaves, parent-bound scoop selection, a streaming Merkle tree, and 16 deterministic canonical spot checks for every winner proof. The registration is mature only when its inclusion is at least one block before the winner block's parent.

## Important security limit

The v4 layout makes generation deterministic and lets every node validate a proof without trusting local plot-registration tables. The Merkle root binds the data, and the 16 spot checks make a sparse/noncanonical tree much harder to pass. However, the leaf generator is a simple SHA-256 chain; it can be recomputed. Therefore this implementation **does not yet prove physical disk possession** and should not be marketed as a storage-hard or formally secure Proof of Capacity. A malicious miner may trade computation for storage, and challenge/parent-hash grinding and multi-registration economics need adversarial study.

The sample count, sample derivation, leaf format, target-slot rule and registration payload are consensus parameters. Any change requires a coordinated protocol version and activation height.

## Sources and interpretation

The linked Burst/Signum and Chia documents describe their own protocols. Their security properties cannot be transferred to CCPoC solely by copying a scoop-size constant, using a Merkle tree, or committing a root. CCPoC's actual generation, proof and economic assumptions require separate review and benchmarks.
