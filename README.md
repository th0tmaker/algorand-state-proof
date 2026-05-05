# algorand-state-proof

This repository is a Rust implementation of **Algorand's State Proof** functionality. State Proofs — also known as Compact Certificates — use quantum-resilient cryptography to attest to Algorand's block history across a fixed State Proof Interval of **256** rounds. Each State Proof is produced natively by the Algorand network: online participating accounts independently sign the interval's attested message using ephemeral keys managed by a Merkle Signature Scheme, and a **pseudo-random, stake-weighted sampling process** selects a subset of those signatures whose combined weight provably exceeds a predetermined ProvenWeight threshold (defined as `TotalWeight × f_SP / 2^32`, approximately 30% of the top-N online accounts' stake).

Each selected signature is accompanied by a **Vector Commitment (Merkle) membership proof** authenticating it against a committed participant array, ensuring signatures can be verified without trusting the prover.

Each State Proof message also carries forward a participant commitment and a `ln(ProvenWeight)` value for the *next* State Proof interval, forming a verifiable chain where every validated proof yields the trust parameters needed to verify the one that follows. A single trusted genesis commitment is sufficient to verify an unbroken sequence of proofs.

This design allows any external party — including light clients and cross-chain bridges — to verify Algorand's consensus **without running a full node**, consuming only a compact proof and a trusted anchor.

Post-quantum security is grounded in two Algorand-specific cryptographic primitives: a deterministic variant of the **FALCON** lattice-based signature scheme (quantum-resilient and SNARK-friendly) for individual participant signatures, and **Sumhash512** (a subset-sum hash function) for the Vector Commitment trees that bind those signatures to the committed participant set.

The workspace is organized as a stack of focused, composable crates — [`keccak`](crates/keccak/), [`sumhash`](crates/sumhash/), and [`merkle`](crates/merkle/) provide the cryptographic building blocks, while [`state-proof`](crates/state-proof/) integrates them into a complete decoding and verification pipeline.

## Disclaimer

**WARNING: This crate is exploratory and has not been audited.** It is not the work of a credentialed cryptographer. Anyone using it should understand the potential risks and liabilities involved, and use it at their own discretion. The API is subject to potentially breaking changes.

## Workspace crates

| Crate | Description |
|---|---|
| [`state-proof`](crates/state-proof/) | State proof decoder and verifier — the primary public-facing crate |
| [`merkle`](crates/merkle/) | Generic Merkle tree and Vector Commitment tree over SHA-256 or Sumhash512 |
| [`sumhash`](crates/sumhash/) | Algorand's Sumhash512 post-quantum hash function |
| [`keccak`](crates/keccak/) | SHAKE-256 extendable-output function and `Zeroize` trait |

Most users only need `state-proof`. The other crates are independently usable but are primarily internal building blocks.

## Quick start

```toml
[dependencies]
algorand-state-proof = { git = "https://github.com/th0tmaker/algorand-state-proof", rev = "<commit-sha>" }

# Enable serde Serialize/Deserialize for TrustAnchor (required for RISC Zero zkVM use)
algorand-state-proof = { git = "https://github.com/th0tmaker/algorand-state-proof", rev = "<commit-sha>", features = ["serde"] }
```

```rust
use algorand_state_proof::{StateProof, StateProofMessage, TrustAnchor, verify_state_proof};

// Decode from Algorand wire format (canonical MessagePack)
let sp      = StateProof::from_msgpack(sp_bytes)?;
let message = StateProofMessage::from_msgpack(msg_bytes)?;

// anchor comes from the previous interval's StateProofMessage
let next_anchor = verify_state_proof(&sp, &message, &anchor)?;

// next_anchor is passed to the next verify_state_proof call
```

See [`crates/state-proof/`](crates/state-proof/) for the full API documentation.

## Building

```sh
cargo build
cargo test
cargo test --features serde  # test serde support for TrustAnchor
```

Requires a C compiler (GCC, Clang, or MSVC) for the vendored Falcon-1024 C library pulled in via `algorand-falcon-keys`.

## License

[MIT](LICENSE)
