# algorand-state-proof

A Rust implementation of **Algorand State Proof** verification. State proofs — also known as *compact certificates of collective knowledge* — use quantum-secure cryptography to prove Algorand's ledger state and transaction history across fixed intervals of **256 consecutive block rounds**. Each proof is produced natively by the Algorand network: online participants independently sign the interval's attested message with ephemeral keys, and a **pseudo-random, stake-weighted sampling process** selects a subset of those signatures until their combined stake weight provably exceeds a predetermined threshold that can act as the
supermajority stake. Each selected signature is accompanied by a Merkle membership proof authenticating it against a committed participant set, ensuring no signature can be fabricated or substituted.

Crucially, each state proof also carries the **trust parameters for the next interval** — the participant commitment and proven weight — forming a *chain of trust* where every verified proof yields the anchor needed to verify the one that follows. A single trusted starting point is all that is required to then verify an unbroken sequence of proofs covering any span of Algorand's history.

This design allows any external party to verify Algorand's consensus **without running a node**, consuming only a compact proof and a trusted anchor, making state proofs the foundation for light clients, cross-chain bridges, and zkVM-based verification pipelines.

The post-quantum security of state proofs comes from two primitives: **Falcon-1024** (a lattice-based signature scheme) for individual participant signatures, and **Sumhash512** (a hash function based on integer linear algebra over a random matrix) for the Merkle commitment trees that bind those signatures together.

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
