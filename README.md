# algorand-state-proof

A Rust implementation of the full cryptographic stack behind Algorand's
post-quantum State Proofs — from low-level primitives (SHAKE-256, Sumhash512,
Merkle and Vector Commitment trees) to a complete decoder and verifier for
State Proofs, block headers, and transactions.

Enables trustless, post-quantum-secure verification of Algorand's ledger state
and transaction history without running a full node — suitable for light
clients, cross-chain bridges, and zkVM guests.

Covers the full verification chain:

- Whether a given state proof is cryptographically valid.
- Whether a given block exists within the attested 256-round interval.
- Whether a given transaction exists within a block.

## Disclaimer

**WARNING: This crate is exploratory and has not been audited.** It is not the work of a credentialed cryptographer. Anyone using it should understand the potential risks and liabilities involved, and use it at their own discretion. The API is subject to potentially breaking changes.

## What is a State Proof?

A State Proof is a compact certificate of collective agreement — a
pseudo-randomly sampled, stake-weighted subset of signatures from Algorand's
online participants, proving that a quorum agreed on a specific block interval
commitment. Rather than including every signature, a State Proof selects only
enough to provably exceed a `ProvenWeight` threshold (~30% of top-N online
stake), each bundled with a Merkle membership proof tying it back to the known
eligible signer set.

Each State Proof carries forward a participant commitment and
`ln(ProvenWeight)` for the next interval — together forming a `TrustAnchor`
— so every validated proof yields the anchor needed to verify the one that
follows. A single trusted starting point is sufficient to validate an entire
unbroken chain.

Post-quantum security rests on two Algorand-specific primitives: a
deterministic variant of the **FALCON** lattice-based signature scheme for
individual participant signatures, and **Sumhash512** (a subset-sum hash) for
the Vector Commitment trees that bind those signatures to the committed
participant set.

## Workspace crates

| Crate | Description |
|---|---|
| [`state-proof`](crates/state-proof/) | State proof decoder and verifier — the primary public-facing crate |
| [`merkle`](crates/merkle/) | Generic Merkle tree and Vector Commitment tree over SHA-256 or Sumhash512 |
| [`sumhash`](crates/sumhash/) | Algorand's Sumhash512 post-quantum hash function |

Most users only need `state-proof`. The other crates are independently usable
but are primarily internal building blocks.

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
// Pass next_anchor to the next verify_state_proof call.
```

See [`crates/state-proof/`](crates/state-proof/) for the full API documentation.

## Building

```sh
cargo build
cargo test
cargo test --features serde  # test serde support for TrustAnchor
```

Requires a C compiler (GCC, Clang, or MSVC) for the Falcon-1024 C library.

## License

[MIT](LICENSE)
