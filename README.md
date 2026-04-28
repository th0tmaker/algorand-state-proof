# algorand-state-proof

Post-quantum verifier for Algorand State Proofs, implemented in Rust. The workspace is organised as a stack of focused crates: [`keccak`](crates/keccak/) provides the SHAKE-256 extendable-output function used for coin generation, [`sumhash`](crates/sumhash/) implements Algorand's Sumhash512 post-quantum hash function, [`merkle`](crates/merkle/) builds generic Merkle and Vector Commitment trees over either hash, and [`state-proof`](crates/state-proof/) ties them together into a complete decoder and verifier for Algorand State Proofs — enabling trustless, lightweight verification of Algorand's ledger state without running a full node.

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

MIT
