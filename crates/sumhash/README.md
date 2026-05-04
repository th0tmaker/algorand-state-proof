# sumhash

Post-quantum hash function crate exposing both a general `Sumhash` type parameterised over digest size and compression matrix, and `Sumhash512` — the specific Algorand protocol variant used as the primary hash function for the participant and signature Vector Commitment trees in Algorand State Proofs.

## Disclaimer

**WARNING: This crate is exploratory and has not been audited.** It is not the work of a credentialed cryptographer. Anyone using it should understand the potential risks and liabilities involved, and use it at their own discretion. The API is subject to potentially breaking changes.

## Overview

Sumhash512 is a post-quantum secure hash function purpose-built for Algorand's state proof system. Its security is grounded in the hardness of the Short Integer Solution (SIS) lattice problem — a well-studied post-quantum hardness assumption — rather than the symmetric-cipher-inspired constructions underlying SHA-2 or SHAKE-256.

The function operates by compressing the input message through integer linear algebra over a large random matrix, a design that delivers high native throughput while providing a wide 512-bit (64-byte) security margin. The matrix is derived deterministically from a public seed, so there is no hidden structure or backdoor assumption.

Sumhash512 implements the `MerkleHasher` trait from the [`merkle`](../merkle/) crate, making it directly usable for any tree construction that supports the trait.

## Usage

```rust
use sumhash::{Sumhash512, Sumhash512Digest, SUMHASH512_DIGEST_SIZE};
use merkle::MerkleHasher;

let mut h = Sumhash512::new();
h.update(b"some data");
let digest: Sumhash512Digest = h.finalize_reset(); // [u8; 64]
```

The hasher can be reused across multiple calls via `finalize_reset()`, which resets the internal state without rebuilding the lookup table — important for performance when hashing many leaves.

## Memory safety

`Sumhash512` implements `Drop` with zeroization: the internal state, output buffer, and block buffer are overwritten with zeros when the hasher is dropped, reducing the window in which intermediate hash state lingers in memory.

## Building

```sh
cargo build
cargo test
```

## License

[MIT](../../LICENSE)
