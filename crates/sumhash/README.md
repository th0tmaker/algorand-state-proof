# sumhash

Subset-sum hash function implementing a generic `Sumhash` construction. It uses a compression matrix deterministically sampled from a
public seed via the [`xof`](crates/xof/) crate’s `Shake256` and precomputes a lookup table to accelerate byte-wise matrix accumulation.

Exposes a fixed instance named `Sumhash512`, instantiated with Algorand-specific parameters (fixed dimension and seed configuration).

Security is grounded in the hardness of the Short Integer Solution (SIS) lattice problem.

The construction is intended for Merkle tree hashing and cryptographic commitments within the Algorand state proof stack.

`no_std` compatible — depends only on `core` and `alloc`.

## Disclaimer

**WARNING: This crate is exploratory and has not been audited.** It is not the work of a credentialed cryptographer.
Anyone using it should understand the potential risks and liabilities involved, and use it at their own discretion.
The API is subject to potentially breaking changes.

## Usage

One-shot digest:

```rust
use sumhash::{Sumhash512, Sumhash512Digest};

let digest: Sumhash512Digest = Sumhash512::digest(b"some data"); // [u8; 64]
```

Streaming with reuse — `reset()` clears internal state without rebuilding the
lookup table, which is important for performance when hashing many leaves:

```rust
use sumhash::{Sumhash512, SUMHASH512_DIGEST_SIZE};

let mut h = Sumhash512::new();
h.update(b"some ");
h.update(b"data");
let mut out = [0u8; SUMHASH512_DIGEST_SIZE];
h.finalize(&mut out);
h.reset(); // ready to hash again
```

`Sumhash512` implements the `MerkleHasher` trait from the [`merkle`](../merkle/)
crate, making it directly usable for any tree construction that supports the trait.

## Memory safety

`Sumhash512` implements `Drop` with zeroization: the internal state, output buffer,
and block buffer are overwritten with zeros on drop, reducing the window in which
intermediate hash state lingers in memory.

## Building

```sh
cargo build
cargo test
```

## License

[MIT](../../LICENSE)
