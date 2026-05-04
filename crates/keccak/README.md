# keccak

SHAKE-256 extendable-output function (XOF) serving two roles in the Algorand state proof stack: seeding Sumhash512, the primary Merkle tree hash function, and driving the pseudorandom coin generation inside the State Proof verification protocol.

## Disclaimer

**WARNING: This crate is exploratory and has not been audited.** It is not the work of a credentialed cryptographer. Anyone using it should understand the potential risks and liabilities involved, and use it at their own discretion. The API is subject to potentially breaking changes.

## Overview

This crate provides a minimal, dependency-free SHAKE-256 implementation built directly on the Keccak-f[1600] permutation. SHAKE-256 is a NIST-standardised extendable-output function (part of the SHA-3 family) and is general-purpose. This implementation is a sponge construction that covers the basic absorb, flip and squeeze interface needed by the state proof verifier.

## Usage

```rust
use keccak::Shake256;

let mut xof = Shake256::new();
xof.absorb(b"seed material");
xof.flip(); // switch from absorb to squeeze mode

let mut out = [0u8; 8];
xof.squeeze(&mut out); // squeeze 8 bytes of output
```

Multiple `squeeze` calls can be made after a single `flip`, producing a pseudorandom stream.

## Zeroize

The crate also exports a `Zeroize` trait with implementations for common types:

```rust
use keccak::Zeroize;

let mut secret = [0u8; 32];
// ... use secret ...
secret.zeroize(); // overwrite with zeros, preventing compiler elision
```

The implementation uses `core::ptr::write_volatile` and a compiler fence to prevent the zeroing from being optimized away as a dead store.

`Shake256` implements `Drop` with automatic zeroization of its internal sponge state and buffer.

## Building

```sh
cargo build
cargo test
```

## License

[MIT](../../LICENSE)
