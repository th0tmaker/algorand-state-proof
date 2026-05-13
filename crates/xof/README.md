# xof

Minimal, dependency-free `Shake256` extendable-output function (XOF) built
directly on the Keccak-f[1600] permutation. Serves two roles in the Algorand
state proof stack: Seeds `Sumhash512`, a quantum-resistant hash function that
backs Merkle tree construction, and drives the pseudorandom coin generation 
used to select which signatures are revealed during verification.

`no_std` compatible — depends only on `core`.

## Disclaimer

**WARNING: This crate is exploratory and has not been audited.** It is not the work of a credentialed cryptographer.
Anyone using it should understand the potential risks and liabilities involved, and use it at their own discretion.
The API is subject to potentially breaking changes.

## Usage

`Shake256` follows a strict **absorb** → **flip** → **squeeze** sponge construction lifecycle shown in the example below:

```rust
use xof::Shake256;

let mut shake = Shake256::new();
shake.absorb(b"seed material"); // feed input; absorb may be called multiple times
shake.flip();                   // finalize — no more absorb calls after this
let mut out = [0u8; 8];
shake.squeeze(&mut out);        // extract output; may be called multiple times
```

Calling `absorb` after `flip`, `flip` more than once, or `squeeze` before
`flip` all panic.

## Zeroize

The crate exports a `Zeroize` trait for zeroing secret memory. `Shake256`
implements `Drop` with automatic zeroization of its internal sponge state and
buffer on drop.

```rust
use xof::Zeroize;

let mut secret = [0u8; 32];
secret.zeroize(); // overwrite with zeros; write_volatile + compiler fence
                  // prevent the compiler from eliding the write
```

## Building

```sh
cargo build
cargo test
```

## License

[MIT](../../LICENSE)
