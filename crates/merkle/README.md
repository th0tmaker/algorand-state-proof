# merkle

Generic Merkle tree and Vector Commitment (VC) tree implementation for the Algorand state proof verifier.

## Disclaimer

**WARNING: This crate is exploratory and has not been audited.** It is not the work of a credentialed cryptographer. Anyone using it should understand the potential risks and liabilities involved, and use it at their own discretion. The API is subject to potentially breaking changes.

## Overview

This crate exposes two tree constructions, each with a corresponding proof type that supports single-leaf and batch verification:

- **`Tree<H>`** — a standard binary Merkle tree for general membership proofs. A proof establishes that a particular leaf exists somewhere in the tree, verifiable against the root via `verify()` and `verify_batch()`.

- **`VcTree<H>`** — a Vector Commitment tree for index-binding inclusion proofs. A proof establishes not just that a leaf exists, but that it occupies a specific position within a known-size array, verifiable against the root via `verify_vc()` and `verify_batch_vc()`. This is the primary tree type used by Algorand's state proof format.

Both types share a common interface — `build()`, `root()`, `depth()`, and `prove()` — and are generic over `MerkleHasher`, a trait that abstracts the underlying hash function. Two implementations are currently provided: `Sha256` (32-byte digest) for block header and transaction trees, and `Sumhash512` (64-byte digest) for participant and signature trees.

## Core types

### Hashing

```rust
use merkle::{Hashable, MerkleHasher, hash_obj, Sha256, Sumhash512};

// Implement Hashable for any type that should be a leaf
struct MyLeaf(u64);

impl Hashable for MyLeaf {
    fn hash_into<H: MerkleHasher>(&self, h: &mut H) {
        h.update(b"MY_DOMAIN");
        h.update(&self.0.to_le_bytes());
    }
}

// Hash a leaf into a digest
let mut h = Sha256::default();
let digest: [u8; 32] = hash_obj(&mut h, &MyLeaf(42));
```

### Building and proving (VcTree)

```rust
use merkle::VcTree;

let leaves = [MyLeaf(1), MyLeaf(2), MyLeaf(3), MyLeaf(4)];
let tree   = VcTree::<Sha256>::build(&leaves);
let root   = tree.root().unwrap();

// Prove leaf at external index 2
let proof = tree.prove(2).unwrap();
```

### Verification

```rust
use merkle::Proof;

// Single leaf
assert!(proof.verify_vc(leaf_digest, 2, &root));

// Batch — multiple leaves against the same proof path
let elems: Vec<(usize, [u8; 32])> = vec![(0, d0), (2, d2)];
assert!(proof.verify_batch_vc(&elems, &root));
```

### Proof construction from wire data

```rust
// Build a Proof<Sha256> from algod API response data
let proof = Proof::<Sha256>::new(tree_depth as u8, path_digests);
```

## Hash types

| Type | Digest size | Used in Algorand for |
|---|---|---|
| `Sha256` | 32 bytes | Block header and transaction VcTree |
| `Sumhash512` | 64 bytes | Participant and signature VcTree |

## Building

```sh
cargo build
cargo test
```

## License

MIT
