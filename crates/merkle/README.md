# merkle

Generic Merkle tree and Vector Commitment (VC) tree implementation for the
Algorand state proof verifier. Exposes two tree constructions, each with a
corresponding proof type supporting single-leaf and batch verification:

- **`Tree<H>`** — standard binary Merkle tree for general membership proofs.
  A proof establishes that a leaf exists in the tree, verified against the root
  via `verify()` and `verify_batch()`.

- **`VcTree<H>`** — Vector Commitment tree for index-binding inclusion proofs.
  A proof establishes that a leaf occupies a *specific position* in a
  known-size array, verified via `verify_vc()` and `verify_batch_vc()`. This
  is the primary tree type used by Algorand's state proof format.

Both types share a common interface — `build()`, `root()`, `depth()`,
`prove()` — and are generic over `MerkleHasher`. Two implementations are
provided: `Sha256` (32-byte digest) for block header and transaction trees,
and `Sumhash512` (64-byte digest) for participant and signature trees.

`no_std` compatible — depends only on `core`, `alloc`, and `sha2`
(`default-features = false`).

## Disclaimer

> [!CAUTION]
> **This crate is exploratory and has not been audited.** It is not the work of a credentialed cryptographer. Anyone using it should understand the potential risks and liabilities involved, and use it at their own discretion. The API and internal derivation parameters are subject to potentially breaking changes.

## Usage

### Hashing

```rust
use merkle::{Hashable, MerkleHasher, hash_obj, Sha256};

struct MyLeaf(u64);

impl Hashable for MyLeaf {
    fn hash_into<H: MerkleHasher>(&self, h: &mut H) {
        h.update(b"MY_DOMAIN");
        h.update(&self.0.to_le_bytes());
    }
}

let mut h = Sha256::default();
let digest: [u8; 32] = hash_obj(&mut h, &MyLeaf(42));
```

### Building and proving (VcTree)

```rust
use merkle::{VcTree, Sha256};

let leaves = [MyLeaf(1), MyLeaf(2), MyLeaf(3), MyLeaf(4)];
let tree   = VcTree::<Sha256>::build(&leaves);
let root   = tree.root().unwrap();
let proof  = tree.prove(2).unwrap(); // proof for leaf at index 2
```

### Verification

```rust
// Single leaf
assert!(proof.verify_vc(leaf_digest, 2, &root));

// Batch — multiple leaves against the same proof path
let elems: Vec<(usize, [u8; 32])> = vec![(0, d0), (2, d2)];
assert!(proof.verify_batch_vc(&elems, &root));
```

### Proof from wire data

```rust
use merkle::{Proof, Sha256};

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

[MIT](../../LICENSE)
