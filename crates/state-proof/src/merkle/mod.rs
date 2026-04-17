// src/merkle/mod.rs

use crate::{constants::SUMHASH512_DIGEST_SIZE, Digest, Sumhash512};

// ── Domain prefixes ───────────────────────────────────────────────────────────
// Prefixes match Algorand's protocol package (protocol.HashID).

/// Prefix for internal Merkle tree nodes: `Hash("MA" || left || right)`.
#[allow(unused)]
const MERKLE_ARRAY_NODE: &[u8] = b"MA";

/// Prefix for empty padding leaves in a vector commitment: `Hash("MB")`.
#[allow(unused)]
const MERKLE_VC_BOTTOM_LEAF: &[u8] = b"MB";

// ── Hashable ──────────────────────────────────────────────────────────────────

/// An object that can be cryptographically hashed. 
pub trait Hashable {
    /// Returns values to be hashed `(domain, data)`. 
    /// The `domain` prevent collisions between different object types with identical byte representations.
    fn to_be_hashed(&self) -> (&'static [u8], Vec<u8>);
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Computes `Hash(domain || data)` for `obj`, reusing `h` without rebuilding its lookup table.
#[allow(unused)]
pub(crate) fn hash_obj(h: &mut Sumhash512, obj: &dyn Hashable) -> Digest {
    h.reset();
    let (domain, data) = obj.to_be_hashed();
    h.update(domain);
    h.update(&data);
    let mut out = [0u8; SUMHASH512_DIGEST_SIZE];
    h.finalize(&mut out);
    out
}

// ── Internal node ─────────────────────────────────────────────────────────────

/// Computes the hash of the internal node directly via `Hash("MA" || left || right)`.
#[allow(unused)]
pub(crate) fn hash_internal_node(h: &mut Sumhash512, left: &Digest, right: &Digest) -> Digest {
    h.reset();
    h.update(MERKLE_ARRAY_NODE);
    h.update(left);
    h.update(right);
    let mut out = [0u8; SUMHASH512_DIGEST_SIZE];
    h.finalize(&mut out);
    out
}

// ── MerkleTree ────────────────────────────────────────────────────────────────

/// A binary Merkle tree built over a slice of [`Hashable`] leaves using [`Sumhash512`].
///
/// `levels[0]` holds the leaf digests; `levels[last]` holds the single root digest.
/// An odd number of nodes at any level is padded with a zero-digest right sibling.
#[allow(unused)]
pub struct MerkleTree {
    levels: Vec<Vec<Digest>>,
}

impl MerkleTree {
    /// Builds a Merkle tree from a slice of [`Hashable`] leaves.
    // #[must_use]
    #[allow(unused)]
    pub fn build<T: Hashable>(leaves: &[T]) -> Self {

        // Defensive guard against a panic on `levels.last().unwrap()`
        // in case call is `build(&[])`, then this method returns
        // empty vector and `root()` returns `None`.
        if leaves.is_empty() {
            return Self { levels: vec![] };
        }

        // Create a new hasher instance
        let mut h = Sumhash512::new();

        // Hash each leaf into a 64-byte digest.
        // This always produced the bottom level (levels[0] of the tree.
        let leaf_level: Vec<Digest> = leaves
            .iter()
            .map(|leaf| hash_obj(&mut h, leaf))
            .collect();

        // Wrap the leaf level (`levels[0]`) inside a Vec<Vec<Digest>>.
        // The outer `Vec` will grow as we push parent levels on top
        // during the build loop.
        let mut levels = vec![leaf_level];

        // Build the tree bottom-up, one level at a time, until only the root remains.
        while levels.last().unwrap().len() > 1 {
            // Grab the current (top) level
            let current = levels.last().unwrap();

            // Pre-allocate the parent level with the right number of slots.
            let mut next = Vec::with_capacity(current.len().div_ceil(2));

            // Split into two chunks representing the internal node children (left, right).
            for chunk in current.chunks(2) {
                // Left child:
                let left = chunk[0];
                // Right child:
                // Note: If a level has an odd number of nodes, the right child is padded with zeroes.
                let right = if chunk.len() == 2 { chunk[1] } else { [0u8; SUMHASH512_DIGEST_SIZE] };
                // Hash each pair into one digest and push it on the parent level.
                next.push(hash_internal_node(&mut h, &left, &right));
            }
            // Push the parent level onto the tree as the top level.
            levels.push(next);
        }

        Self { levels }
    }

    /// Returns the root [`Digest`], or `None` if the tree was built on an empty slice.
    #[allow(unused)]
    pub fn root(&self) -> Option<Digest> {
        self.levels.last().map(|top| top[0])
    }

    /// Returns the sibling path from leaf `index` up to (but not including) the root.
    ///
    /// Each entry is the sibling digest needed to recompute the parent at that level.
    /// Returns `None` if the tree is empty or `index` is out of bounds.
    #[allow(unused)]
    pub fn prove(&self, index: usize) -> Option<Vec<Digest>> {
        if self.levels.is_empty() || index >= self.levels[0].len() {
            return None;
        }

        let mut proof = Vec::with_capacity(self.levels.len() - 1);
        let mut idx = index;

        for level in &self.levels[..self.levels.len() - 1] {
            let sibling_idx = idx ^ 1;
            let sibling = if sibling_idx < level.len() {
                level[sibling_idx]
            } else {
                [0u8; SUMHASH512_DIGEST_SIZE]
            };
            proof.push(sibling);
            idx >>= 1;
        }

        Some(proof)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    struct TestLeaf(&'static [u8]);

    impl Hashable for TestLeaf {
        fn to_be_hashed(&self) -> (&'static [u8], Vec<u8>) {
            (b"TE", self.0.to_vec())
        }
    }

    /// The `hash_obj` helper must produce the same digest for the same input every time.
    #[test]
    fn hash_obj_is_deterministic() {
        let mut h = Sumhash512::new();
        let a = hash_obj(&mut h, &TestLeaf(b"hello"));
        let b = hash_obj(&mut h, &TestLeaf(b"hello"));
        assert_eq!(a, b);
    }

    /// Same data under different domain prefixes must produce different digests.
    #[test]
    fn hash_obj_domain_separation() {
        struct OtherLeaf(&'static [u8]);
        impl Hashable for OtherLeaf {
            fn to_be_hashed(&self) -> (&'static [u8], Vec<u8>) {
                (b"OT", self.0.to_vec())
            }
        }

        let mut h = Sumhash512::new();
        let a = hash_obj(&mut h, &TestLeaf(b"hello"));
        let b = hash_obj(&mut h, &OtherLeaf(b"hello"));
        assert_ne!(a, b);
    }

    /// The `hash_obj` helper called twice in sequence must produce independent 
    /// correct results, confirming the internal reset() fires between calls.
    #[test]
    fn hash_obj_reuses_hasher() {
        let mut h = Sumhash512::new();
        let a = hash_obj(&mut h, &TestLeaf(b"first"));
        let b = hash_obj(&mut h, &TestLeaf(b"second"));

        let mut h2 = Sumhash512::new();
        let expected_a = hash_obj(&mut h2, &TestLeaf(b"first"));
        let expected_b = hash_obj(&mut h2, &TestLeaf(b"second"));

        assert_eq!(a, expected_a);
        assert_eq!(b, expected_b);
    }

    /// Passing an empty slice to the `build` method of `MerkleTree`
    /// should create a tree where the root value is `None`.
    #[test]
    fn empty_tree_has_no_root() {
        let tree = MerkleTree::build::<TestLeaf>(&[]);
        assert!(tree.root().is_none());
    }

    /// The root of a `MerkleTree` with a single leaf must
    /// be equal to that leaf's hash digest.
    #[test]
    fn single_leaf_root_equals_leaf_hash() {
        let leaves = [TestLeaf(b"only")];
        let tree = MerkleTree::build(&leaves);

        let mut h = Sumhash512::new();
        let expected = hash_obj(&mut h, &TestLeaf(b"only"));

        assert_eq!(tree.root(), Some(expected));
    }

    /// Two leaves passed to `MerkleTree:build()` should produce same hash
    /// digest as both leaves hashed individually then combined and hashed
    /// as an internal node.
    #[test]
    fn two_leaves_root_equals_manual_hash() {
        let leaves = [TestLeaf(b"left"), TestLeaf(b"right")];
        let tree = MerkleTree::build(&leaves);

        let mut h = Sumhash512::new();
        let left = hash_obj(&mut h, &TestLeaf(b"left"));
        let right = hash_obj(&mut h, &TestLeaf(b"right"));
        let expected = hash_internal_node(&mut h, &left, &right);

        assert_eq!(tree.root(), Some(expected));
    }

    /// Two different instance of `MerkleTree` with exact same leaves
    /// should produce the same deterministic root.
    #[test]
    fn root_is_deterministic() {
        let leaves = [TestLeaf(b"a"), TestLeaf(b"b"), TestLeaf(b"c")];
        let root_a = MerkleTree::build(&leaves).root();
        let root_b = MerkleTree::build(&leaves).root();
        assert_eq!(root_a, root_b);
    }

    /// Building a `MerkleTree` with different value leaves should
    /// produce a different hash digest at root.
    #[test]
    fn different_leaves_produce_different_roots() {
        let leaves_a = [TestLeaf(b"foo"), TestLeaf(b"bar")];
        let leaves_b = [TestLeaf(b"foo"), TestLeaf(b"baz")];
        assert_ne!(
            MerkleTree::build(&leaves_a).root(),
            MerkleTree::build(&leaves_b).root()
        );
    }
}
