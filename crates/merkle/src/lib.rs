// crates/merkle/src/lib.rs

pub use sumhash::{Sumhash512Digest, SUMHASH512_DIGEST_SIZE};
use sumhash::Sumhash512;

// ── Domain prefixes ───────────────────────────────────────────────────────────
// Prefixes match Algorand's protocol package (protocol.HashID).

/// Prefix for internal Merkle tree nodes: `Hash("MA" || left || right)`.
const MERKLE_ARRAY_NODE: &[u8] = b"MA";

/// Prefix for empty padding leaves in a vector commitment: `Hash("MB")`.
const MERKLE_VC_BOTTOM_LEAF: &[u8] = b"MB";

// ── Hashable ──────────────────────────────────────────────────────────────────

/// An object that can be cryptographically hashed into a tree leaf.
/// The domain prefix prevents cross-type collisions.
pub trait Hashable {
    /// Returns `(domain, data)` for hashing. The `domain` prefix prevents collisions
    /// between different object types with identical byte representations.
    fn to_be_hashed(&self) -> (&'static [u8], Vec<u8>);
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Finalises `h` into a fixed-size digest, consuming the current hash state.
#[inline]
fn finish(h: &mut Sumhash512) -> Sumhash512Digest {
    let mut out = [0u8; SUMHASH512_DIGEST_SIZE];
    h.finalize(&mut out);
    out
}

/// Computes `Hash(domain || data)` for `obj`, reusing `h` without rebuilding its lookup table.
pub(crate) fn hash_obj(h: &mut Sumhash512, obj: &dyn Hashable) -> Sumhash512Digest {
    h.reset();
    let (domain, data) = obj.to_be_hashed();
    h.update(domain);
    h.update(&data);
    finish(h)
}

/// Computes the hash of an internal node directly via `Hash("MA" || left || right)`.
pub(crate) fn hash_internal_node(h: &mut Sumhash512, left: &Sumhash512Digest, right: &Sumhash512Digest) -> Sumhash512Digest {
    h.reset();
    h.update(MERKLE_ARRAY_NODE);
    h.update(left);
    h.update(right);
    finish(h)
}

/// Computes the padding digest for empty VC leaf positions: `Hash("MB")`.
fn hash_vc_bottom_leaf(h: &mut Sumhash512) -> Sumhash512Digest {
    h.reset();
    h.update(MERKLE_VC_BOTTOM_LEAF);
    finish(h)
}

/// Reverses the `depth` least-significant bits of `idx`.
///
/// Algorand Vector Commitments address leaves by bit-reversed index so that
/// sequential external indices map to well-separated internal tree positions.
pub(crate) fn vc_index(idx: usize, depth: u8) -> usize {
    if depth == 0 { 0 } else { idx.reverse_bits() >> (usize::BITS - depth as u32) }
}

/// Builds the level vector bottom-up from `leaf_level`, padding odd-width levels with `pad`.
/// Shared by [`Tree`] and [`VcTree`]; the caller provides the appropriate pad digest.
fn build_levels(h: &mut Sumhash512, leaf_level: Vec<Sumhash512Digest>, pad: Sumhash512Digest) -> Vec<Vec<Sumhash512Digest>> {
    // Wrap the leaf level (levels[0]) inside a Vec<Vec<Digest>>.
    // The outer Vec grows as we push parent levels on top during the build loop.
    let mut levels = vec![leaf_level];

    // Build the tree bottom-up, one level at a time, until only the root remains.
    while levels.last().unwrap().len() > 1 {
        // Grab the current top level.
        let current = levels.last().unwrap();

        // Pre-allocate the parent level with the right number of slots.
        let mut next = Vec::with_capacity(current.len().div_ceil(2));

        // Split into pairs representing (left, right) children of each parent node.
        // If the level has an odd number of nodes, the missing right child is `pad`.
        for chunk in current.chunks(2) {
            let right = chunk.get(1).copied().unwrap_or(pad);
            // Hash the pair into one parent digest and push it onto the parent level.
            next.push(hash_internal_node(h, &chunk[0], &right));
        }

        // Push the parent level onto the tree as the new top level.
        levels.push(next);
    }
    levels
}

// ── Tree ──────────────────────────────────────────────────────────────────────

/// A standard binary Merkle tree built over a slice of [`Hashable`] leaves.
///
/// `levels[0]` holds the leaf digests; `levels[last]` holds the single root digest.
/// Odd-width levels are padded with a zero-digest right sibling.
///
/// For Vector Commitment trees use [`VcTree`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Tree {
    pub(crate) levels: Vec<Vec<Sumhash512Digest>>,
}

impl Tree {
    /// Builds a [`Tree`] from a slice of [`Hashable`] leaves.
    pub fn build<T: Hashable>(leaves: &[T]) -> Self {
        // Defensive guard: an empty slice produces an empty tree where root() returns None.
        if leaves.is_empty() { return Self { levels: vec![] }; }
        let mut h = Sumhash512::new();
        // Hash each leaf into a 64-byte digest — this becomes levels[0] of the tree.
        let leaf_level = leaves.iter().map(|l| hash_obj(&mut h, l)).collect();
        Self { levels: build_levels(&mut h, leaf_level, [0u8; SUMHASH512_DIGEST_SIZE]) }
    }

    /// Returns the root [`Sumhash512Digest`], or `None` if built on an empty slice.
    pub fn root(&self) -> Option<Sumhash512Digest> {
        self.levels.last().map(|top| top[0])
    }

    /// Returns the depth (number of levels - 1).
    pub fn depth(&self) -> usize {
        self.levels.len().saturating_sub(1)
    }

    /// Returns the sibling path from leaf `index` to the root, or `None` if out of bounds.
    pub fn prove(&self, index: usize) -> Option<Proof> {
        if self.levels.is_empty() || index >= self.levels[0].len() {
            return None;
        }
        let mut proof = Vec::with_capacity(self.levels.len() - 1);
        let mut idx = index;
        for level in &self.levels[..self.levels.len() - 1] {
            // XOR with 1 flips the last bit to get the sibling index.
            // If the sibling is out of range (odd-width level), use a zero-digest pad.
            let sibling = if idx ^ 1 < level.len() { level[idx ^ 1] } else { [0u8; SUMHASH512_DIGEST_SIZE] };
            proof.push(sibling);
            // Move to the parent index for the next level up.
            idx >>= 1;
        }
        Some(Proof::new((self.levels.len() - 1) as u8, proof))
    }
}

// ── VcTree ────────────────────────────────────────────────────────────────────

/// A Vector Commitment tree built over a slice of [`Hashable`] leaves.
///
/// Leaves are placed at bit-reversed positions and padded to the next power of
/// two with `Hash("MB")`, matching Algorand's VC spec.
///
/// Distinct from [`Tree`] to prevent accidentally mixing standard Merkle
/// prove/verify with the VC variants — proofs from [`VcTree::prove`] must be
/// verified with [`Proof::verify_vc`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VcTree {
    tree: Tree,
    leaf_count: usize,
}

impl VcTree {
    /// Builds a [`VcTree`] from a slice of [`Hashable`] leaves.
    pub fn build<T: Hashable>(leaves: &[T]) -> Self {
        let leaf_count = leaves.len();
        // Defensive guard: an empty slice produces an empty tree where root() returns None.
        if leaves.is_empty() { return Self { tree: Tree { levels: vec![] }, leaf_count: 0 }; }
        let mut h = Sumhash512::new();
        // Compute the bottom-leaf pad: Hash("MB"), used for all empty positions.
        let bottom_leaf = hash_vc_bottom_leaf(&mut h);
        // Round the capacity up to the next power of two so the tree is complete.
        let capacity = leaf_count.next_power_of_two();
        let depth = capacity.trailing_zeros() as u8;
        // Fill all positions with the bottom-leaf pad, then overwrite the bit-reversed slots.
        let mut leaf_level = vec![bottom_leaf; capacity];
        for (i, leaf) in leaves.iter().enumerate() {
            // vc_index bit-reverses `i` so sequential external indices map to
            // well-separated internal positions, matching Algorand's VC spec.
            leaf_level[vc_index(i, depth)] = hash_obj(&mut h, leaf);
        }
        Self { tree: Tree { levels: build_levels(&mut h, leaf_level, bottom_leaf) }, leaf_count }
    }

    /// Returns the root [`Sumhash512Digest`], or `None` if built on an empty slice.
    pub fn root(&self) -> Option<Sumhash512Digest> { self.tree.root() }

    /// Returns the depth (number of levels - 1).
    pub fn depth(&self) -> usize { self.tree.depth() }

    /// Returns the VC sibling path for external leaf `index`.
    ///
    /// Bounds-checks against the original leaf count, not the padded capacity.
    /// Proofs produced here must be verified with [`Proof::verify_vc`].
    pub fn prove(&self, index: usize) -> Option<Proof> {
        if self.tree.levels.is_empty() || index >= self.leaf_count {
            return None;
        }
        let depth = self.tree.depth() as u8;
        // Translate the external index to its bit-reversed internal position.
        let mut idx = vc_index(index, depth);
        let mut proof = Vec::with_capacity(self.tree.levels.len() - 1);
        // Collect siblings bottom-up. The tree is always complete (power-of-two width),
        // so the sibling (idx ^ 1) is always in bounds — no pad check needed.
        for level in &self.tree.levels[..self.tree.levels.len() - 1] {
            proof.push(level[idx ^ 1]);
            // Move to the parent index for the next level up.
            idx >>= 1;
        }
        Some(Proof::new(depth, proof))
    }
}

// ── HashType / HashFactory ────────────────────────────────────────────────────

/// Numeric hash type identifiers consistent across Algorand's State Proof implementations.
#[repr(u64)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HashType {
    Sha512_256 = 0,
    Sumhash512 = 1,
    Sha256 = 2,
    Sha512 = 3,
}

impl TryFrom<u64> for HashType {
    type Error = u64;
    fn try_from(v: u64) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(Self::Sha512_256),
            1 => Ok(Self::Sumhash512),
            2 => Ok(Self::Sha256),
            3 => Ok(Self::Sha512),
            _ => Err(v),
        }
    }
}

/// Identifies which hash function was used to build the tree. Codec key: `"hsh"`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HashFactory {
    pub hash_type: HashType,  // codec key: "t"
}

impl HashFactory {
    /// Returns a [`HashFactory`] for [`Sumhash512`], the default for Algorand state proofs.
    pub fn sumhash512() -> Self {
        Self { hash_type: HashType::Sumhash512 }
    }
}

// ── Proof ─────────────────────────────────────────────────────────────────────

/// A Merkle inclusion proof: a sibling path from a leaf up to the root.
///
/// Produced by [`Tree::prove`] or [`VcTree::prove`]; verified with [`Proof::verify`]
/// or [`Proof::verify_vc`] respectively.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proof {
    pub tree_depth: u8,
    pub path: Vec<Sumhash512Digest>,
    pub hash_factory: HashFactory,
}

impl Proof {
    /// Creates a new proof from a tree depth and sibling path.
    pub fn new(tree_depth: u8, path: Vec<Sumhash512Digest>) -> Self {
        Self { tree_depth, path, hash_factory: HashFactory::sumhash512() }
    }

    /// Reconstructs the root from the proof path and returns `true` if it matches `root`.
    /// For proofs produced by [`VcTree::prove`] use [`verify_vc`](Self::verify_vc) instead.
    pub fn verify(&self, leaf: Sumhash512Digest, index: usize, root: &Sumhash512Digest) -> bool {
        let mut h = Sumhash512::new();
        let mut current = leaf;
        let mut idx = index;
        for &sibling in &self.path {
            // idx & 1 == 0 means current is the left child; otherwise it is the right child.
            let (left, right) = if idx & 1 == 0 { (current, sibling) } else { (sibling, current) };
            // Recompute the parent and move up one level.
            current = hash_internal_node(&mut h, &left, &right);
            idx >>= 1;
        }
        &current == root
    }

    /// Verifies a proof produced by [`VcTree::prove`].
    ///
    /// Translates external `index` to its bit-reversed internal position, then
    /// delegates to [`verify`](Self::verify).
    pub fn verify_vc(&self, leaf: Sumhash512Digest, index: usize, root: &Sumhash512Digest) -> bool {
        self.verify(leaf, vc_index(index, self.tree_depth), root)
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
            fn to_be_hashed(&self) -> (&'static [u8], Vec<u8>) { (b"OT", self.0.to_vec()) }
        }
        let mut h = Sumhash512::new();
        let a = hash_obj(&mut h, &TestLeaf(b"hello"));
        let b = hash_obj(&mut h, &OtherLeaf(b"hello"));
        assert_ne!(a, b);
    }

    /// The `hash_obj` helper called twice in sequence must produce independent correct
    /// results, confirming the internal `reset()` fires between calls.
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

    /// Passing an empty slice to `Tree::build` must produce a tree where `root()` returns `None`.
    #[test]
    fn empty_tree_has_no_root() {
        let tree = Tree::build::<TestLeaf>(&[]);
        assert_eq!(tree.root(), None);
    }

    /// The root of a single-leaf tree must equal that leaf's hash digest — no internal node is formed.
    #[test]
    fn single_leaf_tree_root_is_leaf_hash() {
        let leaf = TestLeaf(b"only");
        let mut h = Sumhash512::new();
        let expected = hash_obj(&mut h, &leaf);
        let tree = Tree::build(&[leaf]);
        assert_eq!(tree.root(), Some(expected));
    }

    /// Depth must be 0 for empty and single-leaf trees, and ⌈log₂(n)⌉ for larger inputs.
    #[test]
    fn tree_depth_is_correct() {
        assert_eq!(Tree::build::<TestLeaf>(&[]).depth(), 0);
        assert_eq!(Tree::build(&[TestLeaf(b"a")]).depth(), 0);
        assert_eq!(Tree::build(&[TestLeaf(b"a"), TestLeaf(b"b")]).depth(), 1);
        assert_eq!(Tree::build(&[TestLeaf(b"a"), TestLeaf(b"b"), TestLeaf(b"c")]).depth(), 2);
    }

    /// A proof generated by `prove()` must be accepted by `verify()` for both leaves of a two-leaf tree.
    #[test]
    fn prove_verify_two_leaves() {
        let leaves = [TestLeaf(b"left"), TestLeaf(b"right")];
        let tree = Tree::build(&leaves);
        let root = tree.root().unwrap();
        let mut h = Sumhash512::new();
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.prove(i).unwrap();
            let leaf_digest = hash_obj(&mut h, leaf);
            assert!(proof.verify(leaf_digest, i, &root), "proof failed for leaf {i}");
        }
    }

    /// Proofs must be valid for all three leaves of an odd-width tree —
    /// exercises the zero-pad right sibling at level 1.
    #[test]
    fn prove_verify_three_leaves() {
        let leaves = [TestLeaf(b"a"), TestLeaf(b"b"), TestLeaf(b"c")];
        let tree = Tree::build(&leaves);
        let root = tree.root().unwrap();
        let mut h = Sumhash512::new();
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.prove(i).unwrap();
            let leaf_digest = hash_obj(&mut h, leaf);
            assert!(proof.verify(leaf_digest, i, &root), "proof failed for leaf {i}");
        }
    }

    /// The `prove()` method must return `None` for an out-of-bounds index and on an empty tree.
    #[test]
    fn prove_out_of_bounds_returns_none() {
        let tree = Tree::build(&[TestLeaf(b"only")]);
        assert!(tree.prove(1).is_none());
        assert!(Tree::build::<TestLeaf>(&[]).prove(0).is_none());
    }

    /// The `verify()` method must return `false` when the reconstructed root does not match the supplied root.
    #[test]
    fn proof_rejects_wrong_root() {
        let leaves = [TestLeaf(b"a"), TestLeaf(b"b")];
        let tree = Tree::build(&leaves);
        let wrong_root = [0xffu8; SUMHASH512_DIGEST_SIZE];
        let mut h = Sumhash512::new();
        let proof = tree.prove(0).unwrap();
        let leaf_digest = hash_obj(&mut h, &leaves[0]);
        assert!(!proof.verify(leaf_digest, 0, &wrong_root));
    }

    /// A VC proof for each leaf of a power-of-two tree must pass `verify_vc()`.
    #[test]
    fn vc_prove_verify_four_leaves() {
        let leaves = [TestLeaf(b"a"), TestLeaf(b"b"), TestLeaf(b"c"), TestLeaf(b"d")];
        let tree = VcTree::build(&leaves);
        let root = tree.root().unwrap();
        let mut h = Sumhash512::new();
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.prove(i).unwrap();
            let leaf_digest = hash_obj(&mut h, leaf);
            assert!(proof.verify_vc(leaf_digest, i, &root), "VC proof failed for leaf {i}");
        }
    }

    /// A VC proof for each leaf of a non-power-of-two tree must pass `verify_vc()` —
    /// exercises padding to the next power of two with `Hash("MB")` bottom leaves.
    #[test]
    fn vc_prove_verify_five_leaves() {
        let leaves = [TestLeaf(b"a"), TestLeaf(b"b"), TestLeaf(b"c"), TestLeaf(b"d"), TestLeaf(b"e")];
        let tree = VcTree::build(&leaves);
        let root = tree.root().unwrap();
        let mut h = Sumhash512::new();
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.prove(i).unwrap();
            let leaf_digest = hash_obj(&mut h, leaf);
            assert!(proof.verify_vc(leaf_digest, i, &root), "VC proof failed for leaf {i}");
        }
    }

    /// The `verify_vc()` method must return `false` when the reconstructed root does not match the supplied root.
    #[test]
    fn vc_proof_rejects_wrong_root() {
        let leaves = [TestLeaf(b"a"), TestLeaf(b"b")];
        let tree = VcTree::build(&leaves);
        let wrong_root = [0xffu8; SUMHASH512_DIGEST_SIZE];
        let mut h = Sumhash512::new();
        let proof = tree.prove(0).unwrap();
        let leaf_digest = hash_obj(&mut h, &leaves[0]);
        assert!(!proof.verify_vc(leaf_digest, 0, &wrong_root));
    }

    /// `VcTree::prove()` must return `None` for an index beyond the original leaf count
    /// and for an empty tree.
    #[test]
    fn vc_out_of_bounds_returns_none() {
        let tree = VcTree::build(&[TestLeaf(b"only")]);
        assert!(tree.prove(1).is_none());
        assert!(VcTree::build::<TestLeaf>(&[]).prove(0).is_none());
    }
}
