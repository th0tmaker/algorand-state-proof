// crates/merkle/src/lib.rs

pub use sumhash::{Sumhash512, Sumhash512Digest, SUMHASH512_DIGEST_SIZE};

// ── Merkle constants ───────────────────────────────────────────────────────────

/// Prefix for internal Merkle tree nodes: `Hash("MA" || left || right)`.
const MERKLE_ARRAY_NODE: &[u8] = b"MA";

/// Prefix for empty padding leaves ensuring that even unfilled positions in the [VcTree]
/// have a deterministic and consistent representation rather than being undefined or zero.
const MERKLE_VC_BOTTOM_LEAF: &[u8] = b"MB";

/// Maximum Merkle [Tree] depth supported by the fixed-length proof encoding.
pub const MERKLE_MAX_ENCODED_TREE_DEPTH: u8 = 20;

/// Byte length of the fixed-length [Proof] encoding: `1 (depth) + 20 × 64 (path slots)`.
pub const PROOF_FIXED_REPR_SIZE: usize = 1 + MERKLE_MAX_ENCODED_TREE_DEPTH as usize * SUMHASH512_DIGEST_SIZE;

// ── Hashable ──────────────────────────────────────────────────────────────────

/// An object that can be cryptographically hashed into a tree leaf.
/// The domain prefix prevents cross-type collisions.
pub trait Hashable {
    /// Returns `(domain, data)` for hashing. The `domain` prefix prevents collisions
    /// between different object types with identical byte representations.
    fn to_be_hashed(&self) -> (&'static [u8], Vec<u8>);
}

// ── Hash helpers ──────────────────────────────────────────────────────────────

/// Finalises `h` into a fixed-size digest, consuming the current hash state.
#[inline]
fn finish(h: &mut Sumhash512) -> Sumhash512Digest {
    let mut out = [0u8; SUMHASH512_DIGEST_SIZE];
    h.finalize(&mut out);
    out
}

/// Computes the hash of an internal node directly via `Hash("MA" || left || right)`.
fn hash_internal_node(h: &mut Sumhash512, left: &Sumhash512Digest, right: &Sumhash512Digest) -> Sumhash512Digest {
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

/// Computes `Hash(domain || data)` for `obj`, reusing `h` without rebuilding its lookup table.
pub fn hash_obj(h: &mut Sumhash512, obj: &impl Hashable) -> Sumhash512Digest {
    h.reset();
    let (domain, data) = obj.to_be_hashed();
    h.update(domain);
    h.update(&data);
    finish(h)
}

// ── Tree helpers ──────────────────────────────────────────────────────────────

/// Reverses the `depth` least-significant bits of `idx`.
///
/// Algorand Vector Commitments address leaves by bit-reversed index so that
/// sequential external indices map to well-separated internal tree positions.
fn vc_index(idx: usize, depth: u8) -> usize {
    if depth == 0 { 0 } else { idx.reverse_bits() >> (usize::BITS - depth as u32) }
}

/// Builds the level vector bottom-up from `leaf_level`, padding odd-width levels with `pad`.
/// Shared by [Tree] and [VcTree]; the caller provides the appropriate pad digest.
fn build_levels(h: &mut Sumhash512, leaf_level: Vec<Sumhash512Digest>, pad: Sumhash512Digest) -> Vec<Vec<Sumhash512Digest>> {
    // Wrap the leaf level (`levels[0]`) inside a `Vec<Vec<Digest>>`.
    // The outer vector grows as we push parent levels on top during the build loop.
    let mut levels = vec![leaf_level];

    // Build the tree bottom-up, one level at a time, until only the root remains.
    while levels.last().unwrap().len() > 1 {
        // Grab the current uppermost level.
        let current = levels.last().unwrap();

        // Pre-allocate the parent level with the right number of slots.
        let mut next = Vec::with_capacity(current.len().div_ceil(2));

        // Split into pairs representing (left, right) children of each parent node.
        // If the level has an odd number of nodes, the missing right child should be
        // padded with zeroes.
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

/// A standard binary Merkle tree built over a slice of [Hashable] leaves.
///
/// `levels[0]` holds the leaf digests; `levels[last]` holds the single root digest.
/// Odd-width levels are padded with a zero-digest right sibling.
///
/// For Vector Commitment trees use [VcTree].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Tree {
    /// The horizontal levels made up of nodes which build a hierarchical data structure.
    pub(crate) levels: Vec<Vec<Sumhash512Digest>>,
}

impl Tree {
    /// Builds a [Tree] from a slice of [Hashable] leaves.
    pub fn build<T: Hashable>(leaves: &[T]) -> Self {
        // Defensive guard: If no leaves provided return a tree with no levels.
        if leaves.is_empty() { return Self { levels: vec![] }; }

        // Create a new hasher instance.
        let mut h = Sumhash512::new();

        // Hash each leaf into a 64-byte digest — this becomes `levels[0]` of the tree.
        let leaf_level = leaves.iter().map(|l| hash_obj(&mut h, l)).collect();

        // Return the built levels wrapped inside the type.
        Self { levels: build_levels(&mut h, leaf_level, [0u8; SUMHASH512_DIGEST_SIZE]) }
    }

    /// Returns the tree root value of [Sumhash512Digest], or `None` if built on an empty slice.
    pub fn root(&self) -> Option<Sumhash512Digest> {
        self.levels.last().map(|top| top[0])
    }

    /// Returns the tree depth; `number of levels - 1`.
    pub fn depth(&self) -> usize {
        self.levels.len().saturating_sub(1)
    }

    /// Returns the sibling path from leaf `index` to the root, or `None` if out of bounds.
    pub fn prove(&self, index: usize) -> Option<Proof> {
        // Defensive guard: if the tree is empty or inquired index is out of bounds, return `None`.
        if self.levels.is_empty() || index >= self.levels[0].len() {
            return None;
        }

        // Since we guaranteed the tree is not empty, grab the index of last level
        let last_level_idx = self.levels.len() - 1;

        // Preallocate a buffer to store the proof based on the index of last level
        let mut proof = Vec::with_capacity(last_level_idx);
        let mut idx = index;  // make index mutable

        // Iterate over each level in tree levels
        for level in &self.levels[..last_level_idx] {
            // XOR with 1 flips the last bit to get the sibling index.
            // If the sibling is out of range (odd-width level), use a zero-digest pad.
            let sibling = if idx ^ 1 < level.len() { level[idx ^ 1] } else { [0u8; SUMHASH512_DIGEST_SIZE] };
            proof.push(sibling);
            // Move to the parent index for the next level up.
            idx >>= 1;
        }

        // Return the tree depth and the proof wrapped in the `Proof` type or None if early return.
        Some(Proof::new((last_level_idx) as u8, proof))
    }
}

// ── VcTree ────────────────────────────────────────────────────────────────────

/// A vector commitment scheme [Tree] built over a slice of [Hashable] leaves.
///
/// A `VcTree` builds a standard `Tree` by adhering to Algorand's vector commitment specs where the leaves are placed at
/// bit-reversed positions and padded to the next power of two `2^n` with `Hash("MB")` prefix, matching Algorand's VC spec.
///
/// Distinct from [Tree] to prevent accidentally mixing standard Merkle [Tree::prove] with the VC variant,
/// which uses a different proving algorithm. proofs from [VcTree::prove] must be
/// verified with [Proof::verify_vc].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VcTree {
    /// The underlying Merkle [Tree] with its full physical structure (including padded leaves).
    inner: Tree,
    /// The number of real leaves with actual data in the Merkle [Tree], dismissing padded leaves.
    leaf_count: usize,
}

impl VcTree {
    /// Builds a [VcTree] from a slice of [Hashable] leaves.
    pub fn build<T: Hashable>(leaves: &[T]) -> Self {
        // Defensive guard: If no leaves provided return a tree with no levels and leaf count of zero.
        if leaves.is_empty() { return Self { inner: Tree { levels: vec![] }, leaf_count: 0 }; }

        // Get the number of leaves provided.
        let leaf_count = leaves.len();

        // Create a new hasher instance.
        let mut h = Sumhash512::new();

        // Compute the bottom-leaf pad: Hash("MB"), used for all empty positions.
        let bottom_leaf = hash_vc_bottom_leaf(&mut h);

        // Round the capacity up to the next power of two so the tree is complete.
        let capacity = leaf_count.next_power_of_two();
        let depth = capacity.trailing_zeros() as u8;

        // Fill all positions with the bottom-leaf pad, then overwrite the bit-reversed slots.
        let mut leaf_level = vec![bottom_leaf; capacity];
        for (i, leaf) in leaves.iter().enumerate() {
            // the `vc_index` bit-reverses `i` so sequential external indices map
            // to well-separated internal positions, matching Algorand's VC spec.
            leaf_level[vc_index(i, depth)] = hash_obj(&mut h, leaf);
        }

        // Wrap the `Tree` and `leaf_count` into `VcTree` and return it.
        Self { inner: Tree { levels: build_levels(&mut h, leaf_level, bottom_leaf) }, leaf_count }
    }

    /// Returns the tree root value of [Sumhash512Digest], or `None` if built on an empty slice.
    pub fn root(&self) -> Option<Sumhash512Digest> {
        self.inner.root()
    }

    /// Returns the tree depth; `number of levels - 1`.
    pub fn depth(&self) -> usize {
        self.inner.depth()
    }

    /// Returns the sibling path for external leaf `index`.
    ///
    /// Bounds-checks against the original leaf count, not the padded capacity.
    /// Proofs produced here must be verified with [Proof::verify_vc].
    pub fn prove(&self, index: usize) -> Option<Proof> {
        // Defensive guard: if the tree is empty or inquired index is out of bounds, return `None`.
        if self.inner.levels.is_empty() || index >= self.leaf_count {
            return None;
        }

        // Get the last level index and the tree depth.
        let last_level_idx = self.inner.levels.len() - 1;
        let depth = self.inner.depth() as u8;

        // Translate the external index to its bit-reversed internal position.
        let mut idx = vc_index(index, depth);
        let mut proof = Vec::with_capacity(last_level_idx);

        // Collect siblings bottom-up. The tree is always complete (power-of-two width),
        // so the sibling (idx ^ 1) is always in bounds — no pad check needed.
        for level in &self.inner.levels[..last_level_idx] {
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

/// Identifies which [HashType] was used to build the tree.
///
/// Codec key: `"hsh"`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HashFactory {
    pub hash_type: HashType,
}

impl HashFactory {
    /// Returns a [HashFactory] for [Sumhash512], the default for Algorand state proofs.
    pub fn sumhash512() -> Self {
        Self { hash_type: HashType::Sumhash512 }
    }
}

// ── Proof ─────────────────────────────────────────────────────────────────────

/// A Merkle inclusion proof: a sibling path from a leaf up to the root.
///
/// Produced by [Tree::prove] or [VcTree::prove]; verified with [Proof::verify]
/// or [Proof::verify_vc] respectively.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proof {
    pub tree_depth: u8,
    pub path: Vec<Sumhash512Digest>,
    pub hash_factory: HashFactory,
}

impl Proof {
    /// Verify proof with one delegated hasher instance.
    fn verify_with(&self, leaf: Sumhash512Digest, index: usize, root: &Sumhash512Digest, h: &mut Sumhash512) -> bool {
        let mut current = leaf;
        let mut idx = index;
        for &sibling in &self.path {
            // idx & 1 == 0 means current is the left child; otherwise it is the right child.
            let (left, right) = if idx & 1 == 0 { (current, sibling) } else { (sibling, current) };
            // Recompute the parent and move up one level.
            current = hash_internal_node(h, &left, &right);
            idx >>= 1;
        }
        &current == root
    }

    /// Creates a new [Proof] from `tree_depth` and sibling `path`.
    pub fn new(tree_depth: u8, path: Vec<Sumhash512Digest>) -> Self {
        Self { tree_depth, path, hash_factory: HashFactory::sumhash512() }
    }

    /// Reconstructs the `root` from the proof path and returns `true` if the leaf value matches `root` value.
    /// For proofs produced by [VcTree::prove] use [verify_vc](Self::verify_vc) instead.
    pub fn verify(&self, leaf: Sumhash512Digest, index: usize, root: &Sumhash512Digest) -> bool {
        let mut h = Sumhash512::new();
        self.verify_with(leaf, index, root, &mut h)
    }

    /// Verifies a proof produced by [VcTree::prove].
    ///
    /// Translates external `index` to its bit-reversed internal position, then
    /// delegates to [verify](Self::verify).
    /// 
    /// For proofs produced by [Tree::prove] use [verify](Self::verify) instead.
    pub fn verify_vc(&self, leaf: Sumhash512Digest, index: usize, root: &Sumhash512Digest) -> bool {
        let mut h = Sumhash512::new();
        self.verify_with(leaf, vc_index(index, self.tree_depth), root, &mut h)
    }

    /// Serializes the sibling path into the fixed-length binary format used as
    /// leaf data in `StateProof` signature commitments.
    ///
    /// Format: `tree_depth (1 B) || (MAX - depth) × zero_digest || depth × path_entry`
    pub fn to_fixed_bytes(&self) -> [u8; PROOF_FIXED_REPR_SIZE] {
        // Zero-initialised: the leading pad slots are already correct as all-zero digests.
        let mut out = [0u8; PROOF_FIXED_REPR_SIZE];

        // Byte 0: the actual tree depth, so the verifier knows where padding ends and path begins.
        out[0] = self.tree_depth;

        // Compute how many digest-sized zero slots precede the real path entries.
        // A shallow tree (small depth) gets more leading zeroes; a full-depth tree gets none.
        let pad = MERKLE_MAX_ENCODED_TREE_DEPTH.saturating_sub(self.tree_depth) as usize;
        let path_start = 1 + pad * SUMHASH512_DIGEST_SIZE;

        // Write each sibling digest into its fixed slot immediately after the zero padding.
        for (i, entry) in self.path.iter().enumerate() {
            let offset = path_start + i * SUMHASH512_DIGEST_SIZE;
            out[offset..offset + SUMHASH512_DIGEST_SIZE].copy_from_slice(entry);
        }
        out
    }

    /// Verifies a batch of `items` that shares the same [Proof] path for a 
    /// standard Merkle [Tree] for multiple `(internal_position, leaf_digest)` pairs.
    ///
    /// Path elements are consumed greedily in sorted-position order. For [VcTree] use
    /// [verify_batch_vc](Self::verify_batch_vc), which handles bit-reversal automatically.
    pub fn verify_batch(&self, items: &[(usize, Sumhash512Digest)], root: &Sumhash512Digest) -> bool {
        use std::collections::BTreeMap;

        // A proof over zero leaves is valid only if no path elements were provided.
        if items.is_empty() {
            return self.path.is_empty();
        }

        let depth = self.tree_depth as usize;
        let mut h = Sumhash512::new();

        // Load all known (position, digest) pairs into a sorted map so we always
        // process nodes in ascending index order within each level.
        let mut level: BTreeMap<usize, Sumhash512Digest> = items.iter().copied().collect();
        let mut path_iter = self.path.iter();

        // Climb one level at a time, reducing the node set by half each round.
        for _ in 0..depth {
            let mut next: BTreeMap<usize, Sumhash512Digest> = BTreeMap::new();

            // Drain the current level, always taking the lowest-indexed node first.
            while let Some((idx, digest)) = level.pop_first() {

                // Check whether this node's sibling (idx XOR 1) is also in the batch.
                // If so, consume it directly — no path element is needed for this pair.
                // If not, pull the next sibling from the shared proof path.
                let sibling = if let Some(s) = level.remove(&(idx ^ 1)) {
                    s
                } else {
                    match path_iter.next() {
                        Some(&s) => s,
                        // Path exhausted before the tree is fully reduced — proof is invalid.
                        None => return false,
                    }
                };

                // Even index → left child; odd index → right child.
                let (left, right) = if idx & 1 == 0 { (digest, sibling) } else { (sibling, digest) };

                // Hash the pair into their parent and store it at the parent index for the next level.
                next.insert(idx >> 1, hash_internal_node(&mut h, &left, &right));
            }
            level = next;
        }

        // After climbing all levels exactly one node must remain, and it must equal the root.
        level.len() == 1 && level.values().next().unwrap() == root
    }

    /// Verifies a batch of `items` that shares the same [Proof] path for a 
    /// [VcTree].
    ///
    /// Converts external sequential indices to bit-reversed internal positions,
    /// then delegates to [verify_batch](Self::verify_batch).
    /// Use this for proofs received from [VcTree::prove].
    pub fn verify_batch_vc(&self, items: &[(usize, Sumhash512Digest)], root: &Sumhash512Digest) -> bool {
        let depth = self.tree_depth;
        let internal: Vec<(usize, Sumhash512Digest)> = items.iter()
            .map(|&(idx, d)| (vc_index(idx, depth), d))
            .collect();
        self.verify_batch(&internal, root)
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

    /// The `to_fixed_bytes()` method must produce exactly `PROOF_FIXED_REPR_SIZE` bytes with the
    /// depth in byte 0, leading zero padding for unused slots, and the path entries at the tail.
    #[test]
    fn to_fixed_bytes_layout() {
        let leaves = [TestLeaf(b"a"), TestLeaf(b"b"), TestLeaf(b"c"), TestLeaf(b"d")];
        let tree = Tree::build(&leaves);
        let proof = tree.prove(0).unwrap();

        let bytes = proof.to_fixed_bytes();

        // Total length must always equal the compile-time constant.
        assert_eq!(bytes.len(), PROOF_FIXED_REPR_SIZE);

        // First byte encodes the tree depth.
        assert_eq!(bytes[0], proof.tree_depth);

        // The leading pad region (unused slots) must be all zeroes.
        let pad = (MERKLE_MAX_ENCODED_TREE_DEPTH - proof.tree_depth) as usize;
        assert!(bytes[1..1 + pad * SUMHASH512_DIGEST_SIZE].iter().all(|&b| b == 0));

        // The tail must contain the actual path entries in order.
        let path_start = 1 + pad * SUMHASH512_DIGEST_SIZE;
        for (i, entry) in proof.path.iter().enumerate() {
            let offset = path_start + i * SUMHASH512_DIGEST_SIZE;
            assert_eq!(&bytes[offset..offset + SUMHASH512_DIGEST_SIZE], entry.as_slice());
        }
    }

    /// A batch proof over all leaves of a four-leaf tree must verify correctly.
    /// All siblings are within the batch so the shared path should be empty.
    #[test]
    fn verify_batch_all_leaves() {
        let leaves = [TestLeaf(b"a"), TestLeaf(b"b"), TestLeaf(b"c"), TestLeaf(b"d")];
        let tree = Tree::build(&leaves);
        let root = tree.root().unwrap();
        let mut h = Sumhash512::new();

        // Build a single merged proof and collect all leaf digests with their positions.
        let proof = Proof::new(tree.depth() as u8, vec![]);
        let items: Vec<(usize, Sumhash512Digest)> = leaves.iter()
            .enumerate()
            .map(|(i, l)| (i, hash_obj(&mut h, l)))
            .collect();

        assert!(proof.verify_batch(&items, &root));
    }

    /// A batch proof over a sparse subset of leaves must verify when the shared path
    /// supplies the missing siblings, and fail against the wrong root.
    #[test]
    fn verify_batch_sparse_subset() {
        let leaves = [TestLeaf(b"a"), TestLeaf(b"b"), TestLeaf(b"c"), TestLeaf(b"d")];
        let tree = Tree::build(&leaves);
        let root = tree.root().unwrap();
        let wrong_root = [0xffu8; SUMHASH512_DIGEST_SIZE];
        let mut h = Sumhash512::new();

        // Prove leaves 0 and 2; their siblings (1 and 3) must come from the path.
        let proof_0 = tree.prove(0).unwrap();
        let proof_2 = tree.prove(2).unwrap();

        // Merge the two single-leaf paths into one batch path (siblings at each level).
        let batch_path = vec![proof_0.path[0], proof_2.path[0]];
        let batch_proof = Proof::new(tree.depth() as u8, batch_path);

        let items = vec![
            (0, hash_obj(&mut h, &leaves[0])),
            (2, hash_obj(&mut h, &leaves[2])),
        ];

        assert!(batch_proof.verify_batch(&items, &root));
        assert!(!batch_proof.verify_batch(&items, &wrong_root));
    }

    /// A batch VC proof over all leaves of a four-leaf VcTree must verify correctly.
    #[test]
    fn verify_batch_vc_all_leaves() {
        let leaves = [TestLeaf(b"a"), TestLeaf(b"b"), TestLeaf(b"c"), TestLeaf(b"d")];
        let tree = VcTree::build(&leaves);
        let root = tree.root().unwrap();
        let mut h = Sumhash512::new();

        // All four leaves cover the whole tree so no path elements are needed.
        let proof = Proof::new(tree.depth() as u8, vec![]);
        let items: Vec<(usize, Sumhash512Digest)> = leaves.iter()
            .enumerate()
            .map(|(i, l)| (i, hash_obj(&mut h, l)))
            .collect();

        assert!(proof.verify_batch_vc(&items, &root));
    }

    /// A batch VC proof over a sparse subset of VC leaves must verify correctly and
    /// reject a tampered root — exercises the bit-reversal translation.
    #[test]
    fn verify_batch_vc_sparse_subset() {
        let leaves = [TestLeaf(b"a"), TestLeaf(b"b"), TestLeaf(b"c"), TestLeaf(b"d")];
        let tree = VcTree::build(&leaves);
        let root = tree.root().unwrap();
        let wrong_root = [0xffu8; SUMHASH512_DIGEST_SIZE];
        let mut h = Sumhash512::new();

        // Prove external leaves 0 and 1; collect their sibling paths.
        let proof_0 = tree.prove(0).unwrap();
        let proof_1 = tree.prove(1).unwrap();

        // After bit-reversal leaves 0 and 1 land at internal positions 0 and 2 (depth=2),
        // so they are not siblings — each proof contributes one path element per level.
        let batch_path = vec![proof_0.path[0], proof_1.path[0], proof_0.path[1]];
        let batch_proof = Proof::new(tree.depth() as u8, batch_path);

        let items = vec![
            (0, hash_obj(&mut h, &leaves[0])),
            (1, hash_obj(&mut h, &leaves[1])),
        ];

        assert!(batch_proof.verify_batch_vc(&items, &root));
        assert!(!batch_proof.verify_batch_vc(&items, &wrong_root));
    }
}
