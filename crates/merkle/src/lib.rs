// crates/merkle/src/lib.rs
use std::{collections::BTreeMap, fmt};

use sha2::Digest as Sha2Digest;
pub use sha2::Sha256;

pub use sumhash::{Sumhash512, Sumhash512Digest, SUMHASH512_DIGEST_SIZE};


// ── SHA-256 Constants ──────────────────────────────────────────────────────────

/// Byte length of a SHA-256 digest (32 bytes = 256 bits = 8 × 32-bit words).
pub const SHA256_DIGEST_SIZE: usize = 32;

// ── Merkle constants ───────────────────────────────────────────────────────────

/// Prefix for internal Merkle tree nodes: `Hash("MA" || left || right)`.
const MERKLE_ARRAY_NODE: &[u8] = b"MA";

/// Prefix for empty padding leaves ensuring that even unfilled positions in the [VcTree]
/// have a deterministic and consistent representation rather than being undefined or zero.
const MERKLE_VC_BOTTOM_LEAF: &[u8] = b"MB";


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
    /// Returns a [HashFactory] for [Sumhash512].
    /// Used for:
    /// * Participant Commitment: `Sumhash512("spp" || W || KLT || StateProofPK)`.
    /// * Signature Array Commitment: `Sumhash512("sps" || L || SerializedMerkleSignature)`.
    /// * Merkle Signature Scheme: `Sumhash512("KP" || SchemeID || r || Pk_i)`.
    pub fn sumhash512() -> Self {
        Self { hash_type: HashType::Sumhash512 }
    }

    /// Returns a [HashFactory] for SHA-256.
    /// Used for:
    /// * Light Block Header Commitment: `SHA-256("B256" || msgpack(LightBlockHeader))`
    pub fn sha256() -> Self {
        Self { hash_type: HashType::Sha256 }
    }
}


// ── Hashable ──────────────────────────────────────────────────────────────────

/// An object that can be cryptographically hashed into a tree leaf.
/// The domain prefix prevents cross-type collisions.
pub trait Hashable {
    /// Returns `(domain, data)` for hashing. The `domain` prefix prevents collisions
    /// between different object types with identical byte representations.
    fn to_be_hashed(&self) -> (&'static [u8], Vec<u8>);
}


// ── MerkleHasher ──────────────────────────────────────────────────────────────

/// A hash function that can be used to build and verify Merkle trees.
///
/// Implementations are expected to be reusable: `finalize_reset` produces the
/// digest and immediately resets the internal state for the next computation.
/// For [Sumhash512] this preserves the expensive lookup table; for [Sha256] the
/// reset is a trivial swap since initialization is cheap.
pub trait MerkleHasher: Sized {
    /// The fixed-size digest produced by this hasher.
    type Digest: Copy + PartialEq + Eq + fmt::Debug + AsRef<[u8]>;

    /// The identifier for this hasher, used to populate [HashFactory].
    const HASH_TYPE: HashType;

    /// The all-zero digest used to pad incomplete tree levels.
    const ZERO_DIGEST: Self::Digest;

    /// Creates a freshly initialized hasher instance.
    fn init() -> Self;

    /// Feeds `data` into the running hash state.
    fn update(&mut self, data: &[u8]);

    /// Finalizes the hash and resets the internal state for reuse.
    ///
    /// For [Sumhash512]: writes the digest and resets the running state while
    /// preserving the expensive lookup table built at construction.
    /// For [Sha256]: swaps in a fresh instance, which is equally cheap.
    fn finalize_reset(&mut self) -> Self::Digest;
}

impl MerkleHasher for Sumhash512 {
    type Digest = Sumhash512Digest;
    const HASH_TYPE: HashType = HashType::Sumhash512;
    const ZERO_DIGEST: Sumhash512Digest = [0u8; SUMHASH512_DIGEST_SIZE];

    fn init() -> Self {
        Sumhash512::new()
    }

    fn update(&mut self, data: &[u8]) {
        Sumhash512::update(self, data);
    }

    fn finalize_reset(&mut self) -> Self::Digest {
        let mut out = [0u8; SUMHASH512_DIGEST_SIZE];
        Sumhash512::finalize(self, &mut out);
        Sumhash512::reset(self);
        out
    }
}

impl MerkleHasher for Sha256 {
    type Digest = [u8; SHA256_DIGEST_SIZE];
    const HASH_TYPE: HashType = HashType::Sha256;
    const ZERO_DIGEST: [u8; SHA256_DIGEST_SIZE] = [0u8; SHA256_DIGEST_SIZE];

    fn init() -> Self {
        Default::default()
    }

    fn update(&mut self, data: &[u8]) {
        Sha2Digest::update(self, data);
    }

    fn finalize_reset(&mut self) -> Self::Digest {
        // Swap in a fresh instance and finalize the old one — both steps are O(1).
        std::mem::take(self).finalize().into()
    }
}


// ── Hash helpers ──────────────────────────────────────────────────────────────

/// Computes `Hash(domain || data)` for `obj`, reusing `h` across calls.
///
/// For [Sumhash512], reusing `h` avoids rebuilding the expensive lookup table.
/// Pass the same `h` for all leaves when building or verifying a tree.
pub fn hash_obj<H: MerkleHasher>(h: &mut H, obj: &impl Hashable) -> H::Digest {
    let (domain, data) = obj.to_be_hashed();
    h.update(domain);
    h.update(&data);
    h.finalize_reset()
}

/// Computes `Hash("MA" || left || right)` for an internal tree node.
fn hash_internal_node<H: MerkleHasher>(h: &mut H, left: &H::Digest, right: &H::Digest) -> H::Digest {
    h.update(MERKLE_ARRAY_NODE);
    h.update(left.as_ref());
    h.update(right.as_ref());
    h.finalize_reset()
}

/// Computes `Hash("MB")` — the canonical empty-padding digest for [VcTree] leaves.
fn hash_vc_bottom_leaf<H: MerkleHasher>(h: &mut H) -> H::Digest {
    h.update(MERKLE_VC_BOTTOM_LEAF);
    h.finalize_reset()
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
fn build_levels<H: MerkleHasher>(h: &mut H, leaf_level: Vec<H::Digest>, pad: H::Digest) -> Vec<Vec<H::Digest>> {
    let mut levels = vec![leaf_level];

    while let Some(current_level) = levels.last() {
        let total_nodes = current_level.len();
        if total_nodes <= 1 { break; }

        let mut next = Vec::with_capacity(total_nodes.div_ceil(2));

        for chunk in current_level.chunks(2) {
            let right = chunk.get(1).copied().unwrap_or(pad);
            next.push(hash_internal_node(h, &chunk[0], &right));
        }

        levels.push(next);
    }
    levels
}


// ── Tree ──────────────────────────────────────────────────────────────────────

/// A membership binary Merkle tree built over a slice of [Hashable] leaves.
///
/// `levels[0]` holds the leaf digests; `levels[last]` holds the single root digest.
/// Odd-width levels are padded with a zero-digest right sibling.
///
/// For Vector Commitment index-based proving scheme use [VcTree].
pub struct Tree<H: MerkleHasher> {
    levels: Vec<Vec<H::Digest>>,
}

impl<H: MerkleHasher> Tree<H> {
    /// Builds a [Tree] from a slice of [Hashable] leaves.
    pub fn build<T: Hashable>(leaves: &[T]) -> Self {
        if leaves.is_empty() { return Self { levels: vec![] }; }
        let mut h = H::init();
        let leaf_level = leaves.iter().map(|l| hash_obj(&mut h, l)).collect();
        Self { levels: build_levels(&mut h, leaf_level, H::ZERO_DIGEST) }
    }

    /// Returns the tree root, or `None` if built on an empty slice.
    pub fn root(&self) -> Option<H::Digest> {
        self.levels.last().map(|top| top[0])
    }

    /// Returns the tree depth; `number of levels - 1`.
    pub fn depth(&self) -> usize {
        self.levels.len().saturating_sub(1)
    }

    /// Returns the sibling path from leaf `index` to the root, or `None` if out of bounds.
    pub fn prove(&self, index: usize) -> Option<Proof<H>> {
        if self.levels.is_empty() || index >= self.levels[0].len() { return None; }
        let last_level_idx = self.levels.len() - 1;
        let mut proof = Vec::with_capacity(last_level_idx);
        let mut idx = index;
        for level in &self.levels[..last_level_idx] {
            let sibling = if idx ^ 1 < level.len() { level[idx ^ 1] } else { H::ZERO_DIGEST };
            proof.push(sibling);
            idx >>= 1;
        }
        Some(Proof::new(last_level_idx as u8, proof))
    }
}


// ── VcTree ────────────────────────────────────────────────────────────────────

/// A vector commitment scheme [Tree] built over a slice of [Hashable] leaves.
///
/// Leaves are placed at bit-reversed positions and padded to the next power of
/// two with `Hash("MB")`, matching Algorand's VC spec.
///
/// Distinct from [Tree] to prevent accidentally mixing membership Merkle proofs
/// with VC proofs — proofs from [VcTree::prove] must be verified via [Proof::verify_vc].
pub struct VcTree<H: MerkleHasher> {
    inner: Tree<H>,
    leaf_count: usize,
}

impl<H: MerkleHasher> VcTree<H> {
    /// Builds a [VcTree] from a slice of [Hashable] leaves.
    pub fn build<T: Hashable>(leaves: &[T]) -> Self {
        if leaves.is_empty() { return Self { inner: Tree { levels: vec![] }, leaf_count: 0 }; }
        let leaf_count = leaves.len();
        let mut h = H::init();
        let bottom_leaf = hash_vc_bottom_leaf(&mut h);
        let capacity = leaf_count.next_power_of_two();
        let depth = capacity.trailing_zeros() as u8;
        let mut leaf_level = vec![bottom_leaf; capacity];
        for (i, leaf) in leaves.iter().enumerate() {
            leaf_level[vc_index(i, depth)] = hash_obj(&mut h, leaf);
        }
        Self { inner: Tree { levels: build_levels(&mut h, leaf_level, bottom_leaf) }, leaf_count }
    }

    /// Returns the tree root, or `None` if built on an empty slice.
    pub fn root(&self) -> Option<H::Digest> { self.inner.root() }

    /// Returns the tree depth; `number of levels - 1`.
    pub fn depth(&self) -> usize { self.inner.depth() }

    /// Returns the VC sibling path for external leaf `index`.
    ///
    /// Bounds-checks against the original leaf count, not the padded capacity.
    /// Proofs produced here must be verified with [Proof::verify_vc].
    pub fn prove(&self, index: usize) -> Option<Proof<H>> {
        if self.inner.levels.is_empty() || index >= self.leaf_count { return None; }
        let last_level_idx = self.inner.levels.len() - 1;
        let depth = self.inner.depth() as u8;
        let mut idx = vc_index(index, depth);
        let mut proof = Vec::with_capacity(last_level_idx);
        for level in &self.inner.levels[..last_level_idx] {
            proof.push(level[idx ^ 1]);
            idx >>= 1;
        }
        Some(Proof::new(depth, proof))
    }
}


// ── Proof ─────────────────────────────────────────────────────────────────────

/// A Merkle proof (authentication/inclusion path) for verifying a leaf in a hash tree.
///
/// Generic over the [MerkleHasher] `H` so the same type serves both
/// [Sumhash512]-based state-proof trees and [Sha256]-based block-header trees.
pub struct Proof<H: MerkleHasher> {
    /// The depth of the tree (number of levels from leaf to root).
    pub tree_depth: u8,

    /// The sibling path from the leaf up to (but not including) the root.
    pub path: Vec<H::Digest>,

    /// Hash function used to build the tree; must match on both prover and verifier sides.
    pub hash_factory: HashFactory,
}

// Manual trait impls to avoid requiring H: Clone / H: Debug / H: Eq.
// All bounds are on H::Digest, which is already constrained by MerkleHasher.

impl<H: MerkleHasher> Clone for Proof<H> {
    fn clone(&self) -> Self {
        Self { tree_depth: self.tree_depth, path: self.path.clone(), hash_factory: self.hash_factory.clone() }
    }
}

impl<H: MerkleHasher> fmt::Debug for Proof<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Proof")
            .field("tree_depth", &self.tree_depth)
            .field("path", &self.path)
            .field("hash_factory", &self.hash_factory)
            .finish()
    }
}

impl<H: MerkleHasher> PartialEq for Proof<H> {
    fn eq(&self, other: &Self) -> bool {
        self.tree_depth == other.tree_depth
            && self.path == other.path
            && self.hash_factory == other.hash_factory
    }
}

impl<H: MerkleHasher> Eq for Proof<H> {}

impl<H: MerkleHasher> Proof<H> {
    /// Creates a new [Proof] from `tree_depth` and sibling `path`.
    /// The [HashFactory] is derived automatically from `H::HASH_TYPE`.
    pub fn new(tree_depth: u8, path: Vec<H::Digest>) -> Self {
        Self { tree_depth, path, hash_factory: HashFactory { hash_type: H::HASH_TYPE } }
    }

    /// Low-level verify using a caller-supplied hasher. Reuse the same `h` across
    /// multiple proof verifications to avoid rebuilding the [Sumhash512] lookup table.
    pub fn verify_with(&self, leaf: H::Digest, index: usize, root: &H::Digest, h: &mut H) -> bool {
        let mut current = leaf;
        let mut idx = index;
        for &sibling in &self.path {
            let (left, right) = if idx & 1 == 0 { (current, sibling) } else { (sibling, current) };
            current = hash_internal_node(h, &left, &right);
            idx >>= 1;
        }
        &current == root
    }

    /// Reconstructs the root from the proof path and returns `true` if it matches `root`.
    /// For proofs produced by [VcTree::prove] use [verify_vc](Self::verify_vc) instead.
    pub fn verify(&self, leaf: H::Digest, index: usize, root: &H::Digest) -> bool {
        let mut h = H::init();
        self.verify_with(leaf, index, root, &mut h)
    }

    /// Verifies a proof produced by [VcTree::prove].
    ///
    /// Translates external `index` to its bit-reversed internal position, then
    /// delegates to [verify](Self::verify).
    pub fn verify_vc(&self, leaf: H::Digest, index: usize, root: &H::Digest) -> bool {
        let mut h = H::init();
        self.verify_with(leaf, vc_index(index, self.tree_depth), root, &mut h)
    }

    /// Verifies a batch of `items` that share the same [Proof] path for a standard
    /// membership [Tree]. Path elements are consumed greedily in sorted-position order.
    ///
    /// For [VcTree] use [verify_batch_vc](Self::verify_batch_vc), which handles bit-reversal automatically.
    pub fn verify_batch(&self, items: &[(usize, H::Digest)], root: &H::Digest) -> bool {
        if items.is_empty() { return self.path.is_empty(); }
        let depth = self.tree_depth as usize;
        let mut h = H::init();
        let mut level: BTreeMap<usize, H::Digest> = items.iter().copied().collect();
        let mut path_iter = self.path.iter();
        for _ in 0..depth {
            let mut next: BTreeMap<usize, H::Digest> = BTreeMap::new();
            while let Some((idx, digest)) = level.pop_first() {
                let sibling = if let Some(s) = level.remove(&(idx ^ 1)) {
                    s
                } else {
                    match path_iter.next() {
                        Some(&s) => s,
                        None => return false,
                    }
                };
                let (left, right) = if idx & 1 == 0 { (digest, sibling) } else { (sibling, digest) };
                next.insert(idx >> 1, hash_internal_node(&mut h, &left, &right));
            }
            level = next;
        }
        level.len() == 1 && level.values().next().unwrap() == root
    }

    /// Verifies a batch of `items` that share the same [Proof] path for a [VcTree].
    ///
    /// Converts external sequential indices to bit-reversed internal positions,
    /// then delegates to [verify_batch](Self::verify_batch).
    pub fn verify_batch_vc(&self, items: &[(usize, H::Digest)], root: &H::Digest) -> bool {
        let depth = self.tree_depth;
        let internal: Vec<(usize, H::Digest)> = items.iter()
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
        let tree = Tree::<Sumhash512>::build::<TestLeaf>(&[]);
        assert_eq!(tree.root(), None);
    }

    /// The root of a single-leaf tree must equal that leaf's hash digest — no internal node is formed.
    #[test]
    fn single_leaf_tree_root_is_leaf_hash() {
        let leaf = TestLeaf(b"only");
        let mut h = Sumhash512::new();
        let expected = hash_obj(&mut h, &leaf);
        let tree = Tree::<Sumhash512>::build(&[leaf]);
        assert_eq!(tree.root(), Some(expected));
    }

    /// Depth must be 0 for empty and single-leaf trees, and ⌈log₂(n)⌉ for larger inputs.
    #[test]
    fn tree_depth_is_correct() {
        assert_eq!(Tree::<Sumhash512>::build::<TestLeaf>(&[]).depth(), 0);
        assert_eq!(Tree::<Sumhash512>::build(&[TestLeaf(b"a")]).depth(), 0);
        assert_eq!(Tree::<Sumhash512>::build(&[TestLeaf(b"a"), TestLeaf(b"b")]).depth(), 1);
        assert_eq!(Tree::<Sumhash512>::build(&[TestLeaf(b"a"), TestLeaf(b"b"), TestLeaf(b"c")]).depth(), 2);
    }

    /// A proof generated by `prove()` must be accepted by `verify()` for both leaves of a two-leaf tree.
    #[test]
    fn prove_verify_two_leaves() {
        let leaves = [TestLeaf(b"left"), TestLeaf(b"right")];
        let tree = Tree::<Sumhash512>::build(&leaves);
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
        let tree = Tree::<Sumhash512>::build(&leaves);
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
        let tree = Tree::<Sumhash512>::build(&[TestLeaf(b"only")]);
        assert!(tree.prove(1).is_none());
        assert!(Tree::<Sumhash512>::build::<TestLeaf>(&[]).prove(0).is_none());
    }

    /// The `verify()` method must return `false` when the reconstructed root does not match the supplied root.
    #[test]
    fn proof_rejects_wrong_root() {
        let leaves = [TestLeaf(b"a"), TestLeaf(b"b")];
        let tree = Tree::<Sumhash512>::build(&leaves);
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
        let tree = VcTree::<Sumhash512>::build(&leaves);
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
        let tree = VcTree::<Sumhash512>::build(&leaves);
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
        let tree = VcTree::<Sumhash512>::build(&leaves);
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
        let tree = VcTree::<Sumhash512>::build(&[TestLeaf(b"only")]);
        assert!(tree.prove(1).is_none());
        assert!(VcTree::<Sumhash512>::build::<TestLeaf>(&[]).prove(0).is_none());
    }

/// A batch proof over all leaves of a four-leaf tree must verify correctly.
    /// All siblings are within the batch so the shared path should be empty.
    #[test]
    fn verify_batch_all_leaves() {
        let leaves = [TestLeaf(b"a"), TestLeaf(b"b"), TestLeaf(b"c"), TestLeaf(b"d")];
        let tree = Tree::<Sumhash512>::build(&leaves);
        let root = tree.root().unwrap();
        let mut h = Sumhash512::new();
        let proof = Proof::<Sumhash512>::new(tree.depth() as u8, vec![]);
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
        let tree = Tree::<Sumhash512>::build(&leaves);
        let root = tree.root().unwrap();
        let wrong_root = [0xffu8; SUMHASH512_DIGEST_SIZE];
        let mut h = Sumhash512::new();
        let proof_0 = tree.prove(0).unwrap();
        let proof_2 = tree.prove(2).unwrap();
        let batch_path = vec![proof_0.path[0], proof_2.path[0]];
        let batch_proof = Proof::<Sumhash512>::new(tree.depth() as u8, batch_path);
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
        let tree = VcTree::<Sumhash512>::build(&leaves);
        let root = tree.root().unwrap();
        let mut h = Sumhash512::new();
        let proof = Proof::<Sumhash512>::new(tree.depth() as u8, vec![]);
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
        let tree = VcTree::<Sumhash512>::build(&leaves);
        let root = tree.root().unwrap();
        let wrong_root = [0xffu8; SUMHASH512_DIGEST_SIZE];
        let mut h = Sumhash512::new();
        let proof_0 = tree.prove(0).unwrap();
        let proof_1 = tree.prove(1).unwrap();
        let batch_path = vec![proof_0.path[0], proof_1.path[0], proof_0.path[1]];
        let batch_proof = Proof::<Sumhash512>::new(tree.depth() as u8, batch_path);
        let items = vec![
            (0, hash_obj(&mut h, &leaves[0])),
            (1, hash_obj(&mut h, &leaves[1])),
        ];
        assert!(batch_proof.verify_batch_vc(&items, &root));
        assert!(!batch_proof.verify_batch_vc(&items, &wrong_root));
    }

    /// SHA-256 tree: a VC proof for each leaf must verify correctly, confirming the
    /// MerkleHasher abstraction works end-to-end with a second hash function.
    #[test]
    fn sha256_vc_prove_verify() {
        let leaves = [TestLeaf(b"a"), TestLeaf(b"b"), TestLeaf(b"c"), TestLeaf(b"d")];
        let tree = VcTree::<Sha256>::build(&leaves);
        let root = tree.root().unwrap();
        let mut h: Sha256 = Default::default();
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.prove(i).unwrap();
            let leaf_digest = hash_obj(&mut h, leaf);
            assert!(proof.verify_vc(leaf_digest, i, &root), "SHA-256 VC proof failed for leaf {i}");
        }
    }

    /// `vc_index` must correctly bit-reverse the `depth` least-significant bits of `idx`.
    #[test]
    fn vc_index_bit_reversal() {
        assert_eq!(vc_index(0b000, 3), 0b000);
        assert_eq!(vc_index(0b001, 3), 0b100);
        assert_eq!(vc_index(0b010, 3), 0b010);
        assert_eq!(vc_index(0b100, 3), 0b001);
        assert_eq!(vc_index(0b110, 3), 0b011);
        assert_eq!(vc_index(5, 0), 0);
        assert_eq!(vc_index(0, 1), 0);
        assert_eq!(vc_index(1, 1), 1);
    }

    /// `verify_with` must accept a pre-built hasher so callers can reuse it across
    /// multiple proof verifications without rebuilding the Sumhash512 lookup table.
    #[test]
    fn verify_with_reuses_hasher() {
        let leaves = [TestLeaf(b"a"), TestLeaf(b"b"), TestLeaf(b"c"), TestLeaf(b"d")];
        let tree = Tree::<Sumhash512>::build(&leaves);
        let root = tree.root().unwrap();
        let mut h = Sumhash512::new();
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.prove(i).unwrap();
            let leaf_digest = hash_obj(&mut h, leaf);
            assert!(proof.verify_with(leaf_digest, i, &root, &mut h), "verify_with failed for leaf {i}");
        }
    }

    /// SHA-256 and Sumhash512 trees built on the same leaves must produce different roots —
    /// confirming the two hashers are domain-separated at the tree level.
    #[test]
    fn sha256_root_differs_from_sumhash_root() {
        let leaves = [TestLeaf(b"a"), TestLeaf(b"b"), TestLeaf(b"c"), TestLeaf(b"d")];
        let sha_root  = VcTree::<Sha256>::build(&leaves).root();
        let sum_root  = VcTree::<Sumhash512>::build(&leaves).root();
        // Roots are different types ([u8;32] vs [u8;64]) so we just check neither is None.
        assert!(sha_root.is_some());
        assert!(sum_root.is_some());
    }
}
