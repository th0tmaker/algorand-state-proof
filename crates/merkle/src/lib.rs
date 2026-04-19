// crates/merkle/src/lib.rs

pub use sumhash::{Digest, DIGEST_SIZE};
use sumhash::Sumhash512;

// ── Domain prefixes ───────────────────────────────────────────────────────────
// Prefixes match Algorand's protocol package (protocol.HashID).

const MERKLE_ARRAY_NODE:    &[u8] = b"MA";
const MERKLE_VC_BOTTOM_LEAF: &[u8] = b"MB";

// ── Hashable ──────────────────────────────────────────────────────────────────

/// An object that can be cryptographically hashed into a tree leaf.
/// The domain prefix prevents cross-type collisions.
pub trait Hashable {
    fn to_be_hashed(&self) -> (&'static [u8], Vec<u8>);
}

// ── Helpers ───────────────────────────────────────────────────────────────────

#[inline]
fn finish(h: &mut Sumhash512) -> Digest {
    let mut out = [0u8; DIGEST_SIZE];
    h.finalize(&mut out);
    out
}

pub(crate) fn hash_obj(h: &mut Sumhash512, obj: &dyn Hashable) -> Digest {
    h.reset();
    let (domain, data) = obj.to_be_hashed();
    h.update(domain);
    h.update(&data);
    finish(h)
}

pub(crate) fn hash_internal_node(h: &mut Sumhash512, left: &Digest, right: &Digest) -> Digest {
    h.reset();
    h.update(MERKLE_ARRAY_NODE);
    h.update(left);
    h.update(right);
    finish(h)
}

fn hash_vc_bottom_leaf(h: &mut Sumhash512) -> Digest {
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

fn build_levels(h: &mut Sumhash512, leaf_level: Vec<Digest>, pad: Digest) -> Vec<Vec<Digest>> {
    let mut levels = vec![leaf_level];
    while levels.last().unwrap().len() > 1 {
        let current = levels.last().unwrap();
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        for chunk in current.chunks(2) {
            let right = chunk.get(1).copied().unwrap_or(pad);
            next.push(hash_internal_node(h, &chunk[0], &right));
        }
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
    pub(crate) levels: Vec<Vec<Digest>>,
}

impl Tree {
    /// Builds a [`Tree`] from a slice of [`Hashable`] leaves.
    pub fn build<T: Hashable>(leaves: &[T]) -> Self {
        if leaves.is_empty() { return Self { levels: vec![] }; }
        let mut h = Sumhash512::new();
        let leaf_level = leaves.iter().map(|l| hash_obj(&mut h, l)).collect();
        Self { levels: build_levels(&mut h, leaf_level, [0u8; DIGEST_SIZE]) }
    }

    /// Returns the root [`Digest`], or `None` if built on an empty slice.
    pub fn root(&self) -> Option<Digest> {
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
            let sibling = if idx ^ 1 < level.len() { level[idx ^ 1] } else { [0u8; DIGEST_SIZE] };
            proof.push(sibling);
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
        if leaves.is_empty() { return Self { tree: Tree { levels: vec![] }, leaf_count: 0 }; }
        let mut h = Sumhash512::new();
        let bottom_leaf = hash_vc_bottom_leaf(&mut h);
        let capacity = leaf_count.next_power_of_two();
        let depth = capacity.trailing_zeros() as u8;
        let mut leaf_level = vec![bottom_leaf; capacity];
        for (i, leaf) in leaves.iter().enumerate() {
            leaf_level[vc_index(i, depth)] = hash_obj(&mut h, leaf);
        }
        Self { tree: Tree { levels: build_levels(&mut h, leaf_level, bottom_leaf) }, leaf_count }
    }

    /// Returns the root [`Digest`], or `None` if built on an empty slice.
    pub fn root(&self) -> Option<Digest> { self.tree.root() }

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
        let mut idx = vc_index(index, depth);
        let mut proof = Vec::with_capacity(self.tree.levels.len() - 1);
        for level in &self.tree.levels[..self.tree.levels.len() - 1] {
            proof.push(level[idx ^ 1]);
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
    Sha256     = 2,
    Sha512     = 3,
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
    pub hash_type: HashType, // codec key: "t"
}

impl HashFactory {
    /// Returns a [`HashFactory`] for [`Sumhash512`], the default for Algorand state proofs.
    pub fn sumhash512() -> Self {
        Self { hash_type: HashType::Sumhash512 }
    }
}

// ── Proof ─────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proof {
    pub tree_depth:   u8,
    pub path:         Vec<Digest>,
    pub hash_factory: HashFactory,
}

impl Proof {
    /// Creates a new proof from a tree depth and sibling path.
    pub fn new(tree_depth: u8, path: Vec<Digest>) -> Self {
        Self { tree_depth, path, hash_factory: HashFactory::sumhash512() }
    }

    /// Reconstructs the root from the proof path and returns `true` if it matches `root`.
    /// For proofs produced by [`VcTree::prove`] use [`verify_vc`](Self::verify_vc) instead.
    pub fn verify(&self, leaf: Digest, index: usize, root: &Digest) -> bool {
        let mut h = Sumhash512::new();
        let mut current = leaf;
        let mut idx = index;
        for &sibling in &self.path {
            let (left, right) = if idx & 1 == 0 { (current, sibling) } else { (sibling, current) };
            current = hash_internal_node(&mut h, &left, &right);
            idx >>= 1;
        }
        &current == root
    }

    /// Verifies a proof produced by [`VcTree::prove`].
    ///
    /// Translates external `index` to its bit-reversed internal position, then
    /// delegates to [`verify`](Self::verify).
    pub fn verify_vc(&self, leaf: Digest, index: usize, root: &Digest) -> bool {
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

    #[test]
    fn hash_obj_is_deterministic() {
        let mut h = Sumhash512::new();
        let a = hash_obj(&mut h, &TestLeaf(b"hello"));
        let b = hash_obj(&mut h, &TestLeaf(b"hello"));
        assert_eq!(a, b);
    }

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

    #[test]
    fn empty_tree_has_no_root() {
        let tree = Tree::build::<TestLeaf>(&[]);
        assert_eq!(tree.root(), None);
    }

    #[test]
    fn single_leaf_tree_root_is_leaf_hash() {
        let leaf = TestLeaf(b"only");
        let mut h = Sumhash512::new();
        let expected = hash_obj(&mut h, &leaf);
        let tree = Tree::build(&[leaf]);
        assert_eq!(tree.root(), Some(expected));
    }

    #[test]
    fn tree_depth_is_correct() {
        assert_eq!(Tree::build::<TestLeaf>(&[]).depth(), 0);
        assert_eq!(Tree::build(&[TestLeaf(b"a")]).depth(), 0);
        assert_eq!(Tree::build(&[TestLeaf(b"a"), TestLeaf(b"b")]).depth(), 1);
        assert_eq!(Tree::build(&[TestLeaf(b"a"), TestLeaf(b"b"), TestLeaf(b"c")]).depth(), 2);
    }

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

    #[test]
    fn prove_out_of_bounds_returns_none() {
        let tree = Tree::build(&[TestLeaf(b"only")]);
        assert!(tree.prove(1).is_none());
        assert!(Tree::build::<TestLeaf>(&[]).prove(0).is_none());
    }

    #[test]
    fn proof_rejects_wrong_root() {
        let leaves = [TestLeaf(b"a"), TestLeaf(b"b")];
        let tree = Tree::build(&leaves);
        let wrong_root = [0xffu8; DIGEST_SIZE];
        let mut h = Sumhash512::new();
        let proof = tree.prove(0).unwrap();
        let leaf_digest = hash_obj(&mut h, &leaves[0]);
        assert!(!proof.verify(leaf_digest, 0, &wrong_root));
    }

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

    #[test]
    fn vc_proof_rejects_wrong_root() {
        let leaves = [TestLeaf(b"a"), TestLeaf(b"b")];
        let tree = VcTree::build(&leaves);
        let wrong_root = [0xffu8; DIGEST_SIZE];
        let mut h = Sumhash512::new();
        let proof = tree.prove(0).unwrap();
        let leaf_digest = hash_obj(&mut h, &leaves[0]);
        assert!(!proof.verify_vc(leaf_digest, 0, &wrong_root));
    }

    #[test]
    fn vc_out_of_bounds_returns_none() {
        let tree = VcTree::build(&[TestLeaf(b"only")]);
        assert!(tree.prove(1).is_none());
        assert!(VcTree::build::<TestLeaf>(&[]).prove(0).is_none());
    }
}
