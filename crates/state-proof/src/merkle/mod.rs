// crates/state-proof/src/merkle/mod.rs

use crate::{
    codec::{DecodeError, AlgorandMessagePack, MsgPackDecode, MsgPackEncode, Reader},
    constants::SUMHASH512_DIGEST_SIZE,
    Digest, Sumhash512,
};

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
    /// Returns `(domain, data)` to be hashed.
    /// The domain prefix prevents collisions between different object types.
    fn to_be_hashed(&self) -> (&'static [u8], Vec<u8>);
}

// ── Helpers ───────────────────────────────────────────────────────────────────

#[inline]
fn finish(h: &mut Sumhash512) -> Digest {
    let mut out = [0u8; SUMHASH512_DIGEST_SIZE];
    h.finalize(&mut out);
    out
}

/// Computes `Hash(domain || data)` for `obj`, reusing `h` without rebuilding its lookup table.
#[allow(unused)]
pub(crate) fn hash_obj(h: &mut Sumhash512, obj: &dyn Hashable) -> Digest {
    h.reset();
    let (domain, data) = obj.to_be_hashed();
    h.update(domain);
    h.update(&data);
    finish(h)
}

/// Computes `Hash("MA" || left || right)` for an internal tree node.
#[allow(unused)]
pub(crate) fn hash_internal_node(h: &mut Sumhash512, left: &Digest, right: &Digest) -> Digest {
    h.reset();
    h.update(MERKLE_ARRAY_NODE);
    h.update(left);
    h.update(right);
    finish(h)
}

// ── Vector Commitment helpers ─────────────────────────────────────────────────

/// Computes `Hash("MB")` — the canonical empty-padding digest for Vector Commitment trees.
fn hash_vc_bottom_leaf(h: &mut Sumhash512) -> Digest {
    h.reset();
    h.update(MERKLE_VC_BOTTOM_LEAF);
    finish(h)
}

/// Reverses the `depth` least-significant bits of `idx`.
///
/// Algorand Vector Commitments address leaves by bit-reversed index so that
/// sequential external indices map to well-separated internal tree positions.
fn vc_index(idx: usize, depth: u8) -> usize {
    if depth == 0 { 0 } else { idx.reverse_bits() >> (usize::BITS - depth as u32) }
}

// ── Tree internals ────────────────────────────────────────────────────────────

/// Builds the level-by-level structure from an already-prepared leaf level.
///
/// Odd-width levels are padded on the right with `pad`. Pass `[0u8; N]` for
/// standard trees, `hash_vc_bottom_leaf` for VC trees (though VC leaf levels
/// are always power-of-two wide so `pad` is never reached there).
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
/// For Vector Commitment trees use [`VcTree`], which enforces the correct
/// prove/verify pairing at the type level.
#[allow(unused)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Tree {
    levels: Vec<Vec<Digest>>,
}

impl Tree {
    /// Builds a [`Tree`] from a slice of [`Hashable`] leaves.
    #[allow(unused)]
    pub fn build<T: Hashable>(leaves: &[T]) -> Self {
        if leaves.is_empty() { return Self { levels: vec![] }; }
        let mut h = Sumhash512::new();
        let leaf_level = leaves.iter().map(|l| hash_obj(&mut h, l)).collect();
        Self { levels: build_levels(&mut h, leaf_level, [0u8; SUMHASH512_DIGEST_SIZE]) }
    }

    /// Returns the root [`Digest`], or `None` if the tree was built on an empty slice.
    #[allow(unused)]
    pub fn root(&self) -> Option<Digest> {
        self.levels.last().map(|top| top[0])
    }

    /// Returns the depth (number of levels - 1), or `0` for an empty or single-leaf tree.
    #[allow(unused)]
    pub fn depth(&self) -> usize {
        self.levels.len().saturating_sub(1)
    }

    /// Returns the sibling path from leaf `index` up to (but not including) the root.
    ///
    /// Each entry is the sibling digest needed to recompute the parent at that level.
    /// Returns `None` if the tree is empty or `index` is out of bounds.
    #[allow(unused)]
    pub fn prove(&self, index: usize) -> Option<Proof> {
        if self.levels.is_empty() || index >= self.levels[0].len() {
            return None;
        }
        let mut proof = Vec::with_capacity(self.levels.len() - 1);
        let mut idx = index;
        for level in &self.levels[..self.levels.len() - 1] {
            let sibling = if idx ^ 1 < level.len() { level[idx ^ 1] } else { [0u8; SUMHASH512_DIGEST_SIZE] };
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
#[allow(unused)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VcTree {
    tree: Tree,
    leaf_count: usize,
}

impl VcTree {
    /// Builds a [`VcTree`] from a slice of [`Hashable`] leaves.
    #[allow(unused)]
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

    /// Returns the root [`Digest`], or `None` if the tree was built on an empty slice.
    #[allow(unused)]
    pub fn root(&self) -> Option<Digest> { self.tree.root() }

    /// Returns the depth (number of levels - 1), or `0` for an empty or single-leaf tree.
    #[allow(unused)]
    pub fn depth(&self) -> usize { self.tree.depth() }

    /// Returns the VC sibling path for external leaf `index`.
    ///
    /// Bounds-checks against the original leaf count, not the padded capacity —
    /// indices into padding slots return `None`. Proofs produced here must be
    /// verified with [`Proof::verify_vc`].
    #[allow(unused)]
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

// ── HashFactory ───────────────────────────────────────────────────────────────

/// Numeric hash type identifiers consistent across Algorand's State Proof implementations.
#[allow(unused)]
#[repr(u64)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HashType {
    Sha512_256 = 0,
    Sumhash    = 1,
    Sha256     = 2,
    Sha512     = 3,
}

impl TryFrom<u64> for HashType {
    type Error = u64;

    fn try_from(v: u64) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(Self::Sha512_256),
            1 => Ok(Self::Sumhash),
            2 => Ok(Self::Sha256),
            3 => Ok(Self::Sha512),
            _ => Err(v),
        }
    }
}

impl MsgPackDecode for HashType {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        HashType::try_from(r.read_uint()?).map_err(DecodeError::InvalidHashType)
    }
}

/// Identifies which hash function was used to build the tree. Codec key: `"hsh"`.
#[allow(unused)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HashFactory {
    /// Codec key: `"t"`.
    pub hash_type: HashType,
}

impl HashFactory {
    /// Returns a [`HashFactory`] for [`Sumhash512`], the default for Algorand state proofs.
    pub fn sumhash() -> Self {
        Self { hash_type: HashType::Sumhash }
    }
}

impl MsgPackEncode for HashFactory {
    fn to_msgpack(&self) -> AlgorandMessagePack {
        AlgorandMessagePack::new().uint("t", self.hash_type as u64)
    }
}

impl MsgPackDecode for HashFactory {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let n = r.read_map_len()?;
        let mut hash_type = HashType::Sha512_256;
        for _ in 0..n {
            match r.read_str()? {
                "t" => hash_type = HashType::decode(r)?,
                _   => r.skip()?,
            }
        }
        Ok(Self { hash_type })
    }
}

// ── Proof ─────────────────────────────────────────────────────────────────────

#[allow(unused)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proof {
    pub tree_depth: u8,
    pub path: Vec<Digest>,
    pub hash_factory: HashFactory,
}

impl Proof {
    /// Creates a new instance from a tree depth and sibling path.
    #[allow(unused)]
    pub fn new(tree_depth: u8, path: Vec<Digest>) -> Self {
        Self { tree_depth, path, hash_factory: HashFactory::sumhash() }
    }

    /// Reconstructs the root from the proof path and returns `true` if it matches `root`.
    /// For proofs produced by [`VcTree::prove`] use [`verify_vc`] instead.
    #[allow(unused)]
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
    /// delegates to [`verify`].
    #[allow(unused)]
    pub fn verify_vc(&self, leaf: Digest, index: usize, root: &Digest) -> bool {
        self.verify(leaf, vc_index(index, self.tree_depth), root)
    }
}

impl MsgPackEncode for Proof {
    fn to_msgpack(&self) -> AlgorandMessagePack {
        AlgorandMessagePack::new()
            .map("hsh", self.hash_factory.to_msgpack())
            .bytes_array("pth", &self.path)
            .uint("td", self.tree_depth as u64)
    }
}

impl MsgPackDecode for Proof {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let n = r.read_map_len()?;
        let mut tree_depth: u8 = 0;
        let mut path: Vec<Digest> = Vec::new();
        let mut hash_factory = HashFactory::sumhash();
        for _ in 0..n {
            match r.read_str()? {
                "td"  => tree_depth = r.read_uint()? as u8,
                "pth" => {
                    let len = r.read_array_len()?;
                    path = Vec::with_capacity(len);
                    for _ in 0..len {
                        let bytes = r.read_bin()?;
                        if bytes.len() != SUMHASH512_DIGEST_SIZE {
                            return Err(DecodeError::InvalidDigestSize(bytes.len()));
                        }
                        let mut digest = [0u8; SUMHASH512_DIGEST_SIZE];
                        digest.copy_from_slice(bytes);
                        path.push(digest);
                    }
                }
                "hsh" => hash_factory = HashFactory::decode(r)?,
                _     => r.skip()?,
            }
        }
        Ok(Self { tree_depth, path, hash_factory })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::from_msgpack;

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

    #[test]
    fn empty_tree_has_no_root() {
        assert!(Tree::build::<TestLeaf>(&[]).root().is_none());
    }

    #[test]
    fn single_leaf_root_equals_leaf_hash() {
        let leaves = [TestLeaf(b"only")];
        let tree = Tree::build(&leaves);
        let mut h = Sumhash512::new();
        assert_eq!(tree.root(), Some(hash_obj(&mut h, &TestLeaf(b"only"))));
    }

    #[test]
    fn two_leaves_root_equals_manual_hash() {
        let leaves = [TestLeaf(b"left"), TestLeaf(b"right")];
        let tree = Tree::build(&leaves);
        let mut h = Sumhash512::new();
        let left = hash_obj(&mut h, &TestLeaf(b"left"));
        let right = hash_obj(&mut h, &TestLeaf(b"right"));
        assert_eq!(tree.root(), Some(hash_internal_node(&mut h, &left, &right)));
    }

    #[test]
    fn root_is_deterministic() {
        let leaves = [TestLeaf(b"a"), TestLeaf(b"b"), TestLeaf(b"c")];
        assert_eq!(Tree::build(&leaves).root(), Tree::build(&leaves).root());
    }

    #[test]
    fn different_leaves_produce_different_roots() {
        assert_ne!(
            Tree::build(&[TestLeaf(b"foo"), TestLeaf(b"bar")]).root(),
            Tree::build(&[TestLeaf(b"foo"), TestLeaf(b"baz")]).root()
        );
    }

    #[test]
    fn depth_empty_tree_is_zero() {
        assert_eq!(Tree::build::<TestLeaf>(&[]).depth(), 0);
    }

    #[test]
    fn depth_single_leaf_is_zero() {
        assert_eq!(Tree::build(&[TestLeaf(b"a")]).depth(), 0);
    }

    #[test]
    fn depth_four_leaves_is_two() {
        let leaves = [TestLeaf(b"a"), TestLeaf(b"b"), TestLeaf(b"c"), TestLeaf(b"d")];
        assert_eq!(Tree::build(&leaves).depth(), 2);
    }

    #[test]
    fn prove_empty_tree_returns_none() {
        assert!(Tree::build::<TestLeaf>(&[]).prove(0).is_none());
    }

    #[test]
    fn prove_out_of_bounds_returns_none() {
        assert!(Tree::build(&[TestLeaf(b"a"), TestLeaf(b"b")]).prove(2).is_none());
    }

    #[test]
    fn prove_single_leaf_proof_is_empty() {
        let proof = Tree::build(&[TestLeaf(b"only")]).prove(0).unwrap();
        assert!(proof.path.is_empty());
        assert_eq!(proof.tree_depth, 0);
    }

    #[test]
    fn prove_two_leaves_sibling_is_other_leaf() {
        let leaves = [TestLeaf(b"left"), TestLeaf(b"right")];
        let tree = Tree::build(&leaves);
        let mut h = Sumhash512::new();
        let left_digest = hash_obj(&mut h, &TestLeaf(b"left"));
        let right_digest = hash_obj(&mut h, &TestLeaf(b"right"));

        let proof_left = tree.prove(0).unwrap();
        assert_eq!(proof_left.path.len(), 1);
        assert_eq!(proof_left.path[0], right_digest);

        let proof_right = tree.prove(1).unwrap();
        assert_eq!(proof_right.path.len(), 1);
        assert_eq!(proof_right.path[0], left_digest);
    }

    #[test]
    fn prove_odd_last_leaf_sibling_is_zero() {
        let proof = Tree::build(&[TestLeaf(b"a"), TestLeaf(b"b"), TestLeaf(b"c")]).prove(2).unwrap();
        assert_eq!(proof.path[0], [0u8; SUMHASH512_DIGEST_SIZE]);
    }

    #[test]
    fn verify_four_leaves() {
        let leaves = [TestLeaf(b"a"), TestLeaf(b"b"), TestLeaf(b"c"), TestLeaf(b"d")];
        let tree = Tree::build(&leaves);
        let root = tree.root().unwrap();
        let mut h = Sumhash512::new();
        for (i, leaf) in leaves.iter().enumerate() {
            assert!(tree.prove(i).unwrap().verify(hash_obj(&mut h, leaf), i, &root));
        }
    }

    #[test]
    fn verify_five_leaves() {
        let leaves = [TestLeaf(b"a"), TestLeaf(b"b"), TestLeaf(b"c"), TestLeaf(b"d"), TestLeaf(b"e")];
        let tree = Tree::build(&leaves);
        let root = tree.root().unwrap();
        let mut h = Sumhash512::new();
        for (i, leaf) in leaves.iter().enumerate() {
            assert!(tree.prove(i).unwrap().verify(hash_obj(&mut h, leaf), i, &root));
        }
    }

    #[test]
    fn verify_rejects_wrong_leaf() {
        let leaves = [TestLeaf(b"a"), TestLeaf(b"b"), TestLeaf(b"c"), TestLeaf(b"d")];
        let tree = Tree::build(&leaves);
        let root = tree.root().unwrap();
        let mut h = Sumhash512::new();
        assert!(!tree.prove(0).unwrap().verify(hash_obj(&mut h, &TestLeaf(b"x")), 0, &root));
    }

    // ── Vector Commitment tests ───────────────────────────────────────────────

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

    /// VC round-trip for a balanced (power-of-two) tree — every leaf must verify.
    #[test]
    fn vc_prove_verify_four_leaves() {
        let leaves = [TestLeaf(b"a"), TestLeaf(b"b"), TestLeaf(b"c"), TestLeaf(b"d")];
        let tree = VcTree::build(&leaves);
        let root = tree.root().unwrap();
        let mut h = Sumhash512::new();
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.prove(i).unwrap();
            assert!(proof.verify_vc(hash_obj(&mut h, leaf), i, &root), "leaf {i} failed");
        }
    }

    /// VC round-trip for an odd-length tree — the last leaf is padded with Hash("MB").
    #[test]
    fn vc_prove_verify_five_leaves() {
        let leaves = [TestLeaf(b"a"), TestLeaf(b"b"), TestLeaf(b"c"), TestLeaf(b"d"), TestLeaf(b"e")];
        let tree = VcTree::build(&leaves);
        let root = tree.root().unwrap();
        let mut h = Sumhash512::new();
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.prove(i).unwrap();
            assert!(proof.verify_vc(hash_obj(&mut h, leaf), i, &root), "leaf {i} failed");
        }
    }

    /// Indices into padding slots must return None, even though they are within
    /// the padded capacity of the underlying tree.
    #[test]
    fn vc_prove_rejects_padding_index() {
        let leaves = [TestLeaf(b"a"), TestLeaf(b"b"), TestLeaf(b"c")]; // capacity = 4
        let tree = VcTree::build(&leaves);
        assert!(tree.prove(3).is_none()); // padding slot — must be None
        assert!(tree.prove(4).is_none()); // fully out of range
    }

    /// A standard Merkle root and a VC root must differ for the same leaves.
    #[test]
    fn vc_root_differs_from_standard_root() {
        let leaves = [TestLeaf(b"a"), TestLeaf(b"b"), TestLeaf(b"c")];
        assert_ne!(Tree::build(&leaves).root(), VcTree::build(&leaves).root());
    }

    /// A VC proof must be rejected when verified against the wrong (standard) root.
    #[test]
    fn vc_proof_rejects_wrong_root() {
        let leaves = [TestLeaf(b"a"), TestLeaf(b"b"), TestLeaf(b"c"), TestLeaf(b"d")];
        let vc_tree = VcTree::build(&leaves);
        let std_root = Tree::build(&leaves).root().unwrap();
        let mut h = Sumhash512::new();
        let proof = vc_tree.prove(0).unwrap();
        assert!(!proof.verify_vc(hash_obj(&mut h, &leaves[0]), 0, &std_root));
    }

    // ── KAT: golden bytes from algosdk.encoding.msgpack_encode ───────────────

    /// KAT using golden MsgPack bytes produced by Python algosdk.encoding.msgpack_encode.
    ///
    /// Proof: TreeDepth=5, HashType=1 (Sumhash), 12-entry path from
    /// go-stateproof-verification stateProof.json SigProofs field.
    ///
    /// Verifies: decode recovers correct fields, re-encode is byte-for-byte identical.
    #[test]
    fn kat_proof_golden_bytes() {
        const GOLDEN: &str = concat!(
            "83a368736881a17401a37074689c",
            "c440c1a359d33a5e28720f7117a296ceb19d5c5828f98c61743d43c5cc7f9b9d",
            "8763195029b14f80ee4bacde8c7d082a4b0c8b26605dfc8abfa0613d666c599d7f02",
            "c4403dad11bd629e0c4b8504e644517b3030247abf063cbecb0c0f82f5616c5a2b3b",
            "6ed2ab121c8f8e1bf27125f0954be647329cbda0177a9850512c56f8b2ee86f3",
            "c440c1a359d33a5e28720f7117a296ceb19d5c5828f98c61743d43c5cc7f9b9d",
            "8763195029b14f80ee4bacde8c7d082a4b0c8b26605dfc8abfa0613d666c599d7f02",
            "c440c1a359d33a5e28720f7117a296ceb19d5c5828f98c61743d43c5cc7f9b9d",
            "8763195029b14f80ee4bacde8c7d082a4b0c8b26605dfc8abfa0613d666c599d7f02",
            "c440c1a359d33a5e28720f7117a296ceb19d5c5828f98c61743d43c5cc7f9b9d",
            "8763195029b14f80ee4bacde8c7d082a4b0c8b26605dfc8abfa0613d666c599d7f02",
            "c440c1a359d33a5e28720f7117a296ceb19d5c5828f98c61743d43c5cc7f9b9d",
            "8763195029b14f80ee4bacde8c7d082a4b0c8b26605dfc8abfa0613d666c599d7f02",
            "c440c1a359d33a5e28720f7117a296ceb19d5c5828f98c61743d43c5cc7f9b9d",
            "8763195029b14f80ee4bacde8c7d082a4b0c8b26605dfc8abfa0613d666c599d7f02",
            "c440c1a359d33a5e28720f7117a296ceb19d5c5828f98c61743d43c5cc7f9b9d",
            "8763195029b14f80ee4bacde8c7d082a4b0c8b26605dfc8abfa0613d666c599d7f02",
            "c440c1a359d33a5e28720f7117a296ceb19d5c5828f98c61743d43c5cc7f9b9d",
            "8763195029b14f80ee4bacde8c7d082a4b0c8b26605dfc8abfa0613d666c599d7f02",
            "c440c1a359d33a5e28720f7117a296ceb19d5c5828f98c61743d43c5cc7f9b9d",
            "8763195029b14f80ee4bacde8c7d082a4b0c8b26605dfc8abfa0613d666c599d7f02",
            "c440c1a359d33a5e28720f7117a296ceb19d5c5828f98c61743d43c5cc7f9b9d",
            "8763195029b14f80ee4bacde8c7d082a4b0c8b26605dfc8abfa0613d666c599d7f02",
            "c440c1a359d33a5e28720f7117a296ceb19d5c5828f98c61743d43c5cc7f9b9d",
            "8763195029b14f80ee4bacde8c7d082a4b0c8b26605dfc8abfa0613d666c599d7f02",
            "a2746405"
        );

        let golden: Vec<u8> = (0..GOLDEN.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&GOLDEN[i..i + 2], 16).unwrap())
            .collect();

        let proof: Proof = from_msgpack(&golden).unwrap();

        assert_eq!(proof.tree_depth, 5);
        assert_eq!(proof.hash_factory, HashFactory::sumhash());
        assert_eq!(proof.path.len(), 12);
        assert_eq!(proof.encode(), golden);
    }
}
