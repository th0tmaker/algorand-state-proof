// crates/state-proof/src/stateproof/commitment.rs

use merkle::{hash_obj, Hashable, MerkleHasher, Proof, Sha256, SHA256_DIGEST_SIZE};

use crate::codec::{AlgorandMessagePack, DecodeError, MsgPackDecode, Reader};
use super::constants::DOMAIN_BLOCK_HEADER;

/// One leaf of the `block_headers_commitment` SHA-256 [merkle::VcTree].
///
/// The `VcTree` covers the 256 blocks in the attested interval; its root equals
/// `StateProofMessage::block_headers_commitment`. Decode from the algod
/// `GET /v2/blocks/{round}/lightheader` response, then call
/// `verify_block_header_commitment` with the proof from
/// `GET /v2/blocks/{round}/lightheader/proof`.
///
/// Codec keys: `"0"`, `"1"`, `"gh"`, `"r"`, `"tc"`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LightBlockHeader {
    /// `SHA-512/256` block seed. When seed period `p = 0` the proposer runs VRF and the
    /// output is hashed with `SHA-512/256`; when `p ≠ 0` the previous seed is re-hashed
    /// directly with `SHA-512/256`. Codec key: `"0"`.
    pub seed: [u8; 32],
    /// `SHA-512/256` hash of the full block (the primary Algorand block hash). Codec key: `"1"`.
    pub block_hash: [u8; 32],
    /// `SHA-512/256` hash of the genesis configuration, identifying the network instance.
    /// Set in the genesis block and preserved unchanged in every subsequent block.
    /// Codec key: `"gh"`.
    pub genesis_hash: [u8; 32],
    /// Block round number. Codec key: `"r"`.
    pub round: u64,
    /// `SHA-256` Vector Commitment root over the block's transactions, for use in
    /// constrained environments (smart contracts, IoT) that lack `SHA-512/256`.
    /// Codec key: `"tc"`.
    pub txn_commitment: [u8; SHA256_DIGEST_SIZE],
}

impl LightBlockHeader {
    /// Decodes a `LightBlockHeader` from Algorand canonical MessagePack bytes.
    pub fn from_msgpack(bytes: &[u8]) -> Result<Self, DecodeError> {
        Self::decode(bytes)
    }

    fn to_msgpack_bytes(&self) -> Vec<u8> {
        AlgorandMessagePack::new()
            .bytes("0", &self.seed)
            .bytes("1", &self.block_hash)
            .bytes("gh", &self.genesis_hash)
            .uint("r", self.round)
            .bytes("tc", &self.txn_commitment)
            .encode()
    }
}

impl Hashable for LightBlockHeader {
    fn hash_into<H: MerkleHasher>(&self, h: &mut H) {
        h.update(DOMAIN_BLOCK_HEADER);
        h.update(&self.to_msgpack_bytes());
    }
}

impl MsgPackDecode for LightBlockHeader {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let n = r.read_map_len()?;
        let mut seed = [0u8; SHA256_DIGEST_SIZE];
        let mut block_hash = [0u8; SHA256_DIGEST_SIZE];
        let mut genesis_hash = [0u8; SHA256_DIGEST_SIZE];
        let mut round = 0u64;
        let mut txn_commitment = [0u8; SHA256_DIGEST_SIZE];

        for _ in 0..n {
            match r.read_str()? {
                "0" => {
                    let b = r.read_bin()?;
                    if b.len() != SHA256_DIGEST_SIZE {
                        return Err(DecodeError::InvalidDigestSize { expected: SHA256_DIGEST_SIZE, got: b.len() });
                    }
                    seed.copy_from_slice(b);
                }
                "1" => {
                    let b = r.read_bin()?;
                    if b.len() != SHA256_DIGEST_SIZE {
                        return Err(DecodeError::InvalidDigestSize { expected: SHA256_DIGEST_SIZE, got: b.len() });
                    }
                    block_hash.copy_from_slice(b);
                }
                "gh" => {
                    let b = r.read_bin()?;
                    if b.len() != SHA256_DIGEST_SIZE {
                        return Err(DecodeError::InvalidDigestSize { expected: SHA256_DIGEST_SIZE, got: b.len() });
                    }
                    genesis_hash.copy_from_slice(b);
                }
                "r" => round = r.read_uint()?,
                "tc" => {
                    let b = r.read_bin()?;
                    if b.len() != SHA256_DIGEST_SIZE {
                        return Err(DecodeError::InvalidDigestSize { expected: SHA256_DIGEST_SIZE, got: b.len() });
                    }
                    txn_commitment.copy_from_slice(b);
                }
                _ => r.skip()?,
            }
        }

        Ok(Self { seed, block_hash, genesis_hash, round, txn_commitment })
    }
}

/// Verifies that `header` is the leaf at `index` in the block headers [merkle::VcTree].
///
/// `index` is the zero-based position within the 256-block interval
/// (`round - first_attested_round`). `proof` is the path from
/// `GET /v2/blocks/{round}/lightheader/proof`. Returns `true` on success.
pub fn verify_block_header_commitment(
    header: &LightBlockHeader,
    index: usize,
    proof: &Proof<Sha256>,
    commitment: &[u8; SHA256_DIGEST_SIZE],
) -> bool {
    let mut h = Sha256::default();
    let leaf = hash_obj(&mut h, header);
    proof.verify_vc(leaf, index, commitment)
}

/// Verifies that a transaction appears at `index` in a block's SHA-256 transaction [merkle::VcTree].
///
/// `stib_hash` is `SHA-256("STIB" || Sig(Tx) || ApplyData)` — the `stibhash` field
/// returned by `GET /v2/blocks/{round}/transactions/{txid}/proof?hashtype=sha256`.
/// `commitment` is `LightBlockHeader::txn_commitment` for the block that contains the
/// transaction. Returns `true` on success.
pub fn verify_txn_commitment(
    stib_hash: [u8; SHA256_DIGEST_SIZE],
    index: usize,
    proof: &Proof<Sha256>,
    commitment: &[u8; SHA256_DIGEST_SIZE],
) -> bool {
    proof.verify_vc(stib_hash, index, commitment)
}

#[cfg(test)]
mod tests {
    use merkle::VcTree;
    use super::*;

    fn make_header(round: u64) -> LightBlockHeader {
        LightBlockHeader {
            seed:            [1u8; 32],
            block_hash:      [2u8; 32],
            genesis_hash:    [3u8; 32],
            round,
            txn_commitment:  [4u8; SHA256_DIGEST_SIZE],
        }
    }

    #[test]
    fn round_trip_all_fields() {
        let h = make_header(42);
        let decoded = LightBlockHeader::from_msgpack(&h.to_msgpack_bytes()).unwrap();
        assert_eq!(decoded, h);
    }

    #[test]
    fn zero_round_omitted_from_encoding() {
        let h = make_header(0);
        let encoded = h.to_msgpack_bytes();
        // fixmap(4) = 0x84 — "r" is absent because round == 0
        assert_eq!(encoded[0], 0x84);
        assert_eq!(LightBlockHeader::from_msgpack(&encoded).unwrap(), h);
    }

    #[test]
    fn verify_single_leaf() {
        let h = make_header(1);
        let tree = VcTree::<Sha256>::build(&[h.clone()]);
        let root  = tree.root().unwrap();
        let proof = tree.prove(0).unwrap();
        assert!(verify_block_header_commitment(&h, 0, &proof, &root));
    }

    #[test]
    fn verify_rejects_wrong_root() {
        let h = make_header(1);
        let tree  = VcTree::<Sha256>::build(&[h.clone()]);
        let proof = tree.prove(0).unwrap();
        assert!(!verify_block_header_commitment(&h, 0, &proof, &[0xffu8; SHA256_DIGEST_SIZE]));
    }

    #[test]
    fn verify_each_leaf_in_multi_leaf_tree() {
        let headers: Vec<_> = (0..4).map(make_header).collect();
        let tree = VcTree::<Sha256>::build(&headers);
        let root = tree.root().unwrap();
        for (i, h) in headers.iter().enumerate() {
            let proof = tree.prove(i).unwrap();
            assert!(verify_block_header_commitment(h, i, &proof, &root));
        }
    }
}
