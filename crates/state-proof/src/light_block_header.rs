// crates/state-proof/src/light_block_header.rs

use merkle::{hash_obj, Hashable, MerkleHasher, Proof, Sha256, SHA256_DIGEST_SIZE};

use crate::codec::{AlgorandMessagePack, DecodeError, MsgPackDecode, Reader};
use crate::stateproof::constants::{DOMAIN_LIGHT_BLOCK_HEADER, DOMAIN_TXN_LEAF};


// ── LightBlockHeader ──────────────────────────────────────────────────────────

/// Minimal subset of an Algorand block header containing only the fields needed
/// to verify inclusion in [`StateProofMessage::block_headers_commitment`].
///
/// Hashed as a `"B256"` VC leaf: `SHA-256("B256" || canonical_msgpack(LightBlockHeader))`.
/// Verified with [`verify_block_header_commitment`].
///
/// Exactly one of `seed` or `block_hash` is populated depending on the consensus
/// protocol version; the other must be `[0u8; 32]`. The algod API does not
/// return a `LightBlockHeader` directly — it must be constructed from the block
/// header response fields.
///
/// Wire codec keys: `"0"`, `"1"`, `"gh"`, `"r"`, `"tc"`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LightBlockHeader {
    /// 256-bit `SHA-512/256` hash digest acting as the block seed value.
    /// 
    /// Wire codec key: `"0"`.
    pub seed: [u8; SHA256_DIGEST_SIZE],
    /// 256-bit `SHA-512/256` hash digest acting as the block hash value.
    /// 
    /// Wire codec key: `"1"`.
    pub block_hash: [u8; SHA256_DIGEST_SIZE],
    /// 256-bit `SHA-512/256` hash digest of the ledger genesis, identifying the unique network instance.
    ///
    /// Wire codec key: `"gh"`.
    pub genesis_hash: [u8; SHA256_DIGEST_SIZE],
    /// The block round number.
    /// 
    /// Wire codec key: `"r"`.
    pub round: u64,
    /// 256-bit `SHA-256` hash digest vector commitment root on the block's transactions.
    /// 
    /// Wire codec key: `"tc"`.
    pub txn_commitment: [u8; SHA256_DIGEST_SIZE],
}

impl LightBlockHeader {
    /// Encodes to Algorand canonical `MessagePack` bytes. 
    fn to_msgpack_bytes(&self) -> Vec<u8> {
        /* NOTE: Exactly one of `seed` ("0") or `block_hash` ("1") gets encoded.

        A field is considered empty if its value consists entirely of zero bytes
            (e.g. `[0u8; N]`), in which case it is omitted from the MessagePack output.

        Therefore:
        - both fields cannot be empty
        - both fields cannot be non-empty
        - exactly one must be present

        Which field is encoded depends on the consensus protocol version:
        newer protocol versions encode `block_hash` and omit `seed`,
        while older versions encode `seed` and omit `block_hash`. */
        let mut mp = AlgorandMessagePack::new();

        // If `seed` is NOT empty, encode it.
        if self.seed != [0u8; 32] { mp = mp.bytes("0", &self.seed); }

        // If `block_hash` is NOT empty, encode it.
        if self.block_hash != [0u8; 32] { mp = mp.bytes("1", &self.block_hash); }

        // Encode the rest of the fields: `genesis_hash`, `round` and `txn_commitment`
        mp.bytes("gh", &self.genesis_hash)
          .uint("r", self.round)
          .bytes("tc", &self.txn_commitment)
          .encode()
    }

    /// Decodes from Algorand canonical `MessagePack` bytes.
    pub fn from_msgpack(bytes: &[u8]) -> Result<Self, DecodeError> {
        Self::decode(bytes)
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

impl Hashable for LightBlockHeader {
    fn hash_into<H: MerkleHasher>(&self, h: &mut H) {
        h.update(DOMAIN_LIGHT_BLOCK_HEADER);
        h.update(&self.to_msgpack_bytes());
    }
}


// ── VerifyBlockHeader ─────────────────────────────────────────────────────────

/// Verifies that `header` is included at `index` in the block headers VC tree.
///
/// `commitment` is [`StateProofMessage::block_headers_commitment`]; `proof` is
/// fetched from `GET /v2/blocks/{round}/lightheader/proof`. `index` equals
/// `round − first_attested_round` — compute it via
/// [`StateProofMessage::block_index_for_round`].
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


// ── VerifyBlockTxn ────────────────────────────────────────────────────────────

/// Verifies that a transaction is included at `index` in a block’s transaction VC tree.
///
/// `txn_sha256` = `SHA-256("TX" || canonical_msgpack(txn))` — **NOTE**: `SHA-256`, not 
/// the `SHA-512/256` hash algorithm used to produce an Algorand transaction ID.
/// Transaction bytes must include `gh` and `gen` fields that block storage strips.
///
/// `stib_sha256` = `SHA-256("STIB" || Sig(Tx) || ApplyData)` — fetch via
/// `GET /v2/blocks/{round}/transactions/{txid}/proof?hashtype=sha256`.
///
/// `commitment` is [`LightBlockHeader::txn_commitment`] for the block containing
/// the transaction.
pub fn verify_txn_commitment(
    txn_sha256: [u8; SHA256_DIGEST_SIZE],
    stib_sha256: [u8; SHA256_DIGEST_SIZE],
    index: usize,
    proof: &Proof<Sha256>,
    commitment: &[u8; SHA256_DIGEST_SIZE],
) -> bool {
    let mut h = Sha256::default();
    h.update(DOMAIN_TXN_LEAF);
    h.update(&txn_sha256);
    h.update(&stib_sha256);
    let leaf = h.finalize_reset();
    proof.verify_vc(leaf, index, commitment)
}


// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use merkle::VcTree;
    use super::*;

    /// Dummy block header for structural testing.
    fn dummy_block_header(round: u64) -> LightBlockHeader {
        LightBlockHeader {
            seed: [1u8; 32],
            block_hash: [2u8; 32],
            genesis_hash: [3u8; 32],
            round,
            txn_commitment: [4u8; SHA256_DIGEST_SIZE],
        }
    }

    #[test]
    fn round_trip_all_fields() {
        let h = dummy_block_header(42);
        let decoded = LightBlockHeader::from_msgpack(&h.to_msgpack_bytes()).unwrap();
        assert_eq!(decoded, h);
    }

    #[test]
    fn zero_round_omitted_from_encoding() {
        let h = dummy_block_header(0);
        let encoded = h.to_msgpack_bytes();
        // fixmap(4) = 0x84 — "r" is absent because round == 0
        assert_eq!(encoded[0], 0x84);
        assert_eq!(LightBlockHeader::from_msgpack(&encoded).unwrap(), h);
    }

    #[test]
    fn verify_single_leaf() {
        let h = dummy_block_header(1);
        let tree = VcTree::<Sha256>::build(&[h.clone()]);
        let root  = tree.root().unwrap();
        let proof = tree.prove(0).unwrap();
        assert!(verify_block_header_commitment(&h, 0, &proof, &root));
    }

    #[test]
    fn verify_rejects_wrong_root() {
        let h = dummy_block_header(1);
        let tree  = VcTree::<Sha256>::build(&[h.clone()]);
        let proof = tree.prove(0).unwrap();
        assert!(!verify_block_header_commitment(&h, 0, &proof, &[0xffu8; SHA256_DIGEST_SIZE]));
    }

    #[test]
    fn verify_each_leaf_in_multi_leaf_tree() {
        let headers: Vec<_> = (0..4).map(dummy_block_header).collect();
        let tree = VcTree::<Sha256>::build(&headers);
        let root = tree.root().unwrap();
        for (i, h) in headers.iter().enumerate() {
            let proof = tree.prove(i).unwrap();
            assert!(verify_block_header_commitment(h, i, &proof, &root));
        }
    }
}
