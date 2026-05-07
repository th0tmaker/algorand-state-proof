// crates/state-proof/src/stateproof/commitment.rs

use merkle::{hash_obj, Hashable, MerkleHasher, Proof, Sha256, SHA256_DIGEST_SIZE};

use crate::codec::{AlgorandMessagePack, DecodeError, MsgPackDecode, Reader};
use super::constants::DOMAIN_BLOCK_HEADER;

/// ## Overview
/// A stripped-down (light) subset of an Algorand block header containing only the
/// fields required to verify block inclusion inside a `StateProof` interval.
///
/// Fields:
/// - **Block seed**: A 32-byte `SHA-512/256` digest derived from the proposer’s VRF output.
/// - **Block hash**: A 32-byte `SHA-512/256` digest of this block header. This becomes the
///   `prev` field in the next block, linking the chain.
/// - **Genesis hash**: A 32-byte `SHA-512/256` digest identifying the genesis configuration
///   of the ledger.
/// - **Round**: The block round number (`u64`).
/// - **Transaction commitment**: A 32-byte `SHA-256` digest representing the vector
///   commitment root over the block’s transactions.
///
/// ## Role in State Proofs
/// A `LightBlockHeader` is a key component in the Algorand State Proof verification process.
///
/// It is part of the data that gets turned into a leaf that makes up the `block_headers_commitment` vector commitment Merkle tree:
/// 
/// The leaf value is computed via the following formula: 
///
/// 1. The `LightBlockHeader` is encoded using the canonical AlgorandMessagePack.
/// 2. The domain separation prefix `b"B256"` is prepended.
/// 3. The resulting bytes are hashed with `SHA-256`.
///
/// This resulting hash digest ends up as one of several leafs in a VC Merkle tree covering 256 consecutive block headers. 
/// The final root value of this tree is the [`block_headers_commitment`](crate::StateProofMessage::block_headers_commitment)
///
/// ## Relevant endpoints for requesting data
/// - `GET /v2/blocks/{round}`. Retrieves the full block data (header + transactions). 
/// - `GET /v2/blocks/{round}?header-only=true`. Retrieves only the block header (no transactions).
/// - `GET /v2/blocks/{round}/lightheader/proof`. Computes the VC tree path and outputs the proof, 
///    tree depth and the index position of the block within the tree.
///
/// Note: Algod daemon does not provide a `LightBlockHeader` directly. It must be
/// constructed locally by extracting and re-encoding the relevant fields
/// from the block header response.
/// 
/// ## Verification
/// Verify inclusion using `verify_block_header_commitment`, which checks that
/// the constructed `LightBlockHeader` is included in the 256-block interval
/// committed to by the state proof (via `block_headers_commitment`).
/// 
/// ## Codec keys
/// `"0"`, `"1"`, `"gh"`, `"r"`, `"tc"`
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LightBlockHeader {
    /// Block seed value (`SHA-512/256` digest). 
    /// 
    /// Codec key: `"0"`.
    pub seed: [u8; 32],
    /// Hash of the current block  (`SHA-512/256` digest). 
    /// 
    /// Codec key: `"1"`.
    pub block_hash: [u8; 32],
    /// Hash of the ledger genesis config, identifying the network instance. (`SHA-512/256` digest).
    ///
    /// Codec key: `"gh"`.
    pub genesis_hash: [u8; 32],
    /// Block round number.
    /// 
    /// Codec key: `"r"`.
    pub round: u64,
    /// `SHA-256` Vector Commitment root over the block's transactions.
    /// 
    /// Codec key: `"tc"`.
    pub txn_commitment: [u8; SHA256_DIGEST_SIZE],
}

impl LightBlockHeader {
    /// Decodes from Algorand canonical `MessagePack` bytes.
    pub fn from_msgpack(bytes: &[u8]) -> Result<Self, DecodeError> {
        Self::decode(bytes)
    }

    /* NOTE: Exactly one of `seed` ("0") or `block_hash` ("1") gets encoded.

    A field is considered empty if its value consists entirely of zero bytes
        (e.g. `[0u8; N]`), in which case it is omitted from the MessagePack output.

    Therefore:
    - both fields cannot be empty
    - both fields cannot be non-empty
    - exactly one must be present

    Which field is encoded depends on the consensus protocol version:
    newer protocol versions encode `block_hash` and omit `seed`,
    while older versions encode `seed` and omit `block_hash`.
    */
    /// Encodes to Algorand canonical `MessagePack` bytes. 
    fn to_msgpack_bytes(&self) -> Vec<u8> {
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
}

// test this? 
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
        h.update(DOMAIN_BLOCK_HEADER);
        h.update(&self.to_msgpack_bytes());
    }
}

/// ## Overview
/// Verifies the inclusion of a block at the specified `index` by validating
/// its Merkle (vector commitment) proof against the commitment tree root.
///
/// ## Parameters
/// - `header`: The light block header to verify.
/// - `index`: The position of the block within the 256-round interval
///   (0 ≤ index < 256).
/// - `proof`: The Merkle proof for this header.
/// - `commitment`: The SHA-256 hash digest representing the VC tree root from the state proof
///    message field [block_headers_commitment](crate::StateProofMessage::block_headers_commitment).
///
/// ## Returns
/// `true` if the proof is valid and `header` is included at `index`
/// in the committed 256-round interval; `false` otherwise.
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

/// ## Overview
/// Verifies the inclusion of a transaction (represented by its `stib_hash`)
/// at the specified `index` by validating its Merkle (vector commitment)
/// proof against the transaction commitment tree root.
///
/// ## Parameters
/// - `stib_hash`: The hash digest of the preimage `SHA-256("STIB" || Sig(Tx) || ApplyData)`).
/// 
///   This value can be fetched from:
///   `GET /v2/blocks/{round}/transactions/{txid}/proof?hashtype=sha256`.
///
/// - `index`: The position of the transaction within the block’s transaction set.
///
/// - `proof`: The Merkle proof corresponding to this transaction, also returned by:
///   `GET /v2/blocks/{round}/transactions/{txid}/proof?hashtype=sha256`.
///
/// - `commitment`: The SHA-256 hash digest representing the transaction commitment 
///    root for the block, i.e. [LightBlockHeader::txn_commitment].
///
/// ## Returns
/// `true` if the proof is valid and the transaction is included at `index`
///  in the committed set inside the evaluated block; `false` otherwise.
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
