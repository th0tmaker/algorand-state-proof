// crates/state-proof/src/stateproof/mod.rs

mod commitment;
mod coin;
pub(crate) mod constants;
mod message;
mod verifier;

pub use commitment::{LightBlockHeader, verify_block_header_commitment, verify_txn_commitment};
pub use message::{StateProofMessage, TrustAnchor};
pub use verifier::{VerifyError, verify_state_proof};

pub(crate) use coin::{CoinChoiceSeed, CoinGenerator, ln_int_approximation};
use constants::{MAX_REVEALS, MERKLE_SIG_SCHEME_FIXED_REPR_SIZE, MSS_CRYPTO_SUITE_ID, MSS_VC_MAX_DEPTH};

use algorand_falcon_keys::{
    CompressedSignature, PublicKey,
    FALCON_DET1024_PUBKEY_SIZE, FALCON_DET1024_SIG_COMPRESSED_HEADER, FALCON_DET1024_SIG_CT_SIZE,
};
use merkle::{Proof, Sumhash512, Sumhash512Digest, SUMHASH512_DIGEST_SIZE};

use crate::codec::{DecodeError, MsgPackDecode, Reader};

/// SHA-256 hash of the state proof message (`"spm" || canonical_msgpack(message)`).
pub type MessageHash = [u8; 32];

// ── PublicKey ─────────────────────────────────────────────────────────────────

impl MsgPackDecode for PublicKey {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let n = r.read_map_len()?;
        let mut bytes = [0u8; FALCON_DET1024_PUBKEY_SIZE];
        for _ in 0..n {
            match r.read_str()? {
                "k" => {
                    let b = r.read_bin()?;
                    if b.len() != FALCON_DET1024_PUBKEY_SIZE {
                        return Err(DecodeError::InvalidPublicKeySize { expected: FALCON_DET1024_PUBKEY_SIZE, got: b.len() });
                    }
                    bytes.copy_from_slice(b);
                }
                _ => r.skip()?,
            }
        }
        PublicKey::from_bytes(&bytes)
            .map_err(|_| DecodeError::InvalidPublicKey)
    }
}

// ── CompressedSignature ───────────────────────────────────────────────────────

impl MsgPackDecode for CompressedSignature {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let b = r.read_bin()?;
        CompressedSignature::from_bytes(b)
            .map_err(|_| DecodeError::InvalidSignature)
    }
}

// ── MerkleVerifier ────────────────────────────────────────────────────────────

/// Identifies a participant's [StateProof] verifying [PublicKey] and its lifetime.
///
/// The `commitment` is the vector commitment root over all ephemeral FALCON
/// verifying keys for the participant's entire participation period. It serves
/// as the participant's stable, long-lived public identifier (`StateProofPK`)
/// registered on-chain for State Proof verification.
/// 
/// Wire codec keys: `"cmt"`, `"lf"`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MerkleVerifier {
    /// 512-bit `Sumhash512` hash digest vector commitment root on Merkle tree built over all 
    /// the FALCON ephemeral public/verifying keys for a participant's entire participation period.
    ///
    /// Wire codec key: `"cmt"`.
    pub commitment: Sumhash512Digest,
    /// Participant verifying `PublicKey` at index `i` is valid for signing rounds
    /// in `[r, r + key_lifetime - 1]`, where `r` is the `i`-th round satisfying
    /// `r % key_lifetime = 0` within the participation period.
    ///
    /// Wire codec key: `"lf"`.
    pub key_lifetime: u64,
}

impl Default for MerkleVerifier {
    fn default() -> Self {
        Self { commitment: [0u8; SUMHASH512_DIGEST_SIZE], key_lifetime: 0 }
    }
}

impl MsgPackDecode for MerkleVerifier {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let n = r.read_map_len()?;
        let mut commitment = [0u8; SUMHASH512_DIGEST_SIZE];
        let mut key_lifetime = 0u64;
        for _ in 0..n {
            match r.read_str()? {
                "cmt" => {
                    let b = r.read_bin()?;
                    if b.len() != SUMHASH512_DIGEST_SIZE {
                        return Err(DecodeError::InvalidDigestSize { expected: SUMHASH512_DIGEST_SIZE, got: b.len() });
                    }
                    commitment.copy_from_slice(b);
                }
                "lf" => key_lifetime = r.read_uint()?,
                _ => r.skip()?,
            }
        }
        Ok(Self { commitment, key_lifetime })
    }
}

// ── MerkleSignatureScheme ───────────────────────────────────────────────────────────

/// A Merkle-based signature scheme used in State Proof verification.
///
/// This binds an FALCON signature to a specific Vector Commitment (VC) tree leaf
/// via a Merkle proof, allowing verification that the signing key was authorized for
/// the given round.
/// 
/// Wire codec keys: `"sig"`, `"idx"`, `"prf"`, `"vkey"`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MerkleSignatureScheme {
    /// The FALCON [CompressedSignature] over the attested message for this round.
    ///
    /// Wire codec key: `"sig"`.
    pub sig: CompressedSignature,
    /// The leaf index identifying which key was used to sign.
    ///
    /// Wire codec key: `"idx"`.
    pub vc_index: u64,
    /// Merkle membership proof path authenticating `verifying_key` 
    /// against the Vector Commitment (VC) tree `root`.
    ///
    /// Wire codec key: `"prf"`.
    pub proof: Proof<Sumhash512>,
    /// The ephemeral FALCON verifying key (public key) used to verify `sig`.
    ///
    /// Wire codec key: `"vkey"`.
    pub verifying_key: PublicKey,
}

impl Default for MerkleSignatureScheme {
    fn default() -> Self {
        Self {
            sig: CompressedSignature::from_bytes(&[FALCON_DET1024_SIG_COMPRESSED_HEADER, 0]).unwrap(),
            vc_index: 0,
            proof: Proof::<Sumhash512>::new(0, vec![]),
            verifying_key: PublicKey::from_bytes(&[0u8; FALCON_DET1024_PUBKEY_SIZE]).unwrap(),
        }
    }
}

impl MerkleSignatureScheme {
    /// Serializes `MerkleSignatureScheme` into a single flattened buffer of bytes with a specific fixed order.
    ///
    /// Serialized layout:
    /// `b"sps" || l(u64 LE) || MerkleSignatureScheme([u8; 4366])`
    pub(crate) fn to_bytes(&self) -> Result<[u8; MERKLE_SIG_SCHEME_FIXED_REPR_SIZE], algorand_falcon_keys::Error> {
        // Convert Falcon signature from compressed to constant-time (ct) format.
        let ct = self.sig.to_ct()?;

        // Allocate output buffer and initalize cursor position.
        let mut out = [0u8; MERKLE_SIG_SCHEME_FIXED_REPR_SIZE];
        let mut pos = 0;

        // Copy byte slices into buffer.
        out[pos..pos + 2].copy_from_slice(&MSS_CRYPTO_SUITE_ID.to_le_bytes()); pos += 2;
        out[pos..pos + FALCON_DET1024_SIG_CT_SIZE].copy_from_slice(ct.as_bytes()); pos += FALCON_DET1024_SIG_CT_SIZE;
        out[pos..pos + FALCON_DET1024_PUBKEY_SIZE].copy_from_slice(self.verifying_key.as_bytes()); pos += FALCON_DET1024_PUBKEY_SIZE;
        out[pos..pos + 8].copy_from_slice(&self.vc_index.to_le_bytes()); pos += 8;

        // Encode tree depth as a single byte indicating how many path entries (hashes) are valid.
        // E.g. `tree_depth = 3`: [hash_a, 32], [hash_b, 32], [hash_c, 32]...
        //Proof fixed encoding: tree_depth (1 B) || zero-pad for unused slots || path entries
        out[pos] = self.proof.tree_depth; pos += 1;

        // Remaining buffer up to its size will be filled with padding.
        // E.g. `tree_depth = 3`: [hash_a, 32], [hash_b, 32], [hash_c, 32], [00..00, 32]...
        let pad = MSS_VC_MAX_DEPTH.saturating_sub(self.proof.tree_depth) as usize;
        let path_start = pos + pad * SUMHASH512_DIGEST_SIZE;
        
        for (i, entry) in self.proof.path.iter().enumerate() {
            let offset = path_start + i * SUMHASH512_DIGEST_SIZE;
            out[offset..offset + SUMHASH512_DIGEST_SIZE].copy_from_slice(entry);
        }

        Ok(out)
    }

    /// Returns the salt version byte embedded in the CompressedSignature encoding.
    pub(crate) fn salt_version(&self) -> u8 {
        self.sig.salt_version()
    }
}

impl MsgPackDecode for MerkleSignatureScheme {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let n = r.read_map_len()?;
        let mut out = MerkleSignatureScheme::default();
        for _ in 0..n {
            match r.read_str()? {
                "sig" => out.sig = CompressedSignature::decode_from(r)?,
                "idx" => out.vc_index = r.read_uint()?,
                "prf" => out.proof = Proof::decode_from(r)?,
                "vkey" => out.verifying_key = PublicKey::decode_from(r)?,
                _ => r.skip()?,
            }
        }
        Ok(out)
    }
}

// ── SigSlotCommit ─────────────────────────────────────────────────────────────

/// A participant committed signature slot containing:
///
/// * `mss`: The participant's `MerkleSignatureScheme` signature over the attested
///   message, authenticated via `sig_proofs`.
/// * `l`: The cumulative stake weight of all slots below this one (`u64`),
///   defining this slot's coin range `[l, l + weight)`.
/// 
/// Wire codec keys: `"s"`, `"l"`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SigSlotCommit {
    /// The participant's `MerkleSignatureScheme` over the attested message; authenticated via `sig_proofs`.
    ///
    /// Wire codec key: `"s"`.
    pub mss: MerkleSignatureScheme,
    /// Cumulative weight of signatures in all slots below this one; defines this slot's coin range `[l, l + weight)`.
    ///
    /// Wire codec key: `"l"`.
    pub l: u64,
}

impl MsgPackDecode for SigSlotCommit {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let n = r.read_map_len()?;
        let mut out = SigSlotCommit::default();
        for _ in 0..n {
            match r.read_str()? {
                "s" => out.mss = MerkleSignatureScheme::decode_from(r)?,
                "l" => out.l = r.read_uint()?,
                _ => r.skip()?,
            }
        }
        Ok(out)
    }
}

// ── Participant ───────────────────────────────────────────────────────────────

/// An online account that participated in signing the state proof.
///
/// Codec keys: `"p"`, `"w"`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Participant {
    /// Long-term `MerkleVerifier` containing the `Sumhash512Digest` commitment root of the
    /// participant's ephemeral `PublicKey` tree and the key rotation interval.
    ///
    /// Codec key: `"p"`.
    pub pk: MerkleVerifier,
    /// Signed weight (stake); the participant's share of the total signed weight.
    ///
    /// Codec key: `"w"`.
    pub signed_weight: u64,
}

impl MsgPackDecode for Participant {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let n = r.read_map_len()?;
        let mut out = Participant::default();
        for _ in 0..n {
            match r.read_str()? {
                "p" => out.pk = MerkleVerifier::decode_from(r)?,
                "w" => out.signed_weight = r.read_uint()?,
                _ => r.skip()?,
            }
        }
        Ok(out)
    }
}

// ── Reveal ────────────────────────────────────────────────────────────────────

/// A revealed slot in the state proof: the `SigSlotCommit` and the
/// `Participant` data, both authenticated via Merkle proofs in `StateProof`.
///
/// Codec keys: `"s"`, `"p"`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Reveal {
    /// The committed signature slot containing the `MerkleSignatureScheme` and cumulative signed weight.
    ///
    /// Codec key: `"s"`.
    pub sig_slot: SigSlotCommit,
    /// The participant who produced this signature slot.
    ///
    /// Codec key: `"p"`.
    pub participant: Participant,
}

impl MsgPackDecode for Reveal {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let n = r.read_map_len()?;
        let mut out = Reveal::default();
        for _ in 0..n {
            match r.read_str()? {
                "s" => out.sig_slot = SigSlotCommit::decode_from(r)?,
                "p" => out.participant = Participant::decode_from(r)?,
                _ => r.skip()?,
            }
        }
        Ok(out)
    }
}

// ── StateProof ────────────────────────────────────────────────────────────────

/// A post-quantum state proof attesting to the Algorand block state at a given round.
///
/// Received from the network and verified against a known `sig_commit` root and
/// `signed_weight`. Codec keys match the Algorand wire format exactly.
///
/// Wire codec keys: `"c"`, `"w"`, `"S"`, `"P"`, `"v"`, `"r"`, `"pr"`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateProof {
    /// 512-bit `Sumhash512` hash digest vector commitment root on the enitre signature array
    /// (all participants who signed, not just the revealed ones).
    ///
    /// Wire codec key: `"c"`.
    pub sig_commitment: Sumhash512Digest,
    /// 64-bit LE integer representing total (stake) signed weight of all participants 
    /// whose signatures appear in `StateProof` the signature array.
    ///
    /// Wire codec key: `"w"`.
    pub signed_weight: u64,
    /// Merkle membership proof path authenticating all revealed 
    /// `SigSlotCommit` leaves against the Vector Commitment (VC) tree `root`.
    ///
    /// Wire codec key: `"S"`.
    pub sig_proofs: Proof<Sumhash512>,
    /// Merkle membership proof path authenticating all revealed `Participant` 
    /// leaves against the Vector Commitment (VC) tree `root`.
    /// 
    /// Wire codec key: `"P"`.
    pub part_proofs: Proof<Sumhash512>,
    /// Expected FALCON signature salt version; all signatures in `reveals` must match this value.
    ///
    /// Wire codec key: `"v"`.
    pub mss_salt_version: u8,
    /// Revealed positions and their corresponding data.
    ///
    /// A sparse map from a participant's position in the array to a [`Reveal`]
    /// struct. Each entry exposes a single array position and contains:
    ///
    /// - **Participant information**:
    ///   - The participant's balance in μALGO (weight).
    ///   - The participant's Merkle signature scheme commitment (`StateProofPK`).
    ///
    /// - **Signature information**:
    ///   - The participant's `L` value, used for weight-range verification:
    ///     `r.Sig.L <= coin_i < r.Sig.L + r.Part.Weight`.
    ///   - The participant's serialized Merkle Signature for the message being proven.
    ///
    /// The positions revealed are pseudorandomly chosen via a SHAKE256-based coin
    /// derived from the signature commitment, participant commitment, signed weight,
    /// and the State Proof message hash.
    /// 
    /// Wire codec key: `"r"`.
    pub reveals: Vec<(u64, Reveal)>,
    /// Sequence of tree positions to reveal, in coin-index order.
    ///
    /// Position `i` corresponds to coin `i` in the verifier's coin-check loop:
    /// `reveals[positions_to_reveal[i]]` must satisfy the weight-interval check for `coin_i`.
    /// 
    /// Wire codec key: `"pr"`.
    pub positions_to_reveal: Vec<u64>,
}

impl StateProof {
    /// Decodes from Algorand canonical `MessagePack` bytes.
    pub fn from_msgpack(bytes: &[u8]) -> Result<Self, DecodeError> {
        Self::decode(bytes)
    }
}

impl MsgPackDecode for StateProof {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let n = r.read_map_len()?;
        let mut sig_commitment = [0u8; SUMHASH512_DIGEST_SIZE];
        let mut signed_weight = 0u64;
        let mut sig_proofs = Proof::<Sumhash512>::new(0, vec![]);
        let mut part_proofs = Proof::<Sumhash512>::new(0, vec![]);
        let mut mss_salt_version = 0u8;
        let mut reveals = Vec::new();
        let mut positions_to_reveal = Vec::new();
        let check_bound = |len: usize| -> Result<usize, DecodeError> {
            if len > MAX_REVEALS {
                Err(DecodeError::TooManyReveals { got: len, max: MAX_REVEALS })
            } else {
                Ok(len)
            }
        };
        for _ in 0..n {
            match r.read_str()? {
                "c"  => {
                    let b = r.read_bin()?;
                    if b.len() != SUMHASH512_DIGEST_SIZE {
                        return Err(DecodeError::InvalidDigestSize { expected: SUMHASH512_DIGEST_SIZE, got: b.len() });
                    }
                    sig_commitment.copy_from_slice(b);
                }
                "w" => {
                    signed_weight = r.read_uint()?;
                    if signed_weight == 0 {
                        return Err(DecodeError::ZeroSignedWeight);
                    }
                }
                "S" => sig_proofs = Proof::decode_from(r)?,
                "P" => part_proofs = Proof::decode_from(r)?,
                "v" => mss_salt_version = r.read_uint()? as u8,
                "r" => {
                    let len = check_bound(r.read_map_len()?)?;
                    reveals = Vec::with_capacity(len);
                    for _ in 0..len {
                        let pos = r.read_uint()?;
                        let reveal = Reveal::decode_from(r)?;
                        reveals.push((pos, reveal));
                    }
                }
                "pr" => {
                    let len = check_bound(r.read_array_len()?)?;
                    positions_to_reveal = Vec::with_capacity(len);
                    for _ in 0..len {
                        positions_to_reveal.push(r.read_uint()?);
                    }
                }
                _ => r.skip()?,
            }
        }
        Ok(Self {
            sig_commitment,
            signed_weight,
            sig_proofs,
            part_proofs,
            mss_salt_version,
            reveals,
            positions_to_reveal,
        })
    }
}