// crates/state-proof/src/stateproof/mod.rs

// NOTE: Build State Proof message support; struct + msgpack codec + hash_msg function
// Maybe impl Hashable for StateProofMessage with `hash_obj()`

mod coin;
mod verifier;

#[allow(unused)]
pub use coin::{CoinChoiceSeed, CoinGenerator, ln_int_approximation};
pub use verifier::{VerifyError, verify_state_proof};

use algorand_falcon_keys::{
    CompressedSignature, PublicKey,
    FALCON_DET1024_PUBKEY_SIZE, FALCON_DET1024_SIG_COMPRESSED_HEADER, FALCON_DET1024_SIG_CT_SIZE,
};
use merkle::{Sumhash512, Proof, Sumhash512Digest, SHA256_DIGEST_SIZE, SUMHASH512_DIGEST_SIZE};

use crate::codec::{DecodeError, MsgPackDecode, Reader};

// ── Merkle Constants ──────────────────────────────────────────────────────────

/// Identifies the [MerkleSignatureScheme] suite of primitives used in the leaf hash preimages.
/// Included for flexibility; a future suite would potentially use a different ID.
pub(crate) const MERKLE_SIG_SCHEME_ID: u16 = 0;

/// Maximum tree depth accepted by the state proof verifier.
/// Proofs with `tree_depth` exceeding this are rejected as invalid.
pub const MERKLE_MAX_ENCODED_TREE_DEPTH: u8 = 20;

/// Byte length of the fixed-length [Proof\<Sumhash512\>] binary encoding used in the state proof wire format.
///
/// Format: `tree_depth (1 B) || 20 × Sumhash512 digest slots (64 B each)`.
pub const SUMHASH512_PROOF_FIXED_REPR_SIZE: usize = 1 + MERKLE_MAX_ENCODED_TREE_DEPTH as usize * SUMHASH512_DIGEST_SIZE;

/// Byte length of the fixed-length binary representation of a [MerkleSignatureScheme].
///
/// Layout: `MerkleSigSchemeID(2) || sig_ct(1538) || pubkey(1793) || vc_index(8) || proof_fixed_repr`
pub const MERKLE_SIG_SCHEME_FIXED_REPR_SIZE: usize =
    2 + FALCON_DET1024_SIG_CT_SIZE + FALCON_DET1024_PUBKEY_SIZE + 8 + SUMHASH512_PROOF_FIXED_REPR_SIZE;

// ── Sha256 Constants ──────────────────────────────────────────────────────────

/// Byte length of a SHA-256 digest (32 bytes = 256 bits = 8 × 32-bit words).
// pub const SHA256_DIGEST_SIZE: usize = 32;

// ── Sha256 Types ──────────────────────────────────────────────────────────────

/// A 32-byte SHA-256 hash digest ed to by the state proof.
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
                        return Err(DecodeError::InvalidPublicKeySize(b.len()));
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

/// Identifies a participant's long-term Merkle signing key.
///
/// Codec keys: `"cmt"representing the message being attest`, `"lf"`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MerkleVerifier {
    /// [Sumhash512Digest] root commitment of the participant's ephemeral [PublicKey] tree.
    ///
    /// Codec key: `"cmt"`.
    pub commitment: Sumhash512Digest,
    /// Interval in rounds between ephemeral key rotations; a [PublicKey] at index `i`
    /// is valid for signing round `first_valid + i * key_lifetime`.
    ///
    /// Codec key: `"lf"`.
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
                        return Err(DecodeError::InvalidDigestSize(b.len()));
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

/// A single-round [CompressedSignature] bundled with its Merkle membership [merkle::Proof],
/// proving that the signing key is committed to in the participant's long-term [merkle::VcTree].
///
/// Codec keys: `"sig"`, `"idx"`, `"prf"`, `"vkey"`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MerkleSignatureScheme {
    /// The ephemeral [CompressedSignature] over the attested message for this round.
    ///
    /// Codec key: `"sig"`.
    pub sig: CompressedSignature,
    /// Leaf index in the [merkle::VcTree] identifying which ephemeral key was used to sign.
    ///
    /// Codec key: `"idx"`.
    pub vc_index: u64,
    /// Merkle membership [merkle::Proof] authenticating `verifying_key` against the VC tree `root`.
    ///
    /// Codec key: `"prf"`.
    pub proof: Proof<Sumhash512>,
    /// Ephemeral [PublicKey] used to verify this round's signature.
    ///
    /// Codec key: `"vkey"`.
    pub verifying_key: PublicKey,
}

impl Default for MerkleSignatureScheme {
    fn default() -> Self {
        Self {
            // Minimal valid compressed-signature shell: header byte + 1-byte salt version.
            sig: CompressedSignature::from_bytes(
                &[FALCON_DET1024_SIG_COMPRESSED_HEADER, 0]).unwrap(),
            vc_index: 0,
            proof: Proof::<Sumhash512>::new(0, vec![]),
            verifying_key: PublicKey::from_bytes(&[0u8; FALCON_DET1024_PUBKEY_SIZE]).unwrap(),
        }
    }
}

impl MerkleSignatureScheme {
    /// Serializes `self` into the SNARK-friendly fixed-length binary format used as
    /// leaf data in the state-proof signature tree.
    pub(crate) fn to_fixed_bytes(&self) -> Result<[u8; MERKLE_SIG_SCHEME_FIXED_REPR_SIZE], algorand_falcon_keys::Error> {
        let ct = self.sig.to_ct()?;
        let mut out = [0u8; MERKLE_SIG_SCHEME_FIXED_REPR_SIZE];
        let mut pos = 0;

        out[pos..pos + 2].copy_from_slice(&MERKLE_SIG_SCHEME_ID.to_le_bytes()); pos += 2;
        out[pos..pos + FALCON_DET1024_SIG_CT_SIZE].copy_from_slice(ct.as_bytes()); pos += FALCON_DET1024_SIG_CT_SIZE;
        out[pos..pos + FALCON_DET1024_PUBKEY_SIZE].copy_from_slice(self.verifying_key.as_bytes()); pos += FALCON_DET1024_PUBKEY_SIZE;
        out[pos..pos + 8].copy_from_slice(&self.vc_index.to_le_bytes()); pos += 8;
        // Proof fixed encoding: tree_depth (1 B) || zero-pad for unused slots || path entries
        out[pos] = self.proof.tree_depth; pos += 1;
        let pad = MERKLE_MAX_ENCODED_TREE_DEPTH.saturating_sub(self.proof.tree_depth) as usize;
        let path_start = pos + pad * SUMHASH512_DIGEST_SIZE;
        for (i, entry) in self.proof.path.iter().enumerate() {
            let offset = path_start + i * SUMHASH512_DIGEST_SIZE;
            out[offset..offset + SUMHASH512_DIGEST_SIZE].copy_from_slice(entry);
        }

        Ok(out)
    }

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

/// A committed signature slot: the Merkle signature plus the cumulative weight
/// `l` used for coin-range verification.
///
/// Codec keys: `"s"`, `"l"`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SigSlotCommit {
    /// The participant's [MerkleSignatureScheme] over the attested message; authenticated via `sig_proofs`.
    ///
    /// Codec key: `"s"`.
    pub mss: MerkleSignatureScheme,
    /// Cumulative stake weight of all slots below this one; defines this slot's coin range `[l, l + weight)`.
    ///
    /// Codec key: `"l"`.
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
    /// Long-term [MerkleVerifier] containing the [Sumhash512Digest] commitment root of the
    /// participant's ephemeral [PublicKey] tree and the key rotation interval.
    ///
    /// Codec key: `"p"`.
    pub pk: MerkleVerifier,
    /// Stake weight; the participant's share of the total signed weight.
    ///
    /// Codec key: `"w"`.
    pub weight: u64,
}

impl MsgPackDecode for Participant {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let n = r.read_map_len()?;
        let mut out = Participant::default();
        for _ in 0..n {
            match r.read_str()? {
                "p" => out.pk = MerkleVerifier::decode_from(r)?,
                "w" => out.weight = r.read_uint()?,
                _ => r.skip()?,
            }
        }
        Ok(out)
    }
}

// ── Reveal ────────────────────────────────────────────────────────────────────

/// A revealed slot in the state proof: the [SigSlotCommit] and the
/// [Participant] data, both authenticated via Merkle proofs in [StateProof].
///
/// Codec keys: `"s"`, `"p"`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Reveal {
    /// The committed signature slot containing the [MerkleSignatureScheme] and cumulative weight.
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
/// Codec keys: `"c"`, `"w"`, `"S"`, `"P"`, `"v"`, `"r"`, `"pr"`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateProof {
    /// [Sumhash512Digest] root commitment of the signature [merkle::VcTree].
    ///
    /// Codec key: `"c"`.
    pub sig_commitment: Sumhash512Digest,
    /// Total stake weight of all participants who signed.
    ///
    /// Codec key: `"w"`.
    pub signed_weight: u64,
    /// Batch [merkle::Proof] authenticating all revealed [SigSlotCommit] leaves against `sig_commit`.
    ///
    /// Codec key: `"S"`.
    pub sig_proofs: Proof<Sumhash512>,
    /// Batch [merkle::Proof] authenticating all revealed [Participant] leaves against the trusted participant commitment.
    ///
    /// Codec key: `"P"`.
    pub part_proofs: Proof<Sumhash512>,
    /// The [MerkleSignatureScheme] salt version used when hashing ephemeral keys; must match across all reveals.
    ///
    /// Codec key: `"v"`.
    pub mss_salt_version: u8,
    /// Ordered list of `(tree_position, Reveal)` pairs decoded from the wire map.
    ///
    /// Codec key: `"r"`.
    pub reveals: Vec<(u64, Reveal)>,
    /// Ordered list of tree positions that must be revealed; drives the coin-check loop.
    ///
    /// Codec key: `"pr"`.
    pub positions_to_reveal: Vec<u64>,
}

impl MsgPackDecode for StateProof {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let n = r.read_map_len()?;
        let mut sig_commit = [0u8; SUMHASH512_DIGEST_SIZE];
        let mut signed_weight = 0u64;
        let mut sig_proofs = Proof::<Sumhash512>::new(0, vec![]);
        let mut part_proofs = Proof::<Sumhash512>::new(0, vec![]);
        let mut mss_salt_version = 0u8;
        let mut reveals = Vec::new();
        let mut positions_to_reveal = Vec::new();
        for _ in 0..n {
            match r.read_str()? {
                "c"  => {
                    let b = r.read_bin()?;
                    if b.len() != SUMHASH512_DIGEST_SIZE {
                        return Err(DecodeError::InvalidDigestSize(b.len()));
                    }
                    sig_commit.copy_from_slice(b);
                }
                "w" => signed_weight = r.read_uint()?,
                "S" => sig_proofs = Proof::decode_from(r)?,
                "P" => part_proofs = Proof::decode_from(r)?,
                "v" => mss_salt_version = r.read_uint()? as u8,
                "r" => {
                    let len = r.read_map_len()?;
                    reveals = Vec::with_capacity(len);
                    for _ in 0..len {
                        let pos = r.read_uint()?;
                        let reveal = Reveal::decode_from(r)?;
                        reveals.push((pos, reveal));
                    }
                }
                "pr" => {
                    let len = r.read_array_len()?;
                    positions_to_reveal = Vec::with_capacity(len);
                    for _ in 0..len {
                        positions_to_reveal.push(r.read_uint()?);
                    }
                }
                _ => r.skip()?,
            }
        }
        Ok(Self {
            sig_commitment: sig_commit,
            signed_weight,
            sig_proofs,
            part_proofs,
            mss_salt_version,
            reveals,
            positions_to_reveal,
        })
    }
}

impl StateProof {
    /// Decodes a [StateProof] from Algorand canonical MessagePack wire bytes.
    pub fn from_msgpack(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        StateProof::decode_from(&mut r)
    }
}

// ── StateProofMessage ─────────────────────────────────────────────────────────

/// A post-quantum state proof attesting to the Algorand block state at a given round.
///
/// Received from the network and verified against a known `sig_commit` root and
/// `signed_weight`. Codec keys match the Algorand wire format exactly.
///
/// Codec keys: `"b"`, `"f"`, `"l"`, `"P"`, `"v"`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateProofMessage {
    /// The [merkle::VcTree] `root` over all light block headers within the State Proof 
    /// interval — i.e., the blocks from round first-attested-round to latest-attested-round.
    ///
    /// Codec key: `"b"`.
    pub block_headers_commitment: [u8; SHA256_DIGEST_SIZE],
    /// .
    ///
    /// Codec key: `"f"`.
    pub first_attested_round: u64,
    /// .
    ///
    /// Codec key: `"l"`.
    pub latest_attested_round: u64,

    /// .
    ///
    /// Codec key: `"P"`.
    pub ln_proven_weight: u64,
    /// .
    ///
    /// Codec key: `"v"`.
    pub voters_commitment: Sumhash512Digest,
}