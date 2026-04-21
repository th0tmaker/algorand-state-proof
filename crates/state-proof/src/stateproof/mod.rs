// crates/state-proof/src/stateproof/mod.rs

mod coin;
mod verifier;

#[allow(unused)]
pub use coin::{CoinChoiceSeed, CoinGenerator, ln_int_approximation};
pub use verifier::{VerifyError, verify_state_proof};

use algorand_falcon_keys::{CompressedSignature, PublicKey, FALCON_DET1024_PUBKEY_SIZE};
use merkle::{Sumhash512Digest, SUMHASH512_DIGEST_SIZE, Proof};

use crate::codec::{DecodeError, MsgPackDecode, Reader};

// ── FalconVerifier ────────────────────────────────────────────────────────────

/// Wraps a deterministic `Falcon-1024` [PublicKey] used to verify a single round's ephemeral [CompressedSignature].
///
/// Codec key: `"k"`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FalconVerifier {
    /// Deterministic Falcon-1024 [PublicKey].
    ///
    /// Codec key: `"k"`.
    pub public_key: PublicKey
}

impl Default for FalconVerifier {
    fn default() -> Self {
        Self { public_key: PublicKey::from_bytes(&[0u8; FALCON_DET1024_PUBKEY_SIZE]).unwrap() }
    }
}

impl MsgPackDecode for FalconVerifier {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let n = r.read_map_len()?;
        let mut bytes = [0u8; FALCON_DET1024_PUBKEY_SIZE];
        for _ in 0..n {
            match r.read_str()? {
                "k" => {
                    let b = r.read_bin()?;
                    if b.len() != FALCON_DET1024_PUBKEY_SIZE {
                        return Err(DecodeError::InvalidDigestSize(b.len()));
                    }
                    bytes.copy_from_slice(b);
                }
                _ => r.skip()?,
            }
        }
        let public_key = PublicKey::from_bytes(&bytes)
            .map_err(|_| DecodeError::InvalidDigestSize(0))?;
        Ok(Self { public_key })
    }
}

// ── FalconSignature ───────────────────────────────────────────────────────────

/// Wraps a variable-length deterministic `Falcon-1024` [CompressedSignature].
///
/// Codec key: `"sig"`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FalconSignature {
    /// A Falcon-1024 [CompressedSignature].
    ///
    /// Codec key: `"sig"`.
    pub sig: CompressedSignature,
}

impl Default for FalconSignature {
    fn default() -> Self {
        // Minimal valid compressed-signature shell: header byte + 1-byte salt version.
        Self {
            sig: CompressedSignature::from_bytes(
                &[algorand_falcon_keys::FALCON_DET1024_SIG_COMPRESSED_HEADER, 0]).unwrap()
        }
    }
}

impl MsgPackDecode for FalconSignature {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        // Falcon signature is encoded as binary on the wire; raw blob of bytes 
        let b = r.read_bin()?;
        CompressedSignature::from_bytes(b)
            .map(|sig| Self { sig })
            .map_err(|_| DecodeError::InvalidDigestSize(b.len()))
    }
}

// ── MerkleVerifier ────────────────────────────────────────────────────────────

/// Identifies a participant's long-term Merkle signing key.
///
/// Codec keys: `"cmt"`, `"lf"`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MerkleVerifier {
    /// [Sumhash512Digest] root commitment of the participant's ephemeral [PublicKey] tree.
    ///
    /// Codec key: `"cmt"`.
    pub commitment: Sumhash512Digest,
    /// Interval in rounds between ephemeral key rotations; a [FalconVerifier] at index `i`
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

// ── MerkleSignature ───────────────────────────────────────────────────────────

/// A single-round [FalconSignature] bundled with its Merkle membership [merkle::Proof],
/// proving that the signing key is committed to in the participant's long-term [merkle::VcTree].
///
/// Codec keys: `"sig"`, `"idx"`, `"prf"`, `"vkey"`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MerkleSignature {
    /// The ephemeral [FalconSignature] over the attested message for this round.
    ///
    /// Codec key: `"sig"`.
    pub sig: FalconSignature,
    /// Leaf index in the [merkle::VcTree] identifying which ephemeral key was used to sign.
    ///
    /// Codec key: `"idx"`.
    pub vc_index: u64,
    /// Merkle membership [merkle::Proof] authenticating `verifying_key` against the VC root.
    ///
    /// Codec key: `"prf"`.
    pub proof: Proof,
    /// Ephemeral [FalconVerifier] whose public key signed this round.
    ///
    /// Codec key: `"vkey"`.
    pub verifying_key: FalconVerifier,
}

impl Default for MerkleSignature {
    fn default() -> Self {
        Self {
            sig: FalconSignature::default(),
            vc_index: 0,
            proof: Proof::new(0, vec![]),
            verifying_key: FalconVerifier::default(),
        }
    }
}

impl MerkleSignature {
    /// Serializes `self` into the SNARK-friendly fixed-length binary format used as
    /// leaf data in the state-proof signature tree.
    ///
    /// Format: `CryptoPrimitivesID(2 LE) || sig_ct(1538) || pubkey(1793) || vc_index(8 LE) || proof_fixed_repr`
    pub(crate) fn fixed_len_repr(&self) -> Result<Vec<u8>, algorand_falcon_keys::Error> {
        let ct = self.sig.sig.to_ct()?;
        let mut out = Vec::new();
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(ct.as_bytes());
        out.extend_from_slice(self.verifying_key.public_key.as_bytes());
        out.extend_from_slice(&self.vc_index.to_le_bytes());
        out.extend_from_slice(&self.proof.to_fixed_bytes());
        Ok(out)
    }
}

impl MsgPackDecode for MerkleSignature {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let n = r.read_map_len()?;
        let mut out = MerkleSignature::default();
        for _ in 0..n {
            match r.read_str()? {
                "sig" => out.sig = FalconSignature::decode_from(r)?,
                "idx" => out.vc_index = r.read_uint()?,
                "prf" => out.proof = Proof::decode_from(r)?,
                "vkey" => out.verifying_key = FalconVerifier::decode_from(r)?,
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
    /// The participant's [MerkleSignature] over the attested message; authenticated via `sig_proofs`.
    ///
    /// Codec key: `"s"`.
    pub sig: MerkleSignature,
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
                "s" => out.sig = MerkleSignature::decode_from(r)?,
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
                _   => r.skip()?,
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
    /// The committed signature slot containing the [MerkleSignature] and cumulative weight.
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
#[derive(Clone, Debug)]
pub struct StateProof {
    /// [Sumhash512Digest] root commitment of the signature [merkle::VcTree].
    ///
    /// Codec key: `"c"`.
    pub sig_commit: Sumhash512Digest,
    /// Total stake weight of all participants who signed.
    ///
    /// Codec key: `"w"`.
    pub signed_weight: u64,
    /// Batch [merkle::Proof] authenticating all revealed [SigSlotCommit] leaves against `sig_commit`.
    ///
    /// Codec key: `"S"`.
    pub sig_proofs: Proof,
    /// Batch [merkle::Proof] authenticating all revealed [Participant] leaves against the trusted participant commitment.
    ///
    /// Codec key: `"P"`.
    pub part_proofs: Proof,
    /// Salt version used when hashing ephemeral keys; must match across all reveals.
    ///
    /// Codec key: `"v"`.
    pub merkle_sig_salt_version: u8,
    /// Map from tree position to the corresponding [Reveal] data.
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
        let mut sig_proofs = Proof::new(0, vec![]);
        let mut part_proofs = Proof::new(0, vec![]);
        let mut merkle_sig_salt_version = 0u8;
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
                "v" => merkle_sig_salt_version = r.read_uint()? as u8,
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
            sig_commit,
            signed_weight,
            sig_proofs,
            part_proofs,
            merkle_sig_salt_version,
            reveals,
            positions_to_reveal,
        })
    }
}
