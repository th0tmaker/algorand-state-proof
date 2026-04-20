// crates/state-proof/src/stateproof/mod.rs

mod coin;
#[allow(unused)]
pub use coin::{CoinChoiceSeed, CoinGenerator, ln_int_approximation};

use algorand_falcon_keys::{CompressedSignature, PublicKey, FALCON_DET1024_PUBKEY_SIZE};
use merkle::{Sumhash512Digest, SUMHASH512_DIGEST_SIZE, Proof};

use crate::codec::{DecodeError, MsgPackDecode, Reader};

// ── FalconVerifier ────────────────────────────────────────────────────────────

/// Wraps around a deterministic `Falcon-1024` [`PublicKey`];
/// used to verify a single round's ephemeral [`CompressedSignature`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FalconVerifier {
    /// Deterministic Falcon-1024 [`PublicKey`]; Wire codec key: `"k"` 
    pub public_key: PublicKey  // "k"
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

/// Wraps around a variable-length deterministic `Falcon-1024` [`CompressedSignature`].
/// Codec key: `"sig"`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FalconSignature {
    /// a Falcon-1024 [`CompressedSignature`]; Wire codec key: `"sig"` 
    pub sig: CompressedSignature, // "sig"
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
/// Codec keys: `"cmt"` (commitment root), `"lf"` (key lifetime in rounds).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MerkleVerifier {
    /// The commitment is a [`Sumhash512Digest`]; Wire codec key: `"cmt"` 
    pub commitment: Sumhash512Digest,  // "cmt"
    /// The interval (in rounds) between ephemeral key rotations. Specifically,
    /// a [`FalconVerifier`] (ephemeral [`PublicKey`]) at index i in the Merkle
    /// [`merkle::VcTree`] is valid for signing round `first_valid + i * key_lifetime`;
    /// Wire codec key: `"lf"`
    pub key_lifetime: u64,  // "lf"
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

/// A single-round [`FalconSignature`] bundled with its Merkle membership 
/// [`merkle::Proof`], proving that the signing [`FalconVerifier::public_key`]
/// is committed to in the participant's long-term [`merkle::VcTree`].
///
/// Codec keys: `"sig"`, `"idx"`, `"prf"`, `"vkey"`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MerkleSignature {
    /// A single-round [`FalconSignature`].
    pub sig: FalconSignature,  // "sig"
    /// The leaf index in the Merkle [`merkle::VcTree`] that
    /// identifies which key was used to sign.
    pub vc_index: u64,  // "idx"
    /// Merkle membership [`merkle::Proof`].
    pub proof: Proof,  // "prf"
    /// Participant signing [`FalconVerifier::public_key`].
    pub verifying_key: FalconVerifier,  // "vkey"
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
/// `l` used for coin-range verification. Codec keys: `"s"`, `"l"`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SigSlotCommit {
    pub sig: MerkleSignature, // "s"
    pub l:   u64,             // "l"
}

impl MsgPackDecode for SigSlotCommit {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let n = r.read_map_len()?;
        let mut out = SigSlotCommit::default();
        for _ in 0..n {
            match r.read_str()? {
                "s" => out.sig = MerkleSignature::decode_from(r)?,
                "l" => out.l   = r.read_uint()?,
                _   => r.skip()?,
            }
        }
        Ok(out)
    }
}

// ── Participant ───────────────────────────────────────────────────────────────

/// An online account that participated in signing the state proof.
/// Codec keys: `"p"` (Merkle verifier), `"w"` (stake weight).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Participant {
    pub pk:     MerkleVerifier, // "p"
    pub weight: u64,            // "w"
}

impl MsgPackDecode for Participant {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let n = r.read_map_len()?;
        let mut out = Participant::default();
        for _ in 0..n {
            match r.read_str()? {
                "p" => out.pk     = MerkleVerifier::decode_from(r)?,
                "w" => out.weight = r.read_uint()?,
                _   => r.skip()?,
            }
        }
        Ok(out)
    }
}

// ── Reveal ────────────────────────────────────────────────────────────────────

/// A revealed slot in the state proof: the signature commitment and the
/// participant data, both authenticated via Merkle proofs in [`StateProof`].
/// Codec keys: `"s"` (sig slot), `"p"` (participant).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Reveal {
    pub sig_slot:    SigSlotCommit, // "s"
    pub participant: Participant,   // "p"
}

impl MsgPackDecode for Reveal {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let n = r.read_map_len()?;
        let mut out = Reveal::default();
        for _ in 0..n {
            match r.read_str()? {
                "s" => out.sig_slot    = SigSlotCommit::decode_from(r)?,
                "p" => out.participant = Participant::decode_from(r)?,
                _   => r.skip()?,
            }
        }
        Ok(out)
    }
}

// ── StateProof ────────────────────────────────────────────────────────────────

/// A post-quantum state proof attesting to the Algorand block state at a given round.
///
/// Received from the network and verified against a known [`sig_commit`] root and
/// [`signed_weight`]. Codec keys match the Algorand wire format exactly.
#[derive(Clone, Debug)]
pub struct StateProof {
    pub sig_commit:               Sumhash512Digest,          // "c"
    pub signed_weight:            u64,             // "w"
    pub sig_proofs:               Proof,           // "S"
    pub part_proofs:              Proof,           // "P"
    pub merkle_sig_salt_version:  u8,              // "v"
    pub reveals:                  Vec<(u64, Reveal)>, // "r"
    pub positions_to_reveal:      Vec<u64>,        // "pr"
}

impl MsgPackDecode for StateProof {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let n = r.read_map_len()?;
        let mut sig_commit              = [0u8; SUMHASH512_DIGEST_SIZE];
        let mut signed_weight           = 0u64;
        let mut sig_proofs              = Proof::new(0, vec![]);
        let mut part_proofs             = Proof::new(0, vec![]);
        let mut merkle_sig_salt_version = 0u8;
        let mut reveals                 = Vec::new();
        let mut positions_to_reveal     = Vec::new();
        for _ in 0..n {
            match r.read_str()? {
                "c"  => {
                    let b = r.read_bin()?;
                    if b.len() != SUMHASH512_DIGEST_SIZE {
                        return Err(DecodeError::InvalidDigestSize(b.len()));
                    }
                    sig_commit.copy_from_slice(b);
                }
                "w"  => signed_weight           = r.read_uint()?,
                "S"  => sig_proofs              = Proof::decode_from(r)?,
                "P"  => part_proofs             = Proof::decode_from(r)?,
                "v"  => merkle_sig_salt_version = r.read_uint()? as u8,
                "r"  => {
                    let len = r.read_map_len()?;
                    reveals = Vec::with_capacity(len);
                    for _ in 0..len {
                        let pos    = r.read_uint()?;
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
                _    => r.skip()?,
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
