// crates/state-proof/src/stateproof/mod.rs

use merkle::{Digest, DIGEST_SIZE, Proof};

use crate::codec::{DecodeError, MsgPackDecode, Reader};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Byte length of a Falcon-512 public key.
const FALCON_PUBLIC_KEY_SIZE: usize = 897;

// ── FalconPublicKey ───────────────────────────────────────────────────────────

/// A Falcon public key used to verify a single-round ephemeral signature.
/// Heap-allocated to avoid placing ~900 bytes on the stack.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FalconPublicKey(pub Box<[u8]>);

impl Default for FalconPublicKey {
    fn default() -> Self {
        Self(vec![0u8; FALCON_PUBLIC_KEY_SIZE].into_boxed_slice())
    }
}

impl MsgPackDecode for FalconPublicKey {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let b = r.read_bin()?;
        if b.len() != FALCON_PUBLIC_KEY_SIZE {
            return Err(DecodeError::InvalidDigestSize(b.len()));
        }
        Ok(Self(b.to_vec().into_boxed_slice()))
    }
}

// ── FalconVerifier ────────────────────────────────────────────────────────────

/// Wraps a Falcon public key; used to verify a single round's ephemeral signature.
/// Codec key: `"k"`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FalconVerifier {
    pub public_key: FalconPublicKey, // "k"
}

impl MsgPackDecode for FalconVerifier {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let n = r.read_map_len()?;
        let mut public_key = FalconPublicKey::default();
        for _ in 0..n {
            match r.read_str()? {
                "k" => public_key = FalconPublicKey::decode_from(r)?,
                _   => r.skip()?,
            }
        }
        Ok(Self { public_key })
    }
}

// ── FalconSignature ───────────────────────────────────────────────────────────

/// A variable-length Falcon signature byte blob. Codec key: `"sig"`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FalconSignature(pub Vec<u8>);

impl MsgPackDecode for FalconSignature {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self(r.read_bin()?.to_vec()))
    }
}

// ── MerkleVerifier ────────────────────────────────────────────────────────────

/// Identifies a participant's long-term Merkle signing key.
/// Codec keys: `"cmt"` (commitment root), `"lf"` (key lifetime in rounds).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MerkleVerifier {
    pub commitment:   Digest, // "cmt"
    pub key_lifetime: u64,    // "lf"
}

impl Default for MerkleVerifier {
    fn default() -> Self {
        Self { commitment: [0u8; DIGEST_SIZE], key_lifetime: 0 }
    }
}

impl MsgPackDecode for MerkleVerifier {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let n = r.read_map_len()?;
        let mut commitment = [0u8; DIGEST_SIZE];
        let mut key_lifetime = 0u64;
        for _ in 0..n {
            match r.read_str()? {
                "cmt" => {
                    let b = r.read_bin()?;
                    if b.len() != DIGEST_SIZE {
                        return Err(DecodeError::InvalidDigestSize(b.len()));
                    }
                    commitment.copy_from_slice(b);
                }
                "lf" => key_lifetime = r.read_uint()?,
                _    => r.skip()?,
            }
        }
        Ok(Self { commitment, key_lifetime })
    }
}

// ── MerkleSignature ───────────────────────────────────────────────────────────

/// A single-round Falcon signature bundled with its Merkle membership proof,
/// proving that the signing key is committed to in the participant's long-term tree.
///
/// Codec keys: `"sig"`, `"idx"`, `"prf"`, `"vkey"`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MerkleSignature {
    pub sig:          FalconSignature, // "sig"
    pub vc_index:     u64,             // "idx"
    pub proof:        Proof,           // "prf"
    pub verifying_key: FalconVerifier, // "vkey"
}

impl Default for MerkleSignature {
    fn default() -> Self {
        Self {
            sig:          FalconSignature::default(),
            vc_index:     0,
            proof:        Proof::new(0, vec![]),
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
                "sig"  => out.sig          = FalconSignature::decode_from(r)?,
                "idx"  => out.vc_index     = r.read_uint()?,
                "prf"  => out.proof        = Proof::decode_from(r)?,
                "vkey" => out.verifying_key = FalconVerifier::decode_from(r)?,
                _      => r.skip()?,
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
    pub sig_commit:               Digest,          // "c"
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
        let mut sig_commit              = [0u8; DIGEST_SIZE];
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
                    if b.len() != DIGEST_SIZE {
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
