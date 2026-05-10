// crates/state-proof/src/stateproof/mod.rs

mod coin;
pub(crate) mod constants;
mod message;
pub(crate) mod specs;
mod verify;

pub use message::{StateProofMessage, TrustAnchor};
pub use verify::{VerifyError, verify_state_proof};

pub(crate) use coin::{CoinChoiceSeed, CoinGenerator, ln_int_approximation};
use constants::{MAX_REVEALS, MERKLE_SIG_SCHEME_FIXED_REPR_SIZE, MSS_CRYPTO_SUITE_ID, MSS_VC_MAX_DEPTH};

use algorand_falcon_keys::{
    CompressedSignature, PublicKey,
    FALCON_DET1024_PUBKEY_SIZE, FALCON_DET1024_SIG_COMPRESSED_HEADER, FALCON_DET1024_SIG_CT_SIZE,
};
use merkle::{Proof, Sumhash512, Sumhash512Digest, SUMHASH512_DIGEST_SIZE};

use crate::codec::{DecodeError, MsgPackDecode, Reader};

/// A 256-bit hash digest of the State Proof message — the exact value signed 
/// by each participating account using their ephemeral Falcon key.
///
/// Each participant in the State Proof protocol signs this hash (rather than the
/// full message) to attest that the block interval commitment it represents is
/// legitimate. The collective weight of all participants who have signed this value
/// is what a State Proof verifier ultimately confirms.
///
/// This hash also feeds directly into the `Shake256`-based coin derivation used
/// to pseudorandomly select which signature slots are revealed in the proof:
///
/// `Shake256("spc" || Version || ParticipantCommitment || ln(ProvenWeight)
///           || SignatureCommitment || SignedWeight || MessageHash`
///
/// A `MessageHash` can be produced via [StateProofMessage::hash].
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

/// The verifying key for a participant's Merkle signature scheme.
///
/// Together, `commitment` and `key_lifetime` form everything needed to
/// verify any signature the participant produces during their participation
/// period: `commitment` authenticates that an ephemeral key belongs to their
/// pre-registered key tree, and `key_lifetime` determines which leaf in that
/// tree corresponds to a given round (`round / key_lifetime`).
///
/// Registered on-chain as the participant's stable state proof identity
/// (`StateProofPK`).
///
/// Wire codec keys: `"cmt"`, `"lf"`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MerkleVerifier {
    /// `Sumhash512` VC root over all ephemeral public keys for the participant's participation period.
    ///
    /// Wire codec key: `"cmt"`.
    pub commitment: Sumhash512Digest,
    /// Number of consecutive rounds each ephemeral key covers. Determines key epoch boundaries —
    /// see [`key_epoch_start`](Self::key_epoch_start).
    ///
    /// Wire codec key: `"lf"`.
    pub key_lifetime: u64,
}

impl MerkleVerifier {
    /// Returns the start of the key epoch containing `round`.
    ///
    /// Snaps `round` down to the nearest multiple of `key_lifetime` — the epoch
    /// boundary at which the corresponding ephemeral key was generated. This is
    /// the round encoded in the ephemeral key VC leaf when verifying the MSS proof.
    pub(crate) fn key_epoch_start(&self, round: u64) -> u64 {
        if self.key_lifetime == 0 { return round; }
        round - (round % self.key_lifetime)
    }
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

/// One participant's complete Merkle signature over a `MessageHash`.
///
/// Bundles the Falcon signature, the ephemeral key that produced it, the
/// leaf index of that key in the participant's pre-registered key tree, and
/// the Merkle proof authenticating the key against `MerkleVerifier::commitment`.
///
/// Wire codec keys: `"sig"`, `"idx"`, `"prf"`, `"vkey"`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MerkleSignatureScheme {
    /// The Falcon signature over the attested `MessageHash` for this interval.
    ///
    /// Wire codec key: `"sig"`.
    pub signature: CompressedSignature,
    /// The leaf index of `verifying_key` in the participant's key tree.
    ///
    /// Derived from the signed round: `round / key_lifetime`. Used together
    /// with `proof` to authenticate `verifying_key` against
    /// [`MerkleVerifier::commitment`].
    ///
    /// Wire codec key: `"idx"`.
    pub vc_index: u64,
    /// Merkle membership proof authenticating `verifying_key` against the
    /// participant's `MerkleVerifier::commitment`.
    ///
    /// Wire codec key: `"prf"`.
    pub proof: Proof<Sumhash512>,
    /// Ephemeral Falcon verifying key used to verify `signature`.
    ///
    /// Wire codec key: `"vkey"`.
    pub verifying_key: PublicKey,
}

impl Default for MerkleSignatureScheme {
    fn default() -> Self {
        Self {
            signature: CompressedSignature::from_bytes(&[FALCON_DET1024_SIG_COMPRESSED_HEADER, 0]).unwrap(),
            vc_index: 0,
            proof: Proof::<Sumhash512>::new(0, vec![]),
            verifying_key: PublicKey::from_bytes(&[0u8; FALCON_DET1024_PUBKEY_SIZE]).unwrap(),
        }
    }
}

impl MerkleSignatureScheme {
    /// Returns the fixed-length binary representation used as the payload in the `"sps"` sig slot leaf.
    /// See [`specs`](stateproof::specs) for the full layout.
    pub(crate) fn to_bytes(&self) -> Result<[u8; MERKLE_SIG_SCHEME_FIXED_REPR_SIZE], algorand_falcon_keys::Error> {
        // Convert Falcon signature from compressed to constant-time (ct) format.
        let ct = self.signature.to_ct()?;

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

        // The remaining buffer, up to its total fixed size, will be filled with padding.
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
        self.signature.salt_version()
    }
}

impl MsgPackDecode for MerkleSignatureScheme {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let n = r.read_map_len()?;
        let mut out = MerkleSignatureScheme::default();
        for _ in 0..n {
            match r.read_str()? {
                "sig" => out.signature = CompressedSignature::decode_from(r)?,
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

/// The data committed into one slot of the signature array.
///
/// Contains the participant's Merkle signature and `l`, the cumulative
/// weight of all slots below this one. Together with the participant's
/// `signed_weight`, `l` defines the coin range `[l, l + signed_weight)`
/// used in the weight-interval check.
///
/// Wire codec keys: `"s"`, `"l"`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SigSlotCommit {
    /// The participant's Merkle signature over the `MessageHash`;
    /// authenticated against `StateProof::sig_commitment` via
    /// `StateProof::sig_proofs`.
    ///
    /// Wire codec key: `"s"`.
    pub mss: MerkleSignatureScheme,
    /// Cumulative weight of signatures in all slots below this one;
    /// defines this slot's coin range `[l, l + weight)`.
    ///
    /// Wire codec key: `"l"`.
    pub l: u64,
}

impl SigSlotCommit {
    /// Returns `true` if the participant did not sign — indicated by a minimal
    /// 2-byte compressed signature (header + salt only, no Falcon data).
    pub(crate) fn is_empty(&self) -> bool {
        self.mss.signature.as_bytes().len() <= 2
    }
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

/// An online account that participated in signing a given `MessageHash`.
///
/// Codec keys: `"p"`, `"w"`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Participant {
    /// The participant's [`MerkleVerifier`]: verifying key and key lifetime.
    ///
    /// Codec key: `"p"`.
    pub pk: MerkleVerifier,
    /// This participant's individual stake weight.
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

/// The data opened at one pseudorandomly challenged position in the proof.
///
/// Each `Reveal` pairs one entry from the signature array (`sig_slot`) with
/// the matching entry from the participants array (`participant`). Together
/// they let the verifier confirm: the participant signed the `MessageHash`,
/// and their stake satisfies the weight-interval check for the corresponding coin.
///
/// Keyed by array position in [`StateProof::reveals`].
///
/// Codec keys: `"s"`, `"p"`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Reveal {
    /// The signature slot at this position: the participant's `MerkleSignatureScheme`
    /// and cumulative weight `l`, used for the weight-interval check.
    ///
    /// Codec key: `"s"`.
    pub sig_slot: SigSlotCommit,
    /// The participant at this position: their `MerkleVerifier` (verifying key)
    /// and stake weight, used for the weight-interval check.
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

/// Compact certificate proving a quorum of Algorand's online stake holders
/// agreed on a block interval commitment spanning 256 consecutive rounds.
///
/// Rather than carrying every signature, a `StateProof` commits to the full
/// signer set via `sig_commitment` and `signed_weight`, then reveals only a
/// pseudorandomly selected subset — chosen via SHAKE-256 coin toss — sufficient
/// to prove that total signed stake exceeds `ProvenWeight` (≥ 30% of online
/// stake). Two Merkle proofs (`sig_proofs`, `part_proofs`) authenticate the
/// revealed entries against both commitments.
///
/// Verified by [`verify_state_proof`] against a trusted [`TrustAnchor`].
///
/// Wire codec keys: `"c"`, `"w"`, `"S"`, `"P"`, `"v"`, `"r"`, `"pr"`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateProof {
    /// VC root over the entire signature array (all signers, not just the revealed ones).
    ///
    /// Wire codec key: `"c"`.
    pub sig_commitment: Sumhash512Digest,
    /// Total stake of all signers in this proof.
    ///
    /// Wire codec key: `"w"`.
    pub signed_weight: u64,
    /// Merkle proof authenticating the revealed `SigSlotCommit` leaves against `sig_commitment`.
    ///
    /// Wire codec key: `"S"`.
    pub sig_proofs: Proof<Sumhash512>,
    /// Merkle proof authenticating the revealed `Participant`
    /// leaves against `TrustAnchor::part_commitment`.
    ///
    /// Wire codec key: `"P"`.
    pub part_proofs: Proof<Sumhash512>,
    /// Salt version all Falcon signatures in `reveals` must match.
    ///
    /// Wire codec key: `"v"`.
    pub mss_salt_version: u8,
    /// Ordered sequence of (position, [`Reveal`]) pairs decoded from the wire map.
    ///
    /// Wire codec key: `"r"`.
    pub reveals: Vec<(u64, Reveal)>,
    /// Array position for each coin, in coin-index order.
    ///
    /// `positions_to_reveal[i]` is the array position whose `Reveal`
    /// must satisfy the weight-interval check for coin `i`.
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