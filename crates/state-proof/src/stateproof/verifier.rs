// crates/state-proof/src/stateproof/verifier.rs

use core::fmt;
use alloc::collections::BTreeMap;

use algorand_falcon_keys::PublicKey;
use merkle::{hash_obj, Hashable, MerkleHasher, Sumhash512, Sumhash512Digest};

use super::constants::{
    DOMAIN_EMPTY_SLOT, DOMAIN_EPHEMERAL_KEY, DOMAIN_PARTICIPANT, DOMAIN_SIG_SLOT,
    LN2_FIXED_POINT, MERKLE_SIG_SCHEME_ID, STRENGTH_TARGET, VC_PROOF_MAX_DEPTH,
};
use super::message::{StateProofMessage, TrustAnchor};
use super::{
    CoinChoiceSeed, CoinGenerator, MessageHash, MerkleSignatureScheme,
    Participant, Reveal, SigSlotCommit, StateProof, ln_int_approximation,
};


// ── VerifyError ───────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum VerifyError {
    /// The `signed_weight` does not exceed `ln_proven_weight` in log-space.
    SignedWeightTooLow,
    /// The number of revealed positions does not satisfy the security-strength inequality.
    InsufficientReveals,
    /// A tree depth exceeds the protocol maximum of 20.
    TreeDepthTooLarge { field: &'static str, depth: u8 },
    /// An ephemeral signature's salt version does not match the proof's declared version.
    SaltVersionMismatch { position: u64 },
    /// A position in `positions_to_reveal` has no corresponding entry in `reveals`.
    MissingReveal { position: u64 },
    /// Batch Merkle proof for the signature commitment failed.
    SigProofFailed,
    /// Batch Merkle proof for the participant commitment failed.
    PartProofFailed,
    /// The Vector Commitment proof for an ephemeral key failed.
    VcProofFailed { position: u64 },
    /// Falcon signature verification failed.
    FalconVerifyFailed { position: u64 },
    /// Failed to convert a Falcon signature to constant-time format for leaf hashing.
    SigConversionFailed { position: u64 },
    /// The generated coin falls outside the participant's declared weight range.
    CoinOutOfRange { index: usize, position: u64, coin: u64 },
    /// The participant's weight range `[l, l + weight)` overflows `u64`; the proof is malformed.
    WeightRangeOverflow { position: u64 },
    /// The `reveals` map contains duplicate positions; the proof is malformed.
    DuplicateRevealPosition,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SignedWeightTooLow =>
                write!(f, "signed weight does not exceed the proven weight threshold"),
            Self::InsufficientReveals =>
                write!(f, "insufficient reveals to satisfy the security-strength inequality"),
            Self::TreeDepthTooLarge { field, depth } =>
                write!(f, "{field} tree depth {depth} exceeds protocol maximum"),
            Self::SaltVersionMismatch { position } =>
                write!(f, "salt version mismatch at reveal position {position}"),
            Self::MissingReveal { position } =>
                write!(f, "no reveal entry for coin position {position}"),
            Self::SigProofFailed =>
                write!(f, "batch Merkle proof for signature commitment failed"),
            Self::PartProofFailed =>
                write!(f, "batch Merkle proof for participant commitment failed"),
            Self::VcProofFailed { position } =>
                write!(f, "ephemeral key VC proof failed at position {position}"),
            Self::FalconVerifyFailed { position } =>
                write!(f, "Falcon signature verification failed at position {position}"),
            Self::SigConversionFailed { position } =>
                write!(f, "failed signature conversion to CT format at position {position}"),
            Self::CoinOutOfRange { index, position, coin } =>
                write!(f, "coin {coin} at index {index} (position {position}) is outside the participant's weight range"),
            Self::WeightRangeOverflow { position } =>
                write!(f, "participant weight range overflows u64 at position {position}"),
            Self::DuplicateRevealPosition =>
                write!(f, "reveals map contains duplicate positions"),
        }
    }
}

impl core::error::Error for VerifyError {}

// ── Leaf-hash helpers ─────────────────────────────────────────────────────────

/// Wraps a [Participant] for hashing as a leaf in the participants [merkle::VcTree].
/// 
/// Domain tag `"spp"` (state-proof participant). 
/// 
/// Layout: `weight(8) || key_lifetime(8) || commitment(64)`.
struct ParticipantLeaf<'a>(&'a Participant);

impl Hashable for ParticipantLeaf<'_> {
    fn hash_into<H: MerkleHasher>(&self, h: &mut H) {
        let p = self.0;
        h.update(DOMAIN_PARTICIPANT);
        h.update(&p.weight.to_le_bytes());
        h.update(&p.pk.key_lifetime.to_le_bytes());
        h.update(&p.pk.commitment);
    }
}

/// Wraps one slot in a [Participant]'s inner ephemeral key rotation schedule for leaf hashing.
///
/// The state proof uses a two-level [merkle::VcTree] structure:
/// * Outer tree (root = `part_commitment`): one [ParticipantLeaf] per participant,
///   containing the participant's weight and the root of their inner key tree.
/// * Inner tree (root = `participant.pk.commitment`): one [CommittablePK] per key
///   rotation window, containing the ephemeral `PublicKey` valid for that window.
///
/// `round` is the start of the current lifetime window (`first_round_in_key_lifetime`),
/// not the exact round being proven — the same key covers the whole window.
///
/// Domain tag `"KP"`. Layout: `crypto_id(2) || round(8) || pubkey(1793)`.
struct CommittablePK<'a> {
    verifying_key: &'a PublicKey,
    round: u64,
}

impl Hashable for CommittablePK<'_> {
    fn hash_into<H: MerkleHasher>(&self, h: &mut H) {
        h.update(DOMAIN_EPHEMERAL_KEY);
        h.update(&MERKLE_SIG_SCHEME_ID.to_le_bytes());
        h.update(&self.round.to_le_bytes());
        h.update(self.verifying_key.as_bytes());
    }
}


/// Returns the leaf digest of `p` for batch VC proof verification against `part_commitment`.
fn hash_participant_leaf(h: &mut Sumhash512, p: &Participant) -> Sumhash512Digest {
    hash_obj(h, &ParticipantLeaf(p))
}

/// Wraps the empty-slot padding constant for hashing.
/// When a participant did not sign, the sig tree leaf is `Hash("MB")`.
struct EmptySigLeaf;
impl Hashable for EmptySigLeaf {
    fn hash_into<H: MerkleHasher>(&self, h: &mut H) {
        h.update(DOMAIN_EMPTY_SLOT);
    }
}

/// Returns true if the sig slot carries no real signature (participant did not sign).
/// A minimal 2-byte compressed sig (header + salt only, zero Falcon data) signals empty.
fn sig_slot_is_empty(slot: &SigSlotCommit) -> bool {
    slot.mss.sig.as_bytes().len() <= 2
}

/// Computes the Sumhash512 leaf digest for `slot` in the sig VC tree.
///
/// Empty slots (participant did not sign) → `Hash("MB")` (the VC bottom leaf).
/// Non-empty slots → `Hash("sps" || L(8 LE) || GetFixedLengthHashableRepresentation(sig))`.
///
/// Feeds bytes directly into the hasher — no intermediate heap allocation.
fn hash_sig_slot_leaf(h: &mut Sumhash512, pos: u64, slot: &SigSlotCommit) -> Result<Sumhash512Digest, VerifyError> {
    if sig_slot_is_empty(slot) {
        return Ok(hash_obj(h, &EmptySigLeaf));
    }

    let sig_repr = slot.mss.to_fixed_bytes()
        .map_err(|_| VerifyError::SigConversionFailed { position: pos })?;

    h.update(DOMAIN_SIG_SLOT);
    h.update(&slot.l.to_le_bytes());
    h.update(&sig_repr);
    Ok(h.finalize_reset())
}

// ── Round alignment ───────────────────────────────────────────────────────────

/// Returns the latest round ≤ `round` that is a multiple of `key_lifetime`.
///
/// An ephemeral key at VC index `i` covers all rounds in the window
/// `[first_round, first_round + key_lifetime)`, so its VC leaf is always hashed
/// with `first_round` regardless of the specific round being proven.
fn first_round_in_key_lifetime(round: u64, key_lifetime: u64) -> u64 {
    if key_lifetime == 0 { return round; }
    round - (round % key_lifetime)
}

// ── Per-reveal verification ───────────────────────────────────────────────────

/// Verifies a single `MerkleSignatureScheme` in two steps:
/// 1. VC proof — proves the ephemeral key is committed at `mss.vc_index` in the participant's key tree.
/// 2. Falcon — proves the ephemeral key signed `msg_hash` for this round.
fn verify_merkle_sig_scheme(
    h: &mut Sumhash512,
    mss: &MerkleSignatureScheme,
    commitment: &Sumhash512Digest,
    round: u64,
    key_lifetime: u64,
    msg_hash: &MessageHash,
    pos: u64,
) -> Result<(), VerifyError> {
    // Align to the lifetime window boundary; the key was committed at this round.
    let valid_round = first_round_in_key_lifetime(round, key_lifetime);

    // Reconstruct the expected VC leaf hash for the ephemeral key at its committed round.
    let leaf = hash_obj(h, &CommittablePK { verifying_key: &mss.verifying_key, round: valid_round });

    // Verify the key is committed at `vc_index` in the participant's key tree.
    // Safe: vc_index is bounded by `key_lifetime`, a small protocol value well within usize.
    if !mss.proof.verify_vc(leaf, mss.vc_index as usize, commitment) {
        return Err(VerifyError::VcProofFailed { position: pos });
    }

    // Verify the Falcon signature over the attested message against the ephemeral key.
    mss.verifying_key
        .verify_compressed(&mss.sig, msg_hash)
        .map_err(|_| VerifyError::FalconVerifyFailed { position: pos })
}

// ── Public verifier ───────────────────────────────────────────────────────────

/// Verifies a `StateProof` against trusted parameters.
///
/// On success returns the `TrustAnchor` for the *next* interval, extracted from
/// `message`. Chain calls by passing each returned anchor as the next `anchor`.
///
/// ### Parameters
/// * `state_proof` — decoded from the State Proof transaction wire bytes.
/// * `message`     — the `StateProofMessage` from the same transaction.
/// * `anchor`      — trusted `part_commitment` and `ln_proven_weight` from the *previous* interval's `StateProofMessage`.
pub fn verify_state_proof(
    state_proof: &StateProof,
    message: &StateProofMessage,
    anchor: &TrustAnchor,
) -> Result<TrustAnchor, VerifyError> {
    let part_commitment = &anchor.part_commitment;
    let ln_proven_weight = anchor.ln_proven_weight;
    let round = message.last_attested_round;
    let msg_hash = message.hash();
    // ── 1. Reject trees that exceed the protocol depth limit ──────────────────
    if state_proof.sig_proofs.tree_depth > VC_PROOF_MAX_DEPTH {
        return Err(VerifyError::TreeDepthTooLarge {
            field: "sig_proofs",
            depth: state_proof.sig_proofs.tree_depth,
        });
    }
    if state_proof.part_proofs.tree_depth > VC_PROOF_MAX_DEPTH {
        return Err(VerifyError::TreeDepthTooLarge {
            field: "part_proofs",
            depth: state_proof.part_proofs.tree_depth,
        });
    }

    // ── 2. Weight check ───────────────────────────────────────────────────────
    let ln_signed = ln_int_approximation(state_proof.signed_weight)
        .ok_or(VerifyError::SignedWeightTooLow)?;
    if ln_signed <= ln_proven_weight {
        return Err(VerifyError::SignedWeightTooLow);
    }
    // Full strength inequality: numReveals · (ln_signed − ln_proven_weight) ≥ strength_target · ln2
    // Both sides fit in u128 (reveals ≤ 2^20, denom ≤ 2^22 → product ≤ 2^42).
    let denom = ln_signed - ln_proven_weight;
    let lhs = state_proof.positions_to_reveal.len() as u128 * denom as u128;
    let rhs = STRENGTH_TARGET as u128 * LN2_FIXED_POINT as u128;
    if lhs < rhs {
        return Err(VerifyError::InsufficientReveals);
    }

    // ── 3. Build reveal index; reject duplicate reveal positions ─────────────
    // positions_to_reveal can contain repeated values (multiple coins landing on the
    // same heavy participant), so reveals.len() ≤ positions_to_reveal.len() is normal.
    let reveal_map: BTreeMap<u64, &Reveal> =
        state_proof.reveals.iter().map(|(pos, r)| (*pos, r)).collect();
    // BTreeMap deduplicates by key; a smaller map means the wire data had duplicate positions.
    if reveal_map.len() != state_proof.reveals.len() {
        return Err(VerifyError::DuplicateRevealPosition);
    }

    // ── 4. Per-reveal: salt check + VC proof + Falcon + build batch-proof lists ─
    // A single Sumhash512 context is shared across all calls; `hash_obj`
    // resets the hasher internally so each call is independent.
    let mut h = Sumhash512::new();
    let mut sig_elems: Vec<(usize, Sumhash512Digest)> =
        Vec::with_capacity(state_proof.reveals.len());
    let mut part_elems: Vec<(usize, Sumhash512Digest)> =
        Vec::with_capacity(state_proof.reveals.len());

    for &(pos, ref reveal) in &state_proof.reveals {
        let empty = sig_slot_is_empty(&reveal.sig_slot);

        // All non-empty reveals must share the same salt version.
        if !empty && reveal.sig_slot.mss.salt_version() != state_proof.mss_salt_version {
            return Err(VerifyError::SaltVersionMismatch { position: pos });
        }

        // Empty slots (participant did not sign) skip Falcon+VC proof — their sig leaf is Hash("MB").
        if !empty {
            verify_merkle_sig_scheme(
                &mut h,
                &reveal.sig_slot.mss,
                &reveal.participant.pk.commitment,
                round,
                reveal.participant.pk.key_lifetime,
                &msg_hash,
                pos,
            )?;
        }

        // Safe: tree positions are bounded by tree depth ≤ 20 (< 2^20), well within usize on all platforms.
        sig_elems.push((pos as usize, hash_sig_slot_leaf(&mut h, pos, &reveal.sig_slot)?));
        part_elems.push((pos as usize, hash_participant_leaf(&mut h, &reveal.participant)));
    }

    // ── 5. Batch VC proof for the signature commitment ────────────────────────
    if !state_proof.sig_proofs.verify_batch_vc(&sig_elems, &state_proof.sig_commitment) {
        return Err(VerifyError::SigProofFailed);
    }

    // ── 6. Batch VC proof for the participant commitment ──────────────────────
    if !state_proof.part_proofs.verify_batch_vc(&part_elems, part_commitment) {
        return Err(VerifyError::PartProofFailed);
    }

    // ── 7. Coin generation and weight-range check ─────────────────────────────
    let seed = CoinChoiceSeed {
        part_commitment: *part_commitment,
        ln_proven_weight,
        sig_commitment: state_proof.sig_commitment,
        signed_weight: state_proof.signed_weight,
        message_hash: msg_hash,
    };
    
    let mut coins = CoinGenerator::new(&seed);

    for (i, &pos) in state_proof.positions_to_reveal.iter().enumerate() {
        // MissingReveal fires if a coin lands on a position that has no corresponding reveal entry.
        let reveal = reveal_map.get(&pos).copied()
            .ok_or(VerifyError::MissingReveal { position: pos })?;
        let coin = coins.next_coin();
        let l     = reveal.sig_slot.l;
        let upper = l.checked_add(reveal.participant.weight)
            .ok_or(VerifyError::WeightRangeOverflow { position: pos })?;
        
        if coin < l || coin >= upper {
            return Err(VerifyError::CoinOutOfRange { index: i, position: pos, coin });
        }
    }

    Ok(TrustAnchor::from(message))
}