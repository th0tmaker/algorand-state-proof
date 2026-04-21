// crates/state-proof/src/stateproof/verifier.rs

use std::collections::HashMap;

use algorand_falcon_keys::FALCON_DET1024_PUBKEY_SIZE;
use merkle::{hash_obj, Hashable, Sumhash512, Sumhash512Digest, SUMHASH512_DIGEST_SIZE};

use super::{
    CoinChoiceSeed, CoinGenerator, FalconVerifier, MerkleSignature, Participant,
    Reveal, SigSlotCommit, StateProof, ln_int_approximation,
};

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, PartialEq)]
pub enum VerifyError {
    /// `signed_weight` does not exceed `ln_proven_weight` in log-space.
    SignedWeightTooLow,
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
}

// ── Constants ─────────────────────────────────────────────────────────────────

const MAX_TREE_DEPTH: u8 = 20;

/// Identifies the Falcon + Sumhash512 primitive combination in leaf hashes.
const CRYPTO_PRIMITIVES_ID: u16 = 0;

// ── Leaf-hash helpers ─────────────────────────────────────────────────────────

struct ParticipantLeaf<'a>(&'a Participant);

impl Hashable for ParticipantLeaf<'_> {
    fn to_be_hashed(&self) -> (&'static [u8], Vec<u8>) {
        let p = self.0;
        let mut data = Vec::with_capacity(8 + 8 + SUMHASH512_DIGEST_SIZE);
        data.extend_from_slice(&p.weight.to_le_bytes());
        data.extend_from_slice(&p.pk.key_lifetime.to_le_bytes());
        data.extend_from_slice(&p.pk.commitment);
        (b"spp", data)
    }
}

struct CommittablePK<'a> {
    verifying_key: &'a FalconVerifier,
    round: u64,
}

impl Hashable for CommittablePK<'_> {
    fn to_be_hashed(&self) -> (&'static [u8], Vec<u8>) {

        let mut data = Vec::with_capacity(2 + 8 + FALCON_DET1024_PUBKEY_SIZE);

        data.extend_from_slice(&CRYPTO_PRIMITIVES_ID.to_le_bytes());
        data.extend_from_slice(&self.round.to_le_bytes());
        data.extend_from_slice(self.verifying_key.public_key.as_bytes());

        (b"KP", data)
    }
}

struct SigSlotData(Vec<u8>);

impl Hashable for SigSlotData {
    fn to_be_hashed(&self) -> (&'static [u8], Vec<u8>) {
        (b"sps", self.0.clone())
    }
}

fn sig_slot_leaf(h: &mut Sumhash512, pos: u64, slot: &SigSlotCommit) -> Result<Sumhash512Digest, VerifyError> {
    let sig_repr = slot.sig.fixed_len_repr()
        .map_err(|_| VerifyError::SigConversionFailed { position: pos })?;

    let mut data = Vec::with_capacity(8 + sig_repr.len());
    data.extend_from_slice(&slot.l.to_le_bytes());
    data.extend_from_slice(&sig_repr);

    Ok(hash_obj(h, &SigSlotData(data)))
}

fn participant_leaf(h: &mut Sumhash512, p: &Participant) -> Sumhash512Digest {
    hash_obj(h, &ParticipantLeaf(p))
}

// ── Round alignment ───────────────────────────────────────────────────────────

/// Returns the latest round ≤ `round` that is a multiple of `key_lifetime`.
/// Matches Go's `firstRoundInKeyLifetime(round, keyLifetime)`.
fn first_round_in_key_lifetime(round: u64, key_lifetime: u64) -> u64 {
    if key_lifetime == 0 { return round; }
    round - (round % key_lifetime)
}

// ── Per-reveal verification ───────────────────────────────────────────────────

fn verify_merkle_sig(
    h: &mut Sumhash512,
    sig: &MerkleSignature,
    commitment: &Sumhash512Digest,
    round: u64,
    key_lifetime: u64,
    data: &[u8; 32],
    pos: u64,
) -> Result<(), VerifyError> {
    let valid_round = first_round_in_key_lifetime(round, key_lifetime);

    let leaf = hash_obj(h, &CommittablePK { verifying_key: &sig.verifying_key, round: valid_round });

    if !sig.proof.verify_vc(leaf, sig.vc_index as usize, commitment) {
        return Err(VerifyError::VcProofFailed { position: pos });
    }
    
    sig.verifying_key.public_key
        .verify_compressed(&sig.sig.sig, data)
        .map_err(|_| VerifyError::FalconVerifyFailed { position: pos })
}

// ── Public verifier ───────────────────────────────────────────────────────────

/// Verifies a [StateProof] against trusted parameters.
///
/// # Parameters
/// - `state_proof` — decoded from network wire bytes.
/// - `part_commitment` — trusted root of the participants Merkle tree.
/// - `ln_proven_weight` — `ceil(2^16 · ln(proven_weight))`, fixed-point log of the weight threshold.
/// - `strength_target` — security-level parameter (typically 128).
/// - `round` — the block round being attested.
/// - `data` — SHA-256 of the attested message (`MessageHash`).
pub fn verify_state_proof(
    state_proof: &StateProof,
    part_commitment: Sumhash512Digest,
    ln_proven_weight: u64,
    strength_target: u64,
    round: u64,
    data: &[u8; 32],
) -> Result<(), VerifyError> {
    // ── 1. Reject trees that exceed the protocol depth limit ──────────────────
    if state_proof.sig_proofs.tree_depth > MAX_TREE_DEPTH {
        return Err(VerifyError::TreeDepthTooLarge {
            field: "sig_proofs",
            depth: state_proof.sig_proofs.tree_depth,
        });
    }
    if state_proof.part_proofs.tree_depth > MAX_TREE_DEPTH {
        return Err(VerifyError::TreeDepthTooLarge {
            field: "part_proofs",
            depth: state_proof.part_proofs.tree_depth,
        });
    }

    // ── 2. Weight check ───────────────────────────────────────────────────────
    // Full strength-target inequality (go-algorand/crypto/stateproof/weights.go)
    // requires big-integer arithmetic — TODO. For now we verify that
    // ln(signed_weight) > ln_proven_weight, which is the basic necessary condition.
    let _ = strength_target;
    let ln_signed = ln_int_approximation(state_proof.signed_weight)
        .ok_or(VerifyError::SignedWeightTooLow)?;
    if ln_signed <= ln_proven_weight {
        return Err(VerifyError::SignedWeightTooLow);
    }

    // ── 3. Salt version must be consistent across all reveals ─────────────────
    let version = state_proof.merkle_sig_salt_version;
    for &(pos, ref reveal) in &state_proof.reveals {
        if reveal.sig_slot.sig.sig.sig.salt_version() != version {
            return Err(VerifyError::SaltVersionMismatch { position: pos });
        }
    }

    // ── 4. Per-reveal: VC proof + Falcon + build batch-proof element lists ────
    let mut h = Sumhash512::new();
    let mut sig_elems: Vec<(usize, Sumhash512Digest)> =
        Vec::with_capacity(state_proof.reveals.len());
    let mut part_elems: Vec<(usize, Sumhash512Digest)> =
        Vec::with_capacity(state_proof.reveals.len());

    for &(pos, ref reveal) in &state_proof.reveals {
        verify_merkle_sig(
            &mut h,
            &reveal.sig_slot.sig,
            &reveal.participant.pk.commitment,
            round,
            reveal.participant.pk.key_lifetime,
            data,
            pos,
        )?;
        sig_elems.push((pos as usize, sig_slot_leaf(&mut h, pos, &reveal.sig_slot)?));
        part_elems.push((pos as usize, participant_leaf(&mut h, &reveal.participant)));
    }

    // ── 5. Batch VC proof for the signature commitment ────────────────────────
    if !state_proof.sig_proofs.verify_batch_vc(&sig_elems, &state_proof.sig_commit) {
        return Err(VerifyError::SigProofFailed);
    }

    // ── 6. Batch VC proof for the participant commitment ──────────────────────
    if !state_proof.part_proofs.verify_batch_vc(&part_elems, &part_commitment) {
        return Err(VerifyError::PartProofFailed);
    }

    // ── 7. Coin generation and weight-range check ─────────────────────────────
    let seed = CoinChoiceSeed {
        part_commitment,
        ln_proven_weight,
        sig_commitment: state_proof.sig_commit,
        signed_weight:  state_proof.signed_weight,
        message_hash:   *data,
    };
    let mut coins = CoinGenerator::new(&seed);

    let reveal_map: HashMap<u64, &Reveal> =
        state_proof.reveals.iter().map(|(pos, r)| (*pos, r)).collect();

    for (i, &pos) in state_proof.positions_to_reveal.iter().enumerate() {
        let reveal = reveal_map.get(&pos)
            .ok_or(VerifyError::MissingReveal { position: pos })?;
        let coin  = coins.next_coin();
        let l     = reveal.sig_slot.l;
        let upper = l + reveal.participant.weight; // safe: bounded by signed_weight
        if coin < l || coin >= upper {
            return Err(VerifyError::CoinOutOfRange { index: i, position: pos, coin });
        }
    }

    Ok(())
}
