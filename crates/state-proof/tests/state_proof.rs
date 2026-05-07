// crates/state-proof/tests/state_proof.rs
//
// Integration tests for `verify_state_proof`:
//   - Fixture decoding
//   - Message hash KAT
//   - Block-index helpers
//   - Full mainnet verification (SP1 and SP1→SP2 chain)
//   - Verifier error paths
//   - Decoder error paths

mod common;
use common::*;

use algorand_state_proof::{
    DecodeError, StateProof, TrustAnchor, VerifyError,
    verify_state_proof,
};

// ── Decode ────────────────────────────────────────────────────────────────────

#[test]
fn decode_mainnet_state_proof() {
    let sp = sp1_decoded();
    assert_eq!(sp.signed_weight, 1984993817111541);
    assert_eq!(sp.positions_to_reveal.len(), 149);
    // reveals.len() < positions_to_reveal.len(): multiple coins can land on the same
    // heavy participant, so the reveals map deduplicates by tree position.
    assert_eq!(sp.reveals.len(), 67);
}

#[test]
fn message_hash_matches_reference() {
    assert_eq!(sp1_message().hash(), SP1_EXPECTED_MSG_HASH);
}

#[test]
fn block_index_for_interval_bounds() {
    let msg = sp1_message();
    assert_eq!(msg.block_index_for_round(SP1_FIRST_RND), Some(0));
    assert_eq!(msg.block_index_for_round(SP1_LATEST_RND), Some(255));
    assert_eq!(msg.block_index_for_round(SP1_FIRST_RND - 1), None);
    assert_eq!(msg.block_index_for_round(SP1_LATEST_RND + 1), None);
}

// ── Mainnet verification ──────────────────────────────────────────────────────

#[test]
fn verify_mainnet_state_proof() {
    let next_anchor = verify_state_proof(&sp1_decoded(), &sp1_message(), &sp1_anchor())
        .expect("SP1 verification failed");

    assert_eq!(next_anchor.part_commitment, SP1_MSG_VOTERS_COMMITMENT);
    assert_eq!(next_anchor.ln_proven_weight, SP1_MSG_LN_PROVEN_WEIGHT);
}

/// Verifies two consecutive state proofs, confirming the anchor hand-off between them.
#[test]
fn verify_chain_state_proof() {
    // The anchor for SP2 is the TrustAnchor output by verifying SP1.
    let sp2_anchor = TrustAnchor {
        part_commitment:  SP1_MSG_VOTERS_COMMITMENT,
        ln_proven_weight: SP1_MSG_LN_PROVEN_WEIGHT,
    };
    let sp2 = StateProof::from_msgpack(SP2_FIXTURE).expect("SP2 decode failed");

    let next_anchor = verify_state_proof(&sp2, &sp2_message(), &sp2_anchor)
        .expect("SP2 chain verification failed");

    assert_eq!(next_anchor.part_commitment, SP2_MSG_VOTERS_COMMITMENT);
    assert_eq!(next_anchor.ln_proven_weight, SP2_MSG_LN_PROVEN_WEIGHT);
}

// ── Verifier error paths ──────────────────────────────────────────────────────

#[test]
fn sig_proof_failed() {
    let mut sp = sp1_decoded();
    sp.sig_commitment[0] ^= 0xff;
    assert_eq!(
        verify_state_proof(&sp, &sp1_message(), &sp1_anchor()),
        Err(VerifyError::SigProofFailed)
    );
}

#[test]
fn part_proof_failed() {
    let bad_anchor = TrustAnchor {
        part_commitment:  [0xffu8; 64],
        ln_proven_weight: SP1_ANCHOR_LN_PROVEN_WEIGHT,
    };
    assert_eq!(
        verify_state_proof(&sp1_decoded(), &sp1_message(), &bad_anchor),
        Err(VerifyError::PartProofFailed)
    );
}

#[test]
fn falcon_verify_failed() {
    let mut bad_msg = sp1_message();
    bad_msg.block_headers_commitment[0] ^= 0xff;
    assert!(matches!(
        verify_state_proof(&sp1_decoded(), &bad_msg, &sp1_anchor()),
        Err(VerifyError::FalconVerifyFailed { .. })
    ));
}

#[test]
fn salt_version_mismatch() {
    let mut sp = sp1_decoded();
    // All reveals have salt_version=0; declaring version=1 causes a mismatch.
    sp.mss_salt_version = 1;
    assert!(matches!(
        verify_state_proof(&sp, &sp1_message(), &sp1_anchor()),
        Err(VerifyError::SaltVersionMismatch { .. })
    ));
}

#[test]
fn vc_proof_failed() {
    let mut sp = sp1_decoded();
    // Corrupt one node in the first reveal's inner ephemeral-key VC proof path.
    if let Some((_, reveal)) = sp.reveals.first_mut() {
        if let Some(node) = reveal.sig_slot.mss.proof.path.first_mut() {
            node[0] ^= 0xff;
        }
    }
    assert!(matches!(
        verify_state_proof(&sp, &sp1_message(), &sp1_anchor()),
        Err(VerifyError::VcProofFailed { .. })
    ));
}

// ── Decoder error paths ───────────────────────────────────────────────────────

#[test]
fn decode_rejects_zero_signed_weight() {
    // fixmap(1): {"w": 0}  — explicitly encoding w=0 triggers the check.
    let bytes = [0x81u8, 0xa1, 0x77, 0x00];
    assert_eq!(StateProof::from_msgpack(&bytes), Err(DecodeError::ZeroSignedWeight));
}

#[test]
fn decode_rejects_too_many_reveals() {
    // fixmap(1): {"r": map16(641)} — 641 > MAX_REVEALS=640.
    let bytes = [0x81u8, 0xa1, 0x72, 0xde, 0x02, 0x81];
    assert_eq!(
        StateProof::from_msgpack(&bytes),
        Err(DecodeError::TooManyReveals { got: 641, max: 640 })
    );
}
