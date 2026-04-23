// crates/state-proof/tests/verify_state_proof.rs
//
// Known-answer test against a real Algorand mainnet state proof (round 60483072).
//
// Parameters extracted from:
//   GET https://mainnet-api.algonode.cloud/v2/stateproofs/60483072  (JSON)
//   GET https://mainnet-api.algonode.cloud/v2/blocks/60483072        (block header)
//
// msg_hash = SHA-512/256("spm" || canonical_msgpack(StateProofMessage))
// part_commitment = StateProofMessage.VotersCommitment (= block spt[0].v)
// ln_proven_weight = StateProofMessage.LnProvenWeight
// strength_target  = 256 (Algorand mainnet StateProofStrengthTarget)

use algorand_state_proof::{DecodeError, StateProof, verify_state_proof};

const ROUND: u64 = 60483072;
const LN_PROVEN_WEIGHT: u64 = 2231004;
const STRENGTH_TARGET: u64 = 256;

/// Trusted root of the participants Merkle tree (`StateProofMessage.VotersCommitment`).
const PART_COMMITMENT: [u8; 64] = [
    0x59, 0xeb, 0xf2, 0x56, 0x31, 0x3e, 0xe4, 0x6f,
    0x84, 0x16, 0x8d, 0x7d, 0xa3, 0x4f, 0xcc, 0xa8,
    0x37, 0xfb, 0xfb, 0x2a, 0x74, 0xbe, 0x3a, 0xdf,
    0xd7, 0x9d, 0x85, 0xac, 0x6c, 0x89, 0x45, 0x2c,
    0xa6, 0x04, 0xcc, 0x74, 0x9b, 0xa3, 0x4b, 0x98,
    0xfc, 0xa9, 0xd4, 0x13, 0x76, 0x41, 0x4f, 0x5b,
    0x67, 0x89, 0x03, 0x51, 0xeb, 0xdb, 0x4b, 0x78,
    0xca, 0xac, 0x0c, 0xe8, 0x54, 0x99, 0x90, 0x7d,
];

/// SHA-512/256("spm" || canonical_msgpack(StateProofMessage)).
const MSG_HASH: [u8; 32] = [
    0x13, 0xfb, 0x94, 0x62, 0xd5, 0x0f, 0xb3, 0xdf,
    0xaa, 0x9a, 0x8d, 0xe5, 0xbb, 0xb3, 0x40, 0x4b,
    0x7d, 0xb0, 0x19, 0x67, 0x08, 0x8d, 0xce, 0xf4,
    0x06, 0x9c, 0x38, 0xd8, 0xc9, 0x48, 0x85, 0x70,
];

static FIXTURE: &[u8] = include_bytes!("fixtures/stateproof_60483072.bin");

#[test]
fn decode_mainnet_state_proof() {
    let sp = StateProof::from_msgpack(FIXTURE).expect("decode failed");
    assert_eq!(sp.signed_weight, 2008053432038055);
    assert_eq!(sp.positions_to_reveal.len(), 149);
    assert_eq!(sp.reveals.len(), 65);
}

#[test]
fn verify_mainnet_state_proof() {
    let sp = StateProof::from_msgpack(FIXTURE).expect("decode failed");
    verify_state_proof(&sp, &PART_COMMITMENT, LN_PROVEN_WEIGHT, STRENGTH_TARGET, ROUND, &MSG_HASH)
        .expect("verification failed");
}
