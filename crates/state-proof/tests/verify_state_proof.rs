// crates/state-proof/tests/verify_state_proof.rs
//
// Known-answer tests against a real Algorand mainnet state proof.
//
// Current state proof transaction:
//   ID:    U3E4UQIKQF7X2KJWNXAK7F7S6736TOLST5I7MKEGLESK5ZJLSTOQ
//   Round: 60000133  |  Covers rounds: 59999745 – 60000000
//
// Previous state proof transaction (supplies the trusted anchor):
//   ID:    WH6WHFQIFYZTKTOUTMNZUZV4ENEVWGYFBYVQ2AHENUZ3F4Z4P64Q
//   Round: 59999877
//   ln_proven_weight:  2230322
//   voters_commitment: Yqhs72l9VsNRRfXTDe5ZRmRnsTYP9fm0rp5kywwt8y9Ul39tNa1abC7ceX3+Hy3XnxZogVGzYRZsBMJCvpwTWQ==

use algorand_state_proof::{StateProof, StateProofMessage, TrustAnchor, verify_state_proof};

const SP_FIRST_RND:  u64 = 59999745;
const SP_LATEST_RND: u64 = 60000000;

// ── Trusted anchor (from previous state proof message) ────────────────────────

const PREV_SP_LN_PROVEN_WEIGHT: u64 = 2230322;

// base64: Yqhs72l9VsNRRfXTDe5ZRmRnsTYP9fm0rp5kywwt8y9Ul39tNa1abC7ceX3+Hy3XnxZogVGzYRZsBMJCvpwTWQ==
const ANCHOR_PART_COMMITMENT: [u8; 64] = [
    0x62, 0xa8, 0x6c, 0xef, 0x69, 0x7d, 0x56, 0xc3,
    0x51, 0x45, 0xf5, 0xd3, 0x0d, 0xee, 0x59, 0x46,
    0x64, 0x67, 0xb1, 0x36, 0x0f, 0xf5, 0xf9, 0xb4,
    0xae, 0x9e, 0x64, 0xcb, 0x0c, 0x2d, 0xf3, 0x2f,
    0x54, 0x97, 0x7f, 0x6d, 0x35, 0xad, 0x5a, 0x6c,
    0x2e, 0xdc, 0x79, 0x7d, 0xfe, 0x1f, 0x2d, 0xd7,
    0x9f, 0x16, 0x68, 0x81, 0x51, 0xb3, 0x61, 0x16,
    0x6c, 0x04, 0xc2, 0x42, 0xbe, 0x9c, 0x13, 0x59,
];

// ── Current state proof message ───────────────────────────────────────────────

// base64: 751g1mbohNWzYqT/R588/5KlcBSl3GpkY9g9T+HCzj4=
const SP_MSG_BLOCK_HEADERS_COMMITMENT: [u8; 32] = [
    0xef, 0x9d, 0x60, 0xd6, 0x66, 0xe8, 0x84, 0xd5,
    0xb3, 0x62, 0xa4, 0xff, 0x47, 0x9f, 0x3c, 0xff,
    0x92, 0xa5, 0x70, 0x14, 0xa5, 0xdc, 0x6a, 0x64,
    0x63, 0xd8, 0x3d, 0x4f, 0xe1, 0xc2, 0xce, 0x3e,
];

// base64: SHvN62JrCY6VuhDtI8BKJwRH0bHjQyHyMUyecMC+E4p9ulTBwqM4GJNVf8CVX74KUxZN8wpiNvU3R75Izu1MDA==
const SP_MSG_VOTERS_COMMITMENT: [u8; 64] = [
    0x48, 0x7b, 0xcd, 0xeb, 0x62, 0x6b, 0x09, 0x8e,
    0x95, 0xba, 0x10, 0xed, 0x23, 0xc0, 0x4a, 0x27,
    0x04, 0x47, 0xd1, 0xb1, 0xe3, 0x43, 0x21, 0xfa,
    0x31, 0x4c, 0x9e, 0x72, 0xc0, 0xbe, 0x13, 0x8a,
    0x7d, 0xba, 0x54, 0xc1, 0xc2, 0xa3, 0x38, 0x18,
    0x93, 0x55, 0x7f, 0xc0, 0x95, 0x5f, 0xbe, 0x0a,
    0x53, 0x16, 0x4d, 0xf3, 0x0a, 0x62, 0x6b, 0xf5,
    0x37, 0x47, 0xbe, 0x48, 0xce, 0xed, 0x4c, 0x0c,
];

const SP_MSG_LN_PROVEN_WEIGHT: u64 = 2230235;

// Expected SHA-256("spm" || canonical_msgpack(message)).
const EXPECTED_MSG_HASH: [u8; 32] = [
    0x39, 0x3e, 0x12, 0x31, 0xa9, 0x36, 0x90, 0x27,
    0xd5, 0x84, 0x61, 0xc9, 0x0e, 0x4b, 0xc1, 0xfe,
    0x52, 0xd8, 0x3c, 0x63, 0x41, 0xc9, 0xb2, 0x78,
    0x13, 0x6a, 0xd9, 0x94, 0x83, 0xb4, 0x1e, 0xd2,
];

static FIXTURE: &[u8] = include_bytes!("fixtures/stateproof_60000000.bin");

fn make_message() -> StateProofMessage {
    StateProofMessage {
        block_headers_commitment: SP_MSG_BLOCK_HEADERS_COMMITMENT,
        voters_commitment: SP_MSG_VOTERS_COMMITMENT,
        ln_proven_weight: SP_MSG_LN_PROVEN_WEIGHT,
        first_attested_round: SP_FIRST_RND,
        last_attested_round: SP_LATEST_RND,
    }
}

fn make_anchor() -> TrustAnchor {
    TrustAnchor {
        part_commitment: ANCHOR_PART_COMMITMENT,
        ln_proven_weight: PREV_SP_LN_PROVEN_WEIGHT,
    }
}

#[test]
fn decode_mainnet_state_proof() {
    let sp = StateProof::from_msgpack(FIXTURE).expect("decode failed");
    assert_eq!(sp.signed_weight, 1984993817111541);
    assert_eq!(sp.positions_to_reveal.len(), 149);
    // reveals.len() < positions_to_reveal.len(): multiple coins can land on the same
    // heavy participant, so the reveals map deduplicates by tree position.
    assert_eq!(sp.reveals.len(), 67);
}

#[test]
fn message_hash_matches_reference() {
    assert_eq!(make_message().hash(), EXPECTED_MSG_HASH);
}

#[test]
fn block_index_for_interval_bounds() {
    let msg = make_message();
    assert_eq!(msg.block_index_for_round(SP_FIRST_RND), Some(0));
    assert_eq!(msg.block_index_for_round(SP_LATEST_RND), Some(255));
    assert_eq!(msg.block_index_for_round(SP_FIRST_RND - 1), None);
    assert_eq!(msg.block_index_for_round(SP_LATEST_RND + 1), None);
}

#[test]
fn verify_mainnet_state_proof() {
    let sp      = StateProof::from_msgpack(FIXTURE).expect("decode failed");
    let message = make_message();
    let anchor  = make_anchor();

    let next_anchor = verify_state_proof(&sp, &message, &anchor)
        .expect("verification failed");

    // The returned anchor carries the trust parameters for the next interval.
    assert_eq!(next_anchor.part_commitment,  SP_MSG_VOTERS_COMMITMENT);
    assert_eq!(next_anchor.ln_proven_weight, SP_MSG_LN_PROVEN_WEIGHT);
}
