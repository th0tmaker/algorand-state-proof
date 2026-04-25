// crates/state-proof/tests/verify_state_proof.rs
//
// Known-answer test against a real Algorand mainnet state proof.
//
// State proof transaction:
//   ID:    U3E4UQIKQF7X2KJWNXAK7F7S6736TOLST5I7MKEGLESK5ZJLSTOQ
//   Round: 60000133
//   Covers rounds: 59999745 – 60000000  (sprnd = 60000000)
//
// Previous state proof transaction (supplies the trusted params for this proof):
//   ID:    WH6WHFQIFYZTKTOUTMNZUZV4ENEVWGYFBYVQ2AHENUZ3F4Z4P64Q
//   Round: 59999877
//
// Trusted parameters (from previous state proof message):
//   part_commitment  = base64-decode(PREV_SP_VOTERS_COMMITMENT)
//   ln_proven_weight = PREV_SP_LN_PROVEN_WEIGHT
//
// msg_hash = SHA-256("spm" || canonical_msgpack(current message))
// strength_target = 256  (Algorand mainnet StateProofStrengthTarget)

use algorand_state_proof::{StateProof, verify_state_proof};

// ── Current state proof ───────────────────────────────────────────────────────

const SP_TXN_ID:   &str = "U3E4UQIKQF7X2KJWNXAK7F7S6736TOLST5I7MKEGLESK5ZJLSTOQ";
const SP_TXN_RND:  u64  = 60000133;
const SP_LATEST_RND: u64 = 60000000;
const SP_FIRST_RND:  u64 = 59999745;

// ── Previous state proof (trusted bootstrapping data) ─────────────────────────

const PREV_SP_TXN_ID:   &str = "WH6WHFQIFYZTKTOUTMNZUZV4ENEVWGYFBYVQ2AHENUZ3F4Z4P64Q";
const PREV_SP_TXN_RND:  u64  = 59999877;
const PREV_SP_LN_PROVEN_WEIGHT: u64 = 2230322;
const PREV_SP_VOTERS_COMMITMENT: &str =
    "Yqhs72l9VsNRRfXTDe5ZRmRnsTYP9fm0rp5kywwt8y9Ul39tNa1abC7ceX3+Hy3XnxZogVGzYRZsBMJCvpwTWQ==";

// ── Verification parameters ───────────────────────────────────────────────────

const ROUND:            u64 = SP_LATEST_RND;
const LN_PROVEN_WEIGHT: u64 = PREV_SP_LN_PROVEN_WEIGHT;

/// Trusted participant commitment = base64-decode(`PREV_SP_VOTERS_COMMITMENT`).
const PART_COMMITMENT: [u8; 64] = [
    0x62, 0xa8, 0x6c, 0xef, 0x69, 0x7d, 0x56, 0xc3,
    0x51, 0x45, 0xf5, 0xd3, 0x0d, 0xee, 0x59, 0x46,
    0x64, 0x67, 0xb1, 0x36, 0x0f, 0xf5, 0xf9, 0xb4,
    0xae, 0x9e, 0x64, 0xcb, 0x0c, 0x2d, 0xf3, 0x2f,
    0x54, 0x97, 0x7f, 0x6d, 0x35, 0xad, 0x5a, 0x6c,
    0x2e, 0xdc, 0x79, 0x7d, 0xfe, 0x1f, 0x2d, 0xd7,
    0x9f, 0x16, 0x68, 0x81, 0x51, 0xb3, 0x61, 0x16,
    0x6c, 0x04, 0xc2, 0x42, 0xbe, 0x9c, 0x13, 0x59,
];

/// SHA-256("spm" || canonical_msgpack(StateProofMessage for round 60000000)).
const MSG_HASH: [u8; 32] = [
    0x39, 0x3e, 0x12, 0x31, 0xa9, 0x36, 0x90, 0x27,
    0xd5, 0x84, 0x61, 0xc9, 0x0e, 0x4b, 0xc1, 0xfe,
    0x52, 0xd8, 0x3c, 0x63, 0x41, 0xc9, 0xb2, 0x78,
    0x13, 0x6a, 0xd9, 0x94, 0x83, 0xb4, 0x1e, 0xd2,
];

static FIXTURE: &[u8] = include_bytes!("fixtures/stateproof_60000000.bin");

#[test]
fn decode_mainnet_state_proof() {
    let sp = StateProof::from_msgpack(FIXTURE).expect("decode failed");
    assert_eq!(sp.signed_weight, 1984993817111541);
    assert_eq!(sp.positions_to_reveal.len(), 149);
    assert_eq!(sp.reveals.len(), 67);
}

#[test]
fn verify_mainnet_state_proof() {
    let sp = StateProof::from_msgpack(FIXTURE).expect("decode failed");
    verify_state_proof(&sp, &PART_COMMITMENT, LN_PROVEN_WEIGHT, ROUND, &MSG_HASH)
        .expect("verification failed");
}
