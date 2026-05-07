// crates/state-proof/tests/block_header.rs
//
// Integration tests for `verify_block_header_commitment`:
//   - Mainnet KAT proving block 60000000 is committed at index 255 in the
//     SP1 block-headers VcTree (root = SP1_MSG_BLOCK_HEADERS_COMMITMENT).
//   - Negative test confirming a tampered header is rejected.

mod common;
use common::*;

use algorand_state_proof::{LightBlockHeader, Proof, Sha256, verify_block_header_commitment};

// Build the `LightBlockHeader` for block number 60000000.
fn light_block_60000000() -> LightBlockHeader {
    LightBlockHeader {
        // Protocol has StateProofBlockHashInLightHeader set:
        // block_hash is present, seed is zeroed/omitted.
        seed: [0u8; 32],
        block_hash: BLOCK_60000000_HASH,
        genesis_hash: BLOCK_60000000_GENESIS_HASH,
        round: SP1_LATEST_RND,
        txn_commitment: BLOCK_60000000_TXN_COMMITMENT,
    }
}

/// Verifies that block 60000000 (index 255 in the 256-block VcTree) is correctly
/// committed under `SP1_MSG_BLOCK_HEADERS_COMMITMENT` using a real mainnet proof.
#[test]
fn verify_block_header_commitment_mainnet() {
    let proof = Proof::<Sha256>::new(8, BLOCK_60000000_HEADER_PROOF.to_vec());
    assert!(verify_block_header_commitment(
        &light_block_60000000(), 255, &proof, &SP1_MSG_BLOCK_HEADERS_COMMITMENT,
    ));
}

/// A tampered block header must be rejected by the same proof.
#[test]
fn verify_block_header_commitment_rejects_wrong_header() {
    let mut header = light_block_60000000();
    header.block_hash[0] ^= 0xff;  // change `block_hash` value to produce invalid header
    let proof = Proof::<Sha256>::new(8, BLOCK_60000000_HEADER_PROOF.to_vec());
    assert!(!verify_block_header_commitment(
        &header, 255, &proof, &SP1_MSG_BLOCK_HEADERS_COMMITMENT,
    ));
}
