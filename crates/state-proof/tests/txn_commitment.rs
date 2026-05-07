// crates/state-proof/tests/txn_commitment.rs
//
// Integration tests for `verify_txn_commitment`:
//   - Mainnet KAT for the axfer at index 2 in block 60000000 against
//     BLOCK_60000000_TXN_COMMITMENT (the block's SHA-256 txn VcTree root).
//   - Negative test confirming a tampered txn_sha256 is rejected.
//
// Leaf formula: SHA-256("TL" || txn_sha256 || stib_sha256).
// Canonical txn bytes include gh (genesis hash) and gen (genesis ID
// "mainnet-v1.0") which block storage strips but the TXID computation includes.

mod common;
use common::*;

use algorand_state_proof::{Proof, Sha256, verify_txn_commitment};

/// Verifies that the axfer at index 2 in block 60000000 is correctly committed
/// under `BLOCK_60000000_TXN_COMMITMENT` using a real mainnet proof.
#[test]
fn verify_txn_commitment_mainnet() {
    let proof = Proof::<Sha256>::new(5, TXN_60000000_PROOF.to_vec());
    assert!(verify_txn_commitment(
        TXN_60000000_TXN_SHA256, TXN_60000000_STIB_SHA256,
        2, &proof, &BLOCK_60000000_TXN_COMMITMENT,
    ));
}

/// A tampered `txn_sha256` must be rejected by the same proof.
#[test]
fn verify_txn_commitment_rejects_wrong_txn_hash() {
    let mut bad = TXN_60000000_TXN_SHA256;
    bad[0] ^= 0xff;  // change `txn_sha256` value to produce invalid digest bytes.
    let proof = Proof::<Sha256>::new(5, TXN_60000000_PROOF.to_vec());
    assert!(!verify_txn_commitment(
        bad, TXN_60000000_STIB_SHA256,
        2, &proof, &BLOCK_60000000_TXN_COMMITMENT,
    ));
}
