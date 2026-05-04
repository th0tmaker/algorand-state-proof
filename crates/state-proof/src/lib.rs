// crates/state-proof/src/lib.rs

//! Post-quantum Algorand state proof verifier.
//!
//! Verifies Algorand state proofs, enabling lightweight trustless verification
//! of the Algorand ledger without running a full node. State proofs use
//! Falcon-1024 signatures over a Sumhash512 Merkle commitment, providing
//! quantum-secure attestation over a 256-round block interval.
//!
//! ## Verification workflow
//!
//! Each State Proof transaction carries two fields:
//! - `sp` — the [`StateProof`] (the cryptographic proof)
//! - `spmsg` — the [`StateProofMessage`] (what was attested to)
//!
//! To verify a proof you also need a [`TrustAnchor`] sourced from the
//! *previous* interval's [`StateProofMessage`] — this is what makes the
//! proofs chain from genesis.
//!
//! ```no_run
//! use algorand_state_proof::{StateProof, StateProofMessage, TrustAnchor, verify_state_proof};
//!
//! fn verify(sp_bytes: &[u8], msg_bytes: &[u8], anchor: &TrustAnchor)
//!     -> Result<TrustAnchor, algorand_state_proof::VerifyError>
//! {
//!     let sp  = StateProof::from_msgpack(sp_bytes).unwrap();
//!     let msg = StateProofMessage::from_msgpack(msg_bytes).unwrap();
//!     // Returns the anchor for the *next* interval on success.
//!     verify_state_proof(&sp, &msg, anchor)
//! }
//! ```

extern crate alloc;

mod codec;
mod stateproof;

// ── Re-exports from merkle ────────────────────────────────────────────────────
// Sumhash512Digest / SUMHASH512_DIGEST_SIZE are part of the public API:
// `verify_state_proof` takes `part_commitment: &Sumhash512Digest`, so callers
// must be able to name and construct the type.
// HashFactory / HashType / Proof are exposed so callers can inspect the
// `sig_proofs` / `part_proofs` fields of a decoded `StateProof`.
pub use merkle::{HashFactory, HashType, Proof, Sha256, Sumhash512Digest, SHA256_DIGEST_SIZE, SUMHASH512_DIGEST_SIZE};

// ── Re-exports from algorand-falcon-keys ─────────────────────────────────────
// Exposed so callers can inspect `MerkleSignatureScheme` fields
// (verifying_key: FalconPublicKey, sig: FalconCompressedSig).
pub use algorand_falcon_keys::{
    CompressedSignature as FalconCompressedSig,
    PublicKey as FalconPublicKey,
};

// ── Codec error ───────────────────────────────────────────────────────────────
pub use codec::DecodeError;

// ── State proof types and verifier ───────────────────────────────────────────
pub use stateproof::{
    MessageHash,
    LightBlockHeader, verify_block_header_commitment, verify_txn_commitment,
    StateProofMessage, TrustAnchor,
    MerkleVerifier, MerkleSignatureScheme,
    SigSlotCommit, Participant, Reveal,
    StateProof,
    VerifyError, verify_state_proof,
};
