// crates/state-proof/src/lib.rs

//! Lightweight, trustless verification of the Algorand ledger without running a full node.
//!
//! An Algorand state proof is a post-quantum attestation that covers a 256-round block
//! interval. It is built from Falcon-1024 ephemeral signatures over a Sumhash512 Merkle
//! commitment, giving quantum-secure proof that a threshold of online stake signed the
//! attested message.
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
mod light_block_header;
mod stateproof;

pub use merkle::{HashFactory, HashType, Proof, Sha256, Sumhash512Digest, SHA256_DIGEST_SIZE, SUMHASH512_DIGEST_SIZE};
pub use algorand_falcon_keys::{CompressedSignature as FalconCompressedSig, PublicKey as FalconPublicKey};
pub use codec::DecodeError;
pub use light_block_header::{LightBlockHeader, verify_block_header_commitment, verify_txn_commitment};
pub use stateproof::{
    MessageHash,
    StateProofMessage, TrustAnchor,
    MerkleVerifier, MerkleSignatureScheme,
    SigSlotCommit, Participant, Reveal,
    StateProof,
    VerifyError, verify_state_proof,
};
