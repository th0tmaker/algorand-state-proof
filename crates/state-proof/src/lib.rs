// crates/state-proof/src/lib.rs
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
