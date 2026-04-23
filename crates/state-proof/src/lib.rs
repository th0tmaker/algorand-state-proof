// crates/state-proof/src/lib.rs

mod codec;
mod stateproof;

pub use merkle::{Sumhash512Digest, SUMHASH512_DIGEST_SIZE, Hashable, HashFactory, HashType, Proof};
pub use algorand_falcon_keys::{PublicKey as FalconPublicKey, CompressedSignature as FalconCompressedSig};
pub use codec::DecodeError;
pub use stateproof::{
    MessageHash,
    MerkleVerifier, MerkleSignatureScheme,
    SigSlotCommit, Participant, Reveal,
    StateProof,
    VerifyError, verify_state_proof,
};
