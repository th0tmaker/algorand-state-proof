// crates/state-proof/src/lib.rs

mod codec;
mod stateproof;

pub use merkle::{Digest, DIGEST_SIZE, Hashable, HashFactory, HashType, Proof};
pub use stateproof::{
    FalconPublicKey, FalconVerifier, FalconSignature,
    MerkleVerifier, MerkleSignature,
    SigSlotCommit, Participant, Reveal,
    StateProof,
};
