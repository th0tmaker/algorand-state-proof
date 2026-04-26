// crates/state-proof/src/stateproof/message.rs

use sha2::{Digest as Sha2Digest, Sha256};

use merkle::{Sumhash512Digest, SHA256_DIGEST_SIZE, SUMHASH512_DIGEST_SIZE};

use crate::codec::{AlgorandMessagePack, DecodeError, MsgPackDecode, Reader};
use super::{MessageHash, constants::DOMAIN_MSG_HASH};

/// The message that a State Proof attests to, covering one block interval.
///
/// Decoded from the `StateProofMsg` field of the State Proof transaction.
/// Contains the block data being attested and the trust parameters for
/// verifying the *next* State Proof interval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateProofMessage {
    /// SHA-256 VcTree root over the 256 light block headers in this interval.
    ///
    /// Codec key: `"b"`.
    pub block_headers_commitment: [u8; SHA256_DIGEST_SIZE],

    /// Sumhash512 root of the participants VcTree for the *next* interval.
    /// Becomes `TrustAnchor::part_commitment` for verifying the next State Proof.
    ///
    /// Codec key: `"v"`.
    pub voters_commitment: Sumhash512Digest,

    /// `ceil(2^16 · ln(proven_weight))` for the *next* interval.
    /// Becomes `TrustAnchor::ln_proven_weight` for verifying the next State Proof.
    ///
    /// Codec key: `"P"`.
    pub ln_proven_weight: u64,

    /// First round covered by this interval.
    ///
    /// Codec key: `"f"`.
    pub first_attested_round: u64,

    /// Last round covered by this interval. Passed as `round` to `verify_state_proof`.
    ///
    /// Codec key: `"l"`.
    pub last_attested_round: u64,
}

impl StateProofMessage {
    /// Decodes a `StateProofMessage` from Algorand canonical MessagePack bytes.
    pub fn from_msgpack(bytes: &[u8]) -> Result<Self, DecodeError> {
        Self::decode(bytes)
    }

    /// Computes `SHA-256("spm" || canonical_msgpack(self))`.
    ///
    /// This is the 32-byte digest signed by participants' ephemeral Falcon keys,
    /// passed as `msg_hash` internally by `verify_state_proof`.
    pub fn hash(&self) -> MessageHash {
        let encoded = self.to_msgpack_bytes();
        let mut h = Sha256::new();
        Sha2Digest::update(&mut h, DOMAIN_MSG_HASH);
        Sha2Digest::update(&mut h, &encoded);
        Sha2Digest::finalize(h).into()
    }

    /// Canonical msgpack encoding. Keys sorted: P(80) b(98) f(102) l(108) v(118).
    fn to_msgpack_bytes(&self) -> Vec<u8> {
        AlgorandMessagePack::new()
            .uint("P", self.ln_proven_weight)
            .bytes("b", &self.block_headers_commitment)
            .uint("f", self.first_attested_round)
            .uint("l", self.last_attested_round)
            .bytes("v", &self.voters_commitment)
            .encode()
    }
}

impl MsgPackDecode for StateProofMessage {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let n = r.read_map_len()?;
        let mut block_headers_commitment = [0u8; SHA256_DIGEST_SIZE];
        let mut voters_commitment = [0u8; SUMHASH512_DIGEST_SIZE];
        let mut ln_proven_weight = 0u64;
        let mut first_attested_round = 0u64;
        let mut last_attested_round = 0u64;

        for _ in 0..n {
            match r.read_str()? {
                "P" => ln_proven_weight = r.read_uint()?,
                "b" => {
                    let b = r.read_bin()?;
                    if b.len() != SHA256_DIGEST_SIZE {
                        return Err(DecodeError::InvalidDigestSize { expected: SHA256_DIGEST_SIZE, got: b.len() });
                    }
                    block_headers_commitment.copy_from_slice(b);
                }
                "f" => first_attested_round = r.read_uint()?,
                "l" => last_attested_round = r.read_uint()?,
                "v" => {
                    let b = r.read_bin()?;
                    if b.len() != SUMHASH512_DIGEST_SIZE {
                        return Err(DecodeError::InvalidDigestSize {
                            expected: SUMHASH512_DIGEST_SIZE,
                            got: b.len(),
                        });
                    }
                    voters_commitment.copy_from_slice(b);
                }
                _ => r.skip()?,
            }
        }

        Ok(Self {
            block_headers_commitment,
            voters_commitment,
            ln_proven_weight,
            first_attested_round,
            last_attested_round,
        })
    }
}

// ── TrustAnchor ───────────────────────────────────────────────────────────────

/// Trusted parameters used to verify one State Proof interval, produced by
/// verifying the *previous* interval.
///
/// Pass this to `verify_state_proof` along with the current `StateProof` and
/// `StateProofMessage`. On success, `verify_state_proof` returns the next
/// `TrustAnchor` (extracted from the current message) for the following call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustAnchor {
    /// Sumhash512 root of the current interval's participants VcTree.
    /// Sourced from the *previous* `StateProofMessage::voters_commitment`.
    pub part_commitment: Sumhash512Digest,

    /// `ceil(2^16 · ln(proven_weight))` for the current interval.
    /// Sourced from the *previous* `StateProofMessage::ln_proven_weight`.
    pub ln_proven_weight: u64,
}

impl From<&StateProofMessage> for TrustAnchor {
    /// Extracts the trust anchor for the *next* interval from this message.
    fn from(msg: &StateProofMessage) -> Self {
        Self {
            part_commitment: msg.voters_commitment,
            ln_proven_weight: msg.ln_proven_weight,
        }
    }
}