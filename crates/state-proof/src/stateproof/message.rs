// crates/state-proof/src/stateproof/message.rs

use sha2::{Digest as Sha2Digest, Sha256};

use merkle::{Sumhash512Digest, SHA256_DIGEST_SIZE, SUMHASH512_DIGEST_SIZE};

use crate::codec::{AlgorandMessagePack, DecodeError, MsgPackDecode, Reader};
use super::{MessageHash, constants::DOMAIN_SP_MSG_HASH};

/// The message that a State Proof attests to, covering a 256-block interval.
///
/// Decoded from the `message` field of the State Proof transaction.
/// 
/// Contains the block data being attested and the trust parameters for
/// verifying the *next* State Proof interval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateProofMessage {
    /// 256-bit `Sha256` hash digest vector commitment root on the block header array.
    ///
    /// Wire codec key: `"b"`.
    pub block_headers_commitment: [u8; SHA256_DIGEST_SIZE],
    /// 512-bit `Sumhash512` hash digest vector commitment root on the voters array.
    ///
    /// Becomes [part_commitment](TrustAnchor::part_commitment) for verifying the next State Proof.
    ///
    /// Wire codec key: `"v"`.
    pub voters_commitment: Sumhash512Digest,
    /// Real number encoded as a fixed-point integer with 16-bit precision that 
    /// represents the natural log of `proven_weight`
    /// 
    /// Formula: `ceil(2^16 * ln(proven_weight))`.
    /// 
    /// This number is stored inside a 64-bit LE integer for safety insurance and compatibility.
    /// 
    /// Becomes [ln_proven_weight](TrustAnchor::ln_proven_weight) for verifying the next State Proof.
    ///
    /// Wire codec key: `"P"`.
    pub ln_proven_weight: u64,
    /// First round covered by this interval.
    ///
    /// Wire codec key: `"f"`.
    pub first_attested_round: u64,
    /// Last round covered by this interval. 
    /// 
    /// Passed as `round` input to `verify_state_proof`.
    ///
    /// Wire codec key: `"l"`.
    pub last_attested_round: u64,
}

impl StateProofMessage {
    /// Decodes a `StateProofMessage` from Algorand canonical MessagePack bytes.
    pub fn from_msgpack(bytes: &[u8]) -> Result<Self, DecodeError> {
        Self::decode(bytes)
    }

    /// Encodes to Algorand canonical `MessagePack` bytes. 
    fn to_msgpack_bytes(&self) -> Vec<u8> {
        AlgorandMessagePack::new()
            /* NOTE: Keys sorted in lexicographic order based on ASCII:
            P(80), b(98), f(102), l(108), v(118). */
            .uint("P", self.ln_proven_weight)
            .bytes("b", &self.block_headers_commitment)
            .uint("f", self.first_attested_round)
            .uint("l", self.last_attested_round)
            .bytes("v", &self.voters_commitment)
            .encode()
    }

    /// Returns computed digest of: `SHA-256("spm" || canonical_msgpack(self))`.
    pub fn hash(&self) -> MessageHash {
        let encoded = self.to_msgpack_bytes();
        let mut h = Sha256::new();
        Sha2Digest::update(&mut h, DOMAIN_SP_MSG_HASH);
        Sha2Digest::update(&mut h, &encoded);
        Sha2Digest::finalize(h).into()
    }
    
    /// Returns the leaf index (0–255) of `round` in a 256-block interval or `None` if out of range.
    pub fn block_index_for_round(&self, round: u64) -> Option<usize> {
        let idx = round.checked_sub(self.first_attested_round)? as usize;
        if idx > 255 { None } else { Some(idx) }
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

/// Serde helper: serializes `[u8; 64]` as raw bytes and deserializes back with
/// an exact-length check. Uses `deserialize_bytes` so binary formats can hand
/// the data directly to the visitor without a heap allocation.
#[cfg(feature = "serde")]
mod bytes64 {
    use core::fmt;

    use serde::{Deserializer, Serializer, de::{Error, Visitor}};

    pub fn serialize<S: Serializer>(val: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(val)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        d.deserialize_bytes(Bytes64Visitor)
    }

    struct Bytes64Visitor;

    impl<'de> Visitor<'de> for Bytes64Visitor {
        type Value = [u8; 64];

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("exactly 64 bytes")
        }

        fn visit_bytes<E: Error>(self, v: &[u8]) -> Result<[u8; 64], E> {
            v.try_into().map_err(|_| E::custom("expected exactly 64 bytes"))
        }

        fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<[u8; 64], A::Error> {
            let mut arr = [0u8; 64];
            for (i, slot) in arr.iter_mut().enumerate() {
                *slot = seq.next_element()?
                    .ok_or_else(|| A::Error::custom(alloc::format!("expected 64 bytes, got {i}")))?;
            }
            if seq.next_element::<u8>()?.is_some() {
                return Err(A::Error::custom("expected exactly 64 bytes, got more"));
            }
            Ok(arr)
        }
    }
}

/// Trusted parameters used to verify one State Proof interval, produced by
/// verifying the *previous* interval.
///
/// Pass this to `verify_state_proof` along with the current `StateProof` and
/// `StateProofMessage`. On success, `verify_state_proof` returns the next
/// `TrustAnchor` (extracted from the current message) for the following call.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TrustAnchor {
    /// 512-bit `Sumhash512` hash digest vector commitment root on the participants array
    /// of the current `StateProof` interval.
    ///
    /// Sourced from the **previous** `StateProof` message 
    /// [voters_commitment](StateProofMessage::voters_commitment) field.
    #[cfg_attr(feature = "serde", serde(with = "bytes64"))]
    pub part_commitment: Sumhash512Digest,
    /// Real number encoded as a fixed-point integer with 16-bit precision that 
    /// represents the natural log of `proven_weight`
    /// 
    /// Formula: `ceil(2^16 * ln(proven_weight))`.
    /// 
    /// This number is stored inside a 64-bit LE integer for safety insurance and compatibility.
    /// 
    /// Sourced from the **previous** `StateProof` message 
    /// [ln_proven_weight](StateProofMessage::ln_proven_weight) field.
    pub ln_proven_weight: u64,
}

impl From<&StateProofMessage> for TrustAnchor {
    /// Extracts the `TrustAnchor` for the **next** 256-block interval from this message.
    fn from(msg: &StateProofMessage) -> Self {
        Self {
            part_commitment: msg.voters_commitment,
            ln_proven_weight: msg.ln_proven_weight,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Dummy state proof message for structural testing.
    fn dummy_sp_msg(first: u64, last: u64) -> StateProofMessage {
        StateProofMessage {
            block_headers_commitment: [1u8; SHA256_DIGEST_SIZE],
            voters_commitment: [2u8; SUMHASH512_DIGEST_SIZE],
            ln_proven_weight: 1,
            first_attested_round: first,
            last_attested_round: last,
        }
    }

    #[test]
    fn block_index_first_round() {
        assert_eq!(dummy_sp_msg(100, 355).block_index_for_round(100), Some(0));
    }

    #[test]
    fn block_index_last_round() {
        assert_eq!(dummy_sp_msg(100, 355).block_index_for_round(355), Some(255));
    }

    #[test]
    fn block_index_out_of_interval_high() {
        assert_eq!(dummy_sp_msg(100, 355).block_index_for_round(356), None);
    }

    #[test]
    fn block_index_before_interval() {
        assert_eq!(dummy_sp_msg(100, 355).block_index_for_round(99), None);
    }

    #[test]
    fn block_index_underflow_safe() {
        assert_eq!(dummy_sp_msg(1, 256).block_index_for_round(0), None);
    }

    #[test]
    fn msgpack_roundtrip() {
        let original = dummy_sp_msg(59_999_745, 60_000_000);
        let bytes = original.to_msgpack_bytes();
        let decoded = StateProofMessage::from_msgpack(&bytes).expect("decode failed");
        assert_eq!(original, decoded);
    }

    #[test]
    fn trust_anchor_from_message() {
        let msg = dummy_sp_msg(0, 255);
        let anchor = TrustAnchor::from(&msg);
        assert_eq!(anchor.part_commitment, msg.voters_commitment);
        assert_eq!(anchor.ln_proven_weight, msg.ln_proven_weight);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn trust_anchor_serde_round_trip() {
        let anchor = TrustAnchor {
            part_commitment:  [0xabu8; 64],
            ln_proven_weight: 2230322,
        };
        let encoded = serde_json::to_vec(&anchor).unwrap();
        let decoded: TrustAnchor = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(anchor, decoded);
    }
}