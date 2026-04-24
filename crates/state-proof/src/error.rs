// crates/state-proof/src/error.rs

use merkle::HashType;


#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    /// The `HashFactory` type decoded from the wire does not match the expected type for this [merkle::Proof].
    HashTypeMismatch { expected: HashType, got: HashType },
    /// A `HashFactory` type tag did not correspond to a known [HashType].
    InvalidHashType(u64),
    /// A byte sequence had the wrong length for the expected hash digest.
    InvalidDigestSize { expected: usize, got: usize },
    /// A byte sequence of correct length could not be parsed as a valid Falcon-1024 public key.
    InvalidPublicKey,
    /// A byte sequence had the wrong length for a valid Falcon-1024 public key.
    InvalidPublicKeySize { expected: usize, got: usize },
    /// A byte sequence could not be parsed as a valid Falcon compressed signature.
    InvalidSignature,
    /// A MessagePack string field contained invalid UTF-8.
    InvalidUtf8,
    /// The number of reveals or positions in a `StateProof` exceeds the protocol maximum.
    TooManyReveals { got: usize, max: usize },
    /// Bytes remained unconsumed after successfully decoding a complete value.
    TrailingBytes,
    /// The input ended before a complete value could be read.
    UnexpectedEof,
    /// The format byte did not match the expected MessagePack type.
    UnexpectedType { expected: &'static str, got: u8 },
    /// The `signed_weight` field in a `StateProof` is zero; a proof with no stake cannot be valid.
    ZeroSignedWeight,
}
