// crates/state-proof/src/codec/error.rs

use merkle::HashType;


#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DecodeError {
    /// The `HashFactory` type decoded from the wire does not match the expected type for this [`merkle::Proof`].
    HashTypeMismatch { expected: HashType, got: HashType },
    /// A `HashFactory` type tag did not correspond to a known [`HashType`].
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

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::HashTypeMismatch { expected, got } =>
                write!(f, "hash type mismatch: expected {expected:?}, got {got:?}"),
            Self::InvalidHashType(v) =>
                write!(f, "unknown hash type tag: {v}"),
            Self::InvalidDigestSize { expected, got } =>
                write!(f, "digest size mismatch: expected {expected} bytes, got {got}"),
            Self::InvalidPublicKey =>
                write!(f, "invalid Falcon-1024 public key"),
            Self::InvalidPublicKeySize { expected, got } =>
                write!(f, "public key size mismatch: expected {expected} bytes, got {got}"),
            Self::InvalidSignature =>
                write!(f, "invalid Falcon compressed signature"),
            Self::InvalidUtf8 =>
                write!(f, "invalid UTF-8 in msgpack string field"),
            Self::TooManyReveals { got, max } =>
                write!(f, "too many reveals: got {got}, max {max}"),
            Self::TrailingBytes =>
                write!(f, "trailing bytes after decoded value"),
            Self::UnexpectedEof =>
                write!(f, "unexpected end of input"),
            Self::UnexpectedType { expected, got } =>
                write!(f, "msgpack type mismatch: expected {expected}, got 0x{got:02x}"),
            Self::ZeroSignedWeight =>
                write!(f, "signed_weight is zero"),
        }
    }
}

impl core::error::Error for DecodeError {}
