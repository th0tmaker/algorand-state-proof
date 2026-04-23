// crates/state-proof/src/codec/mod.rs

mod msgpack;
pub mod proof;

pub use msgpack::DecodeError;
pub(crate) use msgpack::{AlgorandMessagePack, MsgPackDecode, MsgPackEncode, Reader};
