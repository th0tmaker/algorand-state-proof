// crates/state-proof/src/codec/mod.rs

mod msgpack;
pub mod proof;

pub(crate) use msgpack::{AlgorandMessagePack, DecodeError, MsgPackDecode, MsgPackEncode, Reader};
