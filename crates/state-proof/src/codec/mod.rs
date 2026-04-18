// crates/state-proof/src/codec/mod.rs

mod msgpack;

pub(crate) use msgpack::{AlgorandMessagePack, DecodeError, MsgPackDecode, MsgPackEncode, Reader};

#[cfg(test)]
pub(crate) use msgpack::from_msgpack;
