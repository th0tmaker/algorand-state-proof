// crates/state-proof/src/codec/mod.rs

mod msgpack;
pub mod proof;

pub use crate::error::Error;
pub(crate) use msgpack::{AlgorandMessagePack, MsgPackDecode, MsgPackEncode, Reader};
