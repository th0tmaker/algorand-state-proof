// crates/state-proof/src/codec/proof.rs


use merkle::{Sumhash512, Sumhash512Digest, HashFactory, HashType, Proof, SUMHASH512_DIGEST_SIZE};

use crate::codec::{AlgorandMessagePack, Error, MsgPackDecode, MsgPackEncode, Reader};

// ── HashType ──────────────────────────────────────────────────────────────────

impl MsgPackDecode for HashType {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self, Error> {
        HashType::try_from(r.read_uint()?).map_err(Error::InvalidHashType)
    }
}


// ── HashFactory ───────────────────────────────────────────────────────────────

impl MsgPackEncode for HashFactory {
    fn to_msgpack(&self) -> AlgorandMessagePack {
        AlgorandMessagePack::new().uint("t", self.hash_type as u64)
    }
}

impl MsgPackDecode for HashFactory {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self, Error> {
        let n = r.read_map_len()?;
        let mut hash_type = HashType::Sha512_256;
        for _ in 0..n {
            match r.read_str()? {
                "t" => hash_type = HashType::decode_from(r)?,
                _   => r.skip()?,
            }
        }
        Ok(Self { hash_type })
    }
}


// ── Proof ─────────────────────────────────────────────────────────────────────

impl MsgPackEncode for Proof<Sumhash512> {
    fn to_msgpack(&self) -> AlgorandMessagePack {
        AlgorandMessagePack::new()
            .map("hsh", self.hash_factory.to_msgpack())
            .bytes_array("pth", &self.path)
            .uint("td", self.tree_depth as u64)
    }
}

impl MsgPackDecode for Proof<Sumhash512> {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self, Error> {
        let n = r.read_map_len()?;
        let mut tree_depth: u8 = 0;
        let mut path: Vec<Sumhash512Digest> = Vec::new();
        let mut hash_factory = HashFactory::sumhash512();
        for _ in 0..n {
            match r.read_str()? {
                "td"  => tree_depth = r.read_uint()? as u8,
                "pth" => {
                    let len = r.read_array_len()?;
                    path = Vec::with_capacity(len);
                    for _ in 0..len {
                        let bytes = r.read_bin()?;
                        if bytes.len() != SUMHASH512_DIGEST_SIZE {
                            return Err(Error::InvalidDigestSize { expected: SUMHASH512_DIGEST_SIZE, got: bytes.len() });
                        }
                        let mut digest = [0u8; SUMHASH512_DIGEST_SIZE];
                        digest.copy_from_slice(bytes);
                        path.push(digest);
                    }
                }
                "hsh" => hash_factory = HashFactory::decode_from(r)?,
                _     => r.skip()?,
            }
        }
        if hash_factory.hash_type != HashType::Sumhash512 {
            return Err(Error::HashTypeMismatch {
                expected: HashType::Sumhash512,
                got: hash_factory.hash_type,
            });
        }
        Ok(Self { tree_depth, path, hash_factory })
    }
}


// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::MsgPackEncode;

    /// KAT using golden MsgPack bytes produced by Python algosdk.encoding.msgpack_encode.
    ///
    /// Proof: TreeDepth=5, HashType=1 (Sumhash), 12-entry path from
    /// go-stateproof-verification stateProof.json SigProofs field.
    ///
    /// Verifies: decode recovers correct fields, re-encode is byte-for-byte identical.
    #[test]
    fn kat_proof_golden_bytes() {
        const GOLDEN: &str = concat!(
            "83a368736881a17401a37074689c",
            "c440c1a359d33a5e28720f7117a296ceb19d5c5828f98c61743d43c5cc7f9b9d",
            "8763195029b14f80ee4bacde8c7d082a4b0c8b26605dfc8abfa0613d666c599d7f02",
            "c4403dad11bd629e0c4b8504e644517b3030247abf063cbecb0c0f82f5616c5a2b3b",
            "6ed2ab121c8f8e1bf27125f0954be647329cbda0177a9850512c56f8b2ee86f3",
            "c440c1a359d33a5e28720f7117a296ceb19d5c5828f98c61743d43c5cc7f9b9d",
            "8763195029b14f80ee4bacde8c7d082a4b0c8b26605dfc8abfa0613d666c599d7f02",
            "c440c1a359d33a5e28720f7117a296ceb19d5c5828f98c61743d43c5cc7f9b9d",
            "8763195029b14f80ee4bacde8c7d082a4b0c8b26605dfc8abfa0613d666c599d7f02",
            "c440c1a359d33a5e28720f7117a296ceb19d5c5828f98c61743d43c5cc7f9b9d",
            "8763195029b14f80ee4bacde8c7d082a4b0c8b26605dfc8abfa0613d666c599d7f02",
            "c440c1a359d33a5e28720f7117a296ceb19d5c5828f98c61743d43c5cc7f9b9d",
            "8763195029b14f80ee4bacde8c7d082a4b0c8b26605dfc8abfa0613d666c599d7f02",
            "c440c1a359d33a5e28720f7117a296ceb19d5c5828f98c61743d43c5cc7f9b9d",
            "8763195029b14f80ee4bacde8c7d082a4b0c8b26605dfc8abfa0613d666c599d7f02",
            "c440c1a359d33a5e28720f7117a296ceb19d5c5828f98c61743d43c5cc7f9b9d",
            "8763195029b14f80ee4bacde8c7d082a4b0c8b26605dfc8abfa0613d666c599d7f02",
            "c440c1a359d33a5e28720f7117a296ceb19d5c5828f98c61743d43c5cc7f9b9d",
            "8763195029b14f80ee4bacde8c7d082a4b0c8b26605dfc8abfa0613d666c599d7f02",
            "c440c1a359d33a5e28720f7117a296ceb19d5c5828f98c61743d43c5cc7f9b9d",
            "8763195029b14f80ee4bacde8c7d082a4b0c8b26605dfc8abfa0613d666c599d7f02",
            "c440c1a359d33a5e28720f7117a296ceb19d5c5828f98c61743d43c5cc7f9b9d",
            "8763195029b14f80ee4bacde8c7d082a4b0c8b26605dfc8abfa0613d666c599d7f02",
            "c440c1a359d33a5e28720f7117a296ceb19d5c5828f98c61743d43c5cc7f9b9d",
            "8763195029b14f80ee4bacde8c7d082a4b0c8b26605dfc8abfa0613d666c599d7f02",
            "a2746405"
        );

        let golden: Vec<u8> = (0..GOLDEN.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&GOLDEN[i..i + 2], 16).unwrap())
            .collect();

        let proof = Proof::<Sumhash512>::decode(&golden).unwrap();

        assert_eq!(proof.tree_depth, 5);
        assert_eq!(proof.hash_factory, HashFactory::sumhash512());
        assert_eq!(proof.path.len(), 12);
        assert_eq!(proof.encode(), golden);
    }

    /// Decoding a Proof<Sumhash512> whose wire HashFactory says Sha256 must return
    /// HashTypeMismatch, not silently produce a mismatched proof.
    #[test]
    fn wrong_hash_type_is_rejected() {
        // Encode a minimal proof (depth=1, empty path) with hash_type = Sha256 (2).
        let wire = AlgorandMessagePack::new()
            .map("hsh", AlgorandMessagePack::new().uint("t", HashType::Sha256 as u64))
            .uint("td", 1)
            .encode();
        let result = Proof::<Sumhash512>::decode(&wire);
        assert_eq!(
            result,
            Err(Error::HashTypeMismatch {
                expected: HashType::Sumhash512,
                got: HashType::Sha256,
            })
        );
    }
}
