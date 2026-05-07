// crates/state-proof/src/codec/msgpack.rs

use super::DecodeError;


// ── Format constants ──────────────────────────────────────────────────────────
// Named constants are used by the write helpers only; the Reader matches raw
// literals directly, where inline comments serve the same documentation purpose.

const FIXMAP_BASE:   u8 = 0x80;
const MAP16:         u8 = 0xde;
const MAP32:         u8 = 0xdf;
const FIXARRAY_BASE: u8 = 0x90;
const ARRAY16:       u8 = 0xdc;
const ARRAY32:       u8 = 0xdd;
const FIXSTR_BASE:   u8 = 0xa0;
const STR8:          u8 = 0xd9;
const BIN8:          u8 = 0xc4;
const BIN16:         u8 = 0xc5;
const BIN32:         u8 = 0xc6;
const UINT8:         u8 = 0xcc;
const UINT16:        u8 = 0xcd;
const UINT32:        u8 = 0xce;
const UINT64:        u8 = 0xcf;


// ── Write helpers ─────────────────────────────────────────────────────────────

/// Encodes a `u64` as the smallest `MessagePack` unsigned integer representation.
fn write_uint(out: &mut Vec<u8>, v: u64) {
    match v {
        0..=0x7f => out.push(v as u8),
        0x80..=0xff => { out.push(UINT8);  out.push(v as u8); }
        0x100..=0xffff => { out.push(UINT16); out.extend_from_slice(&(v as u16).to_be_bytes()); }
        0x10000..=0xffff_ffff => { out.push(UINT32); out.extend_from_slice(&(v as u32).to_be_bytes()); }
        _ => { out.push(UINT64); out.extend_from_slice(&v.to_be_bytes()); }
    }
}

/// Encodes a string with the appropriate `MessagePack` string prefix and length.
fn write_str(out: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    match b.len() {
        0..=31 => out.push(FIXSTR_BASE | b.len() as u8),
        32..=255 => { out.push(STR8); out.push(b.len() as u8); }
        _ => panic!("codec key too long"),
    }
    out.extend_from_slice(b);
}

/// Encodes a byte slice as `MessagePack` binary with the appropriate length prefix.
fn write_bin(out: &mut Vec<u8>, b: &[u8]) {
    match b.len() {
        0..=0xff => { out.push(BIN8);  out.push(b.len() as u8); }
        0x100..=0xffff => { out.push(BIN16); out.extend_from_slice(&(b.len() as u16).to_be_bytes()); }
        _ => { out.push(BIN32); out.extend_from_slice(&(b.len() as u32).to_be_bytes()); }
    }
    out.extend_from_slice(b);
}

/// Writes a `MessagePack` collection header (map/array), choosing fix, 16-bit, or 32-bit encoding based on size.
fn write_collection_header(out: &mut Vec<u8>, n: usize, fix: u8, tag16: u8, tag32: u8) {
    match n {
        0..=15 => out.push(fix | n as u8),
        16..=0xffff => { out.push(tag16); out.extend_from_slice(&(n as u16).to_be_bytes()); }
        _ => { out.push(tag32); out.extend_from_slice(&(n as u32).to_be_bytes()); }
    }
}

/// Writes a `MessagePack` map header for `n` key-value pairs.
fn write_map_header(out: &mut Vec<u8>, n: usize) {
    write_collection_header(out, n, FIXMAP_BASE, MAP16, MAP32);
}

/// Writes a `MessagePack` array header for `n` elements.
fn write_array_header(out: &mut Vec<u8>, n: usize) {
    write_collection_header(out, n, FIXARRAY_BASE, ARRAY16, ARRAY32);
}

// ── Value ─────────────────────────────────────────────────────────────────────

// Typed storage for `AlgorandMessagePack` entries. Data is held in its native
// form and serialized only when `encode_into()` is called on the containing map.
#[allow(dead_code)]
enum Value {
    /// Unsigned integer value.
    Uint(u64),
    /// Raw binary blob.
    Bin(Vec<u8>),
    /// Array of binary blobs.
    BinArray(Vec<Vec<u8>>),
    /// Array of unsigned integers.
    UintArray(Vec<u64>),
    /// Integer-keyed map; keys are sorted numerically during encoding for deterministic ordering.
    UintKeyedMap(Vec<(u64, AlgorandMessagePack)>),
    /// Nested MessagePack map with string keys.
    Map(AlgorandMessagePack),
}


// ── AlgorandMessagePack ───────────────────────────────────────────────────────

/// Canonical MessagePack builder that is compatibale with Algorand specs.
///
/// Keys are sorted lexicographically on [AlgorandMessagePack::encode];
/// zero and empty fields are omitted automatically.
pub(crate) struct AlgorandMessagePack {
    /// Holds ordered key-value pairs for Algorand MessagePack encoding, where
    /// the key is a string tag and the value is a variant of `Value`.
    entries: Vec<(&'static str, Value)>,
}

impl AlgorandMessagePack {
    /// Sorts keys lexicographically (Algorand canonical ordering requirement) and
    /// writes the map into `out`. Called recursively for nested Value::Map entries.
    fn encode_into(mut self, out: &mut Vec<u8>) {
        self.entries.sort_unstable_by_key(|(k, _)| *k);
        write_map_header(out, self.entries.len());
        for (key, value) in self.entries {
            write_str(out, key);
            match value {
                Value::Uint(v) => write_uint(out, v),
                Value::Bin(b) => write_bin(out, &b),
                Value::BinArray(elems) => {
                    write_array_header(out, elems.len());
                    for item in elems { write_bin(out, &item); }
                }
                Value::UintArray(elems) => {
                    write_array_header(out, elems.len());
                    for v in elems { write_uint(out, v); }
                }
                Value::UintKeyedMap(mut entries) => {
                    // Integer-keyed maps sort numerically per Algorand canonical ordering.
                    entries.sort_unstable_by_key(|(k, _)| *k);
                    write_map_header(out, entries.len());
                    for (k, v) in entries { write_uint(out, k); v.encode_into(out); }
                }
                Value::Map(inner) => inner.encode_into(out),
            }
        }
    }

    // Creates a new instance of the serialization format ready to append input data
    pub(crate) fn new() -> Self {
        Self { entries: Vec::new() }
    }

    /// Appends a u64 field; omitted if `v == 0`.
    pub(crate) fn uint(mut self, key: &'static str, v: u64) -> Self {
        if v != 0 {
            self.entries.push((key, Value::Uint(v)));
        }
        self
    }

    /// Appends a binary blob field; omitted if `b` is empty.
    pub(crate) fn bytes(mut self, key: &'static str, b: &[u8]) -> Self {
        if !b.is_empty() {
            self.entries.push((key, Value::Bin(b.to_vec())));
        }
        self
    }

    /// Appends an array-of-binaries field; omitted if `elems` is empty.
    pub(crate) fn bytes_array(mut self, key: &'static str, elems: &[impl AsRef<[u8]>]) -> Self {
        if !elems.is_empty() {
            let raw: Vec<Vec<u8>> = elems.iter().map(|i| i.as_ref().to_vec()).collect();
            self.entries.push((key, Value::BinArray(raw)));
        }
        self
    }

    /// Appends an array-of-u64 field; omitted if `elems` is empty.
    #[allow(dead_code)]
    pub(crate) fn uint_array(mut self, key: &'static str, elems: &[u64]) -> Self {
        if !elems.is_empty() {
            self.entries.push((key, Value::UintArray(elems.to_vec())));
        }
        self
    }

    /// Appends an integer-keyed map field; omitted if `entries` is empty.
    #[allow(dead_code)]
    pub(crate) fn uint_keyed_map(mut self, key: &'static str, entries: Vec<(u64, AlgorandMessagePack)>) -> Self {
        if !entries.is_empty() {
            self.entries.push((key, Value::UintKeyedMap(entries)));
        }
        self
    }

    /// Appends a nested map field; omitted if the inner map has no entries.
    pub(crate) fn map(mut self, key: &'static str, inner: AlgorandMessagePack) -> Self {
        if !inner.entries.is_empty() {
            self.entries.push((key, Value::Map(inner)));
        }
        self
    }

    /// Returns canonical `MessagePack` bytes.
    pub(crate) fn encode(self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }
}


// ── Reader ────────────────────────────────────────────────────────────────────

/// Cursor over a borrowed byte slice for reading MessagePack values.
pub(crate) struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Creates a new reader over the provided byte slice.
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Returns the number of unread bytes remaining.
    pub(crate) fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    /// Reads a single byte and advances the cursor.
    fn read_byte(&mut self) -> Result<u8, DecodeError> {
        if self.pos >= self.data.len() { return Err(DecodeError::UnexpectedEof); }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    /// Reads `n` bytes as a slice and advances the cursor.
    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.pos + n > self.data.len() { return Err(DecodeError::UnexpectedEof); }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    /// Reads a big-endian `u16` value.
    fn read_u16(&mut self) -> Result<u16, DecodeError> {
        let b = self.read_bytes(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    /// Reads a big-endian `u32` value.
    fn read_u32(&mut self) -> Result<u32, DecodeError> {
        let b = self.read_bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Reads a big-endian `u64` value.
    fn read_u64(&mut self) -> Result<u64, DecodeError> {
        let b = self.read_bytes(8)?;
        Ok(u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }

    /// Reads a `MessagePack` map header and returns the number of key-value pairs.
    pub(crate) fn read_map_len(&mut self) -> Result<usize, DecodeError> {
        let b = self.read_byte()?;
        match b {
            0x80..=0x8f => Ok((b & 0x0f) as usize),
            0xde => Ok(self.read_u16()? as usize),
            0xdf => Ok(self.read_u32()? as usize),
            _ => Err(DecodeError::UnexpectedType { expected: "map", got: b }),
        }
    }

    /// Reads a `MessagePack` array header and returns the number of elements.
    pub(crate) fn read_array_len(&mut self) -> Result<usize, DecodeError> {
        let b = self.read_byte()?;
        match b {
            0x90..=0x9f => Ok((b & 0x0f) as usize),
            0xdc => Ok(self.read_u16()? as usize),
            0xdd => Ok(self.read_u32()? as usize),
            _ => Err(DecodeError::UnexpectedType { expected: "array", got: b }),
        }
    }

    /// Reads a `MessagePack` string and returns it as a UTF-8 `&str`.
    pub(crate) fn read_str(&mut self) -> Result<&'a str, DecodeError> {
        let b = self.read_byte()?;
        let len = match b {
            0xa0..=0xbf => (b & 0x1f) as usize,
            0xd9 => self.read_byte()? as usize,
            0xda => self.read_u16()? as usize,
            0xdb => self.read_u32()? as usize,
            _ => return Err(DecodeError::UnexpectedType { expected: "str", got: b }),
        };
        core::str::from_utf8(self.read_bytes(len)?).map_err(|_| DecodeError::InvalidUtf8)
    }

    /// Reads a `MessagePack` unsigned integer and returns it as `u64`.
    pub(crate) fn read_uint(&mut self) -> Result<u64, DecodeError> {
        let b = self.read_byte()?;
        match b {
            0x00..=0x7f => Ok(b as u64),
            0xcc => Ok(self.read_byte()? as u64),
            0xcd => Ok(self.read_u16()? as u64),
            0xce => Ok(self.read_u32()? as u64),
            0xcf => self.read_u64(),
            _ => Err(DecodeError::UnexpectedType { expected: "uint", got: b }),
        }
    }

    /// Reads a `MessagePack` binary value and returns it as a byte slice.
    pub(crate) fn read_bin(&mut self) -> Result<&'a [u8], DecodeError> {
        let b = self.read_byte()?;
        let len = match b {
            // v1 bin types
            0xc4 => self.read_byte()? as usize,
            0xc5 => self.read_u16()? as usize,
            0xc6 => self.read_u32()? as usize,
            // v0 raw/str types (Raw=true)
            0xa0..=0xbf => (b & 0x1f) as usize,
            0xda => self.read_u16()? as usize,
            0xdb => self.read_u32()? as usize,
            _ => return Err(DecodeError::UnexpectedType { expected: "bin", got: b }),
        };
        self.read_bytes(len)
    }

    /// Skips one complete `MessagePack` value. Handles all MsgPack types,
    /// including nested maps and arrays by recursing once per contained 
    /// element. Used to step past unknown keys during map decoding.
    pub(crate) fn skip(&mut self) -> Result<(), DecodeError> {
        let b = self.read_byte()?;
        match b {
            0x00..=0x7f => Ok(()),  // positive fixint
            0x80..=0x8f => { for _ in 0..(b & 0x0f) * 2 { self.skip()?; } Ok(()) }  // fixmap
            0x90..=0x9f => { for _ in 0..(b & 0x0f) { self.skip()?; } Ok(()) }  // fixarray
            0xa0..=0xbf => { self.read_bytes((b & 0x1f) as usize)?; Ok(()) }  // fixstr
            0xc0 => Ok(()),  // nil
            0xc2 | 0xc3 => Ok(()),  // bool
            0xc4 => { let n = self.read_byte()? as usize; self.read_bytes(n)?; Ok(()) }
            0xc5 => { let n = self.read_u16()? as usize; self.read_bytes(n)?; Ok(()) }
            0xc6 => { let n = self.read_u32()? as usize; self.read_bytes(n)?; Ok(()) }
            0xc7 => { let n = self.read_byte()? as usize; self.read_bytes(n + 1)?; Ok(()) }  // ext8
            0xc8 => { let n = self.read_u16()? as usize; self.read_bytes(n + 1)?; Ok(()) }  // ext16
            0xc9 => { let n = self.read_u32()? as usize; self.read_bytes(n + 1)?; Ok(()) }  // ext32
            0xca => { self.read_bytes(4)?; Ok(()) }  // float32
            0xcb => { self.read_bytes(8)?; Ok(()) }  // float64
            0xcc => { self.read_byte()?;   Ok(()) }  // uint8
            0xcd => { self.read_bytes(2)?; Ok(()) }  // uint16
            0xce => { self.read_bytes(4)?; Ok(()) }  // uint32
            0xcf => { self.read_bytes(8)?; Ok(()) }  // uint64
            0xd0 => { self.read_byte()?;   Ok(()) }  // int8
            0xd1 => { self.read_bytes(2)?; Ok(()) }  // int16
            0xd2 => { self.read_bytes(4)?; Ok(()) }  // int32
            0xd3 => { self.read_bytes(8)?; Ok(()) }  // int64
            0xd4 => { self.read_bytes(2)?;  Ok(()) }  // fixext1
            0xd5 => { self.read_bytes(3)?;  Ok(()) }  // fixext2
            0xd6 => { self.read_bytes(5)?;  Ok(()) }  // fixext4
            0xd7 => { self.read_bytes(9)?;  Ok(()) }  // fixext8
            0xd8 => { self.read_bytes(17)?; Ok(()) }  // fixext16
            0xd9 => { let n = self.read_byte()? as usize; self.read_bytes(n)?; Ok(()) } // str8
            0xda => { let n = self.read_u16()? as usize; self.read_bytes(n)?; Ok(()) } // str16
            0xdb => { let n = self.read_u32()? as usize; self.read_bytes(n)?; Ok(()) } // str32
            0xdc => { let n = self.read_u16()? as usize; for _ in 0..n { self.skip()?; } Ok(()) } // array16
            0xdd => { let n = self.read_u32()? as usize; for _ in 0..n { self.skip()?; } Ok(()) } // array32
            0xde => { let n = self.read_u16()? as usize; for _ in 0..n * 2 { self.skip()?; } Ok(()) } // map16
            0xdf => { let n = self.read_u32()? as usize; for _ in 0..n * 2 { self.skip()?; } Ok(()) } // map32
            0xe0..=0xff => Ok(()),  // negative fixint
            _ => Err(DecodeError::UnexpectedType { expected: "any", got: b }),  // 0xc1: never used per spec
        }
    }
}


// ── MsgPackDecode ─────────────────────────────────────────────────────────────

/// Types that can be decoded from a canonical MessagePack binary form.
pub(crate) trait MsgPackDecode: Sized {
    /// Decodes one value from a shared `Reader` cursor; used when parsing a field
    /// within a larger structure. Does not check for trailing bytes.
    fn decode_from(r: &mut Reader<'_>) -> Result<Self, DecodeError>;

    /// Decodes `Self` from a complete byte slice. Returns [DecodeError::TrailingBytes]
    /// if any bytes remain unconsumed after the value, guarding against truncated reads.
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let val = Self::decode_from(&mut r)?;
        if r.remaining() > 0 { return Err(DecodeError::TrailingBytes); }
        Ok(val)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Empty map encodes to a single fixmap byte `0x80`.
    #[test]
    fn empty_map() {
        assert_eq!(AlgorandMessagePack::new().encode(), vec![0x80]);
    }

    /// Zero uint fields must be omitted.
    #[test]
    fn uint_zero_omitted() {
        assert_eq!(AlgorandMessagePack::new().uint("x", 0).encode(), vec![0x80]);
    }

    /// Empty bytes fields must be omitted.
    #[test]
    fn bytes_empty_omitted() {
        assert_eq!(AlgorandMessagePack::new().bytes("x", &[]).encode(), vec![0x80]);
    }

    /// Small u64 values use fixint encoding (single byte).
    #[test]
    fn uint_fixint() {
        // fixmap(1) + fixstr("t") + fixint(1)
        let mp = AlgorandMessagePack::new().uint("t", 1).encode();
        assert_eq!(mp, vec![
            0x81,       // fixmap, 1 entry
            0xa1, b't', // fixstr "t"
            0x01,       // fixint 1
        ]);
    }

    /// Keys must be sorted lexicographically.
    #[test]
    fn keys_sorted() {
        let mp = AlgorandMessagePack::new()
            .uint("z", 1)
            .uint("a", 2)
            .encode();
        // fixmap(2), then "a"=2, then "z"=1
        assert_eq!(mp[1], 0xa1);
        assert_eq!(mp[2], b'a');
        assert_eq!(mp[4], 0xa1);
        assert_eq!(mp[5], b'z');
    }

    /// Nested map with a non-zero inner field must appear.
    #[test]
    fn nested_map_non_empty() {
        let mp = AlgorandMessagePack::new()
            .map("hsh", AlgorandMessagePack::new().uint("t", 1))
            .encode();
        // fixmap(1) + fixstr("hsh") + fixmap(1) + fixstr("t") + fixint(1)
        assert_eq!(mp, vec![
            0x81,
            0xa3, b'h', b's', b'h',
            0x81,
            0xa1, b't',
            0x01,
        ]);
    }

    /// Nested map with all-zero inner fields must be omitted entirely.
    #[test]
    fn nested_map_empty_omitted() {
        let mp = AlgorandMessagePack::new()
            .map("hsh", AlgorandMessagePack::new().uint("t", 0))
            .encode();
        assert_eq!(mp, vec![0x80]);
    }

    // ── Encode: uint size variants ────────────────────────────────────────────

    /// Values 0x80..=0xff must use uint8 format (0xcc prefix).
    #[test]
    fn uint_u8() {
        let mp = AlgorandMessagePack::new().uint("v", 0x80).encode();
        assert_eq!(mp[3..], [0xcc, 0x80]);
    }

    /// Values 0x100..=0xffff must use uint16 format (0xcd prefix).
    #[test]
    fn uint_u16() {
        let mp = AlgorandMessagePack::new().uint("v", 0x100).encode();
        assert_eq!(mp[3..], [0xcd, 0x01, 0x00]);
    }

    /// Values 0x10000..=0xffffffff must use uint32 format (0xce prefix).
    #[test]
    fn uint_u32() {
        let mp = AlgorandMessagePack::new().uint("v", 0x10000).encode();
        assert_eq!(mp[3..], [0xce, 0x00, 0x01, 0x00, 0x00]);
    }

    /// Values above 0xffffffff must use uint64 format (0xcf prefix).
    #[test]
    fn uint_u64() {
        let mp = AlgorandMessagePack::new().uint("v", 0x1_0000_0000).encode();
        assert_eq!(mp[3..], [0xcf, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
    }

    // ── Encode: bytes and bytes_array ─────────────────────────────────────────

    /// A bytes field encodes with bin8 header (0xc4) followed by length and data.
    #[test]
    fn bytes_bin8() {
        let mp = AlgorandMessagePack::new().bytes("b", &[0xde, 0xad]).encode();
        // fixmap(1) + fixstr("b") + bin8 + len=2 + data
        assert_eq!(mp, vec![0x81, 0xa1, b'b', 0xc4, 0x02, 0xde, 0xad]);
    }

    /// A bytes_array field encodes as a fixarray of bin8 entries.
    #[test]
    fn bytes_array_encoding() {
        let elems: &[&[u8]] = &[&[0x01], &[0x02, 0x03]];
        let mp = AlgorandMessagePack::new().bytes_array("p", elems).encode();
        assert_eq!(mp, vec![
            0x81,                   // fixmap(1)
            0xa1, b'p',             // fixstr "p"
            0x92,                   // fixarray(2)
            0xc4, 0x01, 0x01,       // bin8, len=1, data
            0xc4, 0x02, 0x02, 0x03, // bin8, len=2, data
        ]);
    }

    // ── Encode: uint_array and uint_keyed_map ────────────────────────────────

    /// A uint_array field encodes as a fixarray of fixints.
    #[test]
    fn uint_array_encoding() {
        let mp = AlgorandMessagePack::new().uint_array("pr", &[1, 2, 3]).encode();
        assert_eq!(mp, vec![
            0x81,               // fixmap(1)
            0xa2, b'p', b'r',   // fixstr "pr"
            0x93,               // fixarray(3)
            0x01, 0x02, 0x03,   // fixints
        ]);
    }

    /// uint_array field is omitted when empty.
    #[test]
    fn uint_array_empty_omitted() {
        assert_eq!(AlgorandMessagePack::new().uint_array("pr", &[]).encode(), vec![0x80]);
    }

    /// Integer-keyed map encodes with uint keys sorted numerically.
    #[test]
    fn uint_keyed_map_encoding() {
        // Insert in reverse order to verify numeric sort.
        let entries = vec![
            (2u64, AlgorandMessagePack::new().uint("v", 20)),
            (1u64, AlgorandMessagePack::new().uint("v", 10)),
        ];
        let mp = AlgorandMessagePack::new().uint_keyed_map("r", entries).encode();
        let mut r = Reader::new(&mp);
        assert_eq!(r.read_map_len().unwrap(), 1);  // outer map
        assert_eq!(r.read_str().unwrap(), "r");
        assert_eq!(r.read_map_len().unwrap(), 2);  // inner uint-keyed map
        assert_eq!(r.read_uint().unwrap(), 1);  // key 1 comes first
        r.read_map_len().unwrap(); r.read_str().unwrap(); assert_eq!(r.read_uint().unwrap(), 10);
        assert_eq!(r.read_uint().unwrap(), 2);  // key 2 comes second
        r.read_map_len().unwrap(); r.read_str().unwrap(); assert_eq!(r.read_uint().unwrap(), 20);
        assert_eq!(r.remaining(), 0);
    }

    /// Integer-keyed map field is omitted when empty.
    #[test]
    fn uint_keyed_map_empty_omitted() {
        assert_eq!(AlgorandMessagePack::new().uint_keyed_map("r", vec![]).encode(), vec![0x80]);
    }

    // ── Decode: Reader basics ─────────────────────────────────────────────────

    /// Reader must parse fixmap, fixstr key, and fixint value correctly.
    #[test]
    fn reader_reads_fixmap_and_fixint() {
        let bytes = vec![0x81, 0xa1, b't', 0x01];
        let mut r = Reader::new(&bytes);
        assert_eq!(r.read_map_len().unwrap(), 1);
        assert_eq!(r.read_str().unwrap(), "t");
        assert_eq!(r.read_uint().unwrap(), 1);
        assert_eq!(r.remaining(), 0);
    }

    /// Reader must parse bin8 correctly.
    #[test]
    fn reader_reads_bin8() {
        let bytes = vec![0xc4, 0x03, 0xaa, 0xbb, 0xcc];
        let mut r = Reader::new(&bytes);
        assert_eq!(r.read_bin().unwrap(), &[0xaa, 0xbb, 0xcc]);
    }

    /// Reader must parse fixarray length correctly.
    #[test]
    fn reader_reads_fixarray_len() {
        let bytes = vec![0x93]; // fixarray(3)
        let mut r = Reader::new(&bytes);
        assert_eq!(r.read_array_len().unwrap(), 3);
    }

    /// skip() must advance past an unknown fixmap entry (key + value).
    #[test]
    fn reader_skip_unknown_key() {
        // fixmap(2): "known"=1, "unknown"=42 — simulate reading known, skipping unknown.
        let mp = AlgorandMessagePack::new().uint("known", 1).uint("unknown", 42).encode();
        let mut r = Reader::new(&mp);
        let n = r.read_map_len().unwrap();
        assert_eq!(n, 2);
        // read first key-value
        let k1 = r.read_str().unwrap();
        assert_eq!(k1, "known");
        r.read_uint().unwrap();
        // skip second key-value
        r.skip().unwrap(); // key
        r.skip().unwrap(); // value
        assert_eq!(r.remaining(), 0);
    }

    /// read_bin accepts v0 raw/str encoding (Raw=true on wire format).
    #[test]
    fn reader_reads_raw_str_as_bin() {
        // fixraw(2): 0xa2 0xde 0xad  — v0 raw format for 2 bytes.
        let mut r = Reader::new(&[0xa2, 0xde, 0xad]);
        assert_eq!(r.read_bin().unwrap(), &[0xde, 0xad]);
        // raw16: 0xda 0x00 0x03 + 3 bytes.
        let mut r2 = Reader::new(&[0xda, 0x00, 0x03, 0x01, 0x02, 0x03]);
        assert_eq!(r2.read_bin().unwrap(), &[0x01, 0x02, 0x03]);
    }

    // ── Decode: error cases ───────────────────────────────────────────────────

    /// Reading past end of buffer must return UnexpectedEof.
    #[test]
    fn reader_eof_error() {
        let mut r = Reader::new(&[]);
        assert_eq!(r.read_map_len(), Err(DecodeError::UnexpectedEof));
    }

    /// Reading a uint tag where a map is expected must return UnexpectedType.
    #[test]
    fn reader_wrong_type_error() {
        let mut r = Reader::new(&[0x01]); // fixint, not a map
        assert!(matches!(r.read_map_len(), Err(DecodeError::UnexpectedType { .. })));
    }

    /// Trailing bytes after a valid value must return TrailingBytes.
    #[test]
    fn from_msgpack_trailing_bytes_error() {
        struct Dummy;
        impl MsgPackDecode for Dummy {
            fn decode_from(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
                r.read_map_len()?;
                Ok(Dummy)
            }
        }
        let bytes = vec![0x80, 0xff]; // empty map + stray byte
        assert!(matches!(Dummy::decode(&bytes), Err(DecodeError::TrailingBytes)));
    }

    // ── Round-trips ───────────────────────────────────────────────────────────

    /// Encoding then decoding a uint must recover the original value.
    #[test]
    fn round_trip_uint() {
        struct Wrapper(u64);
        impl MsgPackDecode for Wrapper {
            fn decode_from(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
                let n = r.read_map_len()?;
                let mut v = 0u64;
                for _ in 0..n {
                    match r.read_str()? {
                        "v" => v = r.read_uint()?,
                        _   => r.skip()?,
                    }
                }
                Ok(Wrapper(v))
            }
        }
        for val in [1u64, 0x80, 0x100, 0x10000, 0x1_0000_0000] {
            let mp = AlgorandMessagePack::new().uint("v", val).encode();
            let decoded = Wrapper::decode(&mp).unwrap();
            assert_eq!(decoded.0, val);
        }
    }

    /// Encoding then decoding bytes must recover the original slice.
    #[test]
    fn round_trip_bytes() {
        struct Wrapper(Vec<u8>);
        impl MsgPackDecode for Wrapper {
            fn decode_from(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
                let n = r.read_map_len()?;
                let mut d = vec![];
                for _ in 0..n {
                    match r.read_str()? {
                        "d" => d = r.read_bin()?.to_vec(),
                        _   => r.skip()?,
                    }
                }
                Ok(Wrapper(d))
            }
        }
        let data = vec![0xde, 0xad, 0xbe, 0xef];
        let encoded = AlgorandMessagePack::new().bytes("d", &data).encode();
        let decoded = Wrapper::decode(&encoded).unwrap();
        assert_eq!(decoded.0, data);
    }
}
