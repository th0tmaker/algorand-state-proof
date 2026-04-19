// crates/sumhash/src/lib.rs

use core::fmt;

use keccak::Shake256;

/// Byte length of a Sumhash512 digest (n × 8 = 8 × 64-bit words = 512 bits).
pub const DIGEST_SIZE: usize = 64;

/// A 64-byte Sumhash512 digest.
pub type Digest = [u8; DIGEST_SIZE];

// ── Sumhash constants ─────────────────────────────────────────────────────────

/// Number of message bytes consumed per compression (m_bytes − n × 8 = 128 − 64).
const SUMHASH512_BLOCK_SIZE: usize = 64;

// ── Lookup table ──────────────────────────────────────────────────────────────
/* The lookup table is a performance optimization for the compression function.
Rather than handling individual bits per row on every compression, we recompute
for every (row, byte_position, byte_value) triple the sum of these 8 matrix
columns corresponding to that byte's bits. Compression then reduces to one
lookup + wrapping add per input byte per row — an 8× reduction over the naive
bit-by-bit approach. */

/// Branchlessly accumulates the 8 matrix columns corresponding to the set bits
/// in `byte`.
///
/// Uses the identity `col & (bit as u64).wrapping_neg()`: when `bit` is 1 the
/// mask is `0xFFFFFFFFFFFFFFFF` (selects the column); when `bit` is 0 the mask
/// is `0` (zeroes it). No branches, no mispredictions.
#[inline(always)]
fn sum_byte(cols: &[u64; 8], byte: u8) -> u64 {
    // For each bit i: mask is all-ones if bit i is set, all-zeros otherwise; AND selects or zeroes the column.
    let a0 = cols[0] & ((byte & 1) as u64).wrapping_neg();
    let a1 = cols[1] & (((byte >> 1) & 1) as u64).wrapping_neg();
    let a2 = cols[2] & (((byte >> 2) & 1) as u64).wrapping_neg();
    let a3 = cols[3] & (((byte >> 3) & 1) as u64).wrapping_neg();
    let a4 = cols[4] & (((byte >> 4) & 1) as u64).wrapping_neg();
    let a5 = cols[5] & (((byte >> 5) & 1) as u64).wrapping_neg();
    let a6 = cols[6] & (((byte >> 6) & 1) as u64).wrapping_neg();
    let a7 = cols[7] & (((byte >> 7) & 1) as u64).wrapping_neg();

    // Sum the selected columns; wrapping_add keeps arithmetic mod 2^64 as required by the hash spec.
    a0.wrapping_add(a1).wrapping_add(a2).wrapping_add(a3)
        .wrapping_add(a4).wrapping_add(a5).wrapping_add(a6).wrapping_add(a7)
}

// ── Sumhash ───────────────────────────────────────────────────────────────────

/// Subset-sum hash over an `n × m`-bit matrix derived from [`keccak::Shake256`]
/// via `SHAKE256(u=64 || n || m || seed)`.
///
/// A lookup table is built at construction so each compression costs
/// `n × (m/8)` table lookups rather than `n × m` bit tests.
#[derive(Clone)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub(crate) struct Sumhash {
    /// Precomputed lookup table: `table[row][byte_pos][byte_val]`.
    table: Box<[Box<[[u64; 256]]>]>,
    /// Running chaining value — `table.len()` words/lanes, updated on each compression.
    state: Box<[u64]>,
    /// Scratch buffer for `compress()` output; pre-allocated to avoid a heap allocation per call.
    out: Box<[u64]>,
    /// Message block buffer; length = `m/8 - n×8` bytes (matrix input minus state portion).
    buf: Box<[u8]>,
    /// Cursor that tracks how many bytes are written into `buf` since the last compression.
    pos: usize,
    /// Total bytes fed across all `update()` calls; used for length padding.
    total_len: u64,
}

impl fmt::Debug for Sumhash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sumhash")
            .field("rows", &self.table.len())
            .field("pos", &self.pos)
            .field("total_len", &self.total_len)
            .finish_non_exhaustive()
    }
}

impl Sumhash {
    /// Absorbs `u=64 || n || m || seed` into [`keccak::Shake256`] and streams
    /// the output directly into a lookup table — 8 `u64` words per byte position,
    /// 256 sums each. Returns a zeroed sponge ready to accept input.
    pub(crate) fn new(n: usize, m: usize, seed: &[u8]) -> Self {
        // Catch oversized params early; `n` and `m` are encoded as `u16` in the SHAKE256 seed.
        debug_assert!(n <= u16::MAX as usize && m <= u16::MAX as usize,
            "n and m must fit in u16 for correct matrix derivation");

        let m_bytes = m / 8;
        let block_size = m_bytes - n * 8;

        // Derive the `(n × m)` matrix from SHAKE256 by absorbing
        // `u=64 || n || m || seed`, where `u`, `n` and `m` are
        // little-endian `u16` to match the encoding across all
        // Algorand implementations of sumhash.
        let mut shake = Shake256::new();
        shake.absorb(&64u16.to_le_bytes());
        shake.absorb(&(n as u16).to_le_bytes());
        shake.absorb(&(m as u16).to_le_bytes());
        shake.absorb(seed);
        shake.flip();

        // Stream `(n × m)` `u64` values from SHAKE256 directly into
        // the lookup table 8 words at a time (one column group per byte
        // position), skipping the intermediate matrix allocation entirely.
        let mut table: Vec<Box<[[u64; 256]]>> = Vec::with_capacity(n);
        let mut word_buf = [0u8; 8];
        let mut cols = [0u64; 8];
        for _ in 0..n {
            let mut row = vec![[0u64; 256]; m_bytes];
            for entry in row.iter_mut().take(m_bytes) {
                for col in cols.iter_mut() {
                    shake.squeeze(&mut word_buf);
                    *col = u64::from_le_bytes(word_buf);
                }
                for (b, slot) in entry.iter_mut().enumerate() {
                    *slot = sum_byte(&cols, b as u8);
                }
            }
            table.push(row.into_boxed_slice());
        }

        Self {
            table: table.into_boxed_slice(),
            state: vec![0u64; n].into_boxed_slice(),
            out: vec![0u64; n].into_boxed_slice(),
            buf: vec![0u8; block_size].into_boxed_slice(),
            pos: 0,
            total_len: 0,
        }
    }

    /// Compresses one message block into `self.state`.
    fn compress(&mut self, message: &[u8]) {
        let n = self.state.len();
        let state_bytes = n * 8;

        for i in 0..n {
            let mut x = 0u64;
            let row = &self.table[i];

            for (wi, &w) in self.state.iter().enumerate() {
                let wb = w.to_le_bytes();
                let base = wi * 8;
                for (bi, &b) in wb.iter().enumerate() {
                    x = x.wrapping_add(row[base + bi][b as usize]);
                }
            }

            for (j, &b) in message.iter().enumerate() {
                x = x.wrapping_add(row[state_bytes + j][b as usize]);
            }

            self.out[i] = x;
        }

        self.state.copy_from_slice(&self.out);
    }

    /// Updates the hasher by feeding `data` into its state, compressing any full blocks.
    pub(crate) fn update(&mut self, data: &[u8]) {
        assert!(
            (data.len() as u64) < (1u64 << (u64::BITS - 3)) - self.total_len,
            "input too large: total_len << 3 would overflow u64 in finalize"
        );

        self.total_len += data.len() as u64;
        let mut data = data;

        if self.pos > 0 {
            let space = self.buf.len() - self.pos;
            let n = space.min(data.len());
            self.buf[self.pos..self.pos + n].copy_from_slice(&data[..n]);
            self.pos += n;
            data = &data[n..];

            if self.pos == self.buf.len() {
                let block = self.buf.clone();
                self.compress(&block);
                self.pos = 0;
            }
        }

        while data.len() >= self.buf.len() {
            let (block, rest) = data.split_at(self.buf.len());
            self.compress(block);
            data = rest;
        }

        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.pos = data.len();
        }
    }

    /// Resets the hasher to a fresh, zeroed state.
    pub(crate) fn reset(&mut self) {
        self.state.fill(0);
        self.buf.fill(0);
        self.pos = 0;
        self.total_len = 0;
    }

    /// Finalises the hash using Merkle-Damgård padding and writes the digest to `out`.
    pub(crate) fn finalize(&mut self, out: &mut [u8]) {
        let b = self.buf.len();
        let p = b - 16;

        self.buf[self.pos] = 0x01;

        if self.pos < p {
            self.buf[self.pos + 1..p].fill(0);
        } else {
            self.buf[self.pos + 1..b].fill(0);
            let block = self.buf.clone();
            self.compress(&block);
            self.buf[0..p].fill(0);
        }

        let bit_len = self.total_len << 3;
        self.buf[p..p + 8].copy_from_slice(&bit_len.to_le_bytes());
        self.buf[p + 8..b].copy_from_slice(&0u64.to_le_bytes());

        let block = self.buf.clone();
        self.compress(&block);

        for (chunk, &w) in out.chunks_mut(8).zip(self.state.iter()) {
            chunk.copy_from_slice(&w.to_le_bytes());
        }
    }
}

// ── Sumhash512 ────────────────────────────────────────────────────────────────

/// [`Sumhash`] instantiated with Algorand's fixed parameters: `n=8` output words,
/// `m=1024`-bit input block, `seed=b"Algorand"` for domain separation.
///
/// The matrix derived from [`keccak::Shake256`] is 8 × 1024 `u64` entries;
/// each 64-byte message block is compressed with the 64-byte chaining value
/// to produce 8 × 64-bit words = 512 bits of output.
#[derive(Clone)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct Sumhash512(pub(crate) Sumhash);

impl fmt::Debug for Sumhash512 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl Sumhash512 {
    /// Returns a new instance of the hasher.
    pub fn new() -> Self {
        let inner = Sumhash::new(8, 1024, b"Algorand");
        debug_assert_eq!(inner.buf.len(), SUMHASH512_BLOCK_SIZE);
        Self(inner)
    }

    /// Feeds `data` into the hasher, compressing any full blocks.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// Resets the hasher to a fresh, zeroed state.
    pub fn reset(&mut self) {
        self.0.reset();
    }

    /// Finalises the hasher and writes the 64-byte digest into `out`.
    pub fn finalize(&mut self, out: &mut [u8; DIGEST_SIZE]) {
        self.0.finalize(out);
    }

    /// Returns the digest of `data` computed in a single pass.
    pub fn digest(data: impl AsRef<[u8]>) -> Digest {
        let mut h = Self::new();
        h.update(data.as_ref());
        let mut out = [0u8; DIGEST_SIZE];
        h.finalize(&mut out);
        out
    }
}

impl Default for Sumhash512 {
    fn default() -> Self { Self::new() }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MSG: &[u8] = b"hello";

    #[test]
    fn sumhash512_construction_invariants() {
        let h = Sumhash512::new();
        let inner = &h.0;
        assert_eq!(inner.table.len(), 8);
        assert_eq!(inner.table[0].len(), 128);
        assert_eq!(inner.state.len(), 8);
        assert_eq!(inner.buf.len(), 64);
        assert_eq!(inner.pos, 0);
        assert_eq!(inner.total_len, 0);
    }

    #[test]
    fn compress_is_deterministic() {
        let mut h1 = Sumhash512::new();
        let mut h2 = Sumhash512::new();
        let message = [0x42u8; SUMHASH512_BLOCK_SIZE];
        h1.0.compress(&message);
        h2.0.compress(&message);
        assert_eq!(h1.0.state, h2.0.state);
    }

    #[test]
    fn compress_different_messages_differ() {
        let mut h1 = Sumhash512::new();
        let mut h2 = Sumhash512::new();
        h1.0.compress(&[0x01u8; SUMHASH512_BLOCK_SIZE]);
        h2.0.compress(&[0x02u8; SUMHASH512_BLOCK_SIZE]);
        assert_ne!(h1.0.state, h2.0.state);
    }

    #[test]
    fn compress_changes_state() {
        let mut h = Sumhash512::new();
        let before = h.0.state.clone();
        h.0.compress(&[0x01u8; SUMHASH512_BLOCK_SIZE]);
        assert_ne!(h.0.state, before);
    }

    #[test]
    fn compress_chaining() {
        let mut h = Sumhash512::new();
        let message = [0x01u8; SUMHASH512_BLOCK_SIZE];
        h.0.compress(&message);
        let after_first = h.0.state.clone();
        h.0.compress(&message);
        assert_ne!(h.0.state, after_first);
    }

    #[test]
    fn update_partial_block_does_not_compress() {
        let mut h = Sumhash512::new();
        let initial_state = h.0.state.clone();
        h.update(&[0x01u8; 32]);
        assert_eq!(h.0.state, initial_state);
        assert_eq!(h.0.pos, 32);
        assert_eq!(h.0.total_len, 32);
    }

    #[test]
    fn update_exact_block_compresses() {
        let mut h = Sumhash512::new();
        let initial_state = h.0.state.clone();
        h.update(&[0x01u8; SUMHASH512_BLOCK_SIZE]);
        assert_ne!(h.0.state, initial_state);
        assert_eq!(h.0.pos, 0);
        assert_eq!(h.0.total_len, SUMHASH512_BLOCK_SIZE as u64);
    }

    #[test]
    fn update_total_len_accumulates() {
        let mut h = Sumhash512::new();
        h.update(&[0u8; 20]);
        h.update(&[0u8; 30]);
        h.update(&[0u8; 50]);
        assert_eq!(h.0.total_len, 100);
    }

    #[test]
    fn update_incremental_matches_single() {
        let data: Vec<u8> = (0u8..=255).cycle().take(200).collect();
        let mut h_single = Sumhash512::new();
        h_single.update(&data);
        let mut h_inc = Sumhash512::new();
        h_inc.update(&data[..50]);
        h_inc.update(&data[50..100]);
        h_inc.update(&data[100..170]);
        h_inc.update(&data[170..]);
        assert_eq!(h_single.0.state, h_inc.0.state);
        assert_eq!(h_single.0.pos, h_inc.0.pos);
        assert_eq!(h_single.0.total_len, h_inc.0.total_len);
    }

    #[test]
    fn update_empty_is_noop() {
        let mut h = Sumhash512::new();
        h.update(&[0x01u8; 32]);
        let state_before = h.0.state.clone();
        let pos_before = h.0.pos;
        let len_before = h.0.total_len;
        h.update(&[]);
        assert_eq!(h.0.state, state_before);
        assert_eq!(h.0.pos, pos_before);
        assert_eq!(h.0.total_len, len_before);
    }

    #[test]
    fn finalize_matches_digest() {
        let expected = Sumhash512::digest(TEST_MSG);
        let mut h = Sumhash512::new();
        h.update(TEST_MSG);
        let mut got = [0u8; DIGEST_SIZE];
        h.finalize(&mut got);
        assert_eq!(got, expected);
    }

    #[test]
    fn finalize_padding_overflow_path() {
        let input = [0xabu8; 50];
        let a = Sumhash512::digest(&input);
        assert_ne!(a, [0u8; DIGEST_SIZE]);
        let b = Sumhash512::digest(&[0xabu8; 47]);
        assert_ne!(a, b);
    }

    #[test]
    fn finalize_multi_block_input() {
        let input: Vec<u8> = (0u8..=255).cycle().take(200).collect();
        let expected = Sumhash512::digest(&input);
        let mut h = Sumhash512::new();
        h.update(&input);
        let mut got = [0u8; DIGEST_SIZE];
        h.finalize(&mut got);
        assert_eq!(got, expected);
    }

    #[test]
    fn digest_is_deterministic() {
        assert_eq!(Sumhash512::digest(TEST_MSG), Sumhash512::digest(TEST_MSG));
    }

    #[test]
    fn digest_empty_is_nonzero() {
        assert_ne!(Sumhash512::digest(b""), [0u8; DIGEST_SIZE]);
    }

    #[test]
    fn reset_reuses_hasher() {
        let mut h = Sumhash512::new();
        h.update(TEST_MSG);
        let mut first = [0u8; DIGEST_SIZE];
        h.finalize(&mut first);
        h.reset();
        assert_eq!(h.0.pos, 0);
        assert_eq!(h.0.total_len, 0);
        assert!(h.0.state.iter().all(|&w| w == 0));
        h.update(TEST_MSG);
        let mut second = [0u8; DIGEST_SIZE];
        h.finalize(&mut second);
        assert_eq!(first, second);
    }

    #[test]
    fn sumhash512_kat() {
        let cases: &[(&[u8], &str)] = &[
            (b"",
             "591591c93181f8f90054d138d6fa85b63eeeb416e6fd201e8375ba05d3cb55391047b9b64e534042562cc61944930c0075f906f16710cdade381ee9dd47d10a0"),
            (b"a",
             "ea067eb25622c633f5ead70ab83f1d1d76a7def8d140a587cb29068b63cb6407107aceecfdffa92579ed43db1eaa5bbeb4781223a6e07dd5b5a12d5e8bde82c6"),
            (b"ab",
             "ef09d55b6add510f1706a52c4b45420a6945d0751d73b801cbc195a54bc0ade0c9ebe30e09c2c00864f2bd1692eba79500965925e2be2d1ac334425d8d343694"),
            (b"abc",
             "a8e9b8259a93b8d2557434905790114a2a2e979fbdc8aa6fd373315a322bf0920a9b49f3dc3a744d8c255c46cd50ff196415c8245cdbb2899dec453fca2ba0f4"),
            (b"abcd",
             "1d4277f17e522c4607bc2912bb0d0ac407e60e3c86e2b6c7daa99e1f740fe2b4fc928defad8e1ccc4e7d96b79896ffe086836c172a3db40a154d2229484f359b"),
            (b"You must be the change you wish to see in the world. -Mahatma Gandhi",
             "5c5f63ac24392d640e5799c4164b7cc03593feeec85844cc9691ea0612a97caabc8775482624e1cd01fb8ce1eca82a17dd9d4b73e00af4c0468fd7d8e6c2e4b5"),
            ("I think, therefore I am. \u{2013} Rene Descartes.".as_bytes(),
             "2d4583cdb18710898c78ec6d696a86cc2a8b941bb4d512f9d46d96816d95cbe3f867c9b8bd31964406c847791f5669d60b603c9c4d69dadcb87578e613b60b7a"),
        ];

        for (input, expected_hex) in cases {
            let digest = Sumhash512::digest(*input);
            let got = digest.iter().map(|b| format!("{:02x}", b)).collect::<String>();
            assert_eq!(got, *expected_hex, "KAT failed for input {:?}", input);
        }
    }
}
