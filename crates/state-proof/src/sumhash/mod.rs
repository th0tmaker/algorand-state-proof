// src/sumhash/mod.rs

use keccak::Shake256;

// ── Lookup table ──────────────────────────────────────────────────────────────
/* Rather than handling individual bits per row on every compression, we
precompute for every (row, byte_position, byte_value) triple the sum of thes
8 matrix columns corresponding to that byte's bits. Compression then reduces
to one lookup + wrapping add per input byte per row — an 8× reduction over
the naive bit-by-bit approach. */

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
pub(crate) struct Sumhash {
    /// Precomputed lookup table: `table[row][byte_pos][byte_val]`.
    table: Box<[Box<[[u64; 256]]>]>,
    /// Running chaining value — `table.len()` words/lanes, updated on each compression.
    state: Box<[u64]>,
    /// Message block buffer; length = `m/8 - n×8` bytes (matrix input minus state portion).
    buf: Box<[u8]>,
    /// Bytes written into `buf` since the last compression.
    pos: usize,
    /// Total bytes fed across all `update()` calls; used for length padding.
    total_len: u64,
}

impl Sumhash {
    /// Absorbs `u=64 || n || m || seed` into [`keccak::Shake256`] and streams
    /// the output directly into a lookup table — 8 `u64` words per byte position,
    /// 256 sums each. Returns a zeroed sponge ready to accept input.
    pub(crate) fn from_seed(n: usize, m: usize, seed: &[u8]) -> Self {
        let m_bytes = m / 8;

        // Derive the `(n × m)` matrix from SHAKE256 by absorbing
        // `u=64 || n || m || seed`, where `u`, `n` and `m` are
        // little-endian `u16` to match the encoding across all
        // Algorand implementations of sumhash.
        let mut shake = Shake256::new();
        shake.absorb(&64u16.to_le_bytes()); // u: bits per output word
        shake.absorb(&(n as u16).to_le_bytes()); // n: rows
        shake.absorb(&(m as u16).to_le_bytes()); // m: columns (bits)
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
            for j in 0..m_bytes {
                for col in cols.iter_mut() {
                    shake.squeeze(&mut word_buf);
                    *col = u64::from_le_bytes(word_buf);
                }
                for b in 0..=255 {
                    row[j][b] = sum_byte(&cols, b as u8);
                }
            }
            table.push(row.into_boxed_slice());
        }

        // The message block is the portion of the matrix input beyond the
        // chaining value: block_size = m_bytes - n*8.
        // For Algorand params (n=8, m=1024): 128 - 64 = 64 bytes.
        let block_size = m_bytes - n * 8;

        Self {
            table: table.into_boxed_slice(),
            state: vec![0u64; n].into_boxed_slice(),
            buf: vec![0u8; block_size].into_boxed_slice(),
            pos: 0,
            total_len: 0,
        }
    }

    /// Compresses one message block into `self.state`.
    ///
    /// The full matrix input is `state_bytes || message`: the chaining value
    /// serialised as little-endian `u64`s, followed by the message block.
    /// The result directly replaces the chaining value — no feed-forward.
    ///
    /// A temporary output buffer is required because all `n` state words are
    /// read when computing each output word; updating in-place would corrupt
    /// the state bytes fed to later rows.
    fn compress(&mut self, message: &[u8]) {
        let n = self.state.len();
        let state_bytes = n * 8;
        let mut out = vec![0u64; n];

        for i in 0..n {
            let mut x = 0u64;
            // State portion: byte positions 0..state_bytes, serialised as LE u64s.
            for (wi, &w) in self.state.iter().enumerate() {
                let wb = w.to_le_bytes();
                for (bi, &b) in wb.iter().enumerate() {
                    x = x.wrapping_add(self.table[i][wi * 8 + bi][b as usize]);
                }
            }
            // Message portion: byte positions state_bytes..m_bytes.
            for (j, &b) in message.iter().enumerate() {
                x = x.wrapping_add(self.table[i][state_bytes + j][b as usize]);
            }
            out[i] = x;
        }

        self.state.copy_from_slice(&out);
    }

    /// Feeds `data` into the hasher, compressing any full blocks.
    pub(crate) fn update(&mut self, data: &[u8]) {
        todo!()
    }

    /// Finalises the hash and writes the digest into `out`.
    pub(crate) fn finalize(self, out: &mut [u8]) {
        todo!()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that `Sumhash512::new()` produces the correct table / state / buf
    /// dimensions for Algorand's fixed parameters (n=8, m=1024, seed=b"Algorand").
    ///
    /// Derived values:
    ///   m_bytes     = 1024 / 8          = 128
    ///   state words = n                 =   8
    ///   block_size  = m_bytes - n*8     =  64
    #[test]
    fn sumhash512_construction_invariants() {
        let h = Sumhash512::new();
        let inner = &h.0;

        assert_eq!(inner.table.len(), 8,   "table must have n=8 rows");
        assert_eq!(inner.table[0].len(), 128, "each row must cover m_bytes=128 byte positions");
        assert_eq!(inner.state.len(), 8,   "state must hold n=8 words");
        assert_eq!(inner.buf.len(), 64,    "buf must hold block_size=64 bytes");
        assert_eq!(inner.pos, 0,           "pos must start at 0");
        assert_eq!(inner.total_len, 0,     "total_len must start at 0");
    }
}

// ── Sumhash512 ────────────────────────────────────────────────────────────────

/// [`Sumhash`] instantiated with Algorand's fixed parameters: `n=8` output words,
/// `m=1024`-bit input block, `seed=b"Algorand"` for domain separation.
///
/// The matrix derived from [`keccak::Shake256`] is 8 × 1024 `u64` entries;
/// each 64-byte message block is compressed with the 64-byte chaining value
/// to produce 8 × 64-bit words = 512 bits of output.
pub(crate) struct Sumhash512(Sumhash);

impl Sumhash512 {
    /// Returns a Sumhash512 state ready to absorb input.
    pub(crate) fn new() -> Self {
        Self(Sumhash::from_seed(8, 1024, b"Algorand"))
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    pub(crate) fn finalize(self, out: &mut [u8; 64]) {
        self.0.finalize(out);
    }
}
