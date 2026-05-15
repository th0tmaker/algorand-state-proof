// crates/sumhash/src/lib.rs

#![no_std]
extern crate alloc;

use alloc::{boxed::Box, sync::Arc, vec};
use core::fmt;

use sha3::{Shake256, digest::{ExtendableOutput, Update, XofReader}};

// ── Sumhash constants ─────────────────────────────────────────────────────────

/// Bytes per state lane (`u64` = 8 bytes).
const LANE_BYTES: usize = 8;

/// Number of possible values for a single byte (2⁸ = 256).
const BYTE_VALUES: usize = 256;

/// Safety cap on table allocation — prevents accidental multi-GB allocations.
const MAX_TABLE_BYTES: usize = 1 << 30;

/// Maximum total bytes that may be fed into one hash — ensures `total_len · 8`
/// (the bit count written into the final padding block) fits in a `u64`.
const MAX_INPUT_BYTES: u64 = 1u64 << 61;

/// Byte length of a Sumhash512 digest (64 bytes = 512 bits = 8 · 64-bit lanes).
pub const SUMHASH512_DIGEST_SIZE: usize = 64;

// ── Sumhash types ─────────────────────────────────────────────────────────────

/// A 64-byte Sumhash512 digest.
pub type Sumhash512Digest = [u8; SUMHASH512_DIGEST_SIZE];


/// Interprets 64 raw XOF bytes as 8 LE `u64` column weights.
#[inline(always)]
fn unpack_cols(bytes: &[u8; 64]) -> [u64; 8] {
    let mut out = [0u64; 8];
    for (i, chunk) in bytes.chunks_exact(8).enumerate() {
        out[i] = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    out
}

/// Computes the subset sum of `cols` selected by the set bits of `byte`.
///
/// Each bit `i` of `byte` selects whether `cols[i]` is included in the sum.
/// The selection is branchless: `wrapping_neg` turns bit 1 into `0xFFFF…F`
/// (include) and bit 0 into `0` (exclude).
#[inline(always)]
fn subset_sum(cols: &[u64; 8], byte: u8) -> u64 {
    let mut sum = 0u64;
    for (i, &col) in cols.iter().enumerate() {
        let mask = (((byte >> i) & 1) as u64).wrapping_neg();
        sum = sum.wrapping_add(col & mask);
    }
    sum
}




// ── SumhashCore ───────────────────────────────────────────────────────────────

/// Immutable algorithm core for the sumhash construction — holds the precomputed
/// lookup table and matrix parameters, shared across hasher instances via [`Arc`].
pub(crate) struct SumhashCore<const N: usize> {
    /// Flattened lookup table precomputed from the `N · m`-bit SHAKE256-derived matrix.
    /// 
    /// Layout: `[byte_pos][byte_val][row]`.
    pub(crate) table: Box<[u64]>,
    /// Input width in bytes (m / 8).
    pub(crate) m_bytes: usize,
    /// Message bytes consumed per compression (m_bytes − N · LANE_BYTES).
    pub(crate) block_size: usize,
}

impl<const N: usize> SumhashCore<N> {
    /// Derives an `N · m`-bit sumhash matrix from `SHAKE256(64 || N || m || seed)`
    /// and precomputes it as a flat lookup table.
    ///
    /// - `N`: Number of `u64` output lanes, giving a digest of `N · 64` bits.
    /// - `m`: Total input width (bits); per-block message size = `m/8 − N·LANE_BYTES` bytes.
    /// - `seed`: Used as a domain separator — different seeds produce entirely
    /// independent matrix families.
    ///
    /// The table is a flat slice indexed as:
    /// 
    /// `[byte_pos][byte_val][row]`: `table[(pos · BYTE_VALUES · N) + (byte_val · N) + row]`.
    /// 
    /// All `N` row accumulators for one `(pos, byte_val)` pair are contiguous,
    /// enabling a single vector load per input byte during compression.
    ///
    /// Panics if `N == 0`, `N > 65535`, `m == 0`, `m % 8 != 0`, `m < N · 64`,
    /// or the resulting table size would exceed 1 GB.
    pub(crate) fn new(m: u16, seed: &[u8]) -> Self {
        assert!(N > 0, "N must be > 0");
        assert!(N <= u16::MAX as usize, "N must fit in u16 for spec-compliant domain separation");
        assert!(m > 0, "m must be > 0");
        assert_eq!(m % 8, 0, "m must be byte-aligned");

        let m_bytes = m as usize / u8::BITS as usize;
        let state_bytes = N * LANE_BYTES;

        assert!(m_bytes >= state_bytes, "m must be wide enough to hold the chaining value (m ≥ N · 64)");

        let block_size = m_bytes - state_bytes;

        let table_size = m_bytes
            .checked_mul(BYTE_VALUES)
            .and_then(|v| v.checked_mul(N))
            .expect("table size overflowed usize");

        assert!(table_size < MAX_TABLE_BYTES, "table size exceeds 1 GB");

        // The spec encodes XOF inputs: `u=64`, `N`, and `m`, as little-endian `u16`.
        let mut hasher = Shake256::default();
        hasher.update(&(u64::BITS as u16).to_le_bytes());
        hasher.update(&(N as u16).to_le_bytes());
        hasher.update(&m.to_le_bytes());
        hasher.update(seed);

        let mut reader = hasher.finalize_xof();

        let mut table = vec![0u64; table_size];
        let mut col_bytes = [0u8; u8::BITS as usize * LANE_BYTES];

        // Row-outer, pos-inner matches the Algorand spec XOF stream order.
        // Each (row, pos) pair reads 64 XOF bytes → 8 u64 column weights;
        // all 256 byte-value sums are precomputed and stored at [pos][byte_val][row].
        for row in 0..N {
            for pos in 0..m_bytes {
                reader.read(&mut col_bytes);
                let cols = unpack_cols(&col_bytes);
                for byte_val in 0u8..=u8::MAX {
                    let index = (pos * BYTE_VALUES * N) + (byte_val as usize * N) + row;
                    table[index] = subset_sum(&cols, byte_val);
                }
            }
        }

        Self {
            table: table.into_boxed_slice(),
            m_bytes,
            block_size,
        }
    }

    /// Computes one Merkle-Damgård compression over `state || message` and
    /// writes the result back into `state`. A separate `out` buffer is required
    /// because all `N` state lanes are read to compute every output lane —
    /// updating in-place would corrupt the byte values fed to later positions.
    pub(crate) fn compress(&self, state: &mut [u64; N], out: &mut [u64; N], message: &[u8]) {
        let state_bytes = N * LANE_BYTES;
        out.fill(0);

        // Serialize the chaining value as LE bytes. For each byte at position
        // `pos`, look up its `N` precomputed row contributions and accumulate them.
        for (lane_idx, &lane) in state.iter().enumerate() {
            let bytes = lane.to_le_bytes();
            for (byte_idx, &byte) in bytes.iter().enumerate() {
                let pos = (lane_idx * LANE_BYTES) + byte_idx;
                let offset = (pos * BYTE_VALUES * N) + (byte as usize * N);
                let entries: &[u64; N] = (&self.table[offset..offset + N]).try_into().unwrap();
                for (acc, &val) in out.iter_mut().zip(entries) {
                    *acc = acc.wrapping_add(val);
                }
            }
        }

        // Message bytes follow the chaining value in the matrix input.
        // Same accumulation — each byte selects `N` table entries at its position.
        for (byte_idx, &byte) in message.iter().enumerate() {
            let pos = state_bytes + byte_idx;
            let offset = (pos * BYTE_VALUES * N) + (byte as usize * N);
            let entries: &[u64; N] = (&self.table[offset..offset + N]).try_into().unwrap();
            for (acc, &val) in out.iter_mut().zip(entries) {
                *acc = acc.wrapping_add(val);
            }
        }

        state.copy_from_slice(out);
    }
}

impl<const N: usize> fmt::Debug for SumhashCore<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SumhashCore")
         .field("n", &N)
         .field("m_bytes", &self.m_bytes)
         .field("block_size", &self.block_size)
         .field("table_len", &self.table.len())
         .finish()
    }
}

// ── Sumhash ───────────────────────────────────────────────────────────────────

/// Stateful Merkle-Damgård hasher wrapping a shared [`SumhashCore<N>`].
/// Holds the running chaining value, message block buffer, and total byte count.
#[derive(Clone)]
pub(crate) struct Sumhash<const N: usize> {
    /// Shared core with precomputed matrix and parameters.
    core: Arc<SumhashCore<N>>,
    /// Running chaining value (`N` lanes), updated after each compression.
    /// Heap-allocated so large `N` does not overflow the stack on constrained `no_std` targets.
    state: Box<[u64]>,
    /// Temporary buffer for compression output — pre-allocated to avoid a heap allocation per call.
    /// Heap-allocated for the same stack-safety reason as `state`.
    scratch: Box<[u64]>,
    /// Message block buffer; filled incrementally until a full block is ready to compress.
    buf: Box<[u8]>,
    /// Current write position in `buf` — equals the number of bytes buffered since the last compression.
    buf_pos: usize,
    /// Total bytes fed via `update()`, encoded as a bit-length in the final padding block.
    // NOTE: Type matches the `go-sumhash` (uint64) reference; the 2-exabyte ceiling
    // is unreachable for Algorand’s main use case — hashing leaves and internal nodes
    // of Merkle trees. Consider changing integer type to `u128` if Sumhash<N> is ever
    // made pub — a GP hasher API should not impose arbitrary length limits on callers.
    total_len: u64,
}

impl<const N: usize> fmt::Debug for Sumhash<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sumhash")
            .field("buf_pos", &self.buf_pos)
            .field("total_len", &self.total_len)
            .finish_non_exhaustive()
    }
}

impl<const N: usize> Sumhash<N> {
    /// Creates a new hasher instance by building a [`SumhashCore`] for the
    /// given parameters and returning a zeroed sponge ready to accept input.
    pub(crate) fn new(m: u16, seed: &[u8]) -> Self {
        let core = Arc::new(SumhashCore::<N>::new(m, seed));
        let block_size = core.block_size;
        Self {
            core,
            state: vec![0u64; N].into_boxed_slice(),
            scratch: vec![0u64; N].into_boxed_slice(),
            buf: vec![0u8; block_size].into_boxed_slice(),
            buf_pos: 0,
            total_len: 0,
        }
    }

    /// Casts the heap-allocated state and scratch slices to fixed-size arrays and delegates to [`SumhashCore::compress`].
    fn compress(&mut self, message: &[u8]) {
        let state: &mut [u64; N] = (&mut *self.state).try_into().unwrap();
        let out: &mut [u64; N] = (&mut *self.scratch).try_into().unwrap();
        self.core.compress(state, out, message);
    }

    /// Updates the hasher by feeding `data` into its state, compressing any full blocks.
    pub(crate) fn update(&mut self, data: &[u8]) {
        let data_len = data.len() as u64;

        // Guard against total_len overflowing when shifted to bits in finalize().
        assert!(
            self.total_len.saturating_add(data_len) < MAX_INPUT_BYTES,
            "input too large: total_len << 3 would overflow u64 in finalize"
        );

        self.total_len += data_len;
        let block_len = self.buf.len();
        let mut data = data;

        /* Example with block_size=64:
        update(30 bytes)  → buffered,              buf_pos=30
        update(200 bytes) → fills buf to 64        → compress (phase 1, via buf)
                          → 166 bytes remain       → compress 64 (phase 2, direct)
                          → 102 bytes remain       → compress 64 (phase 2, direct)
                          →  38 bytes remain       → buffered, buf_pos=38 */

        // Drain any partial block already in the buffer before touching
        // new data, to preserve byte order across calls.
        if self.buf_pos > 0 {
            let space = block_len - self.buf_pos;
            let to_copy = space.min(data.len());
            self.buf[self.buf_pos..self.buf_pos + to_copy].copy_from_slice(&data[..to_copy]);
            self.buf_pos += to_copy;
            data = &data[to_copy..];

            if self.buf_pos == block_len {
                // Clone to avoid holding `&self.buf` across `&mut self.compress()`.
                let block = self.buf.clone();
                self.compress(&block);
                self.buf_pos = 0;
            }
        }

        // Compress full blocks directly from the input, bypassing the buffer.
        // NOTE: Single-block compression is used here — Algorand's Merkle node inputs are
        // small (typically one or two blocks), so the per-call overhead is negligible.
        // For larger streaming inputs, multi-block compression (passing all full blocks
        // in one call) would reduce function call overhead and enable cross-block SIMD,
        // where independent operations across blocks are interleaved in vector lanes.
        while data.len() >= block_len {
            let (block, rest) = data.split_at(block_len);
            self.compress(block);
            data = rest;
        }

        // Buffer any leftover bytes that don't yet form a complete block.
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_pos = data.len();
        }
    }

    /// Resets the hasher to a fresh, zeroed state, making the same instance reusable without full reconstruction.
    pub(crate) fn reset(&mut self) {
        self.state.fill(0);
        self.buf.fill(0);
        self.buf_pos = 0;
        self.total_len = 0;
    }

    /// Finalizes the hash by padding the input, encoding its length,
    /// processing the last block(s), and outputting the final state.
    ///
    /// Utilizes Merkle-Damgård construction with standard MD
    /// strengthening padding in steps:
    ///
    /// 1. Append `0x01` sentinel byte at `buf[buf_pos]` (LE bit order).
    /// 2. Zero-fill up to `len_field_pos = block_len - 16`.
    /// 3. If `buf_pos >= len_field_pos`, compress the current block first, then
    ///    zero-fill a fresh block up to `len_field_pos`.
    /// 4. Write `total_len * 8` (bit count) as two LE `u64`s in the final 16 bytes.
    /// 5. Compress the final padded block.
    /// 6. Serialize the state lanes as LE `u64`s into `out`.
    pub(crate) fn finalize(&mut self, out: &mut [u8]) {
        let block_len = self.buf.len();
        let len_field_pos = block_len - 2 * LANE_BYTES; // last 16 bytes hold the bit-length encoding

        // 1. Sentinel byte at buf_pos.
        self.buf[self.buf_pos] = 0x01;

        // 2. Zero-fill to the length field, compressing an overflow block if needed.
        if self.buf_pos < len_field_pos {
            self.buf[self.buf_pos + 1..len_field_pos].fill(0);
        } else {
            self.buf[self.buf_pos + 1..block_len].fill(0);
            // Clone to avoid holding `&self.buf` across `&mut self.compress()`.
            let block = self.buf.clone();
            self.compress(&block);
            self.buf[0..len_field_pos].fill(0);
        }

        // 3. Encode bit count as two LE u64s and compress the final block.
        let bit_len = self.total_len << 3;
        self.buf[len_field_pos..len_field_pos + 8].copy_from_slice(&bit_len.to_le_bytes());
        self.buf[len_field_pos + 8..block_len].copy_from_slice(&0u64.to_le_bytes());
        // Clone to avoid holding `&self.buf` across `&mut self.compress()`.
        let block = self.buf.clone();
        self.compress(&block);

        // 4. Serialise the final state into the output buffer.
        for (chunk, &w) in out.chunks_mut(8).zip(self.state.iter()) {
            chunk.copy_from_slice(&w.to_le_bytes());
        }
    }
}

// ── Sumhash512 ────────────────────────────────────────────────────────────────

/// `Sumhash` instantiated with Algorand's fixed parameters: `N=8` output lanes,
/// `m=1024`-bit input block, `seed=b"Algorand"` for domain separation.
///
/// The matrix derived from `SHAKE256` is 8 · 1024 `u64` entries;
/// each 64-byte message block is compressed with the 64-byte chaining value
/// to produce 8 · 64-bit lanes = 512 bits of output.
#[derive(Clone)]
pub struct Sumhash512(pub(crate) Sumhash<8>);

impl fmt::Debug for Sumhash512 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sumhash512")
            .field("buf_pos", &self.0.buf_pos)
            .field("total_len", &self.0.total_len)
            .finish_non_exhaustive()
    }
}

impl Sumhash512 {
    /// Returns a new hasher instance. 
    /// 
    /// Creating a new instance recomputes the internal lookup table (~2 MB),
    /// which can be expensive. For hashing multiple unrelated inputs, reuse
    /// the same hasher and call [`Sumhash512::reset`] after finalization.
    pub fn new() -> Self {
        Self(Sumhash::<8>::new(1024, b"Algorand"))
    }

    /// Feeds `data` into the hasher, buffering and compressing complete blocks as they arrive.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// Resets to the initial zeroed state — cheaper than [`Sumhash512::new`], reuses the precomputed matrix.
    pub fn reset(&mut self) {
        self.0.reset();
    }

    /// Finalizes the hash and writes the 64-byte digest into `out`.
    pub fn finalize(&mut self, out: &mut [u8; SUMHASH512_DIGEST_SIZE]) {
        self.0.finalize(out);
    }

    /// Computes and returns the digest of `data` in a single pass.
    pub fn digest(data: impl AsRef<[u8]>) -> Sumhash512Digest {
        let mut h = Self::new();
        h.update(data.as_ref());
        let mut out = [0u8; SUMHASH512_DIGEST_SIZE];
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
    use alloc::{format, string::String, vec::Vec};

    /// Block size for Algorand's Sumhash512 (m_bytes − N · LANE_BYTES = 128 − 64).
    const SUMHASH512_BLOCK_SIZE: usize = 64;
    const TEST_MSG: &[u8] = b"hello";

    /// Verify that `Sumhash512::new()` produces the correct table / state / buf
    /// dimensions for Algorand's fixed parameters (N=8, m=1024, seed=b"Algorand").
    ///
    /// ```text
    /// Derived values:
    /// m_bytes    = 1024 / 8 = 128
    /// state lanes = N = 8  (compile-time constant, encoded in type)
    /// block_size  = m_bytes - N · LANE_BYTES = 64
    /// ```
    #[test]
    fn sumhash512_construction_invariants() {
        let h = Sumhash512::new();
        let inner = &h.0;
        assert_eq!(inner.core.m_bytes, 128);
        assert_eq!(inner.core.block_size, 64);
        assert_eq!(inner.core.table.len(), 128 * BYTE_VALUES * 8);
        assert_eq!(inner.state.len(), 8);
        assert_eq!(inner.buf.len(), 64);
        assert_eq!(inner.buf_pos, 0);
        assert_eq!(inner.total_len, 0);
    }

    /// Sumhash512 `compress` must be pure: two instances built from the same seed, given
    /// the same message, must produce identical state.
    #[test]
    fn compress_is_deterministic() {
        let mut h1 = Sumhash512::new();
        let mut h2 = Sumhash512::new();
        let message = [0x42u8; SUMHASH512_BLOCK_SIZE];
        h1.0.compress(&message);
        h2.0.compress(&message);
        assert_eq!(h1.0.state, h2.0.state);
    }

    /// Different messages must produce different output states — basic
    /// injectivity check at the compression level.
    #[test]
    fn compress_different_messages_differ() {
        let mut h1 = Sumhash512::new();
        let mut h2 = Sumhash512::new();
        h1.0.compress(&[0x01u8; SUMHASH512_BLOCK_SIZE]);
        h2.0.compress(&[0x02u8; SUMHASH512_BLOCK_SIZE]);
        assert_ne!(h1.0.state, h2.0.state);
    }

    /// Sumhash512 `compress` must mix input into the state — a non-zero message
    /// fed into a zeroed state must produce a non-zero state.
    #[test]
    fn compress_changes_state() {
        let mut h = Sumhash512::new();
        let before = h.0.state.clone();
        h.0.compress(&[0x01u8; SUMHASH512_BLOCK_SIZE]);
        assert_ne!(h.0.state, before);
    }

    /// Chaining: the second compression must depend on the updated state, not
    /// the original zero state — same message twice must not produce the same
    /// output as the first compression.
    #[test]
    fn compress_chaining() {
        let mut h = Sumhash512::new();
        let message = [0x01u8; SUMHASH512_BLOCK_SIZE];
        h.0.compress(&message);
        let after_first = h.0.state.clone();
        h.0.compress(&message);
        assert_ne!(h.0.state, after_first);
    }

    /// Feeding less than one block must buffer the bytes without triggering a
    /// compression — state stays all-zeros, buf_pos reflects bytes written.
    #[test]
    fn update_partial_block_does_not_compress() {
        let mut h = Sumhash512::new();
        let initial_state = h.0.state.clone();
        h.update(&[0x01u8; 32]);
        assert_eq!(h.0.state, initial_state, "state must not change before a full block");
        assert_eq!(h.0.buf_pos, 32, "buf_pos must reflect the buffered byte count");
        assert_eq!(h.0.total_len, 32);
    }

    /// Feeding exactly one block must compress and reset the buffer cursor to 0.
    #[test]
    fn update_exact_block_compresses() {
        let mut h = Sumhash512::new();
        let initial_state = h.0.state.clone();
        h.update(&[0x01u8; SUMHASH512_BLOCK_SIZE]);
        assert_ne!(h.0.state, initial_state, "state must change after a full block");
        assert_eq!(h.0.buf_pos, 0, "buf_pos must reset to 0 after compression");
        assert_eq!(h.0.total_len, SUMHASH512_BLOCK_SIZE as u64);
    }

    /// Multiple `update()` calls must accumulate correctly across `total_len`.
    #[test]
    fn update_total_len_accumulates() {
        let mut h = Sumhash512::new();
        h.update(&[0u8; 20]);
        h.update(&[0u8; 30]);
        h.update(&[0u8; 50]);
        assert_eq!(h.0.total_len, 100);
    }

    /// Feeding data in one call must produce the same state as feeding the same
    /// data across multiple smaller calls — validates the buffering logic.
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
        assert_eq!(h_single.0.buf_pos, h_inc.0.buf_pos);
        assert_eq!(h_single.0.total_len, h_inc.0.total_len);
    }

    /// An empty `update()` call must be a complete no-op, meaning
    /// everything should remain unchanged.
    #[test]
    fn update_empty_is_noop() {
        let mut h = Sumhash512::new();
        h.update(&[0x01u8; 32]);
        let state_before = h.0.state.clone();
        let buf_pos_before = h.0.buf_pos;
        let len_before = h.0.total_len;
        h.update(&[]);
        assert_eq!(h.0.state, state_before);
        assert_eq!(h.0.buf_pos, buf_pos_before);
        assert_eq!(h.0.total_len, len_before);
    }

    /// Hasher `finalize()` must produce the same output as `digest()` for the same input.
    #[test]
    fn finalize_matches_digest() {
        let input = TEST_MSG;
        let expected = Sumhash512::digest(input);
        let mut h = Sumhash512::new();
        h.update(input);
        let mut got = [0u8; SUMHASH512_DIGEST_SIZE];
        h.finalize(&mut got);
        assert_eq!(got, expected);
    }

    /// When `buf_pos >= p` (p = block_size - 16 = 48), `finalize()` must compress an
    /// extra overflow block before writing the length field — exercises the `else`
    /// branch in the padding logic.
    #[test]
    fn finalize_padding_overflow_path() {
        // 50 bytes puts buf_pos=50 >= p=48, triggering the overflow branch.
        let input = [0xabu8; 50];
        let a = Sumhash512::digest(&input);
        // Must be stable and non-zero.
        assert_ne!(a, [0u8; SUMHASH512_DIGEST_SIZE]);
        // Must differ from a shorter input that stays under the threshold.
        let b = Sumhash512::digest(&[0xabu8; 47]);
        assert_ne!(a, b);
    }

    /// Input longer than one block (>64 bytes) must chain correctly through
    /// `update()` and produce the correct final digest via `finalize()`.
    #[test]
    fn finalize_multi_block_input() {
        let input: Vec<u8> = (0u8..=255).cycle().take(200).collect();
        let expected = Sumhash512::digest(&input);
        let mut h = Sumhash512::new();
        h.update(&input);
        let mut got = [0u8; SUMHASH512_DIGEST_SIZE];
        h.finalize(&mut got);
        assert_eq!(got, expected);
    }

    /// Same input must always produce the same digest.
    #[test]
    fn digest_is_deterministic() {
        let a = Sumhash512::digest(TEST_MSG);
        let b = Sumhash512::digest(TEST_MSG);
        assert_eq!(a, b);
    }

    /// Hashing the empty input must produce a non-zero digest.
    #[test]
    fn digest_empty_is_nonzero() {
        assert_ne!(Sumhash512::digest(b""), [0u8; SUMHASH512_DIGEST_SIZE]);
    }

    /// A reset hasher must produce the same digest as a freshly constructed one given the same input.
    #[test]
    fn reset_reuses_hasher() {
        let mut h = Sumhash512::new();
        h.update(TEST_MSG);
        let mut first = [0u8; SUMHASH512_DIGEST_SIZE];
        h.finalize(&mut first);
        h.reset();
        assert_eq!(h.0.buf_pos, 0);
        assert_eq!(h.0.total_len, 0);
        assert!(h.0.state.iter().all(|&w| w == 0));
        h.update(TEST_MSG);
        let mut second = [0u8; SUMHASH512_DIGEST_SIZE];
        h.finalize(&mut second);
        assert_eq!(first, second);
    }

    /// KAT (known-answer test) vectors following go-sumhash's `testVector` in sumhash512_test.go.
    /// Seed=b"Algorand", N=8, m=1024, no salt — identical to `New512(nil)`.
    /// Covers the full pipeline: matrix derivation, compression, MD padding, and output serialisation.
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
