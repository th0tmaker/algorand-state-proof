// src/sumhash/mod.rs

// The Algorand Sumhash512 matrix: 8×1024 u64 values derived from
// SHAKE256(seed="Algorand"). Generated at compile time by build.rs.
include!(concat!(env!("OUT_DIR"), "/algorand_matrix.rs"));

/// Output size of Sumhash512 in bytes (8 × u64 = 64 bytes = 512 bits).
const SUMHASH_OUTPUT_BYTES: usize = 64;

/// Input block size in bytes (1024 bits = 128 bytes), matching the number
/// of matrix columns — one column per input bit.
const SUMHASH_BLOCK_BYTES: usize = 128;

/// Sumhash512 state for incremental hashing.
///
/// Implements the Algorand Sumhash512 hash function — a Merkle-Damgård
/// construction whose compression function is a matrix-vector product over
/// Z/2^64. The 8×1024 matrix is derived from SHAKE256(seed="Algorand").
pub(crate) struct Sumhash512 {
    /// Running chaining value; updated by each compression call.
    /// Initialised to all-zeros; holds the final digest after `finalize()`.
    state: [u64; 8],
    /// Partial input block accumulating bytes between `update()` calls.
    buf: [u8; SUMHASH_BLOCK_BYTES],
    /// Bytes written into `buf` since the last compression.
    pos: usize,
    /// Total bytes absorbed across all `update()` calls, used for padding.
    total_len: u64,
}

impl Sumhash512 {
    /// Returns a zeroed Sumhash512 state ready to absorb input.
    pub(crate) fn new() -> Self {
        Self {
            state: [0u64; 8],
            buf: [0u8; SUMHASH_BLOCK_BYTES],
            pos: 0,
            total_len: 0,
        }
    }

    /// Feeds `data` into the hasher, compressing any full blocks.
    pub(crate) fn update(&mut self, data: &[u8]) {
        todo!()
    }

    /// Finalises the hash and writes the 64-byte digest into `out`.
    pub(crate) fn finalize(self, out: &mut [u8; SUMHASH_OUTPUT_BYTES]) {
        todo!()
    }
}

/// Compresses one 128-byte `block` against `state` using `ALGORAND_MATRIX`.
///
/// Treats `block` as 1024 bits. For each of the 8 output words, sums the
/// matrix columns at positions where the corresponding input bit is 1,
/// accumulating mod 2^64. The result is XOR'd with the incoming `state`
/// (Davies-Meyer feed-forward) and written back.
fn compress(state: &mut [u64; 8], block: &[u8; SUMHASH_BLOCK_BYTES]) {
    todo!()
}
