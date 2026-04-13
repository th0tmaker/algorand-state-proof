// Rate for SHAKE256: 1600 − 2×256 = 1088 bits = 136 bytes.
pub(crate) const SHAKE256_STATE_WORDS: usize = 25;
pub(crate) const SHAKE256_RATE: usize = 136;

pub(crate) struct Shake256 {
    /// The 1600-bit (200-byte) Keccak-f[1600] permutation state, stored as 25 × u64 words/lanes.
    state: [u64; SHAKE256_STATE_WORDS],
    /// Input buffer accumulating bytes until a full 136-byte block is ready.
    buf: [u8; SHAKE256_RATE],
    /// Bytes written into `buf` since the last permutation. Resets to 0 each block.
    pos: usize,
    /// Set to `true` after `finalize_xof()`; guards against absorbing after squeezing has begun.
    squeezing: bool,
    /// Bytes consumed from the current output block. When it hits `SHAKE256_RATE`, the block
    /// is exhausted and the next permutation is triggered.
    squeeze_pos: usize,
}

impl Shake256 {
    pub(crate) fn new() -> Self {
        Self {
            state: [0u64; SHAKE256_STATE_WORDS],
            buf: [0u8; SHAKE256_RATE],
            pos: 0,
            squeezing: false,
            squeeze_pos: 0,
        }
    }

    pub(crate) fn absorb(&mut self, data: &[u8]) {
        for &byte in data {
            // Write one byte into the buffer at the current position.
            self.buf[self.pos] = byte;
            self.pos += 1;

            // When the buffer is full (136 bytes = one rate block), XOR it into
            // the state, apply the permutation, then clear the buffer for the
            // next block.
            if self.pos == SHAKE256_RATE {
                self.process_block();
                self.buf = [0u8; SHAKE256_RATE];
                self.pos = 0;
            }
        }
    }

    pub(crate) fn finalize_xof(&mut self) {
        // Apply SHAKE256 padding to the remaining bytes in the buffer:
        //   - 0x1f at the current write position: SHAKE domain separation
        //     (distinguishes SHAKE from SHA-3, which uses 0x06).
        //   - 0x80 at the last byte of the rate block: the trailing '1' bit
        //     of the multi-rate padding rule (pad10*1).
        // If pos == SHAKE256_RATE - 1 both XORs hit the same byte: 0x1f ^ 0x80 = 0x9f.
        self.buf[self.pos] ^= 0x1f;
        self.buf[SHAKE256_RATE - 1] ^= 0x80;
        // Process the final (partial) block, then switch to squeeze mode.
        self.process_block();
        self.squeezing = true;
        self.squeeze_pos = 0;
    }

    pub(crate) fn squeeze_bytes(&mut self, out: &mut [u8]) {
        for byte in out.iter_mut() {
            // When all 136 rate bytes of the current output block have been
            // consumed, apply another permutation to produce the next block.
            if self.squeeze_pos == SHAKE256_RATE {
                keccak_f(&mut self.state);
                self.squeeze_pos = 0;
            }
            // Extract one byte from the state in little-endian lane order:
            // lane index = squeeze_pos / 8, byte within lane = squeeze_pos % 8.
            *byte = (self.state[self.squeeze_pos / 8] >> (8 * (self.squeeze_pos % 8))) as u8;
            self.squeeze_pos += 1;
        }
    }

    fn process_block(&mut self) {
        // XOR the 136-byte buffer into the first 17 u64 lanes of the state
        // (136 / 8 = 17), interpreting each 8-byte chunk as a little-endian u64.
        for i in 0..(SHAKE256_RATE / 8) {
            let word = u64::from_le_bytes(self.buf[8 * i..8 * (i + 1)].try_into().unwrap());
            self.state[i] ^= word;
        }
        keccak_f(&mut self.state);
    }
}

pub(crate) fn keccak_f(state: &mut [u64; SHAKE256_STATE_WORDS]) {
    for round in 0..24 {
        // θ — column parity mixing.
        // C[x] = XOR of all lanes in column x.
        // D[x] = C[x-1] XOR rot(C[x+1], 1) — the mixing derivative.
        // Each lane is XOR'd with D[x] for its column x.
        let c = [
            state[0] ^ state[5] ^ state[10] ^ state[15] ^ state[20],
            state[1] ^ state[6] ^ state[11] ^ state[16] ^ state[21],
            state[2] ^ state[7] ^ state[12] ^ state[17] ^ state[22],
            state[3] ^ state[8] ^ state[13] ^ state[18] ^ state[23],
            state[4] ^ state[9] ^ state[14] ^ state[19] ^ state[24],
        ];
        let d = [
            c[4] ^ c[1].rotate_left(1),
            c[0] ^ c[2].rotate_left(1),
            c[1] ^ c[3].rotate_left(1),
            c[2] ^ c[4].rotate_left(1),
            c[3] ^ c[0].rotate_left(1),
        ];
        for y in 0..5 {
            for x in 0..5 {
                state[x + 5 * y] ^= d[x];
            }
        }

        // ρ + π — combined into one pass over the state.
        // ρ rotates each lane by a fixed offset RHO[x][y].
        // π permutes lanes to new positions: old (x,y) → new (y, (2x+3y) mod 5).
        // Both are linear so they can be merged: rotate first, then write to
        // the new position in the temporary array b.
        const RHO: [[u32; 5]; 5] = [
            [ 0, 36,  3, 41, 18],
            [ 1, 44, 10, 45,  2],
            [62,  6, 43, 15, 61],
            [28, 55, 25, 21, 56],
            [27, 20, 39,  8, 14],
        ];
        let mut b = [0u64; 25];
        for y in 0..5usize {
            for x in 0..5usize {
                b[y + 5 * ((2 * x + 3 * y) % 5)] = state[x + 5 * y].rotate_left(RHO[x][y]);
            }
        }

        // χ — the only non-linear step.
        // A'[x,y] = B[x,y] XOR ((NOT B[x+1,y]) AND B[x+2,y]), x indices mod 5.
        for y in 0..5usize {
            for x in 0..5usize {
                state[x + 5 * y] = b[x + 5 * y] ^ ((!b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
            }
        }

        // ι — XOR a round-specific constant into lane (0,0).
        // The 24 constants break the symmetry of the permutation; without them
        // every round would be identical and the function would be trivially invertible.
        const RC: [u64; 24] = [
            0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
            0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
            0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
            0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
            0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
            0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
            0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
            0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
        ];
        state[0] ^= RC[round];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SHAKE256 of the empty message, first 32 bytes of output.
    /// Skipping absorb entirely exercises the edge case where pos=0 when
    /// finalize_xof is called — the padding bytes land at buf[0] and
    /// buf[135] with nothing in between, which is the smallest valid block.
    /// Expected value from the XKCP reference test vectors (ShortMsgKAT_SHAKE256.txt).
    #[test]
    fn test_shake256_empty() {
        // Create a new instance of Shake256
        let mut shake = Shake256::new();

        // Finalize XOF with empty message (no absorb call).
        shake.finalize_xof();

        // Squeeze the first 32 bytes of XOF output.
        let mut out = [0u8; 32];
        shake.squeeze_bytes(&mut out);

        // With an empty message the entire 136-byte block is just 0x1f at byte 0
        // and 0x80 at byte 135, zeros elsewhere. Keccak-f on that padded block
        // should produce the following bytes deterministically (XKCP ShortMsgKAT_SHAKE256.txt).
        assert_eq!(
            out,
            [0x46, 0xb9, 0xdd, 0x2b, 0x0b, 0xa8, 0x8d, 0x13,
             0x23, 0x3b, 0x3f, 0xeb, 0x74, 0x3e, 0xeb, 0x24,
             0x3f, 0xcd, 0x52, 0xea, 0x62, 0xb8, 0x1b, 0x82,
             0xb5, 0x0c, 0x27, 0x64, 0x6e, 0xd5, 0x76, 0x2f],
        );
    }
    
    /// SHAKE256 of a single byte 0xCC, first 32 bytes of output.
    /// Exercises the absorb path with non-empty data — the byte 
    /// is written into buf field, then `finalize_xof` applies
    /// padding and processes the single partial block
    /// (as 1 data byte + padding, well under 136 bytes).
    /// Expected value from the XKCP reference test vectors
    /// (ShortMsgKAT_SHAKE256.txt, Len=8, Msg=CC).   
    #[test]
    fn test_shake256_absorb() {
        // Create a new instance of Shake256
        let mut shake = Shake256::new();

        // Finalize XOF with absorb call (single byte literal 0xCC).
        shake.absorb(&[0xCC]);
        shake.finalize_xof();

        // Squeeze the first 32 bytes of XOF output.
        let mut out = [0u8; 32];
        shake.squeeze_bytes(&mut out);

        // A mismatch here points to a bug in absorb (bytes written to wrong
        // buf positions) or the interaction between `absorb`` and `finalize_xof`.
        assert_eq!(
            out,
            [0xdd, 0xbf, 0x55, 0xdb, 0xf6, 0x59, 0x77, 0xe3,
             0xe2, 0xa3, 0x67, 0x4d, 0x33, 0xe4, 0x79, 0xf7,
             0x81, 0x63, 0xd5, 0x92, 0x66, 0x6b, 0xc5, 0x76,
             0xfe, 0xb5, 0xe4, 0xc4, 0x04, 0xea, 0x5e, 0x53],
        );
    }

    /// SHAKE256 of a 136-byte message (exactly one full rate block), first 32 bytes of output.
    /// With exactly 136 bytes, absorb fills the buffer completely and calls process_block
    /// once, then finalize_xof pads a fresh empty buffer — exercising the block boundary.
    /// Expected value from XKCP reference test vectors (ShortMsgKAT_SHAKE256.txt, Len=1088).
    #[test]
    fn test_shake256_multi_block_absorb() {
        // Define the 136-byte message
        #[rustfmt::skip]
        let msg = [
            0xB3, 0x2D, 0x95, 0xB0, 0xB9, 0xAA, 0xD2, 0xA8,
            0x81, 0x6D, 0xE6, 0xD0, 0x6D, 0x1F, 0x86, 0x00,
            0x85, 0x05, 0xBD, 0x8C, 0x14, 0x12, 0x4F, 0x6E,
            0x9A, 0x16, 0x3B, 0x5A, 0x2A, 0xDE, 0x55, 0xF8,
            0x35, 0xD0, 0xEC, 0x38, 0x80, 0xEF, 0x50, 0x70,
            0x0D, 0x3B, 0x25, 0xE4, 0x2C, 0xC0, 0xAF, 0x05,
            0x0C, 0xCD, 0x1B, 0xE5, 0xE5, 0x55, 0xB2, 0x30,
            0x87, 0xE0, 0x4D, 0x7B, 0xF9, 0x81, 0x36, 0x22,
            0x78, 0x0C, 0x73, 0x13, 0xA1, 0x95, 0x4F, 0x87,
            0x40, 0xB6, 0xEE, 0x2D, 0x3F, 0x71, 0xF7, 0x68,
            0xDD, 0x41, 0x7F, 0x52, 0x04, 0x82, 0xBD, 0x3A,
            0x08, 0xD4, 0xF2, 0x22, 0xB4, 0xEE, 0x9D, 0xBD,
            0x01, 0x54, 0x47, 0xB3, 0x35, 0x07, 0xDD, 0x50,
            0xF3, 0xAB, 0x42, 0x47, 0xC5, 0xDE, 0x9A, 0x8A,
            0xBD, 0x62, 0xA8, 0xDE, 0xCE, 0xA0, 0x1E, 0x3B,
            0x87, 0xC8, 0xB9, 0x27, 0xF5, 0xB0, 0x8B, 0xEB,
            0x37, 0x67, 0x4C, 0x6F, 0x8E, 0x38, 0x0C, 0x04,
        ];

        // Create a new instance of Shake256
        let mut shake = Shake256::new();

        // Finalize XOF with absorb call (absorbing msg consumes full rate block).
        shake.absorb(&msg);
        shake.finalize_xof();

        // Squeeze the first 32 bytes of XOF output.
        let mut out = [0u8; 32];
        shake.squeeze_bytes(&mut out);

        // A mismatch here means process_block is faulty or was not called correctly
        // at the block boundary, or buf was not cleared properly before `finalize_xof`.
        assert_eq!(
            out,
            [0xCC, 0x2E, 0xAA, 0x04, 0xEE, 0xF8, 0x47, 0x9C,
             0xDA, 0xE8, 0x56, 0x6E, 0xB8, 0xFF, 0xA1, 0x10,
             0x0A, 0x40, 0x79, 0x95, 0xBF, 0x99, 0x9A, 0xE9,
             0x7E, 0xDE, 0x52, 0x66, 0x81, 0xDC, 0x34, 0x90],
        );
    }
    
    /// SHAKE256 of the 136-byte XKCP message (Len=1088), squeezed to 144 bytes.
    /// The squeeze block is 136 bytes; squeezing 144 forces squeeze_bytes to
    /// exhaust the first output block and apply another keccak_f to produce
    /// the next — exercising the squeeze_pos == SHAKE256_RATE branch.
    /// Expected values from XKCP reference (ShortMsgKAT_SHAKE256.txt, Len=1088).
    #[test]
    fn test_shake256_squeeze_block_boundary() {
        #[rustfmt::skip]
        let msg = [
            0xB3, 0x2D, 0x95, 0xB0, 0xB9, 0xAA, 0xD2, 0xA8,
            0x81, 0x6D, 0xE6, 0xD0, 0x6D, 0x1F, 0x86, 0x00,
            0x85, 0x05, 0xBD, 0x8C, 0x14, 0x12, 0x4F, 0x6E,
            0x9A, 0x16, 0x3B, 0x5A, 0x2A, 0xDE, 0x55, 0xF8,
            0x35, 0xD0, 0xEC, 0x38, 0x80, 0xEF, 0x50, 0x70,
            0x0D, 0x3B, 0x25, 0xE4, 0x2C, 0xC0, 0xAF, 0x05,
            0x0C, 0xCD, 0x1B, 0xE5, 0xE5, 0x55, 0xB2, 0x30,
            0x87, 0xE0, 0x4D, 0x7B, 0xF9, 0x81, 0x36, 0x22,
            0x78, 0x0C, 0x73, 0x13, 0xA1, 0x95, 0x4F, 0x87,
            0x40, 0xB6, 0xEE, 0x2D, 0x3F, 0x71, 0xF7, 0x68,
            0xDD, 0x41, 0x7F, 0x52, 0x04, 0x82, 0xBD, 0x3A,
            0x08, 0xD4, 0xF2, 0x22, 0xB4, 0xEE, 0x9D, 0xBD,
            0x01, 0x54, 0x47, 0xB3, 0x35, 0x07, 0xDD, 0x50,
            0xF3, 0xAB, 0x42, 0x47, 0xC5, 0xDE, 0x9A, 0x8A,
            0xBD, 0x62, 0xA8, 0xDE, 0xCE, 0xA0, 0x1E, 0x3B,
            0x87, 0xC8, 0xB9, 0x27, 0xF5, 0xB0, 0x8B, 0xEB,
            0x37, 0x67, 0x4C, 0x6F, 0x8E, 0x38, 0x0C, 0x04,
        ];

        // Create a new instance of Shake256
        let mut shake = Shake256::new();

        // Finalize XOF with absorb call (absorbing msg consumes full rate block).
        shake.absorb(&msg);
        shake.finalize_xof();

        // Squeeze 144 bytes of XOF output.
        let mut out = [0u8; 144];
        shake.squeeze_bytes(&mut out);

        // Bytes 0–135 come from the first squeeze block; bytes 136–143 require
        // a second keccak_f. A mismatch in bytes 136+ means the squeeze boundary
        // handling is broken.
        #[rustfmt::skip]
        assert_eq!(
            out,
            [
                0xCC, 0x2E, 0xAA, 0x04, 0xEE, 0xF8, 0x47, 0x9C,  // 0–7
                0xDA, 0xE8, 0x56, 0x6E, 0xB8, 0xFF, 0xA1, 0x10,  // 8–15
                0x0A, 0x40, 0x79, 0x95, 0xBF, 0x99, 0x9A, 0xE9,  // 16–23
                0x7E, 0xDE, 0x52, 0x66, 0x81, 0xDC, 0x34, 0x90,  // 24–31
                0x61, 0x6F, 0x28, 0x44, 0x2D, 0x20, 0xDA, 0x92,  // 32–39
                0x12, 0x4C, 0xE0, 0x81, 0x58, 0x8B, 0x81, 0x49,  // 40–47
                0x1A, 0xED, 0xF6, 0x5C, 0xAA, 0xF0, 0xD2, 0x7E,  // 48–55
                0x82, 0xA4, 0xB0, 0xE1, 0xD1, 0xCA, 0xB2, 0x38,  // 56–63
                0x33, 0x32, 0x8F, 0x1B, 0x8D, 0xA4, 0x30, 0xC8,  // 64–71
                0xA0, 0x87, 0x66, 0xA8, 0x63, 0x70, 0xFA, 0x84,  // 72–79
                0x8A, 0x79, 0xB5, 0x99, 0x8D, 0xB3, 0xCF, 0xFD,  // 80–87
                0x05, 0x7B, 0x96, 0xE1, 0xE2, 0xEE, 0x0E, 0xF2,  // 88–95
                0x29, 0xEC, 0xA1, 0x33, 0xC1, 0x55, 0x48, 0xF9,  // 96–103
                0x83, 0x99, 0x02, 0x04, 0x37, 0x30, 0xE4, 0x4B,  // 104–111
                0xC5, 0x2C, 0x39, 0xFA, 0xDC, 0x1D, 0xDE, 0xEA,  // 112–119
                0xD9, 0x5F, 0x99, 0x39, 0xF2, 0x20, 0xCA, 0x30,  // 120–127
                0x06, 0x61, 0x54, 0x0D, 0xF7, 0xED, 0xD9, 0xAF,  // 128–135 (end of block 1)
                0x37, 0x8A, 0x5D, 0x4A, 0x19, 0xB2, 0xB9, 0x3E,  // 136–143 (start of block 2)
            ]
        );
    }

    /// Canonical all-zero Keccak-f[1600] state: 25 lanes of 0.
    /// This is the simplest possible input and gives a fully deterministic,
    /// well-known output that exercises all 24 rounds and all five steps
    /// (θ ρ π χ ι) without any absorb/padding logic involved.
    #[test]
    fn test_keccak_f_all_zeros() {
        // Initalize all-zero state
        let mut state = [0u64; SHAKE256_STATE_WORDS];

        // Apply exactly one Keccak-f[1600] permutation in-place.
        keccak_f(&mut state);

        // Expected output: the 25 state lanes after one permutation of the
        // all-zero input, taken from the XKCP (Keccak Code Package) reference
        // test vectors (KeccakF-1600-IntermediateValues.txt).
        // A mismatch here means a bug in the round constants, rotation offsets,
        // or one of the five steps.
        assert_eq!(state, [
            0xF1258F7940E1DDE7, 0x84D5CCF933C0478A, 0xD598261EA65AA9EE, 0xBD1547306F80494D,
            0x8B284E056253D057, 0xFF97A42D7F8E6FD4, 0x90FEE5A0A44647C4, 0x8C5BDA0CD6192E76,
            0xAD30A6F71B19059C, 0x30935AB7D08FFC64, 0xEB5AA93F2317D635, 0xA9A6E6260D712103,
            0x81A57C16DBCF555F, 0x43B831CD0347C826, 0x01F22F1A11A5569F, 0x05E5635A21D9AE61,
            0x64BEFEF28CC970F2, 0x613670957BC46611, 0xB87C5A554FD00ECB, 0x8C3EE88A1CCF32C8,
            0x940C7922AE3A2614, 0x1841F924A2C509E4, 0x16F53526E70465C2, 0x75F644E97F30A13B,
            0xEAF1FF7B5CECA249,
        ]);
    }
}
