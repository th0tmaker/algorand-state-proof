// crates/state-proof/src/stateproof/coin.rs

use xof::Shake256;
use merkle::{Sumhash512Digest, SUMHASH512_DIGEST_SIZE};

use super::constants::{COIN_CHOICE_SEED_SIZE, COIN_GENERATOR_VERSION, DOMAIN_COIN_SEED};
use super::MessageHash;

// ── Ln approximation ─────────────────────────────────────────────────────────

/// Returns `ceil(2^16 * ln(x))` as a fixed-point approximation of `ln(x)`
/// with 16 fractional bits, or `None` if `x == 0`. Required when constructing `CoinChoiceSeed`.
pub fn ln_int_approximation(x: u64) -> Option<u64> {
    // The natural logarithm of zero is undefined; hence we return this as `None`
    // so it can be handled by the caller explicitly.
    if x == 0 { return None; }
    // A `f64` has a 53-bit mantissa; inputs above 2^53 lose integer precision, which 
    // is acceptable for typical Algorand stake weights (well below that threshold).
    let result = (x as f64).ln();
    Some((result * (1u64 << u16::BITS) as f64).ceil() as u64)
}

// ── CoinChoiceSeed ────────────────────────────────────────────────────────────
///
/// The input seed absorbed by [Shake256](xof::Shake256) inside the `CoinGenerator`.
/// A coin is used to pseudorandomly select which signatures get revealed during
/// [StateProof](crate::StateProof) validation.
pub struct CoinChoiceSeed {
    /// 512-bit `Sumhash512` hash digest vector commitment root on the participant array.
    pub part_commitment: Sumhash512Digest,
    /// Real number encoded as a fixed-point integer with 16-bit precision that 
    /// represents the natural log of `proven_weight`
    /// 
    /// Formula: `ceil(2^16 * ln(proven_weight))`.
    /// 
    /// This number is stored inside a 64-bit LE integer for safety insurance and compatibility.
    pub ln_proven_weight: u64,
    /// 512-bit `Sumhash512` hash digest vector commitment root on the signature array
    pub sig_commitment: Sumhash512Digest,
    /// 64-bit LE integer representing total (stake) signed weight of all participants 
    /// whose signatures appear in `StateProof` the signature array.
    pub signed_weight: u64,
    /// 256-bit `SHA-256` hash digest of the state proof message being attested to.
    pub message_hash: MessageHash,
}

impl CoinChoiceSeed {
    /// Serializes `CoinChoiceSeed` into a single flattened buffer of bytes with a specific fixed order.
    ///
    /// Serialized layout:
    /// `b"spc" || version(u8) || part_commitment([u8; 64]) || ln_proven_weight(u64 LE) ||
    /// sig_commitment([u8; 64]) || signed_weight(u64 LE) || message_hash([u8; 32])`
    fn to_bytes(&self) -> [u8; COIN_CHOICE_SEED_SIZE] {
        let mut out = [0u8; COIN_CHOICE_SEED_SIZE];
        let mut pos = 0;
        out[pos..pos + 3].copy_from_slice(DOMAIN_COIN_SEED); pos += 3;
        out[pos] = COIN_GENERATOR_VERSION; pos += 1;
        out[pos..pos + SUMHASH512_DIGEST_SIZE].copy_from_slice(&self.part_commitment); pos += SUMHASH512_DIGEST_SIZE;
        out[pos..pos + 8].copy_from_slice(&self.ln_proven_weight.to_le_bytes()); pos += 8;
        out[pos..pos + SUMHASH512_DIGEST_SIZE].copy_from_slice(&self.sig_commitment);  pos += SUMHASH512_DIGEST_SIZE;
        out[pos..pos + 8].copy_from_slice(&self.signed_weight.to_le_bytes()); pos += 8;
        out[pos..].copy_from_slice(&self.message_hash);
        out
    }
}

// ── CoinGenerator ─────────────────────────────────────────────────────────────

/// Produces a stream of pseudorandom coin values in `[0, signed_weight)` by
/// squeezing 64-bit chunks from a `Shake256` context seeded with `CoinChoiceSeed`.
///
/// Uses rejection sampling to ensure a uniform distribution:
/// `threshold = floor(2^64 / signed_weight) * signed_weight`.
///
/// A sample is accepted only when it falls below the threshold, then
/// returned as `sample % signed_weight`.
#[derive(Debug)]
pub struct CoinGenerator {
    /// The `Shake256` sponge construction extendable output function (XOF).
    xof: Shake256,
    /// Total stake weight of signers only.
    signed_weight: u64,
    /// Largest multiple of `signed_weight` that fits in a u64 — the rejection boundary.
    threshold: u128,
}

impl CoinGenerator {
    /// Creates a new instance of `CoinGenerator` from a `CoinChoiceSeed`
    pub fn new(seed: &CoinChoiceSeed) -> Self {
        // Create a new instance of `Shake256`, absord the seed bytes and flip to squeeze mode.
        let mut xof = Shake256::new();
        xof.absorb(&seed.to_bytes());
        xof.flip();

        // Get the seed total signed weight
        let signed_weight = seed.signed_weight;

        /* NOTE: Rejection sampling threshold; ensures uniform distribution over [0, signed_weight).
        Naively taking a random `u64 % signed_weight` is biased — lower values appear slightly more often
        because 2^64 is rarely divisible by  `signed_weight`. The leftover region (2^64 % signed_weight)
        maps to values [0, remainder) twice.
        
        Fix: only accept samples below threshold = `floor(2^64 / signed_weight) * signed_weight`.
        That is an exact multiple of `signed_weight`, so `sample % signed_weight` is uniform.
        Samples in [threshold, 2^64) are discarded and re-squeezed.
        
        Computed in u128 to avoid overflow (1u128 << 64 = 2^64 exactly). */
        let k = (1u128 << u64::BITS) / signed_weight as u128;
        let threshold = k * signed_weight as u128;

        // Wrap `xof`, `signed_weight` and `threshold` into the type and return
        Self { xof, signed_weight, threshold }
    }

    /// Generates the next unbiased “coin” index in the range `[0, signed_weight)`.
    ///
    /// This uses `Shake256` randomness and rejection sampling to avoid modulo bias:
    ///
    /// 1. A 64-bit random sample is drawn from the XOF stream.
    /// 2. The sample is accepted only if it lies in the largest multiple of
    ///    `signed_weight` that fits within `u64` (the `threshold`).
    /// 3. Once accepted, the sample is reduced with `sample % signed_weight`,
    ///    which is unbiased due to the rejection step.
    ///
    /// Returns a uniformly distributed integer in `[0, signed_weight)`.
    pub fn next_coin(&mut self) -> u64 {
        // Keep looping until we get an acceptable value.
        loop {
            let mut buf = [0u8; 8];
            self.xof.squeeze(&mut buf);
            let sample = u64::from_le_bytes(buf) as u128;
            if sample < self.threshold {
                return (sample % self.signed_weight as u128) as u64;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{*, super::constants::LN2_FIXED_POINT};

    /// Helper method to create a `CoinChoiceSeed` with test values.
    fn make_test_seed(signed_weight: u64) -> CoinChoiceSeed {
        CoinChoiceSeed {
            part_commitment: [0u8; 64],
            ln_proven_weight: ln_int_approximation(signed_weight).unwrap(),
            sig_commitment: [1u8; 64],
            signed_weight,
            message_hash: [2u8; 32],
        }
    }

    /// ln(0) is undefined — must return None.
    #[test]
    fn ln_approx_of_zero_is_none() {
        assert_eq!(ln_int_approximation(0), None);
    }

    /// ln(1) = 0, so the approximation must return Some(0).
    #[test]
    fn ln_approx_of_one_is_zero() {
        assert_eq!(ln_int_approximation(1), Some(0));
    }

    /// ln(2) with 16 bits of precision = ceil(2^16 * ln(2)) = 45427.
    #[test]
    fn ln_approx_of_two_matches_go_constant() {
        assert_eq!(ln_int_approximation(2), Some(LN2_FIXED_POINT));
    }

    /// Two generators built from identical seeds must produce the same coin sequence.
    #[test]
    fn coin_generator_is_deterministic() {
        let seed = make_test_seed(1_000_000);
        let coins_a: Vec<u64> = {
            let mut g = CoinGenerator::new(&seed);
            (0..10).map(|_| g.next_coin()).collect()
        };
        let coins_b: Vec<u64> = {
            let mut g = CoinGenerator::new(&seed);
            (0..10).map(|_| g.next_coin()).collect()
        };
        assert_eq!(coins_a, coins_b);
    }

    /// Two generators built from seeds differing only in `sig_commitment` must diverge.
    #[test]
    fn different_seeds_produce_different_coins() {
        let seed_a = make_test_seed(1_000_000);
        let seed_b = CoinChoiceSeed {
             sig_commitment: [9u8; 64],
            ..make_test_seed(1_000_000)
        };

        let coins_a: Vec<u64> = {
            let mut g = CoinGenerator::new(&seed_a);
            (0..10).map(|_| g.next_coin()).collect()
        };
        let coins_b: Vec<u64> = {
            let mut g = CoinGenerator::new(&seed_b);
            (0..10).map(|_| g.next_coin()).collect()
        };
        assert_ne!(coins_a, coins_b);
    }

    /// Every coin must fall within [0, signed_weight).
    #[test]
    fn coins_are_within_bounds() {
        let signed_weight = 500_000u64;
        let seed = make_test_seed(signed_weight);
        let mut g = CoinGenerator::new(&seed);
        for _ in 0..1000 {
            let coin = g.next_coin();
            assert!(coin < signed_weight, "coin {coin} out of range [0, {signed_weight})");
        }
    }

    /// A `signed_weight=1` must always produce coin = 0.
    #[test]
    fn coins_with_weight_one_are_always_zero() {
        let seed = make_test_seed(1);
        let mut g = CoinGenerator::new(&seed);
        for _ in 0..20 {
            assert_eq!(g.next_coin(), 0);
        }
    }

    /// Known-answer test (KAT) for the full coin generation pipeline against the
    /// mainnet state proof at round 60000000.
    ///
    /// Seed parameters:
    ///   part_commitment  — voters commitment from previous SP (round 59999877)
    ///   ln_proven_weight — from previous SP message
    ///   sig_commitment   — from the round 60000000 state proof (`sp.sig_commitment`)
    ///   signed_weight    — from the round 60000000 state proof (`sp.signed_weight`)
    ///   message_hash     — SHA-256("spm" || canonical_msgpack(message))
    ///
    /// Expected coins computed independently via Python hashlib.shake_256 with
    /// the same rejection-sampling threshold as `CoinGenerator`.
    #[test]
    fn coin_generation_mainnet_kat() {
        let seed = CoinChoiceSeed {
            part_commitment: [
                0x62, 0xa8, 0x6c, 0xef, 0x69, 0x7d, 0x56, 0xc3,
                0x51, 0x45, 0xf5, 0xd3, 0x0d, 0xee, 0x59, 0x46,
                0x64, 0x67, 0xb1, 0x36, 0x0f, 0xf5, 0xf9, 0xb4,
                0xae, 0x9e, 0x64, 0xcb, 0x0c, 0x2d, 0xf3, 0x2f,
                0x54, 0x97, 0x7f, 0x6d, 0x35, 0xad, 0x5a, 0x6c,
                0x2e, 0xdc, 0x79, 0x7d, 0xfe, 0x1f, 0x2d, 0xd7,
                0x9f, 0x16, 0x68, 0x81, 0x51, 0xb3, 0x61, 0x16,
                0x6c, 0x04, 0xc2, 0x42, 0xbe, 0x9c, 0x13, 0x59,
            ],
            ln_proven_weight: 2230322,
            sig_commitment: [
                0x45, 0xeb, 0x1a, 0x41, 0x00, 0xcc, 0x52, 0x70,
                0x1a, 0x83, 0x13, 0x2d, 0xbc, 0xf8, 0x6c, 0x64,
                0x44, 0x46, 0x00, 0xba, 0x4c, 0x55, 0x81, 0xcf,
                0xd3, 0xb6, 0xab, 0x23, 0xd3, 0xc5, 0x8b, 0x73,
                0x38, 0x39, 0xbd, 0x50, 0xc7, 0x25, 0xcd, 0x93,
                0x8c, 0x1a, 0x45, 0x31, 0xab, 0x9f, 0x3c, 0xfc,
                0x70, 0xb2, 0xc8, 0x60, 0x25, 0xc4, 0x00, 0x9d,
                0x09, 0xc7, 0xf7, 0x91, 0xec, 0x46, 0x12, 0x1a,
            ],
            signed_weight: 1984993817111541,
            message_hash: [
                0x39, 0x3e, 0x12, 0x31, 0xa9, 0x36, 0x90, 0x27,
                0xd5, 0x84, 0x61, 0xc9, 0x0e, 0x4b, 0xc1, 0xfe,
                0x52, 0xd8, 0x3c, 0x63, 0x41, 0xc9, 0xb2, 0x78,
                0x13, 0x6a, 0xd9, 0x94, 0x83, 0xb4, 0x1e, 0xd2,
            ],
        };

        let mut coin_gen = CoinGenerator::new(&seed);
        let coins: Vec<u64> = (0..10).map(|_| coin_gen.next_coin()).collect();

        assert_eq!(coins, vec![
            1279314575278130,
            1241225590619783,
            1825077925507590,
            1216318332643470,
             778972575116659,
            1226705497682007,
            1050800381323990,
            1780032487812739,
            1927945203215390,
            1033263256757881,
        ]);
    }
}
