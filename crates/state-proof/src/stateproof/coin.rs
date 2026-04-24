// crates/state-proof/src/stateproof/coin.rs

use keccak::Shake256;
use merkle::{Sumhash512Digest, SUMHASH512_DIGEST_SIZE};

use super::MessageHash;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Domain separator used as a prefix to the coin choice seed before hashing.
const STATE_PROOF_COIN_DOMAIN: &[u8] = b"spc";

/// Salt version byte included in the seed. Changing this produces different
/// coins for different state proof verification algorithm versions.
pub const VERSION_FOR_COIN_GENERATOR: u8 = 0;

/// Byte length of the serialized `CoinChoiceSeed`.
///
/// Layout: `domain(3) || version(1) || partCommitment(64) || lnProvenWeight(8) || sigCommitment(64) || signedWeight(8) || messageHash(32)`
pub(crate) const COIN_CHOICE_SEED_SIZE: usize = 3 + 1 + SUMHASH512_DIGEST_SIZE + 8 + SUMHASH512_DIGEST_SIZE + 8 + 32;

/// `ceil(2^16 · ln 2)` — the fixed-point representation of ln(2) in this scheme,
/// equal to `ln_int_approximation(2)`. Used in the state proof strength inequality.
pub(crate) const LN2_FIXED_POINT: u64 = 45427;

// ── Ln approximation ─────────────────────────────────────────────────────────

/// Returns `ceil(2^16 * ln(x))` as a fixed-point approximation of `ln(x)`,
/// or `None` if `x` is zero.
///
/// Used to derive `ln_proven_weight` from `proven_weight` before constructing
/// a `CoinChoiceSeed`.
pub fn ln_int_approximation(x: u64) -> Option<u64> {
    if x == 0 { return None; }
    // A `f64` has a 53-bit mantissa; inputs above 2^53 lose integer precision, which 
    // is acceptable for typical Algorand stake weights (well below that threshold).
    let result = (x as f64).ln();
    Some((result * (1u64 << u16::BITS) as f64).ceil() as u64)
}

// ── CoinChoiceSeed ────────────────────────────────────────────────────────────

/// The inputs fed into SHAKE256 to derive the randomness stream for coin flips.
///
/// Serialized in a fixed binary layout (not msgpack) so that the encoding is
/// compatible with Algorand's SNARK circuit prover.
///
/// Layout:
/// `"spc" || version(1) || partCommitment(64) || lnProvenWeight(8 LE) || sigCommitment(64) || signedWeight(8 LE) || messageHash(32)`
pub struct CoinChoiceSeed {
    /// The `Sumhash512Digest` root commitment of the participants tree.
    pub part_commitment: Sumhash512Digest,
    /// `ceil(2^16 * ln(provenWeight))` — fixed-point ln approximation with 16 bits of precision.
    pub ln_proven_weight: u64,
    /// The `Sumhash512Digest` root commitment of the signatures tree.
    pub sig_commitment: Sumhash512Digest,
    /// Total stake weight that signed the message.
    pub signed_weight: u64,
    /// SHA-256 hash of the message being attested to.
    pub message_hash: MessageHash,
}

impl CoinChoiceSeed {
    /// Serializes `CoinChoiceSeed` into a single flattened buffer of bytes with a specific fixed order.
    fn to_bytes(&self) -> [u8; COIN_CHOICE_SEED_SIZE] {
        let mut out = [0u8; COIN_CHOICE_SEED_SIZE];
        let mut pos = 0;

        out[pos..pos + 3].copy_from_slice(STATE_PROOF_COIN_DOMAIN); pos += 3;
        out[pos] = VERSION_FOR_COIN_GENERATOR; pos += 1;
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
/// threshold = `floor(2^64 / signed_weight) * signed_weight`.
/// A sample is accepted only when it falls below the threshold, then
/// returned as `sample % signed_weight`.
#[derive(Debug)]
pub struct CoinGenerator {
    /// The `Shake256` sponge construction extendable output function (XOF).
    shake: Shake256,
    /// Total stake weight of signers only.
    signed_weight: u64,
    /// Largest multiple of `signed_weight` that fits in a u64 — the rejection boundary.
    threshold: u128,
}

impl CoinGenerator {
    /// Creates a new instance of `CoinGenerator` from a `CoinChoiceSeed`
    /// by absorbing the serialized seed into `Shake256`.
    pub fn new(seed: &CoinChoiceSeed) -> Self {
        // Create a new instance of `Shake256`, absord the seed bytes and flip to squeeze mode.
        let mut shake = Shake256::new();
        shake.absorb(&seed.to_bytes());
        shake.flip();

        // Get the seed total signed weight
        let signed_weight = seed.signed_weight;

        /* Rejection sampling threshold; ensures uniform distribution over [0, signed_weight).
        Naively taking a random `u64 % signed_weight` is biased — lower values appear
        slightly more often because 2^64 is rarely divisible by `signed_weight`. The
        leftover region (2^64 % signed_weight) maps to values [0, remainder) twice.
        
        Fix: only accept samples below threshold = `floor(2^64 / signed_weight) * signed_weight`.
        That is an exact multiple of `signed_weight`, so `sample % signed_weight` is uniform.
        Samples in [threshold, 2^64) are discarded and re-squeezed.
        
        Computed in u128 to avoid overflow (1u128 << 64 = 2^64 exactly). */
        let k = (1u128 << u64::BITS) / signed_weight as u128;
        let threshold = k * signed_weight as u128;

        // Wrap `shake`, `signed_weight` and `threshold` into the type and return
        Self { shake, signed_weight, threshold }
    }

    /// Returns the next coin value uniformly distributed in `[0, signed_weight)`.
    ///
    /// Squeezes 8 bytes from `Shake256`, rejects if ≥ threshold (rejection sampling),
    /// and returns `sample % signed_weight`.
    pub fn next_coin(&mut self) -> u64 {
        loop {
            let mut buf = [0u8; 8];
            self.shake.squeeze(&mut buf);
            let sample = u64::from_le_bytes(buf) as u128;
            if sample < self.threshold {
                return (sample % self.signed_weight as u128) as u64;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
