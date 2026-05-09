// crates/state-proof/src/stateproof/constants.rs

//! Protocol constants for the Algorand state proof stack.
//! For the complete domain map, hash preimage layouts, and binary format reference see [`specs`](super::specs).

use algorand_falcon_keys::{FALCON_DET1024_PUBKEY_SIZE, FALCON_DET1024_SIG_CT_SIZE};
use merkle::SUMHASH512_DIGEST_SIZE;
pub(crate) use merkle::MERKLE_VC_BOTTOM_LEAF as DOMAIN_EMPTY_SLOT;

// ── Protocol limits ───────────────────────────────────────────────────────────

/// Maximum VC tree depth for `StateProof` participant and signature proof paths.
pub(crate) const SP_VC_MAX_DEPTH: u8 = 20;

/// Maximum VC tree depth for a `MerkleSignatureScheme` membership proof.
/// Limits a participant's total ephemeral keys to at most 2^16.
pub(crate) const MSS_VC_MAX_DEPTH: u8 = 16;

/// Maximum number of reveals permitted in a single `StateProof`.
pub(crate) const MAX_REVEALS: usize = 640;

/// Security-strength target: `256 = k + 2q` where `(k=128, q=64)` accounts
/// for a quantum attacker's Grover-style speedup over hash-based components.
pub(crate) const STRENGTH_TARGET: u16 = 256;

// ── Wire format sizes ─────────────────────────────────────────────────────────

/// Byte length of the fixed-length `Sumhash512` proof encoding. See layout reference below.
pub const SUMHASH512_PROOF_FIXED_REPR_SIZE: usize =
    1 + MSS_VC_MAX_DEPTH as usize * SUMHASH512_DIGEST_SIZE;

/// Byte length of the fixed-length `MerkleSignatureScheme` binary representation. See layout reference below.
pub const MERKLE_SIG_SCHEME_FIXED_REPR_SIZE: usize =
    2 + FALCON_DET1024_SIG_CT_SIZE + FALCON_DET1024_PUBKEY_SIZE + 8 + SUMHASH512_PROOF_FIXED_REPR_SIZE;

/// Byte length of the serialised `CoinChoiceSeed`. See layout reference below.
pub(crate) const COIN_CHOICE_SEED_SIZE: usize =
    3 + 1 + SUMHASH512_DIGEST_SIZE + 8 + SUMHASH512_DIGEST_SIZE + 8 + 32;

// ── Crypto primitives ─────────────────────────────────────────────────────────

/// Identifies the cryptographic suite used in `MerkleSignatureScheme`:
/// `0 = Falcon-1024 (sig) + Sumhash512 (hash)`.
pub(crate) const MSS_CRYPTO_SUITE_ID: u16 = 0;

/// Coin generator version byte. Incrementing this invalidates all proofs
/// built under the previous version.
pub(crate) const COIN_GENERATOR_VERSION: u8 = 0;

/// `ceil(2^16 · ln 2)` — fixed-point ln(2) used in the strength inequality.
pub(crate) const LN2_FIXED_POINT: u64 = 45427;

// ── Hash domain tags: Sumhash512 ─────────────────────────────────────────────

/// Participant VC leaf domain tag. See preimage reference below.
pub(crate) const DOMAIN_PARTICIPANT: &[u8] = b"spp";

/// Ephemeral key VC leaf domain tag. See preimage reference below.
pub(crate) const DOMAIN_EPHEMERAL_KEY: &[u8] = b"KP";

/// Signature slot VC leaf domain tag. See preimage reference below.
pub(crate) const DOMAIN_SIG_SLOT: &[u8] = b"sps";

// DOMAIN_EMPTY_SLOT ("MB") — imported above from merkle::MERKLE_VC_BOTTOM_LEAF.

// ── Hash domain tags: SHAKE-256 ───────────────────────────────────────────────

/// Coin choice seed domain tag. See preimage reference below.
pub(crate) const DOMAIN_COIN_SEED: &[u8] = b"spc";

// ── Hash domain tags: SHA-256 ─────────────────────────────────────────────────

/// State proof message hash domain tag. See preimage reference below.
pub(crate) const DOMAIN_SP_MSG_HASH: &[u8] = b"spm";

/// Block header VC leaf domain tag. See preimage reference below.
pub(crate) const DOMAIN_LIGHT_BLOCK_HEADER: &[u8] = b"B256";

/// Transaction leaf domain tag. See preimage reference below.
pub(crate) const DOMAIN_TXN_LEAF: &[u8] = b"TL";

