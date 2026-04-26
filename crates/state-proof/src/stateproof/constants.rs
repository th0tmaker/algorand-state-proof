// crates/state-proof/src/stateproof/constants.rs
//
// Single source of truth for all constants in the state-proof crate,
// organised by concern. Hash domain sections document the full preimage
// layout and hash function so the hashing landscape is visible at a glance.

use algorand_falcon_keys::{FALCON_DET1024_PUBKEY_SIZE, FALCON_DET1024_SIG_CT_SIZE};
use merkle::SUMHASH512_DIGEST_SIZE;
pub(crate) use merkle::MERKLE_VC_BOTTOM_LEAF as DOMAIN_EMPTY_SLOT;

// ── Protocol limits ───────────────────────────────────────────────────────────

/// Maximum VC tree depth allowed for `sig_proofs` and `part_proofs` in a valid
/// `StateProof`. Proofs with `tree_depth` exceeding this are rejected. [State Proof validity]
pub(crate) const VC_PROOF_MAX_DEPTH: u8 = 20;

/// Maximum tree depth for the inner ephemeral-key Merkle Signature Scheme tree.
/// Used to compute the fixed-length proof encoding within a `MerkleSignatureScheme`.
pub(crate) const MSS_PROOF_MAX_DEPTH: u8 = 16;

/// Maximum number of reveals (and positions) permitted in a single `StateProof`.
pub(crate) const MAX_REVEALS: usize = 640;

/// Security-strength target: `256 = k + 2q` where `(k=128, q=64)` accounts for a
/// quantum attacker's Grover-style speedup over the hash-based components.
/// Matches Algorand mainnet `StateProofStrengthTarget`. [Setting Security Strength]
pub(crate) const STRENGTH_TARGET: u16 = 256;

// ── Wire format sizes ─────────────────────────────────────────────────────────

/// Byte length of the fixed-length inner-proof encoding within a `MerkleSignatureScheme`.
///
/// Layout: `tree_depth(1) || (16 − depth) × zero_digest || depth × Sumhash512_digest(64)`
pub const SUMHASH512_PROOF_FIXED_REPR_SIZE: usize =
    1 + MSS_PROOF_MAX_DEPTH as usize * SUMHASH512_DIGEST_SIZE;

/// Byte length of the fixed-length binary representation of a `MerkleSignatureScheme`.
///
/// Layout: `scheme_id(2) || CT_sig(1538) || pubkey(1793) || vc_index(8) || proof_fixed`
pub const MERKLE_SIG_SCHEME_FIXED_REPR_SIZE: usize =
    2 + FALCON_DET1024_SIG_CT_SIZE + FALCON_DET1024_PUBKEY_SIZE + 8 + SUMHASH512_PROOF_FIXED_REPR_SIZE;

/// Byte length of the serialised `CoinChoiceSeed`.
///
/// Layout: `domain(3) || version(1) || part_commitment(64) || ln_proven_weight(8 LE)
///          || sig_commitment(64) || signed_weight(8 LE) || msg_hash(32)`
pub(crate) const COIN_CHOICE_SEED_SIZE: usize =
    3 + 1 + SUMHASH512_DIGEST_SIZE + 8 + SUMHASH512_DIGEST_SIZE + 8 + 32;

// ── Crypto primitives ─────────────────────────────────────────────────────────

/// Identifies the `MerkleSignatureScheme` cryptographic suite (Sumhash + Falcon).
/// Encoded as the first 2 bytes of `MerkleSignatureScheme::to_fixed_bytes`.
pub(crate) const MERKLE_SIG_SCHEME_ID: u16 = 0;

/// Coin generator version byte. Incrementing this changes coin selection,
/// effectively invalidating all proofs built under the previous version.
pub(crate) const COIN_GENERATOR_VERSION: u8 = 0;

/// `ceil(2^16 · ln 2)` — fixed-point ln(2) used in the strength inequality.
pub(crate) const LN2_FIXED_POINT: u64 = 45427;

// ── Hash domains: Sumhash512 ──────────────────────────────────────────────────
// All VcTree leaves and internal nodes in the sig/part trees use Sumhash512.
// Internal nodes use domain "MA" (merkle::MERKLE_INTERNAL_NODE).
// DOMAIN_EMPTY_SLOT ("MB") is imported above from merkle::MERKLE_VC_BOTTOM_LEAF.

/// **Participant VC leaf** (outer participants tree, root = `part_commitment`).
///
/// `Sumhash("spp" || weight(8 LE) || key_lifetime(8 LE) || commitment(64))`
///
/// Commits a participant's stake weight and ephemeral key tree root.
pub(crate) const DOMAIN_PARTICIPANT: &[u8] = b"spp";

/// **Ephemeral key VC leaf** (inner key tree, root = `participant.pk.commitment`).
///
/// `Sumhash("KP" || scheme_id(2 LE) || round(8 LE) || pubkey(1793))`
///
/// Commits an ephemeral Falcon-1024 public key at its valid round window.
pub(crate) const DOMAIN_EPHEMERAL_KEY: &[u8] = b"KP";

/// **Signature slot VC leaf** (signatures tree, root = `sig_commitment`).
///
/// `Sumhash("sps" || l(8 LE) || fixed_repr(4366))`
///
/// Commits a participant's Merkle signature. `l` is the cumulative weight before
/// this slot; `fixed_repr` is `MerkleSignatureScheme::to_fixed_bytes()`.
pub(crate) const DOMAIN_SIG_SLOT: &[u8] = b"sps";

// DOMAIN_EMPTY_SLOT ("MB") — see import above (merkle::MERKLE_VC_BOTTOM_LEAF).
// `Sumhash("MB")` — no data payload. Used for participants who did not sign.

// ── Hash domains: SHAKE-256 ───────────────────────────────────────────────────

/// **Coin choice seed** — drives pseudorandom selection of positions to reveal.
///
/// `SHAKE256("spc" || version(1) || part_commitment(64) || ln_proven_weight(8 LE)
///            || sig_commitment(64) || signed_weight(8 LE) || msg_hash(32))`
pub(crate) const DOMAIN_COIN_SEED: &[u8] = b"spc";

// ── Hash domains: SHA-256 ────────────────────────────────────────────────────

/// **State proof message hash** — signed by participants' ephemeral Falcon keys.
///
/// `SHA-256("spm" || canonical_msgpack(StateProofMessage))`
///
/// Binds the proof to a specific block interval. The 32-byte result is the
/// `msg_hash` parameter of `verify_state_proof`.
pub(crate) const DOMAIN_MSG_HASH: &[u8] = b"spm";

/// **Light block header VC leaf** (block headers tree, root = `blockHeadersCommitment`).
///
/// `SHA-256("B256" || canonical_msgpack(LightBlockHeader))`
///
/// Commits an individual block header into the SHA-256 VcTree that covers the
/// 256 blocks in the attested interval. Verifying this tree against
/// `blockHeadersCommitment` confirms which transactions the state proof attests to.
pub(crate) const DOMAIN_BLOCK_HEADER: &[u8] = b"B256";

/// **Transaction leaf** — domain prefix for both transaction commitment trees.
///
/// Primary tree (native): `SHA-512/256("STIB" || Sig(Tx) || ApplyData)`
/// SHA-256 tree (for cross-chain use, root = `LightBlockHeader::txn_commitment`):
///   `SHA-256("STIB" || Sig(Tx) || ApplyData)`
///
/// The SHA-256 `stibhash` is returned by
/// `GET /v2/blocks/{round}/transactions/{txid}/proof?hashtype=sha256`
/// and passed directly to `verify_txn_commitment`.
#[allow(dead_code)]
pub(crate) const DOMAIN_TXN_LEAF: &[u8] = b"STIB";
