// crates/state-proof/src/stateproof/specs.rs

//! Protocol specification reference for the Algorand state proof pipeline.
//!
//! ## Complete domain map
//!
//! All hash inputs are prefixed with a domain tag to prevent cross-context
//! collisions. The full set of domain tags used across the pipeline:
//!
//! | Domain   | Hash fn    | Use                                  |
//! |----------|------------|--------------------------------------|
//! | `"spp"`  | Sumhash512 | Participant VC leaf                  |
//! | `"KP"`   | Sumhash512 | Ephemeral key VC leaf                |
//! | `"sps"`  | Sumhash512 | Signature VC leaf                    |
//! | `"MB"`   | Sumhash512 | Empty signature slot leaf            |
//! | `"MA"`   | Sumhash512 | VC internal nodes (all trees)        |
//! | `"spc"`  | SHAKE-256  | Coin seed                            |
//! | `"spm"`  | SHA-256    | State proof message hash             |
//! | `"B256"` | SHA-256    | Block header VC leaf                 |
//! | `"TL"`   | SHA-256    | Transaction VC leaf                  |
//! | `"TX"`   | SHA-256    | Transaction sub-hash                 |
//! | `"STIB"` | SHA-256    | Signed transaction in block sub-hash |
//!
//! > `"MA"`, `"MB"` are defined in the `merkle` crate.
//! > `"TX"` and `"STIB"` are computed by the network; this crate receives their
//! > digests as inputs to [`verify_txn_commitment`](crate::verify_txn_commitment).
//!
//! ## Hash preimage details
//!
//! ### Sumhash512 — participant and signature VC trees
//!
//! **`"spp"` — Participant leaf**
//! ```text
//! Sumhash512("spp" || weight(u64 LE) || key_lifetime(u64 LE) || commitment([u8; 64]))
//! ```
//!
//! **`"KP"` — Ephemeral key leaf**
//! ```text
//! Sumhash512("KP" || scheme_id(u16 LE) || round(u64 LE) || pubkey([u8; 1793]))
//! ```
//!
//! **`"sps"` — Signature slot leaf**
//! ```text
//! Sumhash512("sps" || l(u64 LE) || fixed_repr([u8; 4366]))
//! ```
//!
//! **`"MB"` — Empty slot leaf**
//! ```text
//! Sumhash512("MB")  // no payload; participant did not sign
//! ```
//!
//! **`"MA"` — VC internal node**
//! ```text
//! Sumhash512("MA" || left_child([u8; 64]) || right_child([u8; 64]))
//! ```
//!
//! ### SHAKE-256 — pseudorandom coin generation
//!
//! **`"spc"` — Coin seed**
//! ```text
//! SHAKE-256("spc" || version(u8)
//!           || part_commitment([u8; 64]) || ln_proven_weight(u64 LE)
//!           || sig_commitment([u8; 64])  || signed_weight(u64 LE)
//!           || msg_hash([u8; 32]))
//! ```
//!
//! ### SHA-256 — block header and transaction VC trees
//!
//! **`"spm"` — State proof message hash**
//! ```text
//! SHA-256("spm" || canonical_msgpack(StateProofMessage))
//! ```
//!
//! **`"B256"` — Block header VC leaf**
//! ```text
//! SHA-256("B256" || canonical_msgpack(LightBlockHeader))
//! ```
//!
//! **`"TL"` — Transaction VC leaf**
//! ```text
//! SHA-256("TL" || txn_sha256([u8; 32]) || stib_sha256([u8; 32]))
//! ```
//! where:
//! ```text
//! txn_sha256  = SHA-256("TX"   || canonical_msgpack(txn))
//! stib_sha256 = SHA-256("STIB" || Sig(Tx) || ApplyData)
//! ```
//!
//! ## Binary layouts
//!
//! Fixed-length representations used in hashing and serialization.
//!
//! **`Sumhash512` proof (fixed)**
//! ```text
//! tree_depth(u8) || padding((16 − depth) × [u8; 64]) || path(depth × [u8; 64])
//! ```
//!
//! **`MerkleSignatureScheme` (fixed)**
//! ```text
//! scheme_id(u16 LE) || ct_sig([u8; 1538]) || pubkey([u8; 1793])
//! || vc_index(u64 LE) || proof_fixed
//! ```
//!
//! **`CoinChoiceSeed`**
//! ```text
//! "spc" || version(u8)
//! || part_commitment([u8; 64]) || ln_proven_weight(u64 LE)
//! || sig_commitment([u8; 64])  || signed_weight(u64 LE)
//! || msg_hash([u8; 32])
//! ```
