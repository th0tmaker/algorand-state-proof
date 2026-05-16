# algorand-state-proof

Compact, trustless verifier covering the full cryptographic stack behind Algorand's
post-quantum State Proofs — suitable for light clients, bridges, and zkVM guests. 

Supports constructing `StateProof` and `StateProofMessage` either directly or
by decoding canonical MessagePack-encoded wire bytes.

Implements the full verification protocol across all seven proof fields: weight threshold (`ProvenWeight` check),
strength inequality, Vector Commitment batch Merkle proofs for the signature array (`S`) and participant array (`P`),
FALCON signature verification with salt-version consistency (`v`), ephemeral key commitment via the Merkle Signature Scheme
(within `r`), coin-range validation against the revealed positions (`pr`), and commitment root integrity (`c`).

Also supports verifying that a `LightBlockHeader` is present at a given index within the attested 256-round interval
by the `StateProofMessage`, and that a specific transaction is present at a given index within a block's payset of 
transactions.

## Disclaimer

> [!CAUTION]
> **This crate is exploratory and has not been audited.** It is not the work of a credentialed cryptographer. Anyone using it should understand the potential risks and liabilities involved, and use it at their own discretion. The API and internal derivation parameters are subject to potentially breaking changes.

## Installation

```toml
[dependencies]
algorand-state-proof = { git = "https://github.com/th0tmaker/algorand-state-proof", rev = "<commit-sha>" }

# With serde support for TrustAnchor (required for RISC Zero zkVM and similar)
algorand-state-proof = { git = "https://github.com/th0tmaker/algorand-state-proof", rev = "<commit-sha>", features = ["serde"] }
```

Requires a C compiler (GCC, Clang, or MSVC) for the Falcon-1024 C library.

## Overview

A State Proof is a compact certificate proving that a quorum of Algorand's
online stake holders agreed on a block interval commitment spanning 256
consecutive rounds. Verifying one requires three inputs:

- **`StateProof`** — decoded from the State Proof transaction wire bytes
- **`StateProofMessage`** — decoded from the same transaction; contains the
  block interval commitment and the trust parameters for the *next* interval
- **`TrustAnchor`** — `part_commitment` and `ln_proven_weight` from the
  *previous* interval's `StateProofMessage`

On success, `verify_state_proof` returns the next `TrustAnchor` for the
following call. This chains verification across intervals.

The full verification chain this crate enables:

```
verify_state_proof()                         → next TrustAnchor
  └─ message.block_headers_commitment
       └─ verify_block_header_commitment()   → proves a specific block is in the interval
            └─ header.txn_commitment
                 └─ verify_txn_commitment()  → proves a specific transaction is in the block
```

## Weight concepts

Three distinct weight values appear across the state proof types:

- **`Participant::weight`** — one signer's individual stake. Defines their coin range `[l, l + weight)` in the weight-interval check.
- **`StateProof::signed_weight`** — total aggregate stake of all signers in the proof. Coins are drawn uniformly from `[0, signed_weight)`.
- **`ln_proven_weight`** (in `TrustAnchor`) — log-space encoding of the minimum threshold that `signed_weight` must exceed for the proof to be valid.

## Core API

### Decoding

```rust
use algorand_state_proof::{StateProof, StateProofMessage};

let sp      = StateProof::from_msgpack(sp_bytes)?;
let message = StateProofMessage::from_msgpack(msg_bytes)?;
```

### State proof verification

```rust
use algorand_state_proof::{TrustAnchor, verify_state_proof};

let anchor = TrustAnchor {
    part_commitment:  voters_commitment_from_prev_message,  // [u8; 64]
    ln_proven_weight: ln_proven_weight_from_prev_message,   // u64
};

let next_anchor = verify_state_proof(&sp, &message, &anchor)?;
// Pass next_anchor to the next verify_state_proof call.
```

> NOTE: The first `TrustAnchor` must be bootstrapped out-of-band from a trusted
checkpoint — either the genesis state or a known-good block header.

### Block header verification

```rust
use algorand_state_proof::{LightBlockHeader, verify_block_header_commitment, Proof, Sha256};

let header = LightBlockHeader::from_msgpack(header_bytes)?;
let index  = message.block_index_for_round(round).expect("round not in interval");
let proof  = Proof::<Sha256>::new(tree_depth, path);

let ok = verify_block_header_commitment(&header, index, &proof, &message.block_headers_commitment);
```

> [!NOTE]
> The `LightBlockHeader` is not returned directly by the algod API — it must be
constructed by fetching the full block header in the response and trimming it down.
Exactly one of  `seed` or `block_hash` is populated depending on the consensus
protocol version; the other must be `[0u8; 32]`.

### Transaction verification

```rust
use algorand_state_proof::{verify_txn_commitment, Proof, Sha256};

// Both digests from GET /v2/blocks/{round}/transactions/{txid}/proof?hashtype=sha256
let ok = verify_txn_commitment(
    txn_sha256,           // SHA-256("TX" || canonical_msgpack(txn))
    stib_sha256,          // SHA-256("STIB" || Sig(Tx) || ApplyData)
    txn_index,            // "idx" field from the proof response
    &proof,               // Proof::<Sha256>::new(treedepth, path)
    &header.txn_commitment,
);
```

> NOTE: `txn_sha256` is computed using **SHA-256**, not the `SHA-512/256`,
which is used in Algorand to compute transaction IDs. Transaction bytes
must include `gh` and `gen` fields that block storage strips.

### Error handling

```rust
use algorand_state_proof::{DecodeError, VerifyError};

// Decode errors
match StateProof::from_msgpack(bytes) {
    Err(DecodeError::UnexpectedEof)             => { /* truncated input */ }
    Err(DecodeError::TrailingBytes)             => { /* extra bytes after value */ }
    Err(DecodeError::InvalidDigestSize { .. })  => { /* wrong-length hash field */ }
    Err(DecodeError::ZeroSignedWeight)          => { /* proof carries no stake */ }
    Err(DecodeError::TooManyReveals { .. })     => { /* exceeds protocol maximum */ }
    Ok(sp) => { /* ... */ }
}

// Verification errors
match verify_state_proof(&sp, &message, &anchor) {
    Err(VerifyError::SignedWeightTooLow)          => { /* weight below proven threshold */ }
    Err(VerifyError::InsufficientReveals)         => { /* too few reveals for strength target */ }
    Err(VerifyError::SigProofFailed)              => { /* batch Merkle proof failed */ }
    Err(VerifyError::PartProofFailed)             => { /* participant proof failed */ }
    Err(VerifyError::FalconVerifyFailed { .. })   => { /* falcon signature invalid */ }
    Err(VerifyError::VcProofFailed { .. })        => { /* ephemeral key not committed */ }
    Err(VerifyError::CoinOutOfRange { .. })       => { /* coin outside weight range */ }
    Ok(next_anchor) => { /* chain to next interval */ }
}
```

## Public types

Publicly exposed data types used in State Proof verification:

| Type | Description |
|---|---|
| `StateProof` | Main cryptographic proof that a sufficient amount of online stake signed a message attesting to the state across a 256-round interval.
Encodes commitments, total signed weight, Merkle proofs, and a pseudorandomly revealed subset of participants/signatures. |
| `StateProofMessage` | Message attested by a `StateProof`. Contains the block header commitment, interval bounds,
and the parameters (`voters_commitment`, `ln_proven_weight`) needed to verify the next interval. |
| `TrustAnchor` | Carries trusted parameters (`part_commitment`, `ln_proven_weight`) between intervals.
Used to verify a `StateProof`, producing the next anchor and forming a sequential trust chain. |
| `MessageHash` | `[u8; 32]` SHA-256 digest of the canonical `StateProofMessage`. |
| `Participant` | On-chain voter identity: a `MerkleVerifier` and stake weight. |
| `MerkleVerifier` | Commitment to a participant’s ephemeral keys (`Sumhash512` VC root) and key lifetime. |
| `MerkleSignatureScheme` | Merkle-authenticated signature: Falcon signature, verifying key, VC proof, and leaf index. |
| `SigSlotCommit` | Signature array slot containing a Merkle signature and cumulative weight offset `l`. |
| `Reveal` | One pseudorandomly selected stake-weighted participant (out of all signers) to reveal; pairs a `SigSlotCommit` with its `Participant`. |
| `CoinChoiceSeed` | Structured seed absorbed into SHAKE256 for pseudorandom reveal selection. |
| `CoinGenerator` | SHAKE256-based generator producing uniform coins in `[0, signed_weight)`. |
| `PublicKey` | Falcon-1024 ephemeral verifying key used for signature verification. Imported from `algorand-falcon-keys`. |
| `CompressedSignature` | Compressed Falcon-1024 signature over the `MessageHash`. Imported from `algorand-falcon-keys`. |

## Trust model

This crate is purely a verification pipeline — it holds no private key material and makes no network calls.
Its single trust assumption is the initial `TrustAnchor`: the first anchor must be bootstrapped from a source
you already trust. Every subsequent anchor is derived cryptographically from the previous one. If the initial
anchor is correct and the verification chain is unbroken, the crate provides post-quantum-secure attestation 
of Algorand's ledger state.

## Data sources

External data retrieved from Algorand node APIs for state proof construction and verification:

| Data | Purpose | Provider | Endpoint |
|---|---|---|---|
| `StateProof` & `StateProofMessage` | Retrieve the full state proof object for a given block round | algod | `GET /v2/stateproofs/{round}` |
| State Proof Transactions | Retrieve transactions of type `stpf` (StateProof) over a round range | indexer | `GET /v2/transactions?tx-type=stpf&min-round={round}` |
| Single block header (no payset) | Retrieve a block header without transactions | algod, indexer | `GET /v2/blocks/{round}?header-only=true` |
| Multiple block headers | Fetch a batch of block headers | indexer | `GET /v2/block-headers` |
| Light block header proof | Prove inclusion of a light header in the state proof commitment over block headers | algod | `GET /v2/blocks/{round}/lightheader/proof` |
| Transaction proof | Prove inclusion of a transaction in a block | algod | `GET /v2/blocks/{round}/transactions/{txid}/proof?hashtype=sha256` |

> [!NOTE]
> The `hashtype=sha256` parameter is required — the default `sha512_256` variant
is incompatible with `verify_txn_commitment`.

## Cryptographic primitives

| Primitive | Role | Commits to |
|---|---|---|
| Falcon-1024 (post-quantum) | Ephemeral signature verification | Each participant's signature over the `MessageHash` |
| Sumhash512 (post-quantum) | Participant and signature VC trees | Participant stake + ephemeral key tree root; signature slot data |
| SHAKE-256 | Pseudorandom coin generation | Proof parameters → stream of positions to reveal |
| SHA-256 | Block header and transaction VC trees | Individual block headers in the interval; individual transactions in each block |

## Optional: serde feature

Enables `serde::Serialize` and `serde::Deserialize` for `TrustAnchor`, required
for byte representation consistency when passing it across various platforms
e.g. a RISC Zero zkVM guest/host boundary:

```toml
algorand-state-proof = { ..., features = ["serde"] }
```

```rust
// In a RISC Zero guest:
let anchor: TrustAnchor = env::read();
let next_anchor = verify_state_proof(&sp, &message, &anchor)?;
env::commit(&next_anchor);
```

The `part_commitment` field (`[u8; 64]`) is serialized as raw bytes, with a
visitor that handles both binary (zero-copy) and JSON/text (integer sequence)
formats.

## Building

```sh
cargo build
cargo test
cargo test --features serde
```

The minimum supported Rust edition is **2024**.

## License

[MIT](../../LICENSE)
