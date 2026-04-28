# algorand-state-proof

The primary crate in the `algorand-state-proof` workspace. It brings together all supporting crates into a complete decoder and verifier for Algorand State Proofs, suitable for light clients, bridges, and zkVM guests.

The crate is structured around four areas of responsibility. The **verifier** (`stateproof/verifier.rs`) implements the full seven-step state proof verification protocol — weight checks, Merkle batch proofs, Falcon signature verification, and coin-range validation. The **message and trust types** (`stateproof/message.rs`) provide `StateProofMessage` and `TrustAnchor`, which carry the block interval data and chain trust across consecutive intervals. The **commitment verifiers** (`stateproof/commitment.rs`) expose `LightBlockHeader` and the two downstream verification functions that let callers prove individual block headers and transactions against the commitments attested by a state proof. The **coin generator** (`stateproof/coin.rs`) implements the SHAKE-256-based pseudorandom selection of positions to reveal, matching Algorand's protocol exactly. Underpinning all of these is a custom **canonical MessagePack codec** (`codec/`) — an Algorand-compatible encoder and decoder that handles the specific key-sorting and zero-omission rules of Algorand's wire format.

## Disclaimer

**WARNING: This crate is exploratory and has not been audited.** It is not the work of a credentialed cryptographer. Anyone using it should understand the potential risks and liabilities involved, and use it at their own discretion. The API is subject to potentially breaking changes.

## Installation

```toml
[dependencies]
algorand-state-proof = { git = "https://github.com/th0tmaker/algorand-state-proof", rev = "<commit-sha>" }

# With serde support for TrustAnchor (required for RISC Zero zkVM and similar)
algorand-state-proof = { git = "https://github.com/th0tmaker/algorand-state-proof", rev = "<commit-sha>", features = ["serde"] }
```

## Overview

An Algorand State Proof attests to the state of the blockchain over a 256-round interval. Verifying one requires:

- A **`StateProof`** — decoded from the State Proof transaction wire bytes
- A **`StateProofMessage`** — decoded from the same transaction, containing the block interval commitment and the trust parameters for the next interval
- A **`TrustAnchor`** — the `part_commitment` and `ln_proven_weight` from the *previous* interval's `StateProofMessage`

On success, `verify_state_proof` returns the next `TrustAnchor`, which is passed to the following call. This chains verification across intervals.

The full verification chain this crate enables:

```
verify_state_proof()                      → next TrustAnchor
  └─ message.block_headers_commitment
       └─ verify_block_header_commitment() → proves a specific block is in the interval
            └─ header.txn_commitment
                 └─ verify_txn_commitment()→ proves a specific transaction is in the block
```

## Core API

### Decoding

```rust
use algorand_state_proof::{StateProof, StateProofMessage};

let sp      = StateProof::from_msgpack(sp_bytes)?;
let message = StateProofMessage::from_msgpack(msg_bytes)?;
```

Both types are decoded from Algorand canonical MessagePack wire bytes, as received from the network or indexer.

### State proof verification

```rust
use algorand_state_proof::{TrustAnchor, verify_state_proof};

// anchor is sourced from the previous interval's StateProofMessage
let anchor = TrustAnchor {
    part_commitment:  voters_commitment_from_prev_message,  // [u8; 64]
    ln_proven_weight: ln_proven_weight_from_prev_message,   // u64
};

let next_anchor = verify_state_proof(&sp, &message, &anchor)?;
// Pass next_anchor to the next verify_state_proof call.
```

The first `TrustAnchor` must be sourced out-of-band from a trusted checkpoint — either the genesis state or a known-good block header from an honest full node.

### Block header verification

Once a state proof is verified, individual block headers within the attested interval can be proven against `message.block_headers_commitment`:

```rust
use algorand_state_proof::{LightBlockHeader, verify_block_header_commitment, Proof, Sha256};

// header fields and proof from GET /v2/blocks/{round}/lightheader[/proof]
let header = LightBlockHeader::from_msgpack(header_bytes)?;
let index  = message.block_index_for_round(round).expect("round not in interval");
let proof  = Proof::<Sha256>::new(tree_depth, path);  // from API response

let ok = verify_block_header_commitment(
    &header,
    index,
    &proof,
    &message.block_headers_commitment,
);
```

### Transaction verification

Once a block header is verified, individual transactions can be proven against `header.txn_commitment`:

```rust
use algorand_state_proof::{verify_txn_commitment, Proof, Sha256};

// stib_hash, idx, proof from:
// GET /v2/blocks/{round}/transactions/{txid}/proof?hashtype=sha256
let ok = verify_txn_commitment(
    stib_hash,   // [u8; 32] — the "stibhash" field from the API response
    txn_index,   // the "idx" field
    &proof,      // Proof::<Sha256>::new(treedepth, path)
    &header.txn_commitment,
);
```

### Block index helper

```rust
// Computes the zero-based leaf index of `round` in the 256-block VcTree.
// Returns None if round is outside [first_attested_round, last_attested_round].
let index: Option<usize> = message.block_index_for_round(round);
```

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
    Err(VerifyError::FalconVerifyFailed { .. })   => { /* ephemeral signature invalid */ }
    Err(VerifyError::VcProofFailed { .. })        => { /* ephemeral key not committed */ }
    Err(VerifyError::CoinOutOfRange { .. })       => { /* coin outside weight range */ }
    Ok(next_anchor) => { /* chain to next interval */ }
}
```

## Trust model

This crate is a pure verifier — it holds no private key material and makes no network calls. Its single trust assumption is the initial `TrustAnchor`: the first anchor must be bootstrapped from a source you already trust (genesis state, or a checkpoint from an honest full node). Every subsequent anchor is derived cryptographically from the previous one. If the initial anchor is correct and the verification chain is unbroken, the crate provides post-quantum-secure attestation of Algorand's ledger state.

## Data sources

All wire bytes passed to this crate are fetched from the Algorand node (algod) API:

| Data | Endpoint |
|---|---|
| State proof transaction (msgpack bytes) | `GET /v2/transactions/{txid}` via indexer, or watch for `StateProofTransaction` type |
| `StateProofMessage` fields | Same transaction — the `StateProofMsg` field |
| Previous `StateProofMessage` (for `TrustAnchor`) | The preceding state proof transaction's `StateProofMsg` |
| Light block header | `GET /v2/blocks/{round}/lightheader` |
| Block header proof path | `GET /v2/blocks/{round}/lightheader/proof` |
| Transaction proof | `GET /v2/blocks/{round}/transactions/{txid}/proof?hashtype=sha256` |

The `hashtype=sha256` parameter is required for transaction proofs — the default `sha512_256` variant is incompatible with `verify_txn_commitment`, which verifies against the SHA-256 commitment stored in `LightBlockHeader::txn_commitment`.

## Cryptographic primitives

| Primitive | Used for |
|---|---|
| Falcon-1024 (post-quantum) | Ephemeral signature verification in each reveal |
| Sumhash512 (post-quantum) | Participant and signature VcTree leaf hashing |
| SHAKE-256 | Pseudorandom coin generation for reveal selection |
| SHA-256 | Block header and transaction VcTree leaf hashing |

## Optional: serde feature

Enables `serde::Serialize` and `serde::Deserialize` for `TrustAnchor`, required for passing it across a RISC Zero zkVM guest/host boundary:

```toml
algorand-state-proof = { ..., features = ["serde"] }
```

```rust
// In a RISC Zero guest:
let anchor: TrustAnchor = env::read();
let next_anchor = verify_state_proof(&sp, &message, &anchor)?;
env::commit(&next_anchor);
```

The `part_commitment` field (`[u8; 64]`) is serialized as raw bytes, with a visitor that handles both binary formats (zero-copy) and JSON/text formats (sequence of integers).

## Building

```sh
cargo build
cargo test
cargo test --features serde
```

Requires a C compiler (GCC, Clang, or MSVC) for the Falcon-1024 C library. The minimum supported Rust edition is **2024**.

## License

MIT
