//! Canonical signing-bytes + [`ApprovedTxHash`] core for the IronClaw
//! attested-signing substrate.
//!
//! This is **PR2 of a 10-PR stack** (see
//! `docs/plans/2026-05-23-attested-signing-substrate.md`). It defines the
//! value-binding core: the chain-tagged, chain-SDK-FREE
//! [`DecodedTransaction`] model, the [`render`] function that derives the
//! human-facing view, the [`canonical_signing_bytes`] encoder, and
//! [`compute_approved_tx_hash`] which binds them into the
//! [`ApprovedTxHash`] from `ironclaw_signing_provider`.
//!
//! ## Layering invariant
//!
//! This crate depends on `ironclaw_signing_provider`, `serde`/`serde_json`,
//! `thiserror`, `sha2`, `async-trait`, and — as of PR4 — the pure-Rust,
//! openssl-free WebAuthn crypto trio (`coset` for COSE_Key CBOR, `p256` for
//! ES256, `ed25519-dalek` for EdDSA; NOT `webauthn-rs-core`, which would link
//! `openssl`). It still carries **no chain SDK** (no `solana-sdk`,
//! `near-*`, `alloy`), **no EVM crypto primitives** (`k256`/`sha3`), and **no
//! key custody** (`ironclaw_secrets` / `ironclaw_chain_signing`) — the custody
//! keys and per-chain decode/sign/broadcast land in PR6. The architecture
//! boundary test
//! (`crates/ironclaw_architecture/tests/attested_signing_boundaries.rs`)
//! enforces this.
//!
//! ## PR4 additions
//!
//! - [`challenge`]: the durable one-shot [`ChallengeStore`] + the
//!   [`ChallengePreimage`] that binds a challenge to the exact operation.
//! - [`webauthn`]: the [`WebAuthnCredentialRegistry`] and
//!   [`verify_assertion`] full RP-validation verifier (UV-required,
//!   challenge-echo, rpIdHash, origin, signCount-regression, BE/BS).
//!
//! ## Anti-field-smuggling guarantee
//!
//! The renderer and the canonical encoder both derive from the single
//! [`crate::fields::project`] projection, so the human-approved view and the
//! signed bytes can never diverge. [`compute_approved_tx_hash`] then binds
//! render ∥ canonical bytes ∥ signer/account ∥ chain/network ∥ tx-type ∥
//! schema-version: changing ANY component changes the hash.
#![warn(unreachable_pub)]
#![forbid(unsafe_code)]

mod approved_tx_hash;
mod canonical;
mod challenge;
mod decoded_tx;
mod fields;
mod grant;
mod ledger;
mod rendered;
mod webauthn;

pub use approved_tx_hash::compute_approved_tx_hash;
pub use canonical::canonical_signing_bytes;
pub use challenge::{
    ChallengeCommitment, ChallengeError, ChallengeId, ChallengePreimage, ChallengeStore,
    ConsumedChallenge, CredentialId, DeliveryAttemptId, InMemoryChallengeStore, IssuedChallenge,
};
pub use decoded_tx::{
    Bytes32, DecodedTransaction, EvmAccessListEntry, EvmAddress, EvmTransaction, NearAction,
    NearTransaction, RenderingSchemaVersion, SolanaInstruction, SolanaTransaction,
};
pub use grant::{
    AttestedSigningGrant, ClaimedGrant, GrantError, GrantKey, GrantStatus,
    InMemorySealedGrantStore, SealedGrantStore,
};
pub use ledger::{InMemorySigningLedger, LedgerError, SigningLedger, SigningLedgerState};
pub use rendered::{RenderedField, RenderedTx, render};
pub use webauthn::{
    Aaguid, AssertionInput, AttestationPolicy, BackupFlagPolicy, BootstrapPolicy, CoseError,
    CosePublicKey, InMemoryWebAuthnCredentialRegistry, OriginContext, OriginPolicy,
    RegisteredCredential, RegistrationError, RegistrationRequest, SignCountPolicy,
    StandardOriginPolicy, VerificationError, VerifiedAssertion, WebAuthnCredentialRegistry,
    verify_assertion,
};

// Re-export the binding hash type so downstream PRs import it from the
// attestation crate alongside the functions that produce it.
pub use ironclaw_signing_provider::{APPROVED_TX_HASH_LEN, ApprovedTxHash};
