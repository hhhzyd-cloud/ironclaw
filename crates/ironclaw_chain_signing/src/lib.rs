//! Custodial multi-chain signing for the IronClaw attested-signing substrate.
//!
//! This is **PR6 of the 10-PR attested-signing stack** (see
//! `docs/plans/2026-05-23-attested-signing-substrate.md`). It turns a resolved
//! attestation + a persisted [`ironclaw_attestation::DecodedTransaction`] into a
//! signed, broadcast transaction, behind two independent enforcement points:
//!
//! 1. **Grant claim** — the signer refuses to act without claiming the sealed
//!    one-shot [`ironclaw_attestation::AttestedSigningGrant`] (PR3); a replayed
//!    approval cannot be turned into a second signature.
//! 2. **Sign-time approved-tx-hash re-check** — the signer recomputes the
//!    [`ironclaw_signing_provider::ApprovedTxHash`] *from the persisted decoded
//!    transaction* and refuses (before any key access) if it diverges from the
//!    approved hash.
//!
//! The [`ironclaw_attestation::SigningLedger`] (PR3) provides broadcast
//! idempotency: a gate_ref past `BroadcastSubmitted` can never re-enter signing.
//!
//! ## Custody & the HSM/KMS ship-gate
//!
//! Chain private keys are SECRETS, encrypted with
//! [`ironclaw_secrets::SecretsCrypto`] under the
//! [`ironclaw_secrets::chain_key_aad`] domain (added in this PR). The
//! [`kms::ShipGate`] refuses real-value / mainnet custodial signing unless an
//! HSM/KMS backend with secure custody is wired; hot-key custodial is
//! testnet/dev only (compromised-host hot-key threat). A live cloud-KMS
//! integration and durable PG/libSQL keystore/grant/ledger backends are
//! deferred follow-ups.
//!
//! ## Per-chain layout
//!
//! [`evm`], [`solana`], and [`near`] each carry `decode` / `render` / `sign` /
//! `broadcast` / `policy`. `render` delegates to PR2's shared field projection
//! so the human-approved view and the signed bytes cannot diverge.
//!
//! EVM signing is complete (secp256k1 over alloy-computed signing hashes with a
//! mandatory ecrecover binding check). Solana and NEAR signing use the vendored
//! `ed25519-dalek` (+ `borsh` for NEAR) so the heavy `solana-sdk` /
//! `near-primitives` SDKs are not pulled; their SDK-level wire decoders (Solana
//! `VersionedMessage` with on-chain ALT resolution, NEAR `Transaction` borsh
//! round-trip) are the immediate next slice — flagged here and in the PR body.
//!
//! ## Open questions (injectable, deny-first)
//!
//! First-key bootstrap trust anchor, key rotation, and custody recovery/backup
//! are open governance questions; they are surfaced as injectable
//! [`policy::BootstrapPolicy`] / [`policy::KeyCustodyPolicy`] hooks with
//! conservative deny-first defaults rather than hardcoded answers.
#![warn(unreachable_pub)]
#![forbid(unsafe_code)]

#[cfg(feature = "broadcast-http")]
pub(crate) mod broadcast_http;
mod chain;
mod custodial;
mod error;
mod keystore;
mod kms;
mod policy;

pub mod evm;
pub mod near;
pub mod solana;

#[cfg(feature = "broadcast-http")]
pub use broadcast_http::RpcEndpoint;
pub use chain::{ChainFamily, ChainKeyId};
pub use custodial::{
    CustodialSignOutcome, CustodialSignRequest, CustodialSigner, recompute_approved_hash,
};
pub use error::{ChainSigningError, Result};
pub use keystore::{ChainKeyBinding, ConsumedChainKey, KeyStore, KeyStoreError, SecretsKeyStore};
pub use kms::{HsmKmsBackend, ShipGate, ValueClass};
pub use policy::{
    AllowBootstrapPolicy, BootstrapPolicy, CustodyDecision, DenyFirstBootstrapPolicy,
    DenyFirstCustodyPolicy, KeyCustodyPolicy,
};
