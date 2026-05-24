//! Solana vertical: decode / render / sign / broadcast / policy.
//!
//! ## Scope note
//!
//! The signing primitive (ed25519 over the serialized message) uses the
//! already-vendored `ed25519-dalek`, so this PR does NOT pull the heavy
//! `solana-sdk` / `solana-program` crates. The decode here accepts the PR2
//! [`ironclaw_attestation::SolanaTransaction`] projection (already
//! ALT-resolved); wiring a `solana-sdk`-level wire-format decoder
//! (`VersionedMessage` -> projection, with on-chain ALT resolution) is the
//! immediate next slice flagged in the PR body.

pub mod broadcast;
pub mod decode;
pub mod policy;
pub mod render;
pub mod sign;

pub use broadcast::{SolanaBroadcastOutcome, SolanaBroadcaster};
pub use policy::{SolanaTokenMetadata, check_cluster, check_token_metadata};
pub use render::render_solana;
pub use sign::{SolanaSignature, message_bytes, public_key_of, sign_message_with_binding_check};
