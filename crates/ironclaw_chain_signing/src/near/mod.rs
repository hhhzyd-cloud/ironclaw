//! NEAR vertical: decode / render / sign / broadcast / policy.
//!
//! ## Scope note
//!
//! The signing primitive (ed25519 over `sha256(borsh(tx))`) uses the vendored
//! `ed25519-dalek` + `borsh`, so this PR does NOT pull `near-primitives` /
//! `near-crypto`. The borsh layout here ([`sign::NearSignableTx`]) mirrors the
//! NEAR `Transaction` field order for the fields the PR2 projection carries; a
//! full `near-primitives::Transaction` round-trip (covering every action arg
//! shape) is the immediate next slice flagged in the PR body.

pub mod broadcast;
pub mod decode;
pub mod policy;
pub mod render;
pub mod sign;

pub use broadcast::{NearBroadcastOutcome, NearBroadcaster};
pub use policy::check_network;
pub use render::render_near;
pub use sign::{NearSignature, public_key_of, sign_transaction_with_binding_check};
