//! EVM vertical: decode / render / sign / broadcast / policy.
//!
//! Signing is secp256k1 over the alloy-computed signing hash with a mandatory
//! ecrecover signer-binding check ([`sign::sign_with_binding_check`]).

pub mod broadcast;
pub mod decode;
pub mod policy;
pub mod render;
pub mod sign;

pub use broadcast::{EvmBroadcastOutcome, EvmBroadcaster};
pub use decode::{decode_eip1559, decode_eip2930, decode_legacy};
pub use policy::{
    EvmHiddenFields, EvmTokenMetadata, check_chain_id, check_token_metadata, hidden_fields,
};
pub use render::render_evm;
pub use sign::{EvmSignature, address_of, sign_with_binding_check, signing_key_from_bytes};
