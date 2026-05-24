//! The chain identity newtype shared across the keystore, custodial signer, and
//! per-chain modules.

use ironclaw_attestation::DecodedTransaction;
use serde::{Deserialize, Serialize};

/// A chain / network identity string, e.g. `eip155:1`, `solana:mainnet-beta`,
/// `near:mainnet`.
///
/// This is the value bound into the secrets AAD ([`ironclaw_secrets::chain_key_aad`])
/// and compared against a transaction's [`DecodedTransaction::chain_network`].
/// It is a strong newtype so a raw `String` chain id cannot be confused with an
/// account id or any other identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ChainKeyId(String);

impl ChainKeyId {
    /// Wrap a chain identity string.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the underlying string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The coarse chain family for this identity (`evm`, `solana`, `near`, or
    /// `unknown`). Used to reject wrong-chain confusion before any key access.
    pub fn family(&self) -> ChainFamily {
        if self.0.starts_with("eip155:") {
            ChainFamily::Evm
        } else if self.0.starts_with("solana:") {
            ChainFamily::Solana
        } else if self.0.starts_with("near:") {
            ChainFamily::Near
        } else {
            ChainFamily::Unknown
        }
    }
}

impl std::fmt::Display for ChainKeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Coarse chain family, derived from a [`ChainKeyId`] or a
/// [`DecodedTransaction`] variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainFamily {
    /// EVM family (`eip155:*`).
    Evm,
    /// Solana family (`solana:*`).
    Solana,
    /// NEAR family (`near:*`).
    Near,
    /// Unrecognized — always treated as a mismatch (fail closed).
    Unknown,
}

impl ChainFamily {
    /// The chain family a decoded transaction belongs to.
    pub fn of_transaction(tx: &DecodedTransaction) -> Self {
        match tx {
            DecodedTransaction::Evm(_) => ChainFamily::Evm,
            DecodedTransaction::Solana(_) => ChainFamily::Solana,
            DecodedTransaction::Near(_) => ChainFamily::Near,
        }
    }
}
