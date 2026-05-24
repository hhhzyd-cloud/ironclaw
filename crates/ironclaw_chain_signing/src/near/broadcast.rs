//! NEAR broadcast + finalization tracking.
//!
//! ## No silent nonce bump (broadcast idempotency)
//!
//! NEAR access keys carry a monotonic nonce; re-broadcasting with a fresh nonce
//! after a stuck submission creates a new transaction the user never approved.
//! This module submits an already-signed transaction one-shot and exposes no
//! API that re-signs or bumps the nonce; a fresh nonce requires a new approval
//! (new gate_ref + grant), enforced by the signing-ledger guard.

use async_trait::async_trait;

use crate::error::ChainSigningError;

/// Outcome of submitting a signed NEAR transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NearBroadcastOutcome {
    /// The final transaction hash, base58 in practice.
    pub tx_hash: String,
}

/// Submits an already-signed NEAR transaction.
#[async_trait]
pub trait NearBroadcaster: Send + Sync {
    /// Submit the borsh-serialized signed transaction. MUST NOT bump the nonce
    /// or re-sign.
    async fn broadcast_tx(
        &self,
        signed_tx: &[u8],
    ) -> Result<NearBroadcastOutcome, ChainSigningError>;
}

/// Live NEAR broadcaster: submits the borsh-serialized signed transaction via
/// the `broadcast_tx_async` JSON-RPC method (base64-encoded parameter) to a
/// configured RPC URL, returning the base58 transaction hash.
///
/// One-shot submitter of an already-signed transaction: it never bumps the
/// access-key nonce or re-signs. A fresh nonce requires a fresh approval (new
/// gate_ref + grant), enforced by the signing-ledger guard. We use the `_async`
/// variant deliberately — it returns the tx hash on submission without the node
/// retrying or resubmitting on our behalf. The RPC URL comes from config
/// (network-allowlisted), never hard-coded.
#[cfg(feature = "broadcast-http")]
pub struct JsonRpcNearBroadcaster {
    client: reqwest::Client,
    rpc_url: String,
}

#[cfg(feature = "broadcast-http")]
impl JsonRpcNearBroadcaster {
    /// Build a broadcaster against `rpc_url` (rustls-backed HTTP client).
    pub fn new(rpc_url: impl Into<String>) -> Result<Self, ChainSigningError> {
        let client =
            reqwest::Client::builder()
                .build()
                .map_err(|error| ChainSigningError::Broadcast {
                    chain: "near",
                    reason: format!("failed to build HTTP client: {error}"),
                })?;
        Ok(Self {
            client,
            rpc_url: rpc_url.into(),
        })
    }

    /// Build over a pre-configured client (injected timeouts / proxy / policy).
    pub fn with_client(client: reqwest::Client, rpc_url: impl Into<String>) -> Self {
        Self {
            client,
            rpc_url: rpc_url.into(),
        }
    }
}

#[cfg(feature = "broadcast-http")]
#[async_trait]
impl NearBroadcaster for JsonRpcNearBroadcaster {
    async fn broadcast_tx(
        &self,
        signed_tx: &[u8],
    ) -> Result<NearBroadcastOutcome, ChainSigningError> {
        use base64::Engine as _;

        let broadcast = |reason: String| ChainSigningError::Broadcast {
            chain: "near",
            reason,
        };
        let encoded = base64::engine::general_purpose::STANDARD.encode(signed_tx);
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "ironclaw",
            "method": "broadcast_tx_async",
            "params": [encoded],
        });
        let response = self
            .client
            .post(&self.rpc_url)
            .json(&request)
            .send()
            .await
            .map_err(|error| broadcast(format!("request failed: {error}")))?;
        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|error| broadcast(format!("invalid JSON-RPC response: {error}")))?;
        if let Some(error) = body.get("error") {
            return Err(broadcast(format!("node rejected transaction: {error}")));
        }
        // `broadcast_tx_async` returns the tx hash directly as the result string.
        let tx_hash = body
            .get("result")
            .and_then(|value| value.as_str())
            .ok_or_else(|| broadcast("JSON-RPC response missing result".to_string()))?
            .to_string();
        Ok(NearBroadcastOutcome { tx_hash })
    }
}
