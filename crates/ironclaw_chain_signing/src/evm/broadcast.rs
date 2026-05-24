//! EVM broadcast + finalization tracking.
//!
//! ## No silent fresh-nonce retry (threat #8 / broadcast idempotency)
//!
//! The single most dangerous EVM broadcast mistake is to "retry" a stuck
//! transaction by re-signing with a fresh nonce — that can produce a SECOND
//! valid transaction the user never approved. This module therefore models
//! broadcast as a one-shot submission of an already-signed payload and
//! exposes NO API that re-signs or bumps the nonce. Retrying requires a new
//! approval (a new gate_ref + grant), which the custodial signer enforces via
//! the [`ironclaw_attestation::SigningLedger`] broadcast-idempotency guard.
//!
//! The concrete RPC client (eth_sendRawTransaction + receipt polling) is wired
//! through the injectable [`EvmBroadcaster`] trait; a live JSON-RPC
//! implementation is a deferred follow-up.

use async_trait::async_trait;

use crate::error::ChainSigningError;

/// Outcome of submitting a signed EVM transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmBroadcastOutcome {
    /// The transaction hash assigned by the network.
    pub tx_hash: [u8; 32],
}

/// Submits an already-signed EVM transaction.
///
/// Implementations MUST NOT alter the signed payload (no nonce bump, no
/// re-sign). They submit the exact bytes and report the resulting hash.
#[async_trait]
pub trait EvmBroadcaster: Send + Sync {
    /// Submit the RLP-encoded signed transaction. Returns the tx hash on
    /// acceptance.
    async fn send_raw(&self, signed_rlp: &[u8]) -> Result<EvmBroadcastOutcome, ChainSigningError>;
}

/// Live EVM broadcaster: submits the signed RLP via `eth_sendRawTransaction`
/// over JSON-RPC to a configured endpoint.
///
/// It is a one-shot submitter of an *already-signed* payload: it never bumps
/// the nonce, re-signs, or refreshes any field. A stuck transaction must be
/// re-approved (new gate_ref + grant), which the [`crate::SigningLedger`]
/// broadcast-idempotency guard enforces upstream. The RPC URL is supplied by
/// the composition layer from config (subject to the network allowlist), never
/// hard-coded.
#[cfg(feature = "broadcast-http")]
pub struct JsonRpcEvmBroadcaster {
    client: reqwest::Client,
    rpc_url: String,
}

#[cfg(feature = "broadcast-http")]
impl JsonRpcEvmBroadcaster {
    /// Build a broadcaster against `rpc_url`. The HTTP client is rustls-backed.
    pub fn new(rpc_url: impl Into<String>) -> Result<Self, ChainSigningError> {
        let client =
            reqwest::Client::builder()
                .build()
                .map_err(|error| ChainSigningError::Broadcast {
                    chain: "evm",
                    reason: format!("failed to build HTTP client: {error}"),
                })?;
        Ok(Self {
            client,
            rpc_url: rpc_url.into(),
        })
    }

    /// Build over a pre-configured client (so callers can inject timeouts /
    /// proxy / allowlist policy).
    pub fn with_client(client: reqwest::Client, rpc_url: impl Into<String>) -> Self {
        Self {
            client,
            rpc_url: rpc_url.into(),
        }
    }
}

#[cfg(feature = "broadcast-http")]
#[async_trait]
impl EvmBroadcaster for JsonRpcEvmBroadcaster {
    async fn send_raw(&self, signed_rlp: &[u8]) -> Result<EvmBroadcastOutcome, ChainSigningError> {
        let broadcast = |reason: String| ChainSigningError::Broadcast {
            chain: "evm",
            reason,
        };
        let raw_hex = format!("0x{}", crate::broadcast_http::hex_encode(signed_rlp));
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_sendRawTransaction",
            "params": [raw_hex],
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
        let result = body
            .get("result")
            .and_then(|value| value.as_str())
            .ok_or_else(|| broadcast("JSON-RPC response missing result".to_string()))?;
        let bytes = crate::broadcast_http::decode_hex(result.trim_start_matches("0x"))
            .map_err(|reason| broadcast(format!("invalid tx hash in response: {reason}")))?;
        let tx_hash: [u8; 32] = bytes
            .try_into()
            .map_err(|_| broadcast("tx hash was not 32 bytes".to_string()))?;
        Ok(EvmBroadcastOutcome { tx_hash })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A broadcaster that records submissions and returns a canned hash, proving
    /// the trait submits the exact signed bytes with no mutation.
    struct RecordingBroadcaster {
        submissions: Mutex<Vec<Vec<u8>>>,
        hash: [u8; 32],
    }

    #[async_trait]
    impl EvmBroadcaster for RecordingBroadcaster {
        async fn send_raw(
            &self,
            signed_rlp: &[u8],
        ) -> Result<EvmBroadcastOutcome, ChainSigningError> {
            self.submissions
                .lock()
                .expect("lock")
                .push(signed_rlp.to_vec());
            Ok(EvmBroadcastOutcome { tx_hash: self.hash })
        }
    }

    #[tokio::test]
    async fn broadcaster_submits_exact_bytes() {
        let b = RecordingBroadcaster {
            submissions: Mutex::new(Vec::new()),
            hash: [7u8; 32],
        };
        let out = b.send_raw(&[1, 2, 3]).await.expect("send");
        assert_eq!(out.tx_hash, [7u8; 32]);
        assert_eq!(b.submissions.lock().unwrap().as_slice(), &[vec![1, 2, 3]]);
    }
}
