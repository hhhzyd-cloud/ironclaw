//! Shared helpers for the live JSON-RPC broadcasters (EVM / Solana / NEAR).
//!
//! These run only under `feature = "broadcast-http"`. Every broadcaster is a
//! one-shot submitter of an already-signed payload — none re-signs, bumps a
//! nonce, or refreshes a blockhash. Re-broadcast requires a fresh approval,
//! enforced upstream by the signing-ledger broadcast-idempotency guard.

#![cfg(feature = "broadcast-http")]

/// Lowercase-hex encode without an `0x` prefix.
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Decode lowercase/uppercase hex (no `0x` prefix) into bytes.
pub(crate) fn decode_hex(input: &str) -> Result<Vec<u8>, String> {
    if !input.len().is_multiple_of(2) {
        return Err("odd-length hex".to_string());
    }
    (0..input.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&input[index..index + 2], 16).map_err(|error| error.to_string())
        })
        .collect()
}
