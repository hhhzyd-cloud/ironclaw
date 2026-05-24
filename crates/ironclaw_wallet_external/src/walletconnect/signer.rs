//! Signer recovery / verification for WalletConnect v2 attestations.
//!
//! A WalletConnect wallet attests to the gate-bound operation by signing a
//! **domain-separated attestation digest** that commits to *all* of:
//!
//! * the bound [`ApprovedTxHash`](ironclaw_signing_provider::ApprovedTxHash)
//!   (WYSIWYS hash binding — replay/tamper defense, T20),
//! * the WalletConnect **session topic** the proof belongs to (relay/session
//!   binding — a proof minted under a different session is rejected, T18), and
//! * a per-request **nonce** (replay defense across requests in the same
//!   session, T18).
//!
//! For EVM the signer is recovered from the 65-byte signature via secp256k1
//! ecrecover (`k256`) and reduced to its 20-byte address. For Solana/NEAR the
//! signer is the connected ed25519 account, verified with the vendored
//! `ed25519-dalek`. In every case the resolved signer must equal the bound
//! account ([`SignerMismatch`](ironclaw_signing_provider::SigningProviderError::SignerMismatch)).
//!
//! This module computes the digest and verifies signatures over it. The relay
//! transport / Sign envelope crypto comes from the fork — it is never
//! reimplemented here.

use k256::ecdsa::{RecoveryId, Signature as EcSignature, VerifyingKey};
use sha3::{Digest, Keccak256};

use ed25519_dalek::{Signature as EdSignature, Verifier, VerifyingKey as EdVerifyingKey};

use ironclaw_signing_provider::{ApprovedTxHash, SigningProviderError};

use super::namespace::ChainFamily;

/// Domain-separation tag + version byte for the WalletConnect attestation
/// digest. Distinct from the EIP-191 injected `personal_sign` digest so a proof
/// minted for one provider can never be replayed against the other.
const WC_ATTEST_DOMAIN: &[u8] = b"ironclaw/walletconnect/attest/v1";

/// Compute the 32-byte domain-separated attestation digest the wallet signs.
///
/// `keccak256(domain ∥ approved_tx_hash ∥ len(topic) ∥ topic ∥ len(nonce) ∥ nonce)`.
/// Length-prefixing the variable-length session topic and nonce makes the
/// commitment unambiguous (no concatenation collisions between distinct
/// `(topic, nonce)` pairs).
pub(super) fn attestation_digest(
    approved_tx_hash: &ApprovedTxHash,
    session_topic: &str,
    nonce: &[u8],
) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(WC_ATTEST_DOMAIN);
    hasher.update(approved_tx_hash.as_bytes());
    hasher.update((session_topic.len() as u64).to_be_bytes());
    hasher.update(session_topic.as_bytes());
    hasher.update((nonce.len() as u64).to_be_bytes());
    hasher.update(nonce);
    let out = hasher.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&out);
    digest
}

/// Verify a WalletConnect attestation signature over `digest` and require the
/// resolved signer to equal `bound_account`.
///
/// * `family` selects the recovery scheme.
/// * `signature` is 65 bytes (r ∥ s ∥ v) for EVM, 64 bytes for ed25519 families.
/// * `public_key` is required (32 bytes) for the ed25519 families and ignored
///   for EVM (the address is recovered from the signature).
pub(super) fn verify_attestation(
    family: ChainFamily,
    digest: &[u8; 32],
    signature: &[u8],
    public_key: Option<&[u8]>,
    bound_account: &str,
) -> Result<(), SigningProviderError> {
    match family {
        ChainFamily::Evm => verify_evm(digest, signature, bound_account),
        ChainFamily::Solana | ChainFamily::Near => {
            let pk = public_key.ok_or(SigningProviderError::ProofInvalid {
                reason: "ed25519 walletconnect proof missing public_key".to_string(),
            })?;
            verify_ed25519(digest, signature, pk, bound_account)
        }
    }
}

/// Recover the EVM signer from a 65-byte signature over `digest` and require it
/// to equal `bound_account` (`0x`-prefixed, case-insensitive 20-byte hex).
fn verify_evm(
    digest: &[u8; 32],
    signature: &[u8],
    bound_account: &str,
) -> Result<(), SigningProviderError> {
    if signature.len() != 65 {
        return Err(SigningProviderError::ProofInvalid {
            reason: format!("evm signature must be 65 bytes, got {}", signature.len()),
        });
    }
    let sig = EcSignature::from_slice(&signature[..64]).map_err(|e| {
        SigningProviderError::ProofInvalid {
            reason: format!("invalid evm signature scalars: {e}"),
        }
    })?;
    let rec_id = recovery_id_from_v(signature[64])?;
    let recovered =
        VerifyingKey::recover_from_prehash(digest.as_slice(), &sig, rec_id).map_err(|e| {
            SigningProviderError::ProofInvalid {
                reason: format!("evm signer recovery failed: {e}"),
            }
        })?;
    let recovered_address = address_from_verifying_key(&recovered);
    let bound = parse_evm_address(bound_account)?;
    if recovered_address != bound {
        return Err(SigningProviderError::SignerMismatch);
    }
    Ok(())
}

/// Verify a 64-byte ed25519 signature over `digest` against `public_key`, and
/// require `public_key` to equal `bound_account` (lowercase 32-byte hex).
fn verify_ed25519(
    digest: &[u8; 32],
    signature: &[u8],
    public_key: &[u8],
    bound_account: &str,
) -> Result<(), SigningProviderError> {
    if signature.len() != 64 {
        return Err(SigningProviderError::ProofInvalid {
            reason: format!(
                "ed25519 signature must be 64 bytes, got {}",
                signature.len()
            ),
        });
    }
    let pk_bytes: [u8; 32] =
        public_key
            .try_into()
            .map_err(|_| SigningProviderError::ProofInvalid {
                reason: format!(
                    "ed25519 public key must be 32 bytes, got {}",
                    public_key.len()
                ),
            })?;
    // Signer binding (T17): the verifying key must equal the bound account
    // before we trust any signature it produced.
    let bound = parse_ed25519_pubkey(bound_account)?;
    if pk_bytes != bound {
        return Err(SigningProviderError::SignerMismatch);
    }
    let verifying_key =
        EdVerifyingKey::from_bytes(&pk_bytes).map_err(|e| SigningProviderError::ProofInvalid {
            reason: format!("invalid ed25519 public key: {e}"),
        })?;
    let sig_bytes: [u8; 64] =
        signature
            .try_into()
            .map_err(|_| SigningProviderError::ProofInvalid {
                reason: "ed25519 signature length mismatch".to_string(),
            })?;
    let sig = EdSignature::from_bytes(&sig_bytes);
    verifying_key
        .verify(digest, &sig)
        .map_err(|e| SigningProviderError::ProofInvalid {
            reason: format!("ed25519 verification failed: {e}"),
        })?;
    Ok(())
}

/// Normalize the signature `v` byte to a `k256` [`RecoveryId`] (0/1, 27/28, or
/// EIP-155 reduced to parity).
fn recovery_id_from_v(v: u8) -> Result<RecoveryId, SigningProviderError> {
    let parity = match v {
        0 | 1 => v,
        27 | 28 => v - 27,
        v if v >= 35 => (v - 35) & 1,
        other => {
            return Err(SigningProviderError::ProofInvalid {
                reason: format!("invalid evm recovery id v={other}"),
            });
        }
    };
    RecoveryId::from_byte(parity).ok_or(SigningProviderError::ProofInvalid {
        reason: "invalid evm recovery id parity".to_string(),
    })
}

/// `keccak256(uncompressed_pubkey[1..])[12..]`.
fn address_from_verifying_key(key: &VerifyingKey) -> [u8; 20] {
    let encoded = key.to_encoded_point(false);
    let hash = Keccak256::digest(&encoded.as_bytes()[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    addr
}

/// Parse a `0x`-prefixed (case-insensitive) hex EVM address into 20 bytes.
fn parse_evm_address(s: &str) -> Result<[u8; 20], SigningProviderError> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    if stripped.len() != 40 {
        return Err(SigningProviderError::ProofInvalid {
            reason: format!("bound account is not a 20-byte evm address: {s}"),
        });
    }
    let mut out = [0u8; 20];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&stripped[i * 2..i * 2 + 2], 16).map_err(|e| {
            SigningProviderError::ProofInvalid {
                reason: format!("bound account hex invalid: {e}"),
            }
        })?;
    }
    Ok(out)
}

/// Parse a lowercase-hex 32-byte ed25519 public key into bytes.
fn parse_ed25519_pubkey(s: &str) -> Result<[u8; 32], SigningProviderError> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    if stripped.len() != 64 {
        return Err(SigningProviderError::ProofInvalid {
            reason: format!("bound account is not a 32-byte ed25519 key: {s}"),
        });
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&stripped[i * 2..i * 2 + 2], 16).map_err(|e| {
            SigningProviderError::ProofInvalid {
                reason: format!("bound account hex invalid: {e}"),
            }
        })?;
    }
    Ok(out)
}
