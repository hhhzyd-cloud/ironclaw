//! Solana ed25519 signing over the serialized message, with a fee-payer
//! pubkey binding check.
//!
//! ## Message serialization scope
//!
//! The exact Solana on-wire message format (the bincode layout produced by
//! `solana-sdk`'s `Message::serialize`) is intentionally NOT reproduced here —
//! that requires the heavy `solana-sdk` crate, deferred to the next slice. We
//! instead sign a deterministic, length-prefixed serialization of the
//! PR2-projected message ([`message_bytes`]). The ed25519 signing primitive and
//! the signer↔fee-payer binding check (the security-critical parts) are fully
//! exercised; swapping in the real wire serializer is a localized change to
//! [`message_bytes`].

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use ironclaw_attestation::SolanaTransaction;

use crate::error::ChainSigningError;

/// A produced Solana signature plus the signer pubkey (== fee payer).
#[derive(Debug, Clone)]
pub struct SolanaSignature {
    /// The 64-byte ed25519 signature.
    pub signature: [u8; 64],
    /// The signer's 32-byte public key (the message's first account key).
    pub public_key: [u8; 32],
}

/// Parse a 32-byte ed25519 secret seed into a signing key.
pub fn signing_key_from_bytes(bytes: &[u8]) -> Result<SigningKey, ChainSigningError> {
    let arr: [u8; 32] = bytes.try_into().map_err(|_| ChainSigningError::Sign {
        chain: "solana",
        reason: "ed25519 secret key must be 32 bytes".to_string(),
    })?;
    Ok(SigningKey::from_bytes(&arr))
}

/// The 32-byte public key for a signing key.
pub fn public_key_of(key: &SigningKey) -> [u8; 32] {
    key.verifying_key().to_bytes()
}

/// Deterministic, length-prefixed serialization of the projected message.
///
/// NOTE: this is NOT the Solana wire format (see module docs) — it is a stable
/// commitment over the same fields, sufficient for the signing primitive and
/// binding tests. Replace with `solana-sdk` `Message::serialize` in the next
/// slice.
pub fn message_bytes(tx: &SolanaTransaction) -> Vec<u8> {
    let mut out = Vec::new();
    let push_lp = |out: &mut Vec<u8>, b: &[u8]| {
        out.extend_from_slice(&(b.len() as u32).to_be_bytes());
        out.extend_from_slice(b);
    };
    push_lp(&mut out, tx.cluster.as_bytes());
    push_lp(&mut out, &tx.recent_blockhash.0);
    out.extend_from_slice(&(tx.account_keys.len() as u32).to_be_bytes());
    for k in &tx.account_keys {
        out.extend_from_slice(&k.0);
    }
    out.extend_from_slice(&(tx.instructions.len() as u32).to_be_bytes());
    for ix in &tx.instructions {
        out.extend_from_slice(&ix.program_id.0);
        out.extend_from_slice(&(ix.accounts.len() as u32).to_be_bytes());
        for a in &ix.accounts {
            out.extend_from_slice(&a.0);
        }
        push_lp(&mut out, &ix.data);
    }
    out.extend_from_slice(&tx.compute_unit_limit.unwrap_or(0).to_be_bytes());
    out.extend_from_slice(&tx.compute_unit_price.unwrap_or(0).to_be_bytes());
    out
}

/// Sign the message and enforce that the signer pubkey equals the message's
/// first account key (the fee payer / required signer).
///
/// Mismatch fails closed: a key that is not the declared fee payer cannot
/// produce a usable signature for this message.
pub fn sign_message_with_binding_check(
    tx: &SolanaTransaction,
    key: &SigningKey,
) -> Result<SolanaSignature, ChainSigningError> {
    let fee_payer = tx
        .account_keys
        .first()
        .ok_or(ChainSigningError::Sign {
            chain: "solana",
            reason: "message has no fee payer account key".to_string(),
        })?
        .0;

    let pubkey = public_key_of(key);
    if pubkey != fee_payer {
        return Err(ChainSigningError::SignerMismatch);
    }

    let msg = message_bytes(tx);
    let sig: Signature = key.sign(&msg);

    // Independently verify the signature against the recovered pubkey.
    let vk = VerifyingKey::from_bytes(&pubkey).map_err(|e| ChainSigningError::Sign {
        chain: "solana",
        reason: format!("invalid verifying key: {e}"),
    })?;
    vk.verify_strict(&msg, &sig)
        .map_err(|e| ChainSigningError::Sign {
            chain: "solana",
            reason: format!("signature self-verification failed: {e}"),
        })?;

    Ok(SolanaSignature {
        signature: sig.to_bytes(),
        public_key: pubkey,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironclaw_attestation::{Bytes32, SolanaInstruction};

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[0x22u8; 32])
    }

    fn tx(fee_payer: [u8; 32]) -> SolanaTransaction {
        let program = Bytes32([9u8; 32]);
        SolanaTransaction {
            cluster: "mainnet-beta".into(),
            account_keys: vec![Bytes32(fee_payer), program],
            recent_blockhash: Bytes32([2u8; 32]),
            instructions: vec![SolanaInstruction {
                program_id: program,
                accounts: vec![Bytes32(fee_payer)],
                data: vec![1],
            }],
            compute_unit_limit: Some(200_000),
            compute_unit_price: Some(1),
        }
    }

    #[test]
    fn signs_when_key_is_fee_payer() {
        let k = key();
        let sig = sign_message_with_binding_check(&tx(public_key_of(&k)), &k).expect("sign");
        assert_eq!(sig.public_key, public_key_of(&k));
    }

    #[test]
    fn rejects_when_key_is_not_fee_payer() {
        let k = key();
        let err = sign_message_with_binding_check(&tx([0xff; 32]), &k).unwrap_err();
        assert!(matches!(err, ChainSigningError::SignerMismatch));
    }
}
