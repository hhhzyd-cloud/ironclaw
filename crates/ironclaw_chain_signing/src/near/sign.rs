//! NEAR ed25519 signing over `sha256(borsh(tx))` with a signer-id binding
//! check.
//!
//! NEAR signs the SHA-256 of the borsh-serialized `Transaction`. We mirror the
//! transaction's signing-relevant fields in a local borsh struct
//! ([`NearSignableTx`]) — a full `near-primitives::Transaction` borsh round-trip
//! is the next slice (module docs). The ed25519 primitive and the
//! signer-account binding check are fully exercised here.

use borsh::BorshSerialize;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use ironclaw_attestation::NearTransaction;

use crate::error::ChainSigningError;

/// Borsh-serializable mirror of a NEAR action's signing-relevant fields.
#[derive(BorshSerialize)]
struct SignableAction {
    kind: String,
    method_name: String,
    args: Vec<u8>,
    deposit: Vec<u8>,
    gas: u64,
}

/// Borsh-serializable mirror of the NEAR transaction signing pre-image.
///
/// Field order mirrors `near-primitives::Transaction` for the carried fields;
/// the public key is included (NEAR's `Transaction` carries the signer
/// `public_key`) so the borsh bytes commit to the signing key.
#[derive(BorshSerialize)]
pub struct NearSignableTx {
    signer_id: String,
    public_key: [u8; 32],
    nonce: u64,
    receiver_id: String,
    block_hash: [u8; 32],
    actions: Vec<SignableAction>,
}

impl NearSignableTx {
    fn from_projection(tx: &NearTransaction, public_key: [u8; 32]) -> Self {
        Self {
            signer_id: tx.signer_id.clone(),
            public_key,
            nonce: tx.nonce,
            receiver_id: tx.receiver_id.clone(),
            block_hash: tx.block_hash.0,
            actions: tx
                .actions
                .iter()
                .map(|a| SignableAction {
                    kind: a.kind.clone(),
                    method_name: a.method_name.clone(),
                    args: a.args.clone(),
                    deposit: a.deposit.clone(),
                    gas: a.gas,
                })
                .collect(),
        }
    }
}

/// A produced NEAR signature plus the signer pubkey.
#[derive(Debug, Clone)]
pub struct NearSignature {
    /// The 64-byte ed25519 signature.
    pub signature: [u8; 64],
    /// The signer public key.
    pub public_key: [u8; 32],
    /// The 32-byte sha256 signing hash that was signed.
    pub signing_hash: [u8; 32],
}

/// Parse a 32-byte ed25519 seed into a signing key.
pub fn signing_key_from_bytes(bytes: &[u8]) -> Result<SigningKey, ChainSigningError> {
    let arr: [u8; 32] = bytes.try_into().map_err(|_| ChainSigningError::Sign {
        chain: "near",
        reason: "ed25519 secret key must be 32 bytes".to_string(),
    })?;
    Ok(SigningKey::from_bytes(&arr))
}

/// The 32-byte public key for a signing key.
pub fn public_key_of(key: &SigningKey) -> [u8; 32] {
    key.verifying_key().to_bytes()
}

/// Sign the NEAR transaction and enforce that the bound public key matches the
/// `expected_public_key` (the access key the keystore binding records).
///
/// NEAR account access is keyed by `(account_id, public_key)`. Binding the
/// signing key's public key to the keystore record is the NEAR analog of the
/// EVM ecrecover check: a key whose public key is not the bound access key
/// cannot sign for this account.
pub fn sign_transaction_with_binding_check(
    tx: &NearTransaction,
    key: &SigningKey,
    expected_public_key: [u8; 32],
) -> Result<NearSignature, ChainSigningError> {
    let public_key = public_key_of(key);
    if public_key != expected_public_key {
        return Err(ChainSigningError::SignerMismatch);
    }

    let signable = NearSignableTx::from_projection(tx, public_key);
    let mut borsh_bytes = Vec::new();
    signable
        .serialize(&mut borsh_bytes)
        .map_err(|e| ChainSigningError::Sign {
            chain: "near",
            reason: format!("borsh serialization failed: {e}"),
        })?;

    let signing_hash: [u8; 32] = sha2_256(&borsh_bytes);
    let sig: Signature = key.sign(&signing_hash);

    let vk = VerifyingKey::from_bytes(&public_key).map_err(|e| ChainSigningError::Sign {
        chain: "near",
        reason: format!("invalid verifying key: {e}"),
    })?;
    vk.verify_strict(&signing_hash, &sig)
        .map_err(|e| ChainSigningError::Sign {
            chain: "near",
            reason: format!("signature self-verification failed: {e}"),
        })?;

    Ok(NearSignature {
        signature: sig.to_bytes(),
        public_key,
        signing_hash,
    })
}

/// SHA-256 over a byte slice (NEAR signs sha256(borsh(tx))).
fn sha2_256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironclaw_attestation::{Bytes32, NearAction};

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[0x33u8; 32])
    }

    fn tx() -> NearTransaction {
        NearTransaction {
            network: "mainnet".into(),
            signer_id: "alice.near".into(),
            receiver_id: "bob.near".into(),
            nonce: 1,
            block_hash: Bytes32([3u8; 32]),
            actions: vec![NearAction {
                kind: "Transfer".into(),
                method_name: String::new(),
                args: vec![],
                deposit: vec![1],
                gas: 0,
            }],
        }
    }

    #[test]
    fn signs_when_public_key_matches_binding() {
        let k = key();
        let sig = sign_transaction_with_binding_check(&tx(), &k, public_key_of(&k)).expect("sign");
        assert_eq!(sig.public_key, public_key_of(&k));
    }

    #[test]
    fn rejects_when_public_key_does_not_match_binding() {
        let k = key();
        let err = sign_transaction_with_binding_check(&tx(), &k, [0xff; 32]).unwrap_err();
        assert!(matches!(err, ChainSigningError::SignerMismatch));
    }
}
