//! EVM secp256k1 signing over EIP-1559 / legacy / EIP-2930 with a mandatory
//! ecrecover signer-binding check (threat #5).
//!
//! The signing digest is computed by alloy's
//! [`SignableTransaction::signature_hash`] (the correct keccak256 over the
//! RLP-encoded unsigned payload, including the EIP-2718 type byte). We sign that
//! prehash with `k256` and then **recover the signer from the produced
//! signature and assert it equals the bound keystore account**. If recovery
//! does not match, the signature is discarded and signing fails closed
//! ([`ChainSigningError::SignerMismatch`]).

use alloy_consensus::SignableTransaction;
use alloy_primitives::{Address, Signature};
use k256::ecdsa::SigningKey;

use crate::error::ChainSigningError;

/// The address recovered from a freshly produced signature, plus the signature
/// itself (alloy form). Returned by [`sign_with_binding_check`] only when the
/// recovered address equals the bound account.
#[derive(Debug, Clone)]
pub struct EvmSignature {
    /// The 65-byte (r ∥ s ∥ v) signature.
    pub signature: Signature,
    /// The recovered signer address (== bound account, by construction).
    pub recovered: Address,
}

/// Parse a 32-byte secp256k1 private key into a `k256` signing key.
pub fn signing_key_from_bytes(bytes: &[u8]) -> Result<SigningKey, ChainSigningError> {
    SigningKey::from_slice(bytes).map_err(|e| ChainSigningError::Sign {
        chain: "evm",
        // The error type from k256 does not include key bytes; still, keep the
        // message generic.
        reason: format!("invalid secp256k1 private key: {e}"),
    })
}

/// Derive the EVM address bound to a private key.
pub fn address_of(key: &SigningKey) -> Address {
    Address::from_public_key(key.verifying_key())
}

/// Sign a `SignableTransaction` and enforce that the recovered signer equals
/// `bound_account`.
///
/// This is enforcement of threat #5: even though we sign with the key we just
/// consumed, we independently recover the signer from the signature over the
/// exact signing hash and compare it to the account the keystore says this key
/// is bound to. A mismatch (corrupt key, wrong binding, malleable signature)
/// fails closed.
pub fn sign_with_binding_check<T>(
    tx: &T,
    key: &SigningKey,
    bound_account: Address,
) -> Result<EvmSignature, ChainSigningError>
where
    T: SignableTransaction<Signature>,
{
    let hash = tx.signature_hash();
    let (sig, recid) =
        key.sign_prehash_recoverable(hash.as_slice())
            .map_err(|e| ChainSigningError::Sign {
                chain: "evm",
                reason: format!("prehash signing failed: {e}"),
            })?;
    let signature = Signature::from((sig, recid));

    let recovered =
        signature
            .recover_address_from_prehash(&hash)
            .map_err(|e| ChainSigningError::Sign {
                chain: "evm",
                reason: format!("signer recovery failed: {e}"),
            })?;

    if recovered != bound_account {
        return Err(ChainSigningError::SignerMismatch);
    }

    Ok(EvmSignature {
        signature,
        recovered,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::TxEip1559;
    use alloy_primitives::{Bytes, TxKind, U256, address};
    use k256::ecdsa::SigningKey;

    fn sample_key() -> SigningKey {
        // Deterministic non-zero scalar for reproducible tests.
        SigningKey::from_slice(&[0x11u8; 32]).expect("valid key")
    }

    fn sample_tx() -> TxEip1559 {
        TxEip1559 {
            chain_id: 1,
            nonce: 1,
            gas_limit: 21000,
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 1,
            to: TxKind::Call(address!("00000000000000000000000000000000000000aa")),
            value: U256::from(1u64),
            access_list: Default::default(),
            input: Bytes::new(),
        }
    }

    #[test]
    fn sign_recovers_to_bound_account() {
        let key = sample_key();
        let bound = address_of(&key);
        let sig = sign_with_binding_check(&sample_tx(), &key, bound).expect("sign");
        assert_eq!(sig.recovered, bound);
    }

    #[test]
    fn sign_rejects_when_bound_account_is_wrong() {
        let key = sample_key();
        let wrong = address!("00000000000000000000000000000000000000bb");
        let err = sign_with_binding_check(&sample_tx(), &key, wrong).unwrap_err();
        assert!(matches!(err, ChainSigningError::SignerMismatch));
    }
}
