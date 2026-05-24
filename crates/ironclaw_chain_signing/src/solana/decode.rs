//! Solana decode -> PR2 [`DecodedTransaction`].
//!
//! Accepts an already-projected [`SolanaTransaction`] (the PR2 model, with
//! address-lookup-table references already resolved to absolute pubkeys). A
//! `solana-sdk` `VersionedMessage` wire decoder that performs on-chain ALT
//! resolution is the immediate next slice (see module docs).

use ironclaw_attestation::{DecodedTransaction, SolanaTransaction};

use crate::error::ChainSigningError;

/// Wrap a projected Solana transaction as a chain-tagged [`DecodedTransaction`].
///
/// Validates the basic shape (non-empty account keys) and rejects obvious
/// inconsistencies so a malformed projection can't reach the signer.
pub fn decode_projected(tx: SolanaTransaction) -> Result<DecodedTransaction, ChainSigningError> {
    if tx.account_keys.is_empty() {
        return Err(ChainSigningError::Decode {
            chain: "solana",
            reason: "message has no account keys".to_string(),
        });
    }
    // Every instruction's program id must appear as an account key (Solana
    // requires program ids to be in the account-key list).
    for (i, ix) in tx.instructions.iter().enumerate() {
        if !tx.account_keys.iter().any(|k| k == &ix.program_id) {
            return Err(ChainSigningError::Decode {
                chain: "solana",
                reason: format!("instruction {i} program id not present in account keys"),
            });
        }
    }
    Ok(DecodedTransaction::Solana(tx))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironclaw_attestation::{Bytes32, SolanaInstruction};

    fn tx() -> SolanaTransaction {
        let program = Bytes32([9u8; 32]);
        SolanaTransaction {
            cluster: "mainnet-beta".into(),
            account_keys: vec![Bytes32([1u8; 32]), program],
            recent_blockhash: Bytes32([2u8; 32]),
            instructions: vec![SolanaInstruction {
                program_id: program,
                accounts: vec![Bytes32([1u8; 32])],
                data: vec![1, 2, 3],
            }],
            compute_unit_limit: Some(200_000),
            compute_unit_price: Some(1),
        }
    }

    #[test]
    fn valid_projection_decodes() {
        assert!(decode_projected(tx()).is_ok());
    }

    #[test]
    fn empty_account_keys_rejected() {
        let mut t = tx();
        t.account_keys.clear();
        assert!(decode_projected(t).is_err());
    }

    #[test]
    fn unknown_program_id_rejected() {
        let mut t = tx();
        t.instructions[0].program_id = Bytes32([42u8; 32]);
        assert!(decode_projected(t).is_err());
    }
}
