//! EVM native transaction -> PR2 [`DecodedTransaction`].
//!
//! Populates every signing-relevant field the canonical encoder consumes from
//! an alloy typed request, so the render and the canonical bytes cover exactly
//! what will be signed.

use alloy_consensus::{TxEip1559, TxEip2930, TxLegacy};
use alloy_primitives::TxKind;

use ironclaw_attestation::{
    Bytes32, DecodedTransaction, EvmAccessListEntry, EvmAddress, EvmTransaction,
};

/// Big-endian minimal-byte encoding of a `u128` wei value (matching PR2's
/// `Vec<u8>` value fields). Trims leading zero bytes; an all-zero value encodes
/// as an empty vector, exactly like RLP integer minimality.
fn be_minimal_u128(value: u128) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let first = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    bytes[first..].to_vec()
}

/// Big-endian minimal-byte encoding of a `U256` (for the `value` field).
fn be_minimal_u256(value: alloy_primitives::U256) -> Vec<u8> {
    let bytes: [u8; 32] = value.to_be_bytes();
    let first = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    bytes[first..].to_vec()
}

fn to_field(kind: TxKind) -> Option<EvmAddress> {
    match kind {
        TxKind::Create => None,
        TxKind::Call(addr) => Some(EvmAddress(addr.into_array())),
    }
}

fn access_list_entries(access_list: &alloy_eips::eip2930::AccessList) -> Vec<EvmAccessListEntry> {
    access_list
        .0
        .iter()
        .map(|item| EvmAccessListEntry {
            address: EvmAddress(item.address.into_array()),
            storage_keys: item.storage_keys.iter().map(|k| Bytes32(k.0)).collect(),
        })
        .collect()
}

/// Decode an EIP-1559 (fee-market) transaction.
pub fn decode_eip1559(tx: &TxEip1559) -> DecodedTransaction {
    DecodedTransaction::Evm(EvmTransaction {
        chain_id: tx.chain_id,
        nonce: tx.nonce,
        tx_type: 2,
        to: to_field(tx.to),
        value: be_minimal_u256(tx.value),
        data: tx.input.to_vec(),
        gas_limit: tx.gas_limit,
        gas_price: None,
        max_fee_per_gas: Some(be_minimal_u128(tx.max_fee_per_gas)),
        max_priority_fee_per_gas: Some(be_minimal_u128(tx.max_priority_fee_per_gas)),
        access_list: access_list_entries(&tx.access_list),
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: Vec::new(),
    })
}

/// Decode a legacy transaction.
pub fn decode_legacy(tx: &TxLegacy) -> DecodedTransaction {
    DecodedTransaction::Evm(EvmTransaction {
        // Legacy txs carry an optional chain id (EIP-155). `None` (pre-155)
        // maps to 0, which the policy layer treats as a replay-unprotected tx.
        chain_id: tx.chain_id.unwrap_or(0),
        nonce: tx.nonce,
        tx_type: 0,
        to: to_field(tx.to),
        value: be_minimal_u256(tx.value),
        data: tx.input.to_vec(),
        gas_limit: tx.gas_limit,
        gas_price: Some(be_minimal_u128(tx.gas_price)),
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        access_list: Vec::new(),
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: Vec::new(),
    })
}

/// Decode an EIP-2930 (access-list) transaction.
pub fn decode_eip2930(tx: &TxEip2930) -> DecodedTransaction {
    DecodedTransaction::Evm(EvmTransaction {
        chain_id: tx.chain_id,
        nonce: tx.nonce,
        tx_type: 1,
        to: to_field(tx.to),
        value: be_minimal_u256(tx.value),
        data: tx.input.to_vec(),
        gas_limit: tx.gas_limit,
        gas_price: Some(be_minimal_u128(tx.gas_price)),
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        access_list: access_list_entries(&tx.access_list),
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, Bytes, U256, address};

    #[test]
    fn eip1559_decode_populates_signing_fields() {
        let to: Address = address!("00000000000000000000000000000000000000aa");
        let tx = TxEip1559 {
            chain_id: 1,
            nonce: 7,
            gas_limit: 21000,
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 2,
            to: TxKind::Call(to),
            value: U256::from(1000u64),
            access_list: Default::default(),
            input: Bytes::from(vec![0xde, 0xad]),
        };
        let decoded = decode_eip1559(&tx);
        let DecodedTransaction::Evm(evm) = &decoded else {
            panic!("expected evm");
        };
        assert_eq!(evm.chain_id, 1);
        assert_eq!(evm.nonce, 7);
        assert_eq!(evm.tx_type, 2);
        assert_eq!(evm.to.unwrap().0, to.into_array());
        assert_eq!(evm.value, vec![0x03, 0xe8]); // 1000 = 0x3e8
        assert_eq!(evm.data, vec![0xde, 0xad]);
        assert_eq!(evm.max_fee_per_gas, Some(vec![100]));
    }

    #[test]
    fn be_minimal_trims_leading_zeros() {
        assert_eq!(be_minimal_u128(0), Vec::<u8>::new());
        assert_eq!(be_minimal_u128(1), vec![1]);
        assert_eq!(be_minimal_u128(256), vec![1, 0]);
    }
}
