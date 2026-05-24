//! Durable [`AttestedGateBindingStore`] backends: the authoritative binding
//! must survive a store reopen (durability) and be readable from the sync
//! [`SyncBindingRead`] path the resume port uses (no split-brain with a
//! separate in-memory store). libSQL runs against a local temp file.

#![cfg(all(feature = "integration", feature = "libsql"))]

use std::sync::Arc;

use alloy_consensus::TxEip1559;
use alloy_primitives::{Address, Bytes, TxKind, U256};
use ironclaw_attestation::{DecodedTransaction, RenderingSchemaVersion};
use ironclaw_attested_runtime::{AttestedGateBinding, AttestedGateBindingStore, SyncBindingRead};
use ironclaw_attested_store::LibSqlAttestedGateBindingStore;
use ironclaw_chain_signing::{ChainKeyId, evm};
use ironclaw_host_api::{ResourceScope, TenantId, UserId};
use ironclaw_signing_provider::{
    ActorId, ChainId, GateRef, KeyOrAccountId, ProviderId, RunId, ScopeId, SigningContext,
    TenantId as SigningTenantId, UserId as SigningUserId,
};

const GATE: &str = "gate:durable-binding";

fn sample_binding() -> AttestedGateBinding {
    let tx = TxEip1559 {
        chain_id: 11155111,
        nonce: 1,
        gas_limit: 21_000,
        max_fee_per_gas: 30_000_000_000,
        max_priority_fee_per_gas: 1_000_000_000,
        to: TxKind::Call(Address::repeat_byte(0x11)),
        value: U256::from(5u64),
        input: Bytes::new(),
        access_list: Default::default(),
    };
    let decoded: DecodedTransaction = evm::decode_eip1559(&tx);
    let approved_tx_hash =
        ironclaw_chain_signing::recompute_approved_hash(&decoded, RenderingSchemaVersion::CURRENT);
    AttestedGateBinding {
        provider_id: ProviderId::Injected,
        context: SigningContext {
            tenant: SigningTenantId::new("tenant1"),
            user: SigningUserId::new("user1"),
            scope: ScopeId::new("scope"),
            actor: ActorId::new("actor"),
            run_id: RunId::new("run"),
            gate_ref: GateRef::new(GATE),
            chain_id: ChainId::new("eip155:11155111"),
            key_or_account_id: KeyOrAccountId::new("00".repeat(20)),
        },
        approved_tx_hash,
        decoded,
        chain: ChainKeyId::new("eip155:11155111"),
        scope: ResourceScope {
            tenant_id: TenantId::new("tenant1").unwrap(),
            user_id: UserId::new("user1").unwrap(),
            agent_id: None,
            project_id: None,
            mission_id: None,
            thread_id: None,
            invocation_id: ironclaw_host_api::InvocationId::new(),
        },
        schema_version: RenderingSchemaVersion::CURRENT,
    }
}

async fn build(path: &std::path::Path) -> LibSqlAttestedGateBindingStore {
    let db = Arc::new(
        libsql::Builder::new_local(path)
            .build()
            .await
            .expect("build libsql db"),
    );
    LibSqlAttestedGateBindingStore::connect(db)
        .await
        .expect("connect binding store")
}

#[tokio::test]
async fn put_then_async_and_sync_read_agree() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("bindings.db");
    let store = build(&path).await;
    let gate = GateRef::new(GATE);

    assert!(store.get(&gate).await.is_none());
    assert!(store.get_sync(&gate).is_none());

    let binding = sample_binding();
    store.put(gate.clone(), binding.clone()).await;

    let via_async = store.get(&gate).await.expect("async read");
    let via_sync = store.get_sync(&gate).expect("sync read");
    assert_eq!(via_async.approved_tx_hash, binding.approved_tx_hash);
    assert_eq!(via_sync.approved_tx_hash, binding.approved_tx_hash);
    assert_eq!(via_sync.chain, binding.chain);
}

#[tokio::test]
async fn binding_survives_store_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("bindings.db");
    let gate = GateRef::new(GATE);
    let binding = sample_binding();

    {
        let store = build(&path).await;
        store.put(gate.clone(), binding.clone()).await;
    }

    // Reopen: the cache is rehydrated from the durable table, so the sync read
    // path works after a restart (no split-brain).
    let reopened = build(&path).await;
    let rehydrated = reopened.get_sync(&gate).expect("rehydrated sync read");
    assert_eq!(rehydrated.approved_tx_hash, binding.approved_tx_hash);
    assert_eq!(
        rehydrated.context.gate_ref.as_str(),
        binding.context.gate_ref.as_str()
    );
}
