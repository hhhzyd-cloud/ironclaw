//! Gap-2 regression (attested-signing PR13): the production durable assembly
//! seam (`assemble_libsql`) builds the durable `LibSqlAttestedComposition` from
//! a DB handle + RPC endpoints + provider config — the same backend-selection
//! shape the production runtime slice will call. Proves the durable backend
//! assembles cleanly, runs its migrations, and registers the configured
//! providers (so the durable path is not `ProviderMismatch` for a configured
//! provider).
//!
//! Per CLAUDE.md "Test Through the Caller", this drives `assemble_libsql` (the
//! production builder seam) and then the assembled `driver()`, not the
//! lower-level store constructors in isolation.

#![cfg(all(feature = "libsql", feature = "attested-broadcast"))]

use std::sync::Arc;

use alloy_consensus::TxEip1559;
use alloy_primitives::{Address, Bytes, TxKind, U256};

use ironclaw_attestation::RenderingSchemaVersion;
use ironclaw_attested_runtime::{
    AttestedGateBinding, AttestedGateBindingStore, ContinuationError,
    InMemoryAttestedGateBindingStore,
};
use ironclaw_attested_store::ChainRpcEndpoints;
use ironclaw_chain_signing::{ChainKeyId, SecretsKeyStore};
use ironclaw_host_api::{AgentId, InvocationId, ProjectId, ResourceScope, TenantId, UserId};
use ironclaw_reborn_composition::{
    AttestedProvidersConfig, DurableCustody, NearRedirectConfig, assemble_libsql,
};
use ironclaw_secrets::SecretsCrypto;
use ironclaw_signing_provider::{
    ActorId, ApprovedTxHash, ChainId, GateRef as SigningGateRef, KeyOrAccountId, ProviderId, RunId,
    ScopeId, SigningContext, SigningProof, TenantId as SigningTenantId, UserId as SigningUserId,
};
use ironclaw_wallet_external::{
    NearAccessKeyScope, NearRedirectProofPayload, encode_near_redirect_proof,
};
use secrecy::SecretString;

const GATE: &str = "gate:pr13-durable";
const TENANT: &str = "tenant1";
const USER: &str = "user1";

fn keystore() -> Arc<SecretsKeyStore> {
    let crypto = SecretsCrypto::new(SecretString::from(
        "0123456789abcdef0123456789ABCDEF".to_string(),
    ))
    .expect("valid master key");
    Arc::new(SecretsKeyStore::new(crypto))
}

#[tokio::test]
async fn durable_libsql_assembles_and_drives() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = Arc::new(
        libsql::Builder::new_local(dir.path().join("attested.db"))
            .build()
            .await
            .expect("build libsql db"),
    );

    let bindings: Arc<dyn AttestedGateBindingStore> =
        Arc::new(InMemoryAttestedGateBindingStore::new());

    // NEAR configured; RPC endpoints unset for NEAR (broadcast would fail
    // closed, which is the safe default — the test stops at proof verification).
    let providers = AttestedProvidersConfig {
        near_redirect: Some(NearRedirectConfig {
            wallet_base_url: "https://wallet.testnet.near.org/sign".to_string(),
            callback_url: "https://app.example/near/callback".to_string(),
            state_secret: SecretString::from("durable-test-secret".to_string()),
        }),
        walletconnect_project_id: None,
    };

    let composition = assemble_libsql(
        Arc::clone(&db),
        Arc::clone(&bindings),
        DurableCustody::from_keystore(keystore()),
        ChainRpcEndpoints::default(),
        providers,
    )
    .await
    .expect("durable libsql composition assembles");

    // Register a NEAR gate over the durable stores, then drive the durable
    // driver with a bogus proof: the configured NEAR provider is registered, so
    // the failure is NOT ProviderMismatch.
    let hash = ApprovedTxHash::from_bytes([0x5au8; 32]);
    let account = "alice.near";
    let gate_ref = SigningGateRef::new(GATE);
    composition
        .register_attested_gate(
            gate_ref.clone(),
            AttestedGateBinding {
                provider_id: ProviderId::NearRedirect,
                context: SigningContext {
                    tenant: SigningTenantId::new(TENANT),
                    user: SigningUserId::new(USER),
                    scope: ScopeId::new("scope"),
                    actor: ActorId::new("actor"),
                    run_id: RunId::new("run"),
                    gate_ref: gate_ref.clone(),
                    chain_id: ChainId::new("near:mainnet"),
                    key_or_account_id: KeyOrAccountId::new(account),
                },
                approved_tx_hash: hash,
                decoded: ironclaw_chain_signing::evm::decode_eip1559(&TxEip1559 {
                    chain_id: 11155111,
                    nonce: 1,
                    gas_limit: 21_000,
                    max_fee_per_gas: 30_000_000_000,
                    max_priority_fee_per_gas: 1_000_000_000,
                    to: TxKind::Call(Address::repeat_byte(0x11)),
                    value: U256::from(5u64),
                    input: Bytes::new(),
                    access_list: Default::default(),
                }),
                chain: ChainKeyId::new("near:mainnet"),
                scope: ResourceScope {
                    tenant_id: TenantId::new(TENANT).unwrap(),
                    user_id: UserId::new(USER).unwrap(),
                    agent_id: Some(AgentId::new("agent1").unwrap()),
                    project_id: Some(ProjectId::new("project1").unwrap()),
                    mission_id: None,
                    thread_id: None,
                    invocation_id: InvocationId::new(),
                },
                schema_version: RenderingSchemaVersion::CURRENT,
            },
            0,
            None,
        )
        .await
        .expect("register attested gate on durable stores");

    let proof =
        SigningProof::NearRedirectProof(encode_near_redirect_proof(&NearRedirectProofPayload {
            approved_tx_hash: hash,
            account_id: account.to_string(),
            public_key: vec![0u8; 32],
            signature: vec![0u8; 64],
            access_key_scope: NearAccessKeyScope::FullAccess,
            state: "bogus".to_string(),
        }));

    let err = composition
        .driver()
        .continue_after_resolved::<TxEip1559>(&gate_ref, &proof, None)
        .await
        .expect_err("bogus proof rejected");
    assert!(
        !matches!(err, ContinuationError::ProviderMismatch { .. }),
        "configured NEAR provider must be registered on the durable path; got {err:?}"
    );
}
