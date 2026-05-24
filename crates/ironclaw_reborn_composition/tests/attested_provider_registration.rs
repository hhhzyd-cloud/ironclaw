//! Gap-1 regression (attested-signing PR13): the NEAR-redirect and
//! WalletConnect external-wallet providers, once their ceremony config is
//! present, are REGISTERED in the attested composition's `ProviderRegistry` and
//! reach proof verification through the continuation driver — instead of
//! failing closed as `ProviderMismatch`.
//!
//! Per CLAUDE.md "Test Through the Caller", this drives the assembled
//! `RebornAttestedComposition` (the same `driver()` the WebUI ingress port
//! dispatches through) — not `AttestedProvidersConfig::build_provider_registry`
//! in isolation. The discriminator is the driver's error. An UNregistered
//! provider yields `ContinuationError::ProviderMismatch`; a registered provider
//! lets the proof reach `verify_resume`, where a bad proof surfaces as
//! `ProofRejected` (NOT `ProviderMismatch`).
//!
//! So: with no config the NEAR/WC variants are `ProviderMismatch`; with config
//! present they get past the registry and the SAME bad proof is rejected later.

use std::sync::Arc;

use alloy_consensus::TxEip1559;

use ironclaw_attestation::{DecodedTransaction, RenderingSchemaVersion};
use ironclaw_attested_runtime::{
    AttestedGateBinding, ContinuationError, CustodialMainnetShipGate,
    InMemoryAttestedGateBindingStore,
};
use ironclaw_chain_signing::{ChainKeyId, SecretsKeyStore};
use ironclaw_host_api::{AgentId, InvocationId, ProjectId, ResourceScope, TenantId, UserId};
use ironclaw_reborn_composition::{AttestedProvidersConfig, LocalDevAttestedComposition};
use ironclaw_secrets::SecretsCrypto;
use ironclaw_signing_provider::{
    ActorId, ApprovedTxHash, ChainId, GateRef as SigningGateRef, KeyOrAccountId, ProviderId, RunId,
    ScopeId, SigningContext, SigningProof, TenantId as SigningTenantId, UserId as SigningUserId,
};
use ironclaw_wallet_external::{
    NearAccessKeyScope, NearRedirectProofPayload, ProjectId as WcProjectId,
    WalletConnectProofPayload, encode_near_redirect_proof, encode_walletconnect_proof,
};
use secrecy::SecretString;

const GATE: &str = "gate:pr13-provider-reg";
const TENANT: &str = "tenant1";
const USER: &str = "user1";
const AGENT: &str = "agent1";
const PROJECT: &str = "project1";

fn signing_ctx(chain: &str, account: &str) -> SigningContext {
    SigningContext {
        tenant: SigningTenantId::new(TENANT),
        user: SigningUserId::new(USER),
        scope: ScopeId::new("scope"),
        actor: ActorId::new("actor"),
        run_id: RunId::new("run"),
        gate_ref: SigningGateRef::new(GATE),
        chain_id: ChainId::new(chain),
        key_or_account_id: KeyOrAccountId::new(account),
    }
}

fn placeholder_decoded() -> DecodedTransaction {
    use alloy_primitives::{Address, Bytes, TxKind, U256};
    ironclaw_chain_signing::evm::decode_eip1559(&TxEip1559 {
        chain_id: 11155111,
        nonce: 1,
        gas_limit: 21_000,
        max_fee_per_gas: 30_000_000_000,
        max_priority_fee_per_gas: 1_000_000_000,
        to: TxKind::Call(Address::repeat_byte(0x11)),
        value: U256::from(5u64),
        input: Bytes::new(),
        access_list: Default::default(),
    })
}

fn binding(
    provider_id: ProviderId,
    chain: &str,
    account: &str,
    hash: ApprovedTxHash,
) -> AttestedGateBinding {
    AttestedGateBinding {
        provider_id,
        context: signing_ctx(chain, account),
        approved_tx_hash: hash,
        decoded: placeholder_decoded(),
        chain: ChainKeyId::new(chain),
        scope: ResourceScope {
            tenant_id: TenantId::new(TENANT).unwrap(),
            user_id: UserId::new(USER).unwrap(),
            agent_id: Some(AgentId::new(AGENT).unwrap()),
            project_id: Some(ProjectId::new(PROJECT).unwrap()),
            mission_id: None,
            thread_id: None,
            invocation_id: InvocationId::new(),
        },
        schema_version: RenderingSchemaVersion::CURRENT,
    }
}

fn composition(
    bindings: Arc<InMemoryAttestedGateBindingStore>,
    config: AttestedProvidersConfig,
) -> LocalDevAttestedComposition {
    use ironclaw_attestation::InMemorySealedGrantStore;

    let crypto = SecretsCrypto::new(SecretString::from(
        "0123456789abcdef0123456789ABCDEF".to_string(),
    ))
    .expect("valid local-dev master key");
    let keystore = Arc::new(SecretsKeyStore::new(crypto));
    let ship_gate = CustodialMainnetShipGate::from_env().build_chain_ship_gate(None);
    let grants = Arc::new(InMemorySealedGrantStore::new());
    let registry = config.build_provider_registry(
        Arc::clone(&grants) as Arc<dyn ironclaw_attestation::SealedGrantStore>
    );
    LocalDevAttestedComposition::new_in_memory(bindings, keystore, ship_gate, grants, registry)
}

/// A deliberately-invalid NEAR proof (empty signature / bogus state). Reaches
/// `verify_resume` only if the provider is registered.
fn bad_near_proof(hash: ApprovedTxHash, account: &str) -> SigningProof {
    SigningProof::NearRedirectProof(encode_near_redirect_proof(&NearRedirectProofPayload {
        approved_tx_hash: hash,
        account_id: account.to_string(),
        public_key: vec![0u8; 32],
        signature: vec![0u8; 64],
        access_key_scope: NearAccessKeyScope::FullAccess,
        state: "bogus-state".to_string(),
    }))
}

/// A deliberately-invalid WalletConnect proof.
fn bad_wc_proof(hash: ApprovedTxHash, account: &str) -> SigningProof {
    SigningProof::WalletConnectProof(encode_walletconnect_proof(&WalletConnectProofPayload {
        session_topic: "topic-bogus".to_string(),
        approved_tx_hash: hash,
        claimed_signer: account.to_string(),
        nonce: vec![0u8; 16],
        signature: vec![0u8; 65],
        public_key: None,
    }))
}

async fn register_and_continue(
    composition: &LocalDevAttestedComposition,
    binding: AttestedGateBinding,
    proof: SigningProof,
) -> Result<(), ContinuationError> {
    let gate_ref = SigningGateRef::new(GATE);
    composition
        .register_attested_gate(gate_ref.clone(), binding, 0, None)
        .await
        .expect("register attested gate");
    composition
        .driver()
        .continue_after_resolved::<TxEip1559>(&gate_ref, &proof, None)
        .await
        .map(|_| ())
}

#[tokio::test]
async fn near_provider_unregistered_without_config_is_provider_mismatch() {
    let hash = ApprovedTxHash::from_bytes([0x5au8; 32]);
    let account = "alice.near";
    let bindings = Arc::new(InMemoryAttestedGateBindingStore::new());
    // No NEAR config -> provider stays unregistered (fail-closed).
    let comp = composition(Arc::clone(&bindings), AttestedProvidersConfig::default());
    let err = register_and_continue(
        &comp,
        binding(ProviderId::NearRedirect, "near:mainnet", account, hash),
        bad_near_proof(hash, account),
    )
    .await
    .expect_err("unregistered NEAR provider must fail closed");
    assert!(
        matches!(err, ContinuationError::ProviderMismatch { bound } if bound == ProviderId::NearRedirect),
        "expected ProviderMismatch, got {err:?}"
    );
}

#[tokio::test]
async fn near_provider_registered_with_config_reaches_verification() {
    let hash = ApprovedTxHash::from_bytes([0x5au8; 32]);
    let account = "alice.near";
    let bindings = Arc::new(InMemoryAttestedGateBindingStore::new());
    let config = AttestedProvidersConfig {
        near_redirect: Some(
            ironclaw_reborn_composition::NearRedirectConfig::new(
                "https://wallet.testnet.near.org/sign",
                "https://app.example/near/callback",
                // >=32-byte, high-entropy secret (validated config rejects
                // short / placeholder / low-entropy keys).
                "f3K9pLm2QzR7vWx1Yb4Nc8Hd6Ts0Ug5Ej2Aq",
            )
            .expect("valid near config"),
        ),
        walletconnect: None,
    };
    let comp = composition(Arc::clone(&bindings), config);
    let err = register_and_continue(
        &comp,
        binding(ProviderId::NearRedirect, "near:mainnet", account, hash),
        bad_near_proof(hash, account),
    )
    .await
    .expect_err("a bogus proof must still be rejected");
    // The KEY assertion: registered, so NOT ProviderMismatch.
    assert!(
        !matches!(err, ContinuationError::ProviderMismatch { .. }),
        "NEAR provider should be registered with config present; got {err:?}"
    );
}

#[tokio::test]
async fn walletconnect_provider_unregistered_without_config_is_provider_mismatch() {
    let hash = ApprovedTxHash::from_bytes([0x77u8; 32]);
    let account = "0xabc";
    let bindings = Arc::new(InMemoryAttestedGateBindingStore::new());
    let comp = composition(Arc::clone(&bindings), AttestedProvidersConfig::default());
    let err = register_and_continue(
        &comp,
        binding(ProviderId::WalletConnect, "eip155:1", account, hash),
        bad_wc_proof(hash, account),
    )
    .await
    .expect_err("unregistered WalletConnect provider must fail closed");
    assert!(
        matches!(err, ContinuationError::ProviderMismatch { bound } if bound == ProviderId::WalletConnect),
        "expected ProviderMismatch, got {err:?}"
    );
}

#[tokio::test]
async fn walletconnect_provider_registered_with_config_reaches_verification() {
    let hash = ApprovedTxHash::from_bytes([0x77u8; 32]);
    let account = "0xabc";
    let bindings = Arc::new(InMemoryAttestedGateBindingStore::new());
    let config = AttestedProvidersConfig {
        near_redirect: None,
        walletconnect: Some(
            ironclaw_reborn_composition::WalletConnectConfig::new(
                "00000000000000000000000000000000",
            )
            .expect("valid wc project id"),
        ),
    };
    // Sanity: the project id is a publishable id, constructs cleanly.
    let _ = WcProjectId::from("00000000000000000000000000000000");
    let comp = composition(Arc::clone(&bindings), config);
    let err = register_and_continue(
        &comp,
        binding(ProviderId::WalletConnect, "eip155:1", account, hash),
        bad_wc_proof(hash, account),
    )
    .await
    .expect_err("a bogus proof must still be rejected");
    assert!(
        !matches!(err, ContinuationError::ProviderMismatch { .. }),
        "WalletConnect provider should be registered with config present; got {err:?}"
    );
}

/// `from_env` resolves nothing when no attested env vars are set: both
/// providers stay fail-closed.
#[test]
fn from_env_is_fail_closed_when_unset() {
    // The test process does not set the attested-signing env vars.
    // Guard: only assert fail-closed when the ambient env is genuinely unset
    // (avoids a flaky failure if a developer exported one locally).
    let near_unset = std::env::var("ATTESTED_NEAR_WALLET_BASE_URL").is_err()
        && std::env::var("ATTESTED_NEAR_CALLBACK_URL").is_err()
        && std::env::var("ATTESTED_NEAR_STATE_SECRET").is_err();
    let wc_unset = std::env::var("ATTESTED_WALLETCONNECT_PROJECT_ID").is_err();
    if near_unset && wc_unset {
        let config = AttestedProvidersConfig::from_env().expect("unset env resolves cleanly");
        assert!(config.near_redirect.is_none());
        assert!(config.walletconnect.is_none());
    }
}
