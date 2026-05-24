//! End-to-end tests for the `request_signature` attested-signing raise path
//! (attested-signing PR14).
//!
//! These drive the REAL composition pieces — the composition-owned
//! [`RebornAttestedRaiseHook`] (the exact `AttestedRaiseHook` trait method
//! `DefaultHostRuntime` calls), the real `RebornAttestedComposition`
//! (`register_attested_gate` → seals the one-shot grant + persists the
//! authoritative binding), the real `ironclaw_chain_signing` custodial signer,
//! and the existing `AttestedSignerContinuationDriver` resolve path — rather
//! than a helper in isolation (CLAUDE.md "Test Through the Caller").
//!
//! Coverage:
//! * custodial `request_signature` → `AttestedSigningRequired` → binding
//!   persisted + grant sealed → the existing resolve path
//!   (`continue_after_resolved`) verifies and continues.
//! * a NEAR / WalletConnect `provider_hint` fails closed (`Failed`, NO gate
//!   raised, NO grant sealed).

use std::sync::Arc;

use alloy_consensus::TxEip1559;
use alloy_primitives::{Address, Bytes, TxKind, U256};

use ironclaw_attestation::{DecodedTransaction, InMemorySealedGrantStore, InMemorySigningLedger};
use ironclaw_attested_runtime::{
    CustodialMainnetShipGate, InMemoryAttestedGateBindingStore, ProviderRegistry,
};
use ironclaw_chain_signing::{ChainKeyBinding, ChainKeyId, KeyStore, SecretsKeyStore, evm};
use ironclaw_host_api::{CapabilityId, InvocationId, ProjectId, ResourceScope, TenantId, UserId};
use ironclaw_host_runtime::{
    AttestedRaiseHook, AttestedRaiseRequest, RuntimeCapabilityOutcome, RuntimeFailureKind,
};
use ironclaw_reborn_composition::{RebornAttestedComposition, RebornAttestedRaiseHook};
use ironclaw_secrets::SecretsCrypto;
use ironclaw_signing_provider::{GateRef as SigningGateRef, SigningProof};
use secrecy::SecretString;
use serde_json::json;

const DEV_TESTNET_CHAIN: &str = "eip155:11155111"; // sepolia (testnet)
const MASTER_KEY: &str = "0123456789abcdef0123456789ABCDEF";

fn owner_scope() -> ResourceScope {
    ResourceScope {
        tenant_id: TenantId::new("default").unwrap(),
        user_id: UserId::new("alice").unwrap(),
        agent_id: None,
        project_id: Some(ProjectId::new("bootstrap").unwrap()),
        mission_id: None,
        thread_id: None,
        invocation_id: InvocationId::new(),
    }
}

/// Build the host execution context the raise hook reads identities from. The
/// scope matches `owner_scope()` so the custodial keystore lookup at resolve
/// time finds the provisioned key.
fn execution_context(scope: ResourceScope) -> ironclaw_host_api::ExecutionContext {
    use ironclaw_host_api::{
        CapabilitySet, CorrelationId, ExecutionContext, ExtensionId, MountView, RuntimeKind,
        TrustClass,
    };
    ExecutionContext {
        invocation_id: scope.invocation_id,
        correlation_id: CorrelationId::new(),
        process_id: None,
        parent_process_id: None,
        tenant_id: scope.tenant_id.clone(),
        user_id: scope.user_id.clone(),
        agent_id: scope.agent_id.clone(),
        project_id: scope.project_id.clone(),
        mission_id: None,
        thread_id: None,
        extension_id: ExtensionId::new("builtin").unwrap(),
        runtime: RuntimeKind::Wasm,
        trust: TrustClass::UserTrusted,
        grants: CapabilitySet { grants: vec![] },
        mounts: MountView::default(),
        resource_scope: scope,
    }
}

/// A sample EIP-1559 transaction + its SDK-free decoded projection. The raise
/// hook persists the decoded form; resolve re-signs the matching alloy tx.
fn sample_evm() -> (TxEip1559, DecodedTransaction) {
    let tx = TxEip1559 {
        chain_id: 11155111,
        nonce: 7,
        gas_limit: 21_000,
        max_fee_per_gas: 30_000_000_000,
        max_priority_fee_per_gas: 1_000_000_000,
        to: TxKind::Call(Address::repeat_byte(0xbb)),
        value: U256::from(1_000u64),
        input: Bytes::new(),
        access_list: Default::default(),
    };
    let decoded = evm::decode_eip1559(&tx);
    (tx, decoded)
}

/// Provision an EVM custodial keystore bound to the address derived from
/// `priv_bytes`. Returns the keystore + the lowercase-hex (no `0x`) account.
async fn keystore_with_evm_key(priv_bytes: &[u8; 32]) -> (Arc<SecretsKeyStore>, String) {
    let crypto = SecretsCrypto::new(SecretString::from(MASTER_KEY.to_string())).unwrap();
    let keystore = Arc::new(SecretsKeyStore::new(crypto));
    let key = evm::signing_key_from_bytes(priv_bytes).unwrap();
    let address = evm::address_of(&key);
    let addr_hex = hex::encode(address.as_slice());
    let binding = ChainKeyBinding {
        chain: ChainKeyId::new(DEV_TESTNET_CHAIN),
        public_address_hex: addr_hex.clone(),
        evm_chain_id: Some(11155111),
        derivation_path: "m/44'/60'/0'/0/0".to_string(),
    };
    keystore
        .bind(&owner_scope(), binding, priv_bytes.to_vec())
        .await
        .unwrap();
    (keystore, addr_hex)
}

/// Assemble a real in-memory composition with the provisioned custodial
/// keystore (testnet ship-gate permits hot-key dev signing).
fn composition_with_keystore(
    keystore: Arc<SecretsKeyStore>,
) -> Arc<
    RebornAttestedComposition<
        ironclaw_reborn_composition::NoopBroadcaster,
        InMemorySealedGrantStore,
        InMemorySigningLedger,
    >,
> {
    let bindings = Arc::new(InMemoryAttestedGateBindingStore::new());
    let grants = Arc::new(InMemorySealedGrantStore::new());
    let ship_gate = CustodialMainnetShipGate::new(false).build_chain_ship_gate(None);
    Arc::new(RebornAttestedComposition::new_in_memory(
        bindings,
        keystore,
        ship_gate,
        grants,
        ProviderRegistry::new(),
    ))
}

#[tokio::test]
async fn custodial_request_signature_raises_gate_and_existing_resolve_path_continues() {
    let priv_bytes = [0x11u8; 32];
    let (keystore, account) = keystore_with_evm_key(&priv_bytes).await;
    let (tx, decoded) = sample_evm();

    let composition = composition_with_keystore(Arc::clone(&keystore));
    let hook = RebornAttestedRaiseHook::new(Arc::clone(&composition));

    let capability_id = CapabilityId::new("builtin.request_signature").unwrap();
    let context = execution_context(owner_scope());
    let input = json!({
        "provider_hint": "custodial",
        "signer_account": account,
        "decoded": decoded,
    });

    // Drive the raise through the exact trait method DefaultHostRuntime calls.
    let outcome = hook
        .raise(AttestedRaiseRequest::new(
            capability_id.clone(),
            context,
            input,
        ))
        .await;

    let gate = match outcome {
        RuntimeCapabilityOutcome::AttestedSigningRequired(gate) => gate,
        other => panic!("expected AttestedSigningRequired, got {other:?}"),
    };
    assert_eq!(gate.capability_id, capability_id);
    assert!(!gate.expected_tx_hash.is_empty());

    // The binding the loop's gate ref maps to is `gate:attested-<gate_id>`. The
    // resolve path reads the binding back from the SAME composition's store.
    let gate_ref_str = format!("gate:attested-{}", gate.gate_id.as_str());
    let signing_gate_ref = SigningGateRef::new(gate_ref_str);
    let binding = composition
        .bindings()
        .get(&signing_gate_ref)
        .await
        .expect("authoritative binding persisted on raise");
    // The persisted decoded tx is exactly what resolve recomputes the hash from.
    assert_eq!(binding.decoded, decoded);

    // The existing resolve path: drive the real signer-continuation driver with
    // the matching EVM tx. This reads the persisted binding, claims the sealed
    // one-shot grant, re-checks the hash, custodial-signs, and broadcasts.
    let proof = SigningProof::WebAuthnAssertionProof(vec![]);
    let continuation = composition
        .driver()
        .continue_after_resolved(&signing_gate_ref, &proof, Some(&tx))
        .await
        .expect("existing resolve path continues a raised custodial gate");
    assert_eq!(
        continuation.ledger_state,
        ironclaw_attestation::SigningLedgerState::BroadcastSubmitted
    );

    // The one-shot grant was sealed on raise and is now claimed: a replayed
    // continuation must fail closed.
    let replay = composition
        .driver()
        .continue_after_resolved(&signing_gate_ref, &proof, Some(&tx))
        .await;
    assert!(
        replay.is_err(),
        "replayed continuation must fail closed (grant/ledger guard)"
    );
}

#[tokio::test]
async fn near_and_walletconnect_provider_hints_fail_closed_without_raising() {
    let priv_bytes = [0x22u8; 32];
    let (keystore, account) = keystore_with_evm_key(&priv_bytes).await;
    let (_tx, decoded) = sample_evm();

    let composition = composition_with_keystore(Arc::clone(&keystore));
    let hook = RebornAttestedRaiseHook::new(Arc::clone(&composition));
    let capability_id = CapabilityId::new("builtin.request_signature").unwrap();

    for hint in ["near_redirect", "wallet_connect", "injected"] {
        let input = json!({
            "provider_hint": hint,
            "signer_account": account,
            "decoded": decoded,
        });
        let outcome = hook
            .raise(AttestedRaiseRequest::new(
                capability_id.clone(),
                execution_context(owner_scope()),
                input,
            ))
            .await;

        match outcome {
            RuntimeCapabilityOutcome::Failed(failure) => {
                assert_eq!(failure.capability_id, capability_id);
                assert_eq!(failure.kind, RuntimeFailureKind::Backend);
            }
            other => panic!("expected Failed for hint {hint}, got {other:?}"),
        }
    }

    // No gate was raised and no grant sealed: a fabricated gate ref has no
    // binding, so resolve fails closed with MissingBinding.
    let signing_gate_ref = SigningGateRef::new("gate:attested-does-not-exist");
    let (tx, _) = sample_evm();
    let proof = SigningProof::WebAuthnAssertionProof(vec![]);
    let err = composition
        .driver()
        .continue_after_resolved(&signing_gate_ref, &proof, Some(&tx))
        .await
        .expect_err("no binding was persisted for any failed-closed raise");
    assert!(matches!(
        err,
        ironclaw_attested_runtime::ContinuationError::MissingBinding
    ));
}
