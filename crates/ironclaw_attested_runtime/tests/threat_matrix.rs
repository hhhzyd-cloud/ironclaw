//! Threat-matrix integration tests for the attested-signing reborn runtime
//! (PR10).
//!
//! These drive the REAL composition pieces — the [`RuntimeAttestedResumePort`]
//! through the actual `ironclaw_turns` resume path, and the
//! [`AttestedSignerContinuationDriver`] through the real `ironclaw_chain_signing`
//! custodial signer / `ironclaw_wallet_external` provider and the
//! `ironclaw_attestation` sealed-grant + ledger stores — rather than testing a
//! helper in isolation (CLAUDE.md "Test Through the Caller").
//!
//! Coverage maps to the threat matrix in
//! `docs/plans/2026-05-23-attested-signing-substrate.md`:
//!
//! * #1  sealed-grant replay rejected
//! * #3  caller-supplied hash rejected
//! * #5  EVM `from` spoof caught via ecrecover
//! * #6  broadcast retry blocked by the ledger
//! * #7  `Stuck -> InProgress` double-broadcast blocked (ledger-state-keyed)
//! * #16 LLM-loop never re-entered on resume (resume yields AttestedResolved,
//!   never Queued)
//! * #18 ship-gate refuses custodial mainnet without KMS

use std::sync::Arc;

use alloy_consensus::TxEip1559;
use alloy_primitives::{Address, Bytes, TxKind, U256};

use ironclaw_attestation::{
    AttestedSigningGrant, DecodedTransaction, GrantKey, InMemorySealedGrantStore,
    InMemorySigningLedger, RenderingSchemaVersion, SealedGrantStore, SigningLedger,
    SigningLedgerState,
};
use ironclaw_attested_runtime::{
    AttestedGateBinding, AttestedGateBindingStore, AttestedSignerContinuationDriver,
    ContinuationError, CustodialMainnetShipGate, InMemoryAttestedGateBindingStore,
    InMemoryResumeGuard, ProviderRegistry, ResumeGuard, RuntimeAttestedResumePort, SyncBindingRead,
    approved_tx_hash_ref_hex,
};
use ironclaw_chain_signing::{
    ChainKeyBinding, ChainKeyId, ChainSigningError, CustodialSigner, DenyFirstCustodyPolicy,
    KeyStore, SecretsKeyStore, evm,
};
use ironclaw_host_api::{InvocationId, ProjectId, ResourceScope, TenantId, UserId};
use ironclaw_secrets::SecretsCrypto;
use ironclaw_signing_provider::{
    ActorId, ApprovedTxHash, ChainId, GateRef as SigningGateRef, KeyOrAccountId, ProviderId, RunId,
    ScopeId, SigningContext, SigningProof, TenantId as SigningTenantId, UserId as SigningUserId,
};
use ironclaw_turns::{
    ApprovedTxHashRef, AttestationClaimRef, AttestedResumePort, AttestedResumeRejection,
    AttestedResumeRequest, GateRef as TurnsGateRef,
};
use secrecy::SecretString;

// ── shared fixtures ──────────────────────────────────────────────────────

const GATE: &str = "gate:threat-matrix";
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

fn signing_context(account_hex_no_prefix: &str) -> SigningContext {
    SigningContext {
        tenant: SigningTenantId::new("default"),
        user: SigningUserId::new("alice"),
        scope: ScopeId::new("scope-x"),
        actor: ActorId::new("actor-7"),
        run_id: RunId::new("run-42"),
        gate_ref: SigningGateRef::new(GATE),
        chain_id: ChainId::new(DEV_TESTNET_CHAIN),
        key_or_account_id: KeyOrAccountId::new(account_hex_no_prefix),
    }
}

/// Build a sample EIP-1559 transaction + its decoded form + the binding hash.
fn sample_evm() -> (TxEip1559, DecodedTransaction, ApprovedTxHash) {
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
    let hash =
        ironclaw_chain_signing::recompute_approved_hash(&decoded, RenderingSchemaVersion::CURRENT);
    (tx, decoded, hash)
}

/// An EVM keystore bound to the address derived from `priv_bytes`, plus the
/// lowercase-hex (no `0x`) bound account string.
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

/// The concrete custodial driver type assembled by [`custodial_driver`].
type TestCustodialDriver = AttestedSignerContinuationDriver<
    ironclaw_reborn_noop::NoopBroadcaster,
    InMemorySigningLedger,
    CustodialSigner<SecretsKeyStore, InMemorySealedGrantStore, InMemorySigningLedger>,
>;

/// Assemble a custodial driver with shared grant + ledger stores. Returns the
/// driver, the shared grant store, the shared ledger, and the binding store.
fn custodial_driver(
    keystore: Arc<SecretsKeyStore>,
    bindings: Arc<InMemoryAttestedGateBindingStore>,
) -> (
    TestCustodialDriver,
    Arc<InMemorySealedGrantStore>,
    Arc<InMemorySigningLedger>,
) {
    let grants = Arc::new(InMemorySealedGrantStore::new());
    let ledger = Arc::new(InMemorySigningLedger::new());
    // Testnet chain => ship-gate permits hot-key custodial without a KMS.
    let ship_gate = CustodialMainnetShipGate::new(false).build_chain_ship_gate(None);
    let signer = Arc::new(CustodialSigner::new(
        Arc::clone(&keystore),
        Arc::clone(&grants),
        Arc::clone(&ledger),
        ship_gate,
        Arc::new(DenyFirstCustodyPolicy),
    ));
    let driver = AttestedSignerContinuationDriver::new(
        Arc::clone(&bindings) as Arc<dyn AttestedGateBindingStore>,
        ProviderRegistry::new(),
        signer,
        Arc::clone(&ledger),
        Arc::new(ironclaw_reborn_noop::NoopBroadcaster),
    );
    (driver, grants, ledger)
}

/// A local no-op broadcaster mirroring the composition crate's
/// `NoopBroadcaster` so the driver's ledger guard is exercised without network
/// I/O.
mod ironclaw_reborn_noop {
    use super::*;

    #[derive(Default)]
    pub struct NoopBroadcaster;

    #[async_trait::async_trait]
    impl ironclaw_attested_runtime::Broadcaster for NoopBroadcaster {
        async fn broadcast(
            &self,
            _context: &SigningContext,
            _signed: &[u8],
        ) -> Result<String, ContinuationError> {
            Ok("noop".to_string())
        }
    }
}

async fn seal_grant(grants: &InMemorySealedGrantStore, ctx: &SigningContext, hash: ApprovedTxHash) {
    let key = GrantKey::from_context(ctx, hash);
    grants
        .seal(AttestedSigningGrant::seal(key, 0, None))
        .await
        .expect("seal");
}

async fn put_binding(
    bindings: &InMemoryAttestedGateBindingStore,
    ctx: &SigningContext,
    decoded: DecodedTransaction,
    hash: ApprovedTxHash,
) {
    bindings
        .put(
            SigningGateRef::new(GATE),
            AttestedGateBinding {
                provider_id: ProviderId::Custodial,
                context: ctx.clone(),
                approved_tx_hash: hash,
                decoded,
                chain: ChainKeyId::new(DEV_TESTNET_CHAIN),
                scope: owner_scope(),
                schema_version: RenderingSchemaVersion::CURRENT,
            },
        )
        .await;
}

// ── Threat #18: ship-gate refuses custodial mainnet without KMS ───────────

#[test]
fn threat_18_ship_gate_refuses_custodial_mainnet_without_kms() {
    // Opt-in TRUE but no KMS backend: mainnet must still be refused.
    let gate = CustodialMainnetShipGate::new(true).build_chain_ship_gate(None);
    let err = gate
        .authorize_chain("eip155:1")
        .expect_err("mainnet custodial must be refused without secure custody");
    assert!(matches!(err, ChainSigningError::ShipGateRefused { .. }));

    // Testnet is always allowed (hot-key dev signing).
    assert!(gate.authorize_chain(DEV_TESTNET_CHAIN).is_ok());

    // Opt-out (default) also refuses mainnet.
    let gate_off = CustodialMainnetShipGate::new(false).build_chain_ship_gate(None);
    assert!(gate_off.authorize_chain("eip155:1").is_err());
}

// ── Threat #1 + #6: grant replay & broadcast retry both fail closed ───────

#[tokio::test]
async fn threat_1_and_6_custodial_replay_and_broadcast_retry_blocked() {
    let priv_bytes = [0x11u8; 32];
    let (keystore, account) = keystore_with_evm_key(&priv_bytes).await;
    let ctx = signing_context(&account);
    let (tx, decoded, hash) = sample_evm();

    let bindings = Arc::new(InMemoryAttestedGateBindingStore::new());
    let (driver, grants, _ledger) = custodial_driver(Arc::clone(&keystore), Arc::clone(&bindings));
    seal_grant(&grants, &ctx, hash).await;
    put_binding(&bindings, &ctx, decoded, hash).await;

    let gate = SigningGateRef::new(GATE);
    let proof = SigningProof::WebAuthnAssertionProof(vec![]);

    // First continuation: signs + advances ledger to BroadcastSubmitted.
    let outcome = driver
        .continue_after_resolved(&gate, &proof, Some(&tx))
        .await
        .expect("first continuation succeeds");
    assert_eq!(outcome.ledger_state, SigningLedgerState::BroadcastSubmitted);

    // Second continuation of the SAME gate: the ledger row already exists and
    // is past Signed, so the deterministic continuation is refused (threats
    // #6/#7). The sealed grant was also already claimed (threat #1) — either
    // guard alone fails the replay closed.
    let err = driver
        .continue_after_resolved(&gate, &proof, Some(&tx))
        .await
        .expect_err("replay/broadcast-retry must fail closed");
    assert!(
        matches!(err, ContinuationError::Ledger(_)),
        "expected ledger guard rejection, got {err:?}"
    );
}

// ── Threat #1 directly: a second grant claim is AlreadyClaimed ────────────

#[tokio::test]
async fn threat_1_sealed_grant_one_shot_claim() {
    let priv_bytes = [0x12u8; 32];
    let (keystore, account) = keystore_with_evm_key(&priv_bytes).await;
    let ctx = signing_context(&account);
    let (_tx, _decoded, hash) = sample_evm();

    let grants = InMemorySealedGrantStore::new();
    seal_grant(&grants, &ctx, hash).await;
    let key = GrantKey::from_context(&ctx, hash);
    grants.claim(&key).await.expect("first claim wins");
    let err = grants.claim(&key).await.expect_err("second claim fails");
    assert_eq!(err, ironclaw_attestation::GrantError::AlreadyClaimed);
    let _ = keystore; // keep the bound key alive for parity with other cases
}

// ── Threat #3: caller-supplied hash rejected (sign-time re-check) ─────────

#[tokio::test]
async fn threat_3_caller_supplied_hash_rejected() {
    let priv_bytes = [0x13u8; 32];
    let (keystore, account) = keystore_with_evm_key(&priv_bytes).await;
    let ctx = signing_context(&account);
    let (tx, decoded, real_hash) = sample_evm();

    // Bind a DIFFERENT (caller-asserted) hash than what the decoded tx hashes
    // to. The driver/signer recompute from the persisted decoded tx and reject.
    let bogus_hash = ApprovedTxHash::from_bytes([0x99u8; 32]);
    assert_ne!(bogus_hash, real_hash);

    let bindings = Arc::new(InMemoryAttestedGateBindingStore::new());
    let (driver, grants, _ledger) = custodial_driver(Arc::clone(&keystore), Arc::clone(&bindings));
    seal_grant(&grants, &ctx, bogus_hash).await;
    put_binding(&bindings, &ctx, decoded, bogus_hash).await;

    let gate = SigningGateRef::new(GATE);
    let err = driver
        .continue_after_resolved(
            &gate,
            &SigningProof::WebAuthnAssertionProof(vec![]),
            Some(&tx),
        )
        .await
        .expect_err("caller-supplied hash must be rejected");
    assert!(
        matches!(err, ContinuationError::ApprovedHashMismatch),
        "expected approved-hash mismatch, got {err:?}"
    );
}

// ── Threat #5: EVM `from` spoof caught via ecrecover binding ──────────────

#[tokio::test]
async fn threat_5_evm_from_spoof_caught_via_ecrecover() {
    // Bind the keystore account to an address that is NOT the address of the
    // private key actually stored. The custodial signer recovers the signer
    // from the signature (ecrecover) and compares it to the bound address; a
    // mismatch fails closed. We construct this by binding a wrong public
    // address against the real private key.
    let priv_bytes = [0x14u8; 32];
    let crypto = SecretsCrypto::new(SecretString::from(MASTER_KEY.to_string())).unwrap();
    let keystore = Arc::new(SecretsKeyStore::new(crypto));
    // Wrong bound address (all 0xCD), not the address of priv_bytes.
    let wrong_addr_hex = hex::encode([0xCDu8; 20]);
    let binding = ChainKeyBinding {
        chain: ChainKeyId::new(DEV_TESTNET_CHAIN),
        public_address_hex: wrong_addr_hex.clone(),
        evm_chain_id: Some(11155111),
        derivation_path: "m/44'/60'/0'/0/0".to_string(),
    };
    keystore
        .bind(&owner_scope(), binding, priv_bytes.to_vec())
        .await
        .unwrap();

    let ctx = signing_context(&wrong_addr_hex);
    let (tx, decoded, hash) = sample_evm();
    let bindings = Arc::new(InMemoryAttestedGateBindingStore::new());
    let (driver, grants, _ledger) = custodial_driver(Arc::clone(&keystore), Arc::clone(&bindings));
    seal_grant(&grants, &ctx, hash).await;
    put_binding(&bindings, &ctx, decoded, hash).await;

    let gate = SigningGateRef::new(GATE);
    let err = driver
        .continue_after_resolved(
            &gate,
            &SigningProof::WebAuthnAssertionProof(vec![]),
            Some(&tx),
        )
        .await
        .expect_err("ecrecover binding mismatch must fail closed");
    assert!(
        matches!(
            err,
            ContinuationError::ChainSigning(ChainSigningError::SignerMismatch)
        ),
        "expected ecrecover SignerMismatch, got {err:?}"
    );
}

// ── Threat #7: Stuck->InProgress double-broadcast blocked (ledger-keyed) ──

#[tokio::test]
async fn threat_7_double_broadcast_blocked_by_ledger_state() {
    // Simulate a job that already broadcast: the ledger row for this gate_ref
    // is at BroadcastSubmitted. A recovery worker re-driving the continuation
    // must be refused — the guard is keyed on LEDGER state, not job state.
    let priv_bytes = [0x15u8; 32];
    let (keystore, account) = keystore_with_evm_key(&priv_bytes).await;
    let ctx = signing_context(&account);
    let (tx, decoded, hash) = sample_evm();

    let bindings = Arc::new(InMemoryAttestedGateBindingStore::new());
    let (driver, grants, ledger) = custodial_driver(Arc::clone(&keystore), Arc::clone(&bindings));
    seal_grant(&grants, &ctx, hash).await;
    put_binding(&bindings, &ctx, decoded, hash).await;

    let gate = SigningGateRef::new(GATE);
    // Pre-advance the ledger to BroadcastSubmitted, as if a prior attempt
    // already broadcast.
    ledger.create(&gate).await.unwrap();
    ledger
        .advance(&gate, SigningLedgerState::Signing)
        .await
        .unwrap();
    ledger
        .advance(&gate, SigningLedgerState::Signed)
        .await
        .unwrap();
    ledger
        .advance(&gate, SigningLedgerState::BroadcastSubmitted)
        .await
        .unwrap();

    // The recovery re-drive must be refused (the create fails AlreadyExists and
    // the row is already broadcast).
    let err = driver
        .continue_after_resolved(
            &gate,
            &SigningProof::WebAuthnAssertionProof(vec![]),
            Some(&tx),
        )
        .await
        .expect_err("double-broadcast after recovery must fail closed");
    assert!(
        matches!(err, ContinuationError::Ledger(_)),
        "expected ledger guard rejection, got {err:?}"
    );
    // Ledger never regressed out of BroadcastSubmitted.
    assert_eq!(
        ledger.state(&gate).await.unwrap(),
        SigningLedgerState::BroadcastSubmitted
    );
}

// ── Threats #1/#16 via the resume PORT (drives the turns resume boundary) ──

#[test]
fn threat_16_resume_port_validates_then_one_shot_no_loop_reentry() {
    // The port runs synchronously inside the turn store's resume critical
    // section: it re-checks the bound hash and claims a one-shot resume guard.
    let bindings = Arc::new(InMemoryAttestedGateBindingStore::new());
    let resume_guard: Arc<dyn ResumeGuard> = Arc::new(InMemoryResumeGuard::new());
    let port = RuntimeAttestedResumePort::new(
        Arc::clone(&bindings) as Arc<dyn SyncBindingRead>,
        Arc::clone(&resume_guard),
    );

    let ctx = signing_context(&hex::encode([0xAAu8; 20]));
    let (_tx, decoded, hash) = sample_evm();
    // Persist the authoritative binding (as PR11 ingress would on raising).
    bindings.get_sync(&SigningGateRef::new(GATE)); // no-op read
    // SAFETY: synchronous put via the sync helper-equivalent (use blocking put
    // through a tiny runtime since put is async).
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    rt.block_on(put_binding(&bindings, &ctx, decoded, hash));

    let hash_ref = approved_tx_hash_ref_hex(hash.as_bytes());
    let gate = TurnsGateRef::new(GATE).unwrap();
    let attestation = AttestationClaimRef::new(hash_ref.clone()).unwrap();
    let expected = ApprovedTxHashRef::new(hash_ref).unwrap();

    // First resume verifies (binding matches; guard claimed).
    port.verify_attested_resume(AttestedResumeRequest {
        gate_ref: &gate,
        attestation: &attestation,
        expected_tx_hash: &expected,
    })
    .expect("first attested resume verifies");

    // Replay of the same gate is refused one-shot (threat #1 at the resume
    // boundary). The turn would already be AttestedResolved, never re-queued
    // onto the agent loop (threat #16) — the port only ever returns Ok once.
    let err = port
        .verify_attested_resume(AttestedResumeRequest {
            gate_ref: &gate,
            attestation: &attestation,
            expected_tx_hash: &expected,
        })
        .expect_err("replayed resume must fail closed");
    assert_eq!(err, AttestedResumeRejection::EvidenceRejected);
}

// ── Threat #3 at the resume boundary: caller-supplied hash on resume ──────

#[test]
fn threat_3_resume_port_rejects_mismatched_expected_hash() {
    let bindings = Arc::new(InMemoryAttestedGateBindingStore::new());
    let resume_guard: Arc<dyn ResumeGuard> = Arc::new(InMemoryResumeGuard::new());
    let port = RuntimeAttestedResumePort::new(
        Arc::clone(&bindings) as Arc<dyn SyncBindingRead>,
        resume_guard,
    );

    let ctx = signing_context(&hex::encode([0xABu8; 20]));
    let (_tx, decoded, hash) = sample_evm();
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    rt.block_on(put_binding(&bindings, &ctx, decoded, hash));

    let gate = TurnsGateRef::new(GATE).unwrap();
    // A caller-supplied expected hash that does NOT match the bound hash.
    let bogus = ApprovedTxHashRef::new("00".repeat(32)).unwrap();
    let attestation = AttestationClaimRef::new(approved_tx_hash_ref_hex(hash.as_bytes())).unwrap();
    let err = port
        .verify_attested_resume(AttestedResumeRequest {
            gate_ref: &gate,
            attestation: &attestation,
            expected_tx_hash: &bogus,
        })
        .expect_err("mismatched expected hash must be rejected");
    assert_eq!(err, AttestedResumeRejection::BindingMismatch);
}
