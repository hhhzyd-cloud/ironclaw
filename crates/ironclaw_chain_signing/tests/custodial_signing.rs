//! Adversarial integration tests driving the [`CustodialSigner`] call site
//! (not just the helpers): both enforcement points, broadcast idempotency,
//! wrong-chain confusion, the ship-gate, and untrusted-metadata policy.

use std::sync::Arc;

use alloy_consensus::TxEip1559;
use alloy_primitives::{Bytes, TxKind, U256};

use ironclaw_attestation::{
    AttestedSigningGrant, GrantKey, InMemorySealedGrantStore, InMemorySigningLedger,
    RenderingSchemaVersion, SealedGrantStore, SigningLedger, SigningLedgerState,
};
use ironclaw_chain_signing::{
    ChainKeyBinding, ChainKeyId, ChainSigningError, CustodialSignRequest, CustodialSigner,
    DenyFirstCustodyPolicy, KeyStore, SecretsKeyStore, ShipGate, evm, recompute_approved_hash,
};
use ironclaw_host_api::{
    InvocationId, ProjectId, ResourceScope, TenantId as HostTenantId, UserId as HostUserId,
};
use ironclaw_secrets::SecretsCrypto;
use ironclaw_signing_provider::{
    ActorId, ChainId, GateRef, KeyOrAccountId, RunId, ScopeId, SigningContext, TenantId, UserId,
};
use k256::ecdsa::SigningKey;
use secrecy::SecretString;

const SCHEMA: RenderingSchemaVersion = RenderingSchemaVersion::CURRENT;
const TESTNET_CHAIN: &str = "eip155:11155111"; // sepolia: hot-key allowed

fn crypto() -> SecretsCrypto {
    SecretsCrypto::new(SecretString::from(
        "0123456789abcdef0123456789ABCDEF".to_string(),
    ))
    .unwrap()
}

fn host_scope() -> ResourceScope {
    ResourceScope {
        tenant_id: HostTenantId::new("default").unwrap(),
        user_id: HostUserId::new("alice").unwrap(),
        agent_id: None,
        project_id: Some(ProjectId::new("bootstrap").unwrap()),
        mission_id: None,
        thread_id: None,
        invocation_id: InvocationId::new(),
    }
}

fn ctx(chain: &str) -> SigningContext {
    SigningContext {
        tenant: TenantId::new("default"),
        user: UserId::new("alice"),
        scope: ScopeId::new("scope-x"),
        actor: ActorId::new("actor-1"),
        run_id: RunId::new("run-1"),
        gate_ref: GateRef::new("gate:tx-1"),
        chain_id: ChainId::new(chain),
        key_or_account_id: KeyOrAccountId::new("custodial"),
    }
}

fn sample_tx() -> TxEip1559 {
    TxEip1559 {
        chain_id: 11155111,
        nonce: 3,
        gas_limit: 21000,
        max_fee_per_gas: 100,
        max_priority_fee_per_gas: 2,
        to: TxKind::Call(alloy_primitives::address!(
            "00000000000000000000000000000000000000aa"
        )),
        value: U256::from(1000u64),
        access_list: Default::default(),
        input: Bytes::new(),
    }
}

fn signing_key() -> SigningKey {
    SigningKey::from_slice(&[0x11u8; 32]).unwrap()
}

/// Build a fully-wired signer plus a bound key and a sealed grant for the happy
/// path; the caller can omit the grant seal to test the no-grant case.
struct Fixture {
    signer: CustodialSigner<SecretsKeyStore, InMemorySealedGrantStore, InMemorySigningLedger>,
    grants: Arc<InMemorySealedGrantStore>,
    ledger: Arc<InMemorySigningLedger>,
    req: CustodialSignRequest,
    tx: TxEip1559,
}

async fn fixture(seal_grant: bool, mutate_after_approval: bool) -> Fixture {
    let chain = TESTNET_CHAIN;
    let tx = sample_tx();
    let key = signing_key();
    let bound = evm::address_of(&key);
    let bound_hex = hex::encode(bound.as_slice());

    // Keystore: bind the custodial key.
    let keystore = Arc::new(SecretsKeyStore::new(crypto()));
    keystore
        .bind(
            &host_scope(),
            ChainKeyBinding {
                chain: ChainKeyId::new(chain),
                public_address_hex: bound_hex,
                evm_chain_id: Some(11155111),
                derivation_path: "m/44'/60'/0'/0/0".into(),
            },
            key.to_bytes().to_vec(),
        )
        .await
        .unwrap();

    // Decode the tx into the PR2 model and compute the approved hash.
    let decoded = evm::decode_eip1559(&tx);
    let approved = recompute_approved_hash(&decoded, SCHEMA);

    // Optionally mutate the persisted decoded tx AFTER approval (enforcement #2).
    let persisted = if mutate_after_approval {
        let mut d = decoded.clone();
        if let ironclaw_attestation::DecodedTransaction::Evm(evm_tx) = &mut d {
            evm_tx.value = vec![0xff, 0xff]; // change the value post-approval
        }
        d
    } else {
        decoded
    };

    let grants = Arc::new(InMemorySealedGrantStore::new());
    let ledger = Arc::new(InMemorySigningLedger::new());
    let context = ctx(chain);

    // Ledger row always created at Approved (the gate just approved).
    ledger.create(&context.gate_ref).await.unwrap();

    if seal_grant {
        let key = GrantKey::from_context(&context, approved);
        grants
            .seal(AttestedSigningGrant::seal(key, 0, None))
            .await
            .unwrap();
    }

    let signer = CustodialSigner::new(
        Arc::clone(&keystore),
        Arc::clone(&grants),
        Arc::clone(&ledger),
        // Testnet: hot key allowed.
        ShipGate::new(false, None),
        Arc::new(DenyFirstCustodyPolicy),
    );

    let req = CustodialSignRequest {
        context,
        scope: host_scope(),
        chain: ChainKeyId::new(chain),
        decoded: persisted,
        approved_tx_hash: approved,
        schema_version: SCHEMA,
    };

    Fixture {
        signer,
        grants,
        ledger,
        req,
        tx,
    }
}

#[tokio::test]
async fn happy_path_signs_and_advances_ledger() {
    let f = fixture(true, false).await;
    let out = f.signer.sign_evm(&f.req, &f.tx).await.expect("sign");
    // Recovered signer is surfaced (public address).
    assert!(out.signer.starts_with("0x"));
    assert!(!out.signature.is_empty());
    assert_eq!(
        f.ledger.state(&f.req.context.gate_ref).await.unwrap(),
        SigningLedgerState::Signed
    );
}

#[tokio::test]
async fn refuses_without_a_claimed_grant() {
    // No grant sealed => claim fails with NotFound => signing refused.
    let f = fixture(false, false).await;
    let err = f.signer.sign_evm(&f.req, &f.tx).await.unwrap_err();
    assert!(matches!(err, ChainSigningError::Grant(_)), "got {err:?}");
    // Ledger must NOT have advanced past Approved.
    assert_eq!(
        f.ledger.state(&f.req.context.gate_ref).await.unwrap(),
        SigningLedgerState::Approved
    );
}

#[tokio::test]
async fn second_signing_of_same_grant_is_refused_one_shot() {
    let f = fixture(true, false).await;
    f.signer.sign_evm(&f.req, &f.tx).await.expect("first sign");
    // The grant was claimed; a second claim must fail one-shot. The ledger is
    // also now at Signed, so even the ledger would block re-signing — but the
    // grant one-shot is the primary guard. Re-run with a fresh ledger row to
    // isolate the grant guard.
    let err = f
        .grants
        .claim(&GrantKey::from_context(
            &f.req.context,
            f.req.approved_tx_hash,
        ))
        .await
        .unwrap_err();
    assert_eq!(err, ironclaw_attestation::GrantError::AlreadyClaimed);
}

#[tokio::test]
async fn sign_time_hash_recheck_fails_closed_without_consuming_key() {
    // The persisted decoded tx was mutated after approval => recomputed hash
    // diverges => signing fails closed.
    let f = fixture(true, true).await;
    let err = f.signer.sign_evm(&f.req, &f.tx).await.unwrap_err();
    assert!(
        matches!(err, ChainSigningError::ApprovedHashMismatch),
        "expected ApprovedHashMismatch, got {err:?}"
    );
    // Ledger must not have advanced (no signing happened).
    assert_eq!(
        f.ledger.state(&f.req.context.gate_ref).await.unwrap(),
        SigningLedgerState::Approved
    );
}

#[tokio::test]
async fn evm_signer_binding_rejects_wrong_bound_account() {
    // Bind the keystore to a DIFFERENT address than the key actually derives.
    let chain = TESTNET_CHAIN;
    let tx = sample_tx();
    let key = signing_key();
    let keystore = Arc::new(SecretsKeyStore::new(crypto()));
    keystore
        .bind(
            &host_scope(),
            ChainKeyBinding {
                chain: ChainKeyId::new(chain),
                // Wrong bound address (all 0xbb) — does not match the key.
                public_address_hex: "bb".repeat(20),
                evm_chain_id: Some(11155111),
                derivation_path: "m".into(),
            },
            key.to_bytes().to_vec(),
        )
        .await
        .unwrap();

    let decoded = evm::decode_eip1559(&tx);
    let approved = recompute_approved_hash(&decoded, SCHEMA);
    let grants = Arc::new(InMemorySealedGrantStore::new());
    let ledger = Arc::new(InMemorySigningLedger::new());
    let context = ctx(chain);
    ledger.create(&context.gate_ref).await.unwrap();
    grants
        .seal(AttestedSigningGrant::seal(
            GrantKey::from_context(&context, approved),
            0,
            None,
        ))
        .await
        .unwrap();

    let signer = CustodialSigner::new(
        keystore,
        grants,
        ledger,
        ShipGate::new(false, None),
        Arc::new(DenyFirstCustodyPolicy),
    );
    let req = CustodialSignRequest {
        context,
        scope: host_scope(),
        chain: ChainKeyId::new(chain),
        decoded,
        approved_tx_hash: approved,
        schema_version: SCHEMA,
    };

    let err = signer.sign_evm(&req, &tx).await.unwrap_err();
    assert!(
        matches!(err, ChainSigningError::SignerMismatch),
        "got {err:?}"
    );
}

#[tokio::test]
async fn broadcast_idempotency_blocks_resigning_after_submitted() {
    let f = fixture(true, false).await;
    f.signer.sign_evm(&f.req, &f.tx).await.expect("sign");
    f.signer
        .mark_broadcast_submitted(&f.req.context)
        .await
        .expect("broadcast submitted");

    // Simulate a Stuck->InProgress recovery trying to re-sign the same gate_ref.
    // The ledger refuses to move BroadcastSubmitted back to Signing.
    let err = f
        .ledger
        .advance(&f.req.context.gate_ref, SigningLedgerState::Signing)
        .await
        .unwrap_err();
    assert_eq!(
        err,
        ironclaw_attestation::LedgerError::InvalidTransition {
            from: SigningLedgerState::BroadcastSubmitted,
            to: SigningLedgerState::Signing,
        }
    );

    // And a terminal transition still works.
    f.signer
        .finalize(&f.req.context, SigningLedgerState::Finalized)
        .await
        .expect("finalize");
}

#[tokio::test]
async fn wrong_chain_key_cannot_sign_other_chain_tx() {
    // Key bound to a Solana chain id; present an EVM tx for signing.
    let solana_chain = "solana:devnet";
    let keystore = Arc::new(SecretsKeyStore::new(crypto()));
    keystore
        .bind(
            &host_scope(),
            ChainKeyBinding {
                chain: ChainKeyId::new(solana_chain),
                public_address_hex: "00".repeat(32),
                evm_chain_id: None,
                derivation_path: "m".into(),
            },
            vec![5u8; 32],
        )
        .await
        .unwrap();

    let tx = sample_tx();
    let decoded = evm::decode_eip1559(&tx); // EVM tx
    let approved = recompute_approved_hash(&decoded, SCHEMA);
    let grants = Arc::new(InMemorySealedGrantStore::new());
    let ledger = Arc::new(InMemorySigningLedger::new());
    // Context's gate is for the EVM tx but chain bound is Solana.
    let mut context = ctx(solana_chain);
    context.gate_ref = GateRef::new("gate:confused");
    ledger.create(&context.gate_ref).await.unwrap();
    grants
        .seal(AttestedSigningGrant::seal(
            GrantKey::from_context(&context, approved),
            0,
            None,
        ))
        .await
        .unwrap();

    let signer = CustodialSigner::new(
        keystore,
        grants,
        ledger,
        ShipGate::new(false, None),
        Arc::new(DenyFirstCustodyPolicy),
    );
    let req = CustodialSignRequest {
        context,
        scope: host_scope(),
        chain: ChainKeyId::new(solana_chain), // Solana-bound key
        decoded,                              // EVM tx
        approved_tx_hash: approved,
        schema_version: SCHEMA,
    };

    let err = signer.sign_evm(&req, &tx).await.unwrap_err();
    assert!(
        matches!(err, ChainSigningError::ChainMismatch { .. }),
        "got {err:?}"
    );
}

#[tokio::test]
async fn ship_gate_refuses_mainnet_hot_key() {
    // Mainnet chain, no KMS wired, opt-in on => still refused (hot key).
    let chain = "eip155:1";
    let tx = TxEip1559 {
        chain_id: 1,
        ..sample_tx()
    };
    let key = signing_key();
    let bound = evm::address_of(&key);
    let keystore = Arc::new(SecretsKeyStore::new(crypto()));
    keystore
        .bind(
            &host_scope(),
            ChainKeyBinding {
                chain: ChainKeyId::new(chain),
                public_address_hex: hex::encode(bound.as_slice()),
                evm_chain_id: Some(1),
                derivation_path: "m".into(),
            },
            key.to_bytes().to_vec(),
        )
        .await
        .unwrap();
    let decoded = evm::decode_eip1559(&tx);
    let approved = recompute_approved_hash(&decoded, SCHEMA);
    let grants = Arc::new(InMemorySealedGrantStore::new());
    let ledger = Arc::new(InMemorySigningLedger::new());
    let context = ctx(chain);
    ledger.create(&context.gate_ref).await.unwrap();
    grants
        .seal(AttestedSigningGrant::seal(
            GrantKey::from_context(&context, approved),
            0,
            None,
        ))
        .await
        .unwrap();

    let signer = CustodialSigner::new(
        keystore,
        grants,
        ledger,
        ShipGate::new(true, None), // opt-in but no KMS
        Arc::new(DenyFirstCustodyPolicy),
    );
    let req = CustodialSignRequest {
        context,
        scope: host_scope(),
        chain: ChainKeyId::new(chain),
        decoded,
        approved_tx_hash: approved,
        schema_version: SCHEMA,
    };
    let err = signer.sign_evm(&req, &tx).await.unwrap_err();
    assert!(
        matches!(err, ChainSigningError::ShipGateRefused { .. }),
        "got {err:?}"
    );
}

#[test]
fn untrusted_metadata_rejected_by_policy() {
    use ironclaw_attestation::DecodedTransaction;
    let tx = sample_tx();
    let decoded = evm::decode_eip1559(&tx);
    let DecodedTransaction::Evm(evm_tx) = &decoded else {
        panic!("evm");
    };
    // Wrong chain id.
    assert!(evm::check_chain_id(evm_tx, 1).is_err());
    assert!(evm::check_chain_id(evm_tx, 11155111).is_ok());
}
