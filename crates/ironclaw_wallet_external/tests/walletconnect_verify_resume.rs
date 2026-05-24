//! End-to-end verification tests for the WalletConnect v2
//! [`WalletConnectSigningProvider`] security cores (attested-signing PR9).
//!
//! Drives the provider behind `Arc<dyn SigningProvider>` (object-safety) and
//! through the sealed-grant store + recorded session binding, exercising the
//! full fail-closed contract:
//!
//! * namespace pinning rejects scope broadening (T17/T19);
//! * a valid signature from the session-bound account over the bound hash →
//!   `VerifiedProof`;
//! * a tampered hash, a wrong session topic / nonce (T18), a mismatched signer
//!   (T17), and a replayed / already-claimed grant (T20) all fail closed.
//!
//! The relay is never contacted: the session binding `initiate` would record
//! over the relay (PR10) is installed directly via `record_session_binding`,
//! and the wallet signature is minted in-test over the exact domain-separated
//! digest the verifier recomputes.

use std::sync::Arc;

use ironclaw_attestation::{
    ApprovedTxHash, AttestedSigningGrant, GrantKey, InMemorySealedGrantStore, SealedGrantStore,
};
use ironclaw_signing_provider::{
    ActorId, ChainId, GateRef, KeyOrAccountId, RunId, ScopeId, SigningContext, SigningProof,
    SigningProvider, SigningProviderError, TenantId, UserId,
};
use ironclaw_wallet_external::{
    PinnedScope, ProjectId, ProposedScope, SessionBinding, WalletConnectProofPayload,
    WalletConnectSigningProvider, attestation_digest_for_test, encode_walletconnect_proof,
    enforce_pinned_scope,
};

use ed25519_dalek::{Signer as _, SigningKey as EdSigningKey};
use k256::ecdsa::{SigningKey as EcSigningKey, signature::hazmat::PrehashSigner};
use sha3::{Digest, Keccak256};

const SESSION_TOPIC: &str = "a3f1c0de";
const NONCE: &[u8] = b"nonce-001";

fn project() -> ProjectId {
    // Publishable, API-key class; injected, never hardcoded in production.
    ProjectId::from("00000000000000000000000000000000")
}

fn lower_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    out
}

// ── EVM helpers ──

fn evm_key() -> EcSigningKey {
    EcSigningKey::from_slice(&[0x11u8; 32]).expect("valid secp256k1 key")
}

fn evm_address(key: &EcSigningKey) -> [u8; 20] {
    let vk = key.verifying_key();
    let encoded = vk.to_encoded_point(false);
    let hash = Keccak256::digest(&encoded.as_bytes()[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    addr
}

/// 65-byte (r ∥ s ∥ v) signature over the 32-byte attestation digest.
fn evm_sign_digest(key: &EcSigningKey, digest: &[u8; 32]) -> Vec<u8> {
    let (sig, recid): (k256::ecdsa::Signature, k256::ecdsa::RecoveryId) =
        key.sign_prehash(digest.as_slice()).expect("sign");
    let mut out = sig.to_bytes().to_vec();
    out.push(recid.to_byte());
    out
}

// ── Solana / ed25519 helpers ──

fn ed_key() -> EdSigningKey {
    EdSigningKey::from_bytes(&[0x22u8; 32])
}

// ── Fixtures ──

fn ctx_for(account: &str, chain: &str) -> SigningContext {
    SigningContext {
        tenant: TenantId::new("tenant-a"),
        user: UserId::new("user-1"),
        scope: ScopeId::new("scope-x"),
        actor: ActorId::new("actor-7"),
        run_id: RunId::new("run-42"),
        gate_ref: GateRef::new("gate:abc"),
        chain_id: ChainId::new(chain),
        key_or_account_id: KeyOrAccountId::new(account),
    }
}

async fn seal_grant(store: &InMemorySealedGrantStore, ctx: &SigningContext, hash: ApprovedTxHash) {
    let key = GrantKey::from_context(ctx, hash);
    store
        .seal(AttestedSigningGrant::seal(key, 1_000, None))
        .await
        .expect("seal");
}

fn binding_for(account: &str, chain: &str) -> SessionBinding {
    SessionBinding {
        session_topic: SESSION_TOPIC.to_string(),
        account: account.to_string(),
        nonce: NONCE.to_vec(),
        pinned: PinnedScope::from_chain_id(&ChainId::new(chain)).expect("pinned"),
    }
}

// ── Namespace pinning (T17/T19) ──

#[test]
fn pinning_accepts_exact_scope_and_rejects_broadening() {
    let pinned = PinnedScope::from_chain_id(&ChainId::new("eip155:1")).expect("evm");
    enforce_pinned_scope(
        &pinned,
        &ProposedScope {
            chains: vec!["eip155:1".to_string()],
            methods: vec!["eth_signTransaction".to_string()],
        },
    )
    .expect("exact scope accepted");

    // Extra chain (T19).
    assert!(matches!(
        enforce_pinned_scope(
            &pinned,
            &ProposedScope {
                chains: vec!["eip155:1".to_string(), "eip155:10".to_string()],
                methods: vec!["eth_signTransaction".to_string()],
            },
        )
        .expect_err("broader chains rejected"),
        SigningProviderError::ScopeViolation { .. }
    ));

    // Extra method (T17).
    assert!(matches!(
        enforce_pinned_scope(
            &pinned,
            &ProposedScope {
                chains: vec!["eip155:1".to_string()],
                methods: vec![
                    "eth_signTransaction".to_string(),
                    "eth_sendTransaction".to_string(),
                ],
            },
        )
        .expect_err("broader methods rejected"),
        SigningProviderError::ScopeViolation { .. }
    ));
}

// ── verify_resume: EVM ──

fn evm_proof(
    key: &EcSigningKey,
    account: &str,
    hash: ApprovedTxHash,
    topic: &str,
    nonce: &[u8],
) -> SigningProof {
    let digest = attestation_digest_for_test(&hash, topic, nonce);
    let payload = WalletConnectProofPayload {
        session_topic: topic.to_string(),
        approved_tx_hash: hash,
        claimed_signer: account.to_string(),
        nonce: nonce.to_vec(),
        signature: evm_sign_digest(key, &digest),
        public_key: None,
    };
    SigningProof::WalletConnectProof(encode_walletconnect_proof(&payload))
}

#[tokio::test]
async fn evm_valid_proof_from_session_bound_account_verifies() {
    let store = Arc::new(InMemorySealedGrantStore::new());
    let provider = WalletConnectSigningProvider::new(project(), store.clone());

    let key = evm_key();
    let account = format!("0x{}", lower_hex(&evm_address(&key)));
    let ctx = ctx_for(&account, "eip155:1");
    let hash = ApprovedTxHash::from_bytes([7u8; 32]);
    seal_grant(&store, &ctx, hash).await;
    provider.record_session_binding(&ctx.gate_ref, binding_for(&account, "eip155:1"));

    let proof = evm_proof(&key, &account, hash, SESSION_TOPIC, NONCE);
    let provider: Arc<dyn SigningProvider> = Arc::new(provider);
    let verified = provider
        .verify_resume(&ctx, &hash, &proof)
        .await
        .expect("valid evm walletconnect proof must verify");
    assert_eq!(verified.proof(), &proof);
}

#[tokio::test]
async fn evm_signer_not_bound_account_is_signer_mismatch() {
    let store = Arc::new(InMemorySealedGrantStore::new());
    let provider = WalletConnectSigningProvider::new(project(), store.clone());

    let key = evm_key();
    // Bind a different account than the session settled on / the key recovers to.
    let wrong = "0x00000000000000000000000000000000000000bb";
    let ctx = ctx_for(wrong, "eip155:1");
    let hash = ApprovedTxHash::from_bytes([7u8; 32]);
    seal_grant(&store, &ctx, hash).await;
    // Binding records the *real* signing account, which differs from the bound
    // account → signer-binding check fails closed.
    let real_account = format!("0x{}", lower_hex(&evm_address(&key)));
    provider.record_session_binding(&ctx.gate_ref, binding_for(&real_account, "eip155:1"));

    let proof = evm_proof(&key, &real_account, hash, SESSION_TOPIC, NONCE);
    let err = provider
        .verify_resume(&ctx, &hash, &proof)
        .await
        .expect_err("mismatched signer must reject");
    assert!(matches!(err, SigningProviderError::SignerMismatch));
}

#[tokio::test]
async fn evm_tampered_hash_is_proof_invalid() {
    let store = Arc::new(InMemorySealedGrantStore::new());
    let provider = WalletConnectSigningProvider::new(project(), store.clone());

    let key = evm_key();
    let account = format!("0x{}", lower_hex(&evm_address(&key)));
    let ctx = ctx_for(&account, "eip155:1");
    let bound_hash = ApprovedTxHash::from_bytes([7u8; 32]);
    seal_grant(&store, &ctx, bound_hash).await;
    provider.record_session_binding(&ctx.gate_ref, binding_for(&account, "eip155:1"));

    // Wallet attests to a DIFFERENT hash than the gate bound.
    let attested = ApprovedTxHash::from_bytes([9u8; 32]);
    let proof = evm_proof(&key, &account, attested, SESSION_TOPIC, NONCE);
    let err = provider
        .verify_resume(&ctx, &bound_hash, &proof)
        .await
        .expect_err("tampered hash must fail closed");
    assert!(matches!(err, SigningProviderError::ProofInvalid { .. }));
}

#[tokio::test]
async fn evm_wrong_session_topic_is_rejected_t18() {
    let store = Arc::new(InMemorySealedGrantStore::new());
    let provider = WalletConnectSigningProvider::new(project(), store.clone());

    let key = evm_key();
    let account = format!("0x{}", lower_hex(&evm_address(&key)));
    let ctx = ctx_for(&account, "eip155:1");
    let hash = ApprovedTxHash::from_bytes([7u8; 32]);
    seal_grant(&store, &ctx, hash).await;
    provider.record_session_binding(&ctx.gate_ref, binding_for(&account, "eip155:1"));

    // Proof minted under a DIFFERENT session topic (relay/session compromise).
    let proof = evm_proof(&key, &account, hash, "deadbeef", NONCE);
    let err = provider
        .verify_resume(&ctx, &hash, &proof)
        .await
        .expect_err("wrong session topic must fail closed");
    assert!(matches!(err, SigningProviderError::ProofInvalid { .. }));
}

#[tokio::test]
async fn evm_wrong_nonce_is_rejected_t18() {
    let store = Arc::new(InMemorySealedGrantStore::new());
    let provider = WalletConnectSigningProvider::new(project(), store.clone());

    let key = evm_key();
    let account = format!("0x{}", lower_hex(&evm_address(&key)));
    let ctx = ctx_for(&account, "eip155:1");
    let hash = ApprovedTxHash::from_bytes([7u8; 32]);
    seal_grant(&store, &ctx, hash).await;
    provider.record_session_binding(&ctx.gate_ref, binding_for(&account, "eip155:1"));

    // Proof carries a stale / forged nonce (replay defense).
    let proof = evm_proof(&key, &account, hash, SESSION_TOPIC, b"other-nonce");
    let err = provider
        .verify_resume(&ctx, &hash, &proof)
        .await
        .expect_err("wrong nonce must fail closed");
    assert!(matches!(err, SigningProviderError::ProofInvalid { .. }));
}

#[tokio::test]
async fn evm_missing_session_binding_is_rejected() {
    let store = Arc::new(InMemorySealedGrantStore::new());
    let provider = WalletConnectSigningProvider::new(project(), store.clone());

    let key = evm_key();
    let account = format!("0x{}", lower_hex(&evm_address(&key)));
    let ctx = ctx_for(&account, "eip155:1");
    let hash = ApprovedTxHash::from_bytes([7u8; 32]);
    seal_grant(&store, &ctx, hash).await;
    // No session binding recorded.

    let proof = evm_proof(&key, &account, hash, SESSION_TOPIC, NONCE);
    let err = provider
        .verify_resume(&ctx, &hash, &proof)
        .await
        .expect_err("missing binding must fail closed");
    assert!(matches!(err, SigningProviderError::ProofInvalid { .. }));
}

#[tokio::test]
async fn evm_replay_after_claim_fails_closed_t20() {
    let store = Arc::new(InMemorySealedGrantStore::new());
    let provider = Arc::new(WalletConnectSigningProvider::new(project(), store.clone()));

    let key = evm_key();
    let account = format!("0x{}", lower_hex(&evm_address(&key)));
    let ctx = ctx_for(&account, "eip155:1");
    let hash = ApprovedTxHash::from_bytes([7u8; 32]);
    seal_grant(&store, &ctx, hash).await;
    provider.record_session_binding(&ctx.gate_ref, binding_for(&account, "eip155:1"));

    let proof = evm_proof(&key, &account, hash, SESSION_TOPIC, NONCE);
    provider
        .verify_resume(&ctx, &hash, &proof)
        .await
        .expect("first resume succeeds");

    // Re-record the binding so the replay reaches the grant CAS (the binding is
    // consumed on first use). The one-shot grant must still reject the replay.
    provider.record_session_binding(&ctx.gate_ref, binding_for(&account, "eip155:1"));
    let err = provider
        .verify_resume(&ctx, &hash, &proof)
        .await
        .expect_err("replay must fail closed");
    assert!(matches!(err, SigningProviderError::GrantClaimFailed));
}

#[tokio::test]
async fn evm_unsealed_grant_fails_closed() {
    let store = Arc::new(InMemorySealedGrantStore::new());
    let provider = WalletConnectSigningProvider::new(project(), store.clone());

    let key = evm_key();
    let account = format!("0x{}", lower_hex(&evm_address(&key)));
    let ctx = ctx_for(&account, "eip155:1");
    let hash = ApprovedTxHash::from_bytes([7u8; 32]);
    // No grant sealed.
    provider.record_session_binding(&ctx.gate_ref, binding_for(&account, "eip155:1"));

    let proof = evm_proof(&key, &account, hash, SESSION_TOPIC, NONCE);
    let err = provider
        .verify_resume(&ctx, &hash, &proof)
        .await
        .expect_err("no grant must fail closed");
    assert!(matches!(err, SigningProviderError::GrantClaimFailed));
}

// ── verify_resume: Solana (ed25519) ──

#[tokio::test]
async fn solana_valid_proof_verifies() {
    let store = Arc::new(InMemorySealedGrantStore::new());
    let provider: Arc<dyn SigningProvider> =
        Arc::new(WalletConnectSigningProvider::new(project(), store.clone()));

    let key = ed_key();
    let pubkey = key.verifying_key().to_bytes();
    let account = lower_hex(&pubkey);
    let ctx = ctx_for(&account, "solana:mainnet");
    let hash = ApprovedTxHash::from_bytes([5u8; 32]);
    seal_grant(&store, &ctx, hash).await;

    // Record binding via the concrete provider, then drive via the dyn handle.
    // (Downcast not needed: record before boxing in a separate provider value.)
    let inner = WalletConnectSigningProvider::new(project(), store.clone());
    inner.record_session_binding(&ctx.gate_ref, binding_for(&account, "solana:mainnet"));

    let digest = attestation_digest_for_test(&hash, SESSION_TOPIC, NONCE);
    let sig = key.sign(&digest);
    let payload = WalletConnectProofPayload {
        session_topic: SESSION_TOPIC.to_string(),
        approved_tx_hash: hash,
        claimed_signer: account.clone(),
        nonce: NONCE.to_vec(),
        signature: sig.to_bytes().to_vec(),
        public_key: Some(pubkey.to_vec()),
    };
    let proof = SigningProof::WalletConnectProof(encode_walletconnect_proof(&payload));

    inner
        .verify_resume(&ctx, &hash, &proof)
        .await
        .expect("valid solana walletconnect proof must verify");

    // Object-safety sanity: the dyn handle is usable.
    let _ = provider.provider_id();
}

#[tokio::test]
async fn solana_wrong_signer_is_signer_mismatch() {
    let store = Arc::new(InMemorySealedGrantStore::new());
    let provider = WalletConnectSigningProvider::new(project(), store.clone());

    let key = ed_key();
    let pubkey = key.verifying_key().to_bytes();
    // Bind a different pubkey than the proof's.
    let other = [0x33u8; 32];
    let bound_account = lower_hex(&other);
    let ctx = ctx_for(&bound_account, "solana:mainnet");
    let hash = ApprovedTxHash::from_bytes([5u8; 32]);
    seal_grant(&store, &ctx, hash).await;
    provider.record_session_binding(&ctx.gate_ref, binding_for(&bound_account, "solana:mainnet"));

    let digest = attestation_digest_for_test(&hash, SESSION_TOPIC, NONCE);
    let sig = key.sign(&digest);
    let payload = WalletConnectProofPayload {
        session_topic: SESSION_TOPIC.to_string(),
        approved_tx_hash: hash,
        claimed_signer: bound_account.clone(),
        nonce: NONCE.to_vec(),
        signature: sig.to_bytes().to_vec(),
        public_key: Some(pubkey.to_vec()),
    };
    let proof = SigningProof::WalletConnectProof(encode_walletconnect_proof(&payload));

    let err = provider
        .verify_resume(&ctx, &hash, &proof)
        .await
        .expect_err("mismatched solana signer must reject");
    assert!(matches!(err, SigningProviderError::SignerMismatch));
}

#[tokio::test]
async fn non_walletconnect_proof_is_rejected() {
    let store = Arc::new(InMemorySealedGrantStore::new());
    let provider = WalletConnectSigningProvider::new(project(), store);
    let ctx = ctx_for("0x00000000000000000000000000000000000000aa", "eip155:1");
    let hash = ApprovedTxHash::from_bytes([1u8; 32]);

    let err = provider
        .verify_resume(&ctx, &hash, &SigningProof::InjectedProof(vec![1, 2, 3]))
        .await
        .expect_err("non-walletconnect proof must be rejected");
    assert!(matches!(err, SigningProviderError::ProofInvalid { .. }));
}

#[tokio::test]
async fn object_safe_behind_dyn_arc() {
    let store = Arc::new(InMemorySealedGrantStore::new());
    let provider: Arc<dyn SigningProvider> =
        Arc::new(WalletConnectSigningProvider::new(project(), store));
    assert_eq!(
        provider.provider_id(),
        ironclaw_signing_provider::ProviderId::WalletConnect
    );
    assert_eq!(
        provider.trust_model(),
        ironclaw_signing_provider::TrustModel::ExternalWallet
    );
}
