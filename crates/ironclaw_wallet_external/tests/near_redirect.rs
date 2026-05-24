//! End-to-end verification tests for the NEAR redirect
//! [`NearRedirectSigningProvider`] (attested-signing PR8).
//!
//! These drive the provider behind `Arc<dyn SigningProvider>` (object-safety)
//! and through the sealed-grant store, exercising both halves of the contract:
//!
//! * `initiate` builds an `AwaitingUserAction` redirect directive embedding the
//!   base64 transaction, the callback URL, and the gate-bound `state`.
//! * `verify_resume` is fail-closed: a valid signature from the bound account
//!   with a matching state + covering scope succeeds; a wrong account is
//!   `SignerMismatch`; a tampered hash, a bad signature, or a mismatched state
//!   is `ProofInvalid`; a function-call key with an empty receiver is a
//!   `ScopeViolation`; a replayed (already-claimed) grant fails closed.

use std::sync::Arc;

use ironclaw_attestation::{
    ApprovedTxHash, AttestedSigningGrant, GrantKey, InMemorySealedGrantStore, SealedGrantStore,
};
use ironclaw_signing_provider::{
    ActorId, ChainId, DecodedTransaction, GateRef, InitiationOutcome, KeyOrAccountId, RenderedTx,
    RunId, ScopeId, SigningContext, SigningProof, SigningProvider, SigningProviderError, TenantId,
    UserId,
};
use ironclaw_wallet_external::{
    NearAccessKeyScope, NearRedirectProofPayload, NearRedirectSigningProvider, derive_state,
    encode_near_redirect_proof,
};

use ed25519_dalek::{Signer as _, SigningKey as EdSigningKey};

const WALLET_URL: &str = "https://wallet.near.org/sign";
const CALLBACK_URL: &str = "https://ironclaw.example/api/chat/gate/resolve";
const STATE_SECRET: &[u8] = b"server-side-state-secret";

fn near_key() -> EdSigningKey {
    EdSigningKey::from_bytes(&[0x55u8; 32])
}

fn ctx_for(account: &str) -> SigningContext {
    SigningContext {
        tenant: TenantId::new("tenant-a"),
        user: UserId::new("user-1"),
        scope: ScopeId::new("scope-x"),
        actor: ActorId::new("actor-7"),
        run_id: RunId::new("run-42"),
        gate_ref: GateRef::new("gate:near-1"),
        chain_id: ChainId::new("near:mainnet"),
        key_or_account_id: KeyOrAccountId::new(account),
    }
}

/// A provider with NO gate-bound access key. Used to assert the fail-closed
/// path (a NEAR redirect proof cannot be verified without an authoritative
/// bound key — the callback-supplied key is never trusted as identity).
fn provider(store: Arc<InMemorySealedGrantStore>) -> NearRedirectSigningProvider {
    NearRedirectSigningProvider::new(WALLET_URL, CALLBACK_URL, STATE_SECRET, store)
}

/// A provider bound to `expected_key`'s public key, as PR10 will construct it
/// from the gate record. The signature is verified against THIS key.
fn provider_bound(
    store: Arc<InMemorySealedGrantStore>,
    expected_key: &EdSigningKey,
) -> NearRedirectSigningProvider {
    NearRedirectSigningProvider::with_expected_access_key(
        WALLET_URL,
        CALLBACK_URL,
        STATE_SECRET,
        store,
        expected_key.verifying_key().to_bytes().to_vec(),
    )
}

async fn seal_grant(store: &InMemorySealedGrantStore, ctx: &SigningContext, hash: ApprovedTxHash) {
    let key = GrantKey::from_context(ctx, hash);
    store
        .seal(AttestedSigningGrant::seal(key, 1_000, None))
        .await
        .expect("seal");
}

/// Build a valid proof: the key signs the bound hash, the state is gate-derived.
fn valid_proof(
    key: &EdSigningKey,
    account: &str,
    ctx: &SigningContext,
    hash: ApprovedTxHash,
    scope: NearAccessKeyScope,
) -> SigningProof {
    let sig = key.sign(hash.as_bytes());
    let payload = NearRedirectProofPayload {
        approved_tx_hash: hash,
        account_id: account.to_string(),
        public_key: key.verifying_key().to_bytes().to_vec(),
        signature: sig.to_bytes().to_vec(),
        access_key_scope: scope,
        state: derive_state(STATE_SECRET, ctx, &hash),
    };
    SigningProof::NearRedirectProof(encode_near_redirect_proof(&payload))
}

#[tokio::test]
async fn initiate_returns_redirect_directive_with_state_and_callback() {
    let store = Arc::new(InMemorySealedGrantStore::new());
    let provider = provider(store.clone());
    let ctx = ctx_for("alice.near");
    let hash = ApprovedTxHash::from_bytes([7u8; 32]);
    let decoded = DecodedTransaction::from_opaque(vec![0xab, 0xcd, 0xef]);
    let rendered = RenderedTx::from_opaque(vec![1]);

    let outcome = provider
        .initiate(&ctx, &decoded, &rendered, &hash)
        .await
        .expect("initiate");
    let InitiationOutcome::AwaitingUserAction { directive } = outcome else {
        panic!("near redirect must require a user redirect");
    };
    let url = String::from_utf8(directive).expect("utf8 url");
    assert!(url.starts_with(WALLET_URL), "url: {url}");
    assert!(url.contains("transactions="), "url: {url}");
    assert!(url.contains("callbackUrl="), "url: {url}");
    // The gate-bound state must be embedded so the callback can be matched.
    let state = derive_state(STATE_SECRET, &ctx, &hash);
    assert!(url.contains(&format!("state={state}")), "url: {url}");
}

#[tokio::test]
async fn valid_signature_from_bound_account_verifies() {
    let store = Arc::new(InMemorySealedGrantStore::new());
    let key = near_key();
    let p: Arc<dyn SigningProvider> = Arc::new(provider_bound(store.clone(), &key));
    let account = "alice.near";
    let ctx = ctx_for(account);
    let hash = ApprovedTxHash::from_bytes([7u8; 32]);
    seal_grant(&store, &ctx, hash).await;

    let proof = valid_proof(&key, account, &ctx, hash, NearAccessKeyScope::FullAccess);
    let verified = p
        .verify_resume(&ctx, &hash, &proof)
        .await
        .expect("valid near proof must verify");
    assert_eq!(verified.proof(), &proof);
}

#[tokio::test]
async fn unbound_access_key_fails_closed() {
    // A provider with no gate-bound access key must refuse to verify a NEAR
    // redirect proof: the callback-supplied public key is never trusted as
    // identity. Even an otherwise-valid proof fails closed (`ProofInvalid`).
    let store = Arc::new(InMemorySealedGrantStore::new());
    let p = provider(store.clone());
    let key = near_key();
    let account = "alice.near";
    let ctx = ctx_for(account);
    let hash = ApprovedTxHash::from_bytes([7u8; 32]);
    seal_grant(&store, &ctx, hash).await;

    let proof = valid_proof(&key, account, &ctx, hash, NearAccessKeyScope::FullAccess);
    let err = p
        .verify_resume(&ctx, &hash, &proof)
        .await
        .expect_err("unbound access key must fail closed");
    assert!(matches!(err, SigningProviderError::ProofInvalid { .. }));
}

#[tokio::test]
async fn callback_supplied_key_substitution_is_signer_mismatch() {
    // The gate is bound to `bound_key`, but the attacker signs with and declares
    // their own `attacker_key`. The account_id string still matches the bound
    // account. This must fail closed as a signer mismatch — proving the
    // callback-declared key is not accepted as identity (threat #4).
    let store = Arc::new(InMemorySealedGrantStore::new());
    let bound_key = EdSigningKey::from_bytes(&[0x11u8; 32]);
    let attacker_key = EdSigningKey::from_bytes(&[0x99u8; 32]);
    let p = provider_bound(store.clone(), &bound_key);
    let account = "alice.near";
    let ctx = ctx_for(account);
    let hash = ApprovedTxHash::from_bytes([7u8; 32]);
    seal_grant(&store, &ctx, hash).await;

    // Proof signed by the attacker's key, declaring the attacker's pubkey, but
    // claiming the bound account.
    let proof = valid_proof(
        &attacker_key,
        account,
        &ctx,
        hash,
        NearAccessKeyScope::FullAccess,
    );
    let err = p
        .verify_resume(&ctx, &hash, &proof)
        .await
        .expect_err("callback-supplied key substitution must fail closed");
    assert!(matches!(err, SigningProviderError::SignerMismatch));
}

#[tokio::test]
async fn function_call_scope_fails_closed_without_bound_operation() {
    // A function-call scope cannot be cross-checked against the bound operation
    // at this resume boundary (the structured decode is not carried into
    // resume), so a callback-declared function-call scope must fail closed
    // rather than be accepted on trust (threat #22).
    let store = Arc::new(InMemorySealedGrantStore::new());
    let key = near_key();
    let p = provider_bound(store.clone(), &key);
    let account = "alice.near";
    let ctx = ctx_for(account);
    let hash = ApprovedTxHash::from_bytes([7u8; 32]);
    seal_grant(&store, &ctx, hash).await;

    let scope = NearAccessKeyScope::FunctionCall {
        receiver_id: "contract.near".to_string(),
        method_names: vec!["ft_transfer".to_string()],
    };
    let proof = valid_proof(&key, account, &ctx, hash, scope);
    let err = p
        .verify_resume(&ctx, &hash, &proof)
        .await
        .expect_err("unverifiable function-call scope must fail closed");
    assert!(matches!(err, SigningProviderError::ScopeViolation { .. }));
}

#[tokio::test]
async fn wrong_account_is_signer_mismatch() {
    let store = Arc::new(InMemorySealedGrantStore::new());
    let p = provider(store.clone());
    let key = near_key();
    // Bind a different account than the proof claims.
    let ctx = ctx_for("bob.near");
    let hash = ApprovedTxHash::from_bytes([7u8; 32]);
    seal_grant(&store, &ctx, hash).await;

    // The proof claims `alice.near` (state derived for the bound bob.near ctx
    // would mismatch, so derive the proof for its own claimed account but bind
    // bob.near) — account binding check fires first via the bound ctx account.
    let proof = valid_proof(
        &key,
        "alice.near",
        &ctx,
        hash,
        NearAccessKeyScope::FullAccess,
    );
    let err = p
        .verify_resume(&ctx, &hash, &proof)
        .await
        .expect_err("mismatched account must reject");
    assert!(matches!(err, SigningProviderError::SignerMismatch));
}

#[tokio::test]
async fn tampered_hash_is_proof_invalid() {
    let store = Arc::new(InMemorySealedGrantStore::new());
    let p = provider(store.clone());
    let key = near_key();
    let account = "alice.near";
    let ctx = ctx_for(account);
    let bound_hash = ApprovedTxHash::from_bytes([7u8; 32]);
    seal_grant(&store, &ctx, bound_hash).await;

    // Wallet attests to a DIFFERENT hash than the gate bound.
    let attested = ApprovedTxHash::from_bytes([9u8; 32]);
    let proof = valid_proof(
        &key,
        account,
        &ctx,
        attested,
        NearAccessKeyScope::FullAccess,
    );
    let err = p
        .verify_resume(&ctx, &bound_hash, &proof)
        .await
        .expect_err("tampered hash must fail closed");
    assert!(matches!(err, SigningProviderError::ProofInvalid { .. }));
}

#[tokio::test]
async fn mismatched_state_is_proof_invalid() {
    let store = Arc::new(InMemorySealedGrantStore::new());
    let p = provider(store.clone());
    let key = near_key();
    let account = "alice.near";
    let ctx = ctx_for(account);
    let hash = ApprovedTxHash::from_bytes([7u8; 32]);
    seal_grant(&store, &ctx, hash).await;

    let sig = key.sign(hash.as_bytes());
    let payload = NearRedirectProofPayload {
        approved_tx_hash: hash,
        account_id: account.to_string(),
        public_key: key.verifying_key().to_bytes().to_vec(),
        signature: sig.to_bytes().to_vec(),
        access_key_scope: NearAccessKeyScope::FullAccess,
        // Forged / intercepted state that was not derived for this gate.
        state: "deadbeef".to_string(),
    };
    let proof = SigningProof::NearRedirectProof(encode_near_redirect_proof(&payload));
    let err = p
        .verify_resume(&ctx, &hash, &proof)
        .await
        .expect_err("bad state must fail closed");
    assert!(matches!(err, SigningProviderError::ProofInvalid { .. }));
}

#[tokio::test]
async fn bad_signature_is_proof_invalid() {
    let store = Arc::new(InMemorySealedGrantStore::new());
    let key = near_key();
    let p = provider_bound(store.clone(), &key);
    let account = "alice.near";
    let ctx = ctx_for(account);
    let hash = ApprovedTxHash::from_bytes([7u8; 32]);
    seal_grant(&store, &ctx, hash).await;

    // Signature over a different message.
    let sig = key.sign(&[0u8; 32]);
    let payload = NearRedirectProofPayload {
        approved_tx_hash: hash,
        account_id: account.to_string(),
        public_key: key.verifying_key().to_bytes().to_vec(),
        signature: sig.to_bytes().to_vec(),
        access_key_scope: NearAccessKeyScope::FullAccess,
        state: derive_state(STATE_SECRET, &ctx, &hash),
    };
    let proof = SigningProof::NearRedirectProof(encode_near_redirect_proof(&payload));
    let err = p
        .verify_resume(&ctx, &hash, &proof)
        .await
        .expect_err("bad signature must fail closed");
    assert!(matches!(err, SigningProviderError::ProofInvalid { .. }));
}

#[tokio::test]
async fn empty_receiver_function_call_scope_is_scope_violation() {
    let store = Arc::new(InMemorySealedGrantStore::new());
    let key = near_key();
    let p = provider_bound(store.clone(), &key);
    let account = "alice.near";
    let ctx = ctx_for(account);
    let hash = ApprovedTxHash::from_bytes([7u8; 32]);
    seal_grant(&store, &ctx, hash).await;

    let scope = NearAccessKeyScope::FunctionCall {
        receiver_id: String::new(),
        method_names: vec![],
    };
    let proof = valid_proof(&key, account, &ctx, hash, scope);
    let err = p
        .verify_resume(&ctx, &hash, &proof)
        .await
        .expect_err("empty receiver must be a scope violation");
    assert!(matches!(err, SigningProviderError::ScopeViolation { .. }));
}

#[tokio::test]
async fn replay_after_claim_fails_closed() {
    let store = Arc::new(InMemorySealedGrantStore::new());
    let key = near_key();
    let p = provider_bound(store.clone(), &key);
    let account = "alice.near";
    let ctx = ctx_for(account);
    let hash = ApprovedTxHash::from_bytes([7u8; 32]);
    seal_grant(&store, &ctx, hash).await;

    let proof = valid_proof(&key, account, &ctx, hash, NearAccessKeyScope::FullAccess);
    p.verify_resume(&ctx, &hash, &proof)
        .await
        .expect("first resume succeeds");
    let err = p
        .verify_resume(&ctx, &hash, &proof)
        .await
        .expect_err("replay must fail closed");
    assert!(matches!(err, SigningProviderError::GrantClaimFailed));
}

#[tokio::test]
async fn unsealed_grant_fails_closed() {
    let store = Arc::new(InMemorySealedGrantStore::new());
    let key = near_key();
    let p = provider_bound(store.clone(), &key);
    let account = "alice.near";
    let ctx = ctx_for(account);
    let hash = ApprovedTxHash::from_bytes([7u8; 32]);
    // No grant sealed.

    let proof = valid_proof(&key, account, &ctx, hash, NearAccessKeyScope::FullAccess);
    let err = p
        .verify_resume(&ctx, &hash, &proof)
        .await
        .expect_err("no grant must fail closed");
    assert!(matches!(err, SigningProviderError::GrantClaimFailed));
}

#[tokio::test]
async fn non_near_redirect_proof_is_rejected() {
    let store = Arc::new(InMemorySealedGrantStore::new());
    let p = provider(store);
    let ctx = ctx_for("alice.near");
    let hash = ApprovedTxHash::from_bytes([1u8; 32]);

    let err = p
        .verify_resume(&ctx, &hash, &SigningProof::InjectedProof(vec![1, 2, 3]))
        .await
        .expect_err("non-near-redirect proof must be rejected");
    assert!(matches!(err, SigningProviderError::ProofInvalid { .. }));
}

#[tokio::test]
async fn provider_reports_near_redirect_identity() {
    use ironclaw_signing_provider::{ProviderId, TrustModel};
    let store = Arc::new(InMemorySealedGrantStore::new());
    let p = provider(store);
    assert_eq!(p.provider_id(), ProviderId::NearRedirect);
    assert_eq!(p.trust_model(), TrustModel::ExternalWallet);
}
