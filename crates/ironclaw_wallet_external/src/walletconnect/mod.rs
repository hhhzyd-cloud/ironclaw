//! The WalletConnect v2 [`SigningProvider`] backend (attested-signing PR9).
//!
//! [`WalletConnectSigningProvider`] bridges a WalletConnect v2 session — driven
//! over the openssl-free `relay_client` fork — to the attested-signing gate. It
//! reports [`ProviderId::WalletConnect`] and [`TrustModel::ExternalWallet`] and
//! holds **no key material**: the user's wallet renders + signs natively (true
//! WYSIWYS). It is configured with a WalletConnect Cloud [`ProjectId`]
//! (publishable, API-key class — injected, never hardcoded).
//!
//! ## Two security cores
//!
//! 1. **Namespace pinning** ([`namespace`]). The gate has decided exactly one
//!    chain + one signing operation; a WC session can negotiate far broader
//!    scope. [`PinnedScope`] derives the single CAIP-2 chain + single signing
//!    method the gate authorizes, and every proposed/settled session scope is
//!    checked equal to it — any superset is a [`SigningProviderError::ScopeViolation`]
//!    (threats T17/T19).
//! 2. **Proof verification** ([`Self::verify_resume`]). Fail-closed, in order:
//!    hash binding (T20), session + nonce binding (T18), signer binding (T17,
//!    [`SignerMismatch`](SigningProviderError::SignerMismatch)), then the
//!    one-shot sealed-grant CAS (T20,
//!    [`GrantClaimFailed`](SigningProviderError::GrantClaimFailed)). Only on full
//!    success is a [`VerifiedProof`] returned.
//!
//! ## Scope boundary (PR9 vs PR10)
//!
//! PR9 implements the provider, the namespace pinning, and the full proof
//! verification against a recorded session binding. The encrypted CAIP-25 Sign
//! envelope round-trip over the relay (publishing the pairing proposal,
//! subscribing for the wallet's response, decrypting the signed payload) and the
//! verified-proof → gate handoff + broadcast are composition owned by PR10 and
//! are marked `// PR10:`. The fork's `relay_client` provides relay transport but
//! not the higher-level v2 Sign session layer, so the live round-trip is stubbed
//! at the verified-proof boundary rather than reimplemented here.

mod namespace;
mod proof;
mod session;
mod signer;

use std::sync::Arc;

use async_trait::async_trait;

use ironclaw_attestation::{GrantError, GrantKey, SealedGrantStore};
use ironclaw_signing_provider::{
    ApprovedTxHash, DecodedTransaction, InitiationOutcome, ProviderId, RenderedTx, SigningContext,
    SigningProof, SigningProvider, SigningProviderError, TrustModel, VerifiedProof,
};

// Re-export the publishable relay-side ProjectId newtype from the fork so
// callers configure the provider with the SDK's own type (no parallel newtype).
pub use relay_rpc::domain::ProjectId;

pub use namespace::{ChainFamily, PinnedScope, ProposedScope, enforce_pinned_scope};
pub use proof::{
    WalletConnectProofPayload, decode_walletconnect_proof, encode_walletconnect_proof,
};
pub use session::{SessionBinding, SessionBindingStore};

/// The WalletConnect v2 signing backend.
///
/// Holds the injected [`ProjectId`], a sealed-grant store (for the one-shot CAS
/// at verify time), and the per-gate [`SessionBindingStore`]. Holds **no key
/// material**.
pub struct WalletConnectSigningProvider {
    project_id: ProjectId,
    grants: Arc<dyn SealedGrantStore>,
    bindings: Arc<SessionBindingStore>,
}

impl WalletConnectSigningProvider {
    /// Construct over an injected [`ProjectId`] and a sealed-grant store.
    ///
    /// The `ProjectId` is a publishable WalletConnect Cloud API key sourced from
    /// configuration / `ironclaw_secrets` by the composition layer (PR10) — it
    /// is never hardcoded. Different tenants may inject different project ids;
    /// this provider treats it as opaque per-instance config.
    pub fn new(project_id: ProjectId, grants: Arc<dyn SealedGrantStore>) -> Self {
        Self {
            project_id,
            grants,
            bindings: Arc::new(SessionBindingStore::new()),
        }
    }

    /// The WalletConnect Cloud project id this provider is configured with.
    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    /// Record an expected session binding for a gate.
    ///
    /// In production this is populated by `initiate` once the WC session settles
    /// over the relay (PR10 wires the live settlement). Exposed so the
    /// composition layer — and tests — can install the binding the eventual
    /// proof must match.
    pub fn record_session_binding(
        &self,
        gate: &ironclaw_signing_provider::GateRef,
        binding: SessionBinding,
    ) {
        self.bindings.record(gate, binding);
    }
}

#[async_trait]
impl SigningProvider for WalletConnectSigningProvider {
    fn provider_id(&self) -> ProviderId {
        ProviderId::WalletConnect
    }

    fn trust_model(&self) -> TrustModel {
        TrustModel::ExternalWallet
    }

    async fn initiate(
        &self,
        context: &SigningContext,
        _decoded: &DecodedTransaction,
        _rendered: &RenderedTx,
        _approved_tx_hash: &ApprovedTxHash,
    ) -> Result<InitiationOutcome, SigningProviderError> {
        // Pin the single chain + single signing method the gate authorizes.
        // Resolving this here — before any relay traffic — means a session can
        // only ever be proposed at the pinned scope (T17/T19). An unsupported or
        // malformed chain id fails closed as a ScopeViolation.
        let pinned = PinnedScope::from_chain_id(&context.chain_id)?;

        // PR10: establish the WC v2 session over the forked `relay_client`:
        // build a pairing URI for the configured ProjectId, publish the CAIP-25
        // session proposal pinned to `pinned.caip2_chain` + `pinned.method`,
        // subscribe for the wallet's settlement, enforce `enforce_pinned_scope`
        // against the SETTLED namespaces, mint a per-request nonce, and
        // `record_session_binding(gate, SessionBinding { session_topic, account,
        // nonce, pinned })`. The encrypted Sign envelope layer is not exposed by
        // the relay_client fork, so the live round-trip is deferred to PR10. The
        // pinned method that would be requested is `pinned.method`
        // (e.g. eth_signTransaction / solana_signTransaction /
        // near_signTransactions) — sign-only; broadcast is PR10.
        let _ = (&self.project_id, pinned);

        // Until PR10 wires the live pairing, signal that the ceremony proceeds
        // out of band (the directive bytes a real session would carry — the
        // pairing URI — are a PR10 concern).
        Ok(InitiationOutcome::AwaitingUserAction {
            // PR10: replace with the real WalletConnect pairing URI bytes.
            directive: Vec::new(),
        })
    }

    async fn verify_resume(
        &self,
        context: &SigningContext,
        approved_tx_hash: &ApprovedTxHash,
        proof: &SigningProof,
    ) -> Result<VerifiedProof, SigningProviderError> {
        // Only WalletConnect proofs are accepted; anything else is a routing
        // error and fails closed.
        let SigningProof::WalletConnectProof(bytes) = proof else {
            return Err(SigningProviderError::ProofInvalid {
                reason: "walletconnect provider received a non-walletconnect proof".to_string(),
            });
        };
        let payload = decode_walletconnect_proof(bytes)?;

        // Re-derive the pinned scope from the gate's bound chain id. A malformed
        // / unsupported chain id fails closed (ScopeViolation) before any crypto.
        let pinned = PinnedScope::from_chain_id(&context.chain_id)?;

        // The session binding recorded at initiate. Consumed (taken) here so an
        // in-process replay cannot reuse it; the durable one-shot guarantee is
        // the sealed-grant CAS below (and PR10's persistence).
        let binding =
            self.bindings
                .take(&context.gate_ref)
                .ok_or(SigningProviderError::ProofInvalid {
                    reason: "no recorded walletconnect session binding for this gate".to_string(),
                })?;

        // 1. Hash binding (T20): the wallet must have attested to the exact
        //    bound hash. Reject before any signature work.
        if &payload.approved_tx_hash != approved_tx_hash {
            return Err(SigningProviderError::ProofInvalid {
                reason: "proof approved-tx hash does not match the bound hash".to_string(),
            });
        }

        // 2. Session + nonce binding (T18): the proof must belong to the recorded
        //    session and carry the recorded nonce. A proof minted under a
        //    different WC session / relay key, or replayed with a stale/forged
        //    nonce, is rejected here.
        if payload.session_topic != binding.session_topic {
            return Err(SigningProviderError::ProofInvalid {
                reason: "proof session topic does not match the recorded session binding"
                    .to_string(),
            });
        }
        if payload.nonce != binding.nonce {
            return Err(SigningProviderError::ProofInvalid {
                reason: "proof nonce does not match the recorded session binding".to_string(),
            });
        }

        // The recorded binding's pinned scope must match the gate's bound scope
        // (defense in depth against a binding recorded under a different chain).
        if binding.pinned != pinned {
            return Err(SigningProviderError::ScopeViolation {
                reason: "recorded session binding scope does not match the gate's pinned scope"
                    .to_string(),
            });
        }

        // The session-bound account must equal the gate's bound account — the WC
        // session settled on the same account the grant is bound to.
        let bound_account = context.key_or_account_id.as_str();
        if binding.account != bound_account {
            return Err(SigningProviderError::SignerMismatch);
        }

        // 3. Signer binding (T17): verify the signature over the domain-separated
        //    attestation digest (which commits to hash ∥ session topic ∥ nonce)
        //    and require the resolved signer to equal the bound account.
        let digest =
            signer::attestation_digest(approved_tx_hash, &binding.session_topic, &binding.nonce);
        signer::verify_attestation(
            pinned.family,
            &digest,
            &payload.signature,
            payload.public_key.as_deref(),
            bound_account,
        )?;

        // 4. One-shot grant (T20): claim the sealed grant atomically. A replay of
        //    an already-claimed grant fails closed here.
        let key = GrantKey::from_context(context, *approved_tx_hash);
        self.grants.claim(&key).await.map_err(map_grant_error)?;

        // PR10: hand the verified proof back to the gate / runner for the
        // deterministic post-approval continuation (broadcast via
        // ironclaw_chain_signing). PR9 stops at the verified-proof boundary.
        Ok(VerifiedProof::new(proof.clone()))
    }
}

/// Map a [`GrantError`] onto the provider error taxonomy, fail-closed.
fn map_grant_error(err: GrantError) -> SigningProviderError {
    match err {
        GrantError::AlreadyClaimed | GrantError::NotFound | GrantError::AlreadySealed => {
            SigningProviderError::GrantClaimFailed
        }
        GrantError::Backend { reason } => SigningProviderError::Provider { reason },
    }
}

/// Expose the digest + binding constructor for integration tests that mint a
/// wallet signature over the exact bytes the verifier expects.
#[doc(hidden)]
pub fn attestation_digest_for_test(
    approved_tx_hash: &ApprovedTxHash,
    session_topic: &str,
    nonce: &[u8],
) -> [u8; 32] {
    signer::attestation_digest(approved_tx_hash, session_topic, nonce)
}

/// Hex (de)serialization helpers shared by the proof payload fields.
pub(crate) mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(crate) fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex_encode(bytes))
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex_decode(&s).map_err(serde::de::Error::custom)
    }

    pub(crate) fn hex_encode(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0'));
            out.push(char::from_digit((b & 0x0f) as u32, 16).unwrap_or('0'));
        }
        out
    }

    pub(crate) fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        if !s.len().is_multiple_of(2) {
            return Err("odd-length hex".to_string());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
            .collect()
    }
}
