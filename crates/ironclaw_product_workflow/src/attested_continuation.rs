//! Crypto-free attested-signing continuation port for the WebUI facade
//! (attested-signing PR11).
//!
//! `ironclaw_product_workflow` is a product-facing facade crate that must stay
//! crypto-free: it never names a chain SDK, a signing provider, a sealed grant,
//! or a broadcast ledger. But the WebUI `resolve_gate` path needs to drive the
//! deterministic sign + broadcast continuation once a `BlockedAttested` gate has
//! been resolved to `AttestedResolved`.
//!
//! The bridge is this injected port. The facade:
//!
//! 1. Translates the browser-supplied attested-proof resolution into an opaque
//!    [`AttestedProofClaim`] (all fields are strings / JSON — no crypto types).
//! 2. Builds a `ResumeTurnRequest { attestation: Some(..) }` whose
//!    [`ironclaw_turns::AttestationClaimRef`] is the proof's bound-hash claim,
//!    and calls `resume_turn`. The injected `AttestedResumePort` (wired in the
//!    composition layer, outside `src/`) runs the synchronous binding re-check +
//!    one-shot resume guard and transitions the turn to `AttestedResolved`.
//! 3. Calls [`AttestedGateContinuationPort::continue_resolved_gate`] to run the
//!    heavyweight verification + sign + broadcast through the composition's
//!    signer-continuation driver.
//!
//! The production implementation lives in `ironclaw_reborn_composition` over
//! `ironclaw_attested_runtime`'s driver; this crate declares only the
//! crypto-free contract and the opaque DTOs. Mirrors how the turn store already
//! takes an injected `AttestedResumePort`.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use ironclaw_turns::{GateRef, TurnRunId, TurnScope};

/// The proof family carried on an attested gate resolution. Mirrors the legacy
/// monolith `GateResolutionPayload` variants for wire compatibility; the
/// composition-layer port maps each kind onto the matching
/// `ironclaw_signing_provider::SigningProof` it knows how to verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestedProofKind {
    /// Browser injected wallet (`window.ethereum` / `window.solana`).
    InjectedWallet,
    /// NEAR wallet redirect callback proof.
    NearRedirect,
    /// WalletConnect v2 session proof.
    WalletConnect,
}

impl AttestedProofKind {
    /// Sanitized, snake_case category for diagnostics and error mapping.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InjectedWallet => "injected_wallet",
            Self::NearRedirect => "near_redirect",
            Self::WalletConnect => "wallet_connect",
        }
    }
}

/// The opaque attested-proof claim the facade forwards to the continuation port.
///
/// Every field is a string or JSON value: this crate confers no trust and holds
/// no crypto type. The composition-layer port re-decodes `proof_json` into the
/// concrete provider proof and verifies it against the authoritative gate
/// binding (which it persisted when the gate was raised — never trusting these
/// caller-supplied fields to *define* the binding, only to attest to it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedProofClaim {
    /// Which proof family this claim belongs to.
    pub kind: AttestedProofKind,
    /// Lowercase-hex of the approved-tx hash the wallet attests to. This becomes
    /// the `AttestationClaimRef` on the resume request, so the synchronous
    /// resume-port binding re-check can reject a claim that does not even name
    /// the bound hash before any async verification runs.
    pub approved_tx_hash_hex: String,
    /// The opaque, provider-specific proof payload (signature, signer, scheme,
    /// public key, scope, state echo, …). Re-decoded by the port; never
    /// interpreted here.
    pub proof_json: serde_json::Value,
}

/// Sanitized outcome of a continuation. Carries no chain, signer, or ledger
/// internals beyond the public broadcast attribution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedContinuationOutcome {
    /// Public signer/account the broadcast was attributed to.
    pub signer: String,
}

/// Sanitized rejection taxonomy for an attested continuation. Mirrors the
/// crypto-free spirit of [`ironclaw_turns::AttestedResumeRejection`]: categories
/// only, no ceremony detail.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AttestedContinuationRejection {
    /// No authoritative binding exists for the resolved gate (it was never
    /// raised, or the binding store lost it).
    MissingBinding,
    /// The proof family or its provider did not match the bound provider.
    ProviderMismatch,
    /// The provider rejected the proof (signer/hash mismatch, grant-claim
    /// failure, scope violation), or the custodial signer failed.
    ProofRejected,
    /// A broadcast-idempotency / ledger guard refused the transition (e.g. the
    /// gate was already broadcast).
    LedgerGuard,
    /// The proof payload was malformed and could not be decoded.
    MalformedProof,
    /// The continuation port is not wired on this deployment.
    Unavailable,
}

impl AttestedContinuationRejection {
    /// Sanitized, snake_case category for diagnostics and error mapping.
    pub fn category(&self) -> &'static str {
        match self {
            Self::MissingBinding => "attested_missing_binding",
            Self::ProviderMismatch => "attested_provider_mismatch",
            Self::ProofRejected => "attested_proof_rejected",
            Self::LedgerGuard => "attested_ledger_guard",
            Self::MalformedProof => "attested_malformed_proof",
            Self::Unavailable => "attested_unavailable",
        }
    }
}

/// Injected, crypto-free continuation port for attested-signing gate resolution.
///
/// Implementations live outside this crate (composition / reborn layer). The
/// facade calls [`Self::continue_resolved_gate`] exactly once per attested
/// resolution, *after* `resume_turn` has driven the turn to `AttestedResolved`
/// (i.e. after the synchronous resume-port binding re-check + one-shot guard
/// already passed). The implementation runs the heavyweight provider
/// verification, the sealed-grant CAS, and the ledger-guarded sign + broadcast.
#[async_trait]
pub trait AttestedGateContinuationPort: Send + Sync {
    /// Drive the deterministic sign + broadcast continuation for the resolved
    /// gate. `scope`/`run_id` identify the run; `gate_ref` selects the
    /// authoritative binding; `claim` carries the opaque verified-proof payload.
    async fn continue_resolved_gate(
        &self,
        scope: &TurnScope,
        run_id: TurnRunId,
        gate_ref: &GateRef,
        claim: &AttestedProofClaim,
    ) -> Result<AttestedContinuationOutcome, AttestedContinuationRejection>;
}
