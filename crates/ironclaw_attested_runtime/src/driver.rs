//! The signer-continuation driver: the deterministic post-approval continuation
//! that runs once the turn store transitions `BlockedAttested ->
//! AttestedResolved`.
//!
//! This consumes the `// PR10:` handoff stubs left in PR7-PR9:
//!
//! * `crates/ironclaw_wallet_external/src/walletconnect/mod.rs` ("hand the
//!   verified proof back to the gate / runner for the continuation") — the
//!   driver routes a `WalletConnect` / `Injected` / `NearRedirect` resolved gate
//!   to the matching [`SigningProvider::verify_resume`], turning the verified
//!   proof into a ledger-guarded broadcast.
//! * `src/channels/web/features/chat/attested.rs` ("build `ResumeTurnRequest {
//!   attestation: Some(..) }` + dispatch the broadcast through the gate-resolve
//!   path") — the broadcast half of that handoff lives here; the web ingress
//!   that calls into it is PR11.
//!
//! ## Invariants enforced here
//!
//! * **Threat #1 (sealed-grant replay):** the authoritative one-shot grant is
//!   claimed (atomic CAS) before any signing. The custodial path claims it
//!   inside [`CustodialSigner`]; the external-wallet path claims it inside the
//!   provider's `verify_resume`.
//! * **Threats #6 / #7 (broadcast retry / `Stuck->InProgress` double-broadcast):**
//!   every state move goes through the [`SigningLedger`], which refuses to
//!   re-enter signing for a `gate_ref` already past `BroadcastSubmitted` — and
//!   is keyed on ledger state, not job state, so a job recovery cannot
//!   re-broadcast.
//! * **Threat #16 (LLM-loop reinterpretation):** the driver is only reachable
//!   from the `AttestedResolved` continuation; it validates + signs + broadcasts
//!   and NEVER requeues the agent loop.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;

use ironclaw_attestation::{SigningLedger, SigningLedgerState};
use ironclaw_chain_signing::{
    ChainSigningError, CustodialSignRequest, CustodialSigner, recompute_approved_hash,
};
use ironclaw_signing_provider::{
    GateRef, ProviderId, SigningContext, SigningProof, SigningProvider, SigningProviderError,
    TrustModel,
};

use crate::binding::{AttestedGateBinding, AttestedGateBindingStore};

/// Registry mapping a [`ProviderId`] to the external-wallet
/// [`SigningProvider`] that verifies its proofs.
///
/// The custodial path is NOT in this registry — it is the
/// [`CustodialSigner`], which both claims the grant and signs, and is wired
/// separately into the driver.
#[derive(Default)]
pub struct ProviderRegistry {
    providers: HashMap<ProviderId, Arc<dyn SigningProvider>>,
}

impl ProviderRegistry {
    /// Construct an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an external-wallet provider under its own [`ProviderId`].
    pub fn with_provider(mut self, provider: Arc<dyn SigningProvider>) -> Self {
        self.providers.insert(provider.provider_id(), provider);
        self
    }

    fn get(&self, id: ProviderId) -> Option<&Arc<dyn SigningProvider>> {
        self.providers.get(&id)
    }
}

/// What the continuation produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerContinuationOutcome {
    /// The `gate_ref` that was continued.
    pub gate_ref: GateRef,
    /// The ledger state reached (always `BroadcastSubmitted` on success of the
    /// broadcast step; the driver leaves finalization to the chain watcher).
    pub ledger_state: SigningLedgerState,
    /// The signer/account the broadcast was attributed to (public).
    pub signer: String,
}

/// The result of the verify+claim+sign half of the continuation, produced by
/// [`AttestedSignerContinuationDriver::verify_and_sign`] BEFORE the turn store
/// transitions `BlockedAttested -> AttestedResolved`.
///
/// Holding this value is evidence that:
///
/// * the authoritative binding was read,
/// * the one-shot ledger row was created and advanced through `Signing ->
///   Signed`,
/// * the sealed grant was claimed exactly once (threat #1 — inside the
///   provider's `verify_resume` for the external-wallet path, or inside the
///   [`CustodialSigner`] for the custodial path),
/// * and the signed bytes ready to broadcast were produced.
///
/// [`AttestedSignerContinuationDriver::broadcast_signed_continuation`] consumes
/// it to advance the ledger to `BroadcastSubmitted` and submit. The signed
/// bytes never re-trigger verification or a second grant claim: the heavyweight
/// crypto runs exactly once, here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedContinuation {
    gate_ref: GateRef,
    context: SigningContext,
    signed: Vec<u8>,
    signer: String,
}

impl VerifiedContinuation {
    /// The gate this verified continuation belongs to.
    pub fn gate_ref(&self) -> &GateRef {
        &self.gate_ref
    }

    /// The signer/account the eventual broadcast is attributed to (public).
    pub fn signer(&self) -> &str {
        &self.signer
    }
}

/// Errors the signer-continuation driver can surface. Every variant is
/// fail-closed: the ledger is never advanced past where the failure occurred.
#[derive(Debug)]
pub enum ContinuationError {
    /// No authoritative binding exists for the resolved `gate_ref`.
    MissingBinding,
    /// The carried proof's provider does not match the bound provider, or no
    /// provider is registered for it.
    ProviderMismatch {
        /// The bound provider id.
        bound: ProviderId,
    },
    /// The external-wallet provider rejected the proof (signer mismatch, hash
    /// mismatch, grant-claim failure, scope violation).
    ProofRejected(SigningProviderError),
    /// The custodial chain signer rejected or failed the signing.
    ChainSigning(ChainSigningError),
    /// A ledger transition was rejected (e.g. broadcast idempotency guard).
    Ledger(ironclaw_attestation::LedgerError),
    /// The sign-time approved-tx-hash re-check failed (threat #3): the hash
    /// recomputed from the persisted decoded tx diverged from the bound hash.
    ApprovedHashMismatch,
    /// A broadcaster-side failure.
    Broadcast {
        /// Opaque description (never key material).
        reason: String,
    },
}

impl std::fmt::Display for ContinuationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingBinding => write!(f, "no authoritative binding for the resolved gate"),
            Self::ProviderMismatch { bound } => {
                write!(f, "provider mismatch: bound provider is {bound:?}")
            }
            Self::ProofRejected(e) => write!(f, "external-wallet proof rejected: {e}"),
            Self::ChainSigning(e) => write!(f, "custodial chain signing failed: {e}"),
            Self::Ledger(e) => write!(f, "signing-ledger transition rejected: {e}"),
            Self::ApprovedHashMismatch => {
                write!(f, "sign-time approved-tx-hash re-check failed")
            }
            Self::Broadcast { reason } => write!(f, "broadcast failed: {reason}"),
        }
    }
}

impl std::error::Error for ContinuationError {}

impl From<ironclaw_attestation::LedgerError> for ContinuationError {
    fn from(value: ironclaw_attestation::LedgerError) -> Self {
        Self::Ledger(value)
    }
}

/// Broadcasts a signed transaction to its chain. Injected so the driver stays
/// testable without real network I/O. PR12 / production wires a real
/// per-chain broadcaster; the ledger guard around it is identical regardless.
#[async_trait]
pub trait Broadcaster: Send + Sync {
    /// Submit the signed transaction for `context`'s chain. Returns the opaque
    /// transaction id / hash on success.
    async fn broadcast(
        &self,
        context: &SigningContext,
        signed: &[u8],
    ) -> Result<String, ContinuationError>;
}

/// The signer-continuation driver, wired with the authoritative binding store,
/// the external-wallet provider registry, the custodial signer, the broadcast
/// idempotency ledger, and a broadcaster.
///
/// `K`/`G`/`L` are the custodial signer's keystore / grant store / ledger
/// types; the same ledger `L` is shared so the broadcast-idempotency guard
/// covers both the custodial and external-wallet paths.
pub struct AttestedSignerContinuationDriver<B, L, S> {
    bindings: Arc<dyn AttestedGateBindingStore>,
    providers: ProviderRegistry,
    custodial_signer: Arc<S>,
    ledger: Arc<L>,
    broadcaster: Arc<B>,
}

impl<B, L, S> AttestedSignerContinuationDriver<B, L, S>
where
    B: Broadcaster,
    L: SigningLedger,
{
    /// Construct the driver.
    pub fn new(
        bindings: Arc<dyn AttestedGateBindingStore>,
        providers: ProviderRegistry,
        custodial_signer: Arc<S>,
        ledger: Arc<L>,
        broadcaster: Arc<B>,
    ) -> Self {
        Self {
            bindings,
            providers,
            custodial_signer,
            ledger,
            broadcaster,
        }
    }

    /// Run the deterministic continuation for a gate, end to end: verify +
    /// claim + sign, then broadcast.
    ///
    /// This is the legacy single-shot entrypoint, retained for the threat-matrix
    /// tests and any caller that drives both halves under one lock. The
    /// verify-before-resume facade (PR11 item B) instead calls
    /// [`Self::verify_and_sign`] BEFORE the turn transitions and
    /// [`Self::broadcast_signed_continuation`] AFTER, so the heavyweight
    /// verification + grant claim gate the `BlockedAttested -> AttestedResolved`
    /// transition. The crypto still runs exactly once in either arrangement.
    pub async fn continue_after_resolved<EvmTx>(
        &self,
        gate_ref: &GateRef,
        proof: &SigningProof,
        evm_tx: Option<&EvmTx>,
    ) -> Result<SignerContinuationOutcome, ContinuationError>
    where
        EvmTx: alloy_consensus::SignableTransaction<alloy_primitives::Signature>,
        S: CustodialSignerLike<EvmTx>,
    {
        let verified = self.verify_and_sign(gate_ref, proof, evm_tx).await?;
        self.broadcast_signed_continuation(verified).await
    }

    /// Verify + claim + sign half of the continuation. Runs BEFORE the turn
    /// transitions to `AttestedResolved`, so the FULL cryptographic verification
    /// and the one-shot grant claim gate the transition: a malformed or forged
    /// proof is rejected here, with no broadcast and no `AttestedResolved`
    /// transition (the facade only calls `resume_turn` after this returns `Ok`).
    ///
    /// 1. Read the authoritative binding for `gate_ref` (never trust the
    ///    caller).
    /// 2. Route to the bound provider / custodial signer to verify + claim the
    ///    sealed grant (threat #1) and produce the signature, under the
    ///    broadcast-idempotency ledger guard (threats #6 / #7).
    ///
    /// Fail-closed retry semantics: each path creates / advances the ledger only
    /// once verification is committed to, so a proof that fails verification
    /// (malformed, forged, signer/hash mismatch) leaves NO blocking ledger row
    /// and does NOT claim the grant — a follow-up VALID proof for the same gate
    /// can still succeed. After a SUCCESSFUL verify+claim, the grant CAS and the
    /// ledger row are both consumed, so a same-key retry fails closed (the
    /// continuation is genuinely single-drive).
    ///
    /// The returned [`VerifiedContinuation`] is the only way to reach
    /// [`Self::broadcast_signed_continuation`]; the broadcast half NEVER
    /// re-verifies or re-claims.
    pub async fn verify_and_sign<EvmTx>(
        &self,
        gate_ref: &GateRef,
        proof: &SigningProof,
        evm_tx: Option<&EvmTx>,
    ) -> Result<VerifiedContinuation, ContinuationError>
    where
        EvmTx: alloy_consensus::SignableTransaction<alloy_primitives::Signature>,
        S: CustodialSignerLike<EvmTx>,
    {
        let binding = self
            .bindings
            .get(gate_ref)
            .await
            .ok_or(ContinuationError::MissingBinding)?;

        match binding.provider_id {
            ProviderId::Custodial => self.sign_custodial(gate_ref, &binding, evm_tx).await,
            external => {
                self.verify_external_wallet(gate_ref, external, &binding, proof)
                    .await
            }
        }
    }

    /// One-shot broadcast-idempotency ledger create (threats #6 / #7): an
    /// existing row for this `gate_ref` (a prior attempt) makes any re-entry fail
    /// closed. Surfaced as an invalid-transition ledger error carrying the
    /// existing state.
    async fn create_ledger_row(&self, gate_ref: &GateRef) -> Result<(), ContinuationError> {
        match self.ledger.create(gate_ref).await {
            Ok(()) => Ok(()),
            Err(ironclaw_attestation::LedgerError::AlreadyExists) => {
                let state = self.ledger.state(gate_ref).await?;
                Err(ContinuationError::Ledger(
                    ironclaw_attestation::LedgerError::InvalidTransition {
                        from: state,
                        to: SigningLedgerState::Signing,
                    },
                ))
            }
            Err(other) => Err(other.into()),
        }
    }

    /// Broadcast half of the continuation. Consumes a [`VerifiedContinuation`]
    /// (proof already verified + grant already claimed in
    /// [`Self::verify_and_sign`]) and broadcasts the signed bytes under the
    /// ledger guard. This NEVER calls `verify_resume` and NEVER re-claims the
    /// grant.
    ///
    /// NOTE: item C (broadcast-failure recovery) layers its retry handling on
    /// top of this method on the PR10 branch; the sign-only refactor here keeps
    /// the broadcast tail untouched so the two reconcile at integration.
    pub async fn broadcast_signed_continuation(
        &self,
        verified: VerifiedContinuation,
    ) -> Result<SignerContinuationOutcome, ContinuationError> {
        let VerifiedContinuation {
            gate_ref,
            context,
            signed,
            signer,
        } = verified;
        // Advance the ledger to `BroadcastSubmitted` BEFORE the network submit so
        // a `Stuck->InProgress` recovery that re-enters sees the row already at
        // `BroadcastSubmitted` and the guard refuses a second signing (threat
        // #7).
        self.ledger
            .advance(&gate_ref, SigningLedgerState::BroadcastSubmitted)
            .await?;
        self.broadcaster.broadcast(&context, &signed).await?;
        Ok(SignerContinuationOutcome {
            gate_ref,
            ledger_state: SigningLedgerState::BroadcastSubmitted,
            signer,
        })
    }

    /// External-wallet verify + claim: the wallet already signed natively. We
    /// verify the proof through the bound provider (signer recovery + hash
    /// binding + one-shot sealed-grant CAS) FIRST, so a rejected proof
    /// (malformed, forged, signer/hash mismatch) never touches the ledger and
    /// never claims the grant — leaving the gate cleanly retryable. Only after
    /// the proof verifies + the grant is claimed do we create the
    /// broadcast-idempotency ledger row and advance it `Approved -> Signing ->
    /// Signed`. The wallet-signed bytes (the proof payload) become the
    /// [`VerifiedContinuation`] to broadcast.
    async fn verify_external_wallet(
        &self,
        gate_ref: &GateRef,
        provider_id: ProviderId,
        binding: &AttestedGateBinding,
        proof: &SigningProof,
    ) -> Result<VerifiedContinuation, ContinuationError> {
        let provider = self
            .providers
            .get(provider_id)
            .ok_or(ContinuationError::ProviderMismatch { bound: provider_id })?;
        debug_assert_eq!(provider.trust_model(), TrustModel::ExternalWallet);

        // Verify + claim the one-shot sealed grant (threats #1/#3/#5 all live
        // inside `verify_resume`). This is the gate: a rejected proof returns
        // here with no ledger row created and the grant unclaimed.
        let verified = provider
            .verify_resume(&binding.context, &binding.approved_tx_hash, proof)
            .await
            .map_err(ContinuationError::ProofRejected)?;

        // Proof verified + grant claimed. Now open the broadcast-idempotency
        // ledger row and advance it to `Signed`. The grant CAS already made this
        // single-drive; the ledger guards broadcast retry (threats #6/#7).
        self.create_ledger_row(gate_ref).await?;
        self.ledger
            .advance(gate_ref, SigningLedgerState::Signing)
            .await?;
        self.ledger
            .advance(gate_ref, SigningLedgerState::Signed)
            .await?;

        let signer = binding.context.key_or_account_id.to_string();
        Ok(VerifiedContinuation {
            gate_ref: gate_ref.clone(),
            context: binding.context.clone(),
            signed: verified.proof().payload().to_vec(),
            signer,
        })
    }

    /// Custodial verify + sign: IronClaw holds the key. Delegate to the
    /// [`CustodialSigner`], which runs the ship-gate, claims the sealed grant
    /// (threat #1), re-checks the approved hash (threat #3), and signs with the
    /// ecrecover binding check (threat #5). The signer advances the ledger
    /// `Approved -> Signing -> Signed` itself; the produced signature becomes the
    /// [`VerifiedContinuation`] to broadcast.
    async fn sign_custodial<EvmTx>(
        &self,
        gate_ref: &GateRef,
        binding: &AttestedGateBinding,
        evm_tx: Option<&EvmTx>,
    ) -> Result<VerifiedContinuation, ContinuationError>
    where
        EvmTx: alloy_consensus::SignableTransaction<alloy_primitives::Signature>,
        S: CustodialSignerLike<EvmTx>,
    {
        // Pre-flight enforcement point #2 mirror (threat #3): re-check the hash
        // from the persisted decoded tx before doing anything chain-side, so a
        // mutated binding fails closed with a precise error — before any ledger
        // row is created.
        let recomputed = recompute_approved_hash(&binding.decoded, binding.schema_version);
        if recomputed != binding.approved_tx_hash {
            return Err(ContinuationError::ApprovedHashMismatch);
        }

        let evm_tx = evm_tx.ok_or(ContinuationError::ChainSigning(ChainSigningError::Sign {
            chain: "evm",
            reason: "custodial continuation requires the signable transaction".to_string(),
        }))?;

        // Open the broadcast-idempotency ledger row (threats #6/#7). The
        // custodial signer advances it `Approved -> Signing -> Signed` itself.
        self.create_ledger_row(gate_ref).await?;

        let req = CustodialSignRequest {
            context: binding.context.clone(),
            scope: binding.scope.clone(),
            chain: binding.chain.clone(),
            decoded: binding.decoded.clone(),
            approved_tx_hash: binding.approved_tx_hash,
            schema_version: binding.schema_version,
        };

        let outcome = self
            .custodial_signer
            .sign_evm(&req, evm_tx)
            .await
            .map_err(ContinuationError::ChainSigning)?;

        Ok(VerifiedContinuation {
            gate_ref: gate_ref.clone(),
            context: binding.context.clone(),
            signed: outcome.signature,
            signer: outcome.signer,
        })
    }
}

/// Abstracts the custodial signer's `sign_evm` so the driver is generic over
/// the concrete [`CustodialSigner`] type parameters without naming all three.
#[async_trait]
pub trait CustodialSignerLike<EvmTx>: Send + Sync
where
    EvmTx: alloy_consensus::SignableTransaction<alloy_primitives::Signature>,
{
    /// Sign the EVM transaction for the request, running both enforcement
    /// points and the ecrecover binding check.
    async fn sign_evm(
        &self,
        req: &CustodialSignRequest,
        tx: &EvmTx,
    ) -> Result<ironclaw_chain_signing::CustodialSignOutcome, ChainSigningError>;
}

#[async_trait]
impl<K, G, L, EvmTx> CustodialSignerLike<EvmTx> for CustodialSigner<K, G, L>
where
    K: ironclaw_chain_signing::KeyStore,
    G: ironclaw_attestation::SealedGrantStore,
    L: SigningLedger,
    EvmTx: alloy_consensus::SignableTransaction<alloy_primitives::Signature> + Sync,
{
    async fn sign_evm(
        &self,
        req: &CustodialSignRequest,
        tx: &EvmTx,
    ) -> Result<ironclaw_chain_signing::CustodialSignOutcome, ChainSigningError> {
        CustodialSigner::sign_evm(self, req, tx).await
    }
}
