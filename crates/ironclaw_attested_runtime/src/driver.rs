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

    /// Run the deterministic continuation for a gate that has reached
    /// `AttestedResolved`. `proof` is the verified-proof payload carried back
    /// from the ceremony (external-wallet paths) — for the custodial path the
    /// proof is the WebAuthn assertion that authorized the in-house signer.
    ///
    /// Steps, all fail-closed and ledger-guarded:
    /// 1. Read the authoritative binding for `gate_ref` (never trust the
    ///    caller).
    /// 2. Create the ledger row (one-shot per `gate_ref`; an existing row from
    ///    a prior broadcast attempt that is already past `Signed` makes any
    ///    re-broadcast fail — threats #6 / #7).
    /// 3. Route to the bound provider / custodial signer to verify + claim the
    ///    sealed grant (threat #1) and produce the signature.
    /// 4. Advance the ledger to `BroadcastSubmitted` and broadcast.
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
        let binding = self
            .bindings
            .get(gate_ref)
            .await
            .ok_or(ContinuationError::MissingBinding)?;

        // One-shot ledger create. If a row already exists for this gate_ref
        // (e.g. a previous broadcast attempt), `create` fails AlreadyExists and
        // we must NOT proceed to a fresh broadcast — the existing row's state
        // governs (threats #6 / #7). We surface that as a ledger error.
        match self.ledger.create(gate_ref).await {
            Ok(()) => {}
            Err(ironclaw_attestation::LedgerError::AlreadyExists) => {
                // A row exists. If it is already broadcast, refuse re-broadcast
                // fail-closed; otherwise this is a genuine retry we still refuse
                // because the deterministic continuation is one-shot.
                let state = self.ledger.state(gate_ref).await?;
                return Err(ContinuationError::Ledger(
                    ironclaw_attestation::LedgerError::InvalidTransition {
                        from: state,
                        to: SigningLedgerState::Signing,
                    },
                ));
            }
            Err(other) => return Err(other.into()),
        }

        match binding.provider_id {
            ProviderId::Custodial => self.continue_custodial(gate_ref, &binding, evm_tx).await,
            external => {
                self.continue_external_wallet(gate_ref, external, &binding, proof)
                    .await
            }
        }
    }

    /// External-wallet continuation: the wallet already signed natively. We
    /// verify the proof through the bound provider (signer recovery + hash
    /// binding + one-shot sealed-grant CAS), then broadcast the wallet-signed
    /// transaction under the ledger guard.
    async fn continue_external_wallet(
        &self,
        gate_ref: &GateRef,
        provider_id: ProviderId,
        binding: &AttestedGateBinding,
        proof: &SigningProof,
    ) -> Result<SignerContinuationOutcome, ContinuationError> {
        let provider = self
            .providers
            .get(provider_id)
            .ok_or(ContinuationError::ProviderMismatch { bound: provider_id })?;
        debug_assert_eq!(provider.trust_model(), TrustModel::ExternalWallet);

        // Verify + claim the sealed one-shot grant (threat #1 lives inside
        // `verify_resume`). Advance the ledger Signing->Signed only after the
        // proof verifies, so a rejected proof never moves the ledger.
        self.ledger
            .advance(gate_ref, SigningLedgerState::Signing)
            .await?;
        let verified = provider
            .verify_resume(&binding.context, &binding.approved_tx_hash, proof)
            .await
            .map_err(ContinuationError::ProofRejected)?;
        self.ledger
            .advance(gate_ref, SigningLedgerState::Signed)
            .await?;

        // The wallet-signed bytes are the proof payload; broadcast under the
        // ledger guard.
        let signer = binding.context.key_or_account_id.to_string();
        self.broadcast_signed(
            gate_ref,
            &binding.context,
            verified.proof().payload(),
            signer,
        )
        .await
    }

    /// Custodial continuation: IronClaw holds the key. Delegate to the
    /// [`CustodialSigner`], which runs the ship-gate, claims the sealed grant
    /// (threat #1), re-checks the approved hash (threat #3), and signs with the
    /// ecrecover binding check (threat #5). The signer advances the ledger
    /// Signing->Signed itself; here we broadcast and advance to
    /// BroadcastSubmitted.
    async fn continue_custodial<EvmTx>(
        &self,
        gate_ref: &GateRef,
        binding: &AttestedGateBinding,
        evm_tx: Option<&EvmTx>,
    ) -> Result<SignerContinuationOutcome, ContinuationError>
    where
        EvmTx: alloy_consensus::SignableTransaction<alloy_primitives::Signature>,
        S: CustodialSignerLike<EvmTx>,
    {
        // Pre-flight enforcement point #2 mirror (threat #3): re-check the hash
        // from the persisted decoded tx before doing anything chain-side, so a
        // mutated binding fails closed with a precise error.
        let recomputed = recompute_approved_hash(&binding.decoded, binding.schema_version);
        if recomputed != binding.approved_tx_hash {
            return Err(ContinuationError::ApprovedHashMismatch);
        }

        let evm_tx = evm_tx.ok_or(ContinuationError::ChainSigning(ChainSigningError::Sign {
            chain: "evm",
            reason: "custodial continuation requires the signable transaction".to_string(),
        }))?;

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

        self.broadcast_signed(
            gate_ref,
            &binding.context,
            &outcome.signature,
            outcome.signer,
        )
        .await
    }

    /// Shared broadcast tail: advance the ledger to `BroadcastSubmitted`, then
    /// submit. The ledger advance happens BEFORE the network submit so a
    /// `Stuck->InProgress` recovery that re-enters here sees the row already at
    /// `BroadcastSubmitted` and the guard refuses a second signing (threat #7).
    async fn broadcast_signed(
        &self,
        gate_ref: &GateRef,
        context: &SigningContext,
        signed: &[u8],
        signer: String,
    ) -> Result<SignerContinuationOutcome, ContinuationError> {
        self.ledger
            .advance(gate_ref, SigningLedgerState::BroadcastSubmitted)
            .await?;
        self.broadcaster.broadcast(context, signed).await?;
        Ok(SignerContinuationOutcome {
            gate_ref: gate_ref.clone(),
            ledger_state: SigningLedgerState::BroadcastSubmitted,
            signer,
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
