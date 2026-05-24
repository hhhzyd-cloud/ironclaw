//! Attested-signing signer-continuation wiring for the reborn runtime (PR10).
//!
//! This is the composition seam that turns an `AttestedResolved` turn into a
//! real, ledger-guarded sign + broadcast. It assembles the
//! [`AttestedSignerContinuationDriver`] from the in-memory substrate stores
//! (gate bindings shared with the resume port, sealed grants, broadcast ledger)
//! and the external-wallet provider registry.
//!
//! The driver is constructed here rather than buried in the giant
//! `RebornRuntime` struct so the runtime does not have to name the custodial
//! signer's concrete keystore/grant/ledger generic parameters. PR11's web
//! ingress (`/api/chat/gate/resolve`) calls
//! [`RebornAttestedComposition::driver`] to continue a resolved gate; this
//! module owns the deny-first default policy and the in-memory stores (durable
//! backends are PR12).
//!
//! Why in-memory only: the prompt for this slice mandates the existing
//! in-memory stores and explicitly defers durable PG/libSQL backends to PR12,
//! so no single-backend persistence feature is introduced here (dual-backend
//! rule).

use std::sync::Arc;

use ironclaw_attestation::{
    AttestedSigningGrant, GrantKey, InMemorySealedGrantStore, InMemorySigningLedger,
    SealedGrantStore,
};
use ironclaw_attested_runtime::{
    AttestedGateBinding, AttestedGateBindingStore, AttestedSignerContinuationDriver, Broadcaster,
    ContinuationError, InMemoryAttestedGateBindingStore, ProviderRegistry,
};
use ironclaw_chain_signing::{CustodialSigner, DenyFirstCustodyPolicy, SecretsKeyStore, ShipGate};
use ironclaw_signing_provider::{GateRef, SigningContext};

/// Error from [`RebornAttestedComposition::register_attested_gate`]. Distinct
/// from [`ironclaw_attestation::GrantError`] so the gate-raise caller can tell
/// a hardening rejection (mismatched gate_ref / duplicate raise) apart from a
/// grant-store backend failure.
#[derive(Debug)]
pub enum RegisterAttestedGateError {
    /// The supplied `gate_ref` did not equal `binding.context.gate_ref`.
    GateRefMismatch,
    /// A binding (or sealed grant) already exists for this gate: registration is
    /// insert-only and the first raise wins.
    DuplicateBinding,
    /// The underlying sealed-grant store failed.
    Grant(ironclaw_attestation::GrantError),
}

impl std::fmt::Display for RegisterAttestedGateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GateRefMismatch => {
                write!(f, "gate_ref does not match binding.context.gate_ref")
            }
            Self::DuplicateBinding => {
                write!(f, "attested gate already registered (insert-only)")
            }
            Self::Grant(e) => write!(f, "sealed-grant store failed: {e}"),
        }
    }
}

impl std::error::Error for RegisterAttestedGateError {}

/// The concrete custodial signer type the local-dev composition assembles. Its
/// generic parameters are pinned here so the rest of the runtime never names
/// them.
pub(crate) type LocalDevCustodialSigner =
    CustodialSigner<SecretsKeyStore, InMemorySealedGrantStore, InMemorySigningLedger>;

/// The concrete driver type the local-dev composition assembles.
pub(crate) type LocalDevContinuationDriver = AttestedSignerContinuationDriver<
    NoopBroadcaster,
    InMemorySigningLedger,
    LocalDevCustodialSigner,
>;

/// A broadcaster that records intent but performs no network I/O. The
/// deterministic-continuation ledger guard (threats #6 / #7) is exercised
/// identically regardless of the broadcaster; the real per-chain broadcaster is
/// a PR12 / production concern.
#[derive(Debug, Default)]
pub struct NoopBroadcaster;

#[async_trait::async_trait]
impl Broadcaster for NoopBroadcaster {
    async fn broadcast(
        &self,
        _context: &SigningContext,
        _signed: &[u8],
    ) -> Result<String, ContinuationError> {
        // No network submit; the ledger advance around this call is what the
        // idempotency guard protects. Returns a deterministic placeholder id.
        Ok("noop-broadcast".to_string())
    }
}

/// Bundles the attested-signing composition the reborn runtime exposes to the
/// PR11 ingress: the shared binding store and the assembled continuation
/// driver.
pub struct RebornAttestedComposition {
    bindings: Arc<InMemoryAttestedGateBindingStore>,
    grants: Arc<InMemorySealedGrantStore>,
    driver: Arc<LocalDevContinuationDriver>,
}

impl RebornAttestedComposition {
    /// Assemble the composition for local-dev from the gate-binding store the
    /// resume port already shares, a custodial keystore, the operator
    /// ship-gate, and the shared sealed-grant store. The grant store is shared
    /// so the one-shot CAS (threat #1) is authoritative across both the
    /// custodial signer and the external-wallet providers (which the PR11
    /// ingress registers into `providers` over the same store). The broadcast
    /// ledger is a fresh in-memory instance shared between the custodial signer
    /// and the driver.
    pub fn new(
        bindings: Arc<InMemoryAttestedGateBindingStore>,
        keystore: Arc<SecretsKeyStore>,
        ship_gate: ShipGate,
        grants: Arc<InMemorySealedGrantStore>,
        providers: ProviderRegistry,
    ) -> Self {
        let ledger = Arc::new(InMemorySigningLedger::new());
        let custodial_signer = Arc::new(CustodialSigner::new(
            keystore,
            Arc::clone(&grants),
            Arc::clone(&ledger),
            ship_gate,
            Arc::new(DenyFirstCustodyPolicy),
        ));
        let driver = Arc::new(AttestedSignerContinuationDriver::new(
            Arc::clone(&bindings) as Arc<dyn AttestedGateBindingStore>,
            providers,
            custodial_signer,
            Arc::clone(&ledger),
            Arc::new(NoopBroadcaster),
        ));
        Self {
            bindings,
            grants,
            driver,
        }
    }

    /// Persist the authoritative state when a `BlockedAttested` gate is raised
    /// (attested-signing PR11 raise side).
    ///
    /// Records the authoritative [`AttestedGateBinding`] (gate_ref ∥ expected
    /// `ApprovedTxHash` ∥ bound signer/account ∥ chain/tx-type) the resume port
    /// and driver both read back, and seals the one-shot sealed grant the
    /// external-wallet provider / custodial signer claims (threat #1). The
    /// caller's later resume can only *attest* to this binding's hash — never
    /// redefine it (threats #2 / #3 / #4).
    ///
    /// In-memory only (PR11); durable PG / libSQL backends are PR12.
    ///
    /// Hardening invariants enforced here:
    /// - The supplied `gate_ref` MUST equal `binding.context.gate_ref`. A
    ///   mismatch would let the binding be filed under a key that names a
    ///   different gate than the one the authoritative context describes — the
    ///   resume port and driver both look the binding up by `gate_ref`, so a
    ///   mismatch is a binding-confusion vector. Fail closed.
    /// - Registration is INSERT-ONLY: an existing binding for the same gate
    ///   (request id) is never overwritten. The first raise wins; a second raise
    ///   for the same gate is refused so an attacker cannot redefine the
    ///   authoritative `(hash, signer, decoded tx)` after the fact (threats
    ///   #2/#3/#4). The grant seal is likewise one-shot.
    pub async fn register_attested_gate(
        &self,
        gate_ref: GateRef,
        binding: AttestedGateBinding,
        created_at_ms: i64,
        expiry_ms: Option<i64>,
    ) -> Result<(), RegisterAttestedGateError> {
        // gate_ref must match the authoritative context's gate_ref.
        if binding.context.gate_ref.as_str() != gate_ref.as_str() {
            return Err(RegisterAttestedGateError::GateRefMismatch);
        }

        // Insert-only: refuse to overwrite an existing binding for this gate.
        if self.bindings.get(&gate_ref).await.is_some() {
            return Err(RegisterAttestedGateError::DuplicateBinding);
        }

        // Seal the one-shot grant first. A duplicate seal (AlreadySealed) means
        // the gate was already raised; surface it as a duplicate rather than
        // proceeding to (re)write the binding.
        let grant_key = GrantKey::from_context(&binding.context, binding.approved_tx_hash);
        match self
            .grants
            .seal(AttestedSigningGrant::seal(
                grant_key,
                created_at_ms,
                expiry_ms,
            ))
            .await
        {
            Ok(()) => {}
            Err(ironclaw_attestation::GrantError::AlreadySealed) => {
                return Err(RegisterAttestedGateError::DuplicateBinding);
            }
            Err(other) => return Err(RegisterAttestedGateError::Grant(other)),
        }
        self.bindings.put(gate_ref, binding).await;
        Ok(())
    }

    /// The authoritative gate-binding store. The PR11 ingress persists a
    /// binding here when it raises an attested gate, and the driver reads it
    /// back on continuation.
    pub fn bindings(&self) -> &Arc<InMemoryAttestedGateBindingStore> {
        &self.bindings
    }

    /// The assembled signer-continuation driver dispatched when a turn reaches
    /// `AttestedResolved`.
    pub fn driver(&self) -> &Arc<LocalDevContinuationDriver> {
        &self.driver
    }
}
