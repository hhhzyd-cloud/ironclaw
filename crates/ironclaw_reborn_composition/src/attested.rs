//! Attested-signing signer-continuation wiring for the reborn runtime.
//!
//! This is the composition seam that turns an `AttestedResolved` turn into a
//! real, ledger-guarded sign + broadcast. It assembles the
//! [`AttestedSignerContinuationDriver`] from the substrate stores (gate
//! bindings shared with the resume port, sealed grants, broadcast ledger) and
//! the external-wallet provider registry.
//!
//! The driver is constructed here rather than buried in the giant
//! `RebornRuntime` struct so the runtime does not have to name the custodial
//! signer's concrete keystore/grant/ledger generic parameters. PR11's web
//! ingress (`/api/chat/gate/resolve`) calls
//! [`RebornAttestedComposition::driver`] to continue a resolved gate.
//!
//! ## Backend selection (PR12)
//!
//! [`RebornAttestedComposition`] is generic over the grant store `G`, ledger
//! `L`, and broadcaster `B`. Local-dev/tests use the in-memory stores and the
//! [`NoopBroadcaster`] (the [`LocalDevAttestedComposition`] alias). Production
//! selects the durable PG / libSQL grant store + ledger from
//! `ironclaw_attested_store` and the real [`MultiChainBroadcaster`]; the
//! ledger-guard behaviour (threats #6 / #7) is identical regardless of backend,
//! because the guard lives in the `SigningLedger` state machine, not the
//! broadcaster. Backend choice mirrors every other reborn store: it follows the
//! configured database backend.

use std::sync::Arc;

use ironclaw_attestation::{
    InMemorySealedGrantStore, InMemorySigningLedger, SealedGrantStore, SigningLedger,
};
use ironclaw_attested_runtime::{
    AttestedGateBindingStore, AttestedSignerContinuationDriver, Broadcaster, ContinuationError,
    InMemoryAttestedGateBindingStore, ProviderRegistry,
};
use ironclaw_chain_signing::{CustodialSigner, DenyFirstCustodyPolicy, SecretsKeyStore, ShipGate};
use ironclaw_signing_provider::SigningContext;

/// The custodial signer type, generic over the grant store and ledger backend.
pub(crate) type ComposedCustodialSigner<G, L> = CustodialSigner<SecretsKeyStore, G, L>;

/// The continuation driver type, generic over broadcaster / ledger / signer.
pub(crate) type ComposedContinuationDriver<B, G, L> =
    AttestedSignerContinuationDriver<B, L, ComposedCustodialSigner<G, L>>;

/// The local-dev / test monomorphization of [`RebornAttestedComposition`] the
/// `RebornRuntime` holds (in-memory stores + no-op broadcaster).
pub(crate) type LocalDevAttestedComposition =
    RebornAttestedComposition<NoopBroadcaster, InMemorySealedGrantStore, InMemorySigningLedger>;

/// A broadcaster that records intent but performs no network I/O. The
/// deterministic-continuation ledger guard (threats #6 / #7) is exercised
/// identically regardless of the broadcaster; the real per-chain broadcaster is
/// `ironclaw_attested_store::MultiChainBroadcaster`, selected in production.
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
/// PR11 ingress: the shared binding store and the assembled continuation driver.
///
/// Generic over the durable-vs-in-memory grant store `G`, ledger `L`, and
/// broadcaster `B`.
pub struct RebornAttestedComposition<B, G, L>
where
    B: Broadcaster + 'static,
    G: SealedGrantStore + 'static,
    L: SigningLedger + 'static,
{
    bindings: Arc<dyn AttestedGateBindingStore>,
    driver: Arc<ComposedContinuationDriver<B, G, L>>,
}

impl<B, G, L> RebornAttestedComposition<B, G, L>
where
    B: Broadcaster + 'static,
    G: SealedGrantStore + 'static,
    L: SigningLedger + 'static,
{
    /// Assemble the composition from the gate-binding store the resume port
    /// already shares, a custodial keystore, the operator ship-gate, the shared
    /// sealed-grant store, the broadcast ledger, the provider registry, and the
    /// broadcaster.
    ///
    /// The grant store is shared so the one-shot CAS (threat #1) is
    /// authoritative across both the custodial signer and the external-wallet
    /// providers. The ledger is shared between the custodial signer and the
    /// driver so the broadcast-idempotency guard covers both paths.
    #[allow(clippy::too_many_arguments)]
    pub fn assemble(
        bindings: Arc<dyn AttestedGateBindingStore>,
        keystore: Arc<SecretsKeyStore>,
        ship_gate: ShipGate,
        grants: Arc<G>,
        ledger: Arc<L>,
        broadcaster: Arc<B>,
        providers: ProviderRegistry,
    ) -> Self {
        let custodial_signer = Arc::new(CustodialSigner::new(
            keystore,
            grants,
            Arc::clone(&ledger),
            ship_gate,
            Arc::new(DenyFirstCustodyPolicy),
        ));
        let driver = Arc::new(AttestedSignerContinuationDriver::new(
            Arc::clone(&bindings),
            providers,
            custodial_signer,
            ledger,
            broadcaster,
        ));
        Self { bindings, driver }
    }

    /// The authoritative gate-binding store. The PR11 ingress persists a
    /// binding here when it raises an attested gate, and the driver reads it
    /// back on continuation.
    pub fn bindings(&self) -> &Arc<dyn AttestedGateBindingStore> {
        &self.bindings
    }

    /// The assembled signer-continuation driver dispatched when a turn reaches
    /// `AttestedResolved`.
    pub fn driver(&self) -> &Arc<ComposedContinuationDriver<B, G, L>> {
        &self.driver
    }
}

impl RebornAttestedComposition<NoopBroadcaster, InMemorySealedGrantStore, InMemorySigningLedger> {
    /// Local-dev / test constructor: in-memory grant store + ledger + no-op
    /// broadcaster. Matches the pre-PR12 behaviour.
    pub fn new_in_memory(
        bindings: Arc<InMemoryAttestedGateBindingStore>,
        keystore: Arc<SecretsKeyStore>,
        ship_gate: ShipGate,
        grants: Arc<InMemorySealedGrantStore>,
        providers: ProviderRegistry,
    ) -> Self {
        let ledger = Arc::new(InMemorySigningLedger::new());
        Self::assemble(
            bindings as Arc<dyn AttestedGateBindingStore>,
            keystore,
            ship_gate,
            grants,
            ledger,
            Arc::new(NoopBroadcaster),
            providers,
        )
    }
}

/// Durable PostgreSQL attested-signing composition: PG sealed-grant store + PG
/// signing ledger + the real per-chain broadcaster. The DB-enforced one-shot
/// CAS / broadcast-idempotency guards hold across process restarts and the
/// `Stuck -> InProgress` recovery race.
#[cfg(all(feature = "postgres", feature = "attested-broadcast"))]
pub type PostgresAttestedComposition = RebornAttestedComposition<
    ironclaw_attested_store::MultiChainBroadcaster,
    ironclaw_attested_store::PostgresSealedGrantStore,
    ironclaw_attested_store::PostgresSigningLedger,
>;

/// Durable libSQL / Turso attested-signing composition.
#[cfg(all(feature = "libsql", feature = "attested-broadcast"))]
pub type LibSqlAttestedComposition = RebornAttestedComposition<
    ironclaw_attested_store::MultiChainBroadcaster,
    ironclaw_attested_store::LibSqlSealedGrantStore,
    ironclaw_attested_store::LibSqlSigningLedger,
>;
