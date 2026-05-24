//! The authoritative attested-gate binding the resume path verifies against.
//!
//! When a `BlockedAttested` gate is raised, the composition layer persists the
//! authoritative `(SigningContext, ApprovedTxHash, ProviderId, decoded tx,
//! schema)` for that gate. The resume port and the signer-continuation driver
//! both read this binding back by `gate_ref` rather than trusting any
//! caller-supplied context (threats #2 / #3 / #4): the caller's resume payload
//! only ever *attests* to the bound hash; it can never *redefine* it.
//!
//! In-memory only here (PR10). Durable PG / libSQL backends are PR12 — they
//! must implement [`AttestedGateBindingStore`] with identical semantics and be
//! dual-backend, so no single-backend persistence feature is added in this
//! crate.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;

use ironclaw_attestation::{DecodedTransaction, RenderingSchemaVersion};
use ironclaw_chain_signing::ChainKeyId;
use ironclaw_signing_provider::{ApprovedTxHash, GateRef, ProviderId, SigningContext};

/// Everything the resume path needs to verify and continue an attested-signing
/// gate, persisted authoritatively when the gate is raised.
#[derive(Debug, Clone)]
pub struct AttestedGateBinding {
    /// Which provider drove the ceremony (selects the verifier on resume).
    pub provider_id: ProviderId,
    /// The authoritative signing context (who/what/where/which gate).
    pub context: SigningContext,
    /// The `ApprovedTxHash` recorded at approval time — the one the resume
    /// `expected_tx_hash` must equal and the wallet/authn must attest to.
    pub approved_tx_hash: ApprovedTxHash,
    /// The server-decoded transaction (PR2 model). The custodial signer
    /// recomputes the hash from THIS; the broadcast path re-signs from it.
    pub decoded: DecodedTransaction,
    /// The chain key id the custodial path would consume (custodial only).
    pub chain: ChainKeyId,
    /// The authoritative keystore/AAD owner scope, persisted when the gate was
    /// raised. Carried directly rather than reconstructed from `context` so the
    /// custodial keystore lookup uses the exact validated scope (custodial
    /// only; ignored on external-wallet paths).
    pub scope: ironclaw_host_api::ResourceScope,
    /// Schema version the approval was rendered under.
    pub schema_version: RenderingSchemaVersion,
}

/// Store of authoritative attested-gate bindings, keyed by `gate_ref`.
///
/// One binding per `gate_ref`, created when the gate is raised. The resume path
/// reads it back; durable backends (PR12) carry identical semantics.
#[async_trait]
pub trait AttestedGateBindingStore: Send + Sync {
    /// Persist the authoritative binding for a freshly-raised attested gate.
    async fn put(&self, gate_ref: GateRef, binding: AttestedGateBinding);

    /// Read the authoritative binding for `gate_ref`, if one exists.
    async fn get(&self, gate_ref: &GateRef) -> Option<AttestedGateBinding>;
}

/// In-memory [`AttestedGateBindingStore`].
#[derive(Default)]
pub struct InMemoryAttestedGateBindingStore {
    bindings: Mutex<HashMap<GateRef, AttestedGateBinding>>,
}

impl InMemoryAttestedGateBindingStore {
    /// Construct an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Synchronous read used by the resume port, which runs inside the turn
    /// store's sync critical section and therefore cannot `.await`. The async
    /// trait method is for the driver / ingress paths.
    pub fn get_sync(&self, gate_ref: &GateRef) -> Option<AttestedGateBinding> {
        self.bindings
            .lock()
            .ok()
            .and_then(|map| map.get(gate_ref).cloned())
    }
}

#[async_trait]
impl AttestedGateBindingStore for InMemoryAttestedGateBindingStore {
    async fn put(&self, gate_ref: GateRef, binding: AttestedGateBinding) {
        if let Ok(mut map) = self.bindings.lock() {
            map.insert(gate_ref, binding);
        }
    }

    async fn get(&self, gate_ref: &GateRef) -> Option<AttestedGateBinding> {
        self.get_sync(gate_ref)
    }
}
