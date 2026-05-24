//! Per-gate WalletConnect session binding.
//!
//! When [`initiate`](super::WalletConnectSigningProvider) establishes a session
//! it records, keyed by the gate, the **expected** binding the eventual proof
//! must match: the WalletConnect session topic, the account the session settled
//! on (within the pinned scope), and a freshly-minted per-request nonce. At
//! [`verify_resume`](super::WalletConnectSigningProvider) time the returned
//! proof must carry exactly this `(session_topic, account, nonce)` triple, and
//! the wallet's signature must commit to it (see
//! [`super::signer::attestation_digest`]).
//!
//! Binding the proof to the session + nonce defeats **T18** (a proof minted
//! under a *different* WC session / relay key, or replayed with a stale nonce,
//! is rejected) and complements the one-shot grant CAS (T20).
//!
//! The in-memory store here is the PR9 testable surface. Persisting the binding
//! durably across the initiate→resume gap (so it survives process restarts and
//! is consumed exactly once at the storage layer) is composition wiring owned by
//! PR10.

use std::collections::HashMap;
use std::sync::Mutex;

use ironclaw_signing_provider::GateRef;

use super::namespace::PinnedScope;

/// The expected binding a WalletConnect proof must satisfy for a given gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionBinding {
    /// The WalletConnect v2 session topic the proof must belong to.
    pub session_topic: String,
    /// The account the session settled on (must lie within the pinned scope and
    /// equal the gate's bound account).
    pub account: String,
    /// Per-request nonce the wallet must commit to in its signature.
    pub nonce: Vec<u8>,
    /// The pinned single-chain / single-method scope for this gate.
    pub pinned: PinnedScope,
}

/// In-memory store of per-gate [`SessionBinding`]s.
///
/// `record` inserts the expectation at `initiate`; `take` removes and returns it
/// at `verify_resume` so a binding is consumed at most once in-process. (Durable
/// one-shot consumption is layered by the sealed-grant CAS at verify time and by
/// PR10's persistence.)
#[derive(Debug, Default)]
pub struct SessionBindingStore {
    bindings: Mutex<HashMap<String, SessionBinding>>,
}

impl SessionBindingStore {
    /// Construct an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the expected binding for `gate`. Overwrites any prior binding for
    /// the same gate (a re-initiation supersedes the stale expectation).
    pub fn record(&self, gate: &GateRef, binding: SessionBinding) {
        if let Ok(mut map) = self.bindings.lock() {
            map.insert(gate.as_str().to_string(), binding);
        }
    }

    /// Remove and return the expected binding for `gate`, if any.
    pub fn take(&self, gate: &GateRef) -> Option<SessionBinding> {
        self.bindings
            .lock()
            .ok()
            .and_then(|mut map| map.remove(gate.as_str()))
    }
}
