//! Signing / broadcast idempotency ledger.
//!
//! One ledger row per `gate_ref`, created at [`SigningLedgerState::Approved`]
//! and advanced through a strict state machine. The machine encodes the
//! broadcast-idempotency guard that prevents re-signing or double-submitting a
//! transaction: once a row reaches [`SigningLedgerState::BroadcastSubmitted`]
//! it may only move to a terminal state, NEVER back to `Signing`/`Signed`.
//! This holds even under a `Stuck -> InProgress` job recovery — recovery sees
//! the broadcast already submitted and cannot re-sign with a fresh
//! nonce/blockhash.
//!
//! Durable PG / libSQL backends are stacked follow-ups gated by the canonical
//! [`signing_ledger_contract_cases!`] suite.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use ironclaw_signing_provider::GateRef;

/// State of a single signing/broadcast flow, keyed by `gate_ref`.
///
/// Wire-stable, snake_case serde (see `.claude/rules/types.md`). The legal
/// forward path is:
///
/// ```text
/// Approved -> Signing -> Signed -> BroadcastSubmitted -> Finalized
///                                                      \-> Unknown
///                                                      \-> ManualReview
/// ```
///
/// `Finalized`, `Unknown`, and `ManualReview` are terminal. `Unknown` and
/// `ManualReview` are NEVER auto-retried with a fresh nonce/blockhash — they
/// require out-of-band resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningLedgerState {
    /// The transaction has been approved at the gate; signing not yet started.
    Approved,
    /// Signing is in progress.
    Signing,
    /// The transaction is signed but not yet broadcast.
    Signed,
    /// The signed transaction has been submitted to the network. Past this
    /// point re-signing is forbidden (broadcast-idempotency guard).
    BroadcastSubmitted,
    /// Confirmed on-chain. Terminal.
    Finalized,
    /// Broadcast outcome is unknown (e.g. submit timed out). Terminal; needs
    /// out-of-band resolution, never an automatic fresh-nonce retry.
    Unknown,
    /// Flagged for human resolution. Terminal.
    ManualReview,
}

impl SigningLedgerState {
    /// Whether this state is terminal (no further transitions allowed).
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            SigningLedgerState::Finalized
                | SigningLedgerState::Unknown
                | SigningLedgerState::ManualReview
        )
    }

    /// Whether the transaction has been broadcast (i.e. is at or past
    /// [`SigningLedgerState::BroadcastSubmitted`]).
    pub fn is_broadcast(self) -> bool {
        matches!(
            self,
            SigningLedgerState::BroadcastSubmitted
                | SigningLedgerState::Finalized
                | SigningLedgerState::Unknown
                | SigningLedgerState::ManualReview
        )
    }

    /// Validate a transition from `self` to `to`.
    ///
    /// Encodes: the single legal forward edge between non-broadcast states, the
    /// fan-out from `BroadcastSubmitted` to the three terminals, no regression,
    /// no skipping, and the broadcast-idempotency guard (a broadcast row can
    /// only reach a terminal).
    pub fn can_advance_to(self, to: SigningLedgerState) -> bool {
        use SigningLedgerState::*;
        match self {
            Approved => to == Signing,
            Signing => to == Signed,
            Signed => to == BroadcastSubmitted,
            BroadcastSubmitted => matches!(to, Finalized | Unknown | ManualReview),
            // Terminal states never advance.
            Finalized | Unknown | ManualReview => false,
        }
    }
}

/// Errors a [`SigningLedger`] can surface.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum LedgerError {
    /// The requested transition is not permitted by the state machine.
    #[error("invalid signing-ledger transition from {from:?} to {to:?}")]
    InvalidTransition {
        /// Current state.
        from: SigningLedgerState,
        /// Attempted target state.
        to: SigningLedgerState,
    },

    /// No ledger row exists for the given `gate_ref`.
    #[error("no signing-ledger row for this gate_ref")]
    NotFound,

    /// A row already exists for this `gate_ref` (one-shot create).
    #[error("signing-ledger row already exists for this gate_ref")]
    AlreadyExists,

    /// A backend-internal failure with an opaque description.
    #[error("signing-ledger store error: {reason}")]
    Backend {
        /// Human-readable description of the backend failure.
        reason: String,
    },
}

/// Signing/broadcast idempotency ledger, keyed by `gate_ref`.
#[async_trait]
pub trait SigningLedger: Send + Sync {
    /// Create a new ledger row at [`SigningLedgerState::Approved`]. One-shot per
    /// `gate_ref`: a second create fails with [`LedgerError::AlreadyExists`].
    async fn create(&self, gate_ref: &GateRef) -> Result<(), LedgerError>;

    /// Read the current state for `gate_ref`, or [`LedgerError::NotFound`].
    async fn state(&self, gate_ref: &GateRef) -> Result<SigningLedgerState, LedgerError>;

    /// Advance the row for `gate_ref` to `to`, validating the transition.
    /// Fails with [`LedgerError::InvalidTransition`] for any illegal move and
    /// [`LedgerError::NotFound`] if the row does not exist.
    async fn advance(&self, gate_ref: &GateRef, to: SigningLedgerState) -> Result<(), LedgerError>;
}

/// In-memory [`SigningLedger`]. The single [`Mutex`] makes read-validate-write
/// in [`SigningLedger::advance`] a single critical section.
#[derive(Debug, Default)]
pub struct InMemorySigningLedger {
    rows: Mutex<HashMap<GateRef, SigningLedgerState>>,
}

impl InMemorySigningLedger {
    /// Construct an empty ledger.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl SigningLedger for InMemorySigningLedger {
    async fn create(&self, gate_ref: &GateRef) -> Result<(), LedgerError> {
        let mut rows = self.rows.lock().map_err(|e| LedgerError::Backend {
            reason: e.to_string(),
        })?;
        if rows.contains_key(gate_ref) {
            return Err(LedgerError::AlreadyExists);
        }
        rows.insert(gate_ref.clone(), SigningLedgerState::Approved);
        Ok(())
    }

    async fn state(&self, gate_ref: &GateRef) -> Result<SigningLedgerState, LedgerError> {
        let rows = self.rows.lock().map_err(|e| LedgerError::Backend {
            reason: e.to_string(),
        })?;
        rows.get(gate_ref).copied().ok_or(LedgerError::NotFound)
    }

    async fn advance(&self, gate_ref: &GateRef, to: SigningLedgerState) -> Result<(), LedgerError> {
        let mut rows = self.rows.lock().map_err(|e| LedgerError::Backend {
            reason: e.to_string(),
        })?;
        let from = rows.get_mut(gate_ref).ok_or(LedgerError::NotFound)?;
        if !from.can_advance_to(to) {
            return Err(LedgerError::InvalidTransition { from: *from, to });
        }
        *from = to;
        Ok(())
    }
}

/// Canonical contract suite for [`SigningLedger`] implementations. Mirrors the
/// grant-store and predicate-state contract pattern.
///
/// Exposed publicly behind the `contract-suite` feature so the durable-backend
/// crate (`ironclaw_attested_store`) can drive its PG / libSQL ledgers through
/// the same cases; otherwise `#[cfg(test)]` keeps it crate-private.
#[cfg(any(test, feature = "contract-suite"))]
pub mod contract {
    // `pub` case fns are invoked by the `#[macro_export]`ed contract macro from
    // the durable-backend crate; the lint cannot see that cross-crate use under
    // a plain `#[cfg(test)]` build, so allow it here.
    #![allow(unreachable_pub)]

    use super::*;

    /// The fixed `gate_ref` every ledger contract case operates on.
    pub fn gate() -> GateRef {
        GateRef::new("gate:ledger")
    }

    pub async fn full_valid_sequence<L: SigningLedger>(ledger: L) {
        use SigningLedgerState::*;
        let g = gate();
        ledger.create(&g).await.expect("create");
        assert_eq!(ledger.state(&g).await.expect("state"), Approved);
        for to in [Signing, Signed, BroadcastSubmitted, Finalized] {
            ledger.advance(&g, to).await.expect("valid advance");
            assert_eq!(ledger.state(&g).await.expect("state"), to);
        }
    }

    pub async fn second_create_is_already_exists<L: SigningLedger>(ledger: L) {
        let g = gate();
        ledger.create(&g).await.expect("create");
        assert_eq!(ledger.create(&g).await, Err(LedgerError::AlreadyExists));
    }

    pub async fn advance_missing_is_not_found<L: SigningLedger>(ledger: L) {
        assert_eq!(
            ledger.advance(&gate(), SigningLedgerState::Signing).await,
            Err(LedgerError::NotFound)
        );
        assert_eq!(ledger.state(&gate()).await, Err(LedgerError::NotFound));
    }

    pub async fn skip_forward_is_invalid<L: SigningLedger>(ledger: L) {
        let g = gate();
        ledger.create(&g).await.expect("create");
        // Approved -> Signed skips Signing.
        assert_eq!(
            ledger.advance(&g, SigningLedgerState::Signed).await,
            Err(LedgerError::InvalidTransition {
                from: SigningLedgerState::Approved,
                to: SigningLedgerState::Signed,
            })
        );
    }

    pub async fn regression_is_invalid<L: SigningLedger>(ledger: L) {
        use SigningLedgerState::*;
        let g = gate();
        ledger.create(&g).await.expect("create");
        ledger.advance(&g, Signing).await.expect("to signing");
        ledger.advance(&g, Signed).await.expect("to signed");
        // Signed -> Approved regresses.
        assert_eq!(
            ledger.advance(&g, Approved).await,
            Err(LedgerError::InvalidTransition {
                from: Signed,
                to: Approved
            })
        );
    }

    pub async fn broadcast_idempotency_guard<L: SigningLedger>(ledger: L) {
        use SigningLedgerState::*;
        let g = gate();
        ledger.create(&g).await.expect("create");
        ledger.advance(&g, Signing).await.expect("signing");
        ledger.advance(&g, Signed).await.expect("signed");
        ledger
            .advance(&g, BroadcastSubmitted)
            .await
            .expect("broadcast");
        // Once broadcast, re-signing / re-submitting is forbidden — this is the
        // guard that survives a Stuck->InProgress job recovery.
        for forbidden in [Signing, Signed, Approved] {
            assert_eq!(
                ledger.advance(&g, forbidden).await,
                Err(LedgerError::InvalidTransition {
                    from: BroadcastSubmitted,
                    to: forbidden
                }),
                "broadcast row must not move back to {forbidden:?}"
            );
        }
        // It may still reach a terminal.
        ledger.advance(&g, Finalized).await.expect("finalize");
    }

    pub async fn terminal_states_never_advance<L: SigningLedger>(ledger: L) {
        use SigningLedgerState::*;
        let g = gate();
        ledger.create(&g).await.expect("create");
        ledger.advance(&g, Signing).await.expect("signing");
        ledger.advance(&g, Signed).await.expect("signed");
        ledger
            .advance(&g, BroadcastSubmitted)
            .await
            .expect("broadcast");
        ledger.advance(&g, Unknown).await.expect("to unknown");
        // Unknown is terminal — no auto-retry with a fresh nonce.
        for to in [Signing, BroadcastSubmitted, Finalized, ManualReview] {
            assert_eq!(
                ledger.advance(&g, to).await,
                Err(LedgerError::InvalidTransition { from: Unknown, to }),
                "Unknown is terminal; must not advance to {to:?}"
            );
        }
    }

    /// Drive every contract case against a fresh ledger from `$factory`.
    #[macro_export]
    macro_rules! signing_ledger_contract_cases {
        ($label:ident, $factory:expr) => {
            mod $label {
                #[tokio::test]
                async fn full_valid_sequence() {
                    $crate::ledger::contract::full_valid_sequence($factory()).await;
                }
                #[tokio::test]
                async fn second_create_is_already_exists() {
                    $crate::ledger::contract::second_create_is_already_exists($factory()).await;
                }
                #[tokio::test]
                async fn advance_missing_is_not_found() {
                    $crate::ledger::contract::advance_missing_is_not_found($factory()).await;
                }
                #[tokio::test]
                async fn skip_forward_is_invalid() {
                    $crate::ledger::contract::skip_forward_is_invalid($factory()).await;
                }
                #[tokio::test]
                async fn regression_is_invalid() {
                    $crate::ledger::contract::regression_is_invalid($factory()).await;
                }
                #[tokio::test]
                async fn broadcast_idempotency_guard() {
                    $crate::ledger::contract::broadcast_idempotency_guard($factory()).await;
                }
                #[tokio::test]
                async fn terminal_states_never_advance() {
                    $crate::ledger::contract::terminal_states_never_advance($factory()).await;
                }
            }
        };
    }
}

#[cfg(test)]
crate::signing_ledger_contract_cases!(in_memory, crate::ledger::InMemorySigningLedger::new);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_round_trips_snake_case() {
        let json = serde_json::to_string(&SigningLedgerState::BroadcastSubmitted).expect("ser");
        assert_eq!(json, "\"broadcast_submitted\"");
        let back: SigningLedgerState = serde_json::from_str(&json).expect("de");
        assert_eq!(back, SigningLedgerState::BroadcastSubmitted);
    }

    #[test]
    fn terminal_and_broadcast_predicates() {
        assert!(SigningLedgerState::Finalized.is_terminal());
        assert!(SigningLedgerState::Unknown.is_terminal());
        assert!(SigningLedgerState::ManualReview.is_terminal());
        assert!(!SigningLedgerState::BroadcastSubmitted.is_terminal());
        assert!(SigningLedgerState::BroadcastSubmitted.is_broadcast());
        assert!(!SigningLedgerState::Signed.is_broadcast());
    }
}
