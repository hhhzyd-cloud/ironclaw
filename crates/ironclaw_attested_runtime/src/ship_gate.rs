//! The `CUSTODIAL_MAINNET_ENABLED` ship-gate (threat #18).
//!
//! Mirrors the `HOOKS_THIRD_PARTY_ENABLED` env-gate pattern: a dangerous
//! capability (here, custodial *mainnet* / real-value signing with keys
//! IronClaw holds) is refused unless an operator explicitly opts in **and** a
//! secure-custody HSM/KMS backend is wired. The opt-in flag alone is never
//! sufficient — a hot key in process memory can only ever sign testnet / dev
//! value (compromised-host hot-key threat).
//!
//! This wraps the lower-level [`ironclaw_chain_signing::ShipGate`] (which
//! encodes the actual allow/deny logic and the mainnet-vs-testnet
//! classification) and adds the env-driven construction so the composition
//! layer reads one flag and hands a built gate to the custodial signer.

use ironclaw_chain_signing::{HsmKmsBackend, ShipGate};

/// The environment variable that opts a deployment into custodial mainnet
/// signing. Necessary but NOT sufficient: secure custody is still required.
pub const CUSTODIAL_MAINNET_ENABLED_ENV: &str = "CUSTODIAL_MAINNET_ENABLED";

/// The composition-layer custodial-mainnet ship-gate.
///
/// Reads the `CUSTODIAL_MAINNET_ENABLED` opt-in and builds the chain-signing
/// [`ShipGate`] from it plus the wired KMS backend (if any).
pub struct CustodialMainnetShipGate {
    opt_in: bool,
}

impl CustodialMainnetShipGate {
    /// Build from an explicit opt-in flag (used by tests / callers that own the
    /// config).
    pub fn new(opt_in: bool) -> Self {
        Self { opt_in }
    }

    /// Build by reading the `CUSTODIAL_MAINNET_ENABLED` env var. Anything other
    /// than a truthy value (`1`, `true`, `yes`, case-insensitive) is treated as
    /// opted-out — fail-closed default.
    pub fn from_env() -> Self {
        let opt_in = std::env::var(CUSTODIAL_MAINNET_ENABLED_ENV)
            .ok()
            .map(|v| {
                let v = v.trim().to_ascii_lowercase();
                v == "1" || v == "true" || v == "yes"
            })
            .unwrap_or(false);
        Self { opt_in }
    }

    /// Whether the operator opted into mainnet custodial signing.
    pub fn mainnet_opt_in(&self) -> bool {
        self.opt_in
    }

    /// Build the lower-level chain-signing [`ShipGate`] for the custodial
    /// signer, binding the operator opt-in to the wired KMS backend.
    ///
    /// A `None` backend (no KMS) or a hot-key backend
    /// (`is_secure_custody() == false`) cannot satisfy the mainnet requirement,
    /// regardless of the opt-in (threat #18). Testnet / dev signing is always
    /// allowed.
    pub fn build_chain_ship_gate(&self, kms: Option<&dyn HsmKmsBackend>) -> ShipGate {
        ShipGate::new(self.opt_in, kms)
    }
}
