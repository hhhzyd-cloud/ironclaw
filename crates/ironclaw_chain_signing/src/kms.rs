//! HSM/KMS sign-only backend trait and the mainnet **ship-gate**.
//!
//! ## Threat #18 — compromised-host hot key
//!
//! A custodial private key held in process memory ("hot key") is exposed if the
//! host is compromised. The substrate's answer (mirroring the
//! `HOOKS_THIRD_PARTY_ENABLED` ship-gate pattern) is: **real-value / mainnet
//! custodial signing is refused unless an HSM/KMS backend is wired.** Hot-key
//! custodial signing is permitted only on testnet / dev. The check runs at
//! startup-config time and again at sign time, fail-closed.
//!
//! ## Scope of this PR
//!
//! This PR ships the *trait*, the *gate*, and a *filesystem hot-key default
//! impl* (testnet/dev only). A live cloud-KMS integration (AWS KMS, GCP KMS,
//! YubiHSM, …) that actually performs sign-only operations is a deferred
//! follow-up — noted in the crate docs and the PR body.

use crate::error::ChainSigningError;
use crate::policy::CustodyDecision;

/// A sign-only HSM/KMS backend.
///
/// The defining property is that **private key bytes never leave the backend**:
/// callers hand it a key reference and a digest and receive a signature. This
/// crate's trait is intentionally minimal (sign-only) so a real KMS need expose
/// only its signing primitive.
pub trait HsmKmsBackend: Send + Sync {
    /// A stable identifier for the backend (for audit / config display). Never
    /// includes key material.
    fn backend_id(&self) -> &str;

    /// Whether this backend keeps keys in a hardware/remote security boundary
    /// (true) or holds hot keys in host memory (false). The ship-gate consults
    /// this to decide whether mainnet signing is allowed.
    fn is_secure_custody(&self) -> bool;

    /// Sign a 32-byte digest with the referenced key, returning the raw
    /// signature bytes. `key_ref` is an opaque backend handle — NOT key
    /// material.
    fn sign_digest(&self, key_ref: &str, digest: &[u8; 32]) -> Result<Vec<u8>, ChainSigningError>;
}

/// Whether a signing request targets real value (mainnet) or a test network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueClass {
    /// Mainnet / real-value. Gated on secure custody.
    Mainnet,
    /// Testnet / dev. Hot-key custodial permitted.
    Testnet,
}

impl ValueClass {
    /// Classify a chain identity string into a [`ValueClass`].
    ///
    /// Conservative / fail-closed: anything that is not a recognized testnet is
    /// treated as **mainnet** (real value), so an unknown or spoofed chain id
    /// cannot downgrade itself into the hot-key-allowed bucket.
    pub fn classify(chain: &str) -> Self {
        // Known test networks across the three families.
        const TESTNETS: &[&str] = &[
            // EVM testnets (chain ids).
            "eip155:11155111", // sepolia
            "eip155:17000",    // holesky
            "eip155:5",        // goerli (deprecated)
            "eip155:80002",    // amoy
            "eip155:84532",    // base-sepolia
            // Solana.
            "solana:devnet",
            "solana:testnet",
            // NEAR.
            "near:testnet",
            // Generic local/dev markers.
            "eip155:31337", // anvil/hardhat
            "eip155:1337",
        ];
        if TESTNETS.contains(&chain) {
            ValueClass::Testnet
        } else {
            ValueClass::Mainnet
        }
    }
}

/// The startup-checked mainnet ship-gate.
///
/// Construct from config (mirroring a `CUSTODIAL_MAINNET_ENABLED`-style flag)
/// and an optional wired KMS backend. [`ShipGate::authorize`] refuses mainnet
/// custodial signing unless a secure-custody backend is present, regardless of
/// the flag — the flag alone cannot enable hot-key mainnet.
pub struct ShipGate {
    /// Operator opt-in (e.g. from `CUSTODIAL_MAINNET_ENABLED`). Necessary but
    /// NOT sufficient: secure custody is still required for mainnet.
    mainnet_opt_in: bool,
    /// Whether a wired backend provides secure (HSM/KMS) custody.
    secure_custody_available: bool,
}

impl ShipGate {
    /// Build a ship-gate from the operator opt-in flag and the wired backend
    /// (if any). A backend that reports `is_secure_custody() == false` (a hot
    /// key) does not satisfy the mainnet requirement.
    pub fn new(mainnet_opt_in: bool, backend: Option<&dyn HsmKmsBackend>) -> Self {
        Self {
            mainnet_opt_in,
            secure_custody_available: backend.is_some_and(|b| b.is_secure_custody()),
        }
    }

    /// Authorize (or refuse) a custodial signing request for the given value
    /// class. Fail-closed: mainnet requires BOTH the opt-in flag AND secure
    /// custody; testnet always allowed.
    pub fn authorize(&self, value: ValueClass) -> CustodyDecision {
        match value {
            ValueClass::Testnet => CustodyDecision::Allow,
            ValueClass::Mainnet => {
                if !self.mainnet_opt_in {
                    CustodyDecision::Deny {
                        reason: "mainnet custodial signing is not enabled (set the \
                                 CUSTODIAL_MAINNET_ENABLED opt-in)"
                            .to_string(),
                    }
                } else if !self.secure_custody_available {
                    CustodyDecision::Deny {
                        reason: "mainnet custodial signing requires an HSM/KMS backend with \
                                 secure custody; hot-key custodial is testnet/dev only \
                                 (compromised-host hot-key threat #18)"
                            .to_string(),
                    }
                } else {
                    CustodyDecision::Allow
                }
            }
        }
    }

    /// Convenience: authorize for a chain id string, classifying it first.
    pub fn authorize_chain(&self, chain: &str) -> Result<(), ChainSigningError> {
        match self.authorize(ValueClass::classify(chain)) {
            CustodyDecision::Allow => Ok(()),
            CustodyDecision::Deny { reason } => Err(ChainSigningError::ShipGateRefused { reason }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SecureBackend;
    impl HsmKmsBackend for SecureBackend {
        fn backend_id(&self) -> &str {
            "test-secure-kms"
        }
        fn is_secure_custody(&self) -> bool {
            true
        }
        fn sign_digest(
            &self,
            _key_ref: &str,
            _digest: &[u8; 32],
        ) -> Result<Vec<u8>, ChainSigningError> {
            Ok(vec![0u8; 64])
        }
    }

    struct HotBackend;
    impl HsmKmsBackend for HotBackend {
        fn backend_id(&self) -> &str {
            "test-hot"
        }
        fn is_secure_custody(&self) -> bool {
            false
        }
        fn sign_digest(
            &self,
            _key_ref: &str,
            _digest: &[u8; 32],
        ) -> Result<Vec<u8>, ChainSigningError> {
            Ok(vec![0u8; 64])
        }
    }

    #[test]
    fn unknown_chain_classifies_as_mainnet_fail_closed() {
        assert_eq!(ValueClass::classify("eip155:1"), ValueClass::Mainnet);
        assert_eq!(
            ValueClass::classify("eip155:999999999"),
            ValueClass::Mainnet
        );
        assert_eq!(ValueClass::classify("garbage"), ValueClass::Mainnet);
    }

    #[test]
    fn known_testnets_classify_as_testnet() {
        for c in [
            "eip155:11155111",
            "solana:devnet",
            "near:testnet",
            "eip155:31337",
        ] {
            assert_eq!(ValueClass::classify(c), ValueClass::Testnet, "{c}");
        }
    }

    #[test]
    fn testnet_hot_key_is_allowed_without_kms() {
        let gate = ShipGate::new(false, None);
        assert!(gate.authorize_chain("solana:devnet").is_ok());
    }

    #[test]
    fn mainnet_refused_without_kms_even_with_opt_in() {
        let gate = ShipGate::new(true, None);
        let err = gate.authorize_chain("eip155:1").unwrap_err();
        assert!(matches!(err, ChainSigningError::ShipGateRefused { .. }));

        // A hot-key backend does not satisfy secure custody.
        let hot = HotBackend;
        let gate = ShipGate::new(true, Some(&hot));
        assert!(gate.authorize_chain("eip155:1").is_err());
    }

    #[test]
    fn mainnet_refused_without_opt_in_even_with_kms() {
        let secure = SecureBackend;
        let gate = ShipGate::new(false, Some(&secure));
        assert!(gate.authorize_chain("eip155:1").is_err());
    }

    #[test]
    fn mainnet_allowed_with_opt_in_and_secure_kms() {
        let secure = SecureBackend;
        let gate = ShipGate::new(true, Some(&secure));
        assert!(gate.authorize_chain("eip155:1").is_ok());
    }
}
