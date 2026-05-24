//! CAIP-2 chain-family resolution and WalletConnect v2 session-namespace
//! pinning.
//!
//! The attested-signing gate has *already* decided exactly one chain
//! ([`SigningContext::chain_id`](ironclaw_signing_provider::SigningContext)) and
//! exactly one signing operation. A WalletConnect v2 session, by contrast,
//! negotiates an arbitrarily-broad set of CAIP-2 chains, RPC methods, and events
//! between dapp and wallet. If we let the wallet (or a compromised relay) settle
//! a session whose scope is broader than the gate's single bound operation, a
//! later request could sign a *different* chain or call a *different* method
//! than the human approved — threats **T17** (chain/method scope broadening) and
//! **T19** (multi-chain session reuse).
//!
//! This module derives the *single* CAIP-2 chain + *single* signing method the
//! gate authorizes, and validates any proposed/settled session scope against it,
//! rejecting fail-closed with
//! [`SigningProviderError::ScopeViolation`](ironclaw_signing_provider::SigningProviderError::ScopeViolation)
//! on any superset.

use ironclaw_signing_provider::{ChainId, SigningProviderError};

/// The wallet/crypto family a CAIP-2 chain id belongs to.
///
/// Determines which signing RPC method and which signer-recovery scheme apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainFamily {
    /// EVM chains (`eip155:*`). Signs via `eth_signTransaction`; signer
    /// recovered via secp256k1 ecrecover.
    Evm,
    /// Solana clusters (`solana:*`). Signs via `solana_signTransaction`; signer
    /// is the connected ed25519 account.
    Solana,
    /// NEAR networks (`near:*`). Signs via `near_signTransactions`; signer is
    /// the connected ed25519 account.
    Near,
}

impl ChainFamily {
    /// The single WalletConnect v2 RPC method this family uses to *sign* the
    /// gate-bound transaction.
    ///
    /// We deliberately pin to the **sign**, not the **send/broadcast**, method:
    /// broadcasting is the deterministic post-approval continuation owned by
    /// PR10 (`ironclaw_chain_signing`), never the wallet. Pinning to the
    /// sign-only method also narrows the relay/session attack surface (the
    /// session is never authorized to broadcast on the user's behalf).
    pub fn signing_method(self) -> &'static str {
        match self {
            ChainFamily::Evm => "eth_signTransaction",
            ChainFamily::Solana => "solana_signTransaction",
            ChainFamily::Near => "near_signTransactions",
        }
    }
}

/// The single chain + single method a WalletConnect session is permitted to
/// carry for this gate. Anything broader is a [`SigningProviderError::ScopeViolation`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedScope {
    /// The exact CAIP-2 chain id (e.g. `eip155:1`, `solana:5eykt4...`).
    pub caip2_chain: String,
    /// The chain family resolved from the CAIP-2 namespace.
    pub family: ChainFamily,
    /// The single signing RPC method permitted.
    pub method: String,
}

impl PinnedScope {
    /// Derive the pinned scope from the gate's bound chain id.
    ///
    /// The gate's [`ChainId`] is treated as a CAIP-2 chain id
    /// (`namespace:reference`). The namespace selects the family; the full id is
    /// the single permitted chain; the family selects the single permitted
    /// signing method.
    pub fn from_chain_id(chain_id: &ChainId) -> Result<Self, SigningProviderError> {
        let caip2 = chain_id.as_str();
        let namespace = caip2.split_once(':').map(|(ns, _)| ns).ok_or_else(|| {
            SigningProviderError::ScopeViolation {
                reason: format!("chain id `{caip2}` is not a CAIP-2 `namespace:reference`"),
            }
        })?;
        let family = match namespace {
            "eip155" => ChainFamily::Evm,
            "solana" => ChainFamily::Solana,
            "near" => ChainFamily::Near,
            other => {
                return Err(SigningProviderError::ScopeViolation {
                    reason: format!("unsupported CAIP-2 namespace `{other}`"),
                });
            }
        };
        Ok(Self {
            caip2_chain: caip2.to_string(),
            family,
            method: family.signing_method().to_string(),
        })
    }

    /// The CAIP-2 namespace (the part before the first `:`), e.g. `eip155`.
    pub fn namespace(&self) -> &str {
        self.caip2_chain
            .split_once(':')
            .map(|(ns, _)| ns)
            .unwrap_or(&self.caip2_chain)
    }
}

/// A session scope as *proposed or settled* by the wallet/relay, to be checked
/// against the gate's [`PinnedScope`].
///
/// Mirrors the CAIP-25 `chains` / `methods` arrays of a single namespace.
/// Modeled minimally here (PR9 verifies the negotiated scope; the encrypted
/// CAIP-25 envelope round-trip over the relay is PR10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposedScope {
    /// CAIP-2 chain ids the session would authorize.
    pub chains: Vec<String>,
    /// RPC methods the session would authorize.
    pub methods: Vec<String>,
}

/// Validate a proposed/settled session scope against the gate's pinned scope,
/// fail-closed.
///
/// Rejects (T17/T19) when the proposal:
/// * authorizes any chain other than the single pinned chain, or no chains;
/// * authorizes any method other than the single pinned signing method, or no
///   methods.
///
/// Equality — not subset — is required: the session must be scoped to *exactly*
/// the one chain and one method the human approved. A proposal that is a strict
/// superset (extra chains/methods) is a scope-broadening attempt and is
/// rejected.
pub fn enforce_pinned_scope(
    pinned: &PinnedScope,
    proposed: &ProposedScope,
) -> Result<(), SigningProviderError> {
    if proposed.chains.is_empty() {
        return Err(SigningProviderError::ScopeViolation {
            reason: "session proposal authorizes no chains".to_string(),
        });
    }
    if proposed.methods.is_empty() {
        return Err(SigningProviderError::ScopeViolation {
            reason: "session proposal authorizes no methods".to_string(),
        });
    }
    for chain in &proposed.chains {
        if chain != &pinned.caip2_chain {
            return Err(SigningProviderError::ScopeViolation {
                reason: format!(
                    "session proposal chain `{chain}` broadens scope beyond the pinned chain `{}`",
                    pinned.caip2_chain
                ),
            });
        }
    }
    for method in &proposed.methods {
        if method != &pinned.method {
            return Err(SigningProviderError::ScopeViolation {
                reason: format!(
                    "session proposal method `{method}` broadens scope beyond the pinned method `{}`",
                    pinned.method
                ),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_evm_family_and_method() {
        let pinned = PinnedScope::from_chain_id(&ChainId::new("eip155:1")).expect("evm");
        assert_eq!(pinned.family, ChainFamily::Evm);
        assert_eq!(pinned.method, "eth_signTransaction");
        assert_eq!(pinned.namespace(), "eip155");
        assert_eq!(pinned.caip2_chain, "eip155:1");
    }

    #[test]
    fn resolves_solana_and_near_families() {
        assert_eq!(
            PinnedScope::from_chain_id(&ChainId::new("solana:mainnet"))
                .expect("sol")
                .method,
            "solana_signTransaction"
        );
        assert_eq!(
            PinnedScope::from_chain_id(&ChainId::new("near:mainnet"))
                .expect("near")
                .method,
            "near_signTransactions"
        );
    }

    #[test]
    fn non_caip2_chain_id_is_scope_violation() {
        let err = PinnedScope::from_chain_id(&ChainId::new("ethereum")).expect_err("no colon");
        assert!(matches!(err, SigningProviderError::ScopeViolation { .. }));
    }

    #[test]
    fn unsupported_namespace_is_scope_violation() {
        let err = PinnedScope::from_chain_id(&ChainId::new("cosmos:cosmoshub-4"))
            .expect_err("unsupported");
        assert!(matches!(err, SigningProviderError::ScopeViolation { .. }));
    }

    fn evm_pinned() -> PinnedScope {
        PinnedScope::from_chain_id(&ChainId::new("eip155:1")).expect("evm")
    }

    #[test]
    fn exact_pinned_scope_is_accepted() {
        let proposed = ProposedScope {
            chains: vec!["eip155:1".to_string()],
            methods: vec!["eth_signTransaction".to_string()],
        };
        enforce_pinned_scope(&evm_pinned(), &proposed).expect("exact match accepted");
    }

    #[test]
    fn extra_chain_is_rejected_t19() {
        let proposed = ProposedScope {
            chains: vec!["eip155:1".to_string(), "eip155:137".to_string()],
            methods: vec!["eth_signTransaction".to_string()],
        };
        let err = enforce_pinned_scope(&evm_pinned(), &proposed).expect_err("extra chain");
        assert!(matches!(err, SigningProviderError::ScopeViolation { .. }));
    }

    #[test]
    fn extra_method_is_rejected_t17() {
        let proposed = ProposedScope {
            chains: vec!["eip155:1".to_string()],
            methods: vec![
                "eth_signTransaction".to_string(),
                "eth_sendTransaction".to_string(),
            ],
        };
        let err = enforce_pinned_scope(&evm_pinned(), &proposed).expect_err("extra method");
        assert!(matches!(err, SigningProviderError::ScopeViolation { .. }));
    }

    #[test]
    fn wrong_single_chain_is_rejected() {
        let proposed = ProposedScope {
            chains: vec!["eip155:137".to_string()],
            methods: vec!["eth_signTransaction".to_string()],
        };
        let err = enforce_pinned_scope(&evm_pinned(), &proposed).expect_err("wrong chain");
        assert!(matches!(err, SigningProviderError::ScopeViolation { .. }));
    }

    #[test]
    fn empty_chains_or_methods_rejected() {
        let no_chains = ProposedScope {
            chains: vec![],
            methods: vec!["eth_signTransaction".to_string()],
        };
        assert!(matches!(
            enforce_pinned_scope(&evm_pinned(), &no_chains).expect_err("no chains"),
            SigningProviderError::ScopeViolation { .. }
        ));
        let no_methods = ProposedScope {
            chains: vec!["eip155:1".to_string()],
            methods: vec![],
        };
        assert!(matches!(
            enforce_pinned_scope(&evm_pinned(), &no_methods).expect_err("no methods"),
            SigningProviderError::ScopeViolation { .. }
        ));
    }
}
