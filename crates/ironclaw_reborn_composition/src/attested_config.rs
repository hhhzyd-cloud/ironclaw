//! Attested-signing external-wallet provider configuration (attested-signing
//! PR13).
//!
//! The [`AttestedSignerContinuationDriver`]'s [`ProviderRegistry`] dispatches a
//! resolved attested gate to the external-wallet provider bound on the gate
//! (`window.ethereum`/`window.solana` injected, NEAR redirect, or
//! WalletConnect v2). The injected provider is stateless and always
//! registrable; the NEAR-redirect and WalletConnect providers need ceremony
//! configuration before they can verify a proof:
//!
//! - **NEAR redirect**: the wallet base URL + the callback URL the wallet
//!   redirects back to, and a server-side `state_secret` (HMAC key) that
//!   MAC-binds the redirect `state` parameter to the gate (defeats callback /
//!   deep-link interception). The `state_secret` is a secret and is sourced
//!   from the environment only — never from the operator TOML (mirrors the
//!   `CUSTODIAL_MAINNET_ENABLED` env convention and the "secrets are env-only"
//!   config policy).
//! - **WalletConnect**: the WalletConnect Cloud `ProjectId` — a *publishable*
//!   app-identity key (shareable across tenants, not a per-tenant secret), so
//!   it is plain config, sourced from the environment.
//!
//! ## Fail-closed
//!
//! A provider is registered **only** when its full configuration is present.
//! When any required field is absent the provider stays unregistered: its wire
//! variant still decodes and reaches the driver, which fails closed as
//! [`ContinuationError::ProviderMismatch`]. We never register a provider with a
//! placeholder secret — that would weaken the attestation boundary (a bogus
//! `state_secret` would make every NEAR `state` verify).

use std::sync::Arc;

use ironclaw_attestation::SealedGrantStore;
use ironclaw_attested_runtime::ProviderRegistry;
use ironclaw_wallet_external::{
    InjectedSigningProvider, NearRedirectSigningProvider, ProjectId, WalletConnectSigningProvider,
};
use secrecy::{ExposeSecret, SecretString};

/// Env var holding the NEAR-redirect wallet base URL (e.g. the MyNearWallet /
/// NEAR wallet sign endpoint the user is redirected to).
pub const NEAR_WALLET_BASE_URL_ENV: &str = "ATTESTED_NEAR_WALLET_BASE_URL";
/// Env var holding the NEAR-redirect callback URL the wallet returns to.
pub const NEAR_CALLBACK_URL_ENV: &str = "ATTESTED_NEAR_CALLBACK_URL";
/// Env var holding the NEAR-redirect `state` HMAC secret. **Secret** — env-only.
pub const NEAR_STATE_SECRET_ENV: &str = "ATTESTED_NEAR_STATE_SECRET";
/// Env var holding the WalletConnect Cloud project id (publishable).
pub const WALLETCONNECT_PROJECT_ID_ENV: &str = "ATTESTED_WALLETCONNECT_PROJECT_ID";

/// Resolved NEAR-redirect ceremony config. Present only when all three fields
/// are configured; otherwise the provider stays unregistered (fail-closed).
#[derive(Clone)]
pub struct NearRedirectConfig {
    pub wallet_base_url: String,
    pub callback_url: String,
    /// HMAC key binding the redirect `state` to the gate. Secret.
    pub state_secret: SecretString,
}

impl std::fmt::Debug for NearRedirectConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the state_secret.
        f.debug_struct("NearRedirectConfig")
            .field("wallet_base_url", &self.wallet_base_url)
            .field("callback_url", &self.callback_url)
            .field("state_secret", &"<redacted>")
            .finish()
    }
}

/// Configuration for the external-wallet providers that need ceremony config.
/// Each field is independently optional and independently fail-closed.
#[derive(Clone, Debug, Default)]
pub struct AttestedProvidersConfig {
    /// NEAR-redirect ceremony config. `None` -> NEAR provider unregistered.
    pub near_redirect: Option<NearRedirectConfig>,
    /// WalletConnect Cloud project id. `None` -> WalletConnect unregistered.
    pub walletconnect_project_id: Option<String>,
}

impl AttestedProvidersConfig {
    /// Resolve from the process environment, fail-closed.
    ///
    /// NEAR is configured only when **all** of base URL, callback URL, and the
    /// `state_secret` are present and non-empty. WalletConnect is configured
    /// only when a non-empty project id is present.
    pub fn from_env() -> Self {
        let near_redirect = Self::near_from_env();
        let walletconnect_project_id = non_empty_env(WALLETCONNECT_PROJECT_ID_ENV);
        Self {
            near_redirect,
            walletconnect_project_id,
        }
    }

    fn near_from_env() -> Option<NearRedirectConfig> {
        let wallet_base_url = non_empty_env(NEAR_WALLET_BASE_URL_ENV)?;
        let callback_url = non_empty_env(NEAR_CALLBACK_URL_ENV)?;
        let state_secret = non_empty_env(NEAR_STATE_SECRET_ENV)?;
        Some(NearRedirectConfig {
            wallet_base_url,
            callback_url,
            state_secret: SecretString::from(state_secret),
        })
    }

    /// Build the [`ProviderRegistry`] for the attested driver.
    ///
    /// The injected provider is always registered over `grants` (the SAME
    /// sealed-grant store the custodial signer uses, so the one-shot grant CAS
    /// — threat #1 — is authoritative across every path). The NEAR-redirect and
    /// WalletConnect providers are registered only when their config is present
    /// (fail-closed otherwise).
    pub fn build_provider_registry(&self, grants: Arc<dyn SealedGrantStore>) -> ProviderRegistry {
        let mut registry = ProviderRegistry::new()
            .with_provider(Arc::new(InjectedSigningProvider::new(Arc::clone(&grants))));

        if let Some(near) = &self.near_redirect {
            registry = registry.with_provider(Arc::new(NearRedirectSigningProvider::new(
                near.wallet_base_url.clone(),
                near.callback_url.clone(),
                near.state_secret.expose_secret().as_bytes().to_vec(),
                Arc::clone(&grants),
            )));
        }

        if let Some(project_id) = &self.walletconnect_project_id {
            registry = registry.with_provider(Arc::new(WalletConnectSigningProvider::new(
                ProjectId::from(project_id.as_str()),
                Arc::clone(&grants),
            )));
        }

        registry
    }
}

/// Read an env var, treating absent / empty / whitespace-only as unset.
fn non_empty_env(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(value) if !value.trim().is_empty() => Some(value),
        _ => None,
    }
}
