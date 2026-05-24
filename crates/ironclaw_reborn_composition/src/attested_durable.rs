//! Durable attested-signing composition assembly (attested-signing PR13).
//!
//! Closes Gap 2: the durable [`RebornAttestedComposition`] monomorphizations
//! (`PostgresAttestedComposition` / `LibSqlAttestedComposition`, added in PR12)
//! are now assembled from a production DB handle + RPC config through a single
//! reusable, tested seam — instead of only existing as a type alias and a test.
//!
//! ## Backend selection
//!
//! Backend choice mirrors every other reborn store: it follows the configured
//! database backend. The composition root calls [`assemble_libsql`] when the
//! durable storage is libSQL/Turso and [`assemble_postgres`] when it is
//! PostgreSQL. Both build the identical security envelope (shared sealed-grant
//! store for the one-shot CAS — threat #1; shared signing ledger for the
//! broadcast-idempotency guard — threats #6 / #7); only the persistence backend
//! differs.
//!
//! ## Production runtime wiring (deferred)
//!
//! These helpers are the assembly seam the production runtime slice will call.
//! `RebornRuntime` itself is still local-dev only (`build_reborn_runtime`
//! rejects non-local-dev profiles, and the CLI bails before reaching it), so
//! the production *runtime* entrypoint that consumes these helpers — and the
//! decision to erase `RebornRuntime.attested_signing` behind a trait/enum so it
//! can hold a durable monomorphization — lands with that slice. Until then this
//! is a config-explicit, dual-backend-tested seam, not dead-by-design code:
//! `build_attested_composition` already registers the same providers in
//! local-dev, and these helpers prove the durable backends assemble cleanly.
//!
//! ## Fail-closed
//!
//! Every RPC endpoint and every provider is independently fail-closed: an
//! unconfigured chain family cannot broadcast (the [`MultiChainBroadcaster`]
//! returns an error), and an unconfigured provider stays unregistered
//! (`ProviderMismatch`). No permissive defaults.

#![cfg(all(
    feature = "attested-broadcast",
    any(feature = "libsql", feature = "postgres")
))]

use std::sync::Arc;

use ironclaw_attested_runtime::{ContinuationError, CustodialMainnetShipGate};
use ironclaw_attested_store::{ChainRpcEndpoints, MultiChainBroadcaster};
use ironclaw_chain_signing::{SecretsKeyStore, ShipGate};

use crate::attested::RebornAttestedComposition;
use crate::attested_config::AttestedProvidersConfig;

/// Env var holding the EVM JSON-RPC URL used to broadcast signed EVM txs.
pub const EVM_RPC_URL_ENV: &str = "ATTESTED_EVM_RPC_URL";
/// Env var holding the Solana JSON-RPC URL.
pub const SOLANA_RPC_URL_ENV: &str = "ATTESTED_SOLANA_RPC_URL";
/// Env var holding the NEAR JSON-RPC URL.
pub const NEAR_RPC_URL_ENV: &str = "ATTESTED_NEAR_RPC_URL";

/// Resolve per-chain broadcast RPC endpoints from the environment, fail-closed:
/// an absent / empty var leaves that chain family unconfigured, so a broadcast
/// for it fails closed (no submission) rather than hitting a default endpoint.
pub fn chain_rpc_endpoints_from_env() -> ChainRpcEndpoints {
    ChainRpcEndpoints {
        evm: non_empty_env(EVM_RPC_URL_ENV),
        solana: non_empty_env(SOLANA_RPC_URL_ENV),
        near: non_empty_env(NEAR_RPC_URL_ENV),
    }
}

fn non_empty_env(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(value) if !value.trim().is_empty() => Some(value),
        _ => None,
    }
}

/// Validate the configured RPC endpoints (scheme/host) before they reach the
/// broadcaster, which otherwise stores the URL string verbatim and only fails
/// at first broadcast. A present endpoint must be a well-formed http(s) URL
/// with a host, and must not target a loopback / link-local / cloud-metadata
/// host (SSRF / credential-exfil hardening): an attacker-influenced "RPC URL"
/// pointing at `169.254.169.254` or `localhost` could otherwise be used to
/// probe internal services with the signed-payload POST.
///
/// `None` endpoints stay `None` (that chain family is simply unconfigured and
/// fails closed at broadcast time).
fn validated_endpoints(
    endpoints: ChainRpcEndpoints,
) -> Result<ChainRpcEndpoints, ContinuationError> {
    Ok(ChainRpcEndpoints {
        evm: validate_optional_rpc_url("evm", endpoints.evm)?,
        solana: validate_optional_rpc_url("solana", endpoints.solana)?,
        near: validate_optional_rpc_url("near", endpoints.near)?,
    })
}

fn validate_optional_rpc_url(
    family: &str,
    raw: Option<String>,
) -> Result<Option<String>, ContinuationError> {
    match raw {
        None => Ok(None),
        Some(value) => {
            let trimmed = value.trim();
            let parsed = url::Url::parse(trimmed).map_err(|_| ContinuationError::Broadcast {
                reason: format!("{family} RPC URL is not a valid URL"),
            })?;
            match parsed.scheme() {
                "http" | "https" => {}
                _ => {
                    return Err(ContinuationError::Broadcast {
                        reason: format!("{family} RPC URL must be http(s)"),
                    });
                }
            }
            let host = parsed
                .host_str()
                .filter(|host| !host.is_empty())
                .ok_or_else(|| ContinuationError::Broadcast {
                    reason: format!("{family} RPC URL must have a host"),
                })?;
            if is_internal_host(host) {
                return Err(ContinuationError::Broadcast {
                    reason: format!("{family} RPC URL targets a disallowed internal/metadata host"),
                });
            }
            Ok(Some(trimmed.to_string()))
        }
    }
}

/// Reject loopback, link-local, and cloud-metadata hosts. Uses conservative
/// literal and IP-prefix matching (no DNS resolution — that would be a TOCTOU
/// window and a network call at assembly time).
fn is_internal_host(host: &str) -> bool {
    let host = host.trim_matches(['[', ']']).to_ascii_lowercase();
    if host == "localhost"
        || host.ends_with(".localhost")
        || host == "metadata"
        || host == "metadata.google.internal"
    {
        return true;
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => {
                v4.is_loopback()
                    || v4.is_link_local()
                    || v4.is_unspecified()
                    || v4.octets() == [169, 254, 169, 254]
            }
            std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
        };
    }
    false
}

/// The custodial keystore + operator ship-gate the durable composition signs
/// under. Built by the composition root from the production master key (the
/// durable secret store / KMS); the ship-gate reads `CUSTODIAL_MAINNET_ENABLED`
/// (fail-closed for mainnet).
pub struct DurableCustody {
    pub keystore: Arc<SecretsKeyStore>,
    pub ship_gate: ShipGate,
}

impl DurableCustody {
    /// Build from a custodial keystore. The ship-gate reads
    /// `CUSTODIAL_MAINNET_ENABLED` and is given no KMS backend here (the
    /// production slice supplies one); mainnet custodial signing stays refused
    /// until secure custody is wired (threat #18).
    pub fn from_keystore(keystore: Arc<SecretsKeyStore>) -> Self {
        Self {
            keystore,
            ship_gate: CustodialMainnetShipGate::from_env().build_chain_ship_gate(None),
        }
    }
}

#[cfg(feature = "libsql")]
mod libsql_assembly {
    use super::*;
    use crate::attested::LibSqlAttestedComposition;
    use ironclaw_attested_store::{
        LibSqlAttestedGateBindingStore, LibSqlSealedGrantStore, LibSqlSigningLedger,
    };

    /// Assemble the durable libSQL / Turso attested-signing composition over a
    /// libSQL database handle. Runs the grant + ledger + binding migrations,
    /// builds the **durable** gate-binding store (so the authoritative
    /// resume/driver binding survives a restart — it is not an in-memory store
    /// while grant/ledger are durable), validates + builds the real per-chain
    /// broadcaster from `endpoints`, and registers the external-wallet
    /// providers from `providers`.
    ///
    /// The binding store is built here (typed) rather than accepted as an
    /// `Arc<dyn AttestedGateBindingStore>`, which is what closes the
    /// "durable assembly accepts an in-memory binding store" gap: a caller
    /// cannot hand this path an `InMemoryAttestedGateBindingStore`.
    pub async fn assemble_libsql(
        db: Arc<libsql::Database>,
        custody: DurableCustody,
        endpoints: ChainRpcEndpoints,
        providers: AttestedProvidersConfig,
    ) -> Result<LibSqlAttestedComposition, ContinuationError> {
        // Durable, restart-surviving gate-binding store (runs its own migration
        // + hydrates its sync-read cache in `connect`).
        let bindings = Arc::new(
            LibSqlAttestedGateBindingStore::connect(Arc::clone(&db))
                .await
                .map_err(|error| ContinuationError::Broadcast {
                    reason: format!("libsql attested gate-binding store: {error}"),
                })?,
        );

        let grants = Arc::new(LibSqlSealedGrantStore::new(Arc::clone(&db)));
        grants
            .run_migrations()
            .await
            .map_err(|error| ContinuationError::Broadcast {
                reason: format!("libsql grant store migration: {error}"),
            })?;
        let ledger = Arc::new(LibSqlSigningLedger::new(Arc::clone(&db)));
        ledger
            .run_migrations()
            .await
            .map_err(|error| ContinuationError::Broadcast {
                reason: format!("libsql signing ledger migration: {error}"),
            })?;

        let endpoints = validated_endpoints(endpoints)?;
        let broadcaster = Arc::new(MultiChainBroadcaster::from_endpoints(endpoints)?);
        let registry = providers.build_provider_registry(
            Arc::clone(&grants) as Arc<dyn ironclaw_attestation::SealedGrantStore>
        );

        Ok(RebornAttestedComposition::assemble(
            bindings as Arc<dyn ironclaw_attested_runtime::AttestedGateBindingStore>,
            custody.keystore,
            custody.ship_gate,
            grants,
            ledger,
            broadcaster,
            registry,
        ))
    }
}

#[cfg(feature = "libsql")]
pub use libsql_assembly::assemble_libsql;

#[cfg(feature = "postgres")]
mod postgres_assembly {
    use super::*;
    use crate::attested::PostgresAttestedComposition;
    use ironclaw_attested_store::{
        PostgresAttestedGateBindingStore, PostgresSealedGrantStore, PostgresSigningLedger,
    };

    /// Assemble the durable PostgreSQL attested-signing composition over a
    /// connection pool.
    ///
    /// Runs the idempotent attested grant / ledger / binding PG migrations
    /// (mirroring `assemble_libsql`) so the composition does not assemble OK and
    /// then fail on the first seal / ledger advance / binding write. Builds the
    /// **durable** gate-binding store (typed, not an arbitrary
    /// `Arc<dyn AttestedGateBindingStore>`), so the authoritative
    /// resume/driver binding cannot silently be in-memory while grant/ledger are
    /// durable. Validates + builds the real per-chain broadcaster from
    /// `endpoints` and registers the external-wallet providers from `providers`.
    pub async fn assemble_postgres(
        pool: deadpool_postgres::Pool,
        custody: DurableCustody,
        endpoints: ChainRpcEndpoints,
        providers: AttestedProvidersConfig,
    ) -> Result<PostgresAttestedComposition, ContinuationError> {
        // Durable, restart-surviving gate-binding store (runs its own migration
        // + hydrates its sync-read cache in `connect`).
        let bindings = Arc::new(
            PostgresAttestedGateBindingStore::connect(pool.clone())
                .await
                .map_err(|error| ContinuationError::Broadcast {
                    reason: format!("postgres attested gate-binding store: {error}"),
                })?,
        );

        let grants = Arc::new(PostgresSealedGrantStore::new(pool.clone()));
        grants
            .run_migrations()
            .await
            .map_err(|error| ContinuationError::Broadcast {
                reason: format!("postgres grant store migration: {error}"),
            })?;
        let ledger = Arc::new(PostgresSigningLedger::new(pool));
        ledger
            .run_migrations()
            .await
            .map_err(|error| ContinuationError::Broadcast {
                reason: format!("postgres signing ledger migration: {error}"),
            })?;

        let endpoints = validated_endpoints(endpoints)?;
        let broadcaster = Arc::new(MultiChainBroadcaster::from_endpoints(endpoints)?);
        let registry = providers.build_provider_registry(
            Arc::clone(&grants) as Arc<dyn ironclaw_attestation::SealedGrantStore>
        );

        Ok(RebornAttestedComposition::assemble(
            bindings as Arc<dyn ironclaw_attested_runtime::AttestedGateBindingStore>,
            custody.keystore,
            custody.ship_gate,
            grants,
            ledger,
            broadcaster,
            registry,
        ))
    }
}

#[cfg(feature = "postgres")]
pub use postgres_assembly::assemble_postgres;
