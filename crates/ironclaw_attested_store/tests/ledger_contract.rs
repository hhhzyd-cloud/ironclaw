//! Durable [`SigningLedger`] backends driven through the canonical
//! `ironclaw_attestation` contract cases (the broadcast-idempotency guard,
//! one-shot create, transition validation), proving the DB-level conditional
//! `UPDATE ... WHERE state = <from>` enforces the same state machine.

#![cfg(all(feature = "integration", feature = "contract-suite"))]

use ironclaw_attestation::ledger::contract;

#[cfg(feature = "libsql")]
mod libsql_backend {
    use super::*;
    use std::sync::Arc;

    use ironclaw_attested_store::LibSqlSigningLedger;

    async fn fresh() -> LibSqlSigningLedger {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("ledger.db");
        std::mem::forget(dir);
        let db = Arc::new(
            libsql::Builder::new_local(path)
                .build()
                .await
                .expect("build libsql db"),
        );
        let ledger = LibSqlSigningLedger::new(db);
        ledger.run_migrations().await.expect("migrate");
        ledger
    }

    #[tokio::test]
    async fn full_valid_sequence() {
        contract::full_valid_sequence(fresh().await).await;
    }
    #[tokio::test]
    async fn second_create_is_already_exists() {
        contract::second_create_is_already_exists(fresh().await).await;
    }
    #[tokio::test]
    async fn advance_missing_is_not_found() {
        contract::advance_missing_is_not_found(fresh().await).await;
    }
    #[tokio::test]
    async fn skip_forward_is_invalid() {
        contract::skip_forward_is_invalid(fresh().await).await;
    }
    #[tokio::test]
    async fn regression_is_invalid() {
        contract::regression_is_invalid(fresh().await).await;
    }
    #[tokio::test]
    async fn broadcast_idempotency_guard() {
        contract::broadcast_idempotency_guard(fresh().await).await;
    }
    #[tokio::test]
    async fn terminal_states_never_advance() {
        contract::terminal_states_never_advance(fresh().await).await;
    }
}

#[cfg(feature = "postgres")]
mod postgres_backend {
    use super::*;

    use deadpool_postgres::{Config, Runtime};
    use ironclaw_attested_store::PostgresSigningLedger;
    use tokio_postgres::NoTls;

    async fn fresh() -> Option<PostgresSigningLedger> {
        let url = std::env::var("ATTESTED_STORE_TEST_PG_URL").ok()?;
        let mut config = Config::new();
        config.url = Some(url);
        let pool = config
            .create_pool(Some(Runtime::Tokio1), NoTls)
            .expect("create pool");
        {
            let client = pool.get().await.expect("client");
            client
                .batch_execute("DROP TABLE IF EXISTS attested_signing_ledger")
                .await
                .expect("drop");
        }
        let ledger = PostgresSigningLedger::new(pool);
        ledger.run_migrations().await.expect("migrate");
        Some(ledger)
    }

    macro_rules! pg_case {
        ($name:ident) => {
            #[tokio::test]
            async fn $name() {
                let Some(ledger) = fresh().await else {
                    eprintln!(
                        "ATTESTED_STORE_TEST_PG_URL unset; skipping {}",
                        stringify!($name)
                    );
                    return;
                };
                contract::$name(ledger).await;
            }
        };
    }

    pg_case!(full_valid_sequence);
    pg_case!(second_create_is_already_exists);
    pg_case!(advance_missing_is_not_found);
    pg_case!(skip_forward_is_invalid);
    pg_case!(regression_is_invalid);
    pg_case!(broadcast_idempotency_guard);
    pg_case!(terminal_states_never_advance);
}
