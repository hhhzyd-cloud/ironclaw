//! Durable [`AttestedGateBindingStore`] backends with a write-through cache.
//!
//! The reborn resume port reads the authoritative binding **synchronously**
//! (inside the turn store's sync critical section, see
//! [`ironclaw_attested_runtime::SyncBindingRead`]). A durable store therefore
//! cannot block on DB I/O for that read. Each durable backend keeps an
//! in-memory cache that is:
//!
//! * hydrated from the table on construction (`load`), so bindings survive a
//!   restart, and
//! * write-through on every [`AttestedGateBindingStore::put`].
//!
//! The DB row is the source of truth; the cache is the sync read path. Bindings
//! are stored as a single JSON column and rows are never deleted (a re-`put`
//! upserts, matching the in-memory last-write-wins semantics).

#[cfg(any(feature = "postgres", feature = "libsql"))]
use std::collections::HashMap;
#[cfg(any(feature = "postgres", feature = "libsql"))]
use std::sync::Mutex;

#[cfg(any(feature = "postgres", feature = "libsql"))]
use async_trait::async_trait;
#[cfg(any(feature = "postgres", feature = "libsql"))]
use ironclaw_attested_runtime::{AttestedGateBinding, AttestedGateBindingStore, SyncBindingRead};
#[cfg(any(feature = "postgres", feature = "libsql"))]
use ironclaw_signing_provider::GateRef;

#[cfg(any(feature = "postgres", feature = "libsql"))]
use crate::error::StoreError;

#[cfg(any(feature = "postgres", feature = "libsql"))]
const SCHEMA: &str = "\
CREATE TABLE IF NOT EXISTS attested_gate_bindings (
    gate_ref     TEXT PRIMARY KEY,
    binding_json TEXT NOT NULL
);";

/// The write-through cache shared by both backends.
#[cfg(any(feature = "postgres", feature = "libsql"))]
#[derive(Default)]
struct BindingCache {
    inner: Mutex<HashMap<GateRef, AttestedGateBinding>>,
}

#[cfg(any(feature = "postgres", feature = "libsql"))]
impl BindingCache {
    fn insert(&self, gate_ref: GateRef, binding: AttestedGateBinding) {
        if let Ok(mut map) = self.inner.lock() {
            map.insert(gate_ref, binding);
        }
    }

    fn get(&self, gate_ref: &GateRef) -> Option<AttestedGateBinding> {
        self.inner
            .lock()
            .ok()
            .and_then(|map| map.get(gate_ref).cloned())
    }
}

// ---------------------------------------------------------------------------
// PostgreSQL
// ---------------------------------------------------------------------------

#[cfg(feature = "postgres")]
mod postgres {
    use super::*;
    use deadpool_postgres::Pool;

    /// Durable PostgreSQL [`AttestedGateBindingStore`] with a write-through cache.
    pub struct PostgresAttestedGateBindingStore {
        pool: Pool,
        cache: BindingCache,
    }

    impl PostgresAttestedGateBindingStore {
        /// Wrap a pool, run migrations, and hydrate the cache from the table.
        pub async fn connect(pool: Pool) -> Result<Self, StoreError> {
            let store = Self {
                pool,
                cache: BindingCache::default(),
            };
            store.run_migrations().await?;
            store.load().await?;
            Ok(store)
        }

        async fn run_migrations(&self) -> Result<(), StoreError> {
            let client = self.client().await?;
            client
                .batch_execute(SCHEMA)
                .await
                .map_err(StoreError::backend)
        }

        async fn load(&self) -> Result<(), StoreError> {
            let client = self.client().await?;
            let rows = client
                .query(
                    "SELECT gate_ref, binding_json FROM attested_gate_bindings",
                    &[],
                )
                .await
                .map_err(StoreError::backend)?;
            for row in rows {
                let gate_ref: String = row.get(0);
                let json: String = row.get(1);
                let binding: AttestedGateBinding =
                    serde_json::from_str(&json).map_err(StoreError::backend)?;
                self.cache.insert(GateRef::new(gate_ref), binding);
            }
            Ok(())
        }

        async fn client(&self) -> Result<deadpool_postgres::Object, StoreError> {
            self.pool.get().await.map_err(StoreError::backend)
        }
    }

    impl SyncBindingRead for PostgresAttestedGateBindingStore {
        fn get_sync(&self, gate_ref: &GateRef) -> Option<AttestedGateBinding> {
            self.cache.get(gate_ref)
        }
    }

    #[async_trait]
    impl AttestedGateBindingStore for PostgresAttestedGateBindingStore {
        async fn put(&self, gate_ref: GateRef, binding: AttestedGateBinding) {
            let json = match serde_json::to_string(&binding) {
                Ok(json) => json,
                Err(error) => {
                    tracing::error!(%error, "failed to serialize attested gate binding");
                    return;
                }
            };
            if let Ok(client) = self.client().await {
                if let Err(error) = client
                    .execute(
                        "INSERT INTO attested_gate_bindings (gate_ref, binding_json) \
                         VALUES ($1, $2) \
                         ON CONFLICT (gate_ref) DO UPDATE SET binding_json = EXCLUDED.binding_json",
                        &[&gate_ref.as_str(), &json],
                    )
                    .await
                {
                    tracing::error!(%error, "failed to persist attested gate binding");
                    return;
                }
            } else {
                return;
            }
            // Write-through only after the durable write succeeds.
            self.cache.insert(gate_ref, binding);
        }

        async fn get(&self, gate_ref: &GateRef) -> Option<AttestedGateBinding> {
            self.cache.get(gate_ref)
        }
    }
}

#[cfg(feature = "postgres")]
pub use postgres::PostgresAttestedGateBindingStore;

// ---------------------------------------------------------------------------
// libSQL
// ---------------------------------------------------------------------------

#[cfg(feature = "libsql")]
mod libsql_backend {
    use super::*;
    use std::sync::Arc;

    /// Durable libSQL [`AttestedGateBindingStore`] with a write-through cache.
    pub struct LibSqlAttestedGateBindingStore {
        db: Arc<libsql::Database>,
        cache: BindingCache,
    }

    impl LibSqlAttestedGateBindingStore {
        /// Wrap a db handle, run migrations, and hydrate the cache.
        pub async fn connect(db: Arc<libsql::Database>) -> Result<Self, StoreError> {
            let store = Self {
                db,
                cache: BindingCache::default(),
            };
            store.run_migrations().await?;
            store.load().await?;
            Ok(store)
        }

        async fn run_migrations(&self) -> Result<(), StoreError> {
            let conn = self.connect_db().await?;
            conn.execute_batch(SCHEMA)
                .await
                .map_err(StoreError::backend)?;
            Ok(())
        }

        async fn load(&self) -> Result<(), StoreError> {
            let conn = self.connect_db().await?;
            let mut rows = conn
                .query(
                    "SELECT gate_ref, binding_json FROM attested_gate_bindings",
                    (),
                )
                .await
                .map_err(StoreError::backend)?;
            while let Some(row) = rows.next().await.map_err(StoreError::backend)? {
                let gate_ref: String = row.get(0).map_err(StoreError::backend)?;
                let json: String = row.get(1).map_err(StoreError::backend)?;
                let binding: AttestedGateBinding =
                    serde_json::from_str(&json).map_err(StoreError::backend)?;
                self.cache.insert(GateRef::new(gate_ref), binding);
            }
            Ok(())
        }

        async fn connect_db(&self) -> Result<libsql::Connection, StoreError> {
            let conn = self.db.connect().map_err(StoreError::backend)?;
            conn.query("PRAGMA busy_timeout = 5000", ())
                .await
                .map_err(StoreError::backend)?;
            Ok(conn)
        }
    }

    impl SyncBindingRead for LibSqlAttestedGateBindingStore {
        fn get_sync(&self, gate_ref: &GateRef) -> Option<AttestedGateBinding> {
            self.cache.get(gate_ref)
        }
    }

    #[async_trait]
    impl AttestedGateBindingStore for LibSqlAttestedGateBindingStore {
        async fn put(&self, gate_ref: GateRef, binding: AttestedGateBinding) {
            let json = match serde_json::to_string(&binding) {
                Ok(json) => json,
                Err(error) => {
                    tracing::error!(%error, "failed to serialize attested gate binding");
                    return;
                }
            };
            let conn = match self.connect_db().await {
                Ok(conn) => conn,
                Err(error) => {
                    tracing::error!(%error, "failed to open libsql connection for binding put");
                    return;
                }
            };
            if let Err(error) = conn
                .execute(
                    "INSERT INTO attested_gate_bindings (gate_ref, binding_json) \
                     VALUES (?1, ?2) \
                     ON CONFLICT (gate_ref) DO UPDATE SET binding_json = excluded.binding_json",
                    libsql::params![gate_ref.as_str(), json],
                )
                .await
            {
                tracing::error!(%error, "failed to persist attested gate binding");
                return;
            }
            self.cache.insert(gate_ref, binding);
        }

        async fn get(&self, gate_ref: &GateRef) -> Option<AttestedGateBinding> {
            self.cache.get(gate_ref)
        }
    }
}

#[cfg(feature = "libsql")]
pub use libsql_backend::LibSqlAttestedGateBindingStore;
