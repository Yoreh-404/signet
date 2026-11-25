//! Optional incumbent ledger. Installing empty tables does not
//! establish enrollment, accept a receipt, or grant access.
#![allow(dead_code)]

use crate::application_discovery::axon_v3_restore::{Reconciliation, RestoreInterlock};

pub(crate) const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS axon_v3_incumbent_activation (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    profile TEXT NOT NULL CHECK (profile = 'incumbent_v1'),
    application_db_id TEXT NOT NULL,
    client_db_id TEXT NOT NULL,
    organization_id TEXT NOT NULL,
    enrollment_id TEXT NOT NULL,
    signer_pin TEXT NOT NULL,
    policy_sha256 TEXT NOT NULL,
    policy_json TEXT NOT NULL,
    revision BIGINT NOT NULL CHECK (revision > 0),
    generation BIGINT NOT NULL CHECK (generation > 0),
    withdrawn INTEGER NOT NULL CHECK (withdrawn IN (0, 1)),
    accepted_jws TEXT,
    verified_at BIGINT
)";

/// Installed only with the dormant SQLite incumbent ledger. No code or
/// session bearer is stored: both lookups use their public/hash identities.
pub(crate) const CODE_PROVENANCE_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS axon_v3_incumbent_code_provenance (
    code_sha256 TEXT PRIMARY KEY NOT NULL,
    user_sha256 TEXT NOT NULL,
    session_public_id TEXT NOT NULL,
    application_db_id TEXT NOT NULL,
    client_db_id TEXT NOT NULL,
    enrollment_id TEXT NOT NULL,
    signer_pin TEXT NOT NULL,
    policy_sha256 TEXT NOT NULL,
    revision BIGINT NOT NULL CHECK (revision > 0),
    generation BIGINT NOT NULL CHECK (generation > 0),
    code_expires_at BIGINT NOT NULL
)";
/// Opt-in SQLite purpose index. No JWT, raw identity, or extra lifetime.
pub(crate) const ACCESS_PROOF_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS axon_v3_incumbent_access_proof (
    jti TEXT PRIMARY KEY NOT NULL,
    user_sha256 TEXT NOT NULL,
    session_public_id TEXT NOT NULL,
    application_db_id TEXT NOT NULL,
    profile_id TEXT NOT NULL,
    client_db_id TEXT NOT NULL,
    enrollment_id TEXT NOT NULL,
    signer_key_sha256 TEXT NOT NULL,
    issuer TEXT NOT NULL,
    audience TEXT NOT NULL,
    policy_sha256 TEXT NOT NULL,
    revision BIGINT NOT NULL,
    generation BIGINT NOT NULL,
    expires_at BIGINT NOT NULL
)";

#[cfg(all(feature = "sqlite", feature = "axon-incumbent-storage"))]
pub(super) fn install_schema(conn: &mut diesel::SqliteConnection) -> diesel::QueryResult<()> {
    use diesel::connection::SimpleConnection;

    conn.immediate_transaction(|conn| {
        for ddl in [SCHEMA, CODE_PROVENANCE_SCHEMA, ACCESS_PROOF_SCHEMA] {
            conn.batch_execute(ddl)?;
        }
        Ok(())
    })
}

/// Current row identity for future exact compare-and-set; this is not a grant.
#[derive(Clone, Copy)]
pub(crate) struct Version<'a> {
    pub(crate) digest: &'a str,
    pub(crate) revision: i64,
    pub(crate) generation: i64,
}

/// Keep the original operator gate alive across one prospective transaction.
/// This is not an approval to activate, or a standalone restore guarantee.
pub(crate) struct RestoreSnapshot<'a> {
    interlock: &'a RestoreInterlock,
    initial: Reconciliation,
}

impl<'a> RestoreSnapshot<'a> {
    pub(crate) fn capture(interlock: &'a RestoreInterlock) -> Option<Self> {
        Some(Self { interlock, initial: interlock.reconciled()? })
    }

    pub(crate) fn unchanged(&self) -> bool {
        self.interlock.reconciled().as_ref() == Some(&self.initial)
    }
}

// Private storage primitive: callers do not exist outside the fixture.
// Accepting a value here alone must never be treated as authorization.
#[cfg(all(feature = "sqlite", feature = "axon-incumbent-storage"))]
pub(crate) mod sqlite {
    use super::{RestoreInterlock, RestoreSnapshot, Version};
    use crate::application_discovery::{
        axon_v3_acceptance::VerifiedPolicy,
        incumbent_preflight::{IncumbentPin, approved_enrolled_signer},
    };
    use crate::db::SessionRecord;
    use diesel::{Connection, QueryResult, RunQueryDsl, SqliteConnection, result::Error,
        sql_query, sql_types::{BigInt, Text}};
    use diesel::OptionalExtension;

    use super::super::{authorization::load_sqlite_oidc_policy_snapshot_on_conn as load_policy_snapshot,
        authorization_codes::consume_sqlite_authorization_code_for_client_on_conn as consume_bound_code};

    type BackendConn = SqliteConnection;

    fn registry_select(sql: &'static str) -> &'static str { sql }
    pub(crate) fn registry_write_transaction<T, E: From<Error>>(
        conn: &mut BackendConn, f: impl FnOnce(&mut BackendConn) -> Result<T, E>,
    ) -> Result<T, E> { conn.immediate_transaction(f) }
    fn registry_read_transaction<T>(
        conn: &mut BackendConn, f: impl FnOnce(&mut BackendConn) -> QueryResult<T>,
    ) -> QueryResult<T> { conn.transaction(f) }

    include!("axon_v3_incumbent_registry.rs");

    include!("axon_v3_incumbent_exchange.rs");

}

#[cfg(all(feature = "postgres", feature = "axon-incumbent-storage"))]
pub(crate) mod postgres {
    use super::{RestoreInterlock, RestoreSnapshot, Version};
    use crate::application_discovery::{
        axon_v3_acceptance::VerifiedPolicy,
        incumbent_preflight::{IncumbentPin, approved_enrolled_signer},
    };
    use diesel::{Connection, OptionalExtension, PgConnection, QueryResult, RunQueryDsl,
        result::Error, sql_query, sql_types::{BigInt, Text}};

    type BackendConn = PgConnection;

    use crate::db::SessionRecord;
    use super::super::{authorization::load_postgres_oidc_policy_snapshot_on_conn as load_policy_snapshot,
        authorization_codes::consume_postgres_authorization_code_for_client_on_conn as consume_bound_code};

    // Prevent the exact application's binding, signer or client changing
    // between registry resolution and the end of its activation transaction.
    fn registry_select(sql: &str) -> String { format!("{sql} FOR SHARE OF a,o,d,b,c") }
    pub(crate) fn registry_write_transaction<T, E: From<Error>>(
        conn: &mut BackendConn, f: impl FnOnce(&mut BackendConn) -> Result<T, E>,
    ) -> Result<T, E> { conn.build_transaction().serializable().run(f) }
    fn registry_read_transaction<T>(
        conn: &mut BackendConn, f: impl FnOnce(&mut BackendConn) -> QueryResult<T>,
    ) -> QueryResult<T> { conn.build_transaction().repeatable_read().run(f) }

    include!("axon_v3_incumbent_registry.rs");
    include!("axon_v3_incumbent_exchange.rs");
}
