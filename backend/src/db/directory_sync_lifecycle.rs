use super::{
    DIRECTORY_SYNC_LEASE_TTL_SECONDS, Db, DirectorySyncCheckpointRecord, DirectorySyncRunRecord,
    DirectorySyncRunUpdate, blocking, ph,
};
use crate::{
    config::DatabaseKind,
    error::{AppError, AppResult},
    util,
};
use diesel::sql_types::{BigInt, Integer, Nullable, Text};
use diesel::{Connection, OptionalExtension, RunQueryDsl, sql_query};

impl Db {
    pub async fn start_directory_sync_run(
        &self,
        application_id: &str,
        provider_id: &str,
    ) -> AppResult<DirectorySyncRunRecord> {
        let application_id = application_id.to_string();
        let provider_id = provider_id.to_string();
        let run_id = uuid::Uuid::new_v4().to_string();
        let now = util::now_ts();
        let expires_at = now + DIRECTORY_SYNC_LEASE_TTL_SECONDS;
        with_conn!(self, |conn, kind| {
            conn.transaction::<DirectorySyncRunRecord, AppError, _>(|conn| {
                // The lease row is the concurrency boundary.  A check-then-
                // insert on directory_sync_runs is racy under PostgreSQL and
                // MySQL's default isolation: two workers can both observe no
                // running row.  First reclaim only an expired lease with a
                // compare-and-set update, then attempt the unique-key insert
                // for a previously unseen pair.
                let abandon_sql = format!(
                    "UPDATE directory_sync_runs SET status = 'failed', error = {}, finished_at = {} WHERE status = 'running' AND id IN (SELECT owner_run_id FROM directory_sync_leases WHERE application_id = {} AND provider_id = {} AND expires_at < {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5)
                );
                sql_query(abandon_sql)
                    .bind::<Nullable<Text>, _>(Some(
                        "directory synchronization lease expired".to_string(),
                    ))
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&application_id)
                    .bind::<Text, _>(&provider_id)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let reclaim_sql = format!(
                    "UPDATE directory_sync_leases SET owner_run_id = {}, acquired_at = {}, heartbeat_at = {}, expires_at = {} WHERE application_id = {} AND provider_id = {} AND expires_at < {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                    ph(kind, 6),
                    ph(kind, 7)
                );
                let reclaimed = sql_query(reclaim_sql)
                    .bind::<Text, _>(&run_id)
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(expires_at)
                    .bind::<Text, _>(&application_id)
                    .bind::<Text, _>(&provider_id)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                if reclaimed == 0 {
                    let insert_lease_sql = format!(
                        "INSERT INTO directory_sync_leases (application_id, provider_id, owner_run_id, acquired_at, heartbeat_at, expires_at) VALUES ({}, {}, {}, {}, {}, {})",
                        ph(kind, 1),
                        ph(kind, 2),
                        ph(kind, 3),
                        ph(kind, 4),
                        ph(kind, 5),
                        ph(kind, 6)
                    );
                    let insert_result = sql_query(insert_lease_sql)
                        .bind::<Text, _>(&application_id)
                        .bind::<Text, _>(&provider_id)
                        .bind::<Text, _>(&run_id)
                        .bind::<BigInt, _>(now)
                        .bind::<BigInt, _>(now)
                        .bind::<BigInt, _>(expires_at)
                        .execute(conn);
                    match insert_result {
                        Ok(_) => {}
                        Err(diesel::result::Error::DatabaseError(
                            diesel::result::DatabaseErrorKind::UniqueViolation,
                            _,
                        )) => {
                            return Err(AppError::BadRequest(
                                "directory synchronization is already running".to_string(),
                            ));
                        }
                        Err(error) => return Err(AppError::from(error)),
                    }
                }
                let insert_sql = format!(
                    "INSERT INTO directory_sync_runs (id, application_id, provider_id, status, total_seen, created_count, updated_count, disabled_count, error, cursor, started_at, finished_at) VALUES ({}, {}, {}, 'running', 0, 0, 0, 0, {}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                    ph(kind, 6),
                    ph(kind, 7)
                );
                sql_query(insert_sql)
                    .bind::<Text, _>(&run_id)
                    .bind::<Text, _>(&application_id)
                    .bind::<Text, _>(&provider_id)
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<BigInt, _>(now)
                    .bind::<Nullable<BigInt>, _>(None::<i64>)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let select_sql = format!(
                    "SELECT id, application_id, provider_id, status, total_seen, created_count, updated_count, disabled_count, error, cursor, started_at, finished_at FROM directory_sync_runs WHERE id = {}",
                    ph(kind, 1)
                );
                sql_query(select_sql)
                    .bind::<Text, _>(&run_id)
                    .get_result::<DirectorySyncRunRecord>(conn)
                    .map_err(AppError::from)
            })
        })
    }

    pub async fn finish_directory_sync_run(
        &self,
        update: DirectorySyncRunUpdate<'_>,
    ) -> AppResult<DirectorySyncRunRecord> {
        let run_id = update.run_id.to_string();
        let status = update.status.to_string();
        let total_seen = update.total_seen;
        let created_count = update.created_count;
        let updated_count = update.updated_count;
        let disabled_count = update.disabled_count;
        let error = update.error;
        let cursor = update.cursor;
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<DirectorySyncRunRecord, AppError, _>(|conn| {
                let update_sql = format!(
                    "UPDATE directory_sync_runs SET status = {}, total_seen = {}, created_count = {}, updated_count = {}, disabled_count = {}, error = {}, cursor = {}, finished_at = {} WHERE id = {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                    ph(kind, 6),
                    ph(kind, 7),
                    ph(kind, 8),
                    ph(kind, 9)
                );
                let affected = sql_query(update_sql)
                    .bind::<Text, _>(&status)
                    .bind::<BigInt, _>(total_seen)
                    .bind::<BigInt, _>(created_count)
                    .bind::<BigInt, _>(updated_count)
                    .bind::<BigInt, _>(disabled_count)
                    .bind::<Nullable<Text>, _>(error)
                    .bind::<Nullable<Text>, _>(cursor)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&run_id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                if affected == 0 {
                    return Err(AppError::NotFound);
                }
                let release_sql = format!(
                    "DELETE FROM directory_sync_leases WHERE owner_run_id = {}",
                    ph(kind, 1)
                );
                sql_query(release_sql)
                    .bind::<Text, _>(&run_id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let select_sql = format!(
                    "SELECT id, application_id, provider_id, status, total_seen, created_count, updated_count, disabled_count, error, cursor, started_at, finished_at FROM directory_sync_runs WHERE id = {}",
                    ph(kind, 1)
                );
                sql_query(select_sql)
                    .bind::<Text, _>(&run_id)
                    .get_result::<DirectorySyncRunRecord>(conn)
                    .map_err(AppError::from)
            })
        })
    }

    /// Renews a directory-sync lease only for its current owner.  A stale
    /// worker must fail closed after another worker reclaimed the lease.
    pub async fn renew_directory_sync_lease(
        &self,
        application_id: &str,
        provider_id: &str,
        run_id: &str,
    ) -> AppResult<()> {
        let application_id = application_id.to_string();
        let provider_id = provider_id.to_string();
        let run_id = run_id.to_string();
        let now = util::now_ts();
        let expires_at = now + DIRECTORY_SYNC_LEASE_TTL_SECONDS;
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE directory_sync_leases SET heartbeat_at = {}, expires_at = {} WHERE application_id = {} AND provider_id = {} AND owner_run_id = {} AND expires_at >= {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6)
            );
            let affected = sql_query(sql)
                .bind::<BigInt, _>(now)
                .bind::<BigInt, _>(expires_at)
                .bind::<Text, _>(&application_id)
                .bind::<Text, _>(&provider_id)
                .bind::<Text, _>(&run_id)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            if affected != 1 {
                return Err(AppError::BadRequest(
                    "directory synchronization lease was lost".to_string(),
                ));
            }
            Ok(())
        })
    }

    pub async fn list_directory_sync_runs(
        &self,
        application_id: &str,
        limit: i64,
    ) -> AppResult<Vec<DirectorySyncRunRecord>> {
        let application_id = application_id.to_string();
        let limit = limit.clamp(1, 100);
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT id, application_id, provider_id, status, total_seen, created_count, updated_count, disabled_count, error, cursor, started_at, finished_at FROM directory_sync_runs WHERE application_id = {} ORDER BY started_at DESC LIMIT {limit}",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(application_id)
                .load::<DirectorySyncRunRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }
    pub async fn find_directory_sync_checkpoint(
        &self,
        application_id: &str,
        provider_id: &str,
    ) -> AppResult<Option<DirectorySyncCheckpointRecord>> {
        let application_id = application_id.to_string();
        let provider_id = provider_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT application_id, provider_id, cursor, last_success_at, consecutive_failures, updated_at FROM directory_sync_checkpoints WHERE application_id = {} AND provider_id = {}",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<Text, _>(application_id)
                .bind::<Text, _>(provider_id)
                .get_result::<DirectorySyncCheckpointRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn record_directory_sync_checkpoint(
        &self,
        application_id: &str,
        provider_id: &str,
        cursor: Option<String>,
        success: bool,
    ) -> AppResult<DirectorySyncCheckpointRecord> {
        let application_id = application_id.to_string();
        let provider_id = provider_id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let existing_sql = format!(
                "SELECT application_id, provider_id, cursor, last_success_at, consecutive_failures, updated_at FROM directory_sync_checkpoints WHERE application_id = {} AND provider_id = {}",
                ph(kind, 1),
                ph(kind, 2)
            );
            let existing = sql_query(existing_sql)
                .bind::<Text, _>(&application_id)
                .bind::<Text, _>(&provider_id)
                .get_result::<DirectorySyncCheckpointRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)?;
            let failures = if success {
                0
            } else {
                existing
                    .as_ref()
                    .map(|record| record.consecutive_failures.saturating_add(1))
                    .unwrap_or(1)
            };
            let last_success_at = if success {
                now
            } else {
                existing
                    .as_ref()
                    .map(|record| record.last_success_at)
                    .unwrap_or(0)
            };
            let next_cursor = if success {
                cursor
            } else {
                existing.as_ref().and_then(|record| record.cursor.clone())
            };
            if existing.is_some() {
                let update_sql = format!(
                    "UPDATE directory_sync_checkpoints SET cursor = {}, last_success_at = {}, consecutive_failures = {}, updated_at = {} WHERE application_id = {} AND provider_id = {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                    ph(kind, 6)
                );
                sql_query(update_sql)
                    .bind::<Nullable<Text>, _>(next_cursor)
                    .bind::<BigInt, _>(last_success_at)
                    .bind::<Integer, _>(failures)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&application_id)
                    .bind::<Text, _>(&provider_id)
                    .execute(&mut conn)
                    .map_err(AppError::from)?;
            } else {
                let insert_sql = format!(
                    "INSERT INTO directory_sync_checkpoints (application_id, provider_id, cursor, last_success_at, consecutive_failures, updated_at) VALUES ({}, {}, {}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                    ph(kind, 6)
                );
                sql_query(insert_sql)
                    .bind::<Text, _>(&application_id)
                    .bind::<Text, _>(&provider_id)
                    .bind::<Nullable<Text>, _>(next_cursor)
                    .bind::<BigInt, _>(last_success_at)
                    .bind::<Integer, _>(failures)
                    .bind::<BigInt, _>(now)
                    .execute(&mut conn)
                    .map_err(AppError::from)?;
            }
            let select_sql = format!(
                "SELECT application_id, provider_id, cursor, last_success_at, consecutive_failures, updated_at FROM directory_sync_checkpoints WHERE application_id = {} AND provider_id = {}",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(select_sql)
                .bind::<Text, _>(&application_id)
                .bind::<Text, _>(&provider_id)
                .get_result::<DirectorySyncCheckpointRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }
}
