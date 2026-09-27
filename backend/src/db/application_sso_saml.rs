//! Persistence for application-scoped SAML replay, browser handoff, and sessions.

use super::{
    AppError, AppResult, ApplicationSamlInteractionRecord, ApplicationSamlSessionRecord,
    DatabaseKind, Db, NewApplicationSamlInteraction, NewApplicationSamlSession, bind_text_list,
    blocking, ph, placeholders, select_application_saml_interaction_sql,
    select_application_saml_session_sql,
};
use crate::util;
use diesel::{
    Connection, OptionalExtension, RunQueryDsl, sql_query,
    sql_types::{BigInt, Nullable, Text},
};
use std::sync::atomic::{AtomicI64, Ordering};

// Replay reclamation for the key being claimed belongs to the atomic claim
// statement itself. Full-table expiry cleanup is maintenance only, so keep it
// off the authentication hot path and let at most one call per process/minute
// attempt it. Multi-replica deployments may run one cleanup per replica; the
// expiry index keeps that bounded and cleanup failure never changes the replay
// decision that has already been made.
static SAML_REPLAY_LAST_PURGE_AT: AtomicI64 = AtomicI64::new(0);
const SAML_REPLAY_PURGE_INTERVAL_SECONDS: i64 = 60;

impl Db {
    pub async fn claim_application_saml_replay(
        &self,
        replay_key: &str,
        application_id: &str,
        expires_at: i64,
    ) -> AppResult<bool> {
        let replay_key = replay_key.to_string();
        let application_id = application_id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let claimed = match kind {
                DatabaseKind::Mysql => {
                    let insert_sql = format!(
                        "INSERT IGNORE INTO application_saml_replays (replay_key, application_id, expires_at, created_at) VALUES ({}, {}, {}, {})",
                        ph(kind, 1),
                        ph(kind, 2),
                        ph(kind, 3),
                        ph(kind, 4),
                    );
                    let inserted = sql_query(insert_sql)
                        .bind::<Text, _>(&replay_key)
                        .bind::<Text, _>(&application_id)
                        .bind::<BigInt, _>(expires_at)
                        .bind::<BigInt, _>(now)
                        .execute(&mut conn)
                        .map_err(AppError::from)?;
                    if inserted == 1 {
                        true
                    } else {
                        // MySQL lacks PostgreSQL/SQLite's conflict-WHERE form.
                        // Reclaim only this expired key; concurrent contenders
                        // serialize on the primary-key row and exactly one can
                        // move it back to a future expiry.
                        let reclaim_sql = format!(
                            "UPDATE application_saml_replays SET application_id = {}, expires_at = {}, created_at = {} WHERE replay_key = {} AND expires_at <= {}",
                            ph(kind, 1),
                            ph(kind, 2),
                            ph(kind, 3),
                            ph(kind, 4),
                            ph(kind, 5),
                        );
                        sql_query(reclaim_sql)
                            .bind::<Text, _>(&application_id)
                            .bind::<BigInt, _>(expires_at)
                            .bind::<BigInt, _>(now)
                            .bind::<Text, _>(&replay_key)
                            .bind::<BigInt, _>(now)
                            .execute(&mut conn)
                            .map_err(AppError::from)?
                            == 1
                    }
                }
                DatabaseKind::Sqlite | DatabaseKind::Postgres => {
                    let sql = format!(
                        "INSERT INTO application_saml_replays (replay_key, application_id, expires_at, created_at) VALUES ({}, {}, {}, {}) ON CONFLICT (replay_key) DO UPDATE SET application_id = excluded.application_id, expires_at = excluded.expires_at, created_at = excluded.created_at WHERE application_saml_replays.expires_at <= {}",
                        ph(kind, 1),
                        ph(kind, 2),
                        ph(kind, 3),
                        ph(kind, 4),
                        ph(kind, 5),
                    );
                    sql_query(sql)
                        .bind::<Text, _>(&replay_key)
                        .bind::<Text, _>(&application_id)
                        .bind::<BigInt, _>(expires_at)
                        .bind::<BigInt, _>(now)
                        .bind::<BigInt, _>(now)
                        .execute(&mut conn)
                        .map_err(AppError::from)?
                        == 1
                }
            };

            if saml_replay_purge_due(now) {
                let cleanup_sql = format!(
                    "DELETE FROM application_saml_replays WHERE expires_at <= {}",
                    ph(kind, 1)
                );
                if let Err(error) = sql_query(cleanup_sql)
                    .bind::<BigInt, _>(now)
                    .execute(&mut conn)
                {
                    tracing::warn!(error = %error, "expired SAML replay cleanup failed");
                }
            }
            Ok(claimed)
        })
    }

    pub async fn insert_application_saml_interaction(
        &self,
        interaction: NewApplicationSamlInteraction,
    ) -> AppResult<()> {
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "INSERT INTO application_saml_interactions (handle_hash, application_id, request_id, sp_entity_id, acs_url, relay_state, response_binding, expires_at, created_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
                ph(kind, 7),
                ph(kind, 8),
                ph(kind, 9),
            );
            sql_query(sql)
                .bind::<Text, _>(interaction.handle_hash)
                .bind::<Text, _>(interaction.application_id)
                .bind::<Text, _>(interaction.request_id)
                .bind::<Text, _>(interaction.sp_entity_id)
                .bind::<Text, _>(interaction.acs_url)
                .bind::<Nullable<Text>, _>(interaction.relay_state)
                .bind::<Text, _>(interaction.response_binding)
                .bind::<BigInt, _>(interaction.expires_at)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    /// Consumes a pending SAML browser handoff atomically.  An expired,
    /// unknown, cross-application, or already-consumed handle is indistinguishable
    /// to the caller and returns Unauthorized.
    pub async fn consume_application_saml_interaction(
        &self,
        handle_hash: &str,
        application_id: &str,
    ) -> AppResult<ApplicationSamlInteractionRecord> {
        let handle_hash = handle_hash.to_string();
        let application_id = application_id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<ApplicationSamlInteractionRecord, AppError, _>(|conn| {
                let select_sql = format!(
                    "{} WHERE handle_hash = {} AND application_id = {} AND expires_at > {}",
                    select_application_saml_interaction_sql(),
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                );
                let record = sql_query(select_sql)
                    .bind::<Text, _>(&handle_hash)
                    .bind::<Text, _>(&application_id)
                    .bind::<BigInt, _>(now)
                    .get_result::<ApplicationSamlInteractionRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                    .ok_or(AppError::Unauthorized)?;
                let delete_sql = format!(
                    "DELETE FROM application_saml_interactions WHERE handle_hash = {} AND application_id = {} AND expires_at > {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                );
                let affected = sql_query(delete_sql)
                    .bind::<Text, _>(&handle_hash)
                    .bind::<Text, _>(&application_id)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                if affected != 1 {
                    return Err(AppError::Unauthorized);
                }
                Ok(record)
            })
        })
    }

    pub async fn insert_application_saml_session(
        &self,
        session: NewApplicationSamlSession,
    ) -> AppResult<()> {
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "INSERT INTO application_saml_sessions (session_index_hash, application_id, user_id, signet_session_id, name_id_hash, expires_at, created_at) VALUES ({}, {}, {}, {}, {}, {}, {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
                ph(kind, 7),
            );
            sql_query(sql)
                .bind::<Text, _>(session.session_index_hash)
                .bind::<Text, _>(session.application_id)
                .bind::<Text, _>(session.user_id)
                .bind::<Text, _>(session.signet_session_id)
                .bind::<Text, _>(session.name_id_hash)
                .bind::<BigInt, _>(session.expires_at)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    pub async fn find_application_saml_session(
        &self,
        session_index_hash: &str,
        application_id: &str,
    ) -> AppResult<Option<ApplicationSamlSessionRecord>> {
        let session_index_hash = session_index_hash.to_string();
        let application_id = application_id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE session_index_hash = {} AND application_id = {} AND expires_at > {}",
                select_application_saml_session_sql(),
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
            );
            sql_query(sql)
                .bind::<Text, _>(session_index_hash)
                .bind::<Text, _>(application_id)
                .bind::<BigInt, _>(now)
                .get_result::<ApplicationSamlSessionRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn list_application_saml_sessions_by_indexes(
        &self,
        session_index_hashes: &[String],
        application_id: &str,
    ) -> AppResult<Vec<ApplicationSamlSessionRecord>> {
        if session_index_hashes.is_empty() {
            return Ok(Vec::new());
        }
        let session_index_hashes = session_index_hashes.to_vec();
        let application_id = application_id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let placeholders = placeholders(kind, 1, session_index_hashes.len());
            let application_placeholder = ph(kind, session_index_hashes.len() + 1);
            let now_placeholder = ph(kind, session_index_hashes.len() + 2);
            let sql = format!(
                "{} WHERE session_index_hash IN ({}) AND application_id = {} AND expires_at > {}",
                select_application_saml_session_sql(),
                placeholders,
                application_placeholder,
                now_placeholder,
            );
            bind_text_list(&mut conn, sql_query(sql), &session_index_hashes)
                .bind::<Text, _>(application_id)
                .bind::<BigInt, _>(now)
                .load::<ApplicationSamlSessionRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn list_application_saml_sessions_by_name_id(
        &self,
        name_id_hash: &str,
        application_id: &str,
    ) -> AppResult<Vec<ApplicationSamlSessionRecord>> {
        let name_id_hash = name_id_hash.to_string();
        let application_id = application_id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE name_id_hash = {} AND application_id = {} AND expires_at > {} ORDER BY created_at DESC",
                select_application_saml_session_sql(),
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
            );
            sql_query(sql)
                .bind::<Text, _>(name_id_hash)
                .bind::<Text, _>(application_id)
                .bind::<BigInt, _>(now)
                .load::<ApplicationSamlSessionRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn delete_application_saml_session(
        &self,
        session_index_hash: &str,
        application_id: &str,
    ) -> AppResult<()> {
        let session_index_hash = session_index_hash.to_string();
        let application_id = application_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "DELETE FROM application_saml_sessions WHERE session_index_hash = {} AND application_id = {}",
                ph(kind, 1),
                ph(kind, 2),
            );
            sql_query(sql)
                .bind::<Text, _>(session_index_hash)
                .bind::<Text, _>(application_id)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }
}

fn saml_replay_purge_due(now: i64) -> bool {
    let last = SAML_REPLAY_LAST_PURGE_AT.load(Ordering::Relaxed);
    if last == 0 {
        let _ = SAML_REPLAY_LAST_PURGE_AT.compare_exchange(
            0,
            now,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
        return false;
    }
    if now.saturating_sub(last) < SAML_REPLAY_PURGE_INTERVAL_SECONDS {
        return false;
    }
    SAML_REPLAY_LAST_PURGE_AT
        .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
}
