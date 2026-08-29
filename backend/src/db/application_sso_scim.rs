//! Persistence for application-scoped SCIM tokens.

use super::{
    AppError, AppResult, ApplicationScimTokenRecord, AuditEventRecord, DatabaseKind, Db,
    NewApplicationScimToken, SCIM_TOKEN_USAGE_TOUCH_INTERVAL_SECONDS, blocking, ph,
    select_application_scim_token_sql,
};
use crate::util;
use diesel::{
    Connection, OptionalExtension, RunQueryDsl, sql_query,
    sql_types::{BigInt, Integer, Nullable, Text},
};

impl Db {
    pub async fn insert_application_scim_token(
        &self,
        token: NewApplicationScimToken,
    ) -> AppResult<ApplicationScimTokenRecord> {
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            insert_application_scim_token_on_conn!(conn, kind, &token, now)
        })
    }

    /// Creates an application SCIM token and its audit record atomically.
    /// Only the token hash and non-sensitive prefix are stored or audited.
    pub async fn insert_application_scim_token_with_audit(
        &self,
        token: NewApplicationScimToken,
        event: crate::audit::AuditEvent,
    ) -> AppResult<ApplicationScimTokenRecord> {
        let now = util::now_ts();
        let webhook_db = self.clone();
        let (token, audit_event) = with_conn!(self, |conn, kind| {
            conn.transaction::<(ApplicationScimTokenRecord, AuditEventRecord), AppError, _>(
                |conn| {
                    let token = insert_application_scim_token_on_conn!(conn, kind, &token, now)?;
                    let audit_event = insert_audit_event_on_conn!(conn, kind, event)?;
                    Ok((token, audit_event))
                },
            )
        })?;
        crate::webhooks::spawn_audit_webhook_delivery(webhook_db, audit_event);
        Ok(token)
    }

    pub async fn list_application_scim_tokens(
        &self,
        application_id: &str,
    ) -> AppResult<Vec<ApplicationScimTokenRecord>> {
        let application_id = application_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE application_id = {} ORDER BY created_at DESC",
                select_application_scim_token_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(&application_id)
                .load::<ApplicationScimTokenRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn find_active_application_scim_token(
        &self,
        token_hash: &str,
    ) -> AppResult<Option<ApplicationScimTokenRecord>> {
        let token_hash = token_hash.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE token_hash = {} AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > {})",
                select_application_scim_token_sql(),
                ph(kind, 1),
                ph(kind, 2),
            );
            sql_query(sql)
                .bind::<Text, _>(&token_hash)
                .bind::<BigInt, _>(now)
                .get_result::<ApplicationScimTokenRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn touch_application_scim_token(&self, token_hash: &str) -> AppResult<()> {
        let token_hash = token_hash.to_string();
        let now = util::now_ts();
        let touch_before = now.saturating_sub(SCIM_TOKEN_USAGE_TOUCH_INTERVAL_SECONDS);
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE application_scim_tokens SET last_used_at = {} WHERE token_hash = {} AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > {}) AND (last_used_at IS NULL OR last_used_at < {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
            );
            sql_query(sql)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(&token_hash)
                .bind::<BigInt, _>(now)
                .bind::<BigInt, _>(touch_before)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    pub async fn revoke_application_scim_token(
        &self,
        application_id: &str,
        token_id: &str,
    ) -> AppResult<()> {
        let application_id = application_id.to_string();
        let token_id = token_id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE application_scim_tokens SET revoked_at = {} WHERE application_id = {} AND id = {} AND revoked_at IS NULL",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
            );
            sql_query(sql)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(&application_id)
                .bind::<Text, _>(&token_id)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }
}
