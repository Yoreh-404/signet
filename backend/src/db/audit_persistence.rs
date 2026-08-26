use super::*;

use super::{
    AUDIT_WEBHOOK_OUTBOX_LEASE_TTL_SECONDS, AuditEventRecord, AuditWebhookOutboxRecord,
    AuditWebhookRecord, Db, NewAuditWebhook, UpdateAuditWebhook,
};
use crate::{
    error::{AppError, AppResult},
    util,
};
use diesel::{
    Connection, OptionalExtension, RunQueryDsl, sql_query,
    sql_types::{BigInt, Integer, Nullable, Text},
};

fn audit_event_select(kind: crate::config::DatabaseKind) -> String {
    format!(
        "SELECT id, actor_user_id, actor_client_id, action, target_kind, target_id, outcome, ip_address, user_agent, details, created_at FROM audit_events WHERE id = {}",
        super::ph(kind, 1)
    )
}

fn audit_webhook_select(kind: crate::config::DatabaseKind, suffix: &str) -> String {
    format!(
        "SELECT id, name, url, secret, actions, is_active, timeout_seconds, last_delivered_at, last_status_code, last_error, created_at, updated_at FROM audit_webhooks {suffix}",
    )
}

impl Db {
    pub async fn insert_audit_event(&self, event: crate::audit::AuditEvent) -> AppResult<()> {
        let inserted = with_conn!(self, |conn, kind| {
            conn.transaction::<AuditEventRecord, AppError, _>(|conn| {
                insert_audit_event_on_conn!(conn, kind, event)
            })
        })?;
        crate::webhooks::spawn_audit_webhook_delivery(self.clone(), inserted);
        Ok(())
    }

    pub(crate) async fn claim_audit_webhook_outbox(
        &self,
        limit: i64,
    ) -> AppResult<Vec<AuditWebhookOutboxRecord>> {
        let limit = limit.clamp(1, 100);
        let now = util::now_ts();
        let owner_token = uuid::Uuid::new_v4().to_string();
        let lease_expires_at = now + AUDIT_WEBHOOK_OUTBOX_LEASE_TTL_SECONDS;
        with_conn!(self, |conn, kind| {
            conn.transaction::<Vec<AuditWebhookOutboxRecord>, AppError, _>(|conn| {
                let reclaim_sql = format!(
                    "UPDATE audit_webhook_outbox SET state = 'pending', lease_owner = {}, lease_expires_at = {}, updated_at = {} WHERE state = 'processing' AND lease_expires_at IS NOT NULL AND lease_expires_at <= {}",
                    super::ph(kind, 1),
                    super::ph(kind, 2),
                    super::ph(kind, 3),
                    super::ph(kind, 4),
                );
                sql_query(reclaim_sql)
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<Nullable<BigInt>, _>(None::<i64>)
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;

                let select_sql = format!(
                    "SELECT id, event_id, state, attempts, next_attempt_at, lease_owner, lease_expires_at, last_error, created_at, updated_at FROM audit_webhook_outbox WHERE state = 'pending' AND next_attempt_at <= {} ORDER BY next_attempt_at ASC, created_at ASC, id ASC LIMIT {}",
                    super::ph(kind, 1),
                    super::ph(kind, 2),
                );
                let candidates = sql_query(select_sql)
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(limit)
                    .load::<AuditWebhookOutboxRecord>(conn)
                    .map_err(AppError::from)?;
                let mut claimed = Vec::with_capacity(candidates.len());
                for mut candidate in candidates {
                    let claim_sql = format!(
                        "UPDATE audit_webhook_outbox SET state = {}, lease_owner = {}, lease_expires_at = {}, updated_at = {} WHERE id = {} AND state = {} AND (lease_expires_at IS NULL OR lease_expires_at <= {})",
                        super::ph(kind, 1),
                        super::ph(kind, 2),
                        super::ph(kind, 3),
                        super::ph(kind, 4),
                        super::ph(kind, 5),
                        super::ph(kind, 6),
                        super::ph(kind, 7),
                    );
                    let affected = sql_query(claim_sql)
                        .bind::<Text, _>("processing")
                        .bind::<Text, _>(&owner_token)
                        .bind::<Nullable<BigInt>, _>(Some(lease_expires_at))
                        .bind::<BigInt, _>(now)
                        .bind::<Text, _>(&candidate.id)
                        .bind::<Text, _>("pending")
                        .bind::<BigInt, _>(now)
                        .execute(conn)
                        .map_err(AppError::from)?;
                    if affected == 1 {
                        candidate.state = "processing".to_string();
                        candidate.lease_owner = Some(owner_token.clone());
                        candidate.lease_expires_at = Some(lease_expires_at);
                        candidate.updated_at = now;
                        claimed.push(candidate);
                    }
                }
                Ok(claimed)
            })
        })
    }

    pub(crate) async fn complete_audit_webhook_outbox(
        &self,
        id: &str,
        owner_token: &str,
    ) -> AppResult<bool> {
        let id = id.to_string();
        let owner_token = owner_token.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE audit_webhook_outbox SET state = 'completed', lease_owner = {}, lease_expires_at = {}, updated_at = {} WHERE id = {} AND state = 'processing' AND lease_owner = {}",
                super::ph(kind, 1),
                super::ph(kind, 2),
                super::ph(kind, 3),
                super::ph(kind, 4),
                super::ph(kind, 5),
            );
            sql_query(sql)
                .bind::<Nullable<Text>, _>(None::<String>)
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(id)
                .bind::<Text, _>(owner_token)
                .execute(&mut conn)
                .map(|affected| affected == 1)
                .map_err(AppError::from)
        })
    }

    pub(crate) async fn retry_audit_webhook_outbox(
        &self,
        id: &str,
        owner_token: &str,
        attempts: i32,
        error: String,
    ) -> AppResult<bool> {
        let id = id.to_string();
        let owner_token = owner_token.to_string();
        let error = error.chars().take(1024).collect::<String>();
        let now = util::now_ts();
        let backoff_seconds = (1_i64 << attempts.clamp(0, 10) as u32).min(3_600);
        let next_attempt_at = now + backoff_seconds;
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE audit_webhook_outbox SET state = 'pending', attempts = {}, next_attempt_at = {}, lease_owner = {}, lease_expires_at = {}, last_error = {}, updated_at = {} WHERE id = {} AND state = 'processing' AND lease_owner = {}",
                super::ph(kind, 1),
                super::ph(kind, 2),
                super::ph(kind, 3),
                super::ph(kind, 4),
                super::ph(kind, 5),
                super::ph(kind, 6),
                super::ph(kind, 7),
                super::ph(kind, 8),
            );
            sql_query(sql)
                .bind::<Integer, _>(attempts.saturating_add(1))
                .bind::<BigInt, _>(next_attempt_at)
                .bind::<Nullable<Text>, _>(None::<String>)
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .bind::<Nullable<Text>, _>(Some(error))
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(id)
                .bind::<Text, _>(owner_token)
                .execute(&mut conn)
                .map(|affected| affected == 1)
                .map_err(AppError::from)
        })
    }

    pub(crate) async fn find_audit_event(&self, id: &str) -> AppResult<Option<AuditEventRecord>> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            sql_query(audit_event_select(kind))
                .bind::<Text, _>(id)
                .get_result::<AuditEventRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn list_audit_events(&self, limit: i64) -> AppResult<Vec<AuditEventRecord>> {
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT id, actor_user_id, actor_client_id, action, target_kind, target_id, outcome, ip_address, user_agent, details, created_at FROM audit_events ORDER BY created_at DESC, id DESC LIMIT {}",
                super::ph(kind, 1)
            );
            sql_query(sql)
                .bind::<BigInt, _>(limit.clamp(1, 500))
                .load::<AuditEventRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn list_audit_webhooks(&self) -> AppResult<Vec<AuditWebhookRecord>> {
        with_conn!(self, |conn, kind| {
            sql_query(audit_webhook_select(kind, "ORDER BY created_at DESC"))
                .load::<AuditWebhookRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn find_audit_webhook(&self, id: &str) -> AppResult<Option<AuditWebhookRecord>> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE id = {}",
                audit_webhook_select(kind, ""),
                super::ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<AuditWebhookRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn insert_audit_webhook(
        &self,
        webhook: NewAuditWebhook,
    ) -> AppResult<AuditWebhookRecord> {
        let id = uuid::Uuid::new_v4().to_string();
        let actions = util::to_json(&webhook.actions)?;
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "INSERT INTO audit_webhooks (id, name, url, secret, actions, is_active, timeout_seconds, last_delivered_at, last_status_code, last_error, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
                super::ph(kind, 1),
                super::ph(kind, 2),
                super::ph(kind, 3),
                super::ph(kind, 4),
                super::ph(kind, 5),
                super::ph(kind, 6),
                super::ph(kind, 7),
                super::ph(kind, 8),
                super::ph(kind, 9),
                super::ph(kind, 10),
                super::ph(kind, 11),
                super::ph(kind, 12),
            );
            sql_query(sql)
                .bind::<Text, _>(&id)
                .bind::<Text, _>(webhook.name)
                .bind::<Text, _>(webhook.url)
                .bind::<Text, _>(webhook.secret)
                .bind::<Text, _>(actions)
                .bind::<Integer, _>(i32::from(webhook.is_active))
                .bind::<Integer, _>(webhook.timeout_seconds)
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .bind::<Nullable<Integer>, _>(None::<i32>)
                .bind::<Nullable<Text>, _>(None::<String>)
                .bind::<BigInt, _>(now)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            sql_query(format!(
                "{} WHERE id = {}",
                audit_webhook_select(kind, ""),
                super::ph(kind, 1)
            ))
            .bind::<Text, _>(id)
            .get_result::<AuditWebhookRecord>(&mut conn)
            .map_err(AppError::from)
        })
    }

    pub async fn update_audit_webhook(
        &self,
        id: &str,
        webhook: UpdateAuditWebhook,
    ) -> AppResult<AuditWebhookRecord> {
        let id = id.to_string();
        let actions = util::to_json(&webhook.actions)?;
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let existing = sql_query(format!(
                "{} WHERE id = {}",
                audit_webhook_select(kind, ""),
                super::ph(kind, 1)
            ))
            .bind::<Text, _>(&id)
            .get_result::<AuditWebhookRecord>(&mut conn)
            .optional()
            .map_err(AppError::from)?
            .ok_or(AppError::NotFound)?;
            let secret = webhook.secret.unwrap_or(existing.secret);
            let sql = format!(
                "UPDATE audit_webhooks SET name = {}, url = {}, secret = {}, actions = {}, is_active = {}, timeout_seconds = {}, updated_at = {} WHERE id = {}",
                super::ph(kind, 1),
                super::ph(kind, 2),
                super::ph(kind, 3),
                super::ph(kind, 4),
                super::ph(kind, 5),
                super::ph(kind, 6),
                super::ph(kind, 7),
                super::ph(kind, 8),
            );
            sql_query(sql)
                .bind::<Text, _>(webhook.name)
                .bind::<Text, _>(webhook.url)
                .bind::<Text, _>(secret)
                .bind::<Text, _>(actions)
                .bind::<Integer, _>(i32::from(webhook.is_active))
                .bind::<Integer, _>(webhook.timeout_seconds)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(&id)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            sql_query(format!(
                "{} WHERE id = {}",
                audit_webhook_select(kind, ""),
                super::ph(kind, 1)
            ))
            .bind::<Text, _>(id)
            .get_result::<AuditWebhookRecord>(&mut conn)
            .map_err(AppError::from)
        })
    }

    pub async fn delete_audit_webhook(&self, id: &str) -> AppResult<()> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            let affected = sql_query(format!(
                "DELETE FROM audit_webhooks WHERE id = {}",
                super::ph(kind, 1)
            ))
            .bind::<Text, _>(id)
            .execute(&mut conn)
            .map_err(AppError::from)?;
            if affected == 0 {
                return Err(AppError::NotFound);
            }
            Ok(())
        })
    }

    pub async fn update_audit_webhook_delivery_status(
        &self,
        id: &str,
        status_code: Option<i32>,
        error: Option<String>,
    ) -> AppResult<()> {
        let id = id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE audit_webhooks SET last_delivered_at = {}, last_status_code = {}, last_error = {}, updated_at = {} WHERE id = {}",
                super::ph(kind, 1),
                super::ph(kind, 2),
                super::ph(kind, 3),
                super::ph(kind, 4),
                super::ph(kind, 5),
            );
            sql_query(sql)
                .bind::<BigInt, _>(now)
                .bind::<Nullable<Integer>, _>(status_code)
                .bind::<Nullable<Text>, _>(error)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(id)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }
}
