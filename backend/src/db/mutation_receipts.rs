//! Transaction protocol receipts and their lease/fencing state.
//!
//! A receipt is a durable claim over one idempotent management request.  The
//! owner token is a fencing token, not an identity credential: every reclaim
//! installs a fresh value and a stale worker can therefore never finalize the
//! replacement owner's result.

use super::*;

use super::{Db, blocking, ph};
use crate::{
    config::DatabaseKind,
    error::{AppError, AppResult},
    util,
};
use diesel::{
    OptionalExtension, RunQueryDsl, sql_query,
    sql_types::{BigInt, Integer, Nullable, Text},
};

const MUTATION_RECEIPT_LEASE_TTL_SECONDS: i64 = 5 * 60;

#[derive(Debug, Clone, diesel::QueryableByName)]
pub struct MutationReceiptRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub dedupe_hash: String,
    #[diesel(sql_type = Text)]
    pub scope_key: String,
    #[diesel(sql_type = Text)]
    pub method: String,
    #[diesel(sql_type = Text)]
    pub path: String,
    #[diesel(sql_type = Text)]
    pub idempotency_key: String,
    #[diesel(sql_type = Text)]
    pub request_hash: String,
    #[diesel(sql_type = Text)]
    pub status: String,
    #[diesel(sql_type = Nullable<Integer>)]
    pub response_status: Option<i32>,
    #[diesel(sql_type = Nullable<Text>)]
    pub response_body: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub response_content_type: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub error_code: Option<String>,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub completed_at: Option<i64>,
    #[diesel(sql_type = Nullable<Text>)]
    pub owner_token: Option<String>,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub lease_expires_at: Option<i64>,
}

fn select_receipt_sql(_kind: DatabaseKind, suffix: &str) -> String {
    format!(
        "SELECT id, dedupe_hash, scope_key, method, path, idempotency_key, request_hash, status, response_status, response_body, response_content_type, error_code, created_at, updated_at, completed_at, owner_token, lease_expires_at FROM mutation_receipts {suffix}",
    )
}

impl Db {
    /// Compatibility entry point for callers that only need a database claim.
    /// The transport protocol uses `claim_mutation_receipt_with_owner` so it
    /// can distinguish the owner from a concurrent retry.
    pub async fn claim_mutation_receipt(
        &self,
        dedupe_hash: &str,
        scope_key: &str,
        method: &str,
        path: &str,
        idempotency_key: &str,
        request_hash: &str,
    ) -> AppResult<MutationReceiptRecord> {
        let owner_token = util::random_token(32);
        self.claim_mutation_receipt_with_owner(
            dedupe_hash,
            scope_key,
            method,
            path,
            idempotency_key,
            request_hash,
            &owner_token,
        )
        .await
    }

    /// Claims a new receipt or, when an old in-progress lease has expired,
    /// atomically reclaims it with a fresh fencing token.  A concurrent
    /// claimant either observes the current owner or wins the single CAS;
    /// it can never receive an expired owner's token after losing that CAS.
    pub async fn claim_mutation_receipt_with_owner(
        &self,
        dedupe_hash: &str,
        scope_key: &str,
        method: &str,
        path: &str,
        idempotency_key: &str,
        request_hash: &str,
        owner_token: &str,
    ) -> AppResult<MutationReceiptRecord> {
        if owner_token.trim().is_empty() {
            return Err(AppError::BadRequest(
                "mutation owner token is required".to_string(),
            ));
        }
        let dedupe_hash = dedupe_hash.to_string();
        let scope_key = scope_key.to_string();
        let method = method.to_string();
        let path = path.to_string();
        let idempotency_key = idempotency_key.to_string();
        let request_hash = request_hash.to_string();
        let owner_token = owner_token.to_string();
        let id = uuid::Uuid::new_v4().to_string();
        let now = util::now_ts();
        let lease_expires_at = now + MUTATION_RECEIPT_LEASE_TTL_SECONDS;

        with_conn!(self, |conn, kind| {
            let insert_sql = match kind {
                DatabaseKind::Mysql => format!(
                    "INSERT IGNORE INTO mutation_receipts (id, dedupe_hash, scope_key, method, path, idempotency_key, request_hash, status, response_status, response_body, response_content_type, error_code, created_at, updated_at, completed_at, owner_token, lease_expires_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                    ph(kind, 6),
                    ph(kind, 7),
                    ph(kind, 8),
                    ph(kind, 9),
                    ph(kind, 10),
                    ph(kind, 11),
                    ph(kind, 12),
                    ph(kind, 13),
                    ph(kind, 14),
                    ph(kind, 15),
                    ph(kind, 16),
                    ph(kind, 17),
                ),
                _ => format!(
                    "INSERT INTO mutation_receipts (id, dedupe_hash, scope_key, method, path, idempotency_key, request_hash, status, response_status, response_body, response_content_type, error_code, created_at, updated_at, completed_at, owner_token, lease_expires_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}) ON CONFLICT (dedupe_hash) DO NOTHING",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                    ph(kind, 6),
                    ph(kind, 7),
                    ph(kind, 8),
                    ph(kind, 9),
                    ph(kind, 10),
                    ph(kind, 11),
                    ph(kind, 12),
                    ph(kind, 13),
                    ph(kind, 14),
                    ph(kind, 15),
                    ph(kind, 16),
                    ph(kind, 17),
                ),
            };
            let inserted = sql_query(insert_sql)
                .bind::<Text, _>(&id)
                .bind::<Text, _>(&dedupe_hash)
                .bind::<Text, _>(&scope_key)
                .bind::<Text, _>(&method)
                .bind::<Text, _>(&path)
                .bind::<Text, _>(&idempotency_key)
                .bind::<Text, _>(&request_hash)
                .bind::<Text, _>("in_progress")
                .bind::<Nullable<Integer>, _>(None::<i32>)
                .bind::<Nullable<Text>, _>(None::<String>)
                .bind::<Nullable<Text>, _>(None::<String>)
                .bind::<Nullable<Text>, _>(None::<String>)
                .bind::<BigInt, _>(now)
                .bind::<BigInt, _>(now)
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .bind::<Nullable<Text>, _>(Some(owner_token.clone()))
                .bind::<Nullable<BigInt>, _>(Some(lease_expires_at))
                .execute(&mut conn)
                .map_err(AppError::from)?;
            if inserted == 1 {
                return Ok(MutationReceiptRecord {
                    id,
                    dedupe_hash,
                    scope_key,
                    method,
                    path,
                    idempotency_key,
                    request_hash,
                    status: "in_progress".to_string(),
                    response_status: None,
                    response_body: None,
                    response_content_type: None,
                    error_code: None,
                    created_at: now,
                    updated_at: now,
                    completed_at: None,
                    owner_token: Some(owner_token),
                    lease_expires_at: Some(lease_expires_at),
                });
            }

            let current_sql = format!(
                "{} WHERE dedupe_hash = {}",
                select_receipt_sql(kind, ""),
                ph(kind, 1)
            );
            let current = sql_query(current_sql)
                .bind::<Text, _>(&dedupe_hash)
                .get_result::<MutationReceiptRecord>(&mut conn)
                .map_err(AppError::from)?;

            if current.status == "in_progress"
                && current
                    .lease_expires_at
                    .is_none_or(|expires_at| expires_at <= now)
            {
                let reclaim_sql = format!(
                    "UPDATE mutation_receipts SET owner_token = {}, lease_expires_at = {}, updated_at = {} WHERE dedupe_hash = {} AND status = {} AND (lease_expires_at IS NULL OR lease_expires_at <= {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                    ph(kind, 6),
                );
                let reclaimed = sql_query(reclaim_sql)
                    .bind::<Nullable<Text>, _>(Some(owner_token.clone()))
                    .bind::<Nullable<BigInt>, _>(Some(lease_expires_at))
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&dedupe_hash)
                    .bind::<Text, _>("in_progress")
                    .bind::<BigInt, _>(now)
                    .execute(&mut conn)
                    .map_err(AppError::from)?;
                if reclaimed == 1 {
                    let reclaimed_sql = format!(
                        "{} WHERE dedupe_hash = {}",
                        select_receipt_sql(kind, ""),
                        ph(kind, 1)
                    );
                    return sql_query(reclaimed_sql)
                        .bind::<Text, _>(&dedupe_hash)
                        .get_result::<MutationReceiptRecord>(&mut conn)
                        .map_err(AppError::from);
                }
            }

            Ok(current)
        })
    }

    /// Fences completion by both receipt ID and owner token.  The boolean is
    /// false when a worker lost its lease and another owner reclaimed the
    /// receipt; callers must not publish the stale worker's response then.
    pub async fn finalize_mutation_receipt(
        &self,
        id: &str,
        owner_token: &str,
        status: &str,
        response_status: i32,
        response_body: Option<String>,
        response_content_type: Option<String>,
        error_code: Option<&str>,
    ) -> AppResult<bool> {
        let id = id.to_string();
        let owner_token = owner_token.to_string();
        let status = status.to_string();
        let error_code = error_code.map(ToOwned::to_owned);
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE mutation_receipts SET status = {}, response_status = {}, response_body = {}, response_content_type = {}, error_code = {}, updated_at = {}, completed_at = {}, owner_token = {}, lease_expires_at = {} WHERE id = {} AND owner_token = {} AND status = {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
                ph(kind, 7),
                ph(kind, 8),
                ph(kind, 9),
                ph(kind, 10),
                ph(kind, 11),
                ph(kind, 12),
            );
            sql_query(sql)
                .bind::<Text, _>(status)
                .bind::<Integer, _>(response_status)
                .bind::<Nullable<Text>, _>(response_body)
                .bind::<Nullable<Text>, _>(response_content_type)
                .bind::<Nullable<Text>, _>(error_code)
                .bind::<BigInt, _>(now)
                .bind::<Nullable<BigInt>, _>(Some(now))
                .bind::<Nullable<Text>, _>(None::<String>)
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .bind::<Text, _>(id)
                .bind::<Text, _>(owner_token)
                .bind::<Text, _>("in_progress")
                .execute(&mut conn)
                .map(|affected| affected == 1)
                .map_err(AppError::from)
        })
    }

    /// Extends an active lease without allowing an expired owner to revive
    /// itself after a reclaim.  The owner token is the CAS fence here too.
    pub async fn renew_mutation_receipt_lease(
        &self,
        id: &str,
        owner_token: &str,
    ) -> AppResult<bool> {
        let id = id.to_string();
        let owner_token = owner_token.to_string();
        let now = util::now_ts();
        let lease_expires_at = now + MUTATION_RECEIPT_LEASE_TTL_SECONDS;
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE mutation_receipts SET lease_expires_at = {}, updated_at = {} WHERE id = {} AND owner_token = {} AND status = {} AND (lease_expires_at IS NULL OR lease_expires_at >= {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
            );
            sql_query(sql)
                .bind::<Nullable<BigInt>, _>(Some(lease_expires_at))
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(id)
                .bind::<Text, _>(owner_token)
                .bind::<Text, _>("in_progress")
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map(|affected| affected == 1)
                .map_err(AppError::from)
        })
    }

    pub async fn find_mutation_receipt(
        &self,
        id: &str,
        scope_key: &str,
    ) -> AppResult<Option<MutationReceiptRecord>> {
        let id = id.to_string();
        let scope_key = scope_key.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE id = {} AND scope_key = {}",
                select_receipt_sql(kind, ""),
                ph(kind, 1),
                ph(kind, 2),
            );
            sql_query(sql)
                .bind::<Text, _>(id)
                .bind::<Text, _>(scope_key)
                .get_result::<MutationReceiptRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }
}
