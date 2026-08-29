use super::billing_sql::select_payment_order_sql;
use super::billing_types::{PaymentOrderLease, PaymentOrderRecord};
use super::{Db, bind_text_list, blocking, ph};
use crate::{
    config::DatabaseKind,
    error::{AppError, AppResult},
    util,
};
use diesel::sql_types::{BigInt, Nullable, Text};
use diesel::{Connection, RunQueryDsl, sql_query};

impl Db {
    pub async fn claim_payment_order_for_reconcile(
        &self,
        id: &str,
        owner: &str,
        now: i64,
        lease_seconds: i64,
        force: bool,
    ) -> AppResult<Option<PaymentOrderRecord>> {
        if owner.trim().is_empty() {
            return Err(AppError::BadRequest(
                "billing reconciliation lease owner is required".to_string(),
            ));
        }
        if lease_seconds <= 0 {
            return Err(AppError::BadRequest(
                "billing reconciliation lease duration must be positive".to_string(),
            ));
        }
        let id = id.to_string();
        let owner = owner.to_string();
        let lease_expires_at = now.saturating_add(lease_seconds);
        with_conn!(self, |conn, kind| {
            conn.transaction::<Option<PaymentOrderRecord>, AppError, _>(|conn| {
                let affected = if force {
                    let update_sql = format!(
                        "UPDATE payment_orders SET lease_owner = {}, lease_expires_at = {}, lease_generation = lease_generation + 1, attempt_count = attempt_count + 1, updated_at = {} WHERE id = {} AND status IN ('creating', 'reconcile', 'pending') AND (lease_expires_at IS NULL OR lease_expires_at <= {})",
                        ph(kind, 1),
                        ph(kind, 2),
                        ph(kind, 3),
                        ph(kind, 4),
                        ph(kind, 5)
                    );
                    sql_query(update_sql)
                        .bind::<Nullable<Text>, _>(Some(owner.clone()))
                        .bind::<Nullable<BigInt>, _>(Some(lease_expires_at))
                        .bind::<BigInt, _>(now)
                        .bind::<Text, _>(&id)
                        .bind::<BigInt, _>(now)
                        .execute(conn)
                        .map_err(AppError::from)?
                } else {
                    let update_sql = format!(
                        "UPDATE payment_orders SET lease_owner = {}, lease_expires_at = {}, lease_generation = lease_generation + 1, attempt_count = attempt_count + 1, updated_at = {} WHERE id = {} AND status IN ('creating', 'reconcile', 'pending') AND (next_retry_at IS NULL OR next_retry_at <= {}) AND (lease_expires_at IS NULL OR lease_expires_at <= {})",
                        ph(kind, 1),
                        ph(kind, 2),
                        ph(kind, 3),
                        ph(kind, 4),
                        ph(kind, 5),
                        ph(kind, 6)
                    );
                    sql_query(update_sql)
                        .bind::<Nullable<Text>, _>(Some(owner.clone()))
                        .bind::<Nullable<BigInt>, _>(Some(lease_expires_at))
                        .bind::<BigInt, _>(now)
                        .bind::<Text, _>(&id)
                        .bind::<BigInt, _>(now)
                        .bind::<BigInt, _>(now)
                        .execute(conn)
                        .map_err(AppError::from)?
                };
                if affected == 0 {
                    return Ok(None);
                }
                let select_sql = format!("{} WHERE id = {}", select_payment_order_sql(), ph(kind, 1));
                sql_query(select_sql)
                    .bind::<Text, _>(id.clone())
                    .get_result::<PaymentOrderRecord>(conn)
                    .map(Some)
                    .map_err(AppError::from)
            })
        })
    }

    /// Atomically claims eligible payment orders for one reconciliation
    /// worker. The returned rows are exactly the rows whose claim update
    /// succeeded, so a later provider query always carries a durable fence.
    pub async fn claim_payment_orders_for_reconcile(
        &self,
        owner: &str,
        now: i64,
        lease_seconds: i64,
        limit: i64,
    ) -> AppResult<Vec<PaymentOrderRecord>> {
        if owner.trim().is_empty() {
            return Err(AppError::BadRequest(
                "billing reconciliation lease owner is required".to_string(),
            ));
        }
        if lease_seconds <= 0 {
            return Err(AppError::BadRequest(
                "billing reconciliation lease duration must be positive".to_string(),
            ));
        }
        let owner = owner.to_string();
        let lease_expires_at = now.saturating_add(lease_seconds);
        let limit = limit.clamp(1, 500);
        with_conn!(self, |conn, kind| {
            conn.transaction::<Vec<PaymentOrderRecord>, AppError, _>(|conn| {
                #[derive(Debug, diesel::QueryableByName)]
                struct PaymentOrderIdRow {
                    #[diesel(sql_type = Text)]
                    id: String,
                }
                let lock_suffix = match kind {
                    DatabaseKind::Sqlite => "",
                    DatabaseKind::Postgres | DatabaseKind::Mysql => " FOR UPDATE",
                };
                let select_ids_sql = format!(
                    "SELECT id FROM payment_orders WHERE status IN ('creating', 'reconcile', 'pending') AND (next_retry_at IS NULL OR next_retry_at <= {}) AND (lease_expires_at IS NULL OR lease_expires_at <= {}) ORDER BY updated_at ASC, created_at ASC LIMIT {}{}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    lock_suffix
                );
                let candidates = sql_query(select_ids_sql)
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(limit)
                    .load::<PaymentOrderIdRow>(conn)
                    .map_err(AppError::from)?;
                let mut claimed_ids = Vec::with_capacity(candidates.len());
                for candidate in candidates {
                    let update_sql = format!(
                        "UPDATE payment_orders SET lease_owner = {}, lease_expires_at = {}, lease_generation = lease_generation + 1, attempt_count = attempt_count + 1, updated_at = {} WHERE id = {} AND status IN ('creating', 'reconcile', 'pending') AND (next_retry_at IS NULL OR next_retry_at <= {}) AND (lease_expires_at IS NULL OR lease_expires_at <= {})",
                        ph(kind, 1),
                        ph(kind, 2),
                        ph(kind, 3),
                        ph(kind, 4),
                        ph(kind, 5),
                        ph(kind, 6)
                    );
                    if sql_query(update_sql)
                        .bind::<Nullable<Text>, _>(Some(owner.clone()))
                        .bind::<Nullable<BigInt>, _>(Some(lease_expires_at))
                        .bind::<BigInt, _>(now)
                        .bind::<Text, _>(&candidate.id)
                        .bind::<BigInt, _>(now)
                        .bind::<BigInt, _>(now)
                        .execute(conn)
                        .map_err(AppError::from)?
                        != 1
                    {
                        continue;
                    }
                    claimed_ids.push(candidate.id);
                }
                if claimed_ids.is_empty() {
                    return Ok(Vec::new());
                }
                let select_sql = format!(
                    "{} WHERE id IN ({})",
                    select_payment_order_sql(),
                    (1..=claimed_ids.len())
                        .map(|index| ph(kind, index))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                let claimed_by_id = bind_text_list(conn, sql_query(select_sql), &claimed_ids)
                    .load::<PaymentOrderRecord>(conn)
                    .map_err(AppError::from)?
                    .into_iter()
                    .map(|order| (order.id.clone(), order))
                    .collect::<std::collections::BTreeMap<_, _>>();
                claimed_ids
                    .into_iter()
                    .map(|id| claimed_by_id.get(&id).cloned().ok_or(AppError::NotFound))
                    .collect()
            })
        })
    }

    /// Extends one still-valid lease without changing its generation. A
    /// worker claims a batch atomically, but processes provider calls one at a
    /// time; renewing immediately before each call prevents later rows in a
    /// large batch from expiring while they wait in the local queue.
    pub async fn renew_payment_order_reconcile_lease(
        &self,
        id: &str,
        fence: &PaymentOrderLease,
        lease_seconds: i64,
    ) -> AppResult<Option<PaymentOrderLease>> {
        if lease_seconds <= 0 {
            return Err(AppError::BadRequest(
                "billing reconciliation lease duration must be positive".to_string(),
            ));
        }
        let id = id.to_string();
        let fence = fence.clone();
        let now = util::now_ts();
        let lease_expires_at = fence
            .lease_expires_at
            .max(now.saturating_add(lease_seconds));
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE payment_orders SET lease_expires_at = {}, updated_at = {} WHERE id = {} AND lease_owner = {} AND lease_generation = {} AND lease_expires_at > {} AND status IN ('creating', 'reconcile', 'pending')",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6)
            );
            if sql_query(sql)
                .bind::<BigInt, _>(lease_expires_at)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(&id)
                .bind::<Text, _>(&fence.owner)
                .bind::<BigInt, _>(fence.generation)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?
                == 0
            {
                return Ok(None);
            }
            Ok(Some(PaymentOrderLease {
                owner: fence.owner,
                generation: fence.generation,
                lease_expires_at,
            }))
        })
    }

    async fn update_payment_order_state_fenced(
        &self,
        id: &str,
        fence: &PaymentOrderLease,
        status: &str,
        error: Option<&str>,
        next_retry_at: Option<i64>,
    ) -> AppResult<Option<PaymentOrderRecord>> {
        let id = id.to_string();
        let status = status.to_string();
        let error = error.map(|value| value.chars().take(512).collect::<String>());
        let fence = fence.clone();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let update_sql = format!(
                "UPDATE payment_orders SET status = {}, last_error = {}, next_retry_at = {}, lease_owner = NULL, lease_expires_at = NULL, updated_at = {} WHERE id = {} AND lease_owner = {} AND lease_generation = {} AND lease_expires_at > {} AND status NOT IN ('paid', 'failed', 'closed')",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
                ph(kind, 7),
                ph(kind, 8)
            );
            if sql_query(update_sql)
                .bind::<Text, _>(&status)
                .bind::<Nullable<Text>, _>(error)
                .bind::<Nullable<BigInt>, _>(next_retry_at)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(&id)
                .bind::<Text, _>(&fence.owner)
                .bind::<BigInt, _>(fence.generation)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?
                == 0
            {
                return Ok(None);
            }
            let select_sql = format!("{} WHERE id = {}", select_payment_order_sql(), ph(kind, 1));
            sql_query(select_sql)
                .bind::<Text, _>(id)
                .get_result::<PaymentOrderRecord>(&mut conn)
                .map(Some)
                .map_err(AppError::from)
        })
    }

    pub async fn mark_payment_order_reconcile_fenced(
        &self,
        id: &str,
        fence: &PaymentOrderLease,
        error: &str,
        next_retry_at: i64,
    ) -> AppResult<Option<PaymentOrderRecord>> {
        self.update_payment_order_state_fenced(
            id,
            fence,
            "reconcile",
            Some(error),
            Some(next_retry_at),
        )
        .await
    }

    pub async fn mark_payment_order_pending_fenced(
        &self,
        id: &str,
        fence: &PaymentOrderLease,
        next_retry_at: i64,
    ) -> AppResult<Option<PaymentOrderRecord>> {
        self.update_payment_order_state_fenced(id, fence, "pending", None, Some(next_retry_at))
            .await
    }

    pub async fn mark_payment_order_failed_fenced(
        &self,
        id: &str,
        fence: &PaymentOrderLease,
        error: &str,
    ) -> AppResult<Option<PaymentOrderRecord>> {
        self.update_payment_order_state_fenced(id, fence, "failed", Some(error), None)
            .await
    }

    /// Releases a still-valid lease without changing the payment state. This
    /// is used only when a worker cannot produce a state transition; normal
    /// outcome paths clear the lease atomically with their state update.
    pub async fn release_payment_order_reconcile_lease(
        &self,
        id: &str,
        fence: &PaymentOrderLease,
        next_retry_at: Option<i64>,
    ) -> AppResult<bool> {
        let id = id.to_string();
        let fence = fence.clone();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE payment_orders SET lease_owner = NULL, lease_expires_at = NULL, next_retry_at = {}, updated_at = {} WHERE id = {} AND lease_owner = {} AND lease_generation = {} AND lease_expires_at > {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6)
            );
            sql_query(sql)
                .bind::<Nullable<BigInt>, _>(next_retry_at)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(&id)
                .bind::<Text, _>(&fence.owner)
                .bind::<BigInt, _>(fence.generation)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map(|count| count > 0)
                .map_err(AppError::from)
        })
    }
}
