use super::{CountRow, Db, blocking, ph};
use crate::{
    config::DatabaseKind,
    error::{AppError, AppResult},
    util,
};
use diesel::{
    Connection, OptionalExtension, RunQueryDsl, sql_query,
    sql_types::{BigInt, Integer, Nullable, Text},
};
use serde::Serialize;

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct ApplicationBillingSettingsRecord {
    #[diesel(sql_type = Text)]
    pub application_id: String,
    #[diesel(sql_type = Integer)]
    pub accept_signet_balance: i32,
    #[diesel(sql_type = Text)]
    pub wallet_mode: String,
    #[diesel(sql_type = Text)]
    pub supported_currencies: String,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub mode_locked_at: Option<i64>,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct WalletAccountRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub account_kind: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub user_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub application_id: Option<String>,
    #[diesel(sql_type = Text)]
    pub currency: String,
    #[diesel(sql_type = BigInt)]
    pub available_minor: i64,
    #[diesel(sql_type = BigInt)]
    pub reserved_minor: i64,
    #[diesel(sql_type = BigInt)]
    pub version: i64,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct WalletHoldRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub hold_kind: String,
    #[diesel(sql_type = Text)]
    pub wallet_id: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub user_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub application_id: Option<String>,
    #[diesel(sql_type = Text)]
    pub currency: String,
    #[diesel(sql_type = BigInt)]
    pub amount_minor: i64,
    #[diesel(sql_type = Text)]
    pub status: String,
    #[diesel(sql_type = Text)]
    pub reference: String,
    #[diesel(sql_type = Text)]
    pub idempotency_key: String,
    #[diesel(sql_type = BigInt)]
    pub expires_at: i64,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct WalletTransactionRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub kind: String,
    #[diesel(sql_type = Text)]
    pub status: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub user_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub application_id: Option<String>,
    #[diesel(sql_type = Text)]
    pub currency: String,
    #[diesel(sql_type = BigInt)]
    pub amount_minor: i64,
    #[diesel(sql_type = Nullable<Text>)]
    pub source_wallet_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub destination_wallet_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub hold_id: Option<String>,
    #[diesel(sql_type = Text)]
    pub idempotency_key: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub external_provider: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub external_order_id: Option<String>,
    #[diesel(sql_type = Text)]
    pub metadata: String,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct PaymentOrderRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub user_id: String,
    #[diesel(sql_type = Text)]
    pub provider_slug: String,
    #[diesel(sql_type = Text)]
    pub merchant_order_no: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub idempotency_key: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub provider_trade_id: Option<String>,
    #[diesel(sql_type = Text)]
    pub currency: String,
    #[diesel(sql_type = BigInt)]
    pub amount_minor: i64,
    #[diesel(sql_type = Text)]
    pub subject: String,
    #[diesel(sql_type = Text)]
    pub status: String,
    #[diesel(sql_type = Text)]
    pub checkout_kind: String,
    #[diesel(sql_type = Text)]
    pub checkout_value: String,
    #[diesel(sql_type = BigInt)]
    pub expires_at: i64,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub paid_at: Option<i64>,
    #[diesel(sql_type = Nullable<Text>)]
    pub last_error: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub lease_owner: Option<String>,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub lease_expires_at: Option<i64>,
    #[diesel(sql_type = BigInt)]
    pub lease_generation: i64,
    #[diesel(sql_type = BigInt)]
    pub attempt_count: i64,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub next_retry_at: Option<i64>,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct PaymentRefundRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub payment_order_id: String,
    #[diesel(sql_type = BigInt)]
    pub amount_minor: i64,
    #[diesel(sql_type = Text)]
    pub status: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub provider_refund_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub requested_by: Option<String>,
    #[diesel(sql_type = Text)]
    pub reason: String,
    #[diesel(sql_type = Text)]
    pub idempotency_key: String,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct NewApplicationBillingSettings {
    pub application_id: String,
    pub accept_signet_balance: bool,
    pub wallet_mode: String,
    pub supported_currencies: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct NewPaymentOrder {
    pub user_id: String,
    pub provider_slug: String,
    pub merchant_order_no: String,
    pub idempotency_key: Option<String>,
    pub currency: String,
    pub amount_minor: i64,
    pub subject: String,
    pub checkout_kind: String,
    pub checkout_value: String,
    pub expires_at: i64,
}

/// A database-issued fencing token for one reconciliation attempt. Every
/// provider result must carry the same owner and generation back to the DB;
/// a later claimant makes the token stale before it can mutate the order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentOrderLease {
    pub owner: String,
    pub generation: i64,
    pub lease_expires_at: i64,
}

#[derive(Debug, Clone)]
pub struct NewWalletOperation {
    pub kind: String,
    pub user_id: Option<String>,
    pub application_id: Option<String>,
    pub currency: String,
    pub amount_minor: i64,
    pub source_wallet_id: Option<String>,
    pub destination_wallet_id: Option<String>,
    pub hold_id: Option<String>,
    pub idempotency_key: String,
    pub external_provider: Option<String>,
    pub external_order_id: Option<String>,
    pub metadata: serde_json::Value,
}

fn select_application_billing_settings_sql() -> &'static str {
    "SELECT application_id, accept_signet_balance, wallet_mode, COALESCE(supported_currencies, '[]') AS supported_currencies, mode_locked_at, created_at, updated_at FROM application_billing_settings"
}

fn select_wallet_account_sql() -> &'static str {
    "SELECT id, account_kind, user_id, application_id, currency, available_minor, reserved_minor, version, created_at, updated_at FROM wallet_accounts"
}

fn select_wallet_hold_sql() -> &'static str {
    "SELECT id, hold_kind, wallet_id, user_id, application_id, currency, amount_minor, status, reference, idempotency_key, expires_at, created_at, updated_at FROM wallet_holds"
}

fn select_wallet_transaction_sql() -> &'static str {
    "SELECT id, kind, status, user_id, application_id, currency, amount_minor, source_wallet_id, destination_wallet_id, hold_id, idempotency_key, external_provider, external_order_id, metadata, created_at, updated_at FROM wallet_transactions"
}

fn select_payment_order_sql() -> &'static str {
    "SELECT id, user_id, provider_slug, merchant_order_no, idempotency_key, provider_trade_id, currency, amount_minor, subject, status, checkout_kind, checkout_value, expires_at, paid_at, last_error, lease_owner, lease_expires_at, lease_generation, attempt_count, next_retry_at, created_at, updated_at FROM payment_orders"
}

fn select_payment_refund_sql() -> &'static str {
    "SELECT id, payment_order_id, amount_minor, status, provider_refund_id, requested_by, reason, COALESCE(idempotency_key, '') AS idempotency_key, created_at, updated_at FROM payment_refunds"
}

/// Refund reservations serialize on the payment-order row.  SQLite obtains
/// the write lock when the transaction writes; PostgreSQL and MySQL need an
/// explicit row lock so two refund intents cannot both observe the same
/// refundable remainder.
fn payment_order_lock_suffix(kind: DatabaseKind) -> &'static str {
    match kind {
        DatabaseKind::Sqlite => "",
        DatabaseKind::Postgres | DatabaseKind::Mysql => " FOR UPDATE",
    }
}

fn payment_refund_counts_toward_limit(status: &str) -> bool {
    matches!(status, "pending" | "succeeded")
}

fn wallet_account_scope_key(
    account_kind: &str,
    user_id: Option<&str>,
    application_id: Option<&str>,
    currency: &str,
) -> String {
    format!(
        "{account_kind}:{}:{}:{currency}",
        user_id.unwrap_or("-"),
        application_id.unwrap_or("-")
    )
}

impl Db {
    pub async fn find_application_billing_settings(
        &self,
        application_id: &str,
    ) -> AppResult<Option<ApplicationBillingSettingsRecord>> {
        let application_id = application_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE application_id = {}",
                select_application_billing_settings_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(application_id)
                .get_result::<ApplicationBillingSettingsRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn ensure_application_billing_settings(
        &self,
        application_id: &str,
    ) -> AppResult<ApplicationBillingSettingsRecord> {
        if let Some(settings) = self
            .find_application_billing_settings(application_id)
            .await?
        {
            return Ok(settings);
        }
        self.upsert_application_billing_settings(NewApplicationBillingSettings {
            application_id: application_id.to_string(),
            accept_signet_balance: false,
            wallet_mode: "shared".to_string(),
            supported_currencies: Vec::new(),
        })
        .await
    }

    pub async fn upsert_application_billing_settings(
        &self,
        settings: NewApplicationBillingSettings,
    ) -> AppResult<ApplicationBillingSettingsRecord> {
        let currencies = util::to_json(&settings.supported_currencies)?;
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<ApplicationBillingSettingsRecord, AppError, _>(|conn| {
                let existing_sql = format!(
                    "{} WHERE application_id = {}",
                    select_application_billing_settings_sql(),
                    ph(kind, 1)
                );
                let existing = sql_query(existing_sql)
                    .bind::<Text, _>(&settings.application_id)
                    .get_result::<ApplicationBillingSettingsRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?;
                let activity_count_sql = format!(
                    "SELECT COUNT(*) AS count FROM wallet_transactions WHERE application_id = {}",
                    ph(kind, 1)
                );
                let activity_count = sql_query(activity_count_sql)
                    .bind::<Text, _>(&settings.application_id)
                    .get_result::<CountRow>(conn)
                    .map_err(AppError::from)?
                    .count;
                let mode_locked_at = existing
                    .as_ref()
                    .and_then(|value| value.mode_locked_at)
                    .or_else(|| (activity_count > 0).then_some(now));
                if existing
                    .as_ref()
                    .is_some_and(|value| value.wallet_mode != settings.wallet_mode)
                    && mode_locked_at.is_some()
                {
                    return Err(AppError::BadRequest(
                        "application wallet mode is locked after the first billing transaction"
                            .to_string(),
                    ));
                }
                if existing.is_some() {
                    let update_sql = format!(
                        "UPDATE application_billing_settings SET accept_signet_balance = {}, wallet_mode = {}, supported_currencies = {}, mode_locked_at = {}, updated_at = {} WHERE application_id = {}",
                        ph(kind, 1),
                        ph(kind, 2),
                        ph(kind, 3),
                        ph(kind, 4),
                        ph(kind, 5),
                        ph(kind, 6)
                    );
                    sql_query(update_sql)
                        .bind::<Integer, _>(i32::from(settings.accept_signet_balance))
                        .bind::<Text, _>(&settings.wallet_mode)
                        .bind::<Text, _>(&currencies)
                        .bind::<Nullable<BigInt>, _>(mode_locked_at)
                        .bind::<BigInt, _>(now)
                        .bind::<Text, _>(&settings.application_id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                } else {
                    let insert_sql = format!(
                        "INSERT INTO application_billing_settings (application_id, accept_signet_balance, wallet_mode, supported_currencies, mode_locked_at, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {})",
                        ph(kind, 1),
                        ph(kind, 2),
                        ph(kind, 3),
                        ph(kind, 4),
                        ph(kind, 5),
                        ph(kind, 6),
                        ph(kind, 7)
                    );
                    sql_query(insert_sql)
                        .bind::<Text, _>(&settings.application_id)
                        .bind::<Integer, _>(i32::from(settings.accept_signet_balance))
                        .bind::<Text, _>(&settings.wallet_mode)
                        .bind::<Text, _>(&currencies)
                        .bind::<Nullable<BigInt>, _>(mode_locked_at)
                        .bind::<BigInt, _>(now)
                        .bind::<BigInt, _>(now)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                let select_sql = format!(
                    "{} WHERE application_id = {}",
                    select_application_billing_settings_sql(),
                    ph(kind, 1)
                );
                sql_query(select_sql)
                    .bind::<Text, _>(&settings.application_id)
                    .get_result::<ApplicationBillingSettingsRecord>(conn)
                    .map_err(AppError::from)
            })
        })
    }

    async fn ensure_wallet_account(
        &self,
        account_kind: &str,
        user_id: Option<&str>,
        application_id: Option<&str>,
        currency: &str,
    ) -> AppResult<WalletAccountRecord> {
        let account_kind = account_kind.to_string();
        let user_id = user_id.map(ToOwned::to_owned);
        let application_id = application_id.map(ToOwned::to_owned);
        let currency = currency.to_string();
        let scope_key = wallet_account_scope_key(
            &account_kind,
            user_id.as_deref(),
            application_id.as_deref(),
            &currency,
        );
        with_conn!(self, |conn, kind| {
            let existing_sql = format!(
                "{} WHERE scope_key = {}",
                select_wallet_account_sql(),
                ph(kind, 1)
            );
            if let Some(existing) = sql_query(existing_sql)
                .bind::<Text, _>(&scope_key)
                .get_result::<WalletAccountRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)?
            {
                return Ok(existing);
            }
            let id = uuid::Uuid::new_v4().to_string();
            let now = util::now_ts();
            let insert_sql = format!(
                "INSERT INTO wallet_accounts (id, account_kind, scope_key, user_id, application_id, currency, available_minor, reserved_minor, version, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, 0, 0, 0, {}, {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
                ph(kind, 7),
                ph(kind, 8)
            );
            if let Err(error) = sql_query(insert_sql)
                .bind::<Text, _>(&id)
                .bind::<Text, _>(&account_kind)
                .bind::<Text, _>(&scope_key)
                .bind::<Nullable<Text>, _>(&user_id)
                .bind::<Nullable<Text>, _>(&application_id)
                .bind::<Text, _>(&currency)
                .bind::<BigInt, _>(now)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
            {
                // A concurrent account creation may have won the unique
                // scope_key race. Re-read it before surfacing the database
                // error so callers remain idempotent.
                let retry_sql = format!(
                    "{} WHERE scope_key = {}",
                    select_wallet_account_sql(),
                    ph(kind, 1)
                );
                if let Some(existing) = sql_query(retry_sql)
                    .bind::<Text, _>(&scope_key)
                    .get_result::<WalletAccountRecord>(&mut conn)
                    .optional()
                    .map_err(AppError::from)?
                {
                    return Ok(existing);
                }
                return Err(AppError::from(error));
            }
            let select_sql = format!("{} WHERE id = {}", select_wallet_account_sql(), ph(kind, 1));
            sql_query(select_sql)
                .bind::<Text, _>(id)
                .get_result::<WalletAccountRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn ensure_user_wallet_account(
        &self,
        user_id: &str,
        currency: &str,
    ) -> AppResult<WalletAccountRecord> {
        self.ensure_wallet_account("user_global", Some(user_id), None, currency)
            .await
    }

    pub async fn ensure_application_wallet_account(
        &self,
        user_id: &str,
        application_id: &str,
        currency: &str,
    ) -> AppResult<WalletAccountRecord> {
        self.ensure_wallet_account(
            "user_application",
            Some(user_id),
            Some(application_id),
            currency,
        )
        .await
    }

    pub async fn ensure_settlement_wallet_account(
        &self,
        application_id: &str,
        currency: &str,
    ) -> AppResult<WalletAccountRecord> {
        self.ensure_wallet_account(
            "application_settlement",
            None,
            Some(application_id),
            currency,
        )
        .await
    }

    pub async fn find_wallet_account_by_id(
        &self,
        wallet_id: &str,
    ) -> AppResult<Option<WalletAccountRecord>> {
        let wallet_id = wallet_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!("{} WHERE id = {}", select_wallet_account_sql(), ph(kind, 1));
            sql_query(sql)
                .bind::<Text, _>(wallet_id)
                .get_result::<WalletAccountRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn list_user_wallet_accounts(
        &self,
        user_id: &str,
        currency: Option<&str>,
    ) -> AppResult<Vec<WalletAccountRecord>> {
        let user_id = user_id.to_string();
        let currency = currency.map(ToOwned::to_owned);
        with_conn!(self, |conn, kind| {
            let mut sql = format!(
                "{} WHERE user_id = {}",
                select_wallet_account_sql(),
                ph(kind, 1)
            );
            if currency.is_some() {
                sql.push_str(&format!(" AND currency = {}", ph(kind, 2)));
            }
            sql.push_str(" ORDER BY currency ASC, account_kind ASC, created_at ASC");
            if let Some(currency) = currency {
                sql_query(sql)
                    .bind::<Text, _>(user_id)
                    .bind::<Text, _>(currency)
                    .load::<WalletAccountRecord>(&mut conn)
                    .map_err(AppError::from)
            } else {
                sql_query(sql)
                    .bind::<Text, _>(user_id)
                    .load::<WalletAccountRecord>(&mut conn)
                    .map_err(AppError::from)
            }
        })
    }

    pub async fn list_wallet_transactions_for_user(
        &self,
        user_id: &str,
        limit: i64,
    ) -> AppResult<Vec<WalletTransactionRecord>> {
        let user_id = user_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE user_id = {} ORDER BY created_at DESC LIMIT {}",
                select_wallet_transaction_sql(),
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<Text, _>(user_id)
                .bind::<BigInt, _>(limit.clamp(1, 500))
                .load::<WalletTransactionRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn insert_payment_order(
        &self,
        order: NewPaymentOrder,
    ) -> AppResult<PaymentOrderRecord> {
        self.insert_payment_order_with_status(order, "pending")
            .await
    }

    /// Persists the local payment intent before the provider adapter is
    /// called.  The boolean is true only for the request that won the unique
    /// idempotency/merchant-order race; all other callers must replay or
    /// reconcile the returned durable row instead of issuing a second create.
    pub async fn insert_payment_intent(
        &self,
        order: NewPaymentOrder,
    ) -> AppResult<(PaymentOrderRecord, bool)> {
        let user_id = order.user_id.clone();
        let provider_slug = order.provider_slug.clone();
        let idempotency_key = order.idempotency_key.clone();
        if let Some(idempotency_key) = idempotency_key.as_deref()
            && let Some(existing) = self
                .find_payment_order_by_idempotency_key(&user_id, &provider_slug, idempotency_key)
                .await?
        {
            return Ok((existing, false));
        }
        match self
            .insert_payment_order_with_status(order, "creating")
            .await
        {
            Ok(order) => Ok((order, true)),
            Err(error) => {
                // A concurrent insert may have won the unique constraint.
                // Read it back after the failed statement and make replay
                // deterministic without hiding unrelated database failures.
                if let Some(idempotency_key) = idempotency_key.as_deref()
                    && let Some(existing) = self
                        .find_payment_order_by_idempotency_key(
                            &user_id,
                            &provider_slug,
                            idempotency_key,
                        )
                        .await?
                {
                    return Ok((existing, false));
                }
                Err(error)
            }
        }
    }

    async fn insert_payment_order_with_status(
        &self,
        order: NewPaymentOrder,
        status: &str,
    ) -> AppResult<PaymentOrderRecord> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = util::now_ts();
        let status = status.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "INSERT INTO payment_orders (id, user_id, provider_slug, merchant_order_no, idempotency_key, provider_trade_id, currency, amount_minor, subject, status, checkout_kind, checkout_value, expires_at, paid_at, last_error, lease_owner, lease_expires_at, lease_generation, attempt_count, next_retry_at, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
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
                ph(kind, 18),
                ph(kind, 19),
                ph(kind, 20),
                ph(kind, 21),
                ph(kind, 22)
            );
            sql_query(sql)
                .bind::<Text, _>(&id)
                .bind::<Text, _>(order.user_id)
                .bind::<Text, _>(order.provider_slug)
                .bind::<Text, _>(order.merchant_order_no)
                .bind::<Nullable<Text>, _>(order.idempotency_key)
                .bind::<Nullable<Text>, _>(None::<String>)
                .bind::<Text, _>(order.currency)
                .bind::<BigInt, _>(order.amount_minor)
                .bind::<Text, _>(order.subject)
                .bind::<Text, _>(&status)
                .bind::<Text, _>(order.checkout_kind)
                .bind::<Text, _>(order.checkout_value)
                .bind::<BigInt, _>(order.expires_at)
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .bind::<Nullable<Text>, _>(None::<String>)
                .bind::<Nullable<Text>, _>(None::<String>)
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .bind::<BigInt, _>(0_i64)
                .bind::<BigInt, _>(0_i64)
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .bind::<BigInt, _>(now)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            let select_sql = format!("{} WHERE id = {}", select_payment_order_sql(), ph(kind, 1));
            sql_query(select_sql)
                .bind::<Text, _>(id)
                .get_result::<PaymentOrderRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn find_payment_order(&self, id: &str) -> AppResult<Option<PaymentOrderRecord>> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!("{} WHERE id = {}", select_payment_order_sql(), ph(kind, 1));
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<PaymentOrderRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn find_payment_order_by_merchant_order_no(
        &self,
        provider_slug: &str,
        merchant_order_no: &str,
    ) -> AppResult<Option<PaymentOrderRecord>> {
        let provider_slug = provider_slug.to_string();
        let merchant_order_no = merchant_order_no.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE provider_slug = {} AND merchant_order_no = {}",
                select_payment_order_sql(),
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<Text, _>(provider_slug)
                .bind::<Text, _>(merchant_order_no)
                .get_result::<PaymentOrderRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn find_payment_order_by_idempotency_key(
        &self,
        user_id: &str,
        provider_slug: &str,
        idempotency_key: &str,
    ) -> AppResult<Option<PaymentOrderRecord>> {
        let user_id = user_id.to_string();
        let provider_slug = provider_slug.to_string();
        let idempotency_key = idempotency_key.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE user_id = {} AND provider_slug = {} AND idempotency_key = {}",
                select_payment_order_sql(),
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3)
            );
            sql_query(sql)
                .bind::<Text, _>(user_id)
                .bind::<Text, _>(provider_slug)
                .bind::<Text, _>(idempotency_key)
                .get_result::<PaymentOrderRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn list_payment_refunds(
        &self,
        payment_order_id: &str,
    ) -> AppResult<Vec<PaymentRefundRecord>> {
        let payment_order_id = payment_order_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE payment_order_id = {} ORDER BY created_at DESC",
                select_payment_refund_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(payment_order_id)
                .load::<PaymentRefundRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn find_payment_refund_by_idempotency_key(
        &self,
        payment_order_id: &str,
        idempotency_key: &str,
    ) -> AppResult<Option<PaymentRefundRecord>> {
        let payment_order_id = payment_order_id.to_string();
        let idempotency_key = idempotency_key.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE payment_order_id = {} AND idempotency_key = {} ORDER BY created_at DESC, id DESC LIMIT 1",
                select_payment_refund_sql(),
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<Text, _>(payment_order_id)
                .bind::<Text, _>(idempotency_key)
                .get_result::<PaymentRefundRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn list_payment_orders(
        &self,
        user_id: Option<&str>,
        limit: i64,
    ) -> AppResult<Vec<PaymentOrderRecord>> {
        let user_id = user_id.map(ToOwned::to_owned);
        with_conn!(self, |conn, kind| {
            let mut sql = select_payment_order_sql().to_string();
            if user_id.is_some() {
                sql.push_str(&format!(" WHERE user_id = {}", ph(kind, 1)));
            }
            sql.push_str(&format!(
                " ORDER BY created_at DESC LIMIT {}",
                ph(kind, if user_id.is_some() { 2 } else { 1 })
            ));
            if let Some(user_id) = user_id {
                sql_query(sql)
                    .bind::<Text, _>(user_id)
                    .bind::<BigInt, _>(limit.clamp(1, 500))
                    .load::<PaymentOrderRecord>(&mut conn)
                    .map_err(AppError::from)
            } else {
                sql_query(sql)
                    .bind::<BigInt, _>(limit.clamp(1, 500))
                    .load::<PaymentOrderRecord>(&mut conn)
                    .map_err(AppError::from)
            }
        })
    }

    /// Claims one payment order for reconciliation. A force claim may ignore
    /// `next_retry_at`, but it never ignores an active lease. This is the
    /// database boundary shared by operator commands and the worker; callers
    /// must not query a row they failed to claim.
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
                let mut claimed = Vec::with_capacity(candidates.len());
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
                    let select_sql = format!("{} WHERE id = {}", select_payment_order_sql(), ph(kind, 1));
                    claimed.push(
                        sql_query(select_sql)
                            .bind::<Text, _>(candidate.id)
                            .get_result::<PaymentOrderRecord>(conn)
                            .map_err(AppError::from)?,
                    );
                }
                Ok(claimed)
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
        let lease_expires_at = now.saturating_add(lease_seconds);
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

    pub async fn find_wallet_transaction_by_id(
        &self,
        transaction_id: &str,
    ) -> AppResult<Option<WalletTransactionRecord>> {
        let transaction_id = transaction_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE id = {}",
                select_wallet_transaction_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(transaction_id)
                .get_result::<WalletTransactionRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn find_wallet_transaction_by_operation(
        &self,
        kind_name: &str,
        idempotency_key: &str,
    ) -> AppResult<Option<WalletTransactionRecord>> {
        let kind_name = kind_name.to_string();
        let idempotency_key = idempotency_key.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE kind = {} AND idempotency_key = {}",
                select_wallet_transaction_sql(),
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<Text, _>(kind_name)
                .bind::<Text, _>(idempotency_key)
                .get_result::<WalletTransactionRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn update_payment_order_error(&self, id: &str, error: &str) -> AppResult<()> {
        let id = id.to_string();
        let error = error.chars().take(512).collect::<String>();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE payment_orders SET last_error = {}, updated_at = {} WHERE id = {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3)
            );
            sql_query(sql)
                .bind::<Nullable<Text>, _>(Some(error))
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(id)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    async fn update_payment_order_state(
        &self,
        id: &str,
        status: &str,
        error: Option<&str>,
    ) -> AppResult<PaymentOrderRecord> {
        let id = id.to_string();
        let status = status.to_string();
        let error = error.map(|value| value.chars().take(512).collect::<String>());
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<PaymentOrderRecord, AppError, _>(|conn| {
                let acquire_sql = format!(
                    "UPDATE payment_orders SET updated_at = updated_at WHERE id = {}",
                    ph(kind, 1)
                );
                if sql_query(acquire_sql)
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?
                    == 0
                {
                    return Err(AppError::NotFound);
                }
                let order_sql = format!(
                    "{} WHERE id = {}{}",
                    select_payment_order_sql(),
                    ph(kind, 1),
                    payment_order_lock_suffix(kind)
                );
                let order = sql_query(order_sql)
                    .bind::<Text, _>(&id)
                    .get_result::<PaymentOrderRecord>(conn)
                    .map_err(AppError::from)?;
                if order.status == "paid" {
                    return Ok(order);
                }
                if matches!(order.status.as_str(), "failed" | "closed")
                    && status != "failed"
                {
                    // A known terminal failure must not be reopened by a
                    // late timeout/query from a racing request.  A later
                    // verified provider notification can still enter the
                    // dedicated paid finalizer above.
                    return Ok(order);
                }
                let update_sql = format!(
                    "UPDATE payment_orders SET status = {}, last_error = {}, next_retry_at = NULL, lease_owner = NULL, lease_expires_at = NULL, updated_at = {} WHERE id = {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4)
                );
                sql_query(update_sql)
                    .bind::<Text, _>(&status)
                    .bind::<Nullable<Text>, _>(error)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let select_sql = format!("{} WHERE id = {}", select_payment_order_sql(), ph(kind, 1));
                sql_query(select_sql)
                    .bind::<Text, _>(&id)
                    .get_result::<PaymentOrderRecord>(conn)
                    .map_err(AppError::from)
            })
        })
    }

    /// Records a provider outcome that is known not to have succeeded.
    pub async fn mark_payment_order_failed(
        &self,
        id: &str,
        error: &str,
    ) -> AppResult<PaymentOrderRecord> {
        self.update_payment_order_state(id, "failed", Some(error))
            .await
    }

    /// Records a timeout, transport error, 5xx, or malformed provider
    /// response.  This state is intentionally not terminal: a later query or
    /// provider notification may still prove that money was accepted.
    pub async fn mark_payment_order_reconcile(
        &self,
        id: &str,
        error: &str,
    ) -> AppResult<PaymentOrderRecord> {
        self.update_payment_order_state(id, "reconcile", Some(error))
            .await
    }

    /// Keeps a durable order awaiting payment after a provider query reports
    /// a non-terminal state.  Existing checkout fields are preserved.
    pub async fn mark_payment_order_pending(&self, id: &str) -> AppResult<PaymentOrderRecord> {
        let order = self
            .find_payment_order(id)
            .await?
            .ok_or(AppError::NotFound)?;
        if order.status == "paid" || order.status == "pending" {
            return Ok(order);
        }
        if !matches!(order.status.as_str(), "creating" | "reconcile") {
            return Err(AppError::BadRequest(
                "payment order cannot return to pending".to_string(),
            ));
        }
        self.update_payment_order_state(id, "pending", None).await
    }

    /// Stores the provider checkout only after the provider create call has
    /// returned a complete checkout.  The state transition and the response
    /// are one local mutation, so a crash before this call leaves the intent
    /// recoverable rather than pretending it is payable.
    pub async fn set_payment_order_checkout(
        &self,
        id: &str,
        checkout_kind: &str,
        checkout_value: &str,
    ) -> AppResult<PaymentOrderRecord> {
        if checkout_kind.trim().is_empty() || checkout_value.trim().is_empty() {
            return Err(AppError::BadRequest(
                "payment provider returned an empty checkout".to_string(),
            ));
        }
        let id = id.to_string();
        let checkout_kind = checkout_kind.to_string();
        let checkout_value = checkout_value.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<PaymentOrderRecord, AppError, _>(|conn| {
                let acquire_sql = format!(
                    "UPDATE payment_orders SET updated_at = updated_at WHERE id = {}",
                    ph(kind, 1)
                );
                if sql_query(acquire_sql)
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?
                    == 0
                {
                    return Err(AppError::NotFound);
                }
                let order_sql = format!(
                    "{} WHERE id = {}{}",
                    select_payment_order_sql(),
                    ph(kind, 1),
                    payment_order_lock_suffix(kind)
                );
                let order = sql_query(order_sql)
                    .bind::<Text, _>(&id)
                    .get_result::<PaymentOrderRecord>(conn)
                    .map_err(AppError::from)?;
                if order.status == "paid" {
                    return Ok(order);
                }
                if !matches!(order.status.as_str(), "creating" | "reconcile" | "pending") {
                    return Err(AppError::BadRequest(
                        "payment order is not awaiting a provider checkout".to_string(),
                    ));
                }
                let update_sql = format!(
                    "UPDATE payment_orders SET status = 'pending', checkout_kind = {}, checkout_value = {}, last_error = NULL, next_retry_at = NULL, lease_owner = NULL, lease_expires_at = NULL, updated_at = {} WHERE id = {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4)
                );
                sql_query(update_sql)
                    .bind::<Text, _>(&checkout_kind)
                    .bind::<Text, _>(&checkout_value)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let select_sql = format!("{} WHERE id = {}", select_payment_order_sql(), ph(kind, 1));
                sql_query(select_sql)
                    .bind::<Text, _>(&id)
                    .get_result::<PaymentOrderRecord>(conn)
                    .map_err(AppError::from)
            })
        })
    }

    pub async fn mark_payment_order_paid(
        &self,
        order_id: &str,
        provider_trade_id: &str,
        paid_at: i64,
    ) -> AppResult<PaymentOrderRecord> {
        self.mark_payment_order_paid_with_fence(order_id, provider_trade_id, paid_at, None)
            .await
    }

    /// Finalizes a provider-paid order only while the caller still owns the
    /// exact lease generation. `None` means another worker fenced this
    /// attempt and the provider result must be discarded; a later claimant
    /// will query the provider again and retain wallet idempotency.
    pub async fn mark_payment_order_paid_fenced(
        &self,
        order_id: &str,
        provider_trade_id: &str,
        paid_at: i64,
        fence: &PaymentOrderLease,
    ) -> AppResult<Option<PaymentOrderRecord>> {
        match self
            .mark_payment_order_paid_with_fence(
                order_id,
                provider_trade_id,
                paid_at,
                Some(fence.clone()),
            )
            .await
        {
            Ok(order) => Ok(Some(order)),
            Err(AppError::NotFound) => Ok(None),
            Err(error) => Err(error),
        }
    }

    async fn mark_payment_order_paid_with_fence(
        &self,
        order_id: &str,
        provider_trade_id: &str,
        paid_at: i64,
        fence: Option<PaymentOrderLease>,
    ) -> AppResult<PaymentOrderRecord> {
        let order_id = order_id.to_string();
        let provider_trade_id = provider_trade_id.to_string();
        if provider_trade_id.trim().is_empty() {
            return Err(AppError::BadRequest(
                "payment provider transaction id is required".to_string(),
            ));
        }
        let initial_now = util::now_ts();
        let order_snapshot = self
            .find_payment_order(&order_id)
            .await?
            .ok_or(AppError::NotFound)?;
        if let Some(fence) = fence.as_ref()
            && (order_snapshot.lease_owner.as_deref() != Some(fence.owner.as_str())
                || order_snapshot.lease_generation != fence.generation
                || order_snapshot
                    .lease_expires_at
                    .is_none_or(|expires_at| expires_at <= initial_now))
        {
            return Err(AppError::NotFound);
        }
        if order_snapshot.amount_minor <= 0 {
            return Err(AppError::BadRequest(
                "payment order amount is invalid".to_string(),
            ));
        }
        // Materialize the unique wallet outside the payment transaction so
        // concurrent payments for a new user cannot both race a wallet INSERT
        // while already inside a failed PostgreSQL/MySQL transaction.
        self.ensure_user_wallet_account(&order_snapshot.user_id, &order_snapshot.currency)
            .await?;
        with_conn!(self, |conn, kind| {
            // Wallet materialization can wait for another transaction. Take
            // the fence timestamp only after that wait so a still-owned
            // generation cannot finalize using an already stale `now`.
            let now = util::now_ts();
            conn.transaction::<PaymentOrderRecord, AppError, _>(|conn| {
                let acquired = if let Some(fence) = fence.as_ref() {
                    let acquire_sql = format!(
                        "UPDATE payment_orders SET updated_at = updated_at WHERE id = {} AND lease_owner = {} AND lease_generation = {} AND lease_expires_at > {}",
                        ph(kind, 1),
                        ph(kind, 2),
                        ph(kind, 3),
                        ph(kind, 4)
                    );
                    sql_query(acquire_sql)
                        .bind::<Text, _>(&order_id)
                        .bind::<Text, _>(&fence.owner)
                        .bind::<BigInt, _>(fence.generation)
                        .bind::<BigInt, _>(now)
                        .execute(conn)
                        .map_err(AppError::from)?
                } else {
                    let acquire_sql = format!(
                        "UPDATE payment_orders SET updated_at = updated_at WHERE id = {}",
                        ph(kind, 1)
                    );
                    sql_query(acquire_sql)
                        .bind::<Text, _>(&order_id)
                        .execute(conn)
                        .map_err(AppError::from)?
                };
                if acquired == 0 {
                    return Err(AppError::NotFound);
                }
                let order_sql = format!(
                    "{} WHERE id = {}{}",
                    select_payment_order_sql(),
                    ph(kind, 1),
                    payment_order_lock_suffix(kind)
                );
                let order = sql_query(order_sql)
                    .bind::<Text, _>(&order_id)
                    .get_result::<PaymentOrderRecord>(conn)
                    .map_err(AppError::from)?;
                if order.status == "paid" {
                    if order.provider_trade_id.as_deref() != Some(provider_trade_id.as_str()) {
                        return Err(AppError::BadRequest(
                            "payment order was already paid with a different provider transaction"
                                .to_string(),
                        ));
                    }
                    return Ok(order);
                }
                if !matches!(
                    order.status.as_str(),
                    "creating" | "pending" | "reconcile" | "failed" | "closed"
                ) {
                    return Err(AppError::BadRequest(
                        "payment order is not awaiting payment".to_string(),
                    ));
                }
                if order.amount_minor <= 0 {
                    return Err(AppError::BadRequest(
                        "payment order amount is invalid".to_string(),
                    ));
                }
                // The recharge ledger operation is keyed by the local order
                // id.  It should already be covered by the transaction below,
                // but reading it makes recovery safe even if an older schema
                // or a manual repair left the order status behind the ledger.
                let existing_transaction_sql = format!(
                    "{} WHERE kind = 'recharge' AND idempotency_key = {}",
                    select_wallet_transaction_sql(),
                    ph(kind, 1)
                );
                if let Some(existing) = sql_query(existing_transaction_sql)
                    .bind::<Text, _>(&order.id)
                    .get_result::<WalletTransactionRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                {
                    if existing.amount_minor != order.amount_minor
                        || existing.currency != order.currency
                        || existing.external_order_id.as_deref()
                            != Some(order.merchant_order_no.as_str())
                        || order
                            .provider_trade_id
                            .as_deref()
                            .is_some_and(|value| value != provider_trade_id.as_str())
                    {
                        return Err(AppError::Internal(
                            "billing recharge ledger does not match payment order".to_string(),
                        ));
                    }
                    let update_order_sql = format!(
                        "UPDATE payment_orders SET status = 'paid', provider_trade_id = {}, paid_at = COALESCE(paid_at, {}), next_retry_at = NULL, lease_owner = NULL, lease_expires_at = NULL, updated_at = {}, last_error = NULL WHERE id = {}",
                        ph(kind, 1),
                        ph(kind, 2),
                        ph(kind, 3),
                        ph(kind, 4)
                    );
                    sql_query(update_order_sql)
                        .bind::<Nullable<Text>, _>(Some(provider_trade_id.clone()))
                        .bind::<BigInt, _>(paid_at)
                        .bind::<BigInt, _>(now)
                        .bind::<Text, _>(&order_id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                    let select_sql = format!("{} WHERE id = {}", select_payment_order_sql(), ph(kind, 1));
                    return sql_query(select_sql)
                        .bind::<Text, _>(&order_id)
                        .get_result::<PaymentOrderRecord>(conn)
                        .map_err(AppError::from);
                }
                let scope_key = wallet_account_scope_key(
                    "user_global",
                    Some(&order.user_id),
                    None,
                    &order.currency,
                );
                let wallet_sql = format!(
                    "{} WHERE scope_key = {}{}",
                    select_wallet_account_sql(),
                    ph(kind, 1),
                    payment_order_lock_suffix(kind)
                );
                let wallet = if let Some(wallet) = sql_query(wallet_sql)
                    .bind::<Text, _>(&scope_key)
                    .get_result::<WalletAccountRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                {
                    wallet
                } else {
                    let wallet_id = uuid::Uuid::new_v4().to_string();
                    let insert_wallet_sql = format!(
                        "INSERT INTO wallet_accounts (id, account_kind, scope_key, user_id, application_id, currency, available_minor, reserved_minor, version, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, 0, 0, 0, {}, {})",
                        ph(kind, 1),
                        ph(kind, 2),
                        ph(kind, 3),
                        ph(kind, 4),
                        ph(kind, 5),
                        ph(kind, 6),
                        ph(kind, 7),
                        ph(kind, 8)
                    );
                    sql_query(insert_wallet_sql)
                        .bind::<Text, _>(&wallet_id)
                        .bind::<Text, _>("user_global")
                        .bind::<Text, _>(&scope_key)
                        .bind::<Nullable<Text>, _>(Some(order.user_id.clone()))
                        .bind::<Nullable<Text>, _>(None::<String>)
                        .bind::<Text, _>(&order.currency)
                        .bind::<BigInt, _>(now)
                        .bind::<BigInt, _>(now)
                        .execute(conn)
                        .map_err(AppError::from)?;
                    let select_wallet_sql = format!(
                        "{} WHERE id = {}",
                        select_wallet_account_sql(),
                        ph(kind, 1)
                    );
                    sql_query(select_wallet_sql)
                        .bind::<Text, _>(wallet_id)
                        .get_result::<WalletAccountRecord>(conn)
                        .map_err(AppError::from)?
                };
                let update_wallet_sql = format!(
                    "UPDATE wallet_accounts SET available_minor = available_minor + {}, version = version + 1, updated_at = {} WHERE id = {} AND available_minor <= {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4)
                );
                if sql_query(update_wallet_sql)
                    .bind::<BigInt, _>(order.amount_minor)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&wallet.id)
                    .bind::<BigInt, _>(i64::MAX - order.amount_minor)
                    .execute(conn)
                    .map_err(AppError::from)?
                    == 0
                {
                    return Err(AppError::Internal(
                        "billing wallet balance would overflow".to_string(),
                    ));
                }
                let transaction_id = uuid::Uuid::new_v4().to_string();
                let insert_transaction_sql = format!(
                    "INSERT INTO wallet_transactions (id, kind, status, user_id, application_id, currency, amount_minor, source_wallet_id, destination_wallet_id, hold_id, idempotency_key, external_provider, external_order_id, metadata, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
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
                    ph(kind, 16)
                );
                sql_query(insert_transaction_sql)
                    .bind::<Text, _>(&transaction_id)
                    .bind::<Text, _>("recharge")
                    .bind::<Text, _>("committed")
                    .bind::<Nullable<Text>, _>(Some(order.user_id.clone()))
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<Text, _>(&order.currency)
                    .bind::<BigInt, _>(order.amount_minor)
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<Nullable<Text>, _>(Some(wallet.id.clone()))
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<Text, _>(&order.id)
                    .bind::<Nullable<Text>, _>(Some(order.provider_slug.clone()))
                    .bind::<Nullable<Text>, _>(Some(order.merchant_order_no.clone()))
                    .bind::<Text, _>("{}")
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let entry_sql = format!(
                    "INSERT INTO wallet_entries (id, transaction_id, wallet_id, available_delta_minor, reserved_delta_minor, created_at) VALUES ({}, {}, {}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                    ph(kind, 6)
                );
                sql_query(entry_sql)
                    .bind::<Text, _>(uuid::Uuid::new_v4().to_string())
                    .bind::<Text, _>(&transaction_id)
                    .bind::<Text, _>(&wallet.id)
                    .bind::<BigInt, _>(order.amount_minor)
                    .bind::<BigInt, _>(0_i64)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let update_order_sql = format!(
                    "UPDATE payment_orders SET status = {}, provider_trade_id = {}, paid_at = {}, next_retry_at = NULL, lease_owner = NULL, lease_expires_at = NULL, updated_at = {}, last_error = {} WHERE id = {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                    ph(kind, 6)
                );
                sql_query(update_order_sql)
                    .bind::<Text, _>("paid")
                    .bind::<Nullable<Text>, _>(Some(provider_trade_id.to_string()))
                    .bind::<Nullable<BigInt>, _>(Some(paid_at))
                    .bind::<BigInt, _>(now)
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<Text, _>(&order_id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let select_sql = format!("{} WHERE id = {}", select_payment_order_sql(), ph(kind, 1));
                sql_query(select_sql)
                    .bind::<Text, _>(&order_id)
                    .get_result::<PaymentOrderRecord>(conn)
                    .map_err(AppError::from)
            })
        })
    }

    /// Atomically creates (or reopens the caller's view of) a refund intent.
    ///
    /// `pending` is deliberately included in the refundable total.  A
    /// pending row means that the provider may already have accepted the
    /// refund, so it must never be silently discarded or excluded from the
    /// order limit.  Recovery retries the provider with the same idempotency
    /// key and then calls [`Self::finalize_payment_refund`].
    pub async fn reserve_payment_refund(
        &self,
        order_id: &str,
        amount_minor: i64,
        requested_by: Option<&str>,
        reason: &str,
        idempotency_key: &str,
    ) -> AppResult<PaymentRefundRecord> {
        #[derive(diesel::QueryableByName)]
        struct TotalRow {
            #[diesel(sql_type = BigInt)]
            total: i64,
        }

        if idempotency_key.trim().is_empty() {
            return Err(AppError::BadRequest(
                "billing idempotency_key is invalid".to_string(),
            ));
        }
        let order_id = order_id.to_string();
        let requested_by = requested_by.map(ToOwned::to_owned);
        let reason = reason.chars().take(512).collect::<String>();
        let idempotency_key = idempotency_key.to_string();
        with_conn!(self, |conn, kind| {
            conn.transaction::<PaymentRefundRecord, AppError, _>(|conn| {
                // Lock before looking up the intent.  The second lookup is
                // intentionally inside the lock: otherwise two concurrent
                // transactions can both miss the key and insert two rows.
                let order_sql = format!(
                    "{} WHERE id = {}{}",
                    select_payment_order_sql(),
                    ph(kind, 1),
                    payment_order_lock_suffix(kind)
                );
                let order = sql_query(order_sql)
                    .bind::<Text, _>(&order_id)
                    .get_result::<PaymentOrderRecord>(conn)
                    .map_err(AppError::from)?;
                let existing_sql = format!(
                    "{} WHERE payment_order_id = {} AND idempotency_key = {} ORDER BY created_at DESC, id DESC LIMIT 1{}",
                    select_payment_refund_sql(),
                    ph(kind, 1),
                    ph(kind, 2),
                    payment_order_lock_suffix(kind)
                );
                if let Some(existing) = sql_query(existing_sql)
                    .bind::<Text, _>(&order_id)
                    .bind::<Text, _>(&idempotency_key)
                    .get_result::<PaymentRefundRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                {
                    if existing.amount_minor != amount_minor {
                        return Err(AppError::BadRequest(
                            "billing idempotency_key is already used for another refund"
                                .to_string(),
                        ));
                    }
                    if payment_refund_counts_toward_limit(&existing.status)
                        || existing.status == "canceled"
                    {
                        // succeeded/canceled are terminal replays; pending
                        // is the recoverable state after an unknown outcome
                        // such as a process crash between provider and DB.
                        return Ok(existing);
                    }
                    return Err(AppError::Internal(
                        "billing refund has an unsupported status".to_string(),
                    ));
                }
                if amount_minor <= 0 || order.status != "paid" {
                    return Err(AppError::BadRequest(
                        "payment order is not refundable".to_string(),
                    ));
                }

                let total_sql = format!(
                    "SELECT COALESCE(SUM(amount_minor), 0) AS total FROM payment_refunds WHERE payment_order_id = {} AND status IN ('pending', 'succeeded')",
                    ph(kind, 1)
                );
                let reserved = sql_query(total_sql)
                    .bind::<Text, _>(&order_id)
                    .get_result::<TotalRow>(conn)
                    .map_err(AppError::from)?
                    .total;
                if amount_minor > order.amount_minor.saturating_sub(reserved) {
                    return Err(AppError::BadRequest(
                        "billing refund exceeds the refundable payment amount".to_string(),
                    ));
                }

                // This is a precondition for the later finalize debit.  The
                // conditional UPDATE in finalize remains the final race
                // guard if another wallet operation spends the balance while
                // the provider request is in flight.
                let scope_key = wallet_account_scope_key(
                    "user_global",
                    Some(&order.user_id),
                    None,
                    &order.currency,
                );
                let wallet_sql = format!(
                    "{} WHERE scope_key = {}{}",
                    select_wallet_account_sql(),
                    ph(kind, 1),
                    payment_order_lock_suffix(kind)
                );
                let wallet = sql_query(wallet_sql)
                    .bind::<Text, _>(&scope_key)
                    .get_result::<WalletAccountRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                    .ok_or_else(|| {
                        AppError::BadRequest(
                            "the user wallet has no refundable balance".to_string(),
                        )
                    })?;
                if wallet.available_minor < amount_minor {
                    return Err(AppError::BadRequest(
                        "billing refund would make the wallet balance negative".to_string(),
                    ));
                }

                let refund_id = uuid::Uuid::new_v4().to_string();
                let now = util::now_ts();
                let refund_sql = format!(
                    "INSERT INTO payment_refunds (id, payment_order_id, amount_minor, status, provider_refund_id, requested_by, reason, idempotency_key, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                    ph(kind, 6),
                    ph(kind, 7),
                    ph(kind, 8),
                    ph(kind, 9),
                    ph(kind, 10)
                );
                sql_query(refund_sql)
                    .bind::<Text, _>(&refund_id)
                    .bind::<Text, _>(&order_id)
                    .bind::<BigInt, _>(amount_minor)
                    .bind::<Text, _>("pending")
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<Nullable<Text>, _>(requested_by)
                    .bind::<Text, _>(&reason)
                    .bind::<Text, _>(&idempotency_key)
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let select_sql = format!(
                    "{} WHERE id = {}",
                    select_payment_refund_sql(),
                    ph(kind, 1)
                );
                sql_query(select_sql)
                    .bind::<Text, _>(refund_id)
                    .get_result::<PaymentRefundRecord>(conn)
                    .map_err(AppError::from)
            })
        })
    }

    /// Commits a provider-accepted refund and its wallet ledger effects in a
    /// single transaction.  A failure leaves the intent `pending`, never
    /// `canceled`: the next request with the same key can call the provider's
    /// idempotent refund endpoint again and retry this local finalize.
    pub async fn finalize_payment_refund(
        &self,
        order_id: &str,
        refund_id: &str,
        provider_refund_id: &str,
    ) -> AppResult<PaymentRefundRecord> {
        if provider_refund_id.trim().is_empty() {
            return Err(AppError::BadRequest(
                "billing provider refund id is required".to_string(),
            ));
        }
        let order_id = order_id.to_string();
        let refund_id = refund_id.to_string();
        let provider_refund_id = provider_refund_id.to_string();
        with_conn!(self, |conn, kind| {
            conn.transaction::<PaymentRefundRecord, AppError, _>(|conn| {
                let order_sql = format!(
                    "{} WHERE id = {}{}",
                    select_payment_order_sql(),
                    ph(kind, 1),
                    payment_order_lock_suffix(kind)
                );
                let order = sql_query(order_sql)
                    .bind::<Text, _>(&order_id)
                    .get_result::<PaymentOrderRecord>(conn)
                    .map_err(AppError::from)?;
                let refund_sql = format!(
                    "{} WHERE id = {} AND payment_order_id = {}{}",
                    select_payment_refund_sql(),
                    ph(kind, 1),
                    ph(kind, 2),
                    payment_order_lock_suffix(kind)
                );
                let refund = sql_query(refund_sql)
                    .bind::<Text, _>(&refund_id)
                    .bind::<Text, _>(&order_id)
                    .get_result::<PaymentRefundRecord>(conn)
                    .map_err(AppError::from)?;
                if refund.status == "succeeded" {
                    if refund.provider_refund_id.as_deref() != Some(provider_refund_id.as_str()) {
                        return Err(AppError::BadRequest(
                            "billing provider refund id changed for an existing refund"
                                .to_string(),
                        ));
                    }
                    return Ok(refund);
                }
                if refund.status == "canceled" {
                    return Err(AppError::BadRequest(
                        "billing refund intent is canceled".to_string(),
                    ));
                }
                if refund.status != "pending" {
                    return Err(AppError::Internal(
                        "billing refund has an unsupported status".to_string(),
                    ));
                }
                if order.status != "paid" {
                    return Err(AppError::BadRequest(
                        "payment order is no longer refundable".to_string(),
                    ));
                }

                let scope_key = wallet_account_scope_key(
                    "user_global",
                    Some(&order.user_id),
                    None,
                    &order.currency,
                );
                let wallet_sql = format!(
                    "{} WHERE scope_key = {}{}",
                    select_wallet_account_sql(),
                    ph(kind, 1),
                    payment_order_lock_suffix(kind)
                );
                let wallet = sql_query(wallet_sql)
                    .bind::<Text, _>(&scope_key)
                    .get_result::<WalletAccountRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                    .ok_or_else(|| {
                        AppError::BadRequest(
                            "the user wallet has no refundable balance".to_string(),
                        )
                    })?;
                let now = util::now_ts();
                let debit_sql = format!(
                    "UPDATE wallet_accounts SET available_minor = available_minor - {}, version = version + 1, updated_at = {} WHERE id = {} AND currency = {} AND available_minor >= {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5)
                );
                if sql_query(debit_sql)
                    .bind::<BigInt, _>(refund.amount_minor)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&wallet.id)
                    .bind::<Text, _>(&order.currency)
                    .bind::<BigInt, _>(refund.amount_minor)
                    .execute(conn)
                    .map_err(AppError::from)?
                    == 0
                {
                    // Keep pending.  The provider may already have accepted
                    // the refund; a later replay must retry local finalize.
                    return Err(AppError::BadRequest(
                        "billing refund would make the wallet balance negative".to_string(),
                    ));
                }

                let transaction_id = uuid::Uuid::new_v4().to_string();
                let transaction_sql = format!(
                    "INSERT INTO wallet_transactions (id, kind, status, user_id, application_id, currency, amount_minor, source_wallet_id, destination_wallet_id, hold_id, idempotency_key, external_provider, external_order_id, metadata, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
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
                    ph(kind, 16)
                );
                sql_query(transaction_sql)
                    .bind::<Text, _>(&transaction_id)
                    .bind::<Text, _>("recharge_refund")
                    .bind::<Text, _>("committed")
                    .bind::<Nullable<Text>, _>(Some(order.user_id.clone()))
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<Text, _>(&order.currency)
                    .bind::<BigInt, _>(refund.amount_minor)
                    .bind::<Nullable<Text>, _>(Some(wallet.id.clone()))
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<Nullable<Text>, _>(None::<String>)
                    // Scope the wallet operation by refund id.  Refund keys
                    // are scoped to an order, while wallet operations have a
                    // database-wide (kind, key) uniqueness constraint.
                    .bind::<Text, _>(&refund.id)
                    .bind::<Nullable<Text>, _>(Some(order.provider_slug.clone()))
                    .bind::<Nullable<Text>, _>(Some(order_id.clone()))
                    .bind::<Text, _>("{}")
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let entry_sql = format!(
                    "INSERT INTO wallet_entries (id, transaction_id, wallet_id, available_delta_minor, reserved_delta_minor, created_at) VALUES ({}, {}, {}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                    ph(kind, 6)
                );
                sql_query(entry_sql)
                    .bind::<Text, _>(uuid::Uuid::new_v4().to_string())
                    .bind::<Text, _>(&transaction_id)
                    .bind::<Text, _>(&wallet.id)
                    .bind::<BigInt, _>(-refund.amount_minor)
                    .bind::<BigInt, _>(0_i64)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let update_sql = format!(
                    "UPDATE payment_refunds SET status = {}, provider_refund_id = {}, updated_at = {} WHERE id = {} AND payment_order_id = {} AND status = 'pending'",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5)
                );
                if sql_query(update_sql)
                    .bind::<Text, _>("succeeded")
                    .bind::<Nullable<Text>, _>(Some(provider_refund_id))
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&refund.id)
                    .bind::<Text, _>(&order_id)
                    .execute(conn)
                    .map_err(AppError::from)?
                    != 1
                {
                    return Err(AppError::Internal(
                        "billing refund intent changed during finalize".to_string(),
                    ));
                }
                let select_sql = format!(
                    "{} WHERE id = {}",
                    select_payment_refund_sql(),
                    ph(kind, 1)
                );
                sql_query(select_sql)
                    .bind::<Text, _>(&refund.id)
                    .get_result::<PaymentRefundRecord>(conn)
                    .map_err(AppError::from)
            })
        })
    }

    /// Cancels an intent only after the provider call returned a known
    /// failure.  It is idempotent; a succeeded intent is never downgraded.
    pub async fn cancel_payment_refund(
        &self,
        order_id: &str,
        refund_id: &str,
    ) -> AppResult<PaymentRefundRecord> {
        let order_id = order_id.to_string();
        let refund_id = refund_id.to_string();
        with_conn!(self, |conn, kind| {
            conn.transaction::<PaymentRefundRecord, AppError, _>(|conn| {
                let order_sql = format!(
                    "{} WHERE id = {}{}",
                    select_payment_order_sql(),
                    ph(kind, 1),
                    payment_order_lock_suffix(kind)
                );
                sql_query(order_sql)
                    .bind::<Text, _>(&order_id)
                    .get_result::<PaymentOrderRecord>(conn)
                    .map_err(AppError::from)?;
                let refund_sql = format!(
                    "{} WHERE id = {} AND payment_order_id = {}{}",
                    select_payment_refund_sql(),
                    ph(kind, 1),
                    ph(kind, 2),
                    payment_order_lock_suffix(kind)
                );
                let refund = sql_query(refund_sql)
                    .bind::<Text, _>(&refund_id)
                    .bind::<Text, _>(&order_id)
                    .get_result::<PaymentRefundRecord>(conn)
                    .map_err(AppError::from)?;
                if refund.status == "succeeded" || refund.status == "canceled" {
                    return Ok(refund);
                }
                if refund.status != "pending" {
                    return Err(AppError::Internal(
                        "billing refund has an unsupported status".to_string(),
                    ));
                }
                let update_sql = format!(
                    "UPDATE payment_refunds SET status = {}, updated_at = {} WHERE id = {} AND payment_order_id = {} AND status = 'pending'",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4)
                );
                if sql_query(update_sql)
                    .bind::<Text, _>("canceled")
                    .bind::<BigInt, _>(util::now_ts())
                    .bind::<Text, _>(&refund.id)
                    .bind::<Text, _>(&order_id)
                    .execute(conn)
                    .map_err(AppError::from)?
                    != 1
                {
                    return Err(AppError::Internal(
                        "billing refund intent changed during cancellation".to_string(),
                    ));
                }
                let select_sql = format!(
                    "{} WHERE id = {}",
                    select_payment_refund_sql(),
                    ph(kind, 1)
                );
                sql_query(select_sql)
                    .bind::<Text, _>(&refund.id)
                    .get_result::<PaymentRefundRecord>(conn)
                    .map_err(AppError::from)
            })
        })
    }

    /// Compatibility entry point for callers that already completed the
    /// provider operation.  New code must reserve before invoking a provider;
    /// this wrapper preserves the existing DB API and uses the same atomic
    /// finalization path for old callers and tests.
    pub async fn refund_payment_order(
        &self,
        order_id: &str,
        amount_minor: i64,
        provider_refund_id: &str,
        requested_by: Option<&str>,
        reason: &str,
        idempotency_key: &str,
    ) -> AppResult<PaymentRefundRecord> {
        if provider_refund_id.trim().is_empty() {
            return Err(AppError::BadRequest(
                "billing refund is invalid".to_string(),
            ));
        }
        let intent = self
            .reserve_payment_refund(
                order_id,
                amount_minor,
                requested_by,
                reason,
                idempotency_key,
            )
            .await?;
        match intent.status.as_str() {
            "succeeded" | "canceled" => Ok(intent),
            "pending" => {
                self.finalize_payment_refund(order_id, &intent.id, provider_refund_id)
                    .await
            }
            _ => Err(AppError::Internal(
                "billing refund has an unsupported status".to_string(),
            )),
        }
    }

    pub async fn reserve_wallet_hold(
        &self,
        wallet_id: &str,
        user_id: &str,
        application_id: &str,
        currency: &str,
        amount_minor: i64,
        reference: &str,
        idempotency_key: &str,
        expires_at: i64,
    ) -> AppResult<WalletHoldRecord> {
        let wallet_id = wallet_id.to_string();
        let user_id = user_id.to_string();
        let application_id = application_id.to_string();
        let currency = currency.to_string();
        let reference = reference.to_string();
        let idempotency_key = idempotency_key.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<WalletHoldRecord, AppError, _>(|conn| {
                let existing_sql = format!(
                    "{} WHERE hold_kind = {} AND idempotency_key = {}",
                    select_wallet_hold_sql(),
                    ph(kind, 1),
                    ph(kind, 2)
                );
                if let Some(existing) = sql_query(existing_sql)
                    .bind::<Text, _>("spend")
                    .bind::<Text, _>(&idempotency_key)
                    .get_result::<WalletHoldRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                {
                    return Ok(existing);
                }
                if amount_minor <= 0 {
                    return Err(AppError::BadRequest(
                        "billing amount must be positive".to_string(),
                    ));
                }
                let update_wallet_sql = format!(
                    "UPDATE wallet_accounts SET available_minor = available_minor - {}, reserved_minor = reserved_minor + {}, version = version + 1, updated_at = {} WHERE id = {} AND currency = {} AND available_minor >= {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                    ph(kind, 6)
                );
                let affected = sql_query(update_wallet_sql)
                    .bind::<BigInt, _>(amount_minor)
                    .bind::<BigInt, _>(amount_minor)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&wallet_id)
                    .bind::<Text, _>(&currency)
                    .bind::<BigInt, _>(amount_minor)
                    .execute(conn)
                    .map_err(AppError::from)?;
                if affected == 0 {
                    return Err(AppError::BadRequest(
                        "billing balance is insufficient or wallet is unavailable".to_string(),
                    ));
                }
                let hold_id = uuid::Uuid::new_v4().to_string();
                let insert_hold_sql = format!(
                    "INSERT INTO wallet_holds (id, hold_kind, wallet_id, user_id, application_id, currency, amount_minor, status, reference, idempotency_key, expires_at, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
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
                    ph(kind, 13)
                );
                sql_query(insert_hold_sql)
                    .bind::<Text, _>(&hold_id)
                    .bind::<Text, _>("spend")
                    .bind::<Text, _>(&wallet_id)
                    .bind::<Nullable<Text>, _>(Some(user_id.clone()))
                    .bind::<Nullable<Text>, _>(Some(application_id.clone()))
                    .bind::<Text, _>(&currency)
                    .bind::<BigInt, _>(amount_minor)
                    .bind::<Text, _>("pending")
                    .bind::<Text, _>(&reference)
                    .bind::<Text, _>(&idempotency_key)
                    .bind::<BigInt, _>(expires_at)
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let transaction_id = uuid::Uuid::new_v4().to_string();
                let insert_transaction_sql = format!(
                    "INSERT INTO wallet_transactions (id, kind, status, user_id, application_id, currency, amount_minor, source_wallet_id, destination_wallet_id, hold_id, idempotency_key, external_provider, external_order_id, metadata, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
                    ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6),
                    ph(kind, 7), ph(kind, 8), ph(kind, 9), ph(kind, 10), ph(kind, 11), ph(kind, 12),
                    ph(kind, 13), ph(kind, 14), ph(kind, 15), ph(kind, 16)
                );
                sql_query(insert_transaction_sql)
                    .bind::<Text, _>(&transaction_id)
                    .bind::<Text, _>("reserve")
                    .bind::<Text, _>("committed")
                    .bind::<Nullable<Text>, _>(Some(user_id.clone()))
                    .bind::<Nullable<Text>, _>(Some(application_id.clone()))
                    .bind::<Text, _>(&currency)
                    .bind::<BigInt, _>(amount_minor)
                    .bind::<Nullable<Text>, _>(Some(wallet_id.clone()))
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<Nullable<Text>, _>(Some(hold_id.clone()))
                    .bind::<Text, _>(&idempotency_key)
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<Nullable<Text>, _>(Some(reference.clone()))
                    .bind::<Text, _>("{}")
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let entry_sql = format!(
                    "INSERT INTO wallet_entries (id, transaction_id, wallet_id, available_delta_minor, reserved_delta_minor, created_at) VALUES ({}, {}, {}, {}, {}, {})",
                    ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6)
                );
                sql_query(entry_sql)
                    .bind::<Text, _>(uuid::Uuid::new_v4().to_string())
                    .bind::<Text, _>(&transaction_id)
                    .bind::<Text, _>(&wallet_id)
                    .bind::<BigInt, _>(-amount_minor)
                    .bind::<BigInt, _>(amount_minor)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let select_sql = format!("{} WHERE id = {}", select_wallet_hold_sql(), ph(kind, 1));
                sql_query(select_sql)
                    .bind::<Text, _>(hold_id)
                    .get_result::<WalletHoldRecord>(conn)
                    .map_err(AppError::from)
            })
        })
    }

    pub async fn find_wallet_hold(&self, hold_id: &str) -> AppResult<Option<WalletHoldRecord>> {
        let hold_id = hold_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!("{} WHERE id = {}", select_wallet_hold_sql(), ph(kind, 1));
            sql_query(sql)
                .bind::<Text, _>(hold_id)
                .get_result::<WalletHoldRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn commit_wallet_hold(
        &self,
        hold_id: &str,
        settlement_wallet_id: &str,
        idempotency_key: &str,
    ) -> AppResult<WalletHoldRecord> {
        let hold_id = hold_id.to_string();
        let settlement_wallet_id = settlement_wallet_id.to_string();
        let idempotency_key = idempotency_key.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<WalletHoldRecord, AppError, _>(|conn| {
                let hold_sql = format!("{} WHERE id = {}", select_wallet_hold_sql(), ph(kind, 1));
                let hold = sql_query(hold_sql)
                    .bind::<Text, _>(&hold_id)
                    .get_result::<WalletHoldRecord>(conn)
                    .map_err(AppError::from)?;
                let existing_operation_sql = format!(
                    "{} WHERE kind = 'commit' AND idempotency_key = {}",
                    select_wallet_transaction_sql(),
                    ph(kind, 1)
                );
                if let Some(existing) = sql_query(existing_operation_sql)
                    .bind::<Text, _>(&idempotency_key)
                    .get_result::<WalletTransactionRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                {
                    if existing.hold_id.as_deref() != Some(hold_id.as_str()) {
                        return Err(AppError::BadRequest(
                            "billing idempotency_key is already used for another commit"
                                .to_string(),
                        ));
                    }
                    return Ok(hold);
                }
                if hold.status == "committed" {
                    return Ok(hold);
                }
                if hold.status != "pending" {
                    return Err(AppError::BadRequest("billing hold is not pending".to_string()));
                }
                if hold.expires_at <= now {
                    return Err(AppError::BadRequest("billing hold has expired".to_string()));
                }
                let source_sql = format!(
                    "UPDATE wallet_accounts SET reserved_minor = reserved_minor - {}, version = version + 1, updated_at = {} WHERE id = {} AND reserved_minor >= {}",
                    ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4)
                );
                if sql_query(source_sql)
                    .bind::<BigInt, _>(hold.amount_minor)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&hold.wallet_id)
                    .bind::<BigInt, _>(hold.amount_minor)
                    .execute(conn)
                    .map_err(AppError::from)?
                    == 0
                {
                    return Err(AppError::BadRequest("billing hold source is unavailable".to_string()));
                }
                let destination_sql = format!(
                    "UPDATE wallet_accounts SET available_minor = available_minor + {}, version = version + 1, updated_at = {} WHERE id = {} AND currency = {}",
                    ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4)
                );
                if sql_query(destination_sql)
                    .bind::<BigInt, _>(hold.amount_minor)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&settlement_wallet_id)
                    .bind::<Text, _>(&hold.currency)
                    .execute(conn)
                    .map_err(AppError::from)?
                    == 0
                {
                    return Err(AppError::BadRequest("billing settlement wallet is unavailable".to_string()));
                }
                let transaction_id = uuid::Uuid::new_v4().to_string();
                let insert_transaction_sql = format!(
                    "INSERT INTO wallet_transactions (id, kind, status, user_id, application_id, currency, amount_minor, source_wallet_id, destination_wallet_id, hold_id, idempotency_key, external_provider, external_order_id, metadata, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
                    ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6),
                    ph(kind, 7), ph(kind, 8), ph(kind, 9), ph(kind, 10), ph(kind, 11), ph(kind, 12),
                    ph(kind, 13), ph(kind, 14), ph(kind, 15), ph(kind, 16)
                );
                sql_query(insert_transaction_sql)
                    .bind::<Text, _>(&transaction_id)
                    .bind::<Text, _>("commit")
                    .bind::<Text, _>("committed")
                    .bind::<Nullable<Text>, _>(hold.user_id.clone())
                    .bind::<Nullable<Text>, _>(hold.application_id.clone())
                    .bind::<Text, _>(&hold.currency)
                    .bind::<BigInt, _>(hold.amount_minor)
                    .bind::<Nullable<Text>, _>(Some(hold.wallet_id.clone()))
                    .bind::<Nullable<Text>, _>(Some(settlement_wallet_id.clone()))
                    .bind::<Nullable<Text>, _>(Some(hold_id.clone()))
                    .bind::<Text, _>(&idempotency_key)
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<Nullable<Text>, _>(Some(hold.reference.clone()))
                    .bind::<Text, _>("{}")
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let entry_sql = format!(
                    "INSERT INTO wallet_entries (id, transaction_id, wallet_id, available_delta_minor, reserved_delta_minor, created_at) VALUES ({}, {}, {}, {}, {}, {}), ({}, {}, {}, {}, {}, {})",
                    ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6),
                    ph(kind, 7), ph(kind, 8), ph(kind, 9), ph(kind, 10), ph(kind, 11), ph(kind, 12)
                );
                sql_query(entry_sql)
                    .bind::<Text, _>(uuid::Uuid::new_v4().to_string())
                    .bind::<Text, _>(&transaction_id)
                    .bind::<Text, _>(&hold.wallet_id)
                    .bind::<BigInt, _>(0_i64)
                    .bind::<BigInt, _>(-hold.amount_minor)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(uuid::Uuid::new_v4().to_string())
                    .bind::<Text, _>(&transaction_id)
                    .bind::<Text, _>(&settlement_wallet_id)
                    .bind::<BigInt, _>(hold.amount_minor)
                    .bind::<BigInt, _>(0_i64)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let update_hold_sql = format!(
                    "UPDATE wallet_holds SET status = {}, updated_at = {} WHERE id = {}",
                    ph(kind, 1), ph(kind, 2), ph(kind, 3)
                );
                sql_query(update_hold_sql)
                    .bind::<Text, _>("committed")
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&hold_id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let select_sql = format!("{} WHERE id = {}", select_wallet_hold_sql(), ph(kind, 1));
                sql_query(select_sql)
                    .bind::<Text, _>(&hold_id)
                    .get_result::<WalletHoldRecord>(conn)
                    .map_err(AppError::from)
            })
        })
    }

    pub async fn release_wallet_hold(
        &self,
        hold_id: &str,
        idempotency_key: &str,
    ) -> AppResult<WalletHoldRecord> {
        let hold_id = hold_id.to_string();
        let idempotency_key = idempotency_key.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<WalletHoldRecord, AppError, _>(|conn| {
                let hold_sql = format!("{} WHERE id = {}", select_wallet_hold_sql(), ph(kind, 1));
                let hold = sql_query(hold_sql)
                    .bind::<Text, _>(&hold_id)
                    .get_result::<WalletHoldRecord>(conn)
                    .map_err(AppError::from)?;
                let existing_operation_sql = format!(
                    "{} WHERE kind = 'release' AND idempotency_key = {}",
                    select_wallet_transaction_sql(),
                    ph(kind, 1)
                );
                if let Some(existing) = sql_query(existing_operation_sql)
                    .bind::<Text, _>(&idempotency_key)
                    .get_result::<WalletTransactionRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                {
                    if existing.hold_id.as_deref() != Some(hold_id.as_str()) {
                        return Err(AppError::BadRequest(
                            "billing idempotency_key is already used for another release"
                                .to_string(),
                        ));
                    }
                    return Ok(hold);
                }
                if hold.status == "released" {
                    return Ok(hold);
                }
                if hold.status != "pending" {
                    return Err(AppError::BadRequest("billing hold is not pending".to_string()));
                }
                let update_wallet_sql = format!(
                    "UPDATE wallet_accounts SET available_minor = available_minor + {}, reserved_minor = reserved_minor - {}, version = version + 1, updated_at = {} WHERE id = {} AND reserved_minor >= {}",
                    ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5)
                );
                if sql_query(update_wallet_sql)
                    .bind::<BigInt, _>(hold.amount_minor)
                    .bind::<BigInt, _>(hold.amount_minor)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&hold.wallet_id)
                    .bind::<BigInt, _>(hold.amount_minor)
                    .execute(conn)
                    .map_err(AppError::from)?
                    == 0
                {
                    return Err(AppError::BadRequest("billing hold source is unavailable".to_string()));
                }
                let transaction_id = uuid::Uuid::new_v4().to_string();
                let insert_transaction_sql = format!(
                    "INSERT INTO wallet_transactions (id, kind, status, user_id, application_id, currency, amount_minor, source_wallet_id, destination_wallet_id, hold_id, idempotency_key, external_provider, external_order_id, metadata, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
                    ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6),
                    ph(kind, 7), ph(kind, 8), ph(kind, 9), ph(kind, 10), ph(kind, 11), ph(kind, 12),
                    ph(kind, 13), ph(kind, 14), ph(kind, 15), ph(kind, 16)
                );
                sql_query(insert_transaction_sql)
                    .bind::<Text, _>(&transaction_id)
                    .bind::<Text, _>("release")
                    .bind::<Text, _>("committed")
                    .bind::<Nullable<Text>, _>(hold.user_id.clone())
                    .bind::<Nullable<Text>, _>(hold.application_id.clone())
                    .bind::<Text, _>(&hold.currency)
                    .bind::<BigInt, _>(hold.amount_minor)
                    .bind::<Nullable<Text>, _>(Some(hold.wallet_id.clone()))
                    .bind::<Nullable<Text>, _>(Some(hold.wallet_id.clone()))
                    .bind::<Nullable<Text>, _>(Some(hold_id.clone()))
                    .bind::<Text, _>(&idempotency_key)
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<Nullable<Text>, _>(Some(hold.reference.clone()))
                    .bind::<Text, _>("{}")
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let entry_sql = format!(
                    "INSERT INTO wallet_entries (id, transaction_id, wallet_id, available_delta_minor, reserved_delta_minor, created_at) VALUES ({}, {}, {}, {}, {}, {})",
                    ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6)
                );
                sql_query(entry_sql)
                    .bind::<Text, _>(uuid::Uuid::new_v4().to_string())
                    .bind::<Text, _>(&transaction_id)
                    .bind::<Text, _>(&hold.wallet_id)
                    .bind::<BigInt, _>(hold.amount_minor)
                    .bind::<BigInt, _>(-hold.amount_minor)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let update_hold_sql = format!(
                    "UPDATE wallet_holds SET status = {}, updated_at = {} WHERE id = {}",
                    ph(kind, 1), ph(kind, 2), ph(kind, 3)
                );
                sql_query(update_hold_sql)
                    .bind::<Text, _>("released")
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&hold_id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let select_sql = format!("{} WHERE id = {}", select_wallet_hold_sql(), ph(kind, 1));
                sql_query(select_sql)
                    .bind::<Text, _>(&hold_id)
                    .get_result::<WalletHoldRecord>(conn)
                    .map_err(AppError::from)
            })
        })
    }

    pub async fn transfer_wallets(
        &self,
        user_id: &str,
        source_wallet_id: &str,
        destination_wallet_id: &str,
        currency: &str,
        amount_minor: i64,
        application_id: Option<&str>,
        idempotency_key: &str,
    ) -> AppResult<WalletTransactionRecord> {
        let user_id = user_id.to_string();
        let source_wallet_id = source_wallet_id.to_string();
        let destination_wallet_id = destination_wallet_id.to_string();
        let currency = currency.to_string();
        let application_id = application_id.map(ToOwned::to_owned);
        let idempotency_key = idempotency_key.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<WalletTransactionRecord, AppError, _>(|conn| {
                let existing_sql = format!(
                    "{} WHERE kind = {} AND idempotency_key = {}",
                    select_wallet_transaction_sql(),
                    ph(kind, 1),
                    ph(kind, 2)
                );
                if let Some(existing) = sql_query(existing_sql)
                    .bind::<Text, _>("transfer")
                    .bind::<Text, _>(&idempotency_key)
                    .get_result::<WalletTransactionRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                {
                    return Ok(existing);
                }
                if amount_minor <= 0 || source_wallet_id == destination_wallet_id {
                    return Err(AppError::BadRequest("billing transfer is invalid".to_string()));
                }
                let source_sql = format!(
                    "{} WHERE id = {} AND account_kind IN ('user_global', 'user_application') AND user_id = {} AND currency = {}",
                    select_wallet_account_sql(),
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3)
                );
                let source = sql_query(source_sql)
                    .bind::<Text, _>(&source_wallet_id)
                    .bind::<Text, _>(&user_id)
                    .bind::<Text, _>(&currency)
                    .get_result::<WalletAccountRecord>(conn)
                    .map_err(AppError::from)?;
                let destination_sql = format!(
                    "{} WHERE id = {} AND account_kind IN ('user_global', 'user_application') AND user_id = {} AND currency = {}",
                    select_wallet_account_sql(),
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3)
                );
                let destination = sql_query(destination_sql)
                    .bind::<Text, _>(&destination_wallet_id)
                    .bind::<Text, _>(&user_id)
                    .bind::<Text, _>(&currency)
                    .get_result::<WalletAccountRecord>(conn)
                    .map_err(AppError::from)?;
                let debit_sql = format!(
                    "UPDATE wallet_accounts SET available_minor = available_minor - {}, version = version + 1, updated_at = {} WHERE id = {} AND available_minor >= {}",
                    ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4)
                );
                if sql_query(debit_sql)
                    .bind::<BigInt, _>(amount_minor)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&source.id)
                    .bind::<BigInt, _>(amount_minor)
                    .execute(conn)
                    .map_err(AppError::from)?
                    == 0
                {
                    return Err(AppError::BadRequest("billing balance is insufficient".to_string()));
                }
                let credit_sql = format!(
                    "UPDATE wallet_accounts SET available_minor = available_minor + {}, version = version + 1, updated_at = {} WHERE id = {}",
                    ph(kind, 1), ph(kind, 2), ph(kind, 3)
                );
                sql_query(credit_sql)
                    .bind::<BigInt, _>(amount_minor)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&destination.id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let transaction_id = uuid::Uuid::new_v4().to_string();
                let transaction_sql = format!(
                    "INSERT INTO wallet_transactions (id, kind, status, user_id, application_id, currency, amount_minor, source_wallet_id, destination_wallet_id, hold_id, idempotency_key, external_provider, external_order_id, metadata, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
                    ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6),
                    ph(kind, 7), ph(kind, 8), ph(kind, 9), ph(kind, 10), ph(kind, 11), ph(kind, 12),
                    ph(kind, 13), ph(kind, 14), ph(kind, 15), ph(kind, 16)
                );
                sql_query(transaction_sql)
                    .bind::<Text, _>(&transaction_id)
                    .bind::<Text, _>("transfer")
                    .bind::<Text, _>("committed")
                    .bind::<Nullable<Text>, _>(Some(user_id.clone()))
                    .bind::<Nullable<Text>, _>(application_id.clone())
                    .bind::<Text, _>(&currency)
                    .bind::<BigInt, _>(amount_minor)
                    .bind::<Nullable<Text>, _>(Some(source.id.clone()))
                    .bind::<Nullable<Text>, _>(Some(destination.id.clone()))
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<Text, _>(&idempotency_key)
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<Text, _>("{}")
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let entry_sql = format!(
                    "INSERT INTO wallet_entries (id, transaction_id, wallet_id, available_delta_minor, reserved_delta_minor, created_at) VALUES ({}, {}, {}, {}, {}, {}), ({}, {}, {}, {}, {}, {})",
                    ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6),
                    ph(kind, 7), ph(kind, 8), ph(kind, 9), ph(kind, 10), ph(kind, 11), ph(kind, 12)
                );
                sql_query(entry_sql)
                    .bind::<Text, _>(uuid::Uuid::new_v4().to_string())
                    .bind::<Text, _>(&transaction_id)
                    .bind::<Text, _>(&source.id)
                    .bind::<BigInt, _>(-amount_minor)
                    .bind::<BigInt, _>(0_i64)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(uuid::Uuid::new_v4().to_string())
                    .bind::<Text, _>(&transaction_id)
                    .bind::<Text, _>(&destination.id)
                    .bind::<BigInt, _>(amount_minor)
                    .bind::<BigInt, _>(0_i64)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let select_sql = format!("{} WHERE id = {}", select_wallet_transaction_sql(), ph(kind, 1));
                sql_query(select_sql)
                    .bind::<Text, _>(transaction_id)
                    .get_result::<WalletTransactionRecord>(conn)
                    .map_err(AppError::from)
            })
        })
    }

    pub async fn refund_committed_charge(
        &self,
        transaction_id: &str,
        user_id: &str,
        amount_minor: i64,
        idempotency_key: &str,
    ) -> AppResult<WalletTransactionRecord> {
        #[derive(diesel::QueryableByName)]
        struct TotalRow {
            #[diesel(sql_type = BigInt)]
            total: i64,
        }

        let transaction_id = transaction_id.to_string();
        let user_id = user_id.to_string();
        let idempotency_key = idempotency_key.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<WalletTransactionRecord, AppError, _>(|conn| {
                let existing_sql = format!(
                    "{} WHERE kind = {} AND idempotency_key = {}",
                    select_wallet_transaction_sql(),
                    ph(kind, 1),
                    ph(kind, 2)
                );
                if let Some(existing) = sql_query(existing_sql)
                    .bind::<Text, _>("charge_refund")
                    .bind::<Text, _>(&idempotency_key)
                    .get_result::<WalletTransactionRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                {
                    if existing.external_order_id.as_deref() != Some(transaction_id.as_str()) {
                        return Err(AppError::BadRequest(
                            "billing idempotency_key is already used for another refund"
                                .to_string(),
                        ));
                    }
                    if existing.amount_minor != amount_minor
                        || existing.user_id.as_deref() != Some(user_id.as_str())
                    {
                        return Err(AppError::BadRequest(
                            "billing idempotency_key is already used for another refund request"
                                .to_string(),
                        ));
                    }
                    return Ok(existing);
                }
                let original_sql = format!(
                    "{} WHERE id = {} AND kind = 'commit' AND status = 'committed' AND user_id = {}{}",
                    select_wallet_transaction_sql(),
                    ph(kind, 1),
                    ph(kind, 2),
                    payment_order_lock_suffix(kind)
                );
                let original = sql_query(original_sql)
                    .bind::<Text, _>(&transaction_id)
                    .bind::<Text, _>(&user_id)
                    .get_result::<WalletTransactionRecord>(conn)
                    .map_err(AppError::from)?;
                if amount_minor <= 0 || amount_minor > original.amount_minor {
                    return Err(AppError::BadRequest("billing refund amount is invalid".to_string()));
                }
                let refunded_sql = format!(
                    "SELECT COALESCE(SUM(amount_minor), 0) AS total FROM wallet_transactions WHERE kind = 'charge_refund' AND status = 'committed' AND external_order_id = {}",
                    ph(kind, 1)
                );
                let refunded = sql_query(refunded_sql)
                    .bind::<Nullable<Text>, _>(Some(transaction_id.clone()))
                    .get_result::<TotalRow>(conn)
                    .map_err(AppError::from)?
                    .total;
                if amount_minor > original.amount_minor.saturating_sub(refunded) {
                    return Err(AppError::BadRequest(
                        "billing refund exceeds the refundable charge amount".to_string(),
                    ));
                }
                let settlement_id = original
                    .destination_wallet_id
                    .clone()
                    .ok_or_else(|| AppError::Internal("billing commit has no settlement wallet".to_string()))?;
                let user_wallet_id = original
                    .source_wallet_id
                    .clone()
                    .ok_or_else(|| AppError::Internal("billing commit has no source wallet".to_string()))?;
                let debit_sql = format!(
                    "UPDATE wallet_accounts SET available_minor = available_minor - {}, version = version + 1, updated_at = {} WHERE id = {} AND available_minor >= {}",
                    ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4)
                );
                if sql_query(debit_sql)
                    .bind::<BigInt, _>(amount_minor)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&settlement_id)
                    .bind::<BigInt, _>(amount_minor)
                    .execute(conn)
                    .map_err(AppError::from)?
                    == 0
                {
                    return Err(AppError::BadRequest("application settlement balance is insufficient".to_string()));
                }
                let credit_sql = format!(
                    "UPDATE wallet_accounts SET available_minor = available_minor + {}, version = version + 1, updated_at = {} WHERE id = {}",
                    ph(kind, 1), ph(kind, 2), ph(kind, 3)
                );
                sql_query(credit_sql)
                    .bind::<BigInt, _>(amount_minor)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&user_wallet_id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let refund_id = uuid::Uuid::new_v4().to_string();
                let insert_sql = format!(
                    "INSERT INTO wallet_transactions (id, kind, status, user_id, application_id, currency, amount_minor, source_wallet_id, destination_wallet_id, hold_id, idempotency_key, external_provider, external_order_id, metadata, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
                    ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6),
                    ph(kind, 7), ph(kind, 8), ph(kind, 9), ph(kind, 10), ph(kind, 11), ph(kind, 12),
                    ph(kind, 13), ph(kind, 14), ph(kind, 15), ph(kind, 16)
                );
                sql_query(insert_sql)
                    .bind::<Text, _>(&refund_id)
                    .bind::<Text, _>("charge_refund")
                    .bind::<Text, _>("committed")
                    .bind::<Nullable<Text>, _>(Some(user_id.clone()))
                    .bind::<Nullable<Text>, _>(original.application_id.clone())
                    .bind::<Text, _>(original.currency.clone())
                    .bind::<BigInt, _>(amount_minor)
                    .bind::<Nullable<Text>, _>(Some(settlement_id.clone()))
                    .bind::<Nullable<Text>, _>(Some(user_wallet_id.clone()))
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<Text, _>(&idempotency_key)
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<Nullable<Text>, _>(Some(transaction_id.clone()))
                    .bind::<Text, _>("{}")
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let entry_sql = format!(
                    "INSERT INTO wallet_entries (id, transaction_id, wallet_id, available_delta_minor, reserved_delta_minor, created_at) VALUES ({}, {}, {}, {}, {}, {}), ({}, {}, {}, {}, {}, {})",
                    ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6),
                    ph(kind, 7), ph(kind, 8), ph(kind, 9), ph(kind, 10), ph(kind, 11), ph(kind, 12)
                );
                sql_query(entry_sql)
                    .bind::<Text, _>(uuid::Uuid::new_v4().to_string())
                    .bind::<Text, _>(&refund_id)
                    .bind::<Text, _>(&settlement_id)
                    .bind::<BigInt, _>(-amount_minor)
                    .bind::<BigInt, _>(0_i64)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(uuid::Uuid::new_v4().to_string())
                    .bind::<Text, _>(&refund_id)
                    .bind::<Text, _>(&user_wallet_id)
                    .bind::<BigInt, _>(amount_minor)
                    .bind::<BigInt, _>(0_i64)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let select_sql = format!("{} WHERE id = {}", select_wallet_transaction_sql(), ph(kind, 1));
                sql_query(select_sql)
                    .bind::<Text, _>(refund_id)
                    .get_result::<WalletTransactionRecord>(conn)
                    .map_err(AppError::from)
            })
        })
    }

    pub async fn adjust_wallet(
        &self,
        wallet_id: &str,
        user_id: Option<&str>,
        application_id: Option<&str>,
        currency: &str,
        amount_delta_minor: i64,
        idempotency_key: &str,
        metadata: serde_json::Value,
    ) -> AppResult<WalletTransactionRecord> {
        let wallet_id = wallet_id.to_string();
        let user_id = user_id.map(ToOwned::to_owned);
        let application_id = application_id.map(ToOwned::to_owned);
        let currency = currency.to_string();
        let idempotency_key = idempotency_key.to_string();
        let metadata = util::to_json(&metadata)?;
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<WalletTransactionRecord, AppError, _>(|conn| {
                let existing_sql = format!(
                    "{} WHERE kind = {} AND idempotency_key = {}",
                    select_wallet_transaction_sql(),
                    ph(kind, 1),
                    ph(kind, 2)
                );
                if let Some(existing) = sql_query(existing_sql)
                    .bind::<Text, _>("adjustment")
                    .bind::<Text, _>(&idempotency_key)
                    .get_result::<WalletTransactionRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                {
                    return Ok(existing);
                }
                if amount_delta_minor == 0 {
                    return Err(AppError::BadRequest("billing adjustment cannot be zero".to_string()));
                }
                let update_sql = if amount_delta_minor > 0 {
                    format!(
                        "UPDATE wallet_accounts SET available_minor = available_minor + {}, version = version + 1, updated_at = {} WHERE id = {} AND currency = {}",
                        ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4)
                    )
                } else {
                    format!(
                        "UPDATE wallet_accounts SET available_minor = available_minor - {}, version = version + 1, updated_at = {} WHERE id = {} AND currency = {} AND available_minor >= {}",
                        ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5)
                    )
                };
                let affected = if amount_delta_minor > 0 {
                    sql_query(update_sql)
                        .bind::<BigInt, _>(amount_delta_minor)
                        .bind::<BigInt, _>(now)
                        .bind::<Text, _>(&wallet_id)
                        .bind::<Text, _>(&currency)
                        .execute(conn)
                        .map_err(AppError::from)?
                } else {
                    sql_query(update_sql)
                        .bind::<BigInt, _>(-amount_delta_minor)
                        .bind::<BigInt, _>(now)
                        .bind::<Text, _>(&wallet_id)
                        .bind::<Text, _>(&currency)
                        .bind::<BigInt, _>(-amount_delta_minor)
                        .execute(conn)
                        .map_err(AppError::from)?
                };
                if affected == 0 {
                    return Err(AppError::BadRequest("billing adjustment would make balance negative".to_string()));
                }
                let transaction_id = uuid::Uuid::new_v4().to_string();
                let insert_sql = format!(
                    "INSERT INTO wallet_transactions (id, kind, status, user_id, application_id, currency, amount_minor, source_wallet_id, destination_wallet_id, hold_id, idempotency_key, external_provider, external_order_id, metadata, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
                    ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6),
                    ph(kind, 7), ph(kind, 8), ph(kind, 9), ph(kind, 10), ph(kind, 11), ph(kind, 12),
                    ph(kind, 13), ph(kind, 14), ph(kind, 15), ph(kind, 16)
                );
                sql_query(insert_sql)
                    .bind::<Text, _>(&transaction_id)
                    .bind::<Text, _>("adjustment")
                    .bind::<Text, _>("committed")
                    .bind::<Nullable<Text>, _>(user_id.clone())
                    .bind::<Nullable<Text>, _>(application_id.clone())
                    .bind::<Text, _>(&currency)
                    .bind::<BigInt, _>(amount_delta_minor.abs())
                    .bind::<Nullable<Text>, _>(Some(wallet_id.clone()))
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<Text, _>(&idempotency_key)
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<Text, _>(metadata)
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let entry_sql = format!(
                    "INSERT INTO wallet_entries (id, transaction_id, wallet_id, available_delta_minor, reserved_delta_minor, created_at) VALUES ({}, {}, {}, {}, {}, {})",
                    ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6)
                );
                sql_query(entry_sql)
                    .bind::<Text, _>(uuid::Uuid::new_v4().to_string())
                    .bind::<Text, _>(&transaction_id)
                    .bind::<Text, _>(&wallet_id)
                    .bind::<BigInt, _>(amount_delta_minor)
                    .bind::<BigInt, _>(0_i64)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let select_sql = format!("{} WHERE id = {}", select_wallet_transaction_sql(), ph(kind, 1));
                sql_query(select_sql)
                    .bind::<Text, _>(transaction_id)
                    .get_result::<WalletTransactionRecord>(conn)
                    .map_err(AppError::from)
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DatabaseSettings;

    #[test]
    fn refund_quota_policy_only_releases_canceled_intents() {
        assert!(payment_refund_counts_toward_limit("pending"));
        assert!(payment_refund_counts_toward_limit("succeeded"));
        assert!(!payment_refund_counts_toward_limit("canceled"));
        assert!(!payment_refund_counts_toward_limit("unknown"));
    }

    #[cfg(feature = "sqlite")]
    async fn sqlite_billing_test_db(pool_size: u32) -> (Db, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "gpt-sso-billing-refund-test-{}.sqlite3",
            uuid::Uuid::new_v4()
        ));
        let db = Db::connect(&crate::config::Settings {
            database: DatabaseSettings {
                kind: crate::config::DatabaseKind::Sqlite,
                url: path.to_string_lossy().into_owned(),
                pool_size,
                run_migrations: true,
            },
            ..toml::from_str(include_str!("../../../config/default.toml")).unwrap()
        })
        .unwrap();
        db.migrate().await.unwrap();
        (db, path)
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn refund_intent_is_replayable_and_pending_consumes_order_quota() {
        let (db, path) = sqlite_billing_test_db(1).await;
        let user_id = "refund-intent-user".to_string();
        let order = db
            .insert_payment_order(NewPaymentOrder {
                user_id: user_id.clone(),
                provider_slug: "test-provider".to_string(),
                merchant_order_no: "refund-intent-order".to_string(),
                idempotency_key: Some("recharge-intent".to_string()),
                currency: "CNY".to_string(),
                amount_minor: 10_000,
                subject: "refund intent".to_string(),
                checkout_kind: "redirect".to_string(),
                checkout_value: "https://example.test/checkout".to_string(),
                expires_at: util::now_ts() + 900,
            })
            .await
            .unwrap();
        db.mark_payment_order_paid(&order.id, "provider-trade", util::now_ts())
            .await
            .unwrap();

        let pending = db
            .reserve_payment_refund(
                &order.id,
                7_000,
                Some("admin"),
                "pending refund",
                "refund-key-1",
            )
            .await
            .unwrap();
        assert_eq!(pending.status, "pending");
        assert_eq!(
            db.reserve_payment_refund(
                &order.id,
                7_000,
                Some("different-admin"),
                "replay",
                "refund-key-1",
            )
            .await
            .unwrap()
            .id,
            pending.id
        );
        assert!(
            db.reserve_payment_refund(
                &order.id,
                4_000,
                Some("admin"),
                "different amount",
                "refund-key-2",
            )
            .await
            .is_err()
        );
        assert!(matches!(
            db.reserve_payment_refund(
                &order.id,
                6_000,
                Some("admin"),
                "same key, different amount",
                "refund-key-1",
            )
            .await,
            Err(crate::error::AppError::BadRequest(_))
        ));

        let canceled = db
            .cancel_payment_refund(&order.id, &pending.id)
            .await
            .unwrap();
        assert_eq!(canceled.status, "canceled");
        assert_eq!(
            db.cancel_payment_refund(&order.id, &pending.id)
                .await
                .unwrap()
                .id,
            pending.id
        );

        let recovered = db
            .reserve_payment_refund(
                &order.id,
                4_000,
                Some("admin"),
                "new intent after cancellation",
                "refund-key-2",
            )
            .await
            .unwrap();
        let succeeded = db
            .finalize_payment_refund(&order.id, &recovered.id, "provider-refund-2")
            .await
            .unwrap();
        assert_eq!(succeeded.status, "succeeded");
        assert_eq!(
            db.finalize_payment_refund(&order.id, &recovered.id, "provider-refund-2")
                .await
                .unwrap()
                .id,
            recovered.id
        );
        assert_eq!(
            db.ensure_user_wallet_account(&user_id, "CNY")
                .await
                .unwrap()
                .available_minor,
            6_000
        );
        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn concurrent_refund_intents_cannot_overreserve_one_order() {
        let (db, path) = sqlite_billing_test_db(4).await;
        let order = db
            .insert_payment_order(NewPaymentOrder {
                user_id: "concurrent-refund-user".to_string(),
                provider_slug: "test-provider".to_string(),
                merchant_order_no: "concurrent-refund-order".to_string(),
                idempotency_key: Some("recharge-concurrent".to_string()),
                currency: "CNY".to_string(),
                amount_minor: 10_000,
                subject: "concurrent refund".to_string(),
                checkout_kind: "redirect".to_string(),
                checkout_value: "https://example.test/checkout".to_string(),
                expires_at: util::now_ts() + 900,
            })
            .await
            .unwrap();
        db.mark_payment_order_paid(&order.id, "provider-trade", util::now_ts())
            .await
            .unwrap();

        let left = db.clone();
        let right = db.clone();
        let (left, right) = tokio::join!(
            left.reserve_payment_refund(&order.id, 6_000, Some("left"), "left", "concurrent-left",),
            right.reserve_payment_refund(
                &order.id,
                6_000,
                Some("right"),
                "right",
                "concurrent-right",
            )
        );
        assert!(left.is_ok() ^ right.is_ok());
        assert_eq!(
            db.list_payment_refunds(&order.id)
                .await
                .unwrap()
                .into_iter()
                .filter(|refund| payment_refund_counts_toward_limit(&refund.status))
                .map(|refund| refund.amount_minor)
                .sum::<i64>(),
            6_000
        );
        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn concurrent_payment_intents_have_one_creator_and_one_row() {
        let (db, path) = sqlite_billing_test_db(4).await;
        let left_db = db.clone();
        let right_db = db.clone();
        let left = left_db.insert_payment_intent(NewPaymentOrder {
            user_id: "concurrent-intent-user".to_string(),
            provider_slug: "test-provider".to_string(),
            merchant_order_no: "concurrent-intent-order".to_string(),
            idempotency_key: Some("concurrent-intent-key".to_string()),
            currency: "CNY".to_string(),
            amount_minor: 2_500,
            subject: "concurrent intent".to_string(),
            checkout_kind: String::new(),
            checkout_value: String::new(),
            expires_at: util::now_ts() + 900,
        });
        let right = right_db.insert_payment_intent(NewPaymentOrder {
            user_id: "concurrent-intent-user".to_string(),
            provider_slug: "test-provider".to_string(),
            merchant_order_no: "concurrent-intent-order".to_string(),
            idempotency_key: Some("concurrent-intent-key".to_string()),
            currency: "CNY".to_string(),
            amount_minor: 2_500,
            subject: "concurrent intent".to_string(),
            checkout_kind: String::new(),
            checkout_value: String::new(),
            expires_at: util::now_ts() + 900,
        });
        let (left, right) = tokio::join!(left, right);
        let (left_order, left_created) = left.unwrap();
        let (right_order, right_created) = right.unwrap();
        assert_ne!(left_created, right_created);
        assert_eq!(left_order.id, right_order.id);
        assert_eq!(left_order.status, "creating");
        assert_eq!(
            db.list_payment_orders(Some("concurrent-intent-user"), 10)
                .await
                .unwrap()
                .len(),
            1
        );
        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn payment_reconcile_claims_are_atomic_and_stale_fences_are_rejected() {
        let (db, path) = sqlite_billing_test_db(4).await;
        let order = db
            .insert_payment_order(NewPaymentOrder {
                user_id: "reconcile-claim-user".to_string(),
                provider_slug: "test-provider".to_string(),
                merchant_order_no: "reconcile-claim-order".to_string(),
                idempotency_key: Some("reconcile-claim-key".to_string()),
                currency: "CNY".to_string(),
                amount_minor: 100,
                subject: "reconcile claim".to_string(),
                checkout_kind: String::new(),
                checkout_value: String::new(),
                expires_at: util::now_ts() + 900,
            })
            .await
            .unwrap();
        let now = util::now_ts();
        let left_db = db.clone();
        let right_db = db.clone();
        let (left, right) = tokio::join!(
            left_db.claim_payment_orders_for_reconcile("claim-left", now, 120, 1),
            right_db.claim_payment_orders_for_reconcile("claim-right", now, 120, 1),
        );
        let left = left.unwrap();
        let right = right.unwrap();
        assert_eq!(left.len() + right.len(), 1);
        let claimed = left.into_iter().chain(right).next().unwrap();
        assert_eq!(claimed.id, order.id);
        assert_eq!(claimed.attempt_count, 1);
        assert_eq!(claimed.lease_generation, 1);
        let owner = claimed.lease_owner.clone().unwrap();
        let fence = PaymentOrderLease {
            owner,
            generation: claimed.lease_generation,
            lease_expires_at: claimed.lease_expires_at.unwrap(),
        };
        let renewed = db
            .renew_payment_order_reconcile_lease(&order.id, &fence, 120)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(renewed.owner, fence.owner);
        assert_eq!(renewed.generation, fence.generation);
        assert!(renewed.lease_expires_at >= fence.lease_expires_at);
        assert!(
            db.release_payment_order_reconcile_lease(&order.id, &renewed, None)
                .await
                .unwrap()
        );
        let reclaimed = db
            .claim_payment_orders_for_reconcile("claim-reclaimer", now, 120, 1)
            .await
            .unwrap();
        assert_eq!(reclaimed.len(), 1);
        assert_eq!(reclaimed[0].lease_generation, 2);
        assert!(
            db.mark_payment_order_reconcile_fenced(
                &order.id,
                &fence,
                "stale worker result",
                now + 10,
            )
            .await
            .unwrap()
            .is_none()
        );
        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn payment_claims_respect_retry_due_time_and_active_leases() {
        let (db, path) = sqlite_billing_test_db(2).await;
        let (order, _) = db
            .insert_payment_intent(NewPaymentOrder {
                user_id: "claim-eligibility-user".to_string(),
                provider_slug: "test-provider".to_string(),
                merchant_order_no: "claim-eligibility-order".to_string(),
                idempotency_key: Some("claim-eligibility-key".to_string()),
                currency: "CNY".to_string(),
                amount_minor: 100,
                subject: "claim eligibility".to_string(),
                checkout_kind: String::new(),
                checkout_value: String::new(),
                expires_at: util::now_ts() + 900,
            })
            .await
            .unwrap();
        let now = util::now_ts();
        let order_id = order.id.clone();
        with_conn!(db.clone(), |conn, kind| {
            let sql = format!(
                "UPDATE payment_orders SET next_retry_at = {} WHERE id = {}",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<Nullable<BigInt>, _>(Some(now + 3_600))
                .bind::<Text, _>(&order_id)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
        .unwrap();

        assert!(
            db.claim_payment_order_for_reconcile(&order.id, "due-worker", now, 120, false)
                .await
                .unwrap()
                .is_none()
        );
        let forced = db
            .claim_payment_order_for_reconcile(&order.id, "manual-force", now, 120, true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(forced.lease_generation, 1);
        assert!(
            db.claim_payment_order_for_reconcile(&order.id, "other-worker", now, 120, true)
                .await
                .unwrap()
                .is_none()
        );
        let fence = PaymentOrderLease {
            owner: "manual-force".to_string(),
            generation: forced.lease_generation,
            lease_expires_at: forced.lease_expires_at.unwrap(),
        };
        assert!(
            db.release_payment_order_reconcile_lease(&order.id, &fence, Some(now))
                .await
                .unwrap()
        );
        let reclaimed = db
            .claim_payment_order_for_reconcile(&order.id, "recovery-worker", now, 120, false)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reclaimed.lease_generation, 2);
        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn unknown_payment_outcome_is_recoverable_and_finalize_is_idempotent() {
        let (db, path) = sqlite_billing_test_db(4).await;
        let (order, created) = db
            .insert_payment_intent(NewPaymentOrder {
                user_id: "reconcile-payment-user".to_string(),
                provider_slug: "test-provider".to_string(),
                merchant_order_no: "reconcile-payment-order".to_string(),
                idempotency_key: Some("reconcile-payment-key".to_string()),
                currency: "CNY".to_string(),
                amount_minor: 3_300,
                subject: "reconcile payment".to_string(),
                checkout_kind: String::new(),
                checkout_value: String::new(),
                expires_at: util::now_ts() + 900,
            })
            .await
            .unwrap();
        assert!(created);
        assert_eq!(order.status, "creating");
        let reconcile = db
            .mark_payment_order_reconcile(
                &order.id,
                "billing provider outcome unknown: provider request timed out",
            )
            .await
            .unwrap();
        assert_eq!(reconcile.status, "reconcile");
        assert!(
            reconcile
                .last_error
                .as_deref()
                .is_some_and(|error| error.contains("timed out"))
        );
        let pending = db.mark_payment_order_pending(&order.id).await.unwrap();
        assert_eq!(pending.status, "pending");
        let paid = db
            .mark_payment_order_paid(&order.id, "provider-trade-recovered", util::now_ts())
            .await
            .unwrap();
        assert_eq!(paid.status, "paid");
        let replay = db
            .mark_payment_order_paid(&order.id, "provider-trade-recovered", util::now_ts())
            .await
            .unwrap();
        assert_eq!(replay.id, order.id);
        assert_eq!(
            db.ensure_user_wallet_account("reconcile-payment-user", "CNY")
                .await
                .unwrap()
                .available_minor,
            3_300
        );
        assert_eq!(
            db.list_wallet_transactions_for_user("reconcile-payment-user", 20)
                .await
                .unwrap()
                .into_iter()
                .filter(|transaction| transaction.kind == "recharge")
                .count(),
            1
        );
        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn concurrent_payment_finalize_keeps_wallet_and_ledger_consistent() {
        let (db, path) = sqlite_billing_test_db(4).await;
        let order = db
            .insert_payment_order(NewPaymentOrder {
                user_id: "concurrent-finalize-user".to_string(),
                provider_slug: "test-provider".to_string(),
                merchant_order_no: "concurrent-finalize-order".to_string(),
                idempotency_key: Some("concurrent-finalize-key".to_string()),
                currency: "CNY".to_string(),
                amount_minor: 4_400,
                subject: "concurrent finalize".to_string(),
                checkout_kind: "redirect".to_string(),
                checkout_value: "https://example.test/checkout".to_string(),
                expires_at: util::now_ts() + 900,
            })
            .await
            .unwrap();
        let left_db = db.clone();
        let right_db = db.clone();
        let left =
            left_db.mark_payment_order_paid(&order.id, "concurrent-provider-trade", util::now_ts());
        let right = right_db.mark_payment_order_paid(
            &order.id,
            "concurrent-provider-trade",
            util::now_ts(),
        );
        let (left, right) = tokio::join!(left, right);
        assert!(left.is_ok());
        assert!(right.is_ok());
        assert_eq!(
            db.ensure_user_wallet_account("concurrent-finalize-user", "CNY")
                .await
                .unwrap()
                .available_minor,
            4_400
        );
        assert_eq!(
            db.list_wallet_transactions_for_user("concurrent-finalize-user", 20)
                .await
                .unwrap()
                .into_iter()
                .filter(|transaction| transaction.kind == "recharge")
                .count(),
            1
        );
        drop(db);
        let _ = std::fs::remove_file(path);
    }
}
