use super::billing_policy::payment_order_lock_suffix;
use super::billing_sql::{
    select_wallet_account_sql, select_wallet_hold_sql, select_wallet_transaction_sql,
};
use super::billing_types::{
    WalletAccountRecord, WalletAdjustment, WalletHoldRecord, WalletHoldReservation,
    WalletTransactionRecord, WalletTransfer,
};
use super::{Db, TotalRow, blocking, ph};
use crate::{
    config::DatabaseKind,
    error::{AppError, AppResult},
    util,
};
use diesel::{
    Connection, OptionalExtension, RunQueryDsl, sql_query,
    sql_types::{BigInt, Nullable, Text},
};

impl Db {
    pub async fn reserve_wallet_hold(
        &self,
        reservation: WalletHoldReservation<'_>,
    ) -> AppResult<WalletHoldRecord> {
        let wallet_id = reservation.wallet_id.to_string();
        let user_id = reservation.user_id.to_string();
        let application_id = reservation.application_id.to_string();
        let currency = reservation.currency.to_string();
        let amount_minor = reservation.amount_minor;
        let reference = reservation.reference.to_string();
        let idempotency_key = reservation.idempotency_key.to_string();
        let expires_at = reservation.expires_at;
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
        transfer: WalletTransfer<'_>,
    ) -> AppResult<WalletTransactionRecord> {
        let user_id = transfer.user_id.to_string();
        let source_wallet_id = transfer.source_wallet_id.to_string();
        let destination_wallet_id = transfer.destination_wallet_id.to_string();
        let currency = transfer.currency.to_string();
        let amount_minor = transfer.amount_minor;
        let application_id = transfer.application_id.map(ToOwned::to_owned);
        let idempotency_key = transfer.idempotency_key.to_string();
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
        adjustment: WalletAdjustment<'_>,
    ) -> AppResult<WalletTransactionRecord> {
        let wallet_id = adjustment.wallet_id.to_string();
        let user_id = adjustment.user_id.map(ToOwned::to_owned);
        let application_id = adjustment.application_id.map(ToOwned::to_owned);
        let currency = adjustment.currency.to_string();
        let amount_delta_minor = adjustment.amount_delta_minor;
        let idempotency_key = adjustment.idempotency_key.to_string();
        let metadata = util::to_json(&adjustment.metadata)?;
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
