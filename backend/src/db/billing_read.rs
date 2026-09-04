use super::billing_sql::{
    select_application_billing_settings_sql, select_wallet_account_sql,
    select_wallet_transaction_sql,
};
use super::billing_types::{
    ApplicationBillingSettingsRecord, WalletAccountRecord, WalletTransactionRecord,
};
use super::{Db, blocking, ph};
use crate::{
    config::DatabaseKind,
    error::{AppError, AppResult},
};
use diesel::{
    OptionalExtension, RunQueryDsl, sql_query,
    sql_types::{BigInt, Text},
};

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
}
