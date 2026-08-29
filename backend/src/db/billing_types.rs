use diesel::sql_types::{BigInt, Integer, Nullable, Text};
use serde::Serialize;

pub struct WalletHoldReservation<'a> {
    pub wallet_id: &'a str,
    pub user_id: &'a str,
    pub application_id: &'a str,
    pub currency: &'a str,
    pub amount_minor: i64,
    pub reference: &'a str,
    pub idempotency_key: &'a str,
    pub expires_at: i64,
}

pub struct WalletTransfer<'a> {
    pub user_id: &'a str,
    pub source_wallet_id: &'a str,
    pub destination_wallet_id: &'a str,
    pub currency: &'a str,
    pub amount_minor: i64,
    pub application_id: Option<&'a str>,
    pub idempotency_key: &'a str,
}

pub struct WalletAdjustment<'a> {
    pub wallet_id: &'a str,
    pub user_id: Option<&'a str>,
    pub application_id: Option<&'a str>,
    pub currency: &'a str,
    pub amount_delta_minor: i64,
    pub idempotency_key: &'a str,
    pub metadata: serde_json::Value,
}
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
