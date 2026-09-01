//! Signet wallet, payment-provider, and application settlement domain.
//!
//! The module deliberately keeps provider protocol details separate from the
//! wallet ledger. Provider adapters create/check/refund payment orders; only
//! the billing service mutates wallet state.

use crate::{
    AppState,
    access::Authorizer,
    applications, auth,
    config::{PaymentProviderSettings, Settings},
    db::{
        ApplicationBillingSettingsRecord, NewPaymentOrder, PaymentOrderLease, PaymentOrderRecord,
        UserRecord, WalletAccountRecord, WalletAdjustment, WalletTransactionRecord,
    },
    error::{AppError, AppResult},
    util,
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeSet, future::Future, pin::Pin, time::Duration};

pub const CURRENCY_CNY: &str = "CNY";

pub const BILLING_SCOPE_READ: &str = "billing.read";
pub const BILLING_SCOPE_RESERVE: &str = "billing.reserve";
pub const BILLING_SCOPE_COMMIT: &str = "billing.commit";
pub const BILLING_SCOPE_RELEASE: &str = "billing.release";
pub const BILLING_SCOPE_REFUND: &str = "billing.refund";

#[path = "billing_wallet.rs"]
mod billing_wallet;
#[path = "billing_provider_adapter.rs"]
mod provider_adapter;
#[path = "billing_reconciliation_service.rs"]
mod reconciliation_service;
#[cfg(test)]
use provider_adapter::{
    alipay_sign_content, notification_from_fields, rsa_sha256_sign, rsa_sha256_verify, sign_epay,
};
pub use reconciliation_service::{BillingReconcileWorker, spawn_reconcile_worker};

pub const ACCOUNT_KIND_GLOBAL: &str = "user_global";
pub const ACCOUNT_KIND_APPLICATION: &str = "user_application";
pub const ACCOUNT_KIND_SETTLEMENT: &str = "application_settlement";

pub const WALLET_MODE_SHARED: &str = "shared";
pub const WALLET_MODE_ISOLATED: &str = "isolated";

/// A payment intent is durable before any provider side effect starts.
pub const PAYMENT_STATUS_CREATING: &str = "creating";
pub const PAYMENT_STATUS_PENDING: &str = "pending";
pub const PAYMENT_STATUS_PAID: &str = "paid";
/// The provider outcome is known to be a failure; the intent is terminal.
pub const PAYMENT_STATUS_FAILED: &str = "failed";
/// The provider outcome is unknown and must remain query/reconcile-able.
pub const PAYMENT_STATUS_RECONCILE: &str = "reconcile";
/// Kept for compatibility with callers that close an expired checkout.
pub const PAYMENT_STATUS_CLOSED: &str = "closed";

/// Returns the bounded exponential delay for a claimed reconciliation
/// attempt. The first attempt waits `base_seconds`; later attempts double the
/// delay until `max_seconds`. Saturating arithmetic keeps malformed legacy
/// counters from wrapping a retry into the past.
pub fn reconcile_retry_delay_seconds(
    attempt_count: i64,
    base_seconds: i64,
    max_seconds: i64,
) -> i64 {
    if base_seconds <= 0 || max_seconds <= 0 {
        return 0;
    }
    let exponent = attempt_count.saturating_sub(1).clamp(0, 62) as u32;
    let multiplier = 1_i64.checked_shl(exponent).unwrap_or(i64::MAX);
    base_seconds.saturating_mul(multiplier).min(max_seconds)
}

pub fn reconcile_next_retry_at(
    now: i64,
    attempt_count: i64,
    base_seconds: i64,
    max_seconds: i64,
) -> i64 {
    now.saturating_add(reconcile_retry_delay_seconds(
        attempt_count,
        base_seconds,
        max_seconds,
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpiredPaymentOrderPolicy {
    /// The provider must be queried because local expiry cannot prove that
    /// money was not accepted.
    QueryProvider,
    /// Query the provider but never issue a second create call after a crash
    /// left the local creating intent without checkout material.
    QueryProviderWithoutCreate,
}

fn expired_payment_order_policy(
    status: &str,
    checkout_value: &str,
    expires_at: i64,
    now: i64,
) -> Option<ExpiredPaymentOrderPolicy> {
    if expires_at > now {
        return None;
    }
    if status == PAYMENT_STATUS_CREATING && checkout_value.trim().is_empty() {
        Some(ExpiredPaymentOrderPolicy::QueryProviderWithoutCreate)
    } else {
        Some(ExpiredPaymentOrderPolicy::QueryProvider)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Money {
    pub amount_minor: i64,
    pub currency: String,
    pub minor_unit: u8,
}

#[derive(Debug, Clone, Serialize)]
pub struct WalletView {
    pub id: String,
    pub account_kind: String,
    pub application_id: Option<String>,
    pub currency: String,
    pub minor_unit: u8,
    pub available_minor: i64,
    pub reserved_minor: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct PaymentCheckout {
    pub order_id: String,
    pub provider_slug: String,
    pub status: String,
    pub amount: Money,
    pub checkout_kind: String,
    pub checkout_value: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct PaymentProviderView {
    pub slug: String,
    pub kind: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RechargeInput {
    pub amount_minor: i64,
    pub currency: String,
    pub provider_slug: String,
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TransferInput {
    pub application_id: String,
    pub currency: String,
    pub amount_minor: i64,
    pub direction: String,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReservationInput {
    pub amount_minor: i64,
    pub currency: String,
    pub reference: String,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OperationInput {
    pub idempotency_key: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RefundInput {
    pub amount_minor: i64,
    pub idempotency_key: String,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ManualAdjustmentInput {
    pub wallet_id: String,
    pub amount_delta_minor: i64,
    pub currency: String,
    pub reason: String,
    pub idempotency_key: String,
}

#[derive(Debug, Clone)]
pub struct CheckoutRequest {
    pub merchant_order_no: String,
    pub amount_minor: i64,
    pub currency: String,
    pub subject: String,
    pub notify_url: String,
    pub return_url: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone)]
pub struct NotificationRequest<'a> {
    pub headers: &'a HeaderMap,
    pub body: &'a [u8],
}

#[derive(Debug, Clone)]
pub struct PaymentNotification {
    pub merchant_order_no: String,
    pub provider_trade_id: String,
    pub amount_minor: i64,
    pub currency: String,
    pub paid_at: i64,
    pub status: String,
}

#[derive(Debug, Clone)]
pub struct ProviderRefundResult {
    pub provider_refund_id: String,
}

#[derive(Debug, Clone)]
pub struct PaymentQueryResult {
    pub notification: PaymentNotification,
}

pub type ProviderFuture<'a, T> = Pin<Box<dyn Future<Output = AppResult<T>> + Send + 'a>>;

/// Runtime-configured payment adapters use an object-safe boxed-future trait.
/// Provider code never writes wallets; it only normalizes external protocol
/// results for the billing state machine.
pub trait PaymentProvider: Send + Sync {
    fn slug(&self) -> &str;
    fn create_checkout<'a>(
        &'a self,
        request: &'a CheckoutRequest,
    ) -> ProviderFuture<'a, (String, String)>;
    fn verify_notification<'a>(
        &'a self,
        request: NotificationRequest<'a>,
    ) -> ProviderFuture<'a, PaymentNotification>;
    fn query_payment<'a>(
        &'a self,
        order: &'a PaymentOrderRecord,
    ) -> ProviderFuture<'a, PaymentQueryResult>;
    fn refund_payment<'a>(
        &'a self,
        order: &'a PaymentOrderRecord,
        amount_minor: i64,
        idempotency_key: &'a str,
    ) -> ProviderFuture<'a, ProviderRefundResult>;
}

pub fn normalize_currency(value: &str) -> AppResult<String> {
    let value = value.trim().to_ascii_uppercase();
    if value.len() != 3 || !value.bytes().all(|byte| byte.is_ascii_uppercase()) {
        return Err(crate::error::AppError::BadRequest(
            "currency must be a three-letter uppercase code".to_string(),
        ));
    }
    Ok(value)
}

pub fn minor_unit(settings: &Settings, currency: &str) -> AppResult<u8> {
    let currency = normalize_currency(currency)?;
    settings
        .billing
        .supported_currencies
        .iter()
        .find(|item| item.code.trim().eq_ignore_ascii_case(&currency))
        .map(|item| item.minor_unit)
        .ok_or_else(|| AppError::BadRequest("currency is not enabled for billing".to_string()))
}

pub fn validate_amount(settings: &Settings, currency: &str, amount_minor: i64) -> AppResult<()> {
    let _ = minor_unit(settings, currency)?;
    if amount_minor <= 0 {
        return Err(AppError::BadRequest(
            "billing amount must be positive".to_string(),
        ));
    }
    Ok(())
}

pub fn parse_decimal_to_minor(value: &str, unit: u8) -> AppResult<i64> {
    let value = value.trim();
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if whole.is_empty()
        || whole.starts_with('-')
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || fraction.len() > usize::from(unit)
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(AppError::BadRequest(
            "provider amount is invalid".to_string(),
        ));
    }
    let mut fraction = fraction.to_string();
    while fraction.len() < usize::from(unit) {
        fraction.push('0');
    }
    let digits = format!("{whole}{fraction}");
    digits
        .parse::<i64>()
        .map_err(|_| AppError::BadRequest("provider amount is out of range".to_string()))
}

pub fn format_minor(amount_minor: i64, unit: u8) -> String {
    if unit == 0 {
        return amount_minor.to_string();
    }
    let scale = 10_i64.pow(u32::from(unit));
    let whole = amount_minor / scale;
    let fraction = (amount_minor % scale).abs();
    format!("{whole}.{fraction:0width$}", width = usize::from(unit))
}

fn provider_outcome_unknown() -> AppError {
    provider_outcome_unknown_with_reason("provider outcome is unknown")
}

fn provider_outcome_unknown_with_reason(reason: &str) -> AppError {
    AppError::Internal(format!("billing provider outcome unknown: {reason}"))
}

fn is_provider_outcome_unknown(error: &AppError) -> bool {
    matches!(
        error,
        AppError::Internal(message) if message.starts_with("billing provider outcome unknown")
    )
}

fn provider_error_message(error: &AppError) -> String {
    error.to_string().chars().take(512).collect()
}

#[derive(Debug, Deserialize, Default)]
struct CurrencyQuery {
    currency: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LimitQuery {
    limit: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct ApplicationBillingSettingsResponse {
    pub application_id: String,
    pub accept_signet_balance: bool,
    pub wallet_mode: String,
    pub supported_currencies: Vec<String>,
    pub mode_locked_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct ApplicationBillingSettingsInput {
    #[serde(default)]
    pub accept_signet_balance: bool,
    #[serde(default = "default_wallet_mode")]
    pub wallet_mode: String,
    #[serde(default)]
    pub supported_currencies: Vec<String>,
}

fn default_wallet_mode() -> String {
    WALLET_MODE_SHARED.to_string()
}

pub fn application_billing_settings_response(
    record: ApplicationBillingSettingsRecord,
) -> AppResult<ApplicationBillingSettingsResponse> {
    Ok(ApplicationBillingSettingsResponse {
        application_id: record.application_id,
        accept_signet_balance: record.accept_signet_balance == 1,
        wallet_mode: record.wallet_mode,
        supported_currencies: util::from_json(&record.supported_currencies)?,
        mode_locked_at: record.mode_locked_at,
        created_at: record.created_at,
        updated_at: record.updated_at,
    })
}

pub fn normalize_application_billing_input(
    settings: &Settings,
    input: ApplicationBillingSettingsInput,
) -> AppResult<(bool, String, Vec<String>)> {
    let wallet_mode = input.wallet_mode.trim();
    if !matches!(wallet_mode, WALLET_MODE_SHARED | WALLET_MODE_ISOLATED) {
        return Err(AppError::BadRequest(
            "application wallet_mode must be shared or isolated".to_string(),
        ));
    }
    let mut currencies = BTreeSet::new();
    for currency in input.supported_currencies {
        let currency = normalize_currency(&currency)?;
        let _ = minor_unit(settings, &currency)?;
        currencies.insert(currency);
    }
    Ok((
        input.accept_signet_balance,
        wallet_mode.to_string(),
        currencies.into_iter().collect(),
    ))
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/me/billing/wallets", get(list_wallets))
        .route("/api/me/billing/providers", get(list_provider_catalog))
        .route("/api/me/billing/transactions", get(list_transactions))
        .route(
            "/api/me/billing/recharges",
            get(list_recharges).post(create_recharge),
        )
        .route("/api/me/billing/recharges/{id}", get(get_recharge))
        .route("/api/me/billing/recharges/{id}/query", post(query_recharge))
        .route(
            "/api/me/billing/transfers",
            post(billing_wallet::transfer_wallet),
        )
        .route(
            "/api/billing/providers/{provider}/notify",
            post(provider_notify),
        )
        .route("/api/billing/v1/me", get(application_me))
        .route(
            "/api/billing/v1/reservations",
            post(billing_wallet::create_reservation),
        )
        .route(
            "/api/billing/v1/reservations/{id}/commit",
            post(billing_wallet::commit_reservation),
        )
        .route(
            "/api/billing/v1/reservations/{id}/release",
            post(billing_wallet::release_reservation),
        )
        .route("/api/billing/v1/charges/{id}/refund", post(refund_charge))
        .route("/api/admin/billing/orders", get(list_admin_orders))
        .route("/api/admin/billing/orders/{id}", get(get_admin_order))
        .route(
            "/api/admin/billing/orders/{id}/query",
            post(query_admin_order),
        )
        .route(
            "/api/admin/billing/orders/{id}/refund",
            post(refund_admin_order),
        )
        .route("/api/admin/billing/adjustments", post(adjust_wallet_admin))
}

fn billing_enabled(settings: &Settings) -> AppResult<()> {
    if settings.billing.enabled {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

fn normalize_operation_key(value: &str) -> AppResult<String> {
    let value = value.trim();
    if value.is_empty() || value.len() > 255 || value.chars().any(char::is_control) {
        return Err(AppError::BadRequest(
            "billing idempotency_key is invalid".to_string(),
        ));
    }
    Ok(value.to_string())
}

fn recharge_matches_request(
    order: &PaymentOrderRecord,
    user_id: &str,
    provider_slug: &str,
    currency: &str,
    amount_minor: i64,
) -> AppResult<()> {
    if order.user_id != user_id
        || order.provider_slug != provider_slug
        || order.currency != currency
        || order.amount_minor != amount_minor
    {
        return Err(AppError::BadRequest(
            "billing idempotency_key is already used for another recharge".to_string(),
        ));
    }
    Ok(())
}

fn normalize_reference(value: &str) -> AppResult<String> {
    let value = value.trim();
    if value.is_empty() || value.len() > 255 || value.chars().any(char::is_control) {
        return Err(AppError::BadRequest(
            "billing reference is invalid".to_string(),
        ));
    }
    Ok(value.to_string())
}

fn wallet_view(settings: &Settings, wallet: WalletAccountRecord) -> AppResult<WalletView> {
    let minor_unit = minor_unit(settings, &wallet.currency)?;
    Ok(WalletView {
        id: wallet.id,
        account_kind: wallet.account_kind,
        application_id: wallet.application_id,
        currency: wallet.currency,
        minor_unit,
        available_minor: wallet.available_minor,
        reserved_minor: wallet.reserved_minor,
    })
}

#[derive(Debug, Serialize)]
struct PaymentOrderView {
    id: String,
    user_id: String,
    provider_slug: String,
    merchant_order_no: String,
    provider_trade_id: Option<String>,
    amount: Money,
    subject: String,
    status: String,
    checkout_kind: String,
    checkout_value: String,
    expires_at: i64,
    paid_at: Option<i64>,
    last_error: Option<String>,
    created_at: i64,
    updated_at: i64,
}

fn payment_order_view(
    settings: &Settings,
    order: PaymentOrderRecord,
) -> AppResult<PaymentOrderView> {
    let minor_unit = minor_unit(settings, &order.currency)?;
    Ok(PaymentOrderView {
        id: order.id,
        user_id: order.user_id,
        provider_slug: order.provider_slug,
        merchant_order_no: order.merchant_order_no,
        provider_trade_id: order.provider_trade_id,
        amount: Money {
            amount_minor: order.amount_minor,
            currency: order.currency,
            minor_unit,
        },
        subject: order.subject,
        status: order.status,
        checkout_kind: order.checkout_kind,
        checkout_value: order.checkout_value,
        expires_at: order.expires_at,
        paid_at: order.paid_at,
        last_error: order.last_error,
        created_at: order.created_at,
        updated_at: order.updated_at,
    })
}

fn payment_checkout(settings: &Settings, order: PaymentOrderRecord) -> AppResult<PaymentCheckout> {
    let minor_unit = minor_unit(settings, &order.currency)?;
    Ok(PaymentCheckout {
        order_id: order.id,
        provider_slug: order.provider_slug,
        status: order.status,
        amount: Money {
            amount_minor: order.amount_minor,
            currency: order.currency,
            minor_unit,
        },
        checkout_kind: order.checkout_kind,
        checkout_value: order.checkout_value,
        expires_at: order.expires_at,
    })
}

async fn standard_current_user(state: &AppState, jar: &CookieJar) -> AppResult<auth::CurrentUser> {
    let current = auth::require_current_user(state, jar).await?;
    auth::ensure_current_account_mutable(&current)?;
    Ok(current)
}

fn application_currency_allowed(
    settings: &ApplicationBillingSettingsRecord,
    currency: &str,
) -> AppResult<bool> {
    let currencies: Vec<String> = util::from_json(&settings.supported_currencies)?;
    Ok(currencies.is_empty()
        || currencies
            .iter()
            .any(|value| value.eq_ignore_ascii_case(currency)))
}

async fn list_wallets(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<CurrencyQuery>,
) -> AppResult<Json<Vec<WalletView>>> {
    billing_enabled(&state.settings)?;
    let current = standard_current_user(&state, &jar).await?;
    let currency = query
        .currency
        .as_deref()
        .map(normalize_currency)
        .transpose()?;
    if let Some(currency) = currency.as_deref() {
        let _ = minor_unit(&state.settings, currency)?;
        state
            .db
            .ensure_user_wallet_account(&current.user.id, currency)
            .await?;
    } else {
        for supported in &state.settings.billing.supported_currencies {
            let currency = normalize_currency(&supported.code)?;
            state
                .db
                .ensure_user_wallet_account(&current.user.id, &currency)
                .await?;
        }
    }
    Ok(Json(
        state
            .db
            .list_user_wallet_accounts(&current.user.id, currency.as_deref())
            .await?
            .into_iter()
            .map(|wallet| wallet_view(&state.settings, wallet))
            .collect::<AppResult<Vec<_>>>()?,
    ))
}

async fn list_provider_catalog(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<Vec<PaymentProviderView>>> {
    billing_enabled(&state.settings)?;
    let _current = standard_current_user(&state, &jar).await?;
    Ok(Json(
        state
            .settings
            .billing
            .providers
            .iter()
            .filter(|provider| provider.enabled)
            .map(|provider| PaymentProviderView {
                slug: provider.slug.clone(),
                kind: provider.kind.clone(),
            })
            .collect(),
    ))
}

async fn list_transactions(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<LimitQuery>,
) -> AppResult<Json<Vec<WalletTransactionRecord>>> {
    billing_enabled(&state.settings)?;
    let current = standard_current_user(&state, &jar).await?;
    Ok(Json(
        state
            .db
            .list_wallet_transactions_for_user(&current.user.id, query.limit.unwrap_or(100))
            .await?,
    ))
}

async fn list_recharges(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<LimitQuery>,
) -> AppResult<Json<Vec<PaymentOrderView>>> {
    billing_enabled(&state.settings)?;
    let current = standard_current_user(&state, &jar).await?;
    Ok(Json(
        state
            .db
            .list_payment_orders(Some(&current.user.id), query.limit.unwrap_or(100))
            .await?
            .into_iter()
            .map(|order| payment_order_view(&state.settings, order))
            .collect::<AppResult<Vec<_>>>()?,
    ))
}

async fn get_recharge(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<PaymentOrderView>> {
    billing_enabled(&state.settings)?;
    let current = standard_current_user(&state, &jar).await?;
    let order = state
        .db
        .find_payment_order(&id)
        .await?
        .filter(|order| order.user_id == current.user.id)
        .ok_or(AppError::NotFound)?;
    Ok(Json(payment_order_view(&state.settings, order)?))
}

fn checkout_request_for_order(
    base_url: &str,
    provider_config: &PaymentProviderSettings,
    order: &PaymentOrderRecord,
) -> CheckoutRequest {
    let notify_url = provider_config
        .notify_url
        .clone()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| {
            format!(
                "{}/api/billing/providers/{}/notify",
                base_url.trim_end_matches('/'),
                order.provider_slug
            )
        });
    CheckoutRequest {
        merchant_order_no: order.merchant_order_no.clone(),
        amount_minor: order.amount_minor,
        currency: order.currency.clone(),
        subject: order.subject.clone(),
        notify_url,
        return_url: format!(
            "{}/#/billing?billing_order={}",
            base_url.trim_end_matches('/'),
            order.merchant_order_no
        ),
        expires_at: order.expires_at,
    }
}

async fn persist_provider_create_failure(
    state: &AppState,
    order_id: &str,
    error: &AppError,
) -> AppResult<()> {
    let message = provider_error_message(error);
    if is_provider_outcome_unknown(error) {
        state
            .db
            .mark_payment_order_reconcile(order_id, &message)
            .await?;
    } else {
        state
            .db
            .mark_payment_order_failed(order_id, &message)
            .await?;
    }
    Ok(())
}

async fn create_provider_checkout_for_order(
    state: &AppState,
    base_url: &str,
    order: &PaymentOrderRecord,
) -> AppResult<PaymentOrderRecord> {
    if order.status != PAYMENT_STATUS_CREATING || !order.checkout_value.trim().is_empty() {
        return Err(AppError::BadRequest(
            "payment provider create is allowed only for a new creating intent".to_string(),
        ));
    }
    if order.expires_at <= util::now_ts() {
        return Err(AppError::BadRequest(
            "payment intent expired before provider checkout creation".to_string(),
        ));
    }
    let provider_config =
        match provider_adapter::provider_settings(&state.settings, &order.provider_slug) {
            Ok(config) => config.clone(),
            Err(error) => {
                state
                    .db
                    .mark_payment_order_failed(&order.id, &provider_error_message(&error))
                    .await?;
                return Err(error);
            }
        };
    let provider =
        match provider_adapter::configured_provider(&state.settings, &order.provider_slug) {
            Ok(provider) => provider,
            Err(error) => {
                state
                    .db
                    .mark_payment_order_failed(&order.id, &provider_error_message(&error))
                    .await?;
                return Err(error);
            }
        };
    let request = checkout_request_for_order(base_url, &provider_config, order);
    let checkout_result =
        match tokio::time::timeout(Duration::from_secs(15), provider.create_checkout(&request))
            .await
        {
            Ok(result) => result,
            Err(_) => Err(provider_outcome_unknown_with_reason(
                "provider checkout creation timed out",
            )),
        };
    let checkout = match checkout_result {
        Ok(checkout) => checkout,
        Err(error) => {
            persist_provider_create_failure(state, &order.id, &error).await?;
            return Err(error);
        }
    };
    match state
        .db
        .set_payment_order_checkout(&order.id, &checkout.0, &checkout.1)
        .await
    {
        Ok(order) => Ok(order),
        Err(error) => {
            // Provider checkout creation succeeded, but local persistence did
            // not.  Keep a reconcile state whenever possible so a callback or
            // query can still finalize the payment; never invent a checkout or
            // provider id in the error path.
            let _ = state
                .db
                .mark_payment_order_reconcile(&order.id, &provider_error_message(&error))
                .await;
            Err(error)
        }
    }
}

#[derive(Debug, Deserialize, Default)]
struct ReconcileQuery {
    /// `force=true` is the explicit synchronous retry override. It can ignore
    /// `next_retry_at`, but the durable claim still refuses an active lease.
    #[serde(default)]
    force: bool,
}

async fn query_recharge(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Query(query): Query<ReconcileQuery>,
) -> AppResult<Json<PaymentOrderView>> {
    billing_enabled(&state.settings)?;
    let current = standard_current_user(&state, &jar).await?;
    let order = state
        .db
        .find_payment_order(&id)
        .await?
        .filter(|order| order.user_id == current.user.id)
        .ok_or(AppError::NotFound)?;
    let order = reconciliation_service::BillingCommandService::new(&state)
        .reconcile_order(&order.id, query.force)
        .await?;
    Ok(Json(payment_order_view(&state.settings, order)?))
}

async fn create_recharge(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(input): Json<RechargeInput>,
) -> AppResult<Json<PaymentCheckout>> {
    billing_enabled(&state.settings)?;
    let current = standard_current_user(&state, &jar).await?;
    let currency = normalize_currency(&input.currency)?;
    validate_amount(&state.settings, &currency, input.amount_minor)?;
    let provider_slug = input.provider_slug.trim().to_string();
    let header_idempotency_key = headers
        .get("idempotency-key")
        .map(|value| {
            value
                .to_str()
                .map_err(|_| AppError::BadRequest("billing idempotency_key is invalid".to_string()))
        })
        .transpose()?;
    let idempotency_key = input
        .idempotency_key
        .as_deref()
        .or(header_idempotency_key)
        .map(normalize_operation_key)
        .transpose()?;
    let base_url = state.effective_public_base_url(&headers).await?;
    let merchant_order_no = idempotency_key
        .as_deref()
        .map(|key| {
            let fingerprint = format!("{}:{}:{}", current.user.id, provider_slug, key);
            format!("SGT-IDEM-{}", util::sha256_base64url(&fingerprint))
        })
        .unwrap_or_else(|| format!("SGT-{}-{}", util::now_ts(), util::random_token(12)));
    let (order, created) = state
        .db
        .insert_payment_intent(NewPaymentOrder {
            user_id: current.user.id.clone(),
            provider_slug: provider_slug.clone(),
            merchant_order_no,
            idempotency_key: idempotency_key.clone(),
            currency: currency.clone(),
            amount_minor: input.amount_minor,
            subject: "Signet 余额充值".to_string(),
            // The provider checkout is intentionally empty until the
            // provider call has returned successfully.  This is the durable
            // creating intent that makes crash recovery possible.
            checkout_kind: String::new(),
            checkout_value: String::new(),
            expires_at: util::now_ts() + 900,
        })
        .await?;
    recharge_matches_request(
        &order,
        &current.user.id,
        &provider_slug,
        &currency,
        input.amount_minor,
    )?;
    let order = if created {
        create_provider_checkout_for_order(&state, &base_url, &order).await?
    } else if matches!(
        order.status.as_str(),
        PAYMENT_STATUS_CREATING | PAYMENT_STATUS_RECONCILE
    ) || (order.status == PAYMENT_STATUS_PENDING
        && (order.checkout_value.trim().is_empty() || order.expires_at <= util::now_ts()))
    {
        reconciliation_service::recover_recharge_intent(&state, order).await?
    } else {
        order
    };
    Ok(Json(payment_checkout(&state.settings, order)?))
}

fn provider_callback_response(kind: &str) -> Response {
    if kind == "wechat_native" {
        Json(json!({ "code": "SUCCESS", "message": "成功" })).into_response()
    } else {
        (StatusCode::OK, "success").into_response()
    }
}

async fn provider_notify(
    State(state): State<AppState>,
    Path(provider_slug): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    billing_enabled(&state.settings)?;
    let provider_config =
        provider_adapter::provider_settings(&state.settings, &provider_slug)?.clone();
    let provider = provider_adapter::configured_provider(&state.settings, &provider_slug)?;
    let notification = provider
        .verify_notification(NotificationRequest {
            headers: &headers,
            body: &body,
        })
        .await?;
    let order = state
        .db
        .find_payment_order_by_merchant_order_no(&provider_slug, &notification.merchant_order_no)
        .await?
        .ok_or(AppError::NotFound)?;
    let notification_currency = normalize_currency(&notification.currency)?;
    if notification_currency != order.currency || notification.amount_minor != order.amount_minor {
        state
            .db
            .mark_payment_order_reconcile(
                &order.id,
                "provider notification amount or currency mismatch",
            )
            .await?;
        return Err(AppError::BadRequest(
            "provider notification amount or currency mismatch".to_string(),
        ));
    }
    if notification.status == PAYMENT_STATUS_PAID {
        if notification.provider_trade_id.trim().is_empty() {
            state
                .db
                .mark_payment_order_reconcile(
                    &order.id,
                    "provider notification has no provider transaction id",
                )
                .await?;
            return Err(AppError::BadRequest(
                "provider notification has no trade id".to_string(),
            ));
        }
        state
            .db
            .mark_payment_order_paid(
                &order.id,
                &notification.provider_trade_id,
                notification.paid_at,
            )
            .await?;
    } else if matches!(
        notification.status.as_str(),
        PAYMENT_STATUS_FAILED | PAYMENT_STATUS_CLOSED
    ) {
        state
            .db
            .mark_payment_order_failed(
                &order.id,
                "payment provider reported a terminal unsuccessful state",
            )
            .await?;
    }
    Ok(provider_callback_response(&provider_config.kind))
}

struct BillingApplicationContext {
    user: UserRecord,
    client: crate::db::ClientRecord,
    application: crate::db::ApplicationRecord,
    settings: ApplicationBillingSettingsRecord,
}

fn bearer_token(headers: &HeaderMap) -> AppResult<&str> {
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or(AppError::Unauthorized)?;
    let (scheme, token) = value.split_once(' ').ok_or(AppError::Unauthorized)?;
    if !scheme.eq_ignore_ascii_case("Bearer") || token.trim().is_empty() {
        return Err(AppError::Unauthorized);
    }
    Ok(token.trim())
}

fn scope_contains(scope: &str, required: &str) -> bool {
    scope.split_whitespace().any(|item| item == required)
}

async fn billing_application_context(
    state: &AppState,
    headers: &HeaderMap,
    required_scope: &str,
) -> AppResult<BillingApplicationContext> {
    billing_enabled(&state.settings)?;
    let token = bearer_token(headers)?;
    let issuers = state.accepted_issuers(headers).await?;
    let issuer_refs = issuers.iter().map(String::as_str).collect::<Vec<_>>();
    let claims = state
        .jwt
        .verify_access_token_with_issuers(token, &issuer_refs)?;
    if claims.cnf.is_some()
        || claims.gpt_sso_login_code_level.is_some()
        || !scope_contains(&claims.scope, required_scope)
    {
        return Err(AppError::Forbidden);
    }
    let client = state
        .db
        .find_client_by_client_id(&claims.client_id)
        .await?
        .filter(|client| client.is_active == 1)
        .ok_or(AppError::Unauthorized)?;
    let application = applications::load_active_application_for_client(state, &client.id).await?;
    if !applications::application_protocol_enabled(state, &application.id, "oauth2_oidc").await? {
        return Err(AppError::Forbidden);
    }
    let expected_audience = if client.audience.trim().is_empty() {
        client.client_id.as_str()
    } else {
        client.audience.trim()
    };
    if claims.client_id != client.client_id || claims.aud != expected_audience {
        return Err(AppError::Unauthorized);
    }
    let user = state
        .db
        .find_user_by_id(&claims.sub)
        .await?
        .filter(|user| user.is_active == 1 && user.archived_at.is_none())
        .ok_or(AppError::Unauthorized)?;
    if state
        .db
        .find_trial_enrollment_for_user(&user.id)
        .await?
        .is_some()
    {
        return Err(AppError::Forbidden);
    }
    if !state
        .db
        .user_can_access_application(&application, &user.id)
        .await?
    {
        return Err(AppError::Forbidden);
    }
    if let Some(consent) = state
        .db
        .find_client_grant(&user.id, &client.client_id)
        .await?
        && (consent.revoked_at.is_some()
            || !claims.scope.split_whitespace().all(|scope| {
                consent
                    .granted_scopes
                    .split_whitespace()
                    .any(|granted| granted == scope)
            }))
    {
        return Err(AppError::Forbidden);
    }
    let settings = state
        .db
        .find_application_billing_settings(&application.id)
        .await?
        .ok_or(AppError::Forbidden)?;
    if settings.accept_signet_balance != 1 {
        return Err(AppError::Forbidden);
    }
    Ok(BillingApplicationContext {
        user,
        client,
        application,
        settings,
    })
}

async fn application_me(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    let context = billing_application_context(&state, &headers, BILLING_SCOPE_READ).await?;
    let supported_currencies: Vec<String> =
        util::from_json(&context.settings.supported_currencies)?;
    let currency = supported_currencies
        .first()
        .cloned()
        .unwrap_or_else(|| state.settings.billing.default_currency.clone());
    let currency = normalize_currency(&currency)?;
    let _ = minor_unit(&state.settings, &currency)?;
    let wallet = if context.settings.wallet_mode == WALLET_MODE_ISOLATED {
        state
            .db
            .ensure_application_wallet_account(&context.user.id, &context.application.id, &currency)
            .await?
    } else {
        state
            .db
            .ensure_user_wallet_account(&context.user.id, &currency)
            .await?
    };
    Ok(Json(json!({
        "user_id": context.user.id,
        "client_id": context.client.client_id,
        "application_id": context.application.id,
        "application_name": context.application.name,
        "wallet_mode": context.settings.wallet_mode,
        "supported_currencies": supported_currencies,
        "wallet": wallet_view(&state.settings, wallet)?,
    })))
}

async fn refund_charge(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<RefundInput>,
) -> AppResult<Json<WalletTransactionRecord>> {
    let context = billing_application_context(&state, &headers, BILLING_SCOPE_REFUND).await?;
    if input.amount_minor <= 0 {
        return Err(AppError::BadRequest(
            "billing refund amount is invalid".to_string(),
        ));
    }
    let idempotency_key = normalize_operation_key(&input.idempotency_key)?;
    let original = state
        .db
        .find_wallet_transaction_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    if original.kind != "commit"
        || original.status != "committed"
        || original.user_id.as_deref() != Some(context.user.id.as_str())
        || original.application_id.as_deref() != Some(context.application.id.as_str())
    {
        return Err(AppError::NotFound);
    }
    let transaction = state
        .db
        .refund_committed_charge(&id, &context.user.id, input.amount_minor, &idempotency_key)
        .await?;
    if transaction.user_id.as_deref() != Some(context.user.id.as_str())
        || transaction.application_id.as_deref() != Some(context.application.id.as_str())
        || transaction.external_order_id.as_deref() != Some(id.as_str())
        || transaction.amount_minor != input.amount_minor
    {
        return Err(AppError::BadRequest(
            "billing idempotency_key is already used for another refund".to_string(),
        ));
    }
    Ok(Json(transaction))
}

async fn require_billing_permission(
    state: &AppState,
    jar: &CookieJar,
    permission: crate::access::Permission,
) -> AppResult<auth::CurrentUser> {
    let current = auth::require_current_user(state, jar).await?;
    auth::ensure_current_account_mutable(&current)?;
    state
        .db
        .require_permission(&current.user, permission)
        .await?;
    Ok(current)
}

async fn require_billing_reader(state: &AppState, jar: &CookieJar) -> AppResult<auth::CurrentUser> {
    let current = auth::require_current_user(state, jar).await?;
    auth::ensure_current_account_mutable(&current)?;
    if state
        .db
        .has_permission(&current.user, crate::access::Permission::BillingRead)
        .await?
        || state
            .db
            .has_permission(&current.user, crate::access::Permission::BillingManage)
            .await?
    {
        Ok(current)
    } else {
        Err(AppError::Forbidden)
    }
}

async fn list_admin_orders(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<LimitQuery>,
) -> AppResult<Json<Vec<PaymentOrderView>>> {
    let _ = require_billing_reader(&state, &jar).await?;
    Ok(Json(
        state
            .db
            .list_payment_orders(None, query.limit.unwrap_or(200))
            .await?
            .into_iter()
            .map(|order| payment_order_view(&state.settings, order))
            .collect::<AppResult<Vec<_>>>()?,
    ))
}

#[derive(Debug, Serialize)]
struct AdminPaymentOrderView {
    order: PaymentOrderView,
    refunds: Vec<crate::db::PaymentRefundRecord>,
}

async fn get_admin_order(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<AdminPaymentOrderView>> {
    let _ = require_billing_reader(&state, &jar).await?;
    let order = state
        .db
        .find_payment_order(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(AdminPaymentOrderView {
        refunds: state.db.list_payment_refunds(&id).await?,
        order: payment_order_view(&state.settings, order)?,
    }))
}

async fn query_admin_order(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Query(query): Query<ReconcileQuery>,
) -> AppResult<Json<PaymentOrderView>> {
    let _current =
        require_billing_permission(&state, &jar, crate::access::Permission::BillingManage).await?;
    let order = state
        .db
        .find_payment_order(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    let order = reconciliation_service::BillingCommandService::new(&state)
        .reconcile_order(&order.id, query.force)
        .await?;
    Ok(Json(payment_order_view(&state.settings, order)?))
}

async fn refund_admin_order(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(input): Json<RefundInput>,
) -> AppResult<Json<crate::db::PaymentRefundRecord>> {
    let current =
        require_billing_permission(&state, &jar, crate::access::Permission::BillingManage).await?;
    let order = state
        .db
        .find_payment_order(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    let idempotency_key = normalize_operation_key(&input.idempotency_key)?;
    let reason = input
        .reason
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("Signet billing refund")
        .to_string();
    // Reserve before any external side effect.  A pending intent occupies
    // the order's refundable amount and survives a process crash, so a
    // replay with the same key can safely retry the provider operation.
    let intent = state
        .db
        .reserve_payment_refund(
            &order.id,
            input.amount_minor,
            Some(&current.user.id),
            &reason,
            &idempotency_key,
        )
        .await?;
    if intent.status != "pending" {
        return Ok(Json(intent));
    }

    let provider =
        match provider_adapter::configured_provider(&state.settings, &order.provider_slug) {
            Ok(provider) => provider,
            Err(error) => {
                // No provider call happened, so this intent is a known failure.
                // If cancellation itself fails, preserve that database error: the
                // pending row remains recoverable on the next same-key replay.
                let canceled = state
                    .db
                    .cancel_payment_refund(&order.id, &intent.id)
                    .await?;
                if canceled.status == "succeeded" {
                    return Ok(Json(canceled));
                }
                return Err(error);
            }
        };
    let provider_refund = match provider
        .refund_payment(&order, input.amount_minor, &idempotency_key)
        .await
    {
        Ok(provider_refund) => provider_refund,
        Err(error) => {
            // A timeout, transport failure, malformed success response, or
            // provider 5xx has an unknown outcome: the provider may already
            // have accepted the refund. Keep the intent pending so the same
            // provider idempotency key can recover it later.
            if is_provider_outcome_unknown(&error) {
                return Err(error);
            }
            // This adapter reports a known provider failure.  A crash or a
            // local finalize failure takes the other path and leaves pending
            // so the provider idempotency key can be replayed safely.
            let canceled = state
                .db
                .cancel_payment_refund(&order.id, &intent.id)
                .await?;
            if canceled.status == "succeeded" {
                return Ok(Json(canceled));
            }
            return Err(error);
        }
    };

    // Finalize is deliberately not followed by cancellation on error.  If
    // the provider accepted the refund but this transaction failed, the
    // pending intent is the durable recovery record.
    Ok(Json(
        state
            .db
            .finalize_payment_refund(&order.id, &intent.id, &provider_refund.provider_refund_id)
            .await?,
    ))
}

async fn adjust_wallet_admin(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(input): Json<ManualAdjustmentInput>,
) -> AppResult<Json<WalletTransactionRecord>> {
    let current =
        require_billing_permission(&state, &jar, crate::access::Permission::BillingManage).await?;
    let wallet = state
        .db
        .find_wallet_account_by_id(&input.wallet_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let currency = normalize_currency(&input.currency)?;
    if wallet.currency != currency {
        return Err(AppError::BadRequest(
            "wallet currency does not match adjustment currency".to_string(),
        ));
    }
    if input.amount_delta_minor == 0 || input.reason.trim().is_empty() {
        return Err(AppError::BadRequest(
            "billing adjustment requires a non-zero amount and reason".to_string(),
        ));
    }
    let idempotency_key = normalize_operation_key(&input.idempotency_key)?;
    let transaction = state
        .db
        .adjust_wallet(WalletAdjustment {
            wallet_id: &wallet.id,
            user_id: wallet.user_id.as_deref(),
            application_id: wallet.application_id.as_deref(),
            currency: &currency,
            amount_delta_minor: input.amount_delta_minor,
            idempotency_key: &idempotency_key,
            metadata: json!({ "reason": input.reason, "actor_user_id": current.user.id }),
        })
        .await?;
    if transaction.source_wallet_id.as_deref() != Some(wallet.id.as_str()) {
        return Err(AppError::BadRequest(
            "billing idempotency_key is already used for another adjustment".to_string(),
        ));
    }
    Ok(Json(transaction))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::{
        RsaPrivateKey, RsaPublicKey,
        pkcs8::{DecodePrivateKey, EncodePublicKey, LineEnding},
    };
    use std::collections::BTreeMap;

    #[test]
    fn decimal_amounts_use_integer_minor_units() {
        assert_eq!(parse_decimal_to_minor("12", 2).unwrap(), 1200);
        assert_eq!(parse_decimal_to_minor("12.3", 2).unwrap(), 1230);
        assert_eq!(parse_decimal_to_minor("0.01", 2).unwrap(), 1);
        assert!(parse_decimal_to_minor("12.345", 2).is_err());
        assert!(parse_decimal_to_minor("-1", 2).is_err());
        assert_eq!(format_minor(1230, 2), "12.30");
    }

    #[test]
    fn reconciliation_retry_backoff_is_exponential_and_bounded() {
        assert_eq!(reconcile_retry_delay_seconds(0, 10, 900), 10);
        assert_eq!(reconcile_retry_delay_seconds(1, 10, 900), 10);
        assert_eq!(reconcile_retry_delay_seconds(2, 10, 900), 20);
        assert_eq!(reconcile_retry_delay_seconds(4, 10, 900), 80);
        assert_eq!(reconcile_retry_delay_seconds(20, 10, 900), 900);
        assert_eq!(reconcile_next_retry_at(100, 3, 10, 900), 140);
    }

    #[test]
    fn local_expiry_never_skips_provider_confirmation() {
        assert_eq!(
            expired_payment_order_policy(PAYMENT_STATUS_PENDING, "qr", 99, 100),
            Some(ExpiredPaymentOrderPolicy::QueryProvider)
        );
        assert_eq!(
            expired_payment_order_policy(PAYMENT_STATUS_RECONCILE, "", 99, 100),
            Some(ExpiredPaymentOrderPolicy::QueryProvider)
        );
        assert_eq!(
            expired_payment_order_policy(PAYMENT_STATUS_CREATING, "", 99, 100),
            Some(ExpiredPaymentOrderPolicy::QueryProviderWithoutCreate)
        );
        assert_eq!(
            expired_payment_order_policy(PAYMENT_STATUS_PENDING, "", 101, 100),
            None
        );
    }

    #[test]
    fn provider_unknown_outcomes_are_reconcileable_and_ids_are_never_fabricated() {
        for reason in [
            "provider request timed out",
            "provider network/request failed",
            "provider returned 5xx or another non-success response",
            "provider response JSON is invalid",
        ] {
            let error = provider_outcome_unknown_with_reason(reason);
            assert!(is_provider_outcome_unknown(&error));
            assert!(provider_error_message(&error).contains(reason));
        }
        let notification = notification_from_fields(
            &BTreeMap::from([("out_trade_no".to_string(), "merchant-order".to_string())]),
            100,
            CURRENCY_CNY,
            String::new(),
            PAYMENT_STATUS_PAID,
        )
        .unwrap();
        assert!(notification.provider_trade_id.is_empty());
    }

    #[test]
    fn epay_signature_excludes_protocol_fields_and_empty_values() {
        let fields = BTreeMap::from([
            ("pid".to_string(), "1000".to_string()),
            ("money".to_string(), "1.00".to_string()),
            ("empty".to_string(), String::new()),
        ]);
        let signed = sign_epay(&fields, "secret");
        let mut with_protocol_fields = fields.clone();
        with_protocol_fields.insert("sign".to_string(), "old".to_string());
        with_protocol_fields.insert("sign_type".to_string(), "MD5".to_string());
        assert_eq!(signed, sign_epay(&with_protocol_fields, "secret"));
        assert_eq!(signed.len(), 32);
    }

    #[test]
    fn alipay_rsa2_notification_signature_is_verified() {
        let private_pem = util::generate_rsa_private_key_pem().unwrap();
        let private = RsaPrivateKey::from_pkcs8_pem(&private_pem).unwrap();
        let public_pem = RsaPublicKey::from(&private)
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        let fields = BTreeMap::from([
            ("out_trade_no".to_string(), "order-1".to_string()),
            ("total_amount".to_string(), "1.00".to_string()),
            ("trade_status".to_string(), "TRADE_SUCCESS".to_string()),
        ]);
        let content = alipay_sign_content(&fields);
        let signature = rsa_sha256_sign(&private_pem, &content).unwrap();
        rsa_sha256_verify(&public_pem, &content, &signature).unwrap();
        assert!(rsa_sha256_verify(&public_pem, "tampered", &signature).is_err());
    }

    #[test]
    fn application_billing_input_normalizes_and_validates_currencies() {
        let settings: Settings = toml::from_str(include_str!("../../config/default.toml")).unwrap();
        let (accept, mode, currencies) = normalize_application_billing_input(
            &settings,
            ApplicationBillingSettingsInput {
                accept_signet_balance: true,
                wallet_mode: "isolated".to_string(),
                supported_currencies: vec!["cny".to_string(), "CNY".to_string()],
            },
        )
        .unwrap();
        assert!(accept);
        assert_eq!(mode, WALLET_MODE_ISOLATED);
        assert_eq!(currencies, vec!["CNY"]);
        assert!(
            normalize_application_billing_input(
                &settings,
                ApplicationBillingSettingsInput {
                    accept_signet_balance: true,
                    wallet_mode: "unknown".to_string(),
                    supported_currencies: Vec::new(),
                },
            )
            .is_err()
        );
    }

    #[test]
    fn bearer_tokens_and_scopes_are_checked_exactly() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            "bEaReR access-token".parse().unwrap(),
        );
        assert_eq!(bearer_token(&headers).unwrap(), "access-token");
        assert!(scope_contains(
            "billing.read billing.reserve",
            "billing.read"
        ));
        assert!(!scope_contains("billing.read", "billing.re"));

        headers.insert(header::AUTHORIZATION, "Basic access-token".parse().unwrap());
        assert!(bearer_token(&headers).is_err());
    }
}
