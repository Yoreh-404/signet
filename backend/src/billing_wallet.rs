use super::util;
use super::{
    AppError, AppResult, AppState, BILLING_SCOPE_COMMIT, BILLING_SCOPE_RELEASE,
    BILLING_SCOPE_RESERVE, BillingApplicationContext, OperationInput, ReservationInput,
    TransferInput, WALLET_MODE_ISOLATED, application_currency_allowed, applications,
    billing_application_context, billing_enabled, normalize_currency, normalize_operation_key,
    normalize_reference, standard_current_user, validate_amount,
};
use crate::db::{
    WalletAccountRecord, WalletHoldRecord, WalletHoldReservation, WalletTransactionRecord,
    WalletTransfer,
};
use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
};
use axum_extra::extract::cookie::CookieJar;

pub(super) async fn transfer_wallet(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(input): Json<TransferInput>,
) -> AppResult<Json<WalletTransactionRecord>> {
    billing_enabled(&state.settings)?;
    let current = standard_current_user(&state, &jar).await?;
    let application = applications::load_active_application(&state, &input.application_id).await?;
    if !state
        .db
        .user_can_access_application(&application, &current.user.id)
        .await?
    {
        return Err(AppError::Forbidden);
    }
    let settings = state
        .db
        .find_application_billing_settings(&application.id)
        .await?
        .ok_or(AppError::Forbidden)?;
    if settings.accept_signet_balance != 1 || settings.wallet_mode != WALLET_MODE_ISOLATED {
        return Err(AppError::BadRequest(
            "wallet transfer requires an isolated application wallet".to_string(),
        ));
    }
    let currency = normalize_currency(&input.currency)?;
    validate_amount(&state.settings, &currency, input.amount_minor)?;
    if !application_currency_allowed(&settings, &currency)? {
        return Err(AppError::BadRequest(
            "currency is not enabled for this application".to_string(),
        ));
    }
    let idempotency_key = normalize_operation_key(&input.idempotency_key)?;
    let global = state
        .db
        .ensure_user_wallet_account(&current.user.id, &currency)
        .await?;
    let application_wallet = state
        .db
        .ensure_application_wallet_account(&current.user.id, &application.id, &currency)
        .await?;
    let (source, destination) = match input.direction.trim() {
        "to_application" | "global_to_application" => (global.id, application_wallet.id),
        "from_application" | "application_to_global" => (application_wallet.id, global.id),
        _ => {
            return Err(AppError::BadRequest(
                "transfer direction must be to_application or from_application".to_string(),
            ));
        }
    };
    let transaction = state
        .db
        .transfer_wallets(WalletTransfer {
            user_id: &current.user.id,
            source_wallet_id: &source,
            destination_wallet_id: &destination,
            currency: &currency,
            amount_minor: input.amount_minor,
            application_id: Some(&application.id),
            idempotency_key: &idempotency_key,
        })
        .await?;
    if transaction.user_id.as_deref() != Some(current.user.id.as_str())
        || transaction.application_id.as_deref() != Some(application.id.as_str())
        || transaction.source_wallet_id.as_deref() != Some(source.as_str())
        || transaction.destination_wallet_id.as_deref() != Some(destination.as_str())
    {
        return Err(AppError::BadRequest(
            "billing idempotency_key is already used for another transfer".to_string(),
        ));
    }
    Ok(Json(transaction))
}
pub(super) async fn application_spend_wallet(
    state: &AppState,
    context: &BillingApplicationContext,
    currency: &str,
) -> AppResult<WalletAccountRecord> {
    if !application_currency_allowed(&context.settings, currency)? {
        return Err(AppError::BadRequest(
            "currency is not enabled for this application".to_string(),
        ));
    }
    if context.settings.wallet_mode == WALLET_MODE_ISOLATED {
        state
            .db
            .ensure_application_wallet_account(&context.user.id, &context.application.id, currency)
            .await
    } else {
        state
            .db
            .ensure_user_wallet_account(&context.user.id, currency)
            .await
    }
}

pub(super) fn ensure_hold_belongs_to_application(
    hold: &WalletHoldRecord,
    context: &BillingApplicationContext,
) -> AppResult<()> {
    if hold.user_id.as_deref() != Some(context.user.id.as_str())
        || hold.application_id.as_deref() != Some(context.application.id.as_str())
    {
        return Err(AppError::NotFound);
    }
    Ok(())
}

pub(super) async fn create_reservation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ReservationInput>,
) -> AppResult<Json<WalletHoldRecord>> {
    let context = billing_application_context(&state, &headers, BILLING_SCOPE_RESERVE).await?;
    let currency = normalize_currency(&input.currency)?;
    validate_amount(&state.settings, &currency, input.amount_minor)?;
    let reference = normalize_reference(&input.reference)?;
    let idempotency_key = normalize_operation_key(&input.idempotency_key)?;
    let wallet = application_spend_wallet(&state, &context, &currency).await?;
    let expires_at = util::now_ts() + state.settings.billing.reservation_ttl_seconds;
    let hold = state
        .db
        .reserve_wallet_hold(WalletHoldReservation {
            wallet_id: &wallet.id,
            user_id: &context.user.id,
            application_id: &context.application.id,
            currency: &currency,
            amount_minor: input.amount_minor,
            reference: &reference,
            idempotency_key: &idempotency_key,
            expires_at,
        })
        .await?;
    if hold.user_id.as_deref() != Some(context.user.id.as_str())
        || hold.application_id.as_deref() != Some(context.application.id.as_str())
        || hold.wallet_id != wallet.id
        || hold.currency != currency
        || hold.amount_minor != input.amount_minor
    {
        return Err(AppError::BadRequest(
            "billing idempotency_key is already used for another reservation".to_string(),
        ));
    }
    Ok(Json(hold))
}

pub(super) async fn commit_reservation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<OperationInput>,
) -> AppResult<Json<WalletHoldRecord>> {
    let context = billing_application_context(&state, &headers, BILLING_SCOPE_COMMIT).await?;
    let idempotency_key = normalize_operation_key(&input.idempotency_key)?;
    let hold = state
        .db
        .find_wallet_hold(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    ensure_hold_belongs_to_application(&hold, &context)?;
    let settlement = state
        .db
        .ensure_settlement_wallet_account(&context.application.id, &hold.currency)
        .await?;
    Ok(Json(
        state
            .db
            .commit_wallet_hold(&hold.id, &settlement.id, &idempotency_key)
            .await?,
    ))
}

pub(super) async fn release_reservation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<OperationInput>,
) -> AppResult<Json<WalletHoldRecord>> {
    let context = billing_application_context(&state, &headers, BILLING_SCOPE_RELEASE).await?;
    let idempotency_key = normalize_operation_key(&input.idempotency_key)?;
    let hold = state
        .db
        .find_wallet_hold(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    ensure_hold_belongs_to_application(&hold, &context)?;
    Ok(Json(
        state
            .db
            .release_wallet_hold(&hold.id, &idempotency_key)
            .await?,
    ))
}
