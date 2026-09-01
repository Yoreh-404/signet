use crate::{
    AppState, audit, auth,
    error::{AppError, AppResult},
    mfa::{self, RecoveryCodeIssuer},
    util,
};
use axum::{Json, extract::State, http::HeaderMap};
use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub(crate) struct MfaStatusResponse {
    pub(crate) enabled: bool,
    pub(crate) totp_enabled: bool,
    pub(crate) recovery_codes_remaining: usize,
    pub(crate) recovery_codes_total: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct TotpSetupResponse {
    setup_id: String,
    secret: String,
    otpauth_uri: String,
    expires_at: i64,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ConfirmTotpInput {
    setup_id: String,
    code: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct ConfirmTotpResponse {
    status: MfaStatusResponse,
    recovery_codes: Vec<String>,
}

pub(crate) async fn mfa_status(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<MfaStatusResponse>> {
    let current = auth::require_current_user(&state, &jar).await?;
    Ok(Json(mfa_status_for_user(&state, &current.user.id).await?))
}

pub(crate) async fn start_totp_setup(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> AppResult<Json<TotpSetupResponse>> {
    let current = auth::require_current_user(&state, &jar).await?;
    auth::ensure_current_account_mutable(&current)?;
    let secret = mfa::generate_totp_secret();
    let encrypted_secret = mfa::protect_totp_secret(&state, &secret)?;
    let setup = state
        .db
        .create_mfa_totp_setup(
            &current.user.id,
            encrypted_secret,
            mfa::MFA_SETUP_TTL_SECONDS,
        )
        .await?;
    let issuer = state.effective_issuer(&headers).await?;
    let otpauth_uri = mfa::otpauth_uri(&issuer, &current.user.email, &secret)?;
    Ok(Json(TotpSetupResponse {
        setup_id: setup.id,
        secret,
        otpauth_uri,
        expires_at: setup.expires_at,
    }))
}

pub(crate) async fn confirm_totp_setup(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<ConfirmTotpInput>,
) -> AppResult<Json<ConfirmTotpResponse>> {
    let current = auth::require_current_user(&state, &jar).await?;
    auth::ensure_current_account_mutable(&current)?;
    let setup = state
        .db
        .find_mfa_totp_setup(&payload.setup_id)
        .await?
        .ok_or(AppError::NotFound)?;
    if setup.user_id != current.user.id || setup.expires_at < util::now_ts() {
        return Err(AppError::Unauthorized);
    }
    let secret = mfa::reveal_totp_secret(&state, &setup.secret)?;
    if !mfa::verify_setup_code(&secret, &payload.code)? {
        return Err(AppError::Unauthorized);
    }
    let codes = mfa::StandardRecoveryCodeIssuer.issue_recovery_codes(mfa::RECOVERY_CODE_COUNT)?;
    state
        .db
        .confirm_totp_setup_with_audit(
            &current.user.id,
            &payload.setup_id,
            mfa::code_hashes(&codes),
            audit::management_event(
                current.user.id.clone(),
                "mfa.totp.enable",
                "user",
                Some(current.user.id.clone()),
                serde_json::json!({ "method": "totp" }),
            ),
        )
        .await?;
    Ok(Json(ConfirmTotpResponse {
        status: mfa_status_for_user(&state, &current.user.id).await?,
        recovery_codes: mfa::plaintext_codes(&codes),
    }))
}

pub(crate) async fn rotate_recovery_codes(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<ConfirmTotpResponse>> {
    let current = auth::require_current_user(&state, &jar).await?;
    auth::ensure_current_account_mutable(&current)?;
    let codes = mfa::StandardRecoveryCodeIssuer.issue_recovery_codes(mfa::RECOVERY_CODE_COUNT)?;
    state
        .db
        .replace_recovery_codes_with_audit(
            &current.user.id,
            mfa::code_hashes(&codes),
            audit::management_event(
                current.user.id.clone(),
                "mfa.recovery_codes.rotate",
                "user",
                Some(current.user.id.clone()),
                serde_json::json!({ "count": codes.len() }),
            ),
        )
        .await?;
    Ok(Json(ConfirmTotpResponse {
        status: mfa_status_for_user(&state, &current.user.id).await?,
        recovery_codes: mfa::plaintext_codes(&codes),
    }))
}

pub(crate) async fn disable_mfa(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<MfaStatusResponse>> {
    let current = auth::require_current_user(&state, &jar).await?;
    auth::ensure_current_account_mutable(&current)?;
    state
        .db
        .delete_mfa_for_user_with_audit(
            &current.user.id,
            audit::management_event(
                current.user.id.clone(),
                "mfa.disable",
                "user",
                Some(current.user.id.clone()),
                serde_json::json!({}),
            ),
        )
        .await?;
    Ok(Json(mfa_status_for_user(&state, &current.user.id).await?))
}

pub(crate) async fn mfa_status_for_user(
    state: &AppState,
    user_id: &str,
) -> AppResult<MfaStatusResponse> {
    let method = state.db.find_totp_method(user_id).await?;
    let recovery_codes = state.db.list_recovery_codes(user_id).await?;
    Ok(MfaStatusResponse {
        enabled: mfa::method_enabled(method.as_ref()),
        totp_enabled: method.is_some(),
        recovery_codes_remaining: mfa::recovery_codes_remaining(&recovery_codes),
        recovery_codes_total: recovery_codes.len(),
    })
}
