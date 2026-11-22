//! Self-service sub-identity management. Every sub-identity is a distinct
//! Signet principal. Linking grants management rights, never authentication
//! or automatic admin/application permissions.

use crate::{
    AppState, audit::{self, AuditSink}, auth,
    db::{NewUser, SubIdentityChildRecord, SubIdentityRecord, SUB_IDENTITY_LINK_TTL_SECONDS},
    error::{AppError, AppResult},
    util,
};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{delete, get, post},
};
use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/me/sub-identities", get(list).post(create))
        .route("/api/me/sub-identities/link-claim", post(issue_link_claim))
        .route("/api/me/sub-identities/attach", post(attach))
        .route("/api/me/sub-identities/{user_id}", delete(detach))
}

#[derive(Serialize)]
struct SubIdentityOverview {
    identity: Option<SubIdentityRecord>,
    children: Vec<SubIdentityChildRecord>,
}

async fn list(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<SubIdentityOverview>> {
    let current = auth::require_current_user(&state, &jar).await?;
    auth::ensure_current_account_mutable(&current)?;
    let identity = state.db.find_sub_identity(&current.user.id).await?;
    let children = if identity.is_some() {
        Vec::new()
    } else {
        state.db.list_managed_sub_identities(&current.user.id).await?
    };
    Ok(Json(SubIdentityOverview { identity, children }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateSubIdentityInput {
    username: String,
    email: String,
    password: String,
    #[serde(default)]
    display_name: Option<String>,
}

#[derive(Serialize)]
struct CreatedSubIdentity {
    user_id: String,
    username: String,
    email: String,
}

fn valid_new_sub_identity(input: &CreateSubIdentityInput) -> AppResult<()> {
    let email = input.email.trim();
    let username = input.username.trim();
    let password = input.password.as_str();
    if email.len() < 5
        || email.len() > 254
        || email.contains(char::is_whitespace)
        || email.split_once('@').is_none_or(|(name, domain)| name.is_empty() || !domain.contains('.'))
        || username.len() < 3
        || username.len() > 64
        || !username.chars().all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
        || password.len() < 12
        || password.len() > 256
        || password.trim().is_empty()
    {
        return Err(AppError::BadRequest(
            "sub-identity requires a valid email, 3-64 character username, and password of at least 12 characters".to_string(),
        ));
    }
    Ok(())
}

async fn create(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(input): Json<CreateSubIdentityInput>,
) -> AppResult<Json<CreatedSubIdentity>> {
    let current = auth::require_current_user(&state, &jar).await?;
    auth::ensure_current_account_mutable(&current)?;
    valid_new_sub_identity(&input)?;
    let user = state.db.create_managed_sub_identity(
        &current.user.id,
        NewUser {
            email: input.email.trim().to_lowercase(),
            username: input.username.trim().to_string(),
            display_name: input.display_name.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string),
            phone: None,
            password_hash: util::hash_password(&input.password)?,
            email_verified_at: None,
            phone_verified_at: None,
            is_admin: false,
            is_active: true,
            archived_at: None,
        },
    ).await?;
    state.db.record_audit_event(audit::management_event(
        current.user.id, "sub_identity.create", "user", Some(user.id.clone()),
        serde_json::json!({ "type": "managed" }),
    )).await?;
    Ok(Json(CreatedSubIdentity {
        user_id: user.id,
        username: user.username,
        email: user.email,
    }))
}

#[derive(Serialize)]
struct LinkClaimResponse {
    code: String,
    expires_in_seconds: i64,
}

async fn issue_link_claim(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<LinkClaimResponse>> {
    let current = auth::require_current_user(&state, &jar).await?;
    auth::ensure_current_account_mutable(&current)?;
    let code = state.db.issue_anonymous_sub_identity_link_claim(&current.user.id).await?;
    state.db.record_audit_event(audit::management_event(
        current.user.id, "sub_identity.link_claim_issued", "user", None,
        serde_json::json!({ "ttl_seconds": SUB_IDENTITY_LINK_TTL_SECONDS }),
    )).await?;
    Ok(Json(LinkClaimResponse {
        code,
        expires_in_seconds: SUB_IDENTITY_LINK_TTL_SECONDS,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AttachInput {
    code: String,
}

#[derive(Serialize)]
struct OkResponse {
    ok: bool,
}

async fn attach(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(input): Json<AttachInput>,
) -> AppResult<Json<OkResponse>> {
    let current = auth::require_current_user(&state, &jar).await?;
    auth::ensure_current_account_mutable(&current)?;
    state.db.attach_claimed_sub_identity(&current.user.id, &input.code).await?;
    state.db.record_audit_event(audit::management_event(
        current.user.id, "sub_identity.attach", "user", None,
        serde_json::json!({ "method": "proof_of_possession" }),
    )).await?;
    Ok(Json(OkResponse { ok: true }))
}

async fn detach(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(user_id): Path<String>,
) -> AppResult<Json<OkResponse>> {
    let current = auth::require_current_user(&state, &jar).await?;
    auth::ensure_current_account_mutable(&current)?;
    state.db.detach_managed_sub_identity(&current.user.id, &user_id).await?;
    state.db.record_audit_event(audit::management_event(
        current.user.id, "sub_identity.detach", "user", Some(user_id),
        serde_json::json!({}),
    )).await?;
    Ok(Json(OkResponse { ok: true }))
}
