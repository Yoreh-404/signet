use super::managed_application;
use crate::{
    AppState, applications,
    audit::{self, AuditSink},
    db::{ApplicationScimTokenRecord, NewApplicationScimToken},
    error::{AppError, AppResult},
    util,
};
use axum::{
    Json,
    extract::{Path, State},
};
use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize)]
pub(super) struct ApplicationScimTokenResponse {
    id: String,
    application_id: String,
    token_prefix: String,
    scopes: Vec<String>,
    expires_at: Option<i64>,
    revoked_at: Option<i64>,
    last_used_at: Option<i64>,
    created_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ApplicationScimTokenInput {
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    expires_at: Option<i64>,
}

fn response(
    token: ApplicationScimTokenRecord,
    raw_token: Option<String>,
) -> AppResult<ApplicationScimTokenResponse> {
    Ok(ApplicationScimTokenResponse {
        id: token.id,
        application_id: token.application_id,
        token_prefix: token.token_prefix,
        scopes: util::from_json(&token.scopes)?,
        expires_at: token.expires_at,
        revoked_at: token.revoked_at,
        last_used_at: token.last_used_at,
        created_at: token.created_at,
        token: raw_token,
    })
}

fn normalize_scopes(values: Vec<String>) -> AppResult<Vec<String>> {
    let values = if values.is_empty() {
        vec!["scim.read".to_string(), "scim.write".to_string()]
    } else {
        values
    };
    let mut scopes = BTreeSet::new();
    for value in values {
        match value.trim() {
            "scim.read" | "scim.write" => {
                scopes.insert(value.trim().to_string());
            }
            other => {
                return Err(AppError::BadRequest(format!(
                    "unsupported application SCIM token scope: {other}"
                )));
            }
        }
    }
    Ok(scopes.into_iter().collect())
}

pub(super) async fn list(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<Vec<ApplicationScimTokenResponse>>> {
    let (_, application) = managed_application(&state, &jar, &id).await?;
    let tokens = state
        .db
        .list_application_scim_tokens(&application.id)
        .await?
        .into_iter()
        .map(|token| response(token, None))
        .collect::<AppResult<Vec<_>>>()?;
    Ok(Json(tokens))
}

pub(super) async fn create(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<ApplicationScimTokenInput>,
) -> AppResult<Json<ApplicationScimTokenResponse>> {
    let (current, application) = managed_application(&state, &jar, &id).await?;
    let module = applications::enabled_module_config(&state, &id, "directory_sync")
        .await?
        .ok_or_else(|| {
            AppError::BadRequest("enable directory sync before creating a SCIM token".to_string())
        })?;
    if module
        .get("scim_enabled")
        .and_then(serde_json::Value::as_bool)
        != Some(true)
    {
        return Err(AppError::BadRequest(
            "enable application SCIM before creating a token".to_string(),
        ));
    }
    let scopes = normalize_scopes(payload.scopes)?;
    if payload
        .expires_at
        .is_some_and(|expires_at| expires_at <= util::now_ts())
    {
        return Err(AppError::BadRequest(
            "application SCIM token expiry must be in the future".to_string(),
        ));
    }
    let raw_token = format!("scim_v1_{}", util::random_token(32));
    let token_id = uuid::Uuid::new_v4().to_string();
    let token_prefix = raw_token.chars().take(16).collect::<String>();
    let record = state
        .db
        .insert_application_scim_token_with_audit(
            NewApplicationScimToken {
                id: token_id.clone(),
                application_id: application.id.clone(),
                token_prefix,
                token_hash: util::token_hash(&raw_token),
                scopes,
                expires_at: payload.expires_at,
            },
            audit::management_event(
                current.user.id,
                "application.scim_token.create",
                "application",
                Some(application.id.clone()),
                serde_json::json!({
                    "token_id": token_id,
                    "token_prefix": raw_token.chars().take(16).collect::<String>(),
                }),
            ),
        )
        .await?;
    Ok(Json(response(record, Some(raw_token))?))
}

pub(super) async fn revoke(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, token_id)): Path<(String, String)>,
) -> AppResult<Json<serde_json::Value>> {
    let (current, application) = managed_application(&state, &jar, &id).await?;
    state
        .db
        .revoke_application_scim_token(&application.id, &token_id)
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.scim_token.revoke",
            "application",
            Some(application.id),
            serde_json::json!({ "token_id": token_id }),
        ))
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}
