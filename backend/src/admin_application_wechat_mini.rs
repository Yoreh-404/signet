//! Workspace-scoped WeChat Mini Program credentials.
//!
//! AppID, scopes, and site policy may be declared by the website. AppSecret
//! never leaves Signet after one authorized provisioning request, and no
//! read endpoint can reveal its ciphertext or plaintext.

use super::admin_application_scope::managed_application;
use crate::{AppState, audit, db::{ApplicationAuthCredentialRecord, WECHAT_MINI_TYPE}, error::{AppError, AppResult}, util};
use crate::wechat_mini::MiniProgramOptions;
use axum::{Json, extract::{Path, State}};
use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CredentialInput {
    /// May be omitted on an update to keep the existing encrypted secret.
    #[serde(default)]
    app_secret: Option<String>,
    scopes: Vec<String>,
    #[serde(default)]
    allow_registration: bool,
    #[serde(default = "super::admin_defaults::default_true")]
    is_active: bool,
}

#[derive(Debug, Serialize)]
pub(super) struct CredentialResponse {
    app_id: String,
    application_id: String,
    app_secret_configured: bool,
    scopes: Vec<String>,
    allow_registration: bool,
    is_active: bool,
    created_at: i64,
    updated_at: i64,
}

fn validate_app_id(value: &str) -> AppResult<&str> {
    if value.len() < 8 || value.len() > 64
        || !value.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_') {
        return Err(AppError::BadRequest("WeChat Mini Program AppID is invalid".into()));
    }
    Ok(value)
}

fn response(record: ApplicationAuthCredentialRecord) -> AppResult<CredentialResponse> {
    if record.credential_type != WECHAT_MINI_TYPE {
        return Err(AppError::Internal("unexpected application authentication credential type".into()));
    }
    let options: MiniProgramOptions = serde_json::from_str(&record.config_json)
        .map_err(|_| AppError::Internal("invalid Mini Program options in database".into()))?;
    Ok(CredentialResponse {
        app_id: record.external_id,
        application_id: record.application_id,
        app_secret_configured: !record.secret_ciphertext.is_empty(),
        scopes: options.scopes,
        allow_registration: options.allow_registration,
        is_active: record.is_active == 1,
        created_at: record.created_at,
        updated_at: record.updated_at,
    })
}

pub(super) async fn list(
    State(state): State<AppState>, jar: CookieJar, Path(application_id): Path<String>,
) -> AppResult<Json<Vec<CredentialResponse>>> {
    let (_actor, application) = managed_application(&state, &jar, &application_id).await?;
    let credentials = state.db.list_application_auth_credentials(&application.id, WECHAT_MINI_TYPE).await?;
    Ok(Json(credentials.into_iter().map(response).collect::<AppResult<Vec<_>>>()?))
}

pub(super) async fn upsert(
    State(state): State<AppState>, jar: CookieJar,
    Path((application_id, app_id)): Path<(String, String)>,
    Json(payload): Json<CredentialInput>,
) -> AppResult<Json<CredentialResponse>> {
    validate_app_id(&app_id)?;
    let (actor, application) = managed_application(&state, &jar, &application_id).await?;
    if payload.scopes.is_empty() || payload.scopes.len() > 64 {
        return Err(AppError::BadRequest("Mini Program scopes cannot be empty or exceed 64".into()));
    }
    let supported = state.settings.oidc.supported_scopes.iter().map(String::as_str)
        .collect::<BTreeSet<_>>();
    let unique = payload.scopes.iter().map(String::as_str).collect::<BTreeSet<_>>();
    if unique.len() != payload.scopes.len()
        || payload.scopes.iter().any(|scope| !supported.contains(scope.as_str())) {
        return Err(AppError::BadRequest("Mini Program declares duplicate or unsupported Signet scopes".into()));
    }
    let encrypted = match payload.app_secret.as_deref() {
        None => None,
        Some(value) => {
            if state.settings.discovery.encryption_key.trim().is_empty() {
                return Err(AppError::Configuration("Signet credential encryption is not configured".into()));
            }
            Some(util::encrypt_application_auth_secret(
                &state.settings.discovery.encryption_key, &application.id, WECHAT_MINI_TYPE, &app_id, value,
            )?)
        }
    };
    let record = state.db.upsert_application_auth_credential(
        &application.id, WECHAT_MINI_TYPE, &app_id, encrypted.as_deref(),
        &util::to_json(&MiniProgramOptions {
            scopes: payload.scopes,
            allow_registration: payload.allow_registration,
        })?,
        payload.is_active,
        audit::management_event(
            actor.user.id, "application.wechat_mini.upsert", "application_wechat_mini",
            Some(app_id.clone()), serde_json::json!({
                "application_id": application.id,
                "is_active": payload.is_active,
                "allow_registration": payload.allow_registration,
                "secret_rotated": encrypted.is_some(),
            })
        )
    ).await?;
    Ok(Json(response(record)?))
}

pub(super) async fn delete(
    State(state): State<AppState>, jar: CookieJar,
    Path((application_id, app_id)): Path<(String, String)>,
) -> AppResult<Json<serde_json::Value>> {
    validate_app_id(&app_id)?;
    let (actor, application) = managed_application(&state, &jar, &application_id).await?;
    let removed = state.db.delete_application_auth_credential(
        &application.id, WECHAT_MINI_TYPE, &app_id,
        audit::management_event(actor.user.id,
            "application.wechat_mini.delete", "application_wechat_mini",
            Some(app_id.clone()), serde_json::json!({"application_id": application.id}))
    ).await?;
    if !removed { return Err(AppError::NotFound); }
    Ok(Json(serde_json::json!({"ok":true})))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_id_validation_is_strict_and_public_response_excludes_secrets() {
        assert!(validate_app_id("wx1234567890abcdef").is_ok());
        assert!(validate_app_id("wx!bad").is_err());
        assert!(validate_app_id("wx1234 space").is_err());
        let sample = ApplicationAuthCredentialRecord {
            credential_type: WECHAT_MINI_TYPE.into(),
            external_id: "wx1234567890abcdef".into(),
            application_id: "app-1".into(),
            secret_ciphertext: "signet-application-auth:v1.secret".into(),
            config_json: r#"{"scopes":["openid"],"allow_registration":false}"#.into(),
            is_active: 1, created_at: 1, updated_at: 2,
        };
        let value = serde_json::to_value(response(sample).unwrap()).unwrap();
        assert_eq!(value["app_secret_configured"], true);
        assert!(value.get("app_secret").is_none());
        assert!(value.get("app_secret_ciphertext").is_none());
    }
}
