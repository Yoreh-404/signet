use super::{
    default_application_jwt_client_type, default_jwt_secret_grace_seconds, managed_application,
};
use crate::{
    AppState, applications,
    audit::{self, AuditSink},
    client_assertion,
    db::{ApplicationJwtClientRecord, NewApplicationJwtClient},
    error::{AppError, AppResult},
    util,
};
use axum::{
    Json,
    extract::{Path, State},
};
use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
pub(super) struct ApplicationJwtClientResponse {
    client_id: String,
    client_type: String,
    is_active: bool,
    secret_count: usize,
    active_secret_count: usize,
    latest_secret_created_at: Option<i64>,
    latest_secret_expires_at: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ApplicationJwtClientInput {
    client_id: String,
    #[serde(default = "default_application_jwt_client_type")]
    client_type: String,
    #[serde(default = "super::default_true")]
    is_active: bool,
}

#[derive(Debug, Deserialize)]
pub(super) struct ApplicationJwtSecretRotationInput {
    #[serde(default = "default_jwt_secret_grace_seconds")]
    grace_seconds: i64,
}

#[derive(Debug, Serialize)]
pub(super) struct ApplicationJwtSecretRotationResponse {
    client_id: String,
    secret: String,
    created_at: i64,
    grace_seconds: i64,
}

async fn response(
    state: &AppState,
    client: ApplicationJwtClientRecord,
) -> AppResult<ApplicationJwtClientResponse> {
    let secrets = state
        .db
        .list_application_jwt_secrets(&client.application_id, &client.client_id)
        .await?;
    let now = util::now_ts();
    let active_secret_count = secrets
        .iter()
        .filter(|secret| {
            secret.revoked_at.is_none()
                && secret.expires_at.is_none_or(|expires_at| expires_at >= now)
        })
        .count();
    let latest_secret = secrets.first();
    Ok(ApplicationJwtClientResponse {
        client_id: client.client_id,
        client_type: client.client_type,
        is_active: client.is_active == 1,
        secret_count: secrets.len(),
        active_secret_count,
        latest_secret_created_at: latest_secret.map(|secret| secret.created_at),
        latest_secret_expires_at: latest_secret.and_then(|secret| secret.expires_at),
    })
}

fn protocol_client_id(
    application: &crate::db::ApplicationRecord,
    module: &serde_json::Map<String, serde_json::Value>,
) -> String {
    module
        .get("client_id")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(application.slug.as_str())
        .to_string()
}

pub(super) async fn get(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<Option<ApplicationJwtClientResponse>>> {
    let (_, application) = managed_application(&state, &jar, &id).await?;
    let Some(module) = applications::enabled_protocol_config(&state, &id, "jwt").await? else {
        return Ok(Json(None));
    };
    let client_id = protocol_client_id(&application, &module);
    let client = state
        .db
        .find_application_jwt_client(&id, &client_id)
        .await?;
    match client {
        Some(client) => Ok(Json(Some(response(&state, client).await?))),
        None => Ok(Json(None)),
    }
}

pub(super) async fn update(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<ApplicationJwtClientInput>,
) -> AppResult<Json<ApplicationJwtClientResponse>> {
    let (current, application) = managed_application(&state, &jar, &id).await?;
    let client_type = payload.client_type.trim().to_ascii_lowercase();
    if !matches!(client_type.as_str(), "public" | "confidential") {
        return Err(AppError::BadRequest(
            "application JWT client_type must be public or confidential".to_string(),
        ));
    }
    let client = state
        .db
        .upsert_application_jwt_client(
            &id,
            NewApplicationJwtClient {
                client_id: payload.client_id,
                client_type,
                is_active: payload.is_active,
            },
        )
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.jwt_client.update",
            "application",
            Some(id.clone()),
            serde_json::json!({
                "organization_id": application.organization_id,
                "client_id": client.client_id,
                "client_type": client.client_type,
                "is_active": client.is_active == 1,
            }),
        ))
        .await?;
    Ok(Json(response(&state, client).await?))
}

pub(super) async fn rotate_secret(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<ApplicationJwtSecretRotationInput>,
) -> AppResult<Json<ApplicationJwtSecretRotationResponse>> {
    let (current, application) = managed_application(&state, &jar, &id).await?;
    if !(0..=86_400).contains(&payload.grace_seconds) {
        return Err(AppError::BadRequest(
            "JWT secret grace_seconds must be between 0 and 86400".to_string(),
        ));
    }
    let module = applications::enabled_protocol_config(&state, &id, "jwt")
        .await?
        .ok_or_else(|| AppError::BadRequest("JWT protocol is not enabled".to_string()))?;
    let client_id = protocol_client_id(&application, &module);
    let client = state
        .db
        .find_application_jwt_client(&id, &client_id)
        .await?
        .ok_or_else(|| {
            AppError::BadRequest("configure the JWT client before rotating its secret".to_string())
        })?;
    if client.client_type != "confidential" || client.is_active != 1 {
        return Err(AppError::BadRequest(
            "JWT secret rotation requires an active confidential client".to_string(),
        ));
    }
    let secret = format!("jwt_{}", util::random_token(32));
    let secret_hash = client_assertion::store_client_secret("client_secret_post", &secret)?
        .ok_or_else(|| AppError::Internal("failed to hash JWT client secret".to_string()))?;
    let record = state
        .db
        .rotate_application_jwt_secret_with_audit(
            &id,
            &client_id,
            &secret_hash,
            payload.grace_seconds,
            audit::management_event(
                current.user.id,
                "application.jwt_client.secret.rotate",
                "application",
                Some(id.clone()),
                serde_json::json!({
                    "organization_id": application.organization_id,
                    "client_id": client_id.clone(),
                    "grace_seconds": payload.grace_seconds,
                }),
            ),
        )
        .await?;
    Ok(Json(ApplicationJwtSecretRotationResponse {
        client_id,
        secret,
        created_at: record.created_at,
        grace_seconds: payload.grace_seconds,
    }))
}

pub(super) async fn revoke_secrets(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let (current, application) = managed_application(&state, &jar, &id).await?;
    let module = applications::enabled_protocol_config(&state, &id, "jwt")
        .await?
        .ok_or_else(|| AppError::BadRequest("JWT protocol is not enabled".to_string()))?;
    let client_id = protocol_client_id(&application, &module);
    state
        .db
        .revoke_application_jwt_secrets(&id, &client_id)
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.jwt_client.secret.revoke",
            "application",
            Some(id.clone()),
            serde_json::json!({
                "organization_id": application.organization_id,
                "client_id": client_id,
            }),
        ))
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}
