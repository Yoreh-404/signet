use super::{admin_application_discovery, require_organization_manager_for};
use crate::{
    AppState, application_discovery,
    audit::{self, AuditSink},
    auth,
    error::{AppError, AppResult},
    util,
};
use axum::{Json, extract::State};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(super) struct Input {
    website_url: String,
    #[serde(default)]
    idempotency_key: Option<String>,
}

pub(super) async fn discover(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<Input>,
) -> AppResult<Json<admin_application_discovery::Response>> {
    let current = auth::require_current_user(&state, &jar).await?;
    let origin = application_discovery::website_origin(&payload.website_url)?;
    let entry = state
        .settings
        .discovery
        .auto_registration
        .allowlist
        .iter()
        .find(|entry| {
            entry
                .origin
                .trim()
                .trim_end_matches('/')
                .eq_ignore_ascii_case(&origin)
        })
        .ok_or(AppError::Forbidden)?;
    let idempotency_key = payload
        .idempotency_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if idempotency_key.is_some_and(|value| value.len() > 128 || value.chars().any(char::is_control))
    {
        return Err(AppError::BadRequest(
            "idempotency_key is invalid".to_string(),
        ));
    }
    require_organization_manager_for(&state, &current, &entry.organization_id).await?;
    let record = if let Some(idempotency_key) = idempotency_key {
        let request_hash = util::sha256_base64url(&format!(
            "signet:application-discovery:auto-register:v1:{origin}"
        ));
        match state
            .db
            .claim_application_discovery_idempotency(
                &entry.organization_id,
                idempotency_key,
                &request_hash,
                &origin,
            )
            .await?
        {
            crate::db::ApplicationDiscoveryIdempotencyClaim::Completed { application_id } => {
                let application = state
                    .db
                    .find_application_by_id(&application_id)
                    .await?
                    .ok_or(AppError::NotFound)?;
                if application.organization_id != entry.organization_id {
                    return Err(AppError::Forbidden);
                }
                state
                    .db
                    .find_application_discovery(&application_id)
                    .await?
                    .ok_or(AppError::NotFound)?
            }
            crate::db::ApplicationDiscoveryIdempotencyClaim::InProgress => {
                return Err(AppError::BadRequest(
                    "idempotency_key is already being processed".to_string(),
                ));
            }
            crate::db::ApplicationDiscoveryIdempotencyClaim::Claimed { claim_token } => {
                let result =
                    application_discovery::auto_register_application(&state, &origin).await;
                match result {
                    Ok(record) => {
                        state
                            .db
                            .complete_application_discovery_idempotency(
                                &entry.organization_id,
                                idempotency_key,
                                &claim_token,
                                &record.application_id,
                            )
                            .await?;
                        record
                    }
                    Err(error) => {
                        state
                            .db
                            .fail_application_discovery_idempotency(
                                &entry.organization_id,
                                idempotency_key,
                                &claim_token,
                            )
                            .await?;
                        return Err(error);
                    }
                }
            }
        }
    } else {
        application_discovery::auto_register_application(&state, &origin).await?
    };
    let sync_status = record.sync_status.clone();
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.discovery.auto_register",
            "application_discovery",
            Some(record.application_id.clone()),
            serde_json::json!({
                "origin": origin,
                "idempotency_key": idempotency_key,
                "sync_status": sync_status,
            }),
        ))
        .await?;
    Ok(Json(admin_application_discovery::response(record)))
}
