use super::managed_application;
use crate::{
    AppState, application_discovery, applications,
    audit::{self, AuditSink},
    db::NewApplicationDiscovery,
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
pub(super) struct Response {
    application_id: String,
    management_mode: String,
    website_url: String,
    discovery_url: Option<String>,
    fetch_secret_configured: bool,
    signing_key_configured: bool,
    last_verified_revision: Option<i64>,
    last_verified_version: Option<String>,
    last_verified_digest: Option<String>,
    last_verified_expires_at: Option<i64>,
    sync_status: String,
    last_fetched_at: Option<i64>,
    last_success_at: Option<i64>,
    last_error: Option<String>,
    snapshot_available: bool,
    operator_disabled: bool,
    created_at: i64,
    updated_at: i64,
}

#[derive(Debug, Deserialize)]
pub(super) struct Input {
    #[serde(default)]
    management_mode: Option<String>,
    #[serde(default)]
    website_url: Option<String>,
    #[serde(default)]
    fetch_secret: Option<String>,
    #[serde(default)]
    signing_public_jwks: Option<String>,
    #[serde(default)]
    operator_disabled: Option<bool>,
}

pub(super) fn response(record: crate::db::ApplicationDiscoveryRecord) -> Response {
    let discovery_url = if record.website_url.trim().is_empty() {
        None
    } else {
        application_discovery::default_discovery_url(&record.website_url).ok()
    };
    Response {
        application_id: record.application_id,
        management_mode: record.management_mode,
        website_url: record.website_url,
        discovery_url,
        fetch_secret_configured: !record.fetch_secret_ciphertext.trim().is_empty(),
        signing_key_configured: !record.signing_public_jwks.trim().is_empty(),
        last_verified_revision: record.last_verified_revision,
        last_verified_version: record.last_verified_version,
        last_verified_digest: record.last_verified_digest,
        last_verified_expires_at: record.last_verified_expires_at,
        sync_status: record.sync_status,
        last_fetched_at: record.last_fetched_at,
        last_success_at: record.last_success_at,
        last_error: record.last_error,
        snapshot_available: record.snapshot_json.is_some(),
        operator_disabled: record.operator_disabled != 0,
        created_at: record.created_at,
        updated_at: record.updated_at,
    }
}

pub(super) async fn get(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<Response>> {
    let (_current, application) = managed_application(&state, &jar, &id).await?;
    let record = state
        .db
        .find_application_discovery(&application.id)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(response(record)))
}

pub(super) async fn update(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<Input>,
) -> AppResult<Json<Response>> {
    let (current, application) = managed_application(&state, &jar, &id).await?;
    let existing = state.db.find_application_discovery(&id).await?;
    let current_mode = existing
        .as_ref()
        .map(|record| record.management_mode.as_str())
        .unwrap_or(application_discovery::MANAGEMENT_MODE_SIGNET);
    let management_mode = payload
        .management_mode
        .as_deref()
        .unwrap_or(current_mode)
        .trim()
        .to_string();
    if !matches!(
        management_mode.as_str(),
        application_discovery::MANAGEMENT_MODE_SIGNET
            | application_discovery::MANAGEMENT_MODE_WEBSITE
    ) {
        return Err(AppError::BadRequest(
            "unsupported application discovery management mode".to_string(),
        ));
    }

    let current_website_url = existing
        .as_ref()
        .map(|record| record.website_url.clone())
        .filter(|value| !value.trim().is_empty())
        .or(applications::application_website_url(&state, &id).await?);
    let website_url = payload
        .website_url
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .or(current_website_url)
        .unwrap_or_default();
    let website_url = if website_url.is_empty() {
        if management_mode == application_discovery::MANAGEMENT_MODE_WEBSITE {
            return Err(AppError::BadRequest(
                "website-managed applications require website_url".to_string(),
            ));
        }
        String::new()
    } else {
        application_discovery::website_origin(&website_url)?
    };

    let fetch_secret_ciphertext = match payload.fetch_secret {
        None => existing
            .as_ref()
            .map(|record| record.fetch_secret_ciphertext.clone())
            .unwrap_or_default(),
        Some(secret) if secret.trim().is_empty() => String::new(),
        Some(secret) => {
            if state.settings.discovery.encryption_key.trim().is_empty() {
                return Err(AppError::Configuration(
                    "discovery encryption key is not configured".to_string(),
                ));
            }
            util::encrypt_discovery_secret(&state.settings.discovery.encryption_key, secret.trim())?
        }
    };
    let signing_public_jwks = match payload.signing_public_jwks {
        None => existing
            .as_ref()
            .map(|record| record.signing_public_jwks.clone())
            .unwrap_or_default(),
        Some(value) => {
            let value = value.trim().to_string();
            if value.len() > 128 * 1024 {
                return Err(AppError::BadRequest(
                    "signing public JWKS is too large".to_string(),
                ));
            }
            value
        }
    };
    let operator_disabled = payload
        .operator_disabled
        .or_else(|| {
            existing
                .as_ref()
                .map(|record| record.operator_disabled != 0)
        })
        .unwrap_or(false);
    let trust_changed = existing.as_ref().is_some_and(|record| {
        record.website_url != website_url
            || record.fetch_secret_ciphertext != fetch_secret_ciphertext
            || record.signing_public_jwks != signing_public_jwks
    });
    let has_trust = !signing_public_jwks.is_empty();
    let sync_status = if management_mode == application_discovery::MANAGEMENT_MODE_SIGNET {
        application_discovery::SYNC_DISABLED.to_string()
    } else if !has_trust {
        application_discovery::SYNC_UNCONFIGURED.to_string()
    } else if trust_changed
        || existing
            .as_ref()
            .and_then(|record| record.last_verified_revision)
            .is_none()
    {
        application_discovery::SYNC_PENDING.to_string()
    } else {
        existing
            .as_ref()
            .map(|record| record.sync_status.clone())
            .unwrap_or_else(|| application_discovery::SYNC_PENDING.to_string())
    };
    let reset_snapshot = trust_changed
        || management_mode != current_mode
        || existing
            .as_ref()
            .is_none_or(|record| record.management_mode != management_mode);
    let record = state
        .db
        .upsert_application_discovery(NewApplicationDiscovery {
            application_id: id.clone(),
            management_mode: management_mode.clone(),
            website_url,
            fetch_secret_ciphertext,
            signing_public_jwks,
            last_verified_revision: (!reset_snapshot)
                .then(|| {
                    existing
                        .as_ref()
                        .and_then(|record| record.last_verified_revision)
                })
                .flatten(),
            last_verified_version: (!reset_snapshot)
                .then(|| {
                    existing
                        .as_ref()
                        .and_then(|record| record.last_verified_version.clone())
                })
                .flatten(),
            last_verified_digest: (!reset_snapshot)
                .then(|| {
                    existing
                        .as_ref()
                        .and_then(|record| record.last_verified_digest.clone())
                })
                .flatten(),
            last_verified_expires_at: (!reset_snapshot)
                .then(|| {
                    existing
                        .as_ref()
                        .and_then(|record| record.last_verified_expires_at)
                })
                .flatten(),
            sync_status,
            last_fetched_at: (!reset_snapshot)
                .then(|| existing.as_ref().and_then(|record| record.last_fetched_at))
                .flatten(),
            last_success_at: (!reset_snapshot)
                .then(|| existing.as_ref().and_then(|record| record.last_success_at))
                .flatten(),
            last_error: (!reset_snapshot)
                .then(|| {
                    existing
                        .as_ref()
                        .and_then(|record| record.last_error.clone())
                })
                .flatten(),
            snapshot_json: (!reset_snapshot)
                .then(|| {
                    existing
                        .as_ref()
                        .and_then(|record| record.snapshot_json.clone())
                })
                .flatten(),
            operator_disabled,
        })
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.discovery.update",
            "application_discovery",
            Some(id),
            serde_json::json!({
                "application_id": application.id,
                "management_mode": management_mode,
                "trust_changed": trust_changed,
            }),
        ))
        .await?;
    Ok(Json(response(record)))
}

pub(super) async fn sync(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<Response>> {
    let (current, application) = managed_application(&state, &jar, &id).await?;
    let record = application_discovery::sync_application(&state, &id).await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.discovery.sync",
            "application_discovery",
            Some(id),
            serde_json::json!({
                "application_id": application.id,
                "revision": record.last_verified_revision,
            }),
        ))
        .await?;
    Ok(Json(response(record)))
}
