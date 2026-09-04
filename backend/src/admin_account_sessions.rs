use crate::{
    AppState,
    audit::{self, AuditSink},
    auth,
    db::{ClientGrantWithClientRecord, UserSessionSummary},
    error::{AppError, AppResult},
    util,
};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue},
};
use axum_extra::extract::cookie::CookieJar;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

const DEFAULT_SESSION_PAGE_SIZE: usize = 100;
const MAX_SESSION_PAGE_SIZE: usize = 100;

#[derive(Debug, Default, Deserialize)]
pub(crate) struct SessionListQuery {
    limit: Option<String>,
    cursor: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct SessionCursor {
    created_at: i64,
    id: String,
}

fn session_page_size(value: Option<&str>) -> AppResult<usize> {
    let Some(value) = value else {
        return Ok(DEFAULT_SESSION_PAGE_SIZE);
    };
    let value = value.trim();
    let parsed = value
        .parse::<usize>()
        .map_err(|_| AppError::BadRequest("session limit is invalid".to_string()))?;
    if parsed == 0 {
        return Err(AppError::BadRequest(
            "session limit must be positive".to_string(),
        ));
    }
    Ok(parsed.min(MAX_SESSION_PAGE_SIZE))
}

fn decode_session_cursor(value: Option<&str>) -> AppResult<Option<SessionCursor>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() || value.len() > 2048 {
        return Err(AppError::BadRequest(
            "session cursor is invalid".to_string(),
        ));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| AppError::BadRequest("session cursor is invalid".to_string()))?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| AppError::BadRequest("session cursor is invalid".to_string()))
}

fn encode_session_cursor(cursor: &SessionCursor) -> AppResult<String> {
    let bytes = serde_json::to_vec(cursor)
        .map_err(|error| AppError::Internal(format!("failed to encode session cursor: {error}")))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

#[derive(Debug, Serialize)]
pub(crate) struct MySessionResponse {
    id: String,
    current: bool,
    ip_address: Option<String>,
    user_agent: Option<String>,
    login_method: Option<String>,
    expires_at: i64,
    created_at: i64,
}

impl MySessionResponse {
    fn from_summary(record: UserSessionSummary, current_session_id: &str) -> Self {
        Self {
            current: record.id == current_session_id,
            id: util::session_public_id(&record.id),
            ip_address: record.ip_address,
            user_agent: record.user_agent,
            login_method: record.login_method,
            expires_at: record.expires_at,
            created_at: record.created_at,
        }
    }
}

pub(crate) async fn list_my_sessions(
    State(state): State<AppState>,
    jar: CookieJar,
    axum::extract::Query(query): axum::extract::Query<SessionListQuery>,
) -> AppResult<(HeaderMap, Json<Vec<MySessionResponse>>)> {
    let current = auth::require_current_user(&state, &jar).await?;
    let limit = session_page_size(query.limit.as_deref())?;
    let cursor = decode_session_cursor(query.cursor.as_deref())?;
    let records = state
        .db
        .list_user_session_summaries_page(
            &current.user.id,
            limit,
            cursor
                .as_ref()
                .map(|cursor| (cursor.created_at, cursor.id.clone())),
        )
        .await?;
    let has_more = records.len() > limit;
    let mut records = records;
    if has_more {
        records.truncate(limit);
    }
    let next_cursor = if has_more {
        records.last().map(|record| SessionCursor {
            created_at: record.created_at,
            id: record.id.clone(),
        })
    } else {
        None
    };
    let sessions = records
        .into_iter()
        .map(|record| MySessionResponse::from_summary(record, &current.session_id))
        .collect();
    let mut headers = HeaderMap::new();
    if let Some(next_cursor) = next_cursor {
        headers.insert(
            "x-next-cursor",
            HeaderValue::from_str(&encode_session_cursor(&next_cursor)?).map_err(|error| {
                AppError::Internal(format!("failed to build session cursor header: {error}"))
            })?,
        );
    }
    Ok((headers, Json(sessions)))
}

pub(crate) async fn revoke_my_session(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(session_handle): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let current = auth::require_current_user(&state, &jar).await?;
    auth::ensure_current_account_mutable(&current)?;
    let target = state
        .db
        .list_user_session_summaries(&current.user.id)
        .await?
        .into_iter()
        .find(|record| util::session_public_id(&record.id) == session_handle)
        .ok_or(AppError::NotFound)?;
    if target.id == current.session_id {
        return Err(AppError::BadRequest(
            "current session must be ended with logout".to_string(),
        ));
    }
    let revoked = state
        .db
        .delete_verified_user_session(&current.user.id, &target.id)
        .await?;
    if !revoked {
        return Err(AppError::NotFound);
    }
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "session.revoke",
            "session",
            Some(session_handle),
            serde_json::json!({}),
        ))
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

#[derive(Debug, Serialize)]
pub(crate) struct MyConsentResponse {
    client_id: String,
    client_name: Option<String>,
    granted_scopes: Vec<String>,
    granted_at: i64,
    updated_at: i64,
}

impl From<ClientGrantWithClientRecord> for MyConsentResponse {
    fn from(record: ClientGrantWithClientRecord) -> Self {
        Self {
            client_id: record.client_id,
            client_name: record.client_name,
            granted_scopes: record
                .granted_scopes
                .split_whitespace()
                .filter(|scope| !scope.is_empty())
                .map(ToOwned::to_owned)
                .collect(),
            granted_at: record.granted_at,
            updated_at: record.updated_at,
        }
    }
}

pub(crate) async fn list_my_consents(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<Vec<MyConsentResponse>>> {
    let current = auth::require_current_user(&state, &jar).await?;
    let consents = state
        .db
        .list_active_client_grants(&current.user.id)
        .await?
        .into_iter()
        .map(MyConsentResponse::from)
        .collect();
    Ok(Json(consents))
}

pub(crate) async fn get_my_consent(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(client_id): Path<String>,
) -> AppResult<Json<MyConsentResponse>> {
    let current = auth::require_current_user(&state, &jar).await?;
    let consent = state
        .db
        .list_active_client_grants(&current.user.id)
        .await?
        .into_iter()
        .find(|record| record.client_id == client_id)
        .ok_or(AppError::NotFound)?;
    Ok(Json(MyConsentResponse::from(consent)))
}

pub(crate) async fn revoke_my_consent(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(client_id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let current = auth::require_current_user(&state, &jar).await?;
    auth::ensure_current_account_mutable(&current)?;
    let revoked = state
        .db
        .revoke_client_grant(&current.user.id, &client_id)
        .await?;
    if !revoked {
        return Err(AppError::NotFound);
    }
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "consent.revoke",
            "client_consent",
            Some(client_id),
            serde_json::json!({}),
        ))
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}
