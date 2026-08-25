//! Cross-cutting mutation protocol for authenticated management writes.
//!
//! The protocol is deliberately transport-level: individual handlers do not
//! need to duplicate idempotency-key parsing, request hashing, replay headers,
//! or unknown-outcome handling.  The database receipt is scoped to the
//! browser session hash, so a receipt can never be replayed by another session.

use crate::{AppState, db::MutationReceiptRecord, util};
use axum::{
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{
        HeaderMap, HeaderName, HeaderValue, Method, StatusCode,
        header::{CONTENT_TYPE, COOKIE},
    },
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use serde_json::Value;

pub const MUTATION_ID_HEADER: &str = "x-mutation-id";
pub const MUTATION_STATUS_HEADER: &str = "x-mutation-status";
pub const MUTATION_REPLAYED_HEADER: &str = "x-mutation-replayed";
pub const MAX_IDEMPOTENCY_KEY_CHARS: usize = 200;
const MAX_REQUEST_BYTES: usize = 8 * 1024 * 1024;
const MAX_STORED_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

const STATUS_IN_PROGRESS: &str = "in_progress";
const STATUS_COMMITTED: &str = "committed";
const STATUS_FAILED: &str = "failed";
const STATUS_UNKNOWN: &str = "unknown";

#[derive(Debug, Serialize)]
pub struct PublicMutationReceipt {
    pub id: String,
    pub status: String,
    pub response_status: Option<i32>,
    pub error_code: Option<String>,
    pub replayable: bool,
    pub created_at: i64,
    pub completed_at: Option<i64>,
}

impl From<MutationReceiptRecord> for PublicMutationReceipt {
    fn from(record: MutationReceiptRecord) -> Self {
        Self {
            id: record.id,
            status: record.status,
            response_status: record.response_status,
            error_code: record.error_code,
            replayable: record.response_body.is_some(),
            created_at: record.created_at,
            completed_at: record.completed_at,
        }
    }
}

#[derive(Debug, Serialize)]
struct MutationProtocolError {
    error: &'static str,
    message: &'static str,
    mutation_id: String,
}

/// Runs after browser CSRF protection and before management handlers.
///
/// Missing keys remain accepted during the migration window so old API
/// clients keep working.  New frontend writes always provide a key through
/// the shared transport.  Once all external clients have migrated, the
/// compatibility branch can be made mandatory without changing handlers.
pub async fn protocol(State(state): State<AppState>, request: Request, next: Next) -> Response {
    if !is_management_mutation(request.method(), request.uri().path()) {
        return next.run(request).await;
    }

    let idempotency_header = HeaderName::from_static("idempotency-key");
    let Some(idempotency_key) = request
        .headers()
        .get(&idempotency_header)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
    else {
        return next.run(request).await;
    };
    if idempotency_key.chars().count() > MAX_IDEMPOTENCY_KEY_CHARS
        || idempotency_key.chars().any(char::is_control)
    {
        return protocol_error(
            StatusCode::BAD_REQUEST,
            "invalid_idempotency_key",
            "idempotency key is invalid",
            String::new(),
        );
    }

    let (parts, body) = request.into_parts();
    let body = match to_bytes(body, MAX_REQUEST_BYTES).await {
        Ok(body) => body,
        Err(_) => {
            return protocol_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "mutation_payload_too_large",
                "mutation payload is too large",
                String::new(),
            );
        }
    };
    let uri = parts.uri.to_string();
    let method = parts.method.to_string();
    let scope_key = scope_key(&parts.headers, &state.settings.security.cookie_name);
    let request_hash = request_hash(&method, &uri, &body);
    let dedupe_hash =
        util::sha256_base64url(&format!("{scope_key}\n{method}\n{uri}\n{idempotency_key}"));
    let owner_token = util::random_token(32);

    let receipt = match state
        .db
        .claim_mutation_receipt_with_owner(
            &dedupe_hash,
            &scope_key,
            &method,
            &uri,
            &idempotency_key,
            &request_hash,
            &owner_token,
        )
        .await
    {
        Ok(receipt) => receipt,
        Err(error) => return error.into_response(),
    };

    if receipt.request_hash != request_hash {
        return protocol_error(
            StatusCode::CONFLICT,
            "idempotency_key_reused",
            "idempotency key was already used with a different request",
            receipt.id,
        );
    }
    // A retry that merely observed another live owner must not execute the
    // handler.  Reclaimed receipts carry the retry's fresh fencing token, so
    // only that request is allowed to continue.
    if receipt.status != STATUS_IN_PROGRESS
        || receipt.owner_token.as_deref() != Some(owner_token.as_str())
    {
        return replay_or_status(receipt);
    }

    let mutation_id = receipt.id.clone();
    let request = Request::from_parts(parts, Body::from(body));
    let response = next.run(request).await;
    let (mut response_parts, response_body) = response.into_parts();
    let response_body = match to_bytes(response_body, MAX_REQUEST_BYTES).await {
        Ok(body) => body,
        Err(error) => {
            tracing::error!(mutation_id = %mutation_id, error = %error, "failed to buffer mutation response");
            let _ = state
                .db
                .finalize_mutation_receipt(
                    &mutation_id,
                    &owner_token,
                    STATUS_UNKNOWN,
                    StatusCode::INTERNAL_SERVER_ERROR.as_u16() as i32,
                    None,
                    None,
                    Some("response_buffer_failed"),
                )
                .await;
            return protocol_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "mutation_outcome_unknown",
                "mutation outcome could not be determined",
                mutation_id,
            );
        }
    };

    let status = response_parts.status;
    let outcome = if status.is_success() || status.is_redirection() {
        STATUS_COMMITTED
    } else if status.is_client_error() {
        STATUS_FAILED
    } else {
        STATUS_UNKNOWN
    };
    let response_text = String::from_utf8(response_body.to_vec()).ok();
    let replayable = is_replayable_mutation(&uri)
        && response_text
            .as_ref()
            .is_some_and(|body| body.len() <= MAX_STORED_RESPONSE_BYTES)
        && outcome != STATUS_UNKNOWN;
    let stored_body = replayable.then(|| response_text.clone()).flatten();
    let content_type = replayable
        .then(|| {
            response_parts
                .headers
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        })
        .flatten();
    let error_code = if status.is_client_error() {
        response_text
            .as_deref()
            .and_then(|body| serde_json::from_str::<Value>(body).ok())
            .and_then(|value| {
                value
                    .get("error")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
    } else if outcome == STATUS_UNKNOWN {
        Some("mutation_outcome_unknown".to_string())
    } else {
        None
    };

    let finalize_result = state
        .db
        .finalize_mutation_receipt(
            &mutation_id,
            &owner_token,
            outcome,
            status.as_u16() as i32,
            stored_body,
            content_type,
            error_code.as_deref(),
        )
        .await;
    match finalize_result {
        Ok(true) => {}
        Ok(false) => {
            tracing::warn!(mutation_id = %mutation_id, "mutation receipt owner was fenced before completion");
            return protocol_error(
                StatusCode::CONFLICT,
                "mutation_owner_fenced",
                "mutation ownership changed before the response was committed",
                mutation_id,
            );
        }
        Err(error) => {
            tracing::error!(mutation_id = %mutation_id, error = %error, "failed to finalize mutation receipt");
            response_parts.status = StatusCode::INTERNAL_SERVER_ERROR;
            return response_with_protocol_headers(
                response_parts,
                Body::from(response_body),
                &mutation_id,
                STATUS_UNKNOWN,
                false,
            );
        }
    }

    response_with_protocol_headers(
        response_parts,
        Body::from(response_body),
        &mutation_id,
        outcome,
        false,
    )
}

pub fn scope_key(headers: &HeaderMap, session_cookie_name: &str) -> String {
    let cookie = headers
        .get(COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|header| {
            header.split(';').find_map(|part| {
                let (name, value) = part.trim().split_once('=')?;
                (name.trim() == session_cookie_name).then_some(value.trim())
            })
        })
        .unwrap_or("anonymous");
    format!("session:{}", util::sha256_base64url(cookie))
}

pub fn is_management_mutation(method: &Method, path: &str) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    ) && path.starts_with("/api/admin/")
}

fn is_replayable_mutation(uri: &str) -> bool {
    let path = uri.split('?').next().unwrap_or(uri);
    !path.contains("/secret")
        && !path.contains("/tokens")
        && !path.ends_with("/reveal")
        && path != "/api/admin/authorization-codes"
        && !path.ends_with("/rotate")
}

fn request_hash(method: &str, uri: &str, body: &[u8]) -> String {
    let canonical_body = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|value| serde_json::to_string(&value).ok())
        .unwrap_or_else(|| String::from_utf8_lossy(body).into_owned());
    util::sha256_base64url(&format!("{method}\n{uri}\n{canonical_body}"))
}

fn replay_or_status(receipt: MutationReceiptRecord) -> Response {
    match receipt.status.as_str() {
        STATUS_COMMITTED | STATUS_FAILED => {
            let Some(body) = receipt.response_body else {
                return protocol_error(
                    StatusCode::CONFLICT,
                    "committed_secret_unrecoverable",
                    "mutation was committed but its response cannot be replayed",
                    receipt.id,
                );
            };
            let status = receipt
                .response_status
                .and_then(|value| StatusCode::from_u16(value as u16).ok())
                .unwrap_or(StatusCode::OK);
            let (mut parts, body) = (status, Body::from(body)).into_response().into_parts();
            if let Some(content_type) = receipt.response_content_type {
                if let Ok(value) = HeaderValue::from_str(&content_type) {
                    parts.headers.insert(CONTENT_TYPE, value);
                }
            }
            response_with_protocol_headers(parts, body, &receipt.id, &receipt.status, true)
        }
        STATUS_IN_PROGRESS => protocol_error(
            StatusCode::CONFLICT,
            "mutation_in_progress",
            "the same mutation is already in progress",
            receipt.id,
        ),
        STATUS_UNKNOWN => protocol_error(
            StatusCode::CONFLICT,
            "mutation_outcome_unknown",
            "mutation outcome is unknown; reconcile before retrying",
            receipt.id,
        ),
        _ => protocol_error(
            StatusCode::CONFLICT,
            "invalid_mutation_receipt",
            "mutation receipt has an invalid state",
            receipt.id,
        ),
    }
}

fn response_with_protocol_headers(
    mut parts: axum::http::response::Parts,
    body: Body,
    mutation_id: &str,
    status: &str,
    replayed: bool,
) -> Response {
    let mutation_id_name = HeaderName::from_static(MUTATION_ID_HEADER);
    let mutation_status_name = HeaderName::from_static(MUTATION_STATUS_HEADER);
    let replayed_name = HeaderName::from_static(MUTATION_REPLAYED_HEADER);
    if let Ok(value) = HeaderValue::from_str(mutation_id) {
        parts.headers.insert(mutation_id_name, value);
    }
    if let Ok(value) = HeaderValue::from_str(status) {
        parts.headers.insert(mutation_status_name, value);
    }
    parts.headers.insert(
        replayed_name,
        HeaderValue::from_static(if replayed { "true" } else { "false" }),
    );
    Response::from_parts(parts, body)
}

fn protocol_error(
    status: StatusCode,
    error: &'static str,
    message: &'static str,
    id: String,
) -> Response {
    let mut response = (
        status,
        axum::Json(MutationProtocolError {
            error,
            message,
            mutation_id: id.clone(),
        }),
    )
        .into_response();
    let id_value = HeaderValue::from_str(&id);
    if let Ok(value) = id_value {
        response
            .headers_mut()
            .insert(HeaderName::from_static(MUTATION_ID_HEADER), value);
    }
    response.headers_mut().insert(
        HeaderName::from_static(MUTATION_STATUS_HEADER),
        HeaderValue::from_static("protocol_error"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutation_scope_uses_only_the_configured_session_cookie() {
        let mut first = HeaderMap::new();
        first.insert(
            COOKIE,
            HeaderValue::from_static(
                "browser_context=one; gpt_sso_session=v2.same-session; other=first",
            ),
        );
        let mut second = HeaderMap::new();
        second.insert(
            COOKIE,
            HeaderValue::from_static(
                "other=second; gpt_sso_session=v2.same-session; browser_context=two",
            ),
        );
        assert_eq!(
            scope_key(&first, "gpt_sso_session"),
            scope_key(&second, "gpt_sso_session")
        );

        let mut different = HeaderMap::new();
        different.insert(
            COOKIE,
            HeaderValue::from_static("gpt_sso_session=v2.different"),
        );
        assert_ne!(
            scope_key(&first, "gpt_sso_session"),
            scope_key(&different, "gpt_sso_session")
        );
    }
}
