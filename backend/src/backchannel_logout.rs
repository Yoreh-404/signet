use crate::{
    AppState,
    audit::{self, AuditOutcome, AuditSink},
    db::{ClientRecord, UserRecord},
    error::{AppError, AppResult},
    subject,
};
use axum::http::{HeaderMap, header};
use reqwest::StatusCode;
use std::time::Duration;
use url::Url;

pub const LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";

const LOGOUT_TOKEN_TTL_SECONDS: i64 = 120;
const DELIVERY_TIMEOUT_SECONDS: u64 = 5;

pub fn validate_backchannel_logout_config(uri: &str, session_required: bool) -> AppResult<String> {
    let uri = validate_backchannel_logout_uri(uri)?;
    if session_required && uri.is_empty() {
        return Err(AppError::BadRequest(
            "backchannel_logout_uri is required when backchannel_logout_session_required is true"
                .to_string(),
        ));
    }
    Ok(uri)
}

pub fn validate_backchannel_logout_uri(uri: &str) -> AppResult<String> {
    let uri = uri.trim();
    if uri.is_empty() {
        return Ok(String::new());
    }
    let parsed = Url::parse(uri)
        .map_err(|_| AppError::BadRequest("backchannel_logout_uri must be absolute".to_string()))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err(AppError::BadRequest(
            "backchannel_logout_uri must use http or https".to_string(),
        ));
    }
    if parsed.fragment().is_some() {
        return Err(AppError::BadRequest(
            "backchannel_logout_uri cannot contain a fragment".to_string(),
        ));
    }
    Ok(uri.to_string())
}

pub async fn notify_user_logout(
    state: &AppState,
    headers: &HeaderMap,
    user: &UserRecord,
    sid: Option<&str>,
) -> AppResult<()> {
    let clients = state
        .db
        .list_backchannel_logout_clients_for_user(&user.id)
        .await?;
    if clients.is_empty() {
        return Ok(());
    }
    let issuer = state.effective_issuer(headers).await?;
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(DELIVERY_TIMEOUT_SECONDS))
        .build()
        .map_err(|err| AppError::Internal(format!("failed to build HTTP client: {err}")))?;
    for client in clients {
        deliver_logout_token(state, &http, &issuer, user, sid, &client).await;
    }
    Ok(())
}

async fn deliver_logout_token(
    state: &AppState,
    http: &reqwest::Client,
    issuer: &str,
    user: &UserRecord,
    sid: Option<&str>,
    client: &ClientRecord,
) {
    let result = delivery_result(state, http, issuer, user, sid, client).await;
    match result {
        Ok(()) => {
            audit_delivery(
                state,
                client,
                AuditOutcome::Success,
                serde_json::json!({
                    "user_id": user.id.as_str(),
                    "backchannel_logout_uri": client.backchannel_logout_uri.as_str(),
                    "sid": sid,
                }),
            )
            .await;
        }
        Err(err) => {
            tracing::warn!(
                client_id = %client.client_id,
                error = %err,
                "back-channel logout delivery failed"
            );
            audit_delivery(
                state,
                client,
                AuditOutcome::Failure,
                serde_json::json!({
                    "user_id": user.id.as_str(),
                    "backchannel_logout_uri": client.backchannel_logout_uri.as_str(),
                    "error": err.to_string(),
                    "sid": sid,
                }),
            )
            .await;
        }
    }
}

async fn delivery_result(
    state: &AppState,
    http: &reqwest::Client,
    issuer: &str,
    user: &UserRecord,
    sid: Option<&str>,
    client: &ClientRecord,
) -> AppResult<()> {
    let sid = match (client.backchannel_logout_session_required == 1, sid) {
        (true, None) => {
            return Err(AppError::Internal(
                "client requires sid but no active session id is available".to_string(),
            ));
        }
        (_, value) => value,
    };
    let subject = subject::subject_for_client(issuer, user, client)?;
    let logout_token = state.jwt.sign_logout_token(
        issuer,
        &client.client_id,
        &subject,
        sid,
        LOGOUT_TOKEN_TTL_SECONDS,
    )?;
    let body = serde_urlencoded::to_string([("logout_token", logout_token.as_str())])
        .map_err(|err| AppError::Internal(format!("failed to encode logout token body: {err}")))?;
    let response = http
        .post(client.backchannel_logout_uri.as_str())
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .map_err(delivery_error)?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(AppError::Internal(format!(
            "back-channel logout endpoint returned {}",
            response.status()
        )))
    }
}

fn delivery_error(err: reqwest::Error) -> AppError {
    let status = err.status().unwrap_or(StatusCode::BAD_GATEWAY);
    AppError::Internal(format!("back-channel logout HTTP error ({status}): {err}"))
}

async fn audit_delivery(
    state: &AppState,
    client: &ClientRecord,
    outcome: AuditOutcome,
    details: serde_json::Value,
) {
    if let Err(err) = state
        .db
        .record_audit_event(audit::oauth_event(
            client.client_id.clone(),
            "client.backchannel_logout",
            outcome,
            details,
        ))
        .await
    {
        tracing::warn!(error = %err, "failed to record back-channel logout audit event");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_empty_and_http_urls() {
        assert_eq!(validate_backchannel_logout_uri("").unwrap(), "");
        assert_eq!(
            validate_backchannel_logout_uri("http://127.0.0.1/logout").unwrap(),
            "http://127.0.0.1/logout"
        );
        assert_eq!(
            validate_backchannel_logout_uri("https://app.example/logout").unwrap(),
            "https://app.example/logout"
        );
    }

    #[test]
    fn rejects_unsupported_or_fragmented_urls() {
        assert!(validate_backchannel_logout_uri("ftp://app.example/logout").is_err());
        assert!(validate_backchannel_logout_uri("https://app.example/logout#frag").is_err());
        assert!(validate_backchannel_logout_uri("/relative/logout").is_err());
    }

    #[test]
    fn session_required_needs_uri() {
        assert!(validate_backchannel_logout_config("", false).is_ok());
        assert!(validate_backchannel_logout_config("", true).is_err());
    }
}
