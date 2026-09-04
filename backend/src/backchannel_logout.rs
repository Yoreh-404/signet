use crate::{
    AppState,
    audit::{self, AuditOutcome, AuditSink},
    db::{ClientRecord, UserRecord},
    error::{AppError, AppResult},
    subject,
};
use axum::http::{HeaderMap, header};
use reqwest::StatusCode;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    sync::Arc,
    time::Duration,
};
use tokio::net::lookup_host;
use tokio::{
    task::JoinSet,
    time::{Instant, timeout},
};
use url::Url;

pub const LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";

const LOGOUT_TOKEN_TTL_SECONDS: i64 = 120;
const DELIVERY_TIMEOUT_SECONDS: u64 = 5;
const DELIVERY_CONCURRENCY_LIMIT: usize = 8;
const DELIVERY_DEADLINE_SECONDS: u64 = 5;

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
    resolve_public_addresses(&parsed)?;
    Ok(uri.to_string())
}

fn is_blocked_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address.is_loopback()
                || address.is_private()
                || address.is_link_local()
                || address.is_unspecified()
                || address.is_multicast()
                || address.is_broadcast()
                || address.octets()[0] == 0
                || (address.octets()[0] == 100 && (64..=127).contains(&address.octets()[1]))
                || (address.octets()[0] == 169 && address.octets()[1] == 254)
                || (address.octets()[0] == 192 && address.octets()[1] == 0)
                || (address.octets()[0] == 198 && address.octets()[1] == 18)
                || (address.octets()[0] == 198 && address.octets()[1] == 19)
        }
        IpAddr::V6(address) => {
            address
                .to_ipv4()
                .is_some_and(|address| is_blocked_address(address.into()))
                || address.is_loopback()
                || address.is_unspecified()
                || address.is_multicast()
                || (address.segments()[0] & 0xfe00) == 0xfc00
                || (address.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

fn resolve_public_addresses(url: &Url) -> AppResult<Vec<SocketAddr>> {
    let host = url.host_str().ok_or_else(|| {
        AppError::BadRequest("backchannel_logout_uri must have a host".to_string())
    })?;
    let port = url.port_or_known_default().ok_or_else(|| {
        AppError::BadRequest("backchannel_logout_uri must have a port".to_string())
    })?;
    let addresses = if let Ok(address) = host.parse::<IpAddr>() {
        vec![SocketAddr::new(address, port)]
    } else {
        (host, port)
            .to_socket_addrs()
            .map_err(|_| {
                AppError::BadRequest("backchannel_logout_uri host cannot be resolved".to_string())
            })?
            .collect()
    };
    if addresses.is_empty()
        || addresses
            .iter()
            .any(|address| is_blocked_address(address.ip()))
    {
        return Err(AppError::BadRequest(
            "backchannel_logout_uri must resolve only to public addresses".to_string(),
        ));
    }
    Ok(addresses)
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
    let deadline = Instant::now() + Duration::from_secs(DELIVERY_DEADLINE_SECONDS);
    let semaphore = Arc::new(tokio::sync::Semaphore::new(DELIVERY_CONCURRENCY_LIMIT));
    let mut active_clients = clients
        .iter()
        .map(|client| (client.client_id.clone(), client.clone()))
        .collect::<HashMap<_, _>>();
    let mut deliveries = JoinSet::new();

    for client in clients {
        let permit = semaphore.clone();
        let state = state.clone();
        let issuer = issuer.clone();
        let user = user.clone();
        let sid = sid.map(str::to_owned);
        deliveries.spawn(async move {
            let _permit = permit
                .acquire_owned()
                .await
                .expect("back-channel logout semaphore should not be closed");
            let result = delivery_result(&state, &issuer, &user, sid.as_deref(), &client).await;
            (client, result)
        });
    }

    while !deliveries.is_empty() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match timeout(remaining, deliveries.join_next()).await {
            Ok(Some(Ok((client, result)))) => {
                active_clients.remove(&client.client_id);
                audit_delivery_result(state, &client, user, sid, result).await;
            }
            Ok(Some(Err(err))) => {
                tracing::warn!(error = %err, "back-channel logout delivery task failed");
            }
            Ok(None) | Err(_) => break,
        }
    }

    if !deliveries.is_empty() {
        deliveries.abort_all();
        for client in active_clients.values() {
            audit_delivery_result(
                state,
                client,
                user,
                sid,
                Err(AppError::Internal(
                    "back-channel logout delivery exceeded global deadline".to_string(),
                )),
            )
            .await;
        }
    }
    Ok(())
}

async fn audit_delivery_result(
    state: &AppState,
    client: &ClientRecord,
    user: &UserRecord,
    sid: Option<&str>,
    result: AppResult<()>,
) {
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
    issuer: &str,
    user: &UserRecord,
    sid: Option<&str>,
    client: &ClientRecord,
) -> AppResult<()> {
    let uri = Url::parse(&client.backchannel_logout_uri)
        .map_err(|_| AppError::Internal("stored back-channel logout URI is invalid".to_string()))?;
    let addresses = lookup_host((
        uri.host_str().ok_or_else(|| {
            AppError::Internal("stored back-channel logout URI has no host".to_string())
        })?,
        uri.port_or_known_default().ok_or_else(|| {
            AppError::Internal("stored back-channel logout URI has no port".to_string())
        })?,
    ))
    .await
    .map_err(|_| AppError::Internal("back-channel logout URI host cannot be resolved".to_string()))?
    .collect::<Vec<_>>();
    if addresses.is_empty()
        || addresses
            .iter()
            .any(|address| is_blocked_address(address.ip()))
    {
        return Err(AppError::Internal(
            "back-channel logout URI resolved to a blocked address".to_string(),
        ));
    }
    let address = addresses[0];
    let host = uri.host_str().ok_or_else(|| {
        AppError::Internal("stored back-channel logout URI has no host".to_string())
    })?;
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(DELIVERY_TIMEOUT_SECONDS))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .resolve(host, address)
        .build()
        .map_err(|err| AppError::Internal(format!("failed to build HTTP client: {err}")))?;
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
            validate_backchannel_logout_uri("http://93.184.216.34/logout").unwrap(),
            "http://93.184.216.34/logout"
        );
        assert_eq!(
            validate_backchannel_logout_uri("https://93.184.216.34/logout").unwrap(),
            "https://93.184.216.34/logout"
        );
    }

    #[test]
    fn rejects_unsupported_or_fragmented_urls() {
        for uri in [
            "http://127.0.0.1/logout",
            "http://10.0.0.1/logout",
            "http://169.254.169.254/latest/meta-data",
            "http://100.100.100.200/latest/meta-data",
            "http://localhost/logout",
            "http://[fd00::1]/logout",
            "http://[::ffff:127.0.0.1]/logout",
        ] {
            assert!(validate_backchannel_logout_uri(uri).is_err(), "{uri}");
        }
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
