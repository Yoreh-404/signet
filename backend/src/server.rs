use crate::{
    AppState, Settings, admin, billing, browser_accounts, cas_sso, csrf, frontend, health, iap,
    jwt_sso, mutations, oidc, passkeys, registration, saml_sso, scim,
};
use anyhow::Context;
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::Request,
    http::{HeaderName, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use std::{net::SocketAddr, time::Duration};
use tokio::net::TcpListener;
use tower_http::{
    compression::CompressionLayer,
    cors::{AllowCredentials, CorsLayer},
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    set_header::SetResponseHeaderLayer,
    trace::TraceLayer,
};

pub fn router(state: AppState, settings: &Settings) -> anyhow::Result<Router> {
    let request_id = HeaderName::from_static("x-request-id");
    let app = Router::new()
        .merge(health::routes())
        .merge(admin::routes())
        .merge(billing::routes())
        .merge(browser_accounts::routes())
        .merge(oidc::routes())
        .merge(iap::routes())
        .merge(passkeys::routes())
        .merge(registration::routes())
        .merge(scim::routes())
        .merge(jwt_sso::routes())
        .merge(saml_sso::routes())
        .merge(cas_sso::routes())
        .fallback(frontend::serve)
        // CSRF must remain the outer layer so a duplicate idempotency key
        // cannot turn into a CSRF bypass.  The mutation protocol only sees a
        // request after browser-write protection has succeeded.
        .layer(middleware::from_fn_with_state(
            state.clone(),
            mutations::protocol,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            csrf::protect_browser_writes,
        ))
        .layer(middleware::from_fn(sensitive_response_headers))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("permissions-policy"),
            HeaderValue::from_static("camera=(), geolocation=(), microphone=()"),
        ))
        .layer(cors_layer(settings)?)
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http())
        .layer(PropagateRequestIdLayer::new(request_id.clone()))
        .layer(SetRequestIdLayer::new(request_id, MakeRequestUuid))
        .with_state(state);
    Ok(app)
}

pub async fn serve(state: AppState, settings: &Settings) -> anyhow::Result<()> {
    let app = router(state, settings)?;
    let addr = settings.socket_addr()?;
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind server on {addr}"))?;
    tracing::info!(%addr, "Signet backend listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("server failed")
}

fn cors_layer(settings: &Settings) -> anyhow::Result<CorsLayer> {
    let origins = settings
        .cors
        .allowed_origins
        .iter()
        .map(|origin| origin.parse::<HeaderValue>())
        .collect::<Result<Vec<_>, _>>()?;
    let methods = settings
        .cors
        .allowed_methods
        .iter()
        .map(|method| method.parse::<Method>())
        .collect::<Result<Vec<_>, _>>()?;
    let mut headers = settings
        .cors
        .allowed_headers
        .iter()
        .map(|value| value.parse::<HeaderName>())
        .collect::<Result<Vec<_>, _>>()?;
    let csrf_header = HeaderName::from_static(csrf::CSRF_HEADER);
    if !headers.contains(&csrf_header) {
        headers.push(csrf_header);
    }
    let layer = CorsLayer::new()
        .allow_origin(origins)
        .allow_methods(methods)
        .allow_headers(headers)
        .max_age(Duration::from_secs(3600));
    if settings.cors.allow_credentials {
        Ok(layer.allow_credentials(AllowCredentials::yes()))
    } else {
        Ok(layer)
    }
}

async fn sensitive_response_headers(request: Request, next: Next) -> Response {
    let path = request.uri().path().to_string();
    let method = request.method().clone();
    let if_none_match = request
        .headers()
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let sensitive = path.starts_with("/api/")
        || path.starts_with("/scim/")
        || path.starts_with("/connect/register")
        || (path.starts_with("/oauth2/") && path != "/oauth2/jwks")
        || path.starts_with("/cas/")
        || (path.starts_with("/saml/")
            && !path.ends_with("/metadata")
            && (path.ends_with("/sso") || path.ends_with("/sso/continue")));
    let conditional_admin_get = method == Method::GET && path.starts_with("/api/admin/");
    let mut response = next.run(request).await;
    if conditional_admin_get {
        response = conditional_admin_response(response, if_none_match.as_deref()).await;
    }
    if sensitive {
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
            .headers_mut()
            .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    }
    response
}

/// Adds a representation ETag to authenticated management reads. The browser
/// application keeps these values only in memory and revalidates them with
/// If-None-Match, so sensitive API data retains the global `no-store` policy
/// while page switches avoid transferring (or parsing) unchanged JSON.
async fn conditional_admin_response(response: Response, if_none_match: Option<&str>) -> Response {
    if !response.status().is_success()
        || !response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.contains("application/json"))
    {
        return response;
    }

    let (mut parts, body) = response.into_parts();
    let bytes = match to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::warn!(%error, "failed to buffer admin JSON response for ETag");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let body_text = match std::str::from_utf8(&bytes) {
        Ok(value) => value,
        Err(_) => return Response::from_parts(parts, Body::from(bytes)),
    };
    let etag = format!("\"{}\"", crate::util::sha256_base64url(body_text));
    let etag_header = HeaderValue::from_str(&etag).expect("SHA-256 ETag is a valid header value");
    parts.headers.insert(header::ETAG, etag_header);
    parts
        .headers
        .append(header::VARY, HeaderValue::from_static("Cookie"));

    if if_none_match_matches(if_none_match, &etag) {
        parts.status = StatusCode::NOT_MODIFIED;
        parts.headers.remove(header::CONTENT_LENGTH);
        parts.headers.remove(header::CONTENT_TYPE);
        return Response::from_parts(parts, Body::empty());
    }

    Response::from_parts(parts, Body::from(bytes))
}

fn if_none_match_matches(if_none_match: Option<&str>, etag: &str) -> bool {
    let Some(if_none_match) = if_none_match else {
        return false;
    };
    if_none_match
        .split(',')
        .map(str::trim)
        .any(|candidate| candidate == "*" || candidate == etag)
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::error!(error = %err, "failed to install Ctrl+C handler");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(err) => tracing::error!(error = %err, "failed to install SIGTERM handler"),
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

#[cfg(test)]
mod conditional_response_tests {
    use super::*;
    use axum::Json;

    #[tokio::test]
    async fn returns_not_modified_for_an_unchanged_json_representation() {
        let first = conditional_admin_response(
            Json(serde_json::json!({ "items": ["one"] })).into_response(),
            None,
        )
        .await;
        let etag = first
            .headers()
            .get(header::ETAG)
            .and_then(|value| value.to_str().ok())
            .expect("ETag is present")
            .to_string();

        let revalidated = conditional_admin_response(
            Json(serde_json::json!({ "items": ["one"] })).into_response(),
            Some(&etag),
        )
        .await;

        assert_eq!(revalidated.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(
            revalidated.headers().get(header::ETAG).unwrap(),
            etag.as_str()
        );
    }
}
