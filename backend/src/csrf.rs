use crate::{AppState, auth, error::AppError, util};
use axum::{
    Json,
    extract::{Request, State},
    http::{HeaderMap, Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use axum_extra::extract::cookie::CookieJar;
use serde::Serialize;
use url::Url;

pub const CSRF_HEADER: &str = "x-csrf-token";

#[derive(Debug, Serialize)]
struct CsrfErrorBody {
    error: &'static str,
    message: &'static str,
}

pub async fn protect_browser_writes(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let method = request.method();
    let path = request.uri().path();
    if !is_unsafe_method(method) {
        return next.run(request).await;
    }

    if is_browser_account_write(method, path) {
        return protect_browser_account_write(&state, request, next).await;
    }

    if is_public_browser_write(path) {
        return match has_trusted_request_origin(&state, request.headers()).await {
            Ok(true) => next.run(request).await,
            Ok(false) if path == "/api/register" => match state.db.user_count().await {
                Ok(0) if origin_matches_request_host(request.headers()) => next.run(request).await,
                Ok(_) => csrf_failed("request origin is not trusted"),
                Err(error) => error.into_response(),
            },
            Ok(false) => csrf_failed("request origin is not trusted"),
            Err(error) => error.into_response(),
        };
    }
    if !is_session_protected_write(method, path) {
        return next.run(request).await;
    }

    let jar = CookieJar::from_headers(request.headers());
    let current = match auth::current_user_from_cookie(&state, &jar).await {
        Ok(Some(current)) => current,
        Ok(None) => return next.run(request).await,
        Err(error) => return error.into_response(),
    };
    let session = match state.db.find_session(&current.session_id).await {
        Ok(Some(session)) => session,
        Ok(None) => return next.run(request).await,
        Err(error) => return error.into_response(),
    };
    let supplied_token = request
        .headers()
        .get(CSRF_HEADER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if supplied_token.is_empty()
        || util::token_hash(supplied_token) != util::token_hash(&session.csrf_token)
    {
        return csrf_failed("CSRF token is missing or invalid");
    }
    match request_origin(request.headers()) {
        Some(origin) => match is_trusted_origin(&state, &origin).await {
            Ok(true) => next.run(request).await,
            Ok(false) => csrf_failed("request origin is not trusted"),
            Err(error) => error.into_response(),
        },
        None => next.run(request).await,
    }
}

async fn protect_browser_account_write(state: &AppState, request: Request, next: Next) -> Response {
    match has_trusted_request_origin(state, request.headers()).await {
        Ok(true) => {}
        Ok(false) => return csrf_failed("request origin is not trusted"),
        Err(error) => return error.into_response(),
    }
    let jar = CookieJar::from_headers(request.headers());
    let Some(context_id) = auth::browser_context_id_from_jar(state, &jar) else {
        return csrf_failed("browser account context is missing or invalid");
    };
    let context = match state.db.find_browser_context(&context_id).await {
        Ok(Some(context)) => context,
        Ok(None) => return csrf_failed("browser account context is missing or invalid"),
        Err(error) => return error.into_response(),
    };
    let supplied_token = request
        .headers()
        .get(CSRF_HEADER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if supplied_token.is_empty()
        || util::token_hash(supplied_token) != util::token_hash(&context.csrf_token)
    {
        return csrf_failed("CSRF token is missing or invalid");
    }
    next.run(request).await
}

pub async fn token_for_current_session(
    state: &AppState,
    jar: &CookieJar,
) -> Result<String, AppError> {
    let current = auth::require_current_user(state, jar).await?;
    state
        .db
        .find_session(&current.session_id)
        .await?
        .map(|session| session.csrf_token)
        .ok_or(AppError::Unauthorized)
}

pub async fn validate_form_token(
    state: &AppState,
    jar: &CookieJar,
    supplied_token: Option<&str>,
) -> Result<(), AppError> {
    let expected = token_for_current_session(state, jar).await?;
    let supplied = supplied_token.unwrap_or_default();
    if supplied.is_empty() || util::token_hash(supplied) != util::token_hash(&expected) {
        return Err(AppError::Forbidden);
    }
    Ok(())
}

fn is_unsafe_method(method: &Method) -> bool {
    method == Method::POST
        || method == Method::PUT
        || method == Method::PATCH
        || method == Method::DELETE
}

fn is_session_protected_write(method: &Method, path: &str) -> bool {
    path.starts_with("/api/admin/")
        || path == "/api/logout"
        || path.starts_with("/api/me/")
        || path.starts_with("/api/mfa/")
        || matches!(
            path,
            "/api/passkeys/registration/start" | "/api/passkeys/registration/finish"
        )
        || (*method == Method::DELETE && path.starts_with("/api/passkeys/"))
}

fn is_browser_account_write(method: &Method, path: &str) -> bool {
    (*method == Method::POST
        && matches!(
            path,
            "/api/browser-accounts/select"
                | "/api/browser-accounts/activate"
                | "/api/browser-accounts/add/start"
                | "/api/browser-accounts/logout-all"
        ))
        || (*method == Method::DELETE
            && path.starts_with("/api/browser-accounts/")
            && path != "/api/browser-accounts/csrf")
}

fn is_public_browser_write(path: &str) -> bool {
    matches!(
        path,
        "/api/login"
            | "/api/login/authorization-code"
            | "/api/public/authorization-code/inspect"
            | "/api/register"
            | "/api/register/verification/start"
            | "/api/password-reset/start"
            | "/api/password-reset/complete"
            | "/api/passkeys/authentication/start"
            | "/api/passkeys/authentication/finish"
            | "/login"
    ) || (path.starts_with("/saml/") && path.ends_with("/sso"))
}

async fn has_trusted_request_origin(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<bool, AppError> {
    if state.settings.security.disable_csrf_origin_check {
        return Ok(true);
    }
    let Some(origin) = request_origin(headers) else {
        return Ok(false);
    };
    is_trusted_origin(state, &origin).await
}

pub fn request_origin(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .or_else(|| {
            headers
                .get(header::REFERER)
                .and_then(|value| value.to_str().ok())
        })
        .map(str::to_string)
}

pub fn normalized_origin(headers: &HeaderMap) -> Option<String> {
    let origin = request_origin(headers)?;
    let parsed = Url::parse(origin.trim()).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return None;
    }
    Some(parsed.origin().ascii_serialization())
}

fn origin_matches_request_host(headers: &HeaderMap) -> bool {
    let Some(origin) = normalized_origin(headers) else {
        return false;
    };
    let Some(host) = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let Ok(origin_url) = Url::parse(&origin) else {
        return false;
    };
    let Ok(host_url) = Url::parse(&format!("http://{host}")) else {
        return false;
    };
    if origin_url.host_str().map(str::to_ascii_lowercase)
        != host_url.host_str().map(str::to_ascii_lowercase)
    {
        return false;
    }
    host_url.port().is_none() || origin_url.port() == host_url.port()
}

async fn is_trusted_origin(state: &AppState, candidate: &str) -> Result<bool, AppError> {
    if state.settings.security.disable_csrf_origin_check {
        return Ok(true);
    }
    let Some(candidate) = origin_tuple(candidate) else {
        return Ok(false);
    };
    let runtime = state.db.runtime_settings().await?;
    Ok(std::iter::once(runtime.public_base_url.as_str())
        .chain(std::iter::once(runtime.issuer.as_str()))
        .chain(
            state
                .settings
                .cors
                .allowed_origins
                .iter()
                .map(String::as_str),
        )
        .filter_map(origin_tuple)
        .any(|trusted| trusted == candidate))
}

fn origin_tuple(value: &str) -> Option<(String, String, u16)> {
    let parsed = Url::parse(value.trim()).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return None;
    }
    Some((
        parsed.scheme().to_ascii_lowercase(),
        parsed.host_str()?.to_ascii_lowercase(),
        parsed.port_or_known_default()?,
    ))
}

fn csrf_failed(message: &'static str) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(CsrfErrorBody {
            error: "csrf_failed",
            message,
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "sqlite")]
    use crate::{
        config::DatabaseKind,
        db::{NewUser, SessionMetadata},
    };
    #[cfg(feature = "sqlite")]
    use axum::{
        Router,
        body::{Body, to_bytes},
        extract::State,
        http::{Request, Response, header},
        middleware,
        routing::post,
    };
    #[cfg(feature = "sqlite")]
    use serde_json::Value;
    #[cfg(feature = "sqlite")]
    use std::path::PathBuf;
    #[cfg(feature = "sqlite")]
    use tower::ServiceExt;

    #[cfg(feature = "sqlite")]
    const TRUSTED_ORIGIN: &str = "https://sso.example.com";
    #[cfg(feature = "sqlite")]
    const UNTRUSTED_ORIGIN: &str = "https://sso.example.com.evil.invalid";

    #[test]
    fn origin_matching_is_exact_by_scheme_host_and_port() {
        assert_eq!(
            origin_tuple("https://SSO.example/path?q=1"),
            Some(("https".to_string(), "sso.example".to_string(), 443))
        );
        assert_ne!(
            origin_tuple("https://sso.example.evil"),
            origin_tuple("https://sso.example")
        );
        assert_ne!(
            origin_tuple("http://sso.example"),
            origin_tuple("https://sso.example")
        );
        assert_ne!(
            origin_tuple("https://sso.example:8443"),
            origin_tuple("https://sso.example")
        );
        assert!(origin_tuple("null").is_none());
    }

    #[test]
    fn normalized_origin_discards_referer_path_and_query() {
        let headers = HeaderMap::from_iter([(
            header::REFERER,
            "https://SSO.example.com:443/register?step=1"
                .parse()
                .unwrap(),
        )]);
        assert_eq!(
            normalized_origin(&headers).as_deref(),
            Some("https://sso.example.com")
        );
    }

    #[test]
    fn first_registration_origin_must_match_request_host() {
        let matching = HeaderMap::from_iter([
            (
                header::ORIGIN,
                "https://sso.example.com:8443".parse().unwrap(),
            ),
            (header::HOST, "sso.example.com:8443".parse().unwrap()),
        ]);
        assert!(origin_matches_request_host(&matching));

        let cross_site = HeaderMap::from_iter([
            (header::ORIGIN, "https://evil.example.com".parse().unwrap()),
            (header::HOST, "sso.example.com".parse().unwrap()),
        ]);
        assert!(!origin_matches_request_host(&cross_site));
    }

    #[test]
    fn csrf_routing_protects_browser_sessions_but_exempts_machine_protocols() {
        assert!(is_session_protected_write(
            &Method::POST,
            "/api/admin/users"
        ));
        assert!(is_session_protected_write(
            &Method::DELETE,
            "/api/me/sessions/id"
        ));
        assert!(is_public_browser_write("/api/login"));
        assert!(is_browser_account_write(
            &Method::POST,
            "/api/browser-accounts/select"
        ));
        assert!(is_browser_account_write(
            &Method::POST,
            "/api/browser-accounts/activate"
        ));
        assert!(is_browser_account_write(
            &Method::DELETE,
            "/api/browser-accounts/account-ref"
        ));
        assert!(!is_browser_account_write(
            &Method::GET,
            "/api/browser-accounts"
        ));
        for path in [
            "/oauth2/token",
            "/oauth2/par",
            "/oauth2/introspect",
            "/oauth2/revoke",
            "/connect/register",
            "/scim/v2/Users",
            "/api/iap/forward-auth",
        ] {
            assert!(!is_session_protected_write(&Method::POST, path));
            assert!(!is_public_browser_write(path));
        }
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn session_write_requires_matching_token_and_trusted_origin_before_database_mutation() {
        let (state, path, cookie_value, expected_csrf_token) = test_state().await;
        let cookie = session_cookie_header(&state, &cookie_value);
        let app = csrf_test_router(state.clone());
        assert_eq!(state.db.user_count().await.unwrap(), 1);

        let csrf_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/csrf")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(csrf_response.status(), StatusCode::OK);
        let csrf_body: Value = serde_json::from_slice(
            &to_bytes(csrf_response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let csrf_token = csrf_body["csrf_token"].as_str().unwrap();
        assert_eq!(csrf_token, expected_csrf_token);

        let missing_token = app
            .clone()
            .oneshot(protected_write_request(&cookie, None, TRUSTED_ORIGIN))
            .await
            .unwrap();
        assert_csrf_failed(missing_token).await;
        assert_eq!(state.db.user_count().await.unwrap(), 1);

        let wrong_token = app
            .clone()
            .oneshot(protected_write_request(
                &cookie,
                Some("wrong-token"),
                TRUSTED_ORIGIN,
            ))
            .await
            .unwrap();
        assert_csrf_failed(wrong_token).await;
        assert_eq!(state.db.user_count().await.unwrap(), 1);

        let untrusted_origin = app
            .clone()
            .oneshot(protected_write_request(
                &cookie,
                Some(csrf_token),
                UNTRUSTED_ORIGIN,
            ))
            .await
            .unwrap();
        assert_csrf_failed(untrusted_origin).await;
        assert_eq!(state.db.user_count().await.unwrap(), 1);

        let allowed = app
            .oneshot(protected_write_request(
                &cookie,
                Some(csrf_token),
                TRUSTED_ORIGIN,
            ))
            .await
            .unwrap();
        assert_eq!(allowed.status(), StatusCode::NO_CONTENT);
        assert_eq!(state.db.user_count().await.unwrap(), 2);

        drop(state);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn csrf_origin_check_can_be_disabled_for_local_testing() {
        let (mut state, path, cookie_value, csrf_token) = test_state().await;
        state.settings.security.disable_csrf_origin_check = true;
        assert!(
            has_trusted_request_origin(&state, &HeaderMap::new())
                .await
                .unwrap()
        );

        let app = csrf_test_router(state.clone());
        let response = app
            .oneshot(protected_write_request(
                &session_cookie_header(&state, &cookie_value),
                Some(&csrf_token),
                UNTRUSTED_ORIGIN,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        drop(state);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn browser_account_write_requires_context_token_and_always_requires_trusted_origin() {
        let (state, path, _cookie_value, _session_csrf) = test_state().await;
        let (context_id, context_cookie) = auth::create_browser_context(&state).await.unwrap();
        let context = state
            .db
            .find_browser_context(&context_id)
            .await
            .unwrap()
            .unwrap();
        let cookie = format!("{}={}", context_cookie.name(), context_cookie.value());
        let app = Router::new()
            .merge(crate::browser_accounts::routes())
            .layer(middleware::from_fn_with_state(
                state.clone(),
                protect_browser_writes,
            ))
            .with_state(state.clone());
        let request = |token: Option<&str>, origin: Option<&str>| {
            let mut builder = Request::builder()
                .method(Method::POST)
                .uri("/api/browser-accounts/add/start")
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/json");
            if let Some(token) = token {
                builder = builder.header(CSRF_HEADER, token);
            }
            if let Some(origin) = origin {
                builder = builder.header(header::ORIGIN, origin);
            }
            builder
                .body(Body::from(
                    r#"{"return_to":"/oauth2/authorize?interaction_request=test"}"#,
                ))
                .unwrap()
        };

        assert_csrf_failed(
            app.clone()
                .oneshot(request(Some(&context.csrf_token), None))
                .await
                .unwrap(),
        )
        .await;
        assert_csrf_failed(
            app.clone()
                .oneshot(request(Some("wrong-token"), Some(TRUSTED_ORIGIN)))
                .await
                .unwrap(),
        )
        .await;
        assert_csrf_failed(
            app.clone()
                .oneshot(request(Some(&context.csrf_token), Some(UNTRUSTED_ORIGIN)))
                .await
                .unwrap(),
        )
        .await;
        let accepted = app
            .clone()
            .oneshot(request(Some(&context.csrf_token), Some(TRUSTED_ORIGIN)))
            .await
            .unwrap();
        assert_eq!(accepted.status(), StatusCode::OK);

        drop(app);
        drop(state);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn machine_protocol_routes_are_not_intercepted_by_browser_csrf_layer() {
        let (state, path, cookie_value, _) = test_state().await;
        let cookie = session_cookie_header(&state, &cookie_value);
        let settings = state.settings.clone();
        let app = crate::server::router(state.clone(), &settings).unwrap();
        let initial_user_count = state.db.user_count().await.unwrap();

        for (route, content_type, body) in [
            (
                "/oauth2/token",
                "application/x-www-form-urlencoded",
                "grant_type=client_credentials&client_id=missing-client",
            ),
            (
                "/oauth2/par",
                "application/x-www-form-urlencoded",
                "client_id=missing-client",
            ),
            ("/scim/v2/Users", "application/scim+json", "{}"),
            ("/connect/register", "application/json", "{}"),
            (
                "/api/iap/forward-auth",
                "application/x-www-form-urlencoded",
                "",
            ),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::POST)
                        .uri(route)
                        .header(header::COOKIE, &cookie)
                        .header(header::ORIGIN, UNTRUSTED_ORIGIN)
                        .header(header::CONTENT_TYPE, content_type)
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_not_csrf_failure(route, response).await;
        }
        assert_eq!(state.db.user_count().await.unwrap(), initial_user_count);

        drop(app);
        drop(state);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    async fn test_state() -> (AppState, PathBuf, String, String) {
        let mut settings: crate::Settings =
            toml::from_str(include_str!("../../config/default.toml")).unwrap();
        let path = std::env::temp_dir().join(format!(
            "gpt-sso-csrf-test-{}.sqlite3",
            uuid::Uuid::new_v4()
        ));
        settings.database.kind = DatabaseKind::Sqlite;
        settings.database.url = path.to_string_lossy().into_owned();
        settings.database.run_migrations = true;
        settings.server.public_base_url = TRUSTED_ORIGIN.to_string();
        settings.oidc.issuer = TRUSTED_ORIGIN.to_string();
        settings.cors.allowed_origins = vec![TRUSTED_ORIGIN.to_string()];
        settings.bootstrap.admin.create_on_startup = false;
        settings.bootstrap.clients.clear();
        let db = crate::db::Db::connect(&settings).unwrap();
        db.migrate().await.unwrap();
        db.seed(&settings).await.unwrap();
        let jwt = crate::jwt::JwtManager::new(&settings).unwrap();
        let state = AppState { settings, db, jwt };
        let user = state
            .db
            .insert_user(NewUser {
                email: "csrf-session@example.com".to_string(),
                username: "csrf-session".to_string(),
                display_name: None,
                phone: None,
                password_hash: "test-hash".to_string(),
                email_verified_at: Some(util::now_ts()),
                phone_verified_at: None,
                is_admin: true,
                is_active: true,
                archived_at: None,
            })
            .await
            .unwrap();
        let (session, cookie_value) = state
            .db
            .insert_session(
                &user.id,
                state.settings.security.session_ttl_seconds,
                SessionMetadata::default(),
            )
            .await
            .unwrap();
        (state, path, cookie_value, session.csrf_token)
    }

    #[cfg(feature = "sqlite")]
    fn csrf_test_router(state: AppState) -> Router {
        Router::new()
            .merge(crate::admin::routes())
            .route("/api/admin/csrf-test-write", post(write_database_marker))
            .layer(middleware::from_fn_with_state(
                state.clone(),
                protect_browser_writes,
            ))
            .with_state(state)
    }

    #[cfg(feature = "sqlite")]
    async fn write_database_marker(State(state): State<AppState>) -> Result<StatusCode, AppError> {
        state
            .db
            .insert_user(NewUser {
                email: "csrf-marker@example.com".to_string(),
                username: "csrf-marker".to_string(),
                display_name: None,
                phone: None,
                password_hash: "test-hash".to_string(),
                email_verified_at: Some(util::now_ts()),
                phone_verified_at: None,
                is_admin: false,
                is_active: true,
                archived_at: None,
            })
            .await?;
        Ok(StatusCode::NO_CONTENT)
    }

    #[cfg(feature = "sqlite")]
    fn session_cookie_header(state: &AppState, value: &str) -> String {
        format!("{}={value}", state.settings.security.cookie_name)
    }

    #[cfg(feature = "sqlite")]
    fn protected_write_request(cookie: &str, token: Option<&str>, origin: &str) -> Request<Body> {
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri("/api/admin/csrf-test-write")
            .header(header::COOKIE, cookie)
            .header(header::ORIGIN, origin);
        if let Some(token) = token {
            builder = builder.header(CSRF_HEADER, token);
        }
        builder.body(Body::empty()).unwrap()
    }

    #[cfg(feature = "sqlite")]
    async fn assert_csrf_failed(response: Response<Body>) {
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(body["error"], "csrf_failed");
    }

    #[cfg(feature = "sqlite")]
    async fn assert_not_csrf_failure(route: &str, response: Response<Body>) {
        assert_ne!(response.status(), StatusCode::NOT_FOUND, "route {route}");
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body = String::from_utf8_lossy(&body);
        assert!(
            !body.contains("csrf_failed"),
            "machine route {route} was intercepted by CSRF middleware: {body}"
        );
    }
}
