//! Application-scoped browser JWT SSO.
//!
//! This is deliberately separate from the OAuth token profile.  A website
//! first performs a browser authorization round trip and receives a short
//! lived, one-time code; its backend then exchanges that code for a signed
//! JWT.  The JWT is never placed in a browser URL.

use crate::{
    AppState, applications, auth, authorization,
    db::{ApplicationRecord, NewApplicationJwtCode},
    error::{AppError, AppResult},
    http_urls::validate_safe_http_endpoint,
    pkce::is_valid_code_challenge,
    redirects, util,
};
use axum::{
    Form, Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, header},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use axum_extra::extract::cookie::CookieJar;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeSet;
use url::Url;

const AUTHORIZATION_CODE_TTL_SECONDS: i64 = 60;
const DEFAULT_TOKEN_TTL_SECONDS: i64 = 300;
const MAX_TOKEN_TTL_SECONDS: i64 = 3600;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/jwt/{app}/authorize", get(authorize))
        .route("/jwt/{app}/token", post(token))
        .route("/jwt/{app}/jwks", get(jwks))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthorizeQuery {
    client_id: Option<String>,
    redirect_uri: String,
    response_type: Option<String>,
    state: Option<String>,
    nonce: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TokenRequest {
    grant_type: String,
    code: String,
    redirect_uri: String,
    client_id: Option<String>,
    client_secret: Option<String>,
    code_verifier: Option<String>,
}

#[derive(Debug, Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: i64,
}

async fn authorize(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(app_slug): Path<String>,
    Query(query): Query<AuthorizeQuery>,
) -> AppResult<Response> {
    let (application, config) = load_application(&state, &app_slug).await?;
    let client_id = configured_client_id(&application, &config)?;
    ensure_jwt_client_is_active(&state, &application, &config, &client_id).await?;
    validate_client_id(query.client_id.as_deref(), &client_id)?;
    validate_response_type(query.response_type.as_deref())?;
    validate_state(query.state.as_deref())?;
    validate_nonce(query.nonce.as_deref())?;
    validate_pkce(
        query.code_challenge.as_deref(),
        query.code_challenge_method.as_deref(),
    )?;
    let redirect_uri =
        validate_redirect_uri(&state, &application, &config, &query.redirect_uri).await?;

    let return_to = format!(
        "/jwt/{}/authorize?{}",
        app_slug,
        serde_urlencoded::to_string(&query).map_err(|err| AppError::Internal(format!(
            "failed to encode JWT authorization request: {err}"
        )))?
    );
    let Some(current) = auth::current_user_from_cookie(&state, &jar).await? else {
        let login_url = redirects::frontend_login_url(&return_to, None, true);
        return Ok(Redirect::to(&login_url).into_response());
    };
    if !authorization::check_login_access(&state, &application, &current.user.id)
        .await?
        .allowed
    {
        return Err(AppError::Forbidden);
    }

    let raw_code = util::random_token(32);
    state
        .db
        .insert_application_jwt_code(NewApplicationJwtCode {
            code_hash: util::token_hash(&raw_code),
            application_id: application.id,
            client_id: client_id.clone(),
            redirect_uri: redirect_uri.clone(),
            user_id: current.user.id,
            nonce: query.nonce.clone(),
            code_challenge: query.code_challenge.clone(),
            code_challenge_method: query.code_challenge_method.clone(),
            expires_at: util::now_ts() + AUTHORIZATION_CODE_TTL_SECONDS,
        })
        .await?;

    let mut target = Url::parse(&redirect_uri)
        .map_err(|_| AppError::BadRequest("redirect_uri is invalid".to_string()))?;
    target.query_pairs_mut().append_pair("code", &raw_code);
    if let Some(state_value) = query.state.as_deref() {
        target.query_pairs_mut().append_pair("state", state_value);
    }
    Ok(Redirect::to(target.as_str()).into_response())
}

async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(app_slug): Path<String>,
    Form(request): Form<TokenRequest>,
) -> AppResult<Json<TokenResponse>> {
    let (application, config) = load_application(&state, &app_slug).await?;
    let client_id = configured_client_id(&application, &config)?;
    if request.grant_type.trim() != "authorization_code" {
        return Err(AppError::BadRequest(
            "grant_type must be authorization_code".to_string(),
        ));
    }
    let (basic_client_id, basic_secret) = basic_client_credentials(&headers)?;
    let requested_client_id = basic_client_id.as_deref().or(request.client_id.as_deref());
    validate_client_id(requested_client_id, &client_id)?;
    if let Some(basic_client_id) = basic_client_id.as_deref()
        && request
            .client_id
            .as_deref()
            .is_some_and(|value| value != basic_client_id)
    {
        return Err(AppError::Unauthorized);
    }
    let presented_secret = basic_secret.as_deref().or(request.client_secret.as_deref());
    authenticate_jwt_client(&state, &application, &config, &client_id, presented_secret).await?;
    let verifier = request
        .code_verifier
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("code_verifier is required".to_string()))?;
    if !is_valid_code_challenge(verifier) {
        return Err(AppError::BadRequest("code_verifier is invalid".to_string()));
    }
    let expected_challenge = util::sha256_base64url(verifier);
    let record = state
        .db
        .consume_application_jwt_code(
            &util::token_hash(request.code.trim()),
            &application.id,
            &client_id,
            &request.redirect_uri,
            &expected_challenge,
            "S256",
        )
        .await?;
    let user = state
        .db
        .find_user_by_id(&record.user_id)
        .await?
        .filter(|user| user.is_active == 1 && user.archived_at.is_none())
        .ok_or(AppError::Unauthorized)?;
    let entitlements = authorization::resolve_entitlements(&state, &application, &user).await?;
    let audience = config
        .get("audience")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(&client_id)
        .to_string();
    let ttl_seconds = config
        .get("token_ttl_seconds")
        .and_then(Value::as_i64)
        .unwrap_or(DEFAULT_TOKEN_TTL_SECONDS)
        .clamp(1, MAX_TOKEN_TTL_SECONDS);
    let mut claims = Map::new();
    claims.insert("sub".to_string(), Value::String(user.id.clone()));
    claims.insert(
        "token_use".to_string(),
        Value::String("application_jwt".to_string()),
    );
    claims.insert("client_id".to_string(), Value::String(client_id));
    claims.insert("scope".to_string(), Value::String("openid".to_string()));
    claims.insert("jti".to_string(), Value::String(util::random_token(24)));
    claims.insert("email".to_string(), Value::String(user.email.clone()));
    claims.insert(
        "email_verified".to_string(),
        Value::Bool(user.email_verified_at.is_some()),
    );
    claims.insert(
        "preferred_username".to_string(),
        Value::String(user.username.clone()),
    );
    claims.insert(
        "name".to_string(),
        user.display_name
            .clone()
            .map(Value::String)
            .unwrap_or(Value::String(user.username.clone())),
    );
    claims.extend(entitlements.claims);
    claims.insert(
        "policy_version".to_string(),
        Value::String(entitlements.policy_version),
    );
    if let Some(nonce) = record.nonce.as_deref() {
        claims.insert("nonce".to_string(), Value::String(nonce.to_string()));
    }
    let issuer = state
        .runtime_settings()
        .await?
        .issuer
        .trim_end_matches('/')
        .to_string();
    let jwt = state
        .jwt
        .sign_authorization_response(&issuer, &audience, ttl_seconds, claims)?;
    Ok(Json(TokenResponse {
        access_token: jwt,
        token_type: "Bearer",
        expires_in: ttl_seconds,
    }))
}

async fn jwks(
    State(state): State<AppState>,
    Path(app_slug): Path<String>,
) -> AppResult<Json<crate::jwt::Jwks>> {
    // Keep the public key endpoint behind the same application/protocol
    // boundary as authorization and token exchange.  The key material is
    // public, but an inactive or unconfigured website must not continue to
    // advertise a live JWT integration to relying parties.
    let _ = load_application(&state, &app_slug).await?;
    Ok(Json(state.jwt.jwks()))
}

async fn load_application(
    state: &AppState,
    slug: &str,
) -> AppResult<(ApplicationRecord, Map<String, Value>)> {
    applications::load_active_application_protocol_config(state, slug, "jwt").await
}

async fn ensure_jwt_client_is_active(
    state: &AppState,
    application: &ApplicationRecord,
    config: &Map<String, Value>,
    client_id: &str,
) -> AppResult<()> {
    if let Some(client) = state
        .db
        .find_application_jwt_client(&application.id, client_id)
        .await?
    {
        if client.is_active != 1 {
            return Err(AppError::Forbidden);
        }
        return Ok(());
    }
    if config
        .get("client_type")
        .and_then(Value::as_str)
        .is_some_and(|value| value == "confidential")
    {
        return Err(AppError::Configuration(
            "application JWT confidential client has not been provisioned".to_string(),
        ));
    }
    Ok(())
}

async fn authenticate_jwt_client(
    state: &AppState,
    application: &ApplicationRecord,
    config: &Map<String, Value>,
    client_id: &str,
    presented_secret: Option<&str>,
) -> AppResult<()> {
    let configured_type = config
        .get("client_type")
        .and_then(Value::as_str)
        .unwrap_or("public");
    let client = state
        .db
        .find_application_jwt_client(&application.id, client_id)
        .await?;
    let client_type = client
        .as_ref()
        .map(|client| client.client_type.as_str())
        .unwrap_or(configured_type);
    if client.as_ref().is_some_and(|client| client.is_active != 1) {
        return Err(AppError::Unauthorized);
    }
    match client_type {
        "public" => {
            if presented_secret.is_some_and(|secret| !secret.is_empty()) {
                return Err(AppError::Unauthorized);
            }
            Ok(())
        }
        "confidential" => {
            let secret = presented_secret.ok_or(AppError::Unauthorized)?;
            if secret.len() > 512
                || !state
                    .db
                    .verify_application_jwt_secret(&application.id, client_id, secret)
                    .await?
            {
                return Err(AppError::Unauthorized);
            }
            Ok(())
        }
        _ => Err(AppError::Configuration(
            "application JWT client_type is invalid".to_string(),
        )),
    }
}

fn basic_client_credentials(headers: &HeaderMap) -> AppResult<(Option<String>, Option<String>)> {
    let Some(value) = headers.get(header::AUTHORIZATION) else {
        return Ok((None, None));
    };
    let value = value.to_str().map_err(|_| AppError::Unauthorized)?;
    let (scheme, encoded) = value.split_once(' ').ok_or(AppError::Unauthorized)?;
    if !scheme.eq_ignore_ascii_case("Basic") || encoded.is_empty() {
        return Err(AppError::Unauthorized);
    }
    let decoded = STANDARD
        .decode(encoded)
        .map_err(|_| AppError::Unauthorized)?;
    let decoded = String::from_utf8(decoded).map_err(|_| AppError::Unauthorized)?;
    let (client_id, secret) = decoded.split_once(':').ok_or(AppError::Unauthorized)?;
    if client_id.trim().is_empty() || secret.is_empty() {
        return Err(AppError::Unauthorized);
    }
    Ok((Some(client_id.to_string()), Some(secret.to_string())))
}

fn configured_client_id(
    application: &ApplicationRecord,
    config: &Map<String, Value>,
) -> AppResult<String> {
    let configured = config
        .get("client_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(application.slug.as_str());
    if configured.len() > 128 || configured.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(AppError::Configuration(
            "application JWT client_id is invalid".to_string(),
        ));
    }
    Ok(configured.to_string())
}

fn validate_client_id(actual: Option<&str>, expected: &str) -> AppResult<()> {
    if actual
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some_and(|value| value != expected)
    {
        return Err(AppError::Unauthorized);
    }
    Ok(())
}

fn validate_response_type(value: Option<&str>) -> AppResult<()> {
    if value.unwrap_or("code") != "code" {
        return Err(AppError::BadRequest(
            "response_type must be code".to_string(),
        ));
    }
    Ok(())
}

fn validate_state(value: Option<&str>) -> AppResult<()> {
    if value.is_some_and(|value| {
        value.len() > 2048 || value.bytes().any(|byte| byte.is_ascii_control())
    }) {
        return Err(AppError::BadRequest("state is invalid".to_string()));
    }
    Ok(())
}

fn validate_nonce(value: Option<&str>) -> AppResult<()> {
    if value
        .is_some_and(|value| value.len() > 512 || value.bytes().any(|byte| byte.is_ascii_control()))
    {
        return Err(AppError::BadRequest("nonce is invalid".to_string()));
    }
    Ok(())
}

fn validate_pkce(challenge: Option<&str>, method: Option<&str>) -> AppResult<()> {
    let challenge = challenge.ok_or_else(|| {
        AppError::BadRequest("code_challenge is required for application JWT SSO".to_string())
    })?;
    if !is_valid_code_challenge(challenge) {
        return Err(AppError::BadRequest(
            "code_challenge is invalid".to_string(),
        ));
    }
    if method != Some("S256") {
        return Err(AppError::BadRequest(
            "code_challenge_method must be S256".to_string(),
        ));
    }
    Ok(())
}

async fn validate_redirect_uri(
    state: &AppState,
    application: &ApplicationRecord,
    config: &Map<String, Value>,
    requested: &str,
) -> AppResult<String> {
    validate_redirect_url(requested)?;
    let mut allowed = config
        .get("redirect_uris")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect::<BTreeSet<_>>();
    if allowed.is_empty()
        && let Some(website_url) =
            applications::application_website_url(state, &application.id).await?
    {
        allowed.insert(website_url);
    }
    if !allowed.contains(requested) {
        return Err(AppError::BadRequest(
            "redirect_uri is not registered for this application".to_string(),
        ));
    }
    Ok(requested.to_string())
}

fn validate_redirect_url(value: &str) -> AppResult<()> {
    validate_safe_http_endpoint(value, "redirect_uri")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{HeaderValue, Request, StatusCode, header},
        response::Response,
    };
    use tower::ServiceExt;

    #[test]
    fn basic_credentials_accept_case_insensitive_scheme_and_colons_in_secret() {
        let mut headers = HeaderMap::new();
        let encoded = STANDARD.encode("client:secret:with:colon");
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("basic {encoded}")).unwrap(),
        );
        assert_eq!(
            basic_client_credentials(&headers).unwrap(),
            (
                Some("client".to_string()),
                Some("secret:with:colon".to_string())
            )
        );
    }

    #[test]
    fn basic_credentials_reject_non_basic_and_malformed_values() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer token"),
        );
        assert!(basic_client_credentials(&headers).is_err());

        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic not-base64"),
        );
        assert!(basic_client_credentials(&headers).is_err());
    }

    #[test]
    fn pkce_and_redirect_validation_reject_ambiguous_values() {
        let challenge = "a".repeat(43);
        assert!(validate_pkce(Some(&challenge), Some("S256")).is_ok());
        assert!(validate_pkce(Some(&"!".repeat(43)), Some("S256")).is_err());
        assert!(validate_pkce(Some(&challenge), Some("plain")).is_err());
        assert!(validate_pkce(None, Some("S256")).is_err());

        assert!(validate_redirect_url("https://example.test/callback").is_ok());
        assert!(validate_redirect_url("http://localhost:8080/callback").is_ok());
        assert!(validate_redirect_url("http://example.test/callback").is_err());
        assert!(validate_redirect_url("https://user@example.test/callback").is_err());
        assert!(validate_redirect_url("https://example.test/callback#fragment").is_err());
    }

    #[cfg(feature = "sqlite")]
    async fn http_test_state() -> (AppState, std::path::PathBuf) {
        let mut settings: crate::Settings =
            toml::from_str(include_str!("../../config/default.toml")).unwrap();
        let path = std::env::temp_dir().join(format!(
            "gpt-sso-jwt-http-test-{}.sqlite3",
            uuid::Uuid::new_v4()
        ));
        settings.database.kind = crate::config::DatabaseKind::Sqlite;
        settings.database.url = path.to_string_lossy().into_owned();
        settings.bootstrap.admin.create_on_startup = false;
        settings.bootstrap.clients.clear();
        let db = crate::db::Db::connect(&settings).unwrap();
        db.migrate().await.unwrap();
        db.seed(&settings).await.unwrap();
        let jwt = crate::jwt::JwtManager::new(&settings).unwrap();
        (AppState { settings, db, jwt }, path)
    }

    #[cfg(feature = "sqlite")]
    async fn response_json(response: Response) -> Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[cfg(feature = "sqlite")]
    fn jwt_application(organization_id: &str) -> crate::db::NewApplication {
        crate::db::NewApplication {
            organization_id: organization_id.to_string(),
            slug: "jwt-http-app".to_string(),
            name: "JWT HTTP App".to_string(),
            description: None,
            access_mode: applications::ACCESS_ALL_SIGNET_USERS.to_string(),
            registration_mode: applications::REGISTRATION_DISABLED.to_string(),
            account_selection_mode: applications::ACCOUNT_SELECTION_OPTIONAL.to_string(),
            unique_identity_factors: Vec::new(),
            is_active: true,
        }
    }

    #[cfg(feature = "sqlite")]
    fn jwt_protocol_config() -> Value {
        serde_json::json!({
            "website_url": "https://portal.example.test",
            "jwt": {
                "enabled": true,
                "client_id": "jwt-portal-client",
                "client_type": "public",
                "audience": "https://portal.example.test",
                "redirect_uris": ["https://portal.example.test/callback"],
                "token_ttl_seconds": 300
            }
        })
    }

    #[cfg(feature = "sqlite")]
    async fn jwt_http_request(app: &Router, request: Request<Body>) -> Response {
        app.clone().oneshot(request).await.unwrap()
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn jwt_http_flow_is_application_bound_pkce_protected_and_single_use() {
        let (state, path) = http_test_state().await;
        let organization = state
            .db
            .insert_organization(crate::db::NewOrganization {
                slug: "jwt-http-org".to_string(),
                name: "JWT HTTP Org".to_string(),
                kind: crate::organizations::ORGANIZATION_KIND_TENANT.to_string(),
                description: None,
                allowed_email_domains: Vec::new(),
                is_active: true,
            })
            .await
            .unwrap();
        let application = state
            .db
            .insert_application(jwt_application(&organization.id))
            .await
            .unwrap();
        state
            .db
            .upsert_application_module(
                &application.id,
                "protocols",
                &jwt_protocol_config().to_string(),
                true,
            )
            .await
            .unwrap();
        let user = state
            .db
            .insert_user(crate::db::NewUser {
                email: "jwt-http@example.test".to_string(),
                username: "jwt-http".to_string(),
                display_name: Some("JWT HTTP".to_string()),
                phone: None,
                password_hash: "test-hash".to_string(),
                email_verified_at: Some(util::now_ts()),
                phone_verified_at: None,
                is_admin: false,
                is_active: true,
                archived_at: None,
            })
            .await
            .unwrap();
        let (_session, cookie_value) = state
            .db
            .insert_session(&user.id, 600, crate::db::SessionMetadata::default())
            .await
            .unwrap();
        let cookie = format!("{}={cookie_value}", state.settings.security.cookie_name);
        let verifier = "v".repeat(43);
        let challenge = util::sha256_base64url(&verifier);
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        query
            .append_pair("client_id", "jwt-portal-client")
            .append_pair("redirect_uri", "https://portal.example.test/callback")
            .append_pair("response_type", "code")
            .append_pair("state", "state-value")
            .append_pair("nonce", "nonce-value")
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
        let authorize_response = jwt_http_request(
            &routes().with_state(state.clone()),
            Request::builder()
                .uri(format!(
                    "/jwt/{}/authorize?{}",
                    application.slug,
                    query.finish()
                ))
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(authorize_response.status(), StatusCode::SEE_OTHER);
        let location = authorize_response
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        let callback = Url::parse(location).unwrap();
        assert_eq!(callback.path(), "/callback");
        assert_eq!(
            callback
                .query_pairs()
                .find(|(key, _)| key == "state")
                .map(|(_, value)| value.into_owned()),
            Some("state-value".to_string())
        );
        let code = callback
            .query_pairs()
            .find(|(key, _)| key == "code")
            .map(|(_, value)| value.into_owned())
            .unwrap();

        let form = serde_urlencoded::to_string([
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", "https://portal.example.test/callback"),
            ("client_id", "jwt-portal-client"),
            ("code_verifier", verifier.as_str()),
        ])
        .unwrap();
        let token_response = jwt_http_request(
            &routes().with_state(state.clone()),
            Request::builder()
                .method("POST")
                .uri(format!("/jwt/{}/token", application.slug))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form.clone()))
                .unwrap(),
        )
        .await;
        if token_response.status() != StatusCode::OK {
            let status = token_response.status();
            let body = axum::body::to_bytes(token_response.into_body(), usize::MAX)
                .await
                .unwrap();
            panic!(
                "JWT token exchange failed: {status}: {}",
                String::from_utf8_lossy(&body)
            );
        }
        let token_body = response_json(token_response).await;
        let access_token = token_body["access_token"].as_str().unwrap();
        assert_eq!(token_body["token_type"], "Bearer");
        assert_eq!(token_body["expires_in"], 300);
        let jwk = &state.jwt.jwks().keys[0];
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.validate_aud = false;
        let claims = jsonwebtoken::decode::<Value>(
            access_token,
            &jsonwebtoken::DecodingKey::from_rsa_components(&jwk.n, &jwk.e).unwrap(),
            &validation,
        )
        .unwrap()
        .claims;
        assert_eq!(claims["sub"], user.id);
        assert_eq!(claims["aud"], "https://portal.example.test");
        assert_eq!(claims["nonce"], "nonce-value");
        assert_eq!(claims["token_use"], "application_jwt");

        let reused = jwt_http_request(
            &routes().with_state(state.clone()),
            Request::builder()
                .method("POST")
                .uri(format!("/jwt/{}/token", application.slug))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await;
        assert_eq!(reused.status(), StatusCode::UNAUTHORIZED);

        let jwks_response = jwt_http_request(
            &routes().with_state(state.clone()),
            Request::builder()
                .uri(format!("/jwt/{}/jwks", application.slug))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(jwks_response.status(), StatusCode::OK);

        let missing_protocol = jwt_http_request(
            &routes().with_state(state.clone()),
            Request::builder()
                .uri("/jwt/missing-website/jwks")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(missing_protocol.status(), StatusCode::NOT_FOUND);

        drop(state);
        let _ = std::fs::remove_file(path);
    }
}
