use crate::{
    AppState,
    audit::{self, AuditOutcome, AuditSink},
    auth,
    config::VerificationChannelSettings,
    db::{
        ExternalOidcProviderRecord, NewUser, PublicExternalOidcProvider, PublicLoginSettings,
        PublicRegistrationSettings, VerificationCodeClaim,
    },
    domain_discovery::EmailDomainRoutable,
    error::{AppError, AppResult},
    redirects,
    security_policy::{PasswordPolicy, PasswordSubject},
    util, verification,
};
use axum::{
    Json, Router,
    extract::{ConnectInfo, Path, Query, State},
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::SocketAddr};
use url::Url;

const REGISTRATION_VERIFICATION_PURPOSE: &str = "registration";
const PASSWORD_RESET_VERIFICATION_PURPOSE: &str = "password_reset";

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/public/bootstrap", get(bootstrap))
        .route("/api/register", post(register))
        .route("/api/register/verification/start", post(start_verification))
        .route("/api/password-reset/start", post(start_password_reset))
        .route(
            "/api/password-reset/complete",
            post(complete_password_reset),
        )
        .route("/api/register/oidc/{slug}/start", get(external_oidc_start))
        .route(
            "/api/register/oidc/{slug}/callback",
            get(external_oidc_callback),
        )
}

#[derive(Debug, Serialize)]
struct BootstrapResponse {
    has_users: bool,
    registration: PublicRegistrationSettings,
    login: PublicLoginSettings,
    default_locale: String,
    supported_locales: Vec<String>,
    external_oidc_providers: Vec<PublicProviderSummary>,
    ldap_providers: Vec<PublicDirectorySummary>,
}

#[derive(Debug, Serialize)]
struct PublicProviderSummary {
    slug: String,
    display_name: String,
    start_url: String,
    email_domains: Vec<String>,
    allow_login: bool,
    allow_registration: bool,
}

#[derive(Debug, Serialize)]
struct PublicDirectorySummary {
    slug: String,
    display_name: String,
}

async fn bootstrap(State(state): State<AppState>) -> AppResult<Json<BootstrapResponse>> {
    let has_users = state.db.user_count().await? > 0;
    let settings = state.db.registration_settings().await?.public();
    let mut login = state.db.login_settings().await?.public()?;
    login.quick_links.retain(|link| link.is_active);
    let mut providers = Vec::new();
    for provider in state.db.list_external_oidc_providers().await? {
        let allow_login = external_oidc_login_available(has_users, provider.allow_login == 1);
        let allow_registration = external_oidc_registration_available(
            has_users,
            settings.allow_external_oidc_registration,
            provider.allow_registration == 1,
        );
        if provider.is_active == 1 && (allow_login || allow_registration) {
            providers.push(PublicProviderSummary {
                slug: provider.slug.clone(),
                display_name: provider.display_name.clone(),
                start_url: format!("/api/register/oidc/{}/start", provider.slug),
                email_domains: provider.email_domain_rules()?,
                allow_login,
                allow_registration,
            });
        }
    }
    let ldap_providers = state
        .db
        .list_ldap_providers()
        .await?
        .into_iter()
        .filter(|provider| {
            let allow_login = external_oidc_login_available(has_users, provider.allow_login == 1);
            let allow_registration = external_oidc_registration_available(
                has_users,
                settings.allow_external_oidc_registration,
                provider.allow_registration == 1,
            );
            provider.is_active == 1 && (allow_login || allow_registration)
        })
        .map(|provider| PublicDirectorySummary {
            slug: provider.slug,
            display_name: provider.display_name,
        })
        .collect();
    Ok(Json(BootstrapResponse {
        has_users,
        registration: settings,
        login,
        default_locale: state.settings.i18n.default_locale.clone(),
        supported_locales: state.settings.i18n.supported_locales.clone(),
        external_oidc_providers: providers,
        ldap_providers,
    }))
}

#[derive(Debug, Deserialize)]
struct VerificationStartRequest {
    channel: String,
    target: String,
}

#[derive(Debug, Serialize)]
struct VerificationStartResponse {
    ok: bool,
    channel: String,
    target: String,
    expires_at: i64,
    dev_code: Option<String>,
}

async fn start_verification(
    State(state): State<AppState>,
    Json(payload): Json<VerificationStartRequest>,
) -> AppResult<Json<VerificationStartResponse>> {
    let (settings, normalized_target) =
        verification_channel(&state, &payload.channel, &payload.target)?;
    let response = issue_verification_code(
        &state,
        &payload.channel,
        &normalized_target,
        REGISTRATION_VERIFICATION_PURPOSE,
        settings,
        "registration verification code",
    )
    .await?;
    Ok(Json(response))
}

async fn issue_verification_code(
    state: &AppState,
    channel: &str,
    target: &str,
    purpose: &str,
    settings: &VerificationChannelSettings,
    log_message: &'static str,
) -> AppResult<VerificationStartResponse> {
    if !settings.enabled {
        return Err(AppError::BadRequest(format!(
            "{channel} verification is disabled"
        )));
    }
    let code = util::verification_code();
    let record = state
        .db
        .insert_verification_code(
            channel,
            target,
            purpose,
            util::token_hash(&code),
            settings.code_ttl_seconds,
            settings.resend_interval_seconds,
            settings.max_attempts,
        )
        .await?;
    let delivery = match verification::deliver_verification_code(
        settings,
        &verification::VerificationDeliveryContext {
            channel,
            target,
            purpose,
            code: &code,
            expires_at: record.expires_at,
            message: log_message,
        },
    )
    .await
    {
        Ok(delivery) => delivery,
        Err(err) => {
            if let Err(cleanup_err) = state
                .db
                .delete_unconsumed_verification_code(&record.id)
                .await
            {
                tracing::warn!(
                    error = %cleanup_err,
                    verification_code_id = %record.id,
                    "failed to clean up verification code after delivery failure"
                );
            }
            return Err(err);
        }
    };
    Ok(VerificationStartResponse {
        ok: true,
        channel: channel.to_string(),
        target: target.to_string(),
        expires_at: record.expires_at,
        dev_code: delivery.dev_code,
    })
}

#[derive(Debug, Deserialize)]
struct PasswordResetStartRequest {
    email: String,
}

async fn start_password_reset(
    State(state): State<AppState>,
    Json(payload): Json<PasswordResetStartRequest>,
) -> AppResult<Json<VerificationStartResponse>> {
    let email = normalize_email(&payload.email)?;
    let response = issue_verification_code(
        &state,
        "email",
        &email,
        PASSWORD_RESET_VERIFICATION_PURPOSE,
        &state.settings.verification.email,
        "password reset verification code",
    )
    .await?;
    Ok(Json(response))
}

#[derive(Debug, Deserialize)]
struct PasswordResetCompleteRequest {
    email: String,
    code: String,
    password: String,
}

async fn complete_password_reset(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<PasswordResetCompleteRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let email = normalize_email(&payload.email)?;
    state
        .db
        .consume_verification_code(
            "email",
            &email,
            PASSWORD_RESET_VERIFICATION_PURPOSE,
            payload.code.trim(),
        )
        .await?;
    let user = state
        .db
        .find_user_by_email(&email)
        .await?
        .ok_or_else(|| AppError::BadRequest("password reset request is invalid".to_string()))?;
    if user.is_active != 1 || user.archived_at.is_some() {
        return Err(AppError::BadRequest(
            "password reset is not available for this account".to_string(),
        ));
    }
    state.db.security_policy().await?.validate_password(
        &payload.password,
        PasswordSubject {
            email: &user.email,
            username: &user.username,
        },
    )?;
    state
        .db
        .set_user_password(&user.id, util::hash_password(&payload.password)?)
        .await?;
    state.db.clear_user_auth_state(&user.id).await?;
    state
        .db
        .record_audit_event(audit::AuditEvent {
            actor_user_id: Some(user.id.clone()),
            actor_client_id: None,
            action: "password.reset".to_string(),
            target_kind: "user".to_string(),
            target_id: Some(user.id),
            outcome: AuditOutcome::Success,
            ip_address: state.request_ip(&headers, Some(remote_addr)).await?,
            user_agent: util::user_agent(&headers),
            details: serde_json::json!({ "email": email }),
        })
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

#[derive(Debug, Deserialize)]
struct RegisterRequest {
    email: Option<String>,
    username: Option<String>,
    display_name: Option<String>,
    phone: Option<String>,
    password: Option<String>,
    email_code: Option<String>,
    phone_code: Option<String>,
    invitation_code: Option<String>,
    authorization_code: Option<String>,
}

#[derive(Debug, Serialize)]
struct RegisterResponse {
    user: crate::db::PublicUser,
    first_admin: bool,
}

async fn register(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<RegisterRequest>,
) -> AppResult<(CookieJar, Json<RegisterResponse>)> {
    let user_count = state.db.user_count().await?;
    let first_user = user_count == 0;
    let registration = state.db.registration_settings().await?.public();
    let request_ip = state.request_ip(&headers, Some(remote_addr)).await?;
    let authorization_code =
        first_nonempty_code(&payload.authorization_code, &payload.invitation_code);
    if !first_user {
        if let Some(code) = authorization_code.as_deref() {
            return register_with_authorization_code(
                state, jar, headers, request_ip, payload, code,
            )
            .await;
        }
        if registration.require_invitation {
            return Err(AppError::BadRequest(
                "authorization code is required".to_string(),
            ));
        }
    }
    if !first_user && !registration.allow_password_registration {
        return Err(AppError::Forbidden);
    }

    let email = required_register_email(&payload.email)?;
    auth::assert_registration_allowed(&state, Some(&email), request_ip.as_deref()).await?;
    let username = register_username_or_email_local(&payload.username, &email);
    let password = required_register_password(&payload.password)?;
    state.db.security_policy().await?.validate_password(
        password,
        PasswordSubject {
            email: &email,
            username: &username,
        },
    )?;
    let phone = normalize_optional(&payload.phone);
    let mut verification_claims = Vec::new();
    if registration.require_email_verification && !first_user {
        let code = payload.email_code.as_deref().ok_or_else(|| {
            AppError::BadRequest("email verification code is required".to_string())
        })?;
        verification_claims.push(VerificationCodeClaim::new(
            "email",
            &email,
            REGISTRATION_VERIFICATION_PURPOSE,
            code,
        ));
    }
    if registration.require_phone_verification && !first_user {
        let phone_value = phone
            .as_deref()
            .ok_or_else(|| AppError::BadRequest("phone is required".to_string()))?;
        let code = payload.phone_code.as_deref().ok_or_else(|| {
            AppError::BadRequest("phone verification code is required".to_string())
        })?;
        verification_claims.push(VerificationCodeClaim::new(
            "phone",
            phone_value,
            REGISTRATION_VERIFICATION_PURPOSE,
            code,
        ));
    }
    let now = util::now_ts();
    let user = state
        .db
        .insert_registered_user(
            NewUser {
                email: email.clone(),
                username,
                display_name: normalize_optional(&payload.display_name),
                phone: phone.clone(),
                password_hash: util::hash_password(password)?,
                email_verified_at: if registration.require_email_verification || first_user {
                    Some(now)
                } else {
                    None
                },
                phone_verified_at: if phone.is_some()
                    && (registration.require_phone_verification || first_user)
                {
                    Some(now)
                } else {
                    None
                },
                is_admin: crate::db::registered_user_is_admin(first_user),
                is_active: registration.default_user_active || first_user,
                archived_at: None,
            },
            first_user,
            verification_claims,
        )
        .await?;
    state
        .db
        .record_login_event(
            &user.id,
            request_ip.clone(),
            util::user_agent(&headers),
            "registration",
            None,
            None,
        )
        .await?;
    let session = state
        .db
        .insert_session(
            &user.id,
            state.settings.security.session_ttl_seconds,
            auth::session_metadata(request_ip, &headers, "registration"),
        )
        .await?;
    let cookie = auth::session_cookie(
        &state,
        session.id,
        state.settings.security.session_ttl_seconds,
    );
    Ok((
        jar.add(cookie),
        Json(RegisterResponse {
            user: user.public(),
            first_admin: crate::db::registered_user_is_admin(first_user),
        }),
    ))
}

async fn register_with_authorization_code(
    state: AppState,
    jar: CookieJar,
    headers: HeaderMap,
    request_ip: Option<String>,
    payload: RegisterRequest,
    code: &str,
) -> AppResult<(CookieJar, Json<RegisterResponse>)> {
    auth::assert_authorization_code_access_allowed(&state, request_ip.as_deref()).await?;
    let authorization = state.db.find_invitation_by_code(code).await?;
    let email = match authorization
        .authorized_email
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(value) => normalize_email(value)?,
        None => optional_register_email(&payload.email)?.unwrap_or_else(temporary_email),
    };
    if state.db.find_user_by_email(&email).await?.is_some() {
        return Err(AppError::BadRequest(
            "authorization code cannot be used for an existing account".to_string(),
        ));
    }

    let now = util::now_ts();
    let username_source = authorization
        .authorized_username
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            payload
                .username
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
        })
        .or_else(|| email.split('@').next())
        .unwrap_or("external")
        .to_string();
    let display_name = authorization
        .authorized_display_name
        .clone()
        .and_then(|value| normalize_optional(&Some(value)))
        .or_else(|| normalize_optional(&payload.display_name))
        .or_else(|| authorization.description.clone());
    let user = state
        .db
        .redeem_invitation_for_new_user(
            &authorization.id,
            NewUser {
                email,
                username: temporary_username(&username_source),
                display_name,
                phone: None,
                password_hash: util::hash_password(&util::random_token(32))?,
                email_verified_at: Some(now),
                phone_verified_at: None,
                is_admin: false,
                is_active: true,
                archived_at: Some(now),
            },
        )
        .await?;
    state
        .db
        .record_login_event(
            &user.id,
            request_ip.clone(),
            util::user_agent(&headers),
            "authorization_code",
            None,
            None,
        )
        .await?;
    let session = state
        .db
        .insert_session(
            &user.id,
            state.settings.security.session_ttl_seconds,
            auth::session_metadata(request_ip, &headers, "authorization_code"),
        )
        .await?;
    let cookie = auth::session_cookie(
        &state,
        session.id,
        state.settings.security.session_ttl_seconds,
    );
    Ok((
        jar.add(cookie),
        Json(RegisterResponse {
            user: user.public(),
            first_admin: false,
        }),
    ))
}

#[derive(Debug, Deserialize)]
struct OidcStartQuery {
    return_to: Option<String>,
    login_hint: Option<String>,
    mode: Option<String>,
}

async fn external_oidc_start(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(slug): Path<String>,
    Query(query): Query<OidcStartQuery>,
) -> AppResult<Response> {
    let provider = enabled_provider(&state, &slug).await?;
    let has_users = state.db.user_count().await? > 0;
    let registration = state.db.registration_settings().await?.public();
    let mode = ExternalOidcStartMode::parse(query.mode.as_deref())?;
    if !external_oidc_start_allowed(
        mode,
        has_users,
        registration.allow_external_oidc_registration,
        provider.allow_login == 1,
        provider.allow_registration == 1,
    ) {
        return Err(AppError::Forbidden);
    }
    let state_token = util::random_token(32);
    let nonce = util::random_token(24);
    state
        .db
        .insert_external_oidc_state(
            state_token.clone(),
            provider.slug.clone(),
            nonce.clone(),
            redirects::optional_local_return_to(query.return_to),
            600,
        )
        .await?;
    let mut url = Url::parse(&provider.authorization_endpoint)
        .map_err(|err| AppError::BadRequest(format!("invalid authorization endpoint: {err}")))?;
    let redirect_uri = external_redirect_uri(&state, &headers, &provider).await?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &provider.client_id)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("scope", &provider_scopes(&provider)?)
        .append_pair("state", &state_token)
        .append_pair("nonce", &nonce);
    if let Some(login_hint) = optional_login_hint(&query.login_hint)? {
        url.query_pairs_mut().append_pair("login_hint", &login_hint);
    }
    Ok(Redirect::to(url.as_str()).into_response())
}

#[derive(Debug, Deserialize)]
struct OidcCallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

async fn external_oidc_callback(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    Path(slug): Path<String>,
    Query(query): Query<OidcCallbackQuery>,
) -> AppResult<Response> {
    if let Some(error) = query.error {
        let message = query.error_description.unwrap_or(error);
        let return_to = external_oidc_error_return_to(&state, &slug, query.state.as_deref()).await;
        return Ok(Redirect::to(&redirects::frontend_auth_error_url(
            return_to.as_deref(),
            &message,
        ))
        .into_response());
    }
    let state_value = query
        .state
        .ok_or_else(|| AppError::BadRequest("OIDC state is required".to_string()))?;
    let code = query
        .code
        .ok_or_else(|| AppError::BadRequest("OIDC code is required".to_string()))?;
    let oidc_state = state.db.consume_external_oidc_state(&state_value).await?;
    if oidc_state.provider_slug != slug {
        return Err(AppError::BadRequest("OIDC provider mismatch".to_string()));
    }
    let provider = enabled_provider(&state, &slug).await?;
    let external_redirect = external_redirect_uri(&state, &headers, &provider).await?;
    let claims = fetch_external_userinfo(&provider, &code, &external_redirect).await?;
    let sub = claims
        .get("sub")
        .and_then(|value| value.as_str())
        .ok_or_else(|| AppError::BadRequest("external OIDC userinfo missing sub".to_string()))?
        .to_string();
    let request_ip = state.request_ip(&headers, Some(remote_addr)).await?;
    let existing_identity = state.db.find_linked_identity(&slug, &sub).await?;
    let registration = state.db.registration_settings().await?.public();
    let first_user = state.db.user_count().await? == 0;
    let user = if let Some(identity) = existing_identity {
        if provider.allow_login != 1 {
            return Err(AppError::Forbidden);
        }
        let user = state
            .db
            .find_user_by_id(&identity.user_id)
            .await?
            .ok_or(AppError::Unauthorized)?;
        if user.is_active != 1 || user.archived_at.is_some() {
            return Err(AppError::Unauthorized);
        }
        auth::assert_login_allowed(&state, &user.email, request_ip.as_deref()).await?;
        user
    } else {
        if !external_oidc_can_create_user(
            first_user,
            registration.allow_external_oidc_registration,
            provider.allow_registration == 1,
        ) {
            return Err(AppError::Forbidden);
        }
        let email = external_oidc_email(&claims, &provider.slug, &sub)?;
        auth::assert_registration_allowed(&state, Some(&email), request_ip.as_deref()).await?;
        let username = claims
            .get("preferred_username")
            .and_then(|value| value.as_str())
            .or_else(|| email.split('@').next())
            .unwrap_or("external-user")
            .chars()
            .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '-' || *ch == '_')
            .collect::<String>();
        let display_name = claims
            .get("name")
            .and_then(|value| value.as_str())
            .map(ToOwned::to_owned);
        state
            .db
            .insert_external_oidc_user(
                NewUser {
                    email: email.clone(),
                    username: unique_username(&username, &sub),
                    display_name,
                    phone: None,
                    password_hash: util::hash_password(&util::random_token(32))?,
                    email_verified_at: Some(util::now_ts()),
                    phone_verified_at: None,
                    is_admin: crate::db::registered_user_is_admin(first_user),
                    is_active: registration.default_user_active || first_user,
                    archived_at: None,
                },
                &slug,
                &sub,
                Some(email),
                provider.organization_id.clone(),
                first_user,
            )
            .await?
    };
    if user.is_active != 1 || user.archived_at.is_some() {
        return Err(AppError::Unauthorized);
    }
    state
        .db
        .record_login_event(
            &user.id,
            request_ip.clone(),
            util::user_agent(&headers),
            "external_oidc",
            None,
            Some(slug),
        )
        .await?;
    let session = state
        .db
        .insert_session(
            &user.id,
            state.settings.security.session_ttl_seconds,
            auth::session_metadata(request_ip, &headers, "external_oidc"),
        )
        .await?;
    let cookie = auth::session_cookie(
        &state,
        session.id,
        state.settings.security.session_ttl_seconds,
    );
    let return_to = redirects::local_return_to(oidc_state.return_to.as_deref());
    Ok((jar.add(cookie), Redirect::to(&return_to)).into_response())
}

async fn external_oidc_error_return_to(
    state: &AppState,
    slug: &str,
    state_value: Option<&str>,
) -> Option<String> {
    let Some(state_value) = state_value else {
        return None;
    };
    match state.db.consume_external_oidc_state(state_value).await {
        Ok(oidc_state) if oidc_state.provider_slug == slug => oidc_state.return_to,
        Ok(_) => None,
        Err(err) => {
            tracing::warn!(error = %err, "failed to consume external OIDC error state");
            None
        }
    }
}

async fn enabled_provider(state: &AppState, slug: &str) -> AppResult<ExternalOidcProviderRecord> {
    let provider = state
        .db
        .find_external_oidc_provider(slug)
        .await?
        .ok_or(AppError::NotFound)?;
    if provider.is_active == 1 {
        Ok(provider)
    } else {
        Err(AppError::NotFound)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExternalOidcStartMode {
    Auto,
    Login,
    Register,
}

impl ExternalOidcStartMode {
    fn parse(value: Option<&str>) -> AppResult<Self> {
        match value.map(str::trim).filter(|value| !value.is_empty()) {
            None => Ok(Self::Auto),
            Some("login") => Ok(Self::Login),
            Some("register") => Ok(Self::Register),
            Some(other) => Err(AppError::BadRequest(format!(
                "unsupported external OIDC start mode: {other}"
            ))),
        }
    }
}

fn external_oidc_login_available(has_users: bool, provider_allows_login: bool) -> bool {
    has_users && provider_allows_login
}

fn external_oidc_registration_available(
    has_users: bool,
    global_allows_registration: bool,
    provider_allows_registration: bool,
) -> bool {
    provider_allows_registration && (!has_users || global_allows_registration)
}

fn external_oidc_start_allowed(
    mode: ExternalOidcStartMode,
    has_users: bool,
    global_allows_registration: bool,
    provider_allows_login: bool,
    provider_allows_registration: bool,
) -> bool {
    let login = external_oidc_login_available(has_users, provider_allows_login);
    let registration = external_oidc_registration_available(
        has_users,
        global_allows_registration,
        provider_allows_registration,
    );
    match mode {
        ExternalOidcStartMode::Auto => login || registration,
        ExternalOidcStartMode::Login => login,
        ExternalOidcStartMode::Register => registration,
    }
}

fn external_oidc_can_create_user(
    first_user: bool,
    global_allows_registration: bool,
    provider_allows_registration: bool,
) -> bool {
    provider_allows_registration && (first_user || global_allows_registration)
}

fn verification_channel<'a>(
    state: &'a AppState,
    channel: &str,
    target: &str,
) -> AppResult<(&'a VerificationChannelSettings, String)> {
    match channel {
        "email" => Ok((&state.settings.verification.email, normalize_email(target)?)),
        "phone" => Ok((
            &state.settings.verification.phone,
            target.trim().to_string(),
        )),
        _ => Err(AppError::BadRequest(
            "unsupported verification channel".to_string(),
        )),
    }
}

fn normalize_email(value: &str) -> AppResult<String> {
    let email = value.trim().to_ascii_lowercase();
    if !email.contains('@') {
        return Err(AppError::BadRequest("email is invalid".to_string()));
    }
    Ok(email)
}

fn required_register_email(value: &Option<String>) -> AppResult<String> {
    optional_register_email(value)?
        .ok_or_else(|| AppError::BadRequest("email is required".to_string()))
}

fn optional_register_email(value: &Option<String>) -> AppResult<Option<String>> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(normalize_email)
        .transpose()
}

fn register_username_or_email_local(value: &Option<String>, email: &str) -> String {
    normalize_optional(value).unwrap_or_else(|| {
        email
            .split('@')
            .next()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("user")
            .to_string()
    })
}

fn first_nonempty_code(left: &Option<String>, right: &Option<String>) -> Option<String> {
    [left.as_deref(), right.as_deref()]
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn required_register_password(value: &Option<String>) -> AppResult<&str> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::BadRequest("password is required".to_string()))
}

fn temporary_username(value: &str) -> String {
    let base = value
        .trim()
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '-' || *ch == '_')
        .collect::<String>();
    let base = if base.is_empty() {
        "external".to_string()
    } else {
        base.chars().take(32).collect()
    };
    format!("{base}-{}", util::random_token(12))
}

fn temporary_email() -> String {
    format!("auth-{}@temporary.local", util::random_token(8))
}

fn normalize_optional(value: &Option<String>) -> Option<String> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn optional_login_hint(value: &Option<String>) -> AppResult<Option<String>> {
    let Some(value) = normalize_optional(value) else {
        return Ok(None);
    };
    if value.len() > 320 || value.contains(['\r', '\n']) {
        return Err(AppError::BadRequest("login_hint is invalid".to_string()));
    }
    Ok(Some(value))
}

fn provider_scopes(provider: &ExternalOidcProviderRecord) -> AppResult<String> {
    Ok(util::from_json::<Vec<String>>(&provider.scopes)?.join(" "))
}

async fn external_redirect_uri(
    state: &AppState,
    headers: &HeaderMap,
    provider: &ExternalOidcProviderRecord,
) -> AppResult<String> {
    let base_url = state.effective_public_base_url(headers).await?;
    Ok(format!(
        "{}{}",
        base_url.trim_end_matches('/'),
        provider.redirect_path
    ))
}

async fn fetch_external_userinfo(
    provider: &ExternalOidcProviderRecord,
    code: &str,
    redirect_uri: &str,
) -> AppResult<serde_json::Value> {
    #[derive(Debug, Deserialize)]
    struct TokenResponse {
        access_token: String,
    }

    let client = reqwest::Client::new();
    let mut form = HashMap::new();
    form.insert("grant_type", "authorization_code");
    form.insert("code", code);
    form.insert("redirect_uri", redirect_uri);
    let token = client
        .post(&provider.token_endpoint)
        .basic_auth(&provider.client_id, Some(&provider.client_secret))
        .form(&form)
        .send()
        .await
        .map_err(|err| AppError::BadRequest(format!("external OIDC token request failed: {err}")))?
        .error_for_status()
        .map_err(|err| AppError::BadRequest(format!("external OIDC token response failed: {err}")))?
        .json::<TokenResponse>()
        .await
        .map_err(|err| AppError::BadRequest(format!("external OIDC token JSON failed: {err}")))?;
    client
        .get(&provider.userinfo_endpoint)
        .bearer_auth(token.access_token)
        .send()
        .await
        .map_err(|err| AppError::BadRequest(format!("external OIDC userinfo failed: {err}")))?
        .error_for_status()
        .map_err(|err| {
            AppError::BadRequest(format!("external OIDC userinfo status failed: {err}"))
        })?
        .json::<serde_json::Value>()
        .await
        .map_err(|err| AppError::BadRequest(format!("external OIDC userinfo JSON failed: {err}")))
}

fn unique_username(preferred: &str, sub: &str) -> String {
    let base = if preferred.trim().is_empty() {
        "external-user".to_string()
    } else {
        preferred.trim().to_ascii_lowercase()
    };
    let suffix = util::token_hash(sub).chars().take(8).collect::<String>();
    format!("{base}-{suffix}")
}

fn external_oidc_email(
    claims: &serde_json::Value,
    provider_slug: &str,
    external_subject: &str,
) -> AppResult<String> {
    if let Some(value) = claims
        .get("email")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return normalize_email(value);
    }
    Ok(format!(
        "{}@{}.external",
        external_subject_email_local_part(external_subject),
        provider_slug
    ))
}

fn external_subject_email_local_part(external_subject: &str) -> String {
    let base = external_subject
        .trim()
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(*ch, '-' | '_' | '.'))
        .map(|ch| ch.to_ascii_lowercase())
        .take(32)
        .collect::<String>();
    let base = if base.is_empty() {
        "external-user".to_string()
    } else {
        base
    };
    let suffix = util::token_hash(external_subject)
        .chars()
        .take(8)
        .collect::<String>();
    format!("{base}-{suffix}")
}

#[allow(dead_code)]
fn public_provider(provider: ExternalOidcProviderRecord) -> AppResult<PublicExternalOidcProvider> {
    provider.public()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_registration_requires_password() {
        assert!(required_register_password(&None).is_err());
        assert!(required_register_password(&Some("   ".to_string())).is_err());
        assert_eq!(
            required_register_password(&Some("  passw0rd  ".to_string())).unwrap(),
            "passw0rd"
        );
    }

    #[test]
    fn normal_registration_requires_email_and_can_derive_username() {
        assert!(required_register_email(&None).is_err());
        assert_eq!(
            required_register_email(&Some(" User@Example.COM ".to_string())).unwrap(),
            "user@example.com"
        );
        assert_eq!(
            register_username_or_email_local(&None, "user@example.com"),
            "user"
        );
        assert_eq!(
            register_username_or_email_local(&Some(" alice ".to_string()), "user@example.com"),
            "alice"
        );
    }

    #[test]
    fn authorization_code_detection_does_not_need_password() {
        assert_eq!(
            first_nonempty_code(&Some(" AUTH-123 ".to_string()), &None).as_deref(),
            Some("AUTH-123")
        );
        assert_eq!(
            first_nonempty_code(&Some(" ".to_string()), &Some("AUTH-456".to_string())).as_deref(),
            Some("AUTH-456")
        );
    }

    #[test]
    fn authorization_code_flow_can_generate_temporary_email() {
        assert!(optional_register_email(&None).unwrap().is_none());
        let email = temporary_email();
        assert!(email.starts_with("auth-"));
        assert!(email.ends_with("@temporary.local"));
    }

    #[test]
    fn temporary_username_keeps_prefix_and_uses_high_entropy_suffix() {
        let username = temporary_username(" External User! ");
        let Some(suffix) = username.strip_prefix("ExternalUser-") else {
            panic!("temporary username should preserve sanitized prefix: {username}");
        };
        assert!(suffix.len() >= 16);
    }

    #[test]
    fn external_oidc_start_policy_separates_login_from_registration() {
        assert!(external_oidc_login_available(true, true));
        assert!(!external_oidc_login_available(false, true));
        assert!(!external_oidc_login_available(true, false));

        assert!(external_oidc_registration_available(false, false, true));
        assert!(external_oidc_registration_available(true, true, true));
        assert!(!external_oidc_registration_available(true, false, true));
        assert!(!external_oidc_registration_available(false, true, false));

        assert!(external_oidc_start_allowed(
            ExternalOidcStartMode::Auto,
            true,
            false,
            true,
            false
        ));
        assert!(!external_oidc_start_allowed(
            ExternalOidcStartMode::Login,
            true,
            true,
            false,
            true
        ));
        assert!(external_oidc_start_allowed(
            ExternalOidcStartMode::Register,
            true,
            true,
            false,
            true
        ));
    }

    #[test]
    fn external_oidc_login_hint_is_trimmed_and_bounded() {
        assert_eq!(
            optional_login_hint(&Some(" Alice@Example.COM ".to_string()))
                .unwrap()
                .as_deref(),
            Some("Alice@Example.COM")
        );
        assert!(
            optional_login_hint(&Some(" ".to_string()))
                .unwrap()
                .is_none()
        );
        assert!(optional_login_hint(&Some("a".repeat(321))).is_err());
        assert!(optional_login_hint(&Some("alice@example.com\nbad".to_string())).is_err());
    }

    #[test]
    fn external_oidc_user_creation_requires_registration_permission() {
        assert!(external_oidc_can_create_user(true, false, true));
        assert!(external_oidc_can_create_user(false, true, true));
        assert!(!external_oidc_can_create_user(false, false, true));
        assert!(!external_oidc_can_create_user(true, true, false));
    }

    #[test]
    fn external_oidc_email_claim_is_normalized_like_registration_email() {
        let claims = serde_json::json!({ "email": " Alice@Example.COM " });

        assert_eq!(
            external_oidc_email(&claims, "corp", "subject-1").unwrap(),
            "alice@example.com"
        );
    }

    #[test]
    fn external_oidc_missing_email_uses_safe_stable_fallback() {
        let claims = serde_json::json!({});
        let first = external_oidc_email(&claims, "corp", "User/With Unsafe Subject").unwrap();
        let second = external_oidc_email(&claims, "corp", "User/With Unsafe Subject").unwrap();

        assert_eq!(first, second);
        assert!(first.starts_with("userwithunsafesubject-"));
        assert!(first.ends_with("@corp.external"));
        assert!(!first.contains('/'));
        assert!(normalize_email(&first).is_ok());
    }
}
