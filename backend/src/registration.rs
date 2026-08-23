use crate::{
    AppState, applications,
    audit::{self, AuditOutcome, AuditSink},
    auth, authorization,
    config::VerificationChannelSettings,
    db::{
        AdminLoginCodeRedemptionInput, ApplicationRecord, AuthorizationCodeType,
        ExternalOidcProviderRecord, InvitationRecord, LoginCodeLevel, NewTrialEnrollmentUser,
        NewUser, NewVerificationCode, PublicExternalOidcProvider, PublicLoginSettings,
        PublicRegistrationSettings, VerificationCodeClaim,
    },
    domain_discovery::EmailDomainRoutable,
    error::{AppError, AppResult},
    identity_sources,
    network_policy::TrustedNetworkPolicy,
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
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;
use std::{collections::HashMap, net::SocketAddr};
use url::Url;

const REGISTRATION_VERIFICATION_PURPOSE: &str = "registration";
const PASSWORD_RESET_VERIFICATION_PURPOSE: &str = "password_reset";

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/public/bootstrap", get(bootstrap))
        .route(
            "/api/public/authorization-code/inspect",
            post(inspect_authorization_code),
        )
        .route("/api/register", post(register))
        .route(
            "/api/login/authorization-code",
            post(login_with_authorization_code),
        )
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
    issuer: String,
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

#[derive(Debug, Deserialize, Default)]
struct BootstrapQuery {
    #[serde(default)]
    return_to: Option<String>,
}

async fn bootstrap(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<BootstrapQuery>,
) -> AppResult<Json<BootstrapResponse>> {
    let has_users = state.db.user_count().await? > 0;
    let issuer = state.db.runtime_settings().await?.issuer;
    let settings = state.db.registration_settings().await?.public();
    let target_application =
        registration_target_application(&state, &headers, query.return_to.as_deref()).await?;
    let target_organization_id = target_application
        .as_ref()
        .map(|application| application.organization_id.as_str());
    let mut login = state.db.login_settings().await?.public()?;
    login.quick_links.retain(|link| link.is_active);
    let mut providers = Vec::new();
    for provider in state.db.list_external_oidc_providers().await? {
        if let Some(application) = target_application.as_ref()
            && !applications::application_login_adapter_enabled(
                &state,
                &application.id,
                &provider.id,
            )
            .await?
        {
            continue;
        }
        if !external_oidc_provider_is_available_to_organization(
            &provider,
            target_organization_id.as_deref(),
        ) {
            continue;
        }
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
    let mut ldap_providers = Vec::new();
    for provider in state.db.list_ldap_providers().await? {
        if provider.is_active != 1 {
            continue;
        }
        if let Some(application) = target_application.as_ref() {
            // Directory login is an explicit application binding, just like
            // an external OIDC adapter. The callback path checks this again;
            // bootstrap must not advertise a source the runtime rejects.
            if !applications::application_directory_provider_enabled(
                &state,
                &application.id,
                &provider.id,
            )
            .await?
            {
                continue;
            }
        } else if provider.organization_id.is_some() {
            // Tenant-owned directories are never ambient login choices when
            // no website application has established the target tenant.
            continue;
        }
        let allow_login = external_oidc_login_available(has_users, provider.allow_login == 1);
        let allow_registration = external_oidc_registration_available(
            has_users,
            settings.allow_external_oidc_registration,
            provider.allow_registration == 1,
        );
        if allow_login || allow_registration {
            ldap_providers.push(PublicDirectorySummary {
                slug: provider.slug,
                display_name: provider.display_name,
            });
        }
    }
    Ok(Json(BootstrapResponse {
        has_users,
        issuer,
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
        .insert_verification_code(NewVerificationCode {
            channel,
            target,
            purpose,
            code_hash: util::token_hash(&code),
            ttl_seconds: settings.code_ttl_seconds,
            resend_interval_seconds: settings.resend_interval_seconds,
            max_attempts: settings.max_attempts,
        })
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
    let user = state
        .db
        .find_user_by_email(&email)
        .await?
        .ok_or_else(|| AppError::BadRequest("password reset request is invalid".to_string()))?;
    if state
        .db
        .find_trial_enrollment_for_user(&user.id)
        .await?
        .is_some()
    {
        return Err(AppError::BadRequest(
            "password reset is not available for trial enrollment accounts".to_string(),
        ));
    }
    state
        .db
        .consume_verification_code(
            "email",
            &email,
            PASSWORD_RESET_VERIFICATION_PURPOSE,
            payload.code.trim(),
        )
        .await?;
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
    return_to: Option<String>,
    account_flow: Option<String>,
}

#[derive(Debug, Serialize)]
struct RegisterResponse {
    user: crate::db::PublicUser,
    first_admin: bool,
}

struct RegistrationAuthorizationContext {
    state: AppState,
    jar: CookieJar,
    headers: HeaderMap,
    request_ip: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AuthorizationCodeLoginRequest {
    /// Authorization-code sign-in is deliberately email-address based.  Do
    /// not accept a username here: recovery codes are bound to a user record,
    /// and resolving the currently active record from its normalized email
    /// keeps renamed usernames from becoming an alternate login identifier.
    email: String,
    authorization_code: String,
    return_to: Option<String>,
    account_flow: Option<String>,
}

#[derive(Debug, Serialize)]
struct AuthorizationCodeLoginResponse {
    mode: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    continue_to: Option<String>,
    user: Option<auth::CurrentUserResponse>,
    mfa_required: bool,
    mfa_challenge_id: Option<String>,
    recovery_available: bool,
    captcha_required: bool,
    captcha_challenge_id: Option<String>,
    captcha_prompt: Option<String>,
    captcha_expires_at: Option<i64>,
}

/// The public enrollment form must not infer a code's purpose from its shape
/// or from administrator-only list data.  This deliberately exposes only the
/// minimum UI contract; the code, bound identity, organization and remaining
/// uses stay server-side and are checked again during redemption.
#[derive(Debug, Deserialize)]
struct AuthorizationCodeInspectionRequest {
    authorization_code: String,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum AuthorizationCodeInspectionMode {
    Registration,
    TrialEnrollment,
    SignInOnly,
    Unavailable,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum AuthorizationCodeEmailRequirement {
    Required,
    MustMatchCode,
    NewIdentity,
}

#[derive(Debug, Serialize)]
struct AuthorizationCodeInspectionResponse {
    mode: AuthorizationCodeInspectionMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    email_requirement: Option<AuthorizationCodeEmailRequirement>,
}

async fn inspect_authorization_code(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<AuthorizationCodeInspectionRequest>,
) -> AppResult<Json<AuthorizationCodeInspectionResponse>> {
    let code = payload.authorization_code.trim();
    if code.is_empty() {
        return Ok(Json(AuthorizationCodeInspectionResponse {
            mode: AuthorizationCodeInspectionMode::Unavailable,
            email_requirement: None,
        }));
    }
    let request_ip = state.request_ip(&headers, Some(remote_addr)).await?;
    auth::assert_authorization_code_access_allowed(&state, request_ip.as_deref()).await?;
    let invitation = match state.db.find_invitation_by_code(code).await {
        Ok(invitation) => invitation,
        Err(AppError::Database(_) | AppError::Configuration(_) | AppError::Internal(_)) => {
            return Err(AppError::Internal(
                "authorization-code inspection is temporarily unavailable".to_string(),
            ));
        }
        // Do not distinguish a malformed, expired, exhausted or revoked code.
        Err(_) => {
            return Ok(Json(AuthorizationCodeInspectionResponse {
                mode: AuthorizationCodeInspectionMode::Unavailable,
                email_requirement: None,
            }));
        }
    };
    let response = match invitation.authorization_code_type()? {
        AuthorizationCodeType::Registration => AuthorizationCodeInspectionResponse {
            mode: AuthorizationCodeInspectionMode::Registration,
            email_requirement: Some(
                invitation
                    .authorized_email
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(|_| AuthorizationCodeEmailRequirement::MustMatchCode)
                    .unwrap_or(AuthorizationCodeEmailRequirement::Required),
            ),
        },
        AuthorizationCodeType::Login
            if invitation.login_code_level()? == LoginCodeLevel::TrialEnrollment =>
        {
            AuthorizationCodeInspectionResponse {
                mode: AuthorizationCodeInspectionMode::TrialEnrollment,
                email_requirement: Some(AuthorizationCodeEmailRequirement::NewIdentity),
            }
        }
        AuthorizationCodeType::Login => AuthorizationCodeInspectionResponse {
            mode: AuthorizationCodeInspectionMode::SignInOnly,
            email_requirement: None,
        },
    };
    Ok(Json(response))
}

/// Resolves an OIDC login interaction into the tenant application that owns
/// its client. `return_to` is validated by the OIDC interaction machinery;
/// the browser never gets to name an application directly.
async fn registration_target_application(
    state: &AppState,
    headers: &HeaderMap,
    return_to: Option<&str>,
) -> AppResult<Option<ApplicationRecord>> {
    let context =
        crate::oidc::authorization_login_context_from_return_to(state, headers, return_to).await?;
    let Some(client) = context.client else {
        return Ok(None);
    };
    let application = state
        .db
        .find_application_for_client(&client.id)
        .await?
        // An OIDC client must be governed by an application before its login
        // page can admit a new identity. This is deliberately fail-closed.
        .ok_or(AppError::Forbidden)?;
    crate::applications::ensure_application_runtime_active(state, &application).await?;
    Ok(Some(application))
}

/// New identities are not automatically enterprise members. This makes the
/// application's registration mode an enforceable admission policy rather
/// than a management-console hint.
fn ensure_target_application_allows_new_registration(
    target: Option<&ApplicationRecord>,
    authorization: Option<&InvitationRecord>,
    enrollment_application: Option<&ApplicationRecord>,
) -> AppResult<()> {
    let Some(application) = target else {
        return Ok(());
    };
    if application.is_active != 1 {
        return Err(AppError::Forbidden);
    }
    match application.registration_mode.as_str() {
        crate::applications::REGISTRATION_LEGACY => Ok(()),
        crate::applications::REGISTRATION_DISABLED => Err(AppError::Forbidden),
        crate::applications::REGISTRATION_INVITATION => {
            if enrollment_application.is_some_and(|candidate| candidate.id == application.id) {
                Ok(())
            } else {
                Err(AppError::Forbidden)
            }
        }
        crate::applications::REGISTRATION_ORGANIZATION_MEMBERS => {
            // For a brand-new identity, the only way to already be an
            // enterprise member at the authorization boundary is a code that
            // grants membership in this exact enterprise. Existing active
            // Signet accounts use the normal application login gate and are
            // never enrolled into an application-member roster.
            if authorization
                .and_then(|code| code.organization_id.as_deref())
                .is_some_and(|organization_id| organization_id == application.organization_id)
            {
                Ok(())
            } else {
                Err(AppError::Forbidden)
            }
        }
        _ => Err(AppError::Internal(
            "application registration mode is invalid".to_string(),
        )),
    }
}

/// External identity sources can be an enterprise's authoritative roster.
/// They may therefore create a new identity for an
/// `organization_members` application only when that source belongs to the
/// same enterprise. Invitation-only applications intentionally require their
/// own enrollment capability and cannot be bypassed by a federated login.
fn ensure_target_application_allows_external_oidc_registration(
    target: Option<&ApplicationRecord>,
    provider: &ExternalOidcProviderRecord,
) -> AppResult<()> {
    let Some(application) = target else {
        return Ok(());
    };
    if application.is_active != 1 {
        return Err(AppError::Forbidden);
    }
    match application.registration_mode.as_str() {
        crate::applications::REGISTRATION_LEGACY => Ok(()),
        crate::applications::REGISTRATION_ORGANIZATION_MEMBERS
            if provider.organization_id.as_deref()
                == Some(application.organization_id.as_str()) =>
        {
            Ok(())
        }
        crate::applications::REGISTRATION_DISABLED
        | crate::applications::REGISTRATION_INVITATION
        | crate::applications::REGISTRATION_ORGANIZATION_MEMBERS => Err(AppError::Forbidden),
        _ => Err(AppError::Internal(
            "application registration mode is invalid".to_string(),
        )),
    }
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
    let target_application = if first_user {
        None
    } else {
        registration_target_application(&state, &headers, payload.return_to.as_deref()).await?
    };
    if !first_user {
        if let Some(code) = authorization_code.as_deref() {
            let authorization = state.db.find_invitation_by_code(code).await?;
            let enrollment_application = state
                .db
                .find_application_for_enrollment_code(&authorization.id)
                .await?;
            ensure_target_application_allows_new_registration(
                target_application.as_ref(),
                Some(&authorization),
                enrollment_application.as_ref(),
            )?;
            return match authorization.authorization_code_type()? {
                AuthorizationCodeType::Registration => {
                    register_with_registration_authorization_code(
                        RegistrationAuthorizationContext {
                            state,
                            jar,
                            headers,
                            request_ip,
                        },
                        payload,
                        code,
                        authorization,
                        &registration,
                    )
                    .await
                }
                AuthorizationCodeType::Login => {
                    // `/api/register` is an enrollment surface.  Recovery and
                    // administrator-universal codes must stay on the sign-in
                    // surface; only a trial-enrollment code may create a new
                    // restricted account here.
                    if authorization.login_code_level()? != LoginCodeLevel::TrialEnrollment {
                        return Err(AppError::Unauthorized);
                    }
                    register_with_trial_enrollment_authorization_code(
                        RegistrationAuthorizationContext {
                            state,
                            jar,
                            headers,
                            request_ip,
                        },
                        payload,
                        code,
                    )
                    .await
                }
            };
        }
        if registration.require_invitation {
            return Err(AppError::BadRequest(
                "authorization code is required".to_string(),
            ));
        }
        ensure_target_application_allows_new_registration(target_application.as_ref(), None, None)?;
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
    if registration.require_phone_verification {
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
                phone_verified_at: registration.require_phone_verification.then_some(now),
                is_admin: crate::db::registered_user_is_admin(first_user),
                is_active: registration.default_user_active || first_user,
                archived_at: None,
            },
            first_user,
            verification_claims,
        )
        .await?;
    let jar = auth::issue_session_with_login_event(
        &state,
        jar,
        &headers,
        request_ip,
        &user,
        "registration",
        auth::LoginEventContext {
            account_flow: payload.account_flow.clone(),
            ..Default::default()
        },
    )
    .await?;
    Ok((
        jar,
        Json(RegisterResponse {
            user: user.public(),
            first_admin: crate::db::registered_user_is_admin(first_user),
        }),
    ))
}

async fn register_with_registration_authorization_code(
    context: RegistrationAuthorizationContext,
    payload: RegisterRequest,
    code: &str,
    authorization: InvitationRecord,
    registration: &PublicRegistrationSettings,
) -> AppResult<(CookieJar, Json<RegisterResponse>)> {
    let RegistrationAuthorizationContext {
        state,
        jar,
        headers,
        request_ip,
    } = context;
    auth::assert_authorization_code_access_allowed(&state, request_ip.as_deref()).await?;
    let payload_email = optional_register_email(&payload.email)?;
    let email = match authorization
        .authorized_email
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(value) => {
            let bound = normalize_email(value)?;
            if payload_email
                .as_deref()
                .is_some_and(|value| value != bound.as_str())
            {
                return Err(AppError::BadRequest(
                    "email does not match the registration authorization code".to_string(),
                ));
            }
            bound
        }
        None => {
            payload_email.ok_or_else(|| AppError::BadRequest("email is required".to_string()))?
        }
    };
    auth::assert_registration_allowed(&state, Some(&email), request_ip.as_deref()).await?;
    let payload_username = normalize_optional(&payload.username);
    let username = match authorization
        .authorized_username
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(bound) => {
            if payload_username
                .as_deref()
                .is_some_and(|value| value != bound)
            {
                return Err(AppError::BadRequest(
                    "username does not match the registration authorization code".to_string(),
                ));
            }
            bound.to_string()
        }
        None => register_username_or_email_local(&payload.username, &email),
    };
    let password = required_register_password(&payload.password)?;
    state.db.security_policy().await?.validate_password(
        password,
        PasswordSubject {
            email: &email,
            username: &username,
        },
    )?;
    let password_hash = util::hash_password(password)?;
    let phone = normalize_optional(&payload.phone);
    let mut verification_claims = Vec::new();
    if registration.require_email_verification {
        let verification_code = normalize_optional(&payload.email_code).ok_or_else(|| {
            AppError::BadRequest("email verification code is required".to_string())
        })?;
        verification_claims.push(VerificationCodeClaim::new(
            "email",
            &email,
            REGISTRATION_VERIFICATION_PURPOSE,
            &verification_code,
        ));
    } else if let Some(verification_code) = normalize_optional(&payload.email_code) {
        verification_claims.push(VerificationCodeClaim::new(
            "email",
            &email,
            REGISTRATION_VERIFICATION_PURPOSE,
            &verification_code,
        ));
    }
    if registration.require_phone_verification {
        let phone_value = phone
            .as_deref()
            .ok_or_else(|| AppError::BadRequest("phone is required".to_string()))?;
        let verification_code = normalize_optional(&payload.phone_code).ok_or_else(|| {
            AppError::BadRequest("phone verification code is required".to_string())
        })?;
        verification_claims.push(VerificationCodeClaim::new(
            "phone",
            phone_value,
            REGISTRATION_VERIFICATION_PURPOSE,
            &verification_code,
        ));
    } else if let Some(verification_code) = normalize_optional(&payload.phone_code) {
        let phone_value = phone.as_deref().ok_or_else(|| {
            AppError::BadRequest(
                "phone is required when a phone verification code is supplied".to_string(),
            )
        })?;
        verification_claims.push(VerificationCodeClaim::new(
            "phone",
            phone_value,
            REGISTRATION_VERIFICATION_PURPOSE,
            &verification_code,
        ));
    }
    let now = util::now_ts();
    let email_verified = verification_claims
        .iter()
        .any(|claim| claim.channel == "email");
    // A one-time enterprise invitation is already bound to the exact email
    // address and is itself an email-possession capability. Avoid forcing the
    // recipient through a second verification loop before they can join the
    // enterprise, while leaving ordinary registration-code behavior intact.
    let invitation_confirms_email = authorization.organization_id.is_some()
        && authorization
            .authorized_email
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty());
    let phone_verified = verification_claims
        .iter()
        .any(|claim| claim.channel == "phone");
    let display_name = authorization
        .authorized_display_name
        .clone()
        .and_then(|value| normalize_optional(&Some(value)))
        .or_else(|| normalize_optional(&payload.display_name))
        .or_else(|| authorization.description.clone());
    let user = state
        .db
        .redeem_registration_code_for_new_user(
            code,
            NewUser {
                email,
                username,
                display_name,
                phone: phone.clone(),
                password_hash,
                email_verified_at: (email_verified || invitation_confirms_email).then_some(now),
                phone_verified_at: (phone_verified && phone.is_some()).then_some(now),
                is_admin: false,
                is_active: registration.default_user_active,
                archived_at: None,
            },
            verification_claims,
        )
        .await?;
    let jar = auth::issue_session_with_login_event(
        &state,
        jar,
        &headers,
        request_ip.clone(),
        &user,
        "registration_authorization_code",
        auth::LoginEventContext {
            account_flow: payload.account_flow.clone(),
            ..Default::default()
        },
    )
    .await?;
    state
        .db
        .record_audit_event(audit::AuditEvent {
            actor_user_id: Some(user.id.clone()),
            actor_client_id: None,
            action: "authorization_code.redeem".to_string(),
            target_kind: "authorization_code".to_string(),
            target_id: Some(authorization.id),
            outcome: AuditOutcome::Success,
            ip_address: request_ip,
            user_agent: util::user_agent(&headers),
            details: serde_json::json!({ "code_type": "registration" }),
        })
        .await?;
    Ok((
        jar,
        Json(RegisterResponse {
            user: user.public(),
            first_admin: false,
        }),
    ))
}

/// Redeem a trial-enrollment code only from the enrollment surface.  This is
/// intentionally separate from `/api/login/authorization-code`: a trial code
/// creates a restricted identity, while that endpoint is strictly for signing
/// in to an identity that already exists.
async fn register_with_trial_enrollment_authorization_code(
    context: RegistrationAuthorizationContext,
    payload: RegisterRequest,
    code: &str,
) -> AppResult<(CookieJar, Json<RegisterResponse>)> {
    let RegistrationAuthorizationContext {
        state,
        jar,
        headers,
        request_ip,
    } = context;
    let email = required_register_email(&payload.email)?;
    let username = register_username_or_email_local(&payload.username, &email);

    auth::assert_authorization_code_access_allowed(&state, request_ip.as_deref()).await?;
    // Keep code enrollment protected by the same per-identity lockout as an
    // authorization-code sign-in.  The subject is now the normalized email,
    // matching the public login endpoint and the visible form field.
    auth::assert_login_not_locked(&state, &email).await?;
    auth::assert_registration_allowed(&state, Some(&email), request_ip.as_deref()).await?;

    let redemption = match state
        .db
        .redeem_trial_enrollment_code_for_new_user(
            code,
            NewTrialEnrollmentUser {
                email: email.clone(),
                username,
                // The public enrollment form intentionally collects only an
                // email and a code; do not let an omitted legacy field become
                // a user-controlled profile attribute.
                display_name: None,
                // Trial enrollment is code-only.  This random value prevents
                // password login and cannot be recovered from the response.
                password_hash: util::hash_password(&util::random_token(32))?,
            },
        )
        .await
    {
        Ok(value) => value,
        Err(err) => {
            if !matches!(
                err,
                AppError::Database(_) | AppError::Configuration(_) | AppError::Internal(_)
            ) {
                auth::record_login_failure(
                    &state,
                    request_ip,
                    &headers,
                    &email,
                    "invalid_authorization_code",
                )
                .await?;
                return Err(AppError::Unauthorized);
            }
            return Err(err);
        }
    };
    let session_ttl_seconds =
        auth::authorization_code_session_ttl_seconds(&state, redemption.code_expires_at)?;
    let jar = auth::issue_session_with_login_event(
        &state,
        jar,
        &headers,
        request_ip.clone(),
        &redemption.user,
        "trial_enrollment",
        auth::LoginEventContext {
            account_flow: payload.account_flow.clone(),
            session_ttl_seconds: Some(session_ttl_seconds),
            ..Default::default()
        },
    )
    .await?;
    auth::clear_login_failures(&state, &email).await?;
    state
        .db
        .record_audit_event(audit::AuditEvent {
            actor_user_id: Some(redemption.user.id.clone()),
            actor_client_id: None,
            action: "authorization_code.trial_enrollment_redeem".to_string(),
            target_kind: "authorization_code".to_string(),
            target_id: Some(redemption.invitation_id),
            outcome: AuditOutcome::Success,
            ip_address: request_ip,
            user_agent: util::user_agent(&headers),
            details: serde_json::json!({
                "code_type": "login",
                "login_code_level": "trial_enrollment",
                "organization_id": redemption.organization_id,
                "return_to_present": payload.return_to.is_some(),
            }),
        })
        .await?;
    Ok((
        jar,
        Json(RegisterResponse {
            user: redemption.user.public(),
            first_admin: false,
        }),
    ))
}

async fn login_with_authorization_code(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<AuthorizationCodeLoginRequest>,
) -> AppResult<(CookieJar, Json<AuthorizationCodeLoginResponse>)> {
    let request_ip = state.request_ip(&headers, Some(remote_addr)).await?;
    let (jar, response) =
        perform_authorization_code_login(&state, jar, &headers, request_ip, payload).await?;
    Ok((jar, Json(response)))
}

async fn perform_authorization_code_login(
    state: &AppState,
    jar: CookieJar,
    headers: &HeaderMap,
    request_ip: Option<String>,
    payload: AuthorizationCodeLoginRequest,
) -> AppResult<(CookieJar, AuthorizationCodeLoginResponse)> {
    let email = normalize_authorization_code_login_email(&payload.email)?;
    auth::assert_authorization_code_access_allowed(state, request_ip.as_deref()).await?;
    auth::assert_login_not_locked(state, &email).await?;
    let invitation = match state
        .db
        .find_invitation_by_code(payload.authorization_code.trim())
        .await
    {
        Ok(value) => value,
        Err(err) => {
            if !matches!(
                err,
                AppError::Database(_) | AppError::Configuration(_) | AppError::Internal(_)
            ) {
                auth::record_login_failure(
                    state,
                    request_ip,
                    headers,
                    &email,
                    "invalid_authorization_code",
                )
                .await?;
                return Err(AppError::Unauthorized);
            }
            return Err(err);
        }
    };
    if invitation.authorization_code_type()? != AuthorizationCodeType::Login {
        auth::record_login_failure(
            state,
            request_ip,
            headers,
            &email,
            "invalid_authorization_code",
        )
        .await?;
        return Err(AppError::Unauthorized);
    }
    match invitation.login_code_level()? {
        LoginCodeLevel::AdminUniversal => {
            let user =
                resolve_active_authorization_code_login_user(state, headers, &request_ip, &email)
                    .await?;
            return perform_admin_universal_authorization_code_login(
                state, jar, headers, request_ip, &payload, &email, &user.id,
            )
            .await;
        }
        LoginCodeLevel::TrialEnrollment => {
            // A trial-enrollment code is an account-creation capability, not
            // a login credential.  It can only be redeemed through
            // `/api/register`, where the new-identity checks are performed.
            auth::record_login_failure(
                state,
                request_ip,
                headers,
                &email,
                "invalid_authorization_code",
            )
            .await?;
            return Err(AppError::Unauthorized);
        }
        LoginCodeLevel::AccountRecovery => {}
    }
    let user =
        resolve_active_authorization_code_login_user(state, headers, &request_ip, &email).await?;
    let redemption = match state
        .db
        .redeem_account_recovery_code(payload.authorization_code.trim(), &user.id, &email)
        .await
    {
        Ok(value) => value,
        Err(err) => {
            if !matches!(
                err,
                AppError::Database(_) | AppError::Configuration(_) | AppError::Internal(_)
            ) {
                auth::record_login_failure(
                    state,
                    request_ip,
                    headers,
                    &email,
                    "invalid_authorization_code",
                )
                .await?;
                return Err(AppError::Unauthorized);
            }
            return Err(err);
        }
    };
    let session_ttl_seconds =
        auth::authorization_code_session_ttl_seconds(state, redemption.code_expires_at)?;
    let next_jar = auth::issue_session_with_login_event(
        state,
        jar,
        headers,
        request_ip.clone(),
        &redemption.user,
        "authorization_code",
        auth::LoginEventContext {
            account_flow: payload.account_flow.clone(),
            session_ttl_seconds: Some(session_ttl_seconds),
            ..Default::default()
        },
    )
    .await?;
    auth::clear_login_failures(state, &email).await?;
    state
        .db
        .record_audit_event(audit::AuditEvent {
            actor_user_id: Some(redemption.user.id.clone()),
            actor_client_id: None,
            action: "authorization_code.redeem".to_string(),
            target_kind: "authorization_code".to_string(),
            target_id: Some(redemption.invitation_id),
            outcome: AuditOutcome::Success,
            ip_address: request_ip,
            user_agent: util::user_agent(headers),
            details: serde_json::json!({
                "code_type": "login",
                "login_code_level": "account_recovery",
                "return_to_present": payload.return_to.is_some(),
            }),
        })
        .await?;
    let current = auth::require_current_user(state, &next_jar).await?;
    Ok((
        next_jar,
        AuthorizationCodeLoginResponse {
            mode: "session",
            continue_to: None,
            user: Some(auth::current_user_response_for_session(state, current).await?),
            mfa_required: false,
            mfa_challenge_id: None,
            recovery_available: false,
            captcha_required: false,
            captcha_challenge_id: None,
            captcha_prompt: None,
            captcha_expires_at: None,
        },
    ))
}

/// Look up the existing authorization-code-login target by the normalized
/// email supplied to the public endpoint.  The invitation redemption methods
/// receive this record's immutable id and re-check it transactionally, so a
/// username rename cannot create a second login path or redirect a code to a
/// different account.
async fn resolve_active_authorization_code_login_user(
    state: &AppState,
    headers: &HeaderMap,
    request_ip: &Option<String>,
    email: &str,
) -> AppResult<crate::db::UserRecord> {
    let user = state.db.find_user_by_email(email).await?;
    match user {
        Some(user) if user.is_active == 1 && user.archived_at.is_none() => Ok(user),
        _ => {
            auth::record_login_failure(
                state,
                request_ip.clone(),
                headers,
                email,
                "invalid_authorization_code",
            )
            .await?;
            Err(AppError::Unauthorized)
        }
    }
}

async fn perform_admin_universal_authorization_code_login(
    state: &AppState,
    jar: CookieJar,
    headers: &HeaderMap,
    request_ip: Option<String>,
    payload: &AuthorizationCodeLoginRequest,
    email: &str,
    user_id: &str,
) -> AppResult<(CookieJar, AuthorizationCodeLoginResponse)> {
    let interaction = match crate::oidc::verified_oidc_login_interaction_from_return_to(
        state,
        payload.return_to.as_deref(),
    )
    .await
    {
        Ok(value) => value,
        Err(err) => {
            if matches!(
                err,
                AppError::Database(_) | AppError::Configuration(_) | AppError::Internal(_)
            ) {
                return Err(err);
            }
            auth::record_login_failure(
                state,
                request_ip,
                headers,
                email,
                "invalid_authorization_code",
            )
            .await?;
            return Err(AppError::Unauthorized);
        }
    };
    let policy_requires_mfa = state
        .db
        .security_policy()
        .await?
        .requires_mfa_for_ip(request_ip.as_deref())?;
    if interaction.request_requires_mfa
        || policy_requires_mfa
        || interaction.requests_offline_access
    {
        auth::record_login_failure(
            state,
            request_ip,
            headers,
            email,
            "authorization_code_assurance_not_allowed",
        )
        .await?;
        return Err(AppError::Unauthorized);
    }
    let (credential_hash, cookie_value) = crate::oidc::new_oidc_login_grant_credentials();
    let redemption = match state
        .db
        .redeem_admin_login_code_for_oidc_grant(AdminLoginCodeRedemptionInput {
            code: payload.authorization_code.trim(),
            user_id,
            email,
            trusted_client_id: &interaction.client.client_id,
            interaction_request_hash: &interaction.interaction_request_hash,
            credential_hash: &credential_hash,
            ttl_seconds: crate::oidc::OIDC_LOGIN_GRANT_TTL_SECONDS,
        })
        .await
    {
        Ok(value) => value,
        Err(err) => {
            if matches!(
                err,
                AppError::Database(_) | AppError::Configuration(_) | AppError::Internal(_)
            ) {
                return Err(err);
            }
            auth::record_login_failure(
                state,
                request_ip,
                headers,
                email,
                "invalid_authorization_code",
            )
            .await?;
            return Err(AppError::Unauthorized);
        }
    };
    auth::clear_login_failures(state, email).await?;
    state
        .db
        .record_login_event(
            &redemption.user.id,
            request_ip.clone(),
            util::user_agent(headers),
            "authorization_code_admin_universal",
            Some(interaction.client.client_id.clone()),
            None,
        )
        .await?;
    state
        .db
        .record_audit_event(audit::AuditEvent {
            actor_user_id: None,
            actor_client_id: Some(interaction.client.client_id.clone()),
            action: "authorization_code.admin_universal_redeem".to_string(),
            target_kind: "user".to_string(),
            target_id: Some(redemption.user.id),
            outcome: AuditOutcome::Success,
            ip_address: request_ip,
            user_agent: util::user_agent(headers),
            details: serde_json::json!({
                "authorization_code_id": redemption.invitation_id,
                "client_id": interaction.client.client_id,
                "interaction_request_hash": interaction.interaction_request_hash,
                "grant_expires_at": redemption.grant.expires_at,
            }),
        })
        .await?;
    Ok((
        jar.add(crate::oidc::oidc_login_grant_cookie(state, cookie_value)),
        AuthorizationCodeLoginResponse {
            mode: "oidc_continuation",
            continue_to: Some(interaction.continue_to),
            user: None,
            mfa_required: false,
            mfa_challenge_id: None,
            recovery_available: false,
            captcha_required: false,
            captcha_challenge_id: None,
            captcha_prompt: None,
            captcha_expires_at: None,
        },
    ))
}

#[derive(Debug, Deserialize)]
struct OidcStartQuery {
    return_to: Option<String>,
    login_hint: Option<String>,
    mode: Option<String>,
    account_flow: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct ExternalOidcReturnContext {
    return_to: Option<String>,
    account_flow: Option<String>,
}

fn external_oidc_return_context(
    return_to: Option<String>,
    account_flow: Option<String>,
) -> AppResult<Option<String>> {
    let context = ExternalOidcReturnContext {
        return_to: redirects::optional_local_return_to(return_to),
        account_flow: account_flow
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty()),
    };
    if context.return_to.is_none() && context.account_flow.is_none() {
        Ok(None)
    } else {
        serde_json::to_string(&context)
            .map(Some)
            .map_err(|err| AppError::Internal(err.to_string()))
    }
}

fn parse_external_oidc_return_context(value: Option<String>) -> ExternalOidcReturnContext {
    let Some(value) = value else {
        return ExternalOidcReturnContext::default();
    };
    serde_json::from_str(&value).unwrap_or_else(|_| ExternalOidcReturnContext {
        return_to: redirects::optional_local_return_to(Some(value)),
        account_flow: None,
    })
}

async fn external_oidc_start(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(slug): Path<String>,
    Query(query): Query<OidcStartQuery>,
) -> AppResult<Response> {
    let provider = enabled_provider(&state, &slug).await?;
    let target_application =
        registration_target_application(&state, &headers, query.return_to.as_deref()).await?;
    let target_organization_id = target_application
        .as_ref()
        .map(|application| application.organization_id.as_str());
    if let Some(application) = target_application.as_ref()
        && !applications::application_login_adapter_enabled(&state, &application.id, &provider.id)
            .await?
    {
        return Err(AppError::NotFound);
    }
    if !external_oidc_provider_is_available_to_organization(&provider, target_organization_id) {
        return Err(AppError::NotFound);
    }
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
    if mode == ExternalOidcStartMode::Register {
        ensure_target_application_allows_external_oidc_registration(
            target_application.as_ref(),
            &provider,
        )?;
    }
    let state_token = util::random_token(32);
    let nonce = util::random_token(24);
    state
        .db
        .insert_external_oidc_state(
            state_token.clone(),
            provider.slug.clone(),
            nonce.clone(),
            external_oidc_return_context(query.return_to, query.account_flow)?,
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
    let return_context = parse_external_oidc_return_context(oidc_state.return_to);
    let target_application =
        registration_target_application(&state, &headers, return_context.return_to.as_deref())
            .await?;
    let target_organization_id = target_application
        .as_ref()
        .map(|application| application.organization_id.as_str());
    if let Some(application) = target_application.as_ref()
        && !applications::application_login_adapter_enabled(&state, &application.id, &provider.id)
            .await?
    {
        return Err(AppError::NotFound);
    }
    if !external_oidc_provider_is_available_to_organization(&provider, target_organization_id) {
        return Err(AppError::NotFound);
    }
    let external_redirect = external_redirect_uri(&state, &headers, &provider).await?;
    let claims =
        fetch_external_userinfo(&provider, &code, &external_redirect, &oidc_state.nonce).await?;
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
        ensure_target_application_allows_external_oidc_registration(
            target_application.as_ref(),
            &provider,
        )?;
        let (email, email_verified) =
            external_oidc_email_with_verification(&claims, &provider.slug, &sub)?;
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
                    email_verified_at: email_verified.then_some(util::now_ts()),
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
    if let Some(application) = target_application.as_ref()
        && !authorization::check_login_access(&state, application, &user.id)
            .await?
            .allowed
    {
        // The external provider binding is an input selector, not a bypass
        // around the website's live account/tenant gate. Re-check it after
        // resolving the external subject so a disabled application or tenant
        // cannot still establish a session through a stale callback.
        return Err(AppError::Forbidden);
    }
    let jar = auth::issue_session_with_login_event(
        &state,
        jar,
        &headers,
        request_ip,
        &user,
        "external_oidc",
        auth::LoginEventContext {
            external_provider: Some(slug),
            account_flow: return_context.account_flow,
            ..Default::default()
        },
    )
    .await?;
    let return_to = redirects::local_return_to(return_context.return_to.as_deref());
    Ok((jar, Redirect::to(&return_to)).into_response())
}

async fn external_oidc_error_return_to(
    state: &AppState,
    slug: &str,
    state_value: Option<&str>,
) -> Option<String> {
    let state_value = state_value?;
    match state.db.consume_external_oidc_state(state_value).await {
        Ok(oidc_state) if oidc_state.provider_slug == slug => {
            parse_external_oidc_return_context(oidc_state.return_to).return_to
        }
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

fn external_oidc_provider_is_available_to_organization(
    provider: &ExternalOidcProviderRecord,
    target_organization_id: Option<&str>,
) -> bool {
    provider.organization_id.is_none()
        || provider.organization_id.as_deref() == target_organization_id
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

fn normalize_authorization_code_login_email(value: &str) -> AppResult<String> {
    let email = value.trim();
    if email.is_empty() || email.len() > 320 || email.chars().any(|ch| ch.is_control()) {
        return Err(AppError::Unauthorized);
    }
    normalize_email(email).map_err(|_| AppError::Unauthorized)
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
    expected_nonce: &str,
) -> AppResult<serde_json::Value> {
    #[derive(Debug, Deserialize)]
    struct TokenResponse {
        access_token: String,
        id_token: Option<String>,
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|err| {
            AppError::Internal(format!("failed to build external OIDC client: {err}"))
        })?;
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
    let id_token = token.id_token.ok_or_else(|| {
        AppError::BadRequest("external OIDC token response did not include an ID token".to_string())
    })?;
    let id_token_claims = verify_external_id_token(provider, &id_token, expected_nonce).await?;
    let userinfo = client
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
        .map_err(|err| {
            AppError::BadRequest(format!("external OIDC userinfo JSON failed: {err}"))
        })?;
    let userinfo_sub = userinfo
        .get("sub")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::BadRequest("external OIDC userinfo missing sub".to_string()))?;
    if userinfo_sub != id_token_claims.sub {
        return Err(AppError::BadRequest(
            "external OIDC subject mismatch".to_string(),
        ));
    }
    Ok(userinfo)
}

#[derive(Debug, Clone)]
struct ExternalIdTokenClaims {
    sub: String,
}

async fn verify_external_id_token(
    provider: &ExternalOidcProviderRecord,
    id_token: &str,
    expected_nonce: &str,
) -> AppResult<ExternalIdTokenClaims> {
    let header = decode_header(id_token)
        .map_err(|_| AppError::BadRequest("external OIDC ID token is invalid".to_string()))?;
    if !matches!(
        header.alg,
        Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::ES256
            | Algorithm::ES384
    ) {
        return Err(AppError::BadRequest(
            "external OIDC ID token algorithm is not allowed".to_string(),
        ));
    }
    let discovery = identity_sources::discover_oidc_provider(&provider.issuer).await?;
    if normalize_external_issuer(&discovery.issuer) != normalize_external_issuer(&provider.issuer) {
        return Err(AppError::BadRequest(
            "external OIDC issuer does not match provider configuration".to_string(),
        ));
    }
    let jwks = identity_sources::fetch_oidc_jwks(&discovery.jwks_uri).await?;
    let key = match header.kid.as_deref() {
        Some(kid) => jwks.find(kid),
        None if jwks.keys.len() == 1 => jwks.keys.first(),
        None => None,
    }
    .ok_or_else(|| AppError::BadRequest("external OIDC signing key was not found".to_string()))?;
    if key
        .common
        .key_algorithm
        .is_some_and(|algorithm| algorithm.to_string() != format!("{:?}", header.alg))
    {
        return Err(AppError::BadRequest(
            "external OIDC signing key algorithm does not match token".to_string(),
        ));
    }
    let key = DecodingKey::from_jwk(key)
        .map_err(|_| AppError::BadRequest("external OIDC signing key is invalid".to_string()))?;
    let issuer = normalize_external_issuer(&provider.issuer);
    let mut validation = Validation::new(header.alg);
    validation.set_issuer(&[issuer.as_str()]);
    validation.set_audience(&[provider.client_id.as_str()]);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    validation.leeway = 60;
    let decoded = decode::<Value>(id_token, &key, &validation).map_err(|_| {
        AppError::BadRequest("external OIDC ID token validation failed".to_string())
    })?;
    let claims = decoded.claims;
    let issuer_claim = claims
        .get("iss")
        .and_then(Value::as_str)
        .map(normalize_external_issuer)
        .ok_or_else(|| {
            AppError::BadRequest("external OIDC ID token issuer is missing".to_string())
        })?;
    if issuer_claim != issuer {
        return Err(AppError::BadRequest(
            "external OIDC ID token issuer is invalid".to_string(),
        ));
    }
    let sub = claims
        .get("sub")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            AppError::BadRequest("external OIDC ID token subject is missing".to_string())
        })?
        .to_string();
    let nonce = claims.get("nonce").and_then(Value::as_str).ok_or_else(|| {
        AppError::BadRequest("external OIDC ID token nonce is missing".to_string())
    })?;
    if nonce != expected_nonce {
        return Err(AppError::BadRequest(
            "external OIDC ID token nonce is invalid".to_string(),
        ));
    }
    let issued_at = claims
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or_else(|| AppError::BadRequest("external OIDC ID token iat is missing".to_string()))?;
    if issued_at > util::now_ts() + 60 {
        return Err(AppError::BadRequest(
            "external OIDC ID token iat is in the future".to_string(),
        ));
    }
    Ok(ExternalIdTokenClaims { sub })
}

fn normalize_external_issuer(value: &str) -> String {
    value.trim().trim_end_matches('/').to_string()
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

#[cfg(test)]
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

fn external_oidc_email_with_verification(
    claims: &serde_json::Value,
    provider_slug: &str,
    external_subject: &str,
) -> AppResult<(String, bool)> {
    if let Some(value) = claims
        .get("email")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let normalized = normalize_email(value)?;
        let verified = claims
            .get("email_verified")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if verified {
            return Ok((normalized, true));
        }
    }
    Ok((
        format!(
            "{}@{}.external",
            external_subject_email_local_part(external_subject),
            provider_slug
        ),
        false,
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
    fn authorization_code_login_normalizes_and_requires_an_email() {
        assert_eq!(
            normalize_authorization_code_login_email(" User@Example.COM ").unwrap(),
            "user@example.com"
        );
        assert!(normalize_authorization_code_login_email(" ").is_err());
        assert!(normalize_authorization_code_login_email("not-an-email").is_err());
    }

    #[test]
    fn authorization_code_login_request_accepts_email_not_username() {
        let request: AuthorizationCodeLoginRequest = serde_json::from_value(serde_json::json!({
            "email": "person@example.com",
            "authorization_code": "AUTH-123"
        }))
        .unwrap();
        assert_eq!(request.email, "person@example.com");
        assert!(
            serde_json::from_value::<AuthorizationCodeLoginRequest>(serde_json::json!({
                "username": "person",
                "authorization_code": "AUTH-123"
            }))
            .is_err()
        );
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
    fn tenant_external_oidc_provider_is_not_an_ambient_login_option() {
        let provider = ExternalOidcProviderRecord {
            id: "provider".to_string(),
            slug: "tenant-idp".to_string(),
            display_name: "Tenant IdP".to_string(),
            organization_id: Some("tenant-a".to_string()),
            issuer: "https://issuer.example".to_string(),
            client_id: "client".to_string(),
            client_secret: "secret".to_string(),
            authorization_endpoint: "https://issuer.example/authorize".to_string(),
            token_endpoint: "https://issuer.example/token".to_string(),
            userinfo_endpoint: "https://issuer.example/userinfo".to_string(),
            redirect_path: "/api/register/oidc/tenant-idp/callback".to_string(),
            scopes: "[]".to_string(),
            email_domains: "[]".to_string(),
            is_active: 1,
            allow_login: 1,
            allow_registration: 1,
            created_at: 1,
            updated_at: 1,
        };
        assert!(external_oidc_provider_is_available_to_organization(
            &provider,
            Some("tenant-a")
        ));
        assert!(!external_oidc_provider_is_available_to_organization(
            &provider,
            Some("tenant-b")
        ));
        assert!(!external_oidc_provider_is_available_to_organization(
            &provider, None
        ));

        let mut platform_provider = provider;
        platform_provider.organization_id = None;
        assert!(external_oidc_provider_is_available_to_organization(
            &platform_provider,
            Some("tenant-b")
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
