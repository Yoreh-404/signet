use super::{
    admin_guards::{require_admin_reader, require_security_manager, require_settings_manager},
    admin_providers::normalize_optional_http_url,
};
use crate::{
    AppState,
    access::Authorizer,
    access::Permission,
    audit::{self, AuditSink},
    auth, config,
    db::{
        NewLoginSettings, NewRegistrationSettings, NewRuntimeSettings, NewSecurityPolicy,
        PublicLoginSettings, PublicRegistrationSettings, PublicSecurityPolicy, QuickLink,
        SecurityPolicyRecord, SigningKeyRecord,
    },
    error::{AppError, AppResult},
    network_policy, security_policy, util,
};
use axum::{Json, extract::State, http::HeaderMap};
use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use url::Url;

#[derive(Debug, Serialize)]
pub(super) struct SettingsSummary {
    config_server_public_base_url: String,
    config_issuer: String,
    runtime_public_base_url: String,
    runtime_issuer: String,
    runtime_trust_proxy_headers: bool,
    effective_public_base_url: String,
    effective_issuer: String,
    database_kind: String,
    database_pool_size: u32,
    run_migrations: bool,
    supported_scopes: Vec<String>,
    access_token_ttl_seconds: i64,
    id_token_ttl_seconds: i64,
    refresh_token_ttl_seconds: i64,
    cookie_secure: bool,
    cookie_same_site: String,
    cors_allowed_origins: Vec<String>,
}

pub(super) async fn settings_summary(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> AppResult<Json<SettingsSummary>> {
    require_admin_reader(&state, &jar).await?;
    let runtime = state.runtime_settings().await?;
    Ok(Json(SettingsSummary {
        config_server_public_base_url: state.settings.server.public_base_url.clone(),
        config_issuer: state.settings.oidc.issuer.clone(),
        runtime_public_base_url: runtime.public_base_url.clone(),
        runtime_issuer: runtime.issuer.clone(),
        runtime_trust_proxy_headers: runtime.trust_proxy_headers == 1,
        effective_public_base_url: state.effective_public_base_url(&headers).await?,
        effective_issuer: state.effective_issuer(&headers).await?,
        database_kind: format!("{:?}", state.settings.database.kind).to_ascii_lowercase(),
        database_pool_size: state.settings.database.pool_size,
        run_migrations: state.settings.database.run_migrations,
        supported_scopes: state.settings.oidc.supported_scopes.clone(),
        access_token_ttl_seconds: state.settings.oidc.access_token_ttl_seconds,
        id_token_ttl_seconds: state.settings.oidc.id_token_ttl_seconds,
        refresh_token_ttl_seconds: state.settings.oidc.refresh_token_ttl_seconds,
        cookie_secure: state.settings.security.cookie_secure,
        cookie_same_site: format!("{:?}", state.settings.security.cookie_same_site),
        cors_allowed_origins: state.settings.cors.allowed_origins.clone(),
    }))
}

pub(super) async fn get_registration_settings(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<PublicRegistrationSettings>> {
    require_settings_manager(&state, &jar).await?;
    Ok(Json(state.db.registration_settings().await?.public()))
}

#[derive(Debug, Deserialize)]
pub(super) struct RegistrationSettingsInput {
    allow_password_registration: bool,
    require_email_verification: bool,
    require_phone_verification: bool,
    allow_external_oidc_registration: bool,
    require_invitation: bool,
    first_user_direct_admin: bool,
    default_user_active: bool,
}

pub(super) async fn update_registration_settings(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<RegistrationSettingsInput>,
) -> AppResult<Json<PublicRegistrationSettings>> {
    let current = require_settings_manager(&state, &jar).await?;
    let settings = state
        .db
        .upsert_registration_settings(NewRegistrationSettings {
            allow_password_registration: payload.allow_password_registration,
            require_email_verification: payload.require_email_verification,
            require_phone_verification: payload.require_phone_verification,
            allow_external_oidc_registration: payload.allow_external_oidc_registration,
            require_invitation: payload.require_invitation,
            first_user_direct_admin: payload.first_user_direct_admin
                || crate::db::FIRST_REGISTERED_USER_IS_ADMIN,
            default_user_active: payload.default_user_active,
        })
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "registration_settings.update",
            "registration_settings",
            Some("default".to_string()),
            serde_json::json!({ "require_invitation": payload.require_invitation }),
        ))
        .await?;
    Ok(Json(settings.public()))
}

#[derive(Debug, Deserialize)]
pub(super) struct SecurityPolicyInput {
    password_min_length: i32,
    password_require_uppercase: bool,
    password_require_lowercase: bool,
    password_require_digit: bool,
    password_require_symbol: bool,
    password_reject_user_info: bool,
    login_lockout_enabled: bool,
    max_failed_login_attempts: i32,
    failure_window_seconds: i64,
    lockout_seconds: i64,
    #[serde(default)]
    trusted_ip_cidrs: Vec<String>,
    #[serde(default)]
    require_mfa_outside_trusted_networks: bool,
    #[serde(default)]
    allowed_ip_cidrs: Vec<String>,
    #[serde(default)]
    blocked_ip_cidrs: Vec<String>,
    #[serde(default)]
    allowed_email_domains: Vec<String>,
    #[serde(default)]
    blocked_email_domains: Vec<String>,
    #[serde(default)]
    captcha_enabled: bool,
    #[serde(default = "default_captcha_after_failed_attempts")]
    captcha_after_failed_attempts: i32,
    #[serde(default = "default_captcha_ttl_seconds")]
    captcha_ttl_seconds: i64,
}

pub(super) fn default_captcha_after_failed_attempts() -> i32 {
    3
}

pub(super) fn default_captcha_ttl_seconds() -> i64 {
    300
}

pub(super) fn policy_from_input(payload: SecurityPolicyInput) -> AppResult<NewSecurityPolicy> {
    Ok(NewSecurityPolicy {
        password_min_length: payload.password_min_length,
        password_require_uppercase: payload.password_require_uppercase,
        password_require_lowercase: payload.password_require_lowercase,
        password_require_digit: payload.password_require_digit,
        password_require_symbol: payload.password_require_symbol,
        password_reject_user_info: payload.password_reject_user_info,
        login_lockout_enabled: payload.login_lockout_enabled,
        max_failed_login_attempts: payload.max_failed_login_attempts,
        failure_window_seconds: payload.failure_window_seconds,
        lockout_seconds: payload.lockout_seconds,
        trusted_ip_cidrs: network_policy::normalize_trusted_networks(payload.trusted_ip_cidrs)?,
        require_mfa_outside_trusted_networks: payload.require_mfa_outside_trusted_networks,
        allowed_ip_cidrs: network_policy::normalize_networks(
            payload.allowed_ip_cidrs,
            "allowed IP network",
        )?,
        blocked_ip_cidrs: network_policy::normalize_networks(
            payload.blocked_ip_cidrs,
            "blocked IP network",
        )?,
        allowed_email_domains: security_policy::normalize_email_domain_rules(
            payload.allowed_email_domains,
        )?,
        blocked_email_domains: security_policy::normalize_email_domain_rules(
            payload.blocked_email_domains,
        )?,
        captcha_enabled: payload.captcha_enabled,
        captcha_after_failed_attempts: payload.captcha_after_failed_attempts,
        captcha_ttl_seconds: payload.captcha_ttl_seconds,
    })
}

pub(super) fn policy_record_for_validation(
    settings: &NewSecurityPolicy,
) -> AppResult<SecurityPolicyRecord> {
    Ok(SecurityPolicyRecord {
        id: "default".to_string(),
        password_min_length: settings.password_min_length,
        password_require_uppercase: i32::from(settings.password_require_uppercase),
        password_require_lowercase: i32::from(settings.password_require_lowercase),
        password_require_digit: i32::from(settings.password_require_digit),
        password_require_symbol: i32::from(settings.password_require_symbol),
        password_reject_user_info: i32::from(settings.password_reject_user_info),
        login_lockout_enabled: i32::from(settings.login_lockout_enabled),
        max_failed_login_attempts: settings.max_failed_login_attempts,
        failure_window_seconds: settings.failure_window_seconds,
        lockout_seconds: settings.lockout_seconds,
        trusted_ip_cidrs: util::to_json(&settings.trusted_ip_cidrs)?,
        require_mfa_outside_trusted_networks: i32::from(
            settings.require_mfa_outside_trusted_networks,
        ),
        allowed_ip_cidrs: util::to_json(&settings.allowed_ip_cidrs)?,
        blocked_ip_cidrs: util::to_json(&settings.blocked_ip_cidrs)?,
        allowed_email_domains: util::to_json(&settings.allowed_email_domains)?,
        blocked_email_domains: util::to_json(&settings.blocked_email_domains)?,
        captcha_enabled: i32::from(settings.captcha_enabled),
        captcha_after_failed_attempts: settings.captcha_after_failed_attempts,
        captcha_ttl_seconds: settings.captcha_ttl_seconds,
        updated_at: util::now_ts(),
    })
}

pub(super) async fn get_security_policy(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<PublicSecurityPolicy>> {
    let current = auth::require_current_user(&state, &jar).await?;
    state
        .db
        .require_permission(&current.user, Permission::SecurityManage)
        .await?;
    state.db.security_policy().await?.public().map(Json)
}

pub(super) async fn update_security_policy(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<SecurityPolicyInput>,
) -> AppResult<Json<PublicSecurityPolicy>> {
    let current = auth::require_current_user(&state, &jar).await?;
    state
        .db
        .require_permission(&current.user, Permission::SecurityManage)
        .await?;
    let next = policy_from_input(payload)?;
    let record = policy_record_for_validation(&next)?;
    security_policy::validate_policy_input(&record)?;
    let settings = state.db.upsert_security_policy(next).await?;
    let public = settings.public()?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "security_policy.update",
            "security_policy",
            Some("default".to_string()),
            serde_json::json!({
                "trusted_ip_cidrs": &public.trusted_ip_cidrs,
                "require_mfa_outside_trusted_networks": settings.require_mfa_outside_trusted_networks == 1,
                "allowed_ip_cidrs": &public.allowed_ip_cidrs,
                "blocked_ip_cidrs": &public.blocked_ip_cidrs,
                "allowed_email_domains": &public.allowed_email_domains,
                "blocked_email_domains": &public.blocked_email_domains,
                "captcha_enabled": settings.captcha_enabled == 1,
                "captcha_after_failed_attempts": settings.captcha_after_failed_attempts,
                "captcha_ttl_seconds": settings.captcha_ttl_seconds
            }),
        ))
        .await?;
    Ok(Json(public))
}

#[derive(Debug, Serialize)]
pub(super) struct SigningKeyResponse {
    id: String,
    kid: String,
    is_active: bool,
    created_at: i64,
    activated_at: Option<i64>,
    retired_at: Option<i64>,
}

impl From<SigningKeyRecord> for SigningKeyResponse {
    fn from(record: SigningKeyRecord) -> Self {
        Self {
            id: record.id,
            kid: record.kid,
            is_active: record.is_active == 1,
            created_at: record.created_at,
            activated_at: record.activated_at,
            retired_at: record.retired_at,
        }
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct RotateSigningKeyInput {
    kid: Option<String>,
}

pub(super) async fn list_signing_keys(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<Vec<SigningKeyResponse>>> {
    require_security_manager(&state, &jar).await?;
    let keys = state
        .db
        .list_signing_keys()
        .await?
        .into_iter()
        .map(SigningKeyResponse::from)
        .collect();
    Ok(Json(keys))
}

pub(super) async fn rotate_signing_key(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<RotateSigningKeyInput>,
) -> AppResult<Json<SigningKeyResponse>> {
    let current = require_security_manager(&state, &jar).await?;
    let key = state.db.rotate_signing_key(payload.kid).await?;
    let keys = state.db.list_signing_keys().await?;
    state.jwt.reload(keys)?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "signing_key.rotate",
            "signing_key",
            Some(key.id.clone()),
            serde_json::json!({ "kid": key.kid.clone() }),
        ))
        .await?;
    Ok(Json(SigningKeyResponse::from(key)))
}

#[derive(Debug, Serialize)]
pub(super) struct RuntimeSettingsResponse {
    public_base_url: String,
    issuer: String,
    trust_proxy_headers: bool,
    effective_public_base_url: String,
    effective_issuer: String,
    updated_at: i64,
}

#[derive(Debug, Deserialize)]
pub(super) struct RuntimeSettingsInput {
    public_base_url: String,
    issuer: Option<String>,
    trust_proxy_headers: bool,
}

pub(super) async fn get_runtime_settings(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> AppResult<Json<RuntimeSettingsResponse>> {
    require_settings_manager(&state, &jar).await?;
    runtime_settings_response(&state, &headers).await.map(Json)
}

pub(super) async fn update_runtime_settings(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(payload): Json<RuntimeSettingsInput>,
) -> AppResult<Json<RuntimeSettingsResponse>> {
    let current = require_settings_manager(&state, &jar).await?;
    let public_base_url = normalize_base_url(&payload.public_base_url, "public_base_url")?;
    let issuer = match payload
        .issuer
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(value) => normalize_base_url(value, "issuer")?,
        None => public_base_url.clone(),
    };
    state
        .db
        .upsert_runtime_settings(NewRuntimeSettings {
            public_base_url: public_base_url.clone(),
            issuer: issuer.clone(),
            trust_proxy_headers: payload.trust_proxy_headers,
        })
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "runtime_settings.update",
            "runtime_settings",
            Some("default".to_string()),
            serde_json::json!({ "public_base_url": public_base_url, "issuer": issuer }),
        ))
        .await?;
    runtime_settings_response(&state, &headers).await.map(Json)
}

async fn runtime_settings_response(
    state: &AppState,
    headers: &HeaderMap,
) -> AppResult<RuntimeSettingsResponse> {
    let runtime = state.runtime_settings().await?;
    Ok(RuntimeSettingsResponse {
        public_base_url: runtime.public_base_url,
        issuer: runtime.issuer,
        trust_proxy_headers: runtime.trust_proxy_headers == 1,
        effective_public_base_url: state.effective_public_base_url(headers).await?,
        effective_issuer: state.effective_issuer(headers).await?,
        updated_at: runtime.updated_at,
    })
}

#[derive(Debug, Deserialize)]
pub(super) struct LoginSettingsInput {
    pub(super) brand_logo_url: Option<String>,
    pub(super) email_domains: Vec<String>,
    pub(super) quick_links: Vec<QuickLink>,
}

pub(super) async fn get_login_settings(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<PublicLoginSettings>> {
    require_settings_manager(&state, &jar).await?;
    state.db.login_settings().await?.public().map(Json)
}

pub(super) async fn update_login_settings(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<LoginSettingsInput>,
) -> AppResult<Json<PublicLoginSettings>> {
    let current = require_settings_manager(&state, &jar).await?;
    let LoginSettingsInput {
        brand_logo_url,
        email_domains,
        quick_links,
    } = payload;
    let quick_link_count = quick_links.len();
    let brand_logo_url = match brand_logo_url {
        Some(value) => normalize_brand_logo_url(value)?,
        None => state.db.login_settings().await?.brand_logo_url,
    };
    let settings = state
        .db
        .upsert_login_settings(NewLoginSettings {
            brand_logo_url,
            email_domains: normalize_email_domains(email_domains)?,
            quick_links: normalize_quick_links(quick_links)?,
        })
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "login_settings.update",
            "login_settings",
            Some("default".to_string()),
            serde_json::json!({ "quick_links": quick_link_count }),
        ))
        .await?;
    settings.public().map(Json)
}

pub(super) fn normalize_base_url(value: &str, field: &str) -> AppResult<String> {
    config::validate_public_origin(value, field)
        .map_err(|err| AppError::BadRequest(err.to_string()))
}

pub(super) fn normalize_email_domains(values: Vec<String>) -> AppResult<Vec<String>> {
    security_policy::normalize_email_domain_rules(values)
}

pub(super) fn normalize_brand_logo_url(value: String) -> AppResult<String> {
    let value = normalize_optional_http_url(value, "brand_logo_url", false)?;
    if value.len() > 2048 {
        return Err(AppError::BadRequest(
            "brand_logo_url exceeds 2048 characters".to_string(),
        ));
    }
    Ok(value)
}

pub(super) fn normalize_quick_links(values: Vec<QuickLink>) -> AppResult<Vec<QuickLink>> {
    let mut links = Vec::new();
    let mut ids = BTreeSet::new();
    for value in values {
        let label = value.label.trim();
        let url = value.url.trim();
        if label.is_empty() && url.is_empty() {
            continue;
        }
        if label.is_empty() {
            return Err(AppError::BadRequest(
                "quick link label is required".to_string(),
            ));
        }
        let parsed = Url::parse(url)
            .map_err(|err| AppError::BadRequest(format!("quick link url is invalid: {err}")))?;
        if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
            return Err(AppError::BadRequest(
                "quick link url must be an absolute http(s) URL".to_string(),
            ));
        }
        let id = value
            .id
            .trim()
            .chars()
            .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '-' || *ch == '_')
            .collect::<String>();
        let id = if id.is_empty() {
            uuid::Uuid::new_v4().to_string()
        } else {
            id
        };
        if !ids.insert(id.clone()) {
            return Err(AppError::BadRequest(
                "quick link id must be unique".to_string(),
            ));
        }
        links.push(QuickLink {
            id,
            label: label.chars().take(48).collect(),
            url: url.to_string(),
            // Preserve the serialized field for compatibility with existing
            // data, but do not carry forward a preconfigured icon mapping.
            icon: String::new(),
            is_active: value.is_active,
        });
    }
    Ok(links)
}

pub(crate) fn normalize_optional_text(value: Option<String>) -> Option<String> {
    value
        .map(|item| item.trim().to_string())
        .filter(|item| !item.is_empty())
}

pub(crate) fn normalize_required_text(value: String, field: &str) -> AppResult<String> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(AppError::BadRequest(format!("{field} cannot be empty")));
    }
    Ok(value)
}

pub(crate) fn normalize_optional_email(value: Option<String>) -> AppResult<Option<String>> {
    let Some(value) = normalize_optional_text(value) else {
        return Ok(None);
    };
    let email = value.to_ascii_lowercase();
    if !email.contains('@') || email.ends_with('@') {
        return Err(AppError::BadRequest("email is invalid".to_string()));
    }
    Ok(Some(email))
}
