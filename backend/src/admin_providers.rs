use super::{admin_client_policy::validate_absolute_http_url, normalize_required_text};
use crate::{
    AppState,
    audit::{self, AuditSink},
    db::{
        NewExternalOidcProvider, NewLdapProvider, PublicExternalOidcProvider, PublicLdapProvider,
    },
    error::{AppError, AppResult},
    identity_sources::{self, OidcDiscoveryResult, OidcProviderTemplate},
    security_policy,
};
use axum::{
    Json,
    extract::{Path, State},
};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use std::collections::BTreeSet;
use url::Url;

pub(super) async fn list_external_oidc_providers(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<Vec<PublicExternalOidcProvider>>> {
    let (_, organization, platform_manager) =
        super::current_organization_provider_manager(&state, &jar).await?;
    let mut providers = Vec::new();
    for provider in state.db.list_external_oidc_providers().await? {
        if !platform_manager
            && provider.organization_id.as_deref() != Some(organization.id.as_str())
        {
            continue;
        }
        providers.push(provider.public()?);
    }
    Ok(Json(providers))
}

pub(super) async fn list_external_oidc_provider_templates(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<Vec<OidcProviderTemplate>>> {
    super::current_organization_provider_manager(&state, &jar).await?;
    Ok(Json(identity_sources::oidc_provider_templates()))
}

#[derive(Debug, Deserialize)]
pub(super) struct OidcDiscoveryInput {
    pub(super) issuer: String,
}

pub(super) async fn discover_external_oidc_provider(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<OidcDiscoveryInput>,
) -> AppResult<Json<OidcDiscoveryResult>> {
    super::current_organization_provider_manager(&state, &jar).await?;
    identity_sources::discover_oidc_provider(&payload.issuer)
        .await
        .map(Json)
}

#[derive(Debug, Deserialize)]
pub(super) struct ExternalOidcProviderInput {
    pub(super) slug: String,
    pub(super) display_name: String,
    #[serde(default)]
    pub(super) organization_id: Option<String>,
    pub(super) issuer: String,
    pub(super) client_id: String,
    pub(super) client_secret: String,
    #[serde(default)]
    pub(super) clear_client_secret: bool,
    pub(super) authorization_endpoint: String,
    pub(super) token_endpoint: String,
    pub(super) userinfo_endpoint: String,
    pub(super) redirect_path: String,
    pub(super) scopes: Vec<String>,
    pub(super) email_domains: Vec<String>,
    pub(super) is_active: bool,
    #[serde(default = "super::default_true")]
    pub(super) allow_login: bool,
    pub(super) allow_registration: bool,
}

pub(super) async fn create_external_oidc_provider(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<ExternalOidcProviderInput>,
) -> AppResult<Json<PublicExternalOidcProvider>> {
    let (current, organization, platform_manager) =
        super::current_organization_provider_manager(&state, &jar).await?;
    let organization_id = if platform_manager {
        super::normalize_client_organization_id(&state, payload.organization_id.clone()).await?
    } else {
        super::client_organization_from_context(payload.organization_id.clone(), &organization)?
    };
    let provider_input = normalize_external_provider_input(payload, organization_id.clone())?;
    let provider = state
        .db
        .insert_external_oidc_provider(provider_input)
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "external_oidc_provider.create",
            "external_oidc_provider",
            Some(provider.id.clone()),
            serde_json::json!({
                "slug": provider.slug.clone(),
                "organization_id": organization_id,
                "allow_login": provider.allow_login == 1,
                "allow_registration": provider.allow_registration == 1,
            }),
        ))
        .await?;
    Ok(Json(provider.public()?))
}

pub(super) async fn update_external_oidc_provider(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<ExternalOidcProviderInput>,
) -> AppResult<Json<PublicExternalOidcProvider>> {
    let (current, organization, platform_manager) =
        super::current_organization_provider_manager(&state, &jar).await?;
    let existing = state
        .db
        .find_external_oidc_provider_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    if !platform_manager && existing.organization_id.as_deref() != Some(organization.id.as_str()) {
        return Err(AppError::NotFound);
    }
    let organization_id = if platform_manager {
        super::normalize_client_organization_id(&state, payload.organization_id.clone()).await?
    } else {
        super::client_organization_from_context(payload.organization_id.clone(), &organization)?
    };
    let clear_client_secret = payload.clear_client_secret;
    let mut provider_input = normalize_external_provider_input(payload, organization_id.clone())?;
    apply_external_provider_secret_update(
        &mut provider_input,
        &existing.client_secret,
        clear_client_secret,
    );
    let provider = state
        .db
        .update_external_oidc_provider(&id, provider_input)
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "external_oidc_provider.update",
            "external_oidc_provider",
            Some(id),
            serde_json::json!({
                "slug": provider.slug.clone(),
                "organization_id": organization_id,
                "allow_login": provider.allow_login == 1,
                "allow_registration": provider.allow_registration == 1,
            }),
        ))
        .await?;
    Ok(Json(provider.public()?))
}

pub(super) async fn delete_external_oidc_provider(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let (current, organization, platform_manager) =
        super::current_organization_provider_manager(&state, &jar).await?;
    let existing = state
        .db
        .find_external_oidc_provider_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    if !platform_manager && existing.organization_id.as_deref() != Some(organization.id.as_str()) {
        return Err(AppError::NotFound);
    }
    state.db.delete_external_oidc_provider(&id).await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "external_oidc_provider.delete",
            "external_oidc_provider",
            Some(id),
            serde_json::json!({}),
        ))
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

pub(super) async fn list_ldap_providers(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<Vec<PublicLdapProvider>>> {
    let (_, organization, platform_manager) =
        super::current_organization_provider_manager(&state, &jar).await?;
    let providers = state
        .db
        .list_ldap_providers()
        .await?
        .into_iter()
        .filter(|provider| {
            platform_manager
                || provider.organization_id.as_deref() == Some(organization.id.as_str())
        })
        .map(|provider| provider.public())
        .collect();
    Ok(Json(providers))
}

#[derive(Debug, Deserialize)]
pub(super) struct LdapProviderInput {
    pub(super) slug: String,
    pub(super) display_name: String,
    #[serde(default)]
    pub(super) organization_id: Option<String>,
    pub(super) url: String,
    pub(super) starttls: bool,
    pub(super) bind_dn: String,
    #[serde(default)]
    pub(super) bind_password: Option<String>,
    #[serde(default)]
    pub(super) clear_bind_password: bool,
    pub(super) base_dn: String,
    pub(super) user_filter: String,
    pub(super) user_id_attribute: String,
    pub(super) email_attribute: String,
    pub(super) username_attribute: String,
    pub(super) display_name_attribute: String,
    pub(super) phone_attribute: String,
    pub(super) is_active: bool,
    pub(super) allow_login: bool,
    pub(super) allow_registration: bool,
}

pub(super) async fn create_ldap_provider(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<LdapProviderInput>,
) -> AppResult<Json<PublicLdapProvider>> {
    let (current, organization, platform_manager) =
        super::current_organization_provider_manager(&state, &jar).await?;
    let organization_id = if platform_manager {
        super::normalize_client_organization_id(&state, payload.organization_id.clone()).await?
    } else {
        super::client_organization_from_context(payload.organization_id.clone(), &organization)?
    };
    let provider_input = normalize_ldap_provider_input(payload, organization_id.clone())?;
    let provider = state.db.insert_ldap_provider(provider_input).await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "ldap_provider.create",
            "ldap_provider",
            Some(provider.id.clone()),
            serde_json::json!({
                "slug": provider.slug.clone(),
                "organization_id": organization_id,
            }),
        ))
        .await?;
    Ok(Json(provider.public()))
}

pub(super) async fn update_ldap_provider(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<LdapProviderInput>,
) -> AppResult<Json<PublicLdapProvider>> {
    let (current, organization, platform_manager) =
        super::current_organization_provider_manager(&state, &jar).await?;
    let existing = state
        .db
        .find_ldap_provider_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    if !platform_manager && existing.organization_id.as_deref() != Some(organization.id.as_str()) {
        return Err(AppError::NotFound);
    }
    let organization_id = if platform_manager {
        super::normalize_client_organization_id(&state, payload.organization_id.clone()).await?
    } else {
        super::client_organization_from_context(payload.organization_id.clone(), &organization)?
    };
    if organization_id != existing.organization_id {
        return Err(AppError::BadRequest(
            "LDAP provider organization cannot be changed after creation".to_string(),
        ));
    }
    let provider_input = normalize_ldap_provider_input(payload, organization_id.clone())?;
    let provider = state.db.update_ldap_provider(&id, provider_input).await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "ldap_provider.update",
            "ldap_provider",
            Some(id),
            serde_json::json!({
                "slug": provider.slug.clone(),
                "organization_id": organization_id,
            }),
        ))
        .await?;
    Ok(Json(provider.public()))
}

pub(super) async fn delete_ldap_provider(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let (current, organization, platform_manager) =
        super::current_organization_provider_manager(&state, &jar).await?;
    let existing = state
        .db
        .find_ldap_provider_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    if !platform_manager && existing.organization_id.as_deref() != Some(organization.id.as_str()) {
        return Err(AppError::NotFound);
    }
    state.db.delete_ldap_provider(&id).await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "ldap_provider.delete",
            "ldap_provider",
            Some(id),
            serde_json::json!({}),
        ))
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

pub(super) fn normalize_external_provider_input(
    payload: ExternalOidcProviderInput,
    organization_id: Option<String>,
) -> AppResult<NewExternalOidcProvider> {
    let slug = normalize_provider_slug(payload.slug)?;
    let display_name = normalize_required_text(payload.display_name, "display_name")?;
    let issuer = normalize_optional_http_url(payload.issuer, "issuer", true)?;
    let client_id = payload.client_id.trim().to_string();
    let client_secret = payload.client_secret.trim().to_string();
    let authorization_endpoint = normalize_optional_http_url(
        payload.authorization_endpoint,
        "authorization_endpoint",
        false,
    )?;
    let token_endpoint =
        normalize_optional_http_url(payload.token_endpoint, "token_endpoint", false)?;
    let userinfo_endpoint =
        normalize_optional_http_url(payload.userinfo_endpoint, "userinfo_endpoint", false)?;
    let redirect_path = normalize_external_redirect_path(payload.redirect_path, &slug)?;
    let scopes = normalize_scope_list(payload.scopes)?;
    let email_domains = security_policy::normalize_email_domain_rules(payload.email_domains)?;
    if payload.is_active
        && (issuer.is_empty()
            || client_id.is_empty()
            || authorization_endpoint.is_empty()
            || token_endpoint.is_empty()
            || userinfo_endpoint.is_empty())
    {
        return Err(AppError::BadRequest(
            "active provider requires issuer, client_id, and all endpoints".to_string(),
        ));
    }
    if !scopes.iter().any(|scope| scope == "openid") {
        return Err(AppError::BadRequest(
            "external provider scopes must include openid".to_string(),
        ));
    }
    Ok(NewExternalOidcProvider {
        slug,
        display_name,
        organization_id,
        issuer,
        client_id,
        client_secret,
        authorization_endpoint,
        token_endpoint,
        userinfo_endpoint,
        redirect_path,
        scopes,
        email_domains,
        is_active: payload.is_active,
        allow_login: payload.allow_login,
        allow_registration: payload.allow_registration,
    })
}

pub(super) fn apply_external_provider_secret_update(
    provider: &mut NewExternalOidcProvider,
    existing_secret: &str,
    clear_secret: bool,
) {
    if clear_secret {
        provider.client_secret.clear();
    } else if provider.client_secret.is_empty() {
        provider.client_secret = existing_secret.to_string();
    }
}

pub(super) fn normalize_ldap_provider_input(
    payload: LdapProviderInput,
    organization_id: Option<String>,
) -> AppResult<NewLdapProvider> {
    let slug = normalize_provider_slug(payload.slug)?;
    let display_name = normalize_required_text(payload.display_name, "display_name")?;
    let url = normalize_ldap_url(payload.url)?;
    let bind_dn = payload.bind_dn.trim().to_string();
    let base_dn = payload.base_dn.trim().to_string();
    let user_filter = normalize_ldap_user_filter(payload.user_filter);
    let user_id_attribute =
        normalize_ldap_attribute(payload.user_id_attribute, "user_id_attribute", false)?;
    let email_attribute =
        normalize_ldap_attribute(payload.email_attribute, "email_attribute", false)?;
    let username_attribute =
        normalize_ldap_attribute(payload.username_attribute, "username_attribute", false)?;
    let display_name_attribute = normalize_ldap_attribute(
        payload.display_name_attribute,
        "display_name_attribute",
        true,
    )?;
    let phone_attribute =
        normalize_ldap_attribute(payload.phone_attribute, "phone_attribute", true)?;
    if payload.is_active {
        if url.is_empty() || base_dn.is_empty() {
            return Err(AppError::BadRequest(
                "active LDAP provider requires url and base_dn".to_string(),
            ));
        }
        if !user_filter.contains("{login}") {
            return Err(AppError::BadRequest(
                "LDAP user_filter must contain {login}".to_string(),
            ));
        }
    }
    let bind_password = if payload.clear_bind_password {
        Some(String::new())
    } else {
        super::normalize_optional_text(payload.bind_password)
    };
    Ok(NewLdapProvider {
        slug,
        display_name,
        organization_id,
        url,
        starttls: payload.starttls,
        bind_dn,
        bind_password,
        base_dn,
        user_filter,
        user_id_attribute,
        email_attribute,
        username_attribute,
        display_name_attribute,
        phone_attribute,
        is_active: payload.is_active,
        allow_login: payload.allow_login,
        allow_registration: payload.allow_registration,
    })
}

pub(super) fn normalize_ldap_url(value: String) -> AppResult<String> {
    let value = value.trim().trim_end_matches('/').to_string();
    if value.is_empty() {
        return Ok(String::new());
    }
    let parsed = Url::parse(&value)
        .map_err(|err| AppError::BadRequest(format!("LDAP url is invalid: {err}")))?;
    if !matches!(parsed.scheme(), "ldap" | "ldaps") || parsed.host_str().is_none() {
        return Err(AppError::BadRequest(
            "LDAP url must be an absolute ldap:// or ldaps:// URL".to_string(),
        ));
    }
    if parsed.fragment().is_some()
        || parsed.query().is_some()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(AppError::BadRequest(
            "LDAP url cannot include credentials, query or fragment".to_string(),
        ));
    }
    if !matches!(parsed.path(), "" | "/") {
        return Err(AppError::BadRequest(
            "LDAP url must not include a path; use base_dn separately".to_string(),
        ));
    }
    Ok(value)
}

pub(super) fn normalize_ldap_user_filter(value: String) -> String {
    let value = value.trim();
    if value.is_empty() {
        "(&(|(mail={login})(uid={login})(sAMAccountName={login}))(objectClass=person))".to_string()
    } else {
        value.to_string()
    }
}

pub(super) fn normalize_ldap_attribute(
    value: String,
    field: &str,
    allow_empty: bool,
) -> AppResult<String> {
    let value = value.trim().to_string();
    if value.is_empty() && allow_empty {
        return Ok(String::new());
    }
    if value.is_empty() {
        return Err(AppError::BadRequest(format!("{field} is required")));
    }
    if value.eq_ignore_ascii_case("dn") {
        return Ok("dn".to_string());
    }
    if value.len() > 128
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ';'))
    {
        return Err(AppError::BadRequest(format!(
            "{field} must be a simple LDAP attribute name or dn"
        )));
    }
    Ok(value)
}

pub(super) fn normalize_provider_slug(value: String) -> AppResult<String> {
    let slug = value.trim().to_ascii_lowercase();
    if slug.is_empty()
        || slug.len() > 64
        || !slug
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    {
        return Err(AppError::BadRequest(
            "provider slug must contain only ASCII letters, numbers, '-' or '_'".to_string(),
        ));
    }
    Ok(slug)
}

pub(super) fn normalize_optional_http_url(
    value: String,
    field: &str,
    trim_trailing_slash: bool,
) -> AppResult<String> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Ok(String::new());
    }
    validate_absolute_http_url(&value, field)?;
    if trim_trailing_slash {
        Ok(value.trim_end_matches('/').to_string())
    } else {
        Ok(value)
    }
}

pub(super) fn normalize_external_redirect_path(value: String, slug: &str) -> AppResult<String> {
    let path = value.trim().to_string();
    let expected = format!("/api/register/oidc/{slug}/callback");
    if path != expected {
        return Err(AppError::BadRequest(format!(
            "redirect_path must be {expected}"
        )));
    }
    Ok(path)
}

pub(super) fn normalize_scope_list(values: Vec<String>) -> AppResult<Vec<String>> {
    let scopes = values
        .into_iter()
        .map(|scope| scope.trim().to_string())
        .filter(|scope| !scope.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if scopes.is_empty()
        || scopes
            .iter()
            .any(|scope| scope.chars().any(char::is_whitespace))
    {
        return Err(AppError::BadRequest(
            "external provider scopes must be non-empty tokens".to_string(),
        ));
    }
    Ok(scopes)
}
