use crate::{
    AppState,
    access::{Authorizer, Permission},
    auth::{self, AccountCapabilities},
    db::{IapApplicationRecord, NewIapApplication, UserOrganizationRecord},
    error::{AppError, AppResult},
    redirects, util,
};
use axum::{
    Router,
    extract::{Query, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
    routing::get,
};
use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, future::Future};
use url::Url;

const LOGIN_START_PATH: &str = "/api/iap/start";
const LOGIN_FINISH_PATH: &str = "/api/iap/finish";

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/iap/forward-auth",
            get(forward_auth).post(forward_auth),
        )
        .route(LOGIN_START_PATH, get(start_login))
        .route(LOGIN_FINISH_PATH, get(finish_login))
}

#[derive(Debug, Deserialize)]
struct ForwardAuthQuery {
    target: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IapLoginQuery {
    return_to: String,
}

#[derive(Debug, Clone)]
pub struct IapTarget {
    pub method: String,
    pub url: String,
    pub host: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct IapDecision {
    pub allowed: bool,
    pub application_id: Option<String>,
    pub reason: Option<&'static str>,
}

pub trait IapApplicationRepository {
    fn active_iap_applications(
        &self,
    ) -> impl Future<Output = AppResult<Vec<IapApplicationRecord>>> + Send;

    fn user_organizations(
        &self,
        user_id: &str,
    ) -> impl Future<Output = AppResult<Vec<UserOrganizationRecord>>> + Send;
}

impl IapApplicationRepository for crate::db::Db {
    async fn active_iap_applications(&self) -> AppResult<Vec<IapApplicationRecord>> {
        self.list_active_iap_applications().await
    }

    async fn user_organizations(&self, user_id: &str) -> AppResult<Vec<UserOrganizationRecord>> {
        self.list_user_organizations(user_id).await
    }
}

pub trait IapAccessPolicy {
    fn matching_application<'a>(
        &self,
        target: &IapTarget,
        applications: &'a [IapApplicationRecord],
    ) -> Option<&'a IapApplicationRecord>;

    fn permits_organization(
        &self,
        application: &IapApplicationRecord,
        organizations: &[UserOrganizationRecord],
    ) -> AppResult<bool>;
}

#[derive(Debug, Clone, Copy)]
pub struct DefaultIapAccessPolicy;

impl IapAccessPolicy for DefaultIapAccessPolicy {
    fn matching_application<'a>(
        &self,
        target: &IapTarget,
        applications: &'a [IapApplicationRecord],
    ) -> Option<&'a IapApplicationRecord> {
        applications
            .iter()
            .filter(|application| {
                application.is_active == 1
                    && host_matches(&application.external_host, &target.host)
                    && path_matches(&application.path_prefix, &target.path)
            })
            .max_by_key(|application| {
                (
                    application.path_prefix.len(),
                    application.external_host.eq_ignore_ascii_case(&target.host),
                )
            })
    }

    fn permits_organization(
        &self,
        application: &IapApplicationRecord,
        organizations: &[UserOrganizationRecord],
    ) -> AppResult<bool> {
        let Some(required_id) = application.required_organization_id.as_deref() else {
            return Ok(true);
        };
        let roles = application.required_organization_roles()?;
        Ok(organizations.iter().any(|organization| {
            organization.id == required_id
                && organization.is_active == 1
                && (roles.is_empty() || roles.iter().any(|role| role == &organization.role))
        }))
    }
}

async fn forward_auth(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Query(query): Query<ForwardAuthQuery>,
) -> AppResult<Response> {
    let target = target_from_request(query.target.as_deref(), &headers)?;
    let Some(current) = auth::current_user_from_cookie(&state, &jar).await? else {
        return Ok(deny_response(
            StatusCode::UNAUTHORIZED,
            "login_required",
            Some(&login_start_url(&target.url)),
        ));
    };
    if !iap_session_can_access(&current) {
        return Ok(deny_response(
            StatusCode::FORBIDDEN,
            "temporary_account_not_allowed",
            None,
        ));
    }
    let applications = state.db.active_iap_applications().await?;
    let Some(application) = DefaultIapAccessPolicy.matching_application(&target, &applications)
    else {
        return Ok(deny_response(
            StatusCode::FORBIDDEN,
            "no_matching_application",
            None,
        ));
    };
    ensure_user_allowed(&state, application, &current.user).await?;
    allow_response(application, &current.user, &target)
}

async fn start_login(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<IapLoginQuery>,
) -> AppResult<Response> {
    let target = target_from_url("GET", &query.return_to)?;
    let application = ensure_target_is_configured(&state, &target).await?;
    let current = auth::current_user_from_cookie(&state, &jar).await?;
    if let Some(current) = current.as_ref()
        && iap_session_can_access(current)
    {
        match ensure_user_allowed(&state, &application, &current.user).await {
            Ok(()) => return Ok(Redirect::to(&target.url).into_response()),
            Err(AppError::Unauthorized | AppError::Forbidden) => {}
            Err(err) => return Err(err),
        }
    }
    let finish = format!(
        "{LOGIN_FINISH_PATH}?return_to={}",
        util::url_encode(&target.url)
    );
    Ok(Redirect::to(&redirects::frontend_login_url(
        &finish,
        None,
        current.is_some(),
    ))
    .into_response())
}

async fn finish_login(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<IapLoginQuery>,
) -> AppResult<Response> {
    let target = target_from_url("GET", &query.return_to)?;
    let application = ensure_target_is_configured(&state, &target).await?;
    let current = auth::require_current_user(&state, &jar).await?;
    if !iap_session_can_access(&current) {
        let finish = format!(
            "{LOGIN_FINISH_PATH}?return_to={}",
            util::url_encode(&target.url)
        );
        return Ok(Redirect::to(&redirects::frontend_auth_error_url(
            Some(&finish),
            "temporary archived accounts cannot access protected applications",
        ))
        .into_response());
    }
    ensure_user_allowed(&state, &application, &current.user).await?;
    Ok(Redirect::to(&target.url).into_response())
}

fn iap_session_can_access(current: &auth::CurrentUser) -> bool {
    current.can_authorize_oauth_client()
}

async fn ensure_target_is_configured(
    state: &AppState,
    target: &IapTarget,
) -> AppResult<IapApplicationRecord> {
    let applications = state.db.active_iap_applications().await?;
    DefaultIapAccessPolicy
        .matching_application(target, &applications)
        .cloned()
        .ok_or_else(|| AppError::BadRequest("IAP target is not configured".to_string()))
}

async fn ensure_user_allowed(
    state: &AppState,
    application: &IapApplicationRecord,
    user: &crate::db::UserRecord,
) -> AppResult<()> {
    for permission in application.required_permissions()? {
        state
            .db
            .require_permission(user, Permission::try_from(permission.as_str())?)
            .await?;
    }
    let organizations = state.db.user_organizations(&user.id).await?;
    if DefaultIapAccessPolicy.permits_organization(application, &organizations)? {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

fn allow_response(
    application: &IapApplicationRecord,
    user: &crate::db::UserRecord,
    target: &IapTarget,
) -> AppResult<Response> {
    let mut response = StatusCode::NO_CONTENT.into_response();
    let headers = response.headers_mut();
    insert_header(headers, "x-gpt-sso-iap-application", &application.slug)?;
    insert_header(headers, "x-gpt-sso-iap-method", &target.method)?;
    insert_header(headers, "x-auth-request-user", &user.username)?;
    insert_header(headers, "x-auth-request-email", &user.email)?;
    insert_header(headers, "x-auth-request-user-id", &user.id)?;
    if let Some(display_name) = user.display_name.as_deref() {
        insert_header(headers, "x-auth-request-name", display_name)?;
    }
    Ok(response)
}

fn deny_response(status: StatusCode, reason: &'static str, login_url: Option<&str>) -> Response {
    let mut response = status.into_response();
    let headers = response.headers_mut();
    let _ = insert_header(headers, "x-gpt-sso-iap-decision", "deny");
    let _ = insert_header(headers, "x-gpt-sso-iap-reason", reason);
    if let Some(login_url) = login_url {
        if let Ok(value) = HeaderValue::from_str(login_url) {
            headers.insert(header::LOCATION, value);
        }
        let _ = insert_header(headers, "x-auth-request-redirect", login_url);
    }
    response
}

fn insert_header(headers: &mut HeaderMap, name: &'static str, value: &str) -> AppResult<()> {
    let name = HeaderName::from_static(name);
    let value = HeaderValue::from_str(value)
        .map_err(|_| AppError::Internal(format!("IAP header value is invalid: {name}")))?;
    headers.insert(name, value);
    Ok(())
}

fn login_start_url(target: &str) -> String {
    format!("{LOGIN_START_PATH}?return_to={}", util::url_encode(target))
}

pub fn normalize_iap_application(input: NewIapApplication) -> AppResult<NewIapApplication> {
    let slug = normalize_slug(&input.slug)?;
    let name = normalize_required_text(&input.name, "name")?;
    let description = input
        .description
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let external_host = normalize_external_host(&input.external_host)?;
    let path_prefix = normalize_path_prefix(&input.path_prefix)?;
    let required_organization_id = input
        .required_organization_id
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let required_organization_roles = normalize_roles(input.required_organization_roles)?;
    Ok(NewIapApplication {
        slug,
        name,
        description,
        external_host,
        path_prefix,
        required_organization_id,
        required_organization_roles,
        required_permissions: input.required_permissions,
        is_active: input.is_active,
    })
}

fn normalize_slug(value: &str) -> AppResult<String> {
    let value = value.trim().to_ascii_lowercase();
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(AppError::BadRequest(
            "IAP application slug must use lowercase letters, digits, or '-'".to_string(),
        ));
    }
    Ok(value)
}

fn normalize_required_text(value: &str, field: &str) -> AppResult<String> {
    let value = value.trim().to_string();
    if value.is_empty() {
        Err(AppError::BadRequest(format!("{field} is required")))
    } else {
        Ok(value)
    }
}

fn normalize_external_host(value: &str) -> AppResult<String> {
    let raw = value.trim().to_ascii_lowercase();
    let value = if let Some(suffix) = raw.strip_prefix("*.") {
        let suffix = suffix.trim_end_matches('.');
        if suffix.is_empty() {
            return Err(AppError::BadRequest("external_host is invalid".to_string()));
        }
        format!("*.{suffix}")
    } else {
        raw.trim_end_matches('.').to_string()
    };
    if value.is_empty()
        || value.contains('/')
        || value.contains('\\')
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(AppError::BadRequest("external_host is invalid".to_string()));
    }
    if value == "*" {
        return Ok(value);
    }
    if let Some(suffix) = value.strip_prefix("*.") {
        if suffix.is_empty() || suffix.contains('*') {
            return Err(AppError::BadRequest("external_host is invalid".to_string()));
        }
        return Ok(value);
    }
    if value.contains('*') || !value.chars().any(|ch| ch.is_ascii_alphanumeric()) {
        return Err(AppError::BadRequest("external_host is invalid".to_string()));
    }
    Ok(value)
}

fn normalize_path_prefix(value: &str) -> AppResult<String> {
    let mut value = value.trim().to_string();
    if value.is_empty() {
        value = "/".to_string();
    }
    if !value.starts_with('/')
        || value.starts_with("//")
        || value.contains('\\')
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(AppError::BadRequest("path_prefix is invalid".to_string()));
    }
    while value.len() > 1 && value.ends_with('/') {
        value.pop();
    }
    Ok(value)
}

fn normalize_roles(values: Vec<String>) -> AppResult<Vec<String>> {
    let mut roles = BTreeSet::new();
    for value in values {
        let value = value.trim().to_ascii_lowercase();
        if value.is_empty() {
            continue;
        }
        match value.as_str() {
            "owner" | "admin" | "member" => {
                roles.insert(value);
            }
            _ => {
                return Err(AppError::BadRequest(format!(
                    "unknown organization role: {value}"
                )));
            }
        }
    }
    Ok(roles.into_iter().collect())
}

fn target_from_request(target: Option<&str>, headers: &HeaderMap) -> AppResult<IapTarget> {
    let method = first_header(headers, "x-forwarded-method")
        .or_else(|| first_header(headers, "x-original-method"))
        .unwrap_or_else(|| "GET".to_string());
    if let Some(target) = target.map(str::trim).filter(|value| !value.is_empty()) {
        return target_from_url(&method, target);
    }
    for header_name in ["x-original-url", "x-forwarded-url"] {
        if let Some(value) = first_header(headers, header_name)
            && (value.starts_with("http://") || value.starts_with("https://"))
        {
            return target_from_url(&method, &value);
        }
    }
    let host = first_header(headers, "x-forwarded-host")
        .or_else(|| first_header(headers, "x-original-host"))
        .or_else(|| first_header(headers, "host"))
        .ok_or_else(|| AppError::BadRequest("IAP target host is missing".to_string()))?;
    let host = normalize_external_host(&host)?;
    let proto = first_header(headers, "x-forwarded-proto")
        .or_else(|| first_header(headers, "x-forwarded-scheme"))
        .unwrap_or_else(|| "https".to_string());
    let uri = first_header(headers, "x-forwarded-uri")
        .or_else(|| first_header(headers, "x-original-uri"))
        .or_else(|| first_header(headers, "x-request-uri"))
        .unwrap_or_else(|| "/".to_string());
    if uri.starts_with("http://") || uri.starts_with("https://") {
        return target_from_url(&method, &uri);
    }
    let uri = normalize_uri_reference(&uri)?;
    target_from_url(&method, &format!("{proto}://{host}{uri}"))
}

fn target_from_url(method: &str, value: &str) -> AppResult<IapTarget> {
    let url = Url::parse(value)
        .map_err(|_| AppError::BadRequest("IAP target URL is invalid".to_string()))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(AppError::BadRequest(
            "IAP target URL must be absolute http(s)".to_string(),
        ));
    }
    if url.fragment().is_some() || !url.username().is_empty() || url.password().is_some() {
        return Err(AppError::BadRequest(
            "IAP target URL is invalid".to_string(),
        ));
    }
    let host = normalize_external_host(
        url.host_str()
            .ok_or_else(|| AppError::BadRequest("IAP target host is missing".to_string()))?,
    )?;
    let host = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    };
    Ok(IapTarget {
        method: method.trim().to_ascii_uppercase(),
        url: url.to_string(),
        host,
        path: normalize_path_prefix(url.path())?,
    })
}

fn normalize_uri_reference(value: &str) -> AppResult<String> {
    let value = value.trim();
    if value.starts_with('/')
        && !value.starts_with("//")
        && !value.contains('\\')
        && !value.bytes().any(|byte| byte.is_ascii_control())
    {
        Ok(value.to_string())
    } else {
        Err(AppError::BadRequest(
            "IAP target URI is invalid".to_string(),
        ))
    }
}

fn first_header(headers: &HeaderMap, name: &'static str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn host_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let host = host.to_ascii_lowercase();
    if pattern == "*" || pattern == host {
        return true;
    }
    let Some(suffix) = pattern.strip_prefix("*.") else {
        return false;
    };
    host.ends_with(&format!(".{suffix}")) && host != suffix
}

fn path_matches(prefix: &str, path: &str) -> bool {
    prefix == "/" || path == prefix || path.starts_with(&format!("{prefix}/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(host: &str, prefix: &str) -> IapApplicationRecord {
        IapApplicationRecord {
            id: "id".to_string(),
            slug: "docs".to_string(),
            name: "Docs".to_string(),
            description: None,
            external_host: host.to_string(),
            path_prefix: prefix.to_string(),
            required_organization_id: None,
            required_organization_roles: "[]".to_string(),
            required_permissions: "[]".to_string(),
            is_active: 1,
            created_at: 1,
            updated_at: 1,
        }
    }

    #[test]
    fn path_prefix_requires_segment_boundary() {
        assert!(path_matches("/docs", "/docs"));
        assert!(path_matches("/docs", "/docs/file"));
        assert!(!path_matches("/docs", "/docs2"));
    }

    #[test]
    fn policy_matches_wildcard_hosts_and_longest_prefix() {
        let applications = vec![app("*.example.com", "/"), app("docs.example.com", "/admin")];
        let target = target_from_url("GET", "https://docs.example.com/admin/panel").unwrap();

        let matched = DefaultIapAccessPolicy
            .matching_application(&target, &applications)
            .unwrap();

        assert_eq!(matched.path_prefix, "/admin");
    }

    #[test]
    fn target_rejects_open_redirect_shapes() {
        assert!(target_from_url("GET", "https://app.example.com/path").is_ok());
        assert!(target_from_url("GET", "https://user@app.example.com/path").is_err());
        assert!(target_from_url("GET", "javascript:alert(1)").is_err());
        assert!(normalize_uri_reference("//app.example.com/path").is_err());
        assert!(normalize_external_host("*.example.com").is_ok());
        assert!(normalize_external_host("*").is_ok());
        assert!(normalize_external_host("*.").is_err());
        assert!(normalize_external_host("foo*bar.example.com").is_err());
    }

    #[test]
    fn normalizes_iap_application_input() {
        let normalized = normalize_iap_application(NewIapApplication {
            slug: "Docs-App".to_string(),
            name: " Docs ".to_string(),
            description: Some(" ".to_string()),
            external_host: "Docs.Example.COM".to_string(),
            path_prefix: "/docs/".to_string(),
            required_organization_id: Some(" ".to_string()),
            required_organization_roles: vec!["admin".to_string(), "member".to_string()],
            required_permissions: vec!["users.read".to_string()],
            is_active: true,
        })
        .unwrap();

        assert_eq!(normalized.slug, "docs-app");
        assert_eq!(normalized.external_host, "docs.example.com");
        assert_eq!(normalized.path_prefix, "/docs");
        assert!(normalized.description.is_none());
        assert!(normalized.required_organization_id.is_none());
    }

    #[test]
    fn temporary_authorization_code_sessions_cannot_access_iap() {
        let standard = current(auth::AccountSessionKind::Standard);
        let temporary = current(auth::AccountSessionKind::TemporaryAuthorizationCode);

        assert!(iap_session_can_access(&standard));
        assert!(!iap_session_can_access(&temporary));
    }

    fn current(session_kind: auth::AccountSessionKind) -> auth::CurrentUser {
        auth::CurrentUser {
            user: crate::db::UserRecord {
                id: "user-id".to_string(),
                email: "user@example.com".to_string(),
                username: "user".to_string(),
                display_name: None,
                phone: None,
                password_hash: "hash".to_string(),
                email_verified_at: None,
                phone_verified_at: None,
                is_admin: 0,
                is_active: 1,
                archived_at: (session_kind == auth::AccountSessionKind::TemporaryAuthorizationCode)
                    .then_some(1),
                registration_source: "local".to_string(),
                last_login_at: None,
                last_login_ip: None,
                last_oidc_client_id: None,
                last_login_method: None,
                created_at: 1,
                updated_at: 1,
            },
            session_id: "session-id".to_string(),
            session_kind,
        }
    }
}
