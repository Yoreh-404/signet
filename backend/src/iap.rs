use crate::{
    AppState,
    access::Permission,
    auth::{self, AccountCapabilities},
    db::{IapApplicationRecord, NewIapApplication, UserOrganizationRecord},
    error::{AppError, AppResult},
    redirects, util,
};
use axum::{
    Router,
    extract::{Query, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
    routing::get,
};
use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use url::Url;

const LOGIN_START_PATH: &str = "/api/iap/start";
const LOGIN_FINISH_PATH: &str = "/api/iap/finish";
// Keep the domain contract portable across SQLite/PostgreSQL/MySQL and keep
// assertion-backed legacy proxy headers within ordinary reverse-proxy limits.
// The host is ASCII by validation; path is capped by UTF-8 bytes because it is
// embedded in the signed assertion and therefore contributes directly to the
// HTTP header size after base64url expansion.
const MAX_IAP_NAME_CHARS: usize = 160;
const MAX_IAP_EXTERNAL_HOST_BYTES: usize = 255;
const MAX_IAP_PATH_PREFIX_BYTES: usize = 2_048;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/iap/forward-auth",
            get(forward_auth).post(forward_auth),
        )
        .route("/api/iap/bearer-auth", get(bearer_auth).post(bearer_auth))
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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct IapAuthorizationContext {
    organization: Option<String>,
    roles: Vec<String>,
    permissions: Vec<String>,
}

#[derive(Clone)]
pub(crate) struct IapCachedAuthorization {
    current: auth::CurrentUser,
    authorization: IapAuthorizationContext,
    assertion: String,
    audience: String,
    assertion_fingerprint: String,
    assertion_expires_at: i64,
    session_expires_at: i64,
}

impl IapCachedAuthorization {
    fn session_is_live(&self) -> bool {
        self.session_expires_at >= util::now_ts()
    }

    fn assertion_ttl_remaining_seconds(&self) -> i64 {
        self.assertion_expires_at.saturating_sub(util::now_ts())
    }

    fn can_reuse_assertion(&self, fingerprint: &str, ttl_seconds: i64) -> bool {
        let refresh_margin = (ttl_seconds / 10).clamp(1, 5);
        self.assertion_fingerprint == fingerprint
            && self.assertion_ttl_remaining_seconds() > refresh_margin
    }
}

#[derive(Serialize)]
struct IapAssertionFingerprint<'a> {
    issuer: &'a str,
    audience: &'a str,
    subject: &'a str,
    sid: &'a str,
    username: &'a str,
    email: &'a str,
    name: Option<&'a str>,
    iap_rule: &'a str,
    application_id: Option<&'a str>,
    host_pattern: &'a str,
    path_prefix: &'a str,
    organization: Option<&'a str>,
    roles: &'a [String],
    permissions: &'a [String],
}

#[derive(Debug, Clone, Default)]
pub(crate) struct IapRoutingIndex {
    exact_hosts: HashMap<String, Vec<IapApplicationRecord>>,
    wildcard_hosts: Vec<IapApplicationRecord>,
}

impl IapRoutingIndex {
    pub(crate) fn new(applications: Vec<IapApplicationRecord>) -> Self {
        let mut exact_hosts = HashMap::<String, Vec<IapApplicationRecord>>::new();
        let mut wildcard_hosts = Vec::new();
        for application in applications.into_iter().filter(|item| item.is_active == 1) {
            if application.external_host == "*" || application.external_host.starts_with("*.") {
                wildcard_hosts.push(application);
            } else {
                exact_hosts
                    .entry(application.external_host.to_ascii_lowercase())
                    .or_default()
                    .push(application);
            }
        }
        for rules in exact_hosts.values_mut() {
            sort_iap_rules(rules);
        }
        sort_iap_rules(&mut wildcard_hosts);
        Self {
            exact_hosts,
            wildcard_hosts,
        }
    }

    pub(crate) fn matching_application(&self, target: &IapTarget) -> Option<&IapApplicationRecord> {
        let host = target.host.to_ascii_lowercase();
        let exact = self.exact_hosts.get(&host).and_then(|rules| {
            rules
                .iter()
                .find(|application| path_matches(&application.path_prefix, &target.path))
        });
        let wildcard = self.wildcard_hosts.iter().find(|application| {
            host_matches(&application.external_host, &target.host)
                && path_matches(&application.path_prefix, &target.path)
        });
        match (exact, wildcard) {
            (Some(exact), Some(wildcard)) => {
                if exact.path_prefix.len() >= wildcard.path_prefix.len() {
                    Some(exact)
                } else {
                    Some(wildcard)
                }
            }
            (Some(exact), None) => Some(exact),
            (None, Some(wildcard)) => Some(wildcard),
            (None, None) => None,
        }
    }
}

fn sort_iap_rules(rules: &mut [IapApplicationRecord]) {
    rules.sort_by(|left, right| {
        right
            .path_prefix
            .len()
            .cmp(&left.path_prefix.len())
            .then_with(|| left.slug.cmp(&right.slug))
    });
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
    let Some(credential_id) = session_credential_id(&state, &jar) else {
        return Ok(login_required_response(&target));
    };
    let (routing, routing_generation) = state.iap_routing_snapshot().await?;
    let Some(application) = routing.matching_application(&target) else {
        // Keep the historical response ordering: an invalid/expired session
        // is still a login challenge rather than an oracle for configured
        // IAP hosts and paths.
        let Some(current) = auth::current_user_from_cookie(&state, &jar).await? else {
            return Ok(login_required_response(&target));
        };
        if !iap_session_can_access(&current) {
            return Ok(deny_response(
                StatusCode::FORBIDDEN,
                "temporary_account_not_allowed",
                None,
            ));
        }
        return Ok(deny_response(
            StatusCode::FORBIDDEN,
            "no_matching_application",
            None,
        ));
    };
    let cache_key = format!(
        "session:{credential_id}\n{}\n{routing_generation}",
        application.id
    );
    if let Some(cached) = state.iap_authorization_cache_entry(&cache_key)?
        && cached.session_is_live()
    {
        return allow_response(application, &target, &cached);
    }

    // Collapse a page-load burst onto one database authorization read. The
    // lock is per session+rule and weakly retained, so unrelated users never
    // serialize behind each other and historical sessions do not leak locks.
    // If another request is already refreshing this exact decision, peers may
    // use the previous decision only inside the separately configured short
    // stale-while-refresh window. There is no stale-on-error fallback.
    let refresh_lock = state.iap_authorization_refresh_lock(&cache_key)?;
    let _refresh = match refresh_lock.try_lock() {
        Ok(guard) => guard,
        Err(_) => {
            if let Some(cached) = state.iap_authorization_stale_while_refresh_entry(&cache_key)?
                && cached.session_is_live()
            {
                return allow_response(application, &target, &cached);
            }
            refresh_lock.lock().await
        }
    };
    if let Some(cached) = state.iap_authorization_cache_entry(&cache_key)?
        && cached.session_is_live()
    {
        return allow_response(application, &target, &cached);
    }
    let previous = state.iap_authorization_cache_entry_stale(&cache_key)?;

    let (session, current) = if let Some((session, user)) = state
        .db
        .find_standard_iap_session_by_credential(&credential_id)
        .await?
    {
        let current = auth::CurrentUser {
            user,
            session_id: session.id.clone(),
            session_kind: auth::AccountSessionKind::Standard,
        };
        (session, current)
    } else {
        // Preserve the general authentication path for invalid/restricted
        // sessions so the historical denial behavior and lifecycle
        // cleanup semantics remain unchanged off the successful hot path.
        let Some(session) = auth::session_from_cookie(&state, &jar).await? else {
            return Ok(login_required_response(&target));
        };
        let Some(current) = auth::current_user_from_session(&state, &session).await? else {
            return Ok(login_required_response(&target));
        };
        (session, current)
    };
    if !iap_session_can_access(&current) {
        return Ok(deny_response(
            StatusCode::FORBIDDEN,
            "temporary_account_not_allowed",
            None,
        ));
    }
    let authorization = ensure_user_allowed(&state, application, &current.user).await?;
    let cached = build_cached_authorization(
        &state,
        application,
        current,
        authorization,
        session.expires_at,
        previous.as_ref(),
    )
    .await?;
    state.store_iap_authorization_cache_entry(cache_key, cached.clone())?;
    allow_response(application, &target, &cached)
}

async fn bearer_auth(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ForwardAuthQuery>,
) -> AppResult<Response> {
    let target = target_from_request(query.target.as_deref(), &headers)?;
    let raw_token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.trim().is_empty())
        .ok_or(AppError::Unauthorized)?;
    let claims = crate::oidc::verify_iap_bearer_claims(&state, &headers, raw_token).await?;

    let (routing, routing_generation) = state.iap_routing_snapshot().await?;
    let application = routing
        .matching_application(&target)
        .ok_or(AppError::Forbidden)?;
    validate_bearer_iap_claims(&claims, application)?;

    let token_key = claims
        .jti
        .clone()
        .unwrap_or_else(|| util::sha256_base64url(raw_token));
    let cache_key = format!(
        "bearer:{token_key}\n{}\n{routing_generation}",
        application.id
    );
    if let Some(cached) = state.iap_authorization_cache_entry(&cache_key)?
        && cached.session_is_live()
    {
        return allow_response(application, &target, &cached);
    }

    let refresh_lock = state.iap_authorization_refresh_lock(&cache_key)?;
    let _refresh = match refresh_lock.try_lock() {
        Ok(guard) => guard,
        Err(_) => {
            if let Some(cached) = state.iap_authorization_stale_while_refresh_entry(&cache_key)?
                && cached.session_is_live()
            {
                return allow_response(application, &target, &cached);
            }
            refresh_lock.lock().await
        }
    };
    if let Some(cached) = state.iap_authorization_cache_entry(&cache_key)?
        && cached.session_is_live()
    {
        return allow_response(application, &target, &cached);
    }
    let previous = state.iap_authorization_cache_entry_stale(&cache_key)?;

    let user = crate::oidc::live_iap_bearer_user_from_claims(&state, &claims).await?;
    let authorization = ensure_user_allowed(&state, application, &user).await?;
    let session_seed = claims
        .sid
        .clone()
        .or(claims.grant_id.clone())
        .or(claims.jti.clone())
        .unwrap_or_else(|| format!("{}:{}:{}", claims.client_id, claims.sub, claims.iat));
    // build_cached_authorization only needs a user plus an opaque seed for the
    // public `sid` projection here; no browser session is created or trusted.
    let current = auth::CurrentUser {
        user,
        session_id: session_seed,
        session_kind: auth::AccountSessionKind::Standard,
    };
    let cached = build_cached_authorization(
        &state,
        application,
        current,
        authorization,
        claims.exp,
        previous.as_ref(),
    )
    .await?;
    state.store_iap_authorization_cache_entry(cache_key, cached.clone())?;
    allow_response(application, &target, &cached)
}

fn validate_bearer_iap_claims(
    claims: &crate::jwt::TokenClaims,
    application: &IapApplicationRecord,
) -> AppResult<()> {
    if !claims
        .scope
        .split_whitespace()
        .any(|scope| scope == "iap.assert")
    {
        return Err(AppError::Forbidden);
    }
    // The edge profile uses a first-party access token whose audience is the
    // edge client itself. A token deliberately minted for another resource
    // must not become interchangeable with a browser/IAP credential merely
    // because it happens to carry the same scope.
    if claims.aud != claims.client_id {
        return Err(AppError::Forbidden);
    }
    let rule_application_id = application
        .application_id
        .as_deref()
        .ok_or(AppError::Forbidden)?;
    if claims.application_id.as_deref() != Some(rule_application_id) {
        return Err(AppError::Forbidden);
    }
    Ok(())
}

fn session_credential_id(state: &AppState, jar: &CookieJar) -> Option<String> {
    let cookie = jar.get(&state.settings.security.cookie_name)?;
    util::session_id_from_cookie(cookie.value())
}

fn login_required_response(target: &IapTarget) -> Response {
    deny_response(
        StatusCode::UNAUTHORIZED,
        "login_required",
        Some(&login_start_url(&target.url)),
    )
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
            Ok(_) => return Ok(Redirect::to(&target.url).into_response()),
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
    let _ = ensure_user_allowed(&state, &application, &current.user).await?;
    Ok(Redirect::to(&target.url).into_response())
}

fn iap_session_can_access(current: &auth::CurrentUser) -> bool {
    current.can_authorize_oauth_client()
}

async fn ensure_target_is_configured(
    state: &AppState,
    target: &IapTarget,
) -> AppResult<IapApplicationRecord> {
    let routing = state.iap_routing_index().await?;
    routing
        .matching_application(target)
        .cloned()
        .ok_or_else(|| AppError::BadRequest("IAP target is not configured".to_string()))
}

async fn ensure_user_allowed(
    state: &AppState,
    application: &IapApplicationRecord,
    user: &crate::db::UserRecord,
) -> AppResult<IapAuthorizationContext> {
    let required_permissions = application
        .required_permissions()?
        .into_iter()
        .map(|permission| Permission::try_from(permission.as_str()))
        .collect::<AppResult<Vec<_>>>()?;
    if !crate::access::user_can_hold_permissions(user) {
        return Err(AppError::Forbidden);
    }
    let projected_permissions = required_permissions
        .iter()
        .map(|permission| permission.as_str().to_string())
        .collect::<Vec<_>>();
    if user.is_admin != 1 && !projected_permissions.is_empty() {
        let required = projected_permissions
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        if !state
            .db
            .has_all_effective_permissions(&user.id, &required)
            .await?
        {
            return Err(AppError::Forbidden);
        }
    }
    let organization = application.required_organization_id.clone();
    let roles = if let Some(required_id) = organization.as_deref() {
        let membership = state
            .db
            .find_active_organization_membership(&user.id, required_id)
            .await?
            .ok_or(AppError::Forbidden)?;
        let required_roles = application.required_organization_roles()?;
        if !required_roles.is_empty() && !required_roles.iter().any(|role| role == &membership.role)
        {
            return Err(AppError::Forbidden);
        }
        vec![membership.role]
    } else {
        Vec::new()
    };
    Ok(IapAuthorizationContext {
        organization,
        roles,
        permissions: projected_permissions,
    })
}

async fn build_cached_authorization(
    state: &AppState,
    application: &IapApplicationRecord,
    current: auth::CurrentUser,
    authorization: IapAuthorizationContext,
    session_expires_at: i64,
    previous: Option<&IapCachedAuthorization>,
) -> AppResult<IapCachedAuthorization> {
    let user = &current.user;
    let runtime = state.runtime_settings().await?;
    // Bind the assertion audience to the immutable rule id rather than its
    // human-readable slug. A slug can be reused after rule deletion while a
    // previously issued short-lived assertion is still valid; the id keeps
    // those two rule lifecycles cryptographically distinct.
    let audience = format!("signet:iap:{}", application.id);
    let public_sid = util::session_public_id(&current.session_id);
    let assertion_fingerprint = iap_assertion_fingerprint(
        &runtime.issuer,
        &audience,
        &current,
        &public_sid,
        application,
        &authorization,
    )?;
    let ttl_seconds = state.settings.security.iap_assertion_ttl_seconds;
    let (assertion, assertion_expires_at) = if let Some(previous) = previous
        .filter(|previous| previous.can_reuse_assertion(&assertion_fingerprint, ttl_seconds))
    {
        (previous.assertion.clone(), previous.assertion_expires_at)
    } else {
        let expires_at = util::now_ts().saturating_add(ttl_seconds);
        let assertion = state.jwt.sign_iap_assertion(
            &runtime.issuer,
            &audience,
            &user.id,
            &public_sid,
            &user.username,
            &user.email,
            user.display_name.as_deref(),
            &application.slug,
            application.application_id.as_deref(),
            &application.external_host,
            &application.path_prefix,
            authorization.organization.as_deref(),
            authorization.roles.clone(),
            authorization.permissions.clone(),
            ttl_seconds,
        )?;
        (assertion, expires_at)
    };
    Ok(IapCachedAuthorization {
        current,
        authorization,
        assertion,
        audience,
        assertion_fingerprint,
        assertion_expires_at,
        session_expires_at,
    })
}

fn iap_assertion_fingerprint(
    issuer: &str,
    audience: &str,
    current: &auth::CurrentUser,
    public_sid: &str,
    application: &IapApplicationRecord,
    authorization: &IapAuthorizationContext,
) -> AppResult<String> {
    let claims = IapAssertionFingerprint {
        issuer,
        audience,
        subject: &current.user.id,
        sid: public_sid,
        username: &current.user.username,
        email: &current.user.email,
        name: current.user.display_name.as_deref(),
        iap_rule: &application.slug,
        application_id: application.application_id.as_deref(),
        host_pattern: &application.external_host,
        path_prefix: &application.path_prefix,
        organization: authorization.organization.as_deref(),
        roles: &authorization.roles,
        permissions: &authorization.permissions,
    };
    let canonical = serde_json::to_string(&claims).map_err(|error| {
        AppError::Internal(format!(
            "failed to fingerprint IAP assertion claims: {error}"
        ))
    })?;
    Ok(util::sha256_base64url(&canonical))
}

fn allow_response(
    application: &IapApplicationRecord,
    target: &IapTarget,
    cached: &IapCachedAuthorization,
) -> AppResult<Response> {
    let user = &cached.current.user;
    let authorization = &cached.authorization;
    let mut response = StatusCode::NO_CONTENT.into_response();
    let headers = response.headers_mut();
    mark_iap_response_private(headers);
    insert_header(headers, "x-gpt-sso-iap-decision", "allow")?;
    insert_header(headers, "x-gpt-sso-iap-application", &application.slug)?;
    insert_header(headers, "x-gpt-sso-iap-method", &target.method)?;
    insert_header(headers, "x-auth-request-user", &user.username)?;
    insert_header(headers, "x-auth-request-email", &user.email)?;
    insert_header(headers, "x-auth-request-user-id", &user.id)?;
    insert_header(headers, "x-forwarded-user", &user.username)?;
    insert_header(headers, "x-forwarded-email", &user.email)?;
    insert_header(headers, "x-signet-subject", &user.id)?;
    insert_header(headers, "x-signet-email", &user.email)?;
    insert_header(headers, "x-signet-assertion", &cached.assertion)?;
    insert_header(headers, "x-signet-assertion-audience", &cached.audience)?;
    insert_header(
        headers,
        "x-signet-assertion-expires-in",
        &cached.assertion_ttl_remaining_seconds().max(0).to_string(),
    )?;
    if let Some(organization) = authorization.organization.as_deref() {
        insert_header(headers, "x-signet-organization", organization)?;
    }
    if !authorization.roles.is_empty() {
        insert_header(headers, "x-signet-roles", &authorization.roles.join(","))?;
    }
    if !authorization.permissions.is_empty() {
        insert_header(
            headers,
            "x-signet-permissions",
            &authorization.permissions.join(","),
        )?;
    }
    if let Some(display_name) = user.display_name.as_deref() {
        insert_header(headers, "x-auth-request-name", display_name)?;
        insert_header(headers, "x-signet-name", display_name)?;
    }
    Ok(response)
}

fn deny_response(status: StatusCode, reason: &'static str, login_url: Option<&str>) -> Response {
    let mut response = status.into_response();
    let headers = response.headers_mut();
    mark_iap_response_private(headers);
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

fn mark_iap_response_private(headers: &mut HeaderMap) {
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, private"),
    );
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(header::VARY, HeaderValue::from_static("Cookie"));
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
    let name = normalize_required_text(&input.name, "name", MAX_IAP_NAME_CHARS)?;
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
        application_id: input.application_id,
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

fn normalize_required_text(value: &str, field: &str, max_chars: usize) -> AppResult<String> {
    let value = value.trim().to_string();
    if value.is_empty() {
        Err(AppError::BadRequest(format!("{field} is required")))
    } else if value.chars().count() > max_chars {
        Err(AppError::BadRequest(format!(
            "{field} must not exceed {max_chars} characters"
        )))
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
        || value.len() > MAX_IAP_EXTERNAL_HOST_BYTES
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
    if value.len() > MAX_IAP_PATH_PREFIX_BYTES {
        return Err(AppError::BadRequest(format!(
            "path_prefix must not exceed {MAX_IAP_PATH_PREFIX_BYTES} UTF-8 bytes"
        )));
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
    let method = Method::from_bytes(method.trim().as_bytes())
        .map_err(|_| AppError::BadRequest("IAP target method is invalid".to_string()))?;
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
        method: method.as_str().to_string(),
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
            application_id: Some("application-id".to_string()),
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
    fn routing_index_prefers_exact_host_and_longest_prefix() {
        let mut wildcard = app("*.example.com", "/admin");
        wildcard.slug = "wildcard".to_string();
        let mut root = app("docs.example.com", "/");
        root.slug = "root".to_string();
        let mut exact = app("docs.example.com", "/admin");
        exact.slug = "exact".to_string();
        let index = IapRoutingIndex::new(vec![wildcard, root, exact]);

        let admin = target_from_url("GET", "https://docs.example.com/admin/panel").unwrap();
        assert_eq!(index.matching_application(&admin).unwrap().slug, "exact");

        let root = target_from_url("GET", "https://docs.example.com/home").unwrap();
        assert_eq!(index.matching_application(&root).unwrap().slug, "root");

        let wildcard = target_from_url("GET", "https://other.example.com/admin/panel").unwrap();
        assert_eq!(
            index.matching_application(&wildcard).unwrap().slug,
            "wildcard"
        );
    }

    #[test]
    fn routing_index_preserves_longest_prefix_before_exact_host_tiebreak() {
        let mut exact_root = app("docs.example.com", "/");
        exact_root.slug = "exact-root".to_string();
        let mut wildcard_admin = app("*.example.com", "/admin");
        wildcard_admin.slug = "wildcard-admin".to_string();
        let index = IapRoutingIndex::new(vec![exact_root, wildcard_admin]);
        let target = target_from_url("GET", "https://docs.example.com/admin/panel").unwrap();

        assert_eq!(
            index.matching_application(&target).unwrap().slug,
            "wildcard-admin"
        );
    }

    #[test]
    fn target_rejects_open_redirect_shapes() {
        assert!(target_from_url("GET", "https://app.example.com/path").is_ok());
        assert!(target_from_url("NOT A METHOD", "https://app.example.com/path").is_err());
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
            application_id: "application-id".to_string(),
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
    fn iap_contract_enforces_portable_proxy_safe_length_limits() {
        let mut oversized_name = app("docs.example.com", "/");
        assert!(
            normalize_required_text(
                &"x".repeat(MAX_IAP_NAME_CHARS + 1),
                "name",
                MAX_IAP_NAME_CHARS,
            )
            .is_err()
        );

        oversized_name.external_host = format!("{}.example.com", "a".repeat(245));
        assert!(normalize_external_host(&oversized_name.external_host).is_err());

        assert!(
            normalize_path_prefix(&format!("/{}", "a".repeat(MAX_IAP_PATH_PREFIX_BYTES))).is_err()
        );
        assert!(
            normalize_path_prefix(&format!("/{}", "a".repeat(MAX_IAP_PATH_PREFIX_BYTES - 1)))
                .is_ok()
        );
    }

    #[test]
    fn temporary_authorization_code_sessions_cannot_access_iap() {
        let standard = current(auth::AccountSessionKind::Standard);
        let temporary = current(auth::AccountSessionKind::TemporaryAuthorizationCode);

        assert!(iap_session_can_access(&standard));
        assert!(!iap_session_can_access(&temporary));
    }

    #[test]
    fn forward_auth_responses_are_private_and_keep_legacy_identity_headers() {
        let application = app("docs.example.com", "/");
        let target = target_from_url("GET", "https://docs.example.com/private").unwrap();
        let cached = IapCachedAuthorization {
            current: current(auth::AccountSessionKind::Standard),
            authorization: IapAuthorizationContext {
                organization: Some("org-id".to_string()),
                roles: vec!["member".to_string()],
                permissions: vec!["users.read".to_string()],
            },
            assertion: "signed-assertion".to_string(),
            audience: "signet:iap:id".to_string(),
            assertion_fingerprint: "fingerprint".to_string(),
            assertion_expires_at: util::now_ts() + 30,
            session_expires_at: util::now_ts() + 60,
        };

        let response = allow_response(&application, &target, &cached).unwrap();
        let headers = response.headers();
        assert_eq!(
            headers.get(header::CACHE_CONTROL).unwrap(),
            "no-store, private"
        );
        assert_eq!(headers.get("x-gpt-sso-iap-decision").unwrap(), "allow");
        assert_eq!(headers.get("x-auth-request-user").unwrap(), "user");
        assert_eq!(headers.get("x-forwarded-user").unwrap(), "user");
        assert_eq!(headers.get("x-signet-subject").unwrap(), "user-id");
        assert_eq!(
            headers.get("x-signet-assertion").unwrap(),
            "signed-assertion"
        );
        assert_eq!(
            headers.get("x-signet-assertion-audience").unwrap(),
            "signet:iap:id"
        );

        let denied = deny_response(StatusCode::FORBIDDEN, "forbidden", None);
        assert_eq!(
            denied.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store, private"
        );
        assert_eq!(
            denied.headers().get("x-gpt-sso-iap-decision").unwrap(),
            "deny"
        );
    }

    #[test]
    fn bearer_iap_claims_require_dedicated_scope_and_same_application() {
        let application = app("docs.example.com", "/");
        let mut claims = bearer_claims();

        assert!(validate_bearer_iap_claims(&claims, &application).is_ok());

        claims.scope = "openid profile".to_string();
        assert!(matches!(
            validate_bearer_iap_claims(&claims, &application),
            Err(AppError::Forbidden)
        ));

        claims.scope = "openid iap.assert.other".to_string();
        assert!(matches!(
            validate_bearer_iap_claims(&claims, &application),
            Err(AppError::Forbidden)
        ));

        claims.scope = "openid iap.assert".to_string();
        claims.aud = "https://api.example.test".to_string();
        assert!(matches!(
            validate_bearer_iap_claims(&claims, &application),
            Err(AppError::Forbidden)
        ));

        claims.aud = claims.client_id.clone();
        claims.application_id = Some("other-application".to_string());
        assert!(matches!(
            validate_bearer_iap_claims(&claims, &application),
            Err(AppError::Forbidden)
        ));

        let mut unbound_rule = application;
        unbound_rule.application_id = None;
        claims.application_id = Some("application-id".to_string());
        assert!(matches!(
            validate_bearer_iap_claims(&claims, &unbound_rule),
            Err(AppError::Forbidden)
        ));
    }

    #[test]
    fn cached_iap_authorization_never_extends_session_expiry() {
        let mut cached = IapCachedAuthorization {
            current: current(auth::AccountSessionKind::Standard),
            authorization: IapAuthorizationContext::default(),
            assertion: "assertion".to_string(),
            audience: "signet:iap:id".to_string(),
            assertion_fingerprint: "fingerprint".to_string(),
            assertion_expires_at: util::now_ts() + 30,
            session_expires_at: util::now_ts() + 60,
        };
        assert!(cached.session_is_live());
        cached.session_expires_at = util::now_ts() - 1;
        assert!(!cached.session_is_live());
    }

    #[test]
    fn cached_iap_assertion_is_reused_only_while_claims_and_ttl_are_safe() {
        let mut cached = IapCachedAuthorization {
            current: current(auth::AccountSessionKind::Standard),
            authorization: IapAuthorizationContext::default(),
            assertion: "assertion".to_string(),
            audience: "signet:iap:id".to_string(),
            assertion_fingerprint: "fingerprint".to_string(),
            assertion_expires_at: util::now_ts() + 30,
            session_expires_at: util::now_ts() + 60,
        };
        assert!(cached.can_reuse_assertion("fingerprint", 30));
        assert!(!cached.can_reuse_assertion("changed", 30));

        cached.assertion_expires_at = util::now_ts() + 3;
        assert!(!cached.can_reuse_assertion("fingerprint", 30));
    }

    fn bearer_claims() -> crate::jwt::TokenClaims {
        crate::jwt::TokenClaims {
            iss: "https://sso.example.com".to_string(),
            sub: "user-id".to_string(),
            aud: "legacy-edge".to_string(),
            exp: util::now_ts() + 300,
            iat: util::now_ts(),
            jti: Some("token-id".to_string()),
            token_use: "access_token".to_string(),
            client_id: "legacy-edge".to_string(),
            application_id: Some("application-id".to_string()),
            authorization_profile_id: Some("default".to_string()),
            scope: "openid profile email iap.assert".to_string(),
            email: "user@example.com".to_string(),
            email_verified: true,
            name: Some("User".to_string()),
            preferred_username: "user".to_string(),
            nonce: None,
            auth_time: None,
            sid: Some("browser-session".to_string()),
            cnf: None,
            authorization_details: None,
            act: None,
            grant_id: Some("grant-id".to_string()),
            gpt_sso_login_code_level: None,
        }
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
