//! Application-scoped CAS 2.0 identity provider.
//!
//! CAS is deliberately modeled as a ticket protocol, not as another account
//! membership system.  A service URL is an application configuration boundary;
//! the ticket only proves that an active Signet account passed the normal
//! application authorization calculation.

use crate::{
    AppState, applications, auth,
    auth::AccountCapabilities,
    authorization,
    db::{ApplicationRecord, NewApplicationCasTicket},
    error::{AppError, AppResult},
    redirects, util,
};
use axum::{
    Router,
    extract::{Path, Query, State},
    http::{HeaderValue, header},
    response::{IntoResponse, Redirect, Response},
    routing::get,
};
use axum_extra::extract::cookie::CookieJar;
use reqwest::Client;
use serde::Deserialize;
use serde_json::{Map, Value};
use url::Url;

const CAS_NAMESPACE: &str = "http://www.yale.edu/tp/cas";
const CAS_SERVICE_TICKET: &str = "service";
const CAS_PROXY_TICKET: &str = "proxy";
const CAS_PROXY_GRANTING_TICKET: &str = "proxy_granting";
const DEFAULT_TICKET_TTL_SECONDS: i64 = 300;
const DEFAULT_PGT_TTL_SECONDS: i64 = 300;
const MAX_TICKET_TTL_SECONDS: i64 = 600;
const MAX_PGT_TTL_SECONDS: i64 = 86_400;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/cas/{app}/login", get(login))
        .route("/cas/{app}/serviceValidate", get(service_validate))
        .route("/cas/{app}/p3/serviceValidate", get(p3_service_validate))
        .route("/cas/{app}/proxyValidate", get(proxy_validate))
        .route("/cas/{app}/proxy", get(proxy))
        .route("/cas/{app}/logout", get(logout))
}

#[derive(Debug, Clone)]
struct CasApplicationConfig {
    service_urls: Vec<String>,
    proxy_callback_urls: Vec<String>,
    allow_proxy: bool,
    ticket_ttl_seconds: i64,
    pgt_ttl_seconds: i64,
}

#[derive(Debug, Deserialize)]
struct CasLoginQuery {
    service: String,
    renew: Option<String>,
    gateway: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CasValidateQuery {
    service: Option<String>,
    ticket: Option<String>,
    #[serde(rename = "pgtUrl")]
    pgt_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CasProxyQuery {
    pgt: Option<String>,
    #[serde(rename = "targetService")]
    target_service: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CasLogoutQuery {
    service: Option<String>,
}

#[derive(Debug)]
struct CasProtocolFailure {
    code: &'static str,
    detail: &'static str,
}

impl CasProtocolFailure {
    const fn new(code: &'static str, detail: &'static str) -> Self {
        Self { code, detail }
    }
}

async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(app_slug): Path<String>,
    Query(query): Query<CasLoginQuery>,
) -> AppResult<Response> {
    let (application, config) = load_application(&state, &app_slug).await?;
    validate_service(&config, &query.service)?;
    let renew = flag(query.renew.as_deref());
    let gateway = flag(query.gateway.as_deref());
    let return_to = cas_login_return_to(&app_slug, &query)?;

    let current = auth::current_user_from_cookie(&state, &jar).await?;
    if let Some(current) = current {
        if !renew {
            return issue_service_ticket(&state, &application, &config, &query.service, &current)
                .await;
        }
    } else if gateway {
        // CAS gateway mode is explicitly non-interactive: an unauthenticated
        // browser returns to the service without a ticket.
        return Ok(Redirect::to(&query.service).into_response());
    }

    let login_url = redirects::frontend_login_url(&return_to, None, true);
    Ok(Redirect::to(&login_url).into_response())
}

async fn service_validate(
    State(state): State<AppState>,
    Path(app_slug): Path<String>,
    Query(query): Query<CasValidateQuery>,
) -> AppResult<Response> {
    validate_ticket_endpoint(&state, &app_slug, query, false, false).await
}

async fn p3_service_validate(
    State(state): State<AppState>,
    Path(app_slug): Path<String>,
    Query(query): Query<CasValidateQuery>,
) -> AppResult<Response> {
    validate_ticket_endpoint(&state, &app_slug, query, true, false).await
}

async fn proxy_validate(
    State(state): State<AppState>,
    Path(app_slug): Path<String>,
    Query(query): Query<CasValidateQuery>,
) -> AppResult<Response> {
    validate_ticket_endpoint(&state, &app_slug, query, true, true).await
}

async fn validate_ticket_endpoint(
    state: &AppState,
    app_slug: &str,
    query: CasValidateQuery,
    include_attributes: bool,
    allow_proxy_ticket: bool,
) -> AppResult<Response> {
    let (application, config) = load_application(state, app_slug).await?;
    let Some(service) = query
        .service
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(cas_failure("INVALID_REQUEST", "service is required"));
    };
    if validate_service(&config, service).is_err() {
        return Ok(cas_failure("INVALID_SERVICE", "service is not registered"));
    }
    let Some(ticket) = query
        .ticket
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(cas_failure("INVALID_TICKET", "ticket is required"));
    };
    if !valid_ticket_value(ticket) {
        return Ok(cas_failure("INVALID_TICKET", "ticket is invalid"));
    }

    let callback = match validate_pgt_url(&config, query.pgt_url.as_deref()) {
        Ok(callback) => callback,
        Err(failure) => return Ok(cas_failure(failure.code, failure.detail)),
    };
    let accepted_types = if allow_proxy_ticket {
        vec![CAS_SERVICE_TICKET, CAS_PROXY_TICKET]
    } else {
        vec![CAS_SERVICE_TICKET]
    };
    let record = match state
        .db
        .consume_application_cas_ticket(
            &util::token_hash(ticket),
            &application.id,
            service,
            &accepted_types,
        )
        .await
    {
        Ok(record) => record,
        Err(AppError::Unauthorized) => {
            return Ok(cas_failure(
                "INVALID_TICKET",
                "ticket is invalid or expired",
            ));
        }
        Err(error) => return Err(error),
    };
    let Some(user) = state
        .db
        .find_user_by_id(&record.user_id)
        .await?
        .filter(|user| user.is_active == 1 && user.archived_at.is_none())
    else {
        return Ok(cas_failure("INVALID_TICKET", "account is no longer active"));
    };
    let entitlements = match authorization::resolve_entitlements(state, &application, &user).await {
        Ok(entitlements) => entitlements,
        Err(AppError::Forbidden) => {
            return Ok(cas_failure("INVALID_TICKET", "account is not authorized"));
        }
        Err(error) => return Err(error),
    };
    let pgt_iou = if let Some(callback) = callback {
        match issue_proxy_grant(state, &application, &config, &user, &callback).await? {
            Ok(iou) => Some(iou),
            Err(failure) => return Ok(cas_failure(failure.code, failure.detail)),
        }
    } else {
        None
    };
    Ok(cas_success(
        &user,
        &entitlements,
        pgt_iou.as_deref(),
        include_attributes,
    ))
}

async fn proxy(
    State(state): State<AppState>,
    Path(app_slug): Path<String>,
    Query(query): Query<CasProxyQuery>,
) -> AppResult<Response> {
    let (application, config) = load_application(&state, &app_slug).await?;
    if !config.allow_proxy {
        return Ok(cas_failure(
            "UNAUTHORIZED_PROXYING",
            "proxy tickets are disabled",
        ));
    }
    let Some(pgt) = query
        .pgt
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(cas_failure("INVALID_TICKET", "pgt is required"));
    };
    let Some(target_service) = query
        .target_service
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(cas_failure("INVALID_REQUEST", "targetService is required"));
    };
    if validate_service(&config, target_service).is_err() {
        return Ok(cas_failure(
            "INVALID_SERVICE",
            "targetService is not registered for this application",
        ));
    }
    if !valid_ticket_value(pgt) {
        return Ok(cas_failure("INVALID_TICKET", "pgt is invalid"));
    }
    let Some(pgt_record) = state
        .db
        .find_application_cas_ticket(
            &util::token_hash(pgt),
            &application.id,
            CAS_PROXY_GRANTING_TICKET,
        )
        .await?
    else {
        return Ok(cas_failure("INVALID_TICKET", "pgt is invalid or expired"));
    };
    // A PGT is bound to the callback URL that accepted it.  Re-check the
    // current application configuration here as well as when the PGT is
    // issued, so removing a callback immediately invalidates outstanding
    // grants instead of leaving an old integration boundary usable.
    if !config
        .proxy_callback_urls
        .iter()
        .any(|callback| callback == &pgt_record.service)
    {
        return Ok(cas_failure(
            "INVALID_TICKET",
            "pgt callback is no longer registered",
        ));
    }
    let Some(user) = state
        .db
        .find_user_by_id(&pgt_record.user_id)
        .await?
        .filter(|user| user.is_active == 1 && user.archived_at.is_none())
    else {
        return Ok(cas_failure("INVALID_TICKET", "account is no longer active"));
    };
    if authorization::resolve_entitlements(&state, &application, &user)
        .await
        .is_err()
    {
        return Ok(cas_failure("INVALID_TICKET", "account is not authorized"));
    }

    let raw_ticket = format!("PT-{}", util::random_token(32));
    state
        .db
        .insert_application_cas_ticket(NewApplicationCasTicket {
            ticket_hash: util::token_hash(&raw_ticket),
            application_id: application.id,
            ticket_type: CAS_PROXY_TICKET.to_string(),
            service: target_service.to_string(),
            user_id: user.id,
            parent_ticket_hash: Some(util::token_hash(pgt)),
            pgt_iou: None,
            expires_at: util::now_ts() + config.ticket_ttl_seconds,
        })
        .await?;
    Ok(cas_proxy_success(&raw_ticket))
}

async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(app_slug): Path<String>,
    Query(query): Query<CasLogoutQuery>,
) -> AppResult<Response> {
    let (_, config) = load_application(&state, &app_slug).await?;
    if let Some(service) = query.service.as_deref() {
        validate_service(&config, service)?;
    }
    if let Some(current) = auth::current_user_from_cookie(&state, &jar).await? {
        state.db.delete_session(&current.session_id).await?;
    }
    Ok(query
        .service
        .as_deref()
        .map(Redirect::to)
        .unwrap_or_else(|| Redirect::to("/"))
        .into_response())
}

async fn issue_service_ticket(
    state: &AppState,
    application: &ApplicationRecord,
    config: &CasApplicationConfig,
    service: &str,
    current: &auth::CurrentUser,
) -> AppResult<Response> {
    if !current.can_authorize_oauth_client() {
        return Err(AppError::Forbidden);
    }
    authorization::resolve_entitlements(state, application, &current.user).await?;
    let raw_ticket = format!("ST-{}", util::random_token(32));
    state
        .db
        .insert_application_cas_ticket(NewApplicationCasTicket {
            ticket_hash: util::token_hash(&raw_ticket),
            application_id: application.id.clone(),
            ticket_type: CAS_SERVICE_TICKET.to_string(),
            service: service.to_string(),
            user_id: current.user.id.clone(),
            parent_ticket_hash: None,
            pgt_iou: None,
            expires_at: util::now_ts() + config.ticket_ttl_seconds,
        })
        .await?;
    let target = append_ticket(service, &raw_ticket)?;
    Ok(Redirect::to(&target).into_response())
}

async fn issue_proxy_grant(
    state: &AppState,
    application: &ApplicationRecord,
    config: &CasApplicationConfig,
    user: &crate::db::UserRecord,
    callback: &str,
) -> AppResult<Result<String, CasProtocolFailure>> {
    if !config.allow_proxy {
        return Ok(Err(CasProtocolFailure::new(
            "INVALID_PROXY_CALLBACK",
            "proxying is disabled",
        )));
    }
    let raw_pgt = format!("PGT-{}", util::random_token(32));
    let pgt_iou = format!("PGTIOU-{}", util::random_token(24));
    let pgt_hash = util::token_hash(&raw_pgt);
    state
        .db
        .insert_application_cas_ticket(NewApplicationCasTicket {
            ticket_hash: pgt_hash.clone(),
            application_id: application.id.clone(),
            ticket_type: CAS_PROXY_GRANTING_TICKET.to_string(),
            service: callback.to_string(),
            user_id: user.id.clone(),
            parent_ticket_hash: None,
            pgt_iou: Some(pgt_iou.clone()),
            expires_at: util::now_ts() + config.pgt_ttl_seconds,
        })
        .await?;
    let callback_url = append_callback_parameters(callback, &pgt_iou, &raw_pgt)?;
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        // A registered callback is an explicit integration boundary. Do not
        // follow a callback-controlled redirect into a second host, which
        // would turn the CAS PGT exchange into an SSRF primitive.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|err| AppError::Internal(format!("failed to build CAS proxy client: {err}")))?;
    let callback_ok = client
        .get(callback_url)
        .header(reqwest::header::ACCEPT, "text/plain, */*")
        .send()
        .await
        .is_ok_and(|response| response.status().is_success());
    if !callback_ok {
        state.db.revoke_application_cas_ticket(&pgt_hash).await?;
        return Ok(Err(CasProtocolFailure::new(
            "INVALID_PROXY_CALLBACK",
            "proxy callback did not accept the granting ticket",
        )));
    }
    Ok(Ok(pgt_iou))
}

async fn load_application(
    state: &AppState,
    app_slug: &str,
) -> AppResult<(ApplicationRecord, CasApplicationConfig)> {
    let application = state
        .db
        .find_active_application_by_slug(app_slug)
        .await?
        .ok_or(AppError::NotFound)?;
    applications::ensure_application_runtime_active(state, &application).await?;
    let protocol = applications::enabled_protocol_config(state, &application.id, "cas")
        .await?
        .ok_or(AppError::NotFound)?;
    let mut config = parse_cas_config(&protocol)?;
    if config.service_urls.is_empty()
        && let Some(website_url) =
            applications::application_website_url(state, &application.id).await?
    {
        validate_service_url(&website_url)?;
        config.service_urls.push(website_url);
    }
    if config.service_urls.is_empty() {
        return Err(AppError::Configuration(
            "CAS requires at least one registered service URL".to_string(),
        ));
    }
    Ok((application, config))
}

fn parse_cas_config(config: &Map<String, Value>) -> AppResult<CasApplicationConfig> {
    let mut service_urls = string_list(config, "service_urls")?;
    if service_urls.is_empty()
        && let Some(value) = config.get("service_validate_url").and_then(Value::as_str)
    {
        if !value.trim().is_empty() {
            service_urls.push(value.trim().to_string());
        }
    }
    for service in &service_urls {
        validate_service_url(service)?;
    }
    let proxy_callback_urls = string_list(config, "proxy_callback_urls")?;
    for callback in &proxy_callback_urls {
        validate_service_url(callback)?;
    }
    let allow_proxy = config
        .get("allow_proxy")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if allow_proxy && proxy_callback_urls.is_empty() {
        return Err(AppError::BadRequest(
            "CAS proxying requires at least one registered proxy callback URL".to_string(),
        ));
    }
    let ticket_ttl_seconds = integer_value(config, "ticket_ttl_seconds")
        .unwrap_or(DEFAULT_TICKET_TTL_SECONDS)
        .clamp(30, MAX_TICKET_TTL_SECONDS);
    let pgt_ttl_seconds = integer_value(config, "pgt_ttl_seconds")
        .unwrap_or(DEFAULT_PGT_TTL_SECONDS)
        .clamp(60, MAX_PGT_TTL_SECONDS);
    Ok(CasApplicationConfig {
        service_urls,
        proxy_callback_urls,
        allow_proxy,
        ticket_ttl_seconds,
        pgt_ttl_seconds,
    })
}

fn string_list(config: &Map<String, Value>, field: &str) -> AppResult<Vec<String>> {
    let Some(value) = config.get(field) else {
        return Ok(Vec::new());
    };
    let values = value
        .as_array()
        .ok_or_else(|| AppError::BadRequest(format!("CAS {field} must be a string list")))?;
    if values.iter().any(|value| value.as_str().is_none()) {
        return Err(AppError::BadRequest(format!(
            "CAS {field} must be a string list"
        )));
    }
    Ok(values
        .iter()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect())
}

fn integer_value(config: &Map<String, Value>, field: &str) -> Option<i64> {
    config.get(field).and_then(Value::as_i64).or_else(|| {
        config
            .get(field)
            .and_then(Value::as_u64)
            .map(|value| value as i64)
    })
}

fn validate_service(config: &CasApplicationConfig, service: &str) -> AppResult<()> {
    validate_service_url(service)?;
    if config.service_urls.iter().any(|allowed| allowed == service) {
        Ok(())
    } else {
        Err(AppError::BadRequest(
            "CAS service is not registered for this application".to_string(),
        ))
    }
}

fn validate_service_url(value: &str) -> AppResult<()> {
    let value = value.trim();
    if value.len() > 2048 || value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(AppError::BadRequest(
            "CAS service URL is invalid".to_string(),
        ));
    }
    let url = Url::parse(value)
        .map_err(|_| AppError::BadRequest("CAS service URL is invalid".to_string()))?;
    let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
    if !matches!(url.scheme(), "https" | "http")
        || url.host_str().is_none()
        || (url.scheme() == "http" && !loopback)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.query_pairs().any(|(key, _)| {
            key.eq_ignore_ascii_case("ticket")
                || key.eq_ignore_ascii_case("pgtIou")
                || key.eq_ignore_ascii_case("pgtId")
        })
    {
        return Err(AppError::BadRequest(
            "CAS service URL is invalid".to_string(),
        ));
    }
    Ok(())
}

fn validate_pgt_url(
    config: &CasApplicationConfig,
    value: Option<&str>,
) -> Result<Option<String>, CasProtocolFailure> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    if !config.allow_proxy
        || !config
            .proxy_callback_urls
            .iter()
            .any(|allowed| allowed == value)
    {
        return Err(CasProtocolFailure::new(
            "INVALID_PROXY_CALLBACK",
            "proxy callback URL is not registered",
        ));
    }
    validate_service_url(value).map_err(|_| {
        CasProtocolFailure::new("INVALID_PROXY_CALLBACK", "proxy callback URL is invalid")
    })?;
    Ok(Some(value.to_string()))
}

fn append_ticket(service: &str, ticket: &str) -> AppResult<String> {
    let mut target = Url::parse(service)
        .map_err(|_| AppError::BadRequest("CAS service URL is invalid".to_string()))?;
    target.query_pairs_mut().append_pair("ticket", ticket);
    Ok(target.to_string())
}

fn append_callback_parameters(callback: &str, iou: &str, pgt: &str) -> AppResult<String> {
    let mut target = Url::parse(callback)
        .map_err(|_| AppError::BadRequest("CAS proxy callback URL is invalid".to_string()))?;
    target
        .query_pairs_mut()
        .append_pair("pgtIou", iou)
        .append_pair("pgtId", pgt);
    Ok(target.to_string())
}

fn cas_login_return_to(app_slug: &str, query: &CasLoginQuery) -> AppResult<String> {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("service", &query.service);
    if let Some(renew) = query.renew.as_deref() {
        serializer.append_pair("renew", renew);
    }
    if let Some(gateway) = query.gateway.as_deref() {
        serializer.append_pair("gateway", gateway);
    }
    Ok(format!("/cas/{app_slug}/login?{}", serializer.finish()))
}

fn flag(value: Option<&str>) -> bool {
    value.is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "" | "1" | "true" | "yes"
        )
    })
}

fn valid_ticket_value(value: &str) -> bool {
    (8..=512).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn cas_success(
    user: &crate::db::UserRecord,
    entitlements: &authorization::ApplicationEntitlements,
    pgt_iou: Option<&str>,
    include_attributes: bool,
) -> Response {
    let mut body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><cas:serviceResponse xmlns:cas=\"{CAS_NAMESPACE}\"><cas:authenticationSuccess><cas:user>{}</cas:user>",
        xml_escape(&user.username)
    );
    if let Some(pgt_iou) = pgt_iou {
        body.push_str("<cas:proxyGrantingTicket>");
        body.push_str(&xml_escape(pgt_iou));
        body.push_str("</cas:proxyGrantingTicket>");
    }
    if include_attributes {
        body.push_str("<cas:attributes>");
        for (name, value) in cas_attributes(entitlements) {
            body.push_str("<cas:");
            body.push_str(&name);
            body.push('>');
            body.push_str(&xml_escape(&value));
            body.push_str("</cas:");
            body.push_str(&name);
            body.push_str(">");
        }
        body.push_str("</cas:attributes>");
    }
    body.push_str("</cas:authenticationSuccess></cas:serviceResponse>");
    xml_response(body)
}

fn cas_proxy_success(ticket: &str) -> Response {
    xml_response(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><cas:serviceResponse xmlns:cas=\"{CAS_NAMESPACE}\"><cas:proxySuccess><cas:proxyTicket>{}</cas:proxyTicket></cas:proxySuccess></cas:serviceResponse>",
        xml_escape(ticket)
    ))
}

fn cas_failure(code: &str, detail: &str) -> Response {
    xml_response(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><cas:serviceResponse xmlns:cas=\"{CAS_NAMESPACE}\"><cas:authenticationFailure code=\"{}\">{}</cas:authenticationFailure></cas:serviceResponse>",
        xml_escape(code),
        xml_escape(detail)
    ))
}

fn xml_response(body: String) -> Response {
    let mut response = body.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/xml; charset=utf-8"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

fn cas_attributes(entitlements: &authorization::ApplicationEntitlements) -> Vec<(String, String)> {
    let mut attributes = Vec::new();
    for (claim, value) in &entitlements.claims {
        let name = xml_attribute_name(claim);
        match value {
            Value::Array(values) => {
                for value in values.iter().filter_map(value_to_string) {
                    attributes.push((name.clone(), value));
                }
            }
            value => {
                if let Some(value) = value_to_string(value) {
                    attributes.push((name.clone(), value));
                }
            }
        }
    }
    attributes
}

fn value_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn xml_attribute_name(value: &str) -> String {
    let mut name = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.') {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    if name.is_empty() || !name.as_bytes()[0].is_ascii_alphabetic() && name.as_bytes()[0] != b'_' {
        name.insert_str(0, "attr_");
    }
    name
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        extract::Query,
        http::{Request, StatusCode, header},
        response::Response,
        routing::get,
    };
    use std::{
        collections::BTreeMap,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, Ordering},
        },
    };
    use tower::ServiceExt;

    #[test]
    fn service_urls_are_exact_and_ticket_query_is_not_ambiguous() {
        assert!(validate_service_url("https://portal.example.test/cas").is_ok());
        assert!(validate_service_url("https://portal.example.test/cas?ticket=old").is_err());
        assert!(validate_service_url("https://portal.example.test/cas?pgtIou=old").is_err());
        assert!(validate_service_url("https://portal.example.test/cas?pgtId=old").is_err());
        assert!(validate_service_url("http://localhost:8080/cas").is_ok());
        assert!(validate_service_url("http://portal.example.test/cas").is_err());
    }

    #[test]
    fn ticket_and_callback_values_are_encoded_without_open_redirects() {
        assert_eq!(
            append_ticket("https://portal.example.test/cas?next=%2Fhome", "ST-a_b").unwrap(),
            "https://portal.example.test/cas?next=%2Fhome&ticket=ST-a_b"
        );
        assert!(
            append_callback_parameters("https://idp.example.test/callback", "iou", "pgt")
                .unwrap()
                .contains("pgtIou=iou&pgtId=pgt")
        );
    }

    #[test]
    fn xml_claim_names_and_values_are_safe() {
        assert_eq!(xml_attribute_name("roles"), "roles");
        assert_eq!(xml_attribute_name("a:b"), "a_b");
        assert!(xml_attribute_name("1bad").starts_with("attr_"));
        assert_eq!(xml_escape("<&\"'"), "&lt;&amp;&quot;&apos;");
    }

    #[test]
    fn cas_config_requires_callbacks_when_proxying_is_enabled() {
        let config = serde_json::json!({
            "service_urls": ["https://portal.example.test/cas"],
            "allow_proxy": true
        });
        assert!(parse_cas_config(config.as_object().unwrap()).is_err());

        let config = serde_json::json!({
            "service_urls": ["https://portal.example.test/cas"],
            "proxy_callback_urls": ["https://portal.example.test/pgt"],
            "allow_proxy": true,
            "ticket_ttl_seconds": 1,
            "pgt_ttl_seconds": 999999
        });
        let parsed = parse_cas_config(config.as_object().unwrap()).unwrap();
        assert!(parsed.allow_proxy);
        assert_eq!(parsed.ticket_ttl_seconds, 30);
        assert_eq!(parsed.pgt_ttl_seconds, MAX_PGT_TTL_SECONDS);
    }

    #[test]
    fn invalid_proxy_target_is_a_protocol_failure_input() {
        let config = CasApplicationConfig {
            service_urls: vec!["https://portal.example.test/cas".to_string()],
            proxy_callback_urls: Vec::new(),
            allow_proxy: true,
            ticket_ttl_seconds: DEFAULT_TICKET_TTL_SECONDS,
            pgt_ttl_seconds: DEFAULT_PGT_TTL_SECONDS,
        };
        assert!(validate_service(&config, "https://other.example.test/cas").is_err());
    }

    #[cfg(feature = "sqlite")]
    async fn http_test_state() -> (AppState, std::path::PathBuf) {
        let mut settings: crate::Settings =
            toml::from_str(include_str!("../../config/default.toml")).unwrap();
        let path = std::env::temp_dir().join(format!(
            "gpt-sso-cas-http-test-{}.sqlite3",
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
    async fn body_text(response: Response) -> String {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[cfg(feature = "sqlite")]
    fn cas_application(organization_id: &str) -> crate::db::NewApplication {
        crate::db::NewApplication {
            organization_id: organization_id.to_string(),
            slug: "cas-http-app".to_string(),
            name: "CAS HTTP App".to_string(),
            description: None,
            access_mode: applications::ACCESS_ALL_SIGNET_USERS.to_string(),
            registration_mode: applications::REGISTRATION_DISABLED.to_string(),
            account_selection_mode: applications::ACCOUNT_SELECTION_OPTIONAL.to_string(),
            unique_identity_factors: Vec::new(),
            is_active: true,
        }
    }

    #[cfg(feature = "sqlite")]
    async fn cas_request(app: &Router, uri: &str) -> Response {
        app.clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    #[cfg(feature = "sqlite")]
    async fn enable_cas(
        state: &AppState,
        application_id: &str,
        service_url: &str,
        callback_urls: &[&str],
        allow_proxy: bool,
    ) {
        state
            .db
            .upsert_application_module(
                application_id,
                "protocols",
                &serde_json::json!({
                    "website_url": "https://portal.example.test",
                    "cas": {
                        "enabled": true,
                        "service_urls": [service_url],
                        "proxy_callback_urls": callback_urls,
                        "allow_proxy": allow_proxy
                    }
                })
                .to_string(),
                true,
            )
            .await
            .unwrap();
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn cas_http_validation_is_bound_to_service_and_consumes_tickets_once() {
        let (state, path) = http_test_state().await;
        let organization = state
            .db
            .insert_organization(crate::db::NewOrganization {
                slug: "cas-http-org".to_string(),
                name: "CAS HTTP Org".to_string(),
                kind: crate::organizations::ORGANIZATION_KIND_TENANT.to_string(),
                description: None,
                allowed_email_domains: Vec::new(),
                is_active: true,
            })
            .await
            .unwrap();
        let application = state
            .db
            .insert_application(cas_application(&organization.id))
            .await
            .unwrap();
        let service = "https://portal.example.test/cas";
        state
            .db
            .upsert_application_module(
                &application.id,
                "protocols",
                &serde_json::json!({
                    "website_url": "https://portal.example.test",
                    "cas": {
                        "enabled": true,
                        "service_urls": [service],
                        "allow_proxy": false
                    }
                })
                .to_string(),
                true,
            )
            .await
            .unwrap();
        let user = state
            .db
            .insert_user(crate::db::NewUser {
                email: "cas-http@example.test".to_string(),
                username: "cas-http".to_string(),
                display_name: Some("CAS HTTP".to_string()),
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
        let raw_ticket = "ST-cas-http-ticket";
        state
            .db
            .insert_application_cas_ticket(NewApplicationCasTicket {
                ticket_hash: util::token_hash(raw_ticket),
                application_id: application.id.clone(),
                ticket_type: CAS_SERVICE_TICKET.to_string(),
                service: service.to_string(),
                user_id: user.id.clone(),
                parent_ticket_hash: None,
                pgt_iou: None,
                expires_at: util::now_ts() + 300,
            })
            .await
            .unwrap();

        let mut query = url::form_urlencoded::Serializer::new(String::new());
        query
            .append_pair("service", service)
            .append_pair("ticket", raw_ticket);
        let app = routes().with_state(state.clone());
        let response = cas_request(
            &app,
            &format!(
                "/cas/{}/serviceValidate?{}",
                application.slug,
                query.finish()
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/xml; charset=utf-8")
        );
        let body = body_text(response).await;
        assert!(body.contains("<cas:authenticationSuccess>"));
        assert!(body.contains("<cas:user>cas-http</cas:user>"));

        let mut reused_query = url::form_urlencoded::Serializer::new(String::new());
        reused_query
            .append_pair("service", service)
            .append_pair("ticket", raw_ticket);
        let reused = cas_request(
            &app,
            &format!(
                "/cas/{}/serviceValidate?{}",
                application.slug,
                reused_query.finish()
            ),
        )
        .await;
        assert_eq!(reused.status(), StatusCode::OK);
        assert!(body_text(reused).await.contains("code=\"INVALID_TICKET\""));

        let mut foreign_query = url::form_urlencoded::Serializer::new(String::new());
        foreign_query
            .append_pair("service", "https://attacker.example.test/cas")
            .append_pair("ticket", raw_ticket);
        let foreign = cas_request(
            &app,
            &format!(
                "/cas/{}/serviceValidate?{}",
                application.slug,
                foreign_query.finish()
            ),
        )
        .await;
        assert_eq!(foreign.status(), StatusCode::OK);
        assert!(
            body_text(foreign)
                .await
                .contains("code=\"INVALID_SERVICE\"")
        );

        let login = cas_request(
            &app,
            &format!(
                "/cas/{}/login?service={}",
                application.slug,
                urlencoding(service)
            ),
        )
        .await;
        assert_eq!(login.status(), StatusCode::SEE_OTHER);
        assert!(login.headers().contains_key(header::LOCATION));

        drop(state);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn cas_tickets_are_expiring_revocable_and_bound_to_current_application_policy() {
        let (state, path) = http_test_state().await;
        let organization = state
            .db
            .insert_organization(crate::db::NewOrganization {
                slug: "cas-lifecycle-org".to_string(),
                name: "CAS Lifecycle Org".to_string(),
                kind: crate::organizations::ORGANIZATION_KIND_TENANT.to_string(),
                description: None,
                allowed_email_domains: Vec::new(),
                is_active: true,
            })
            .await
            .unwrap();
        let mut first_input = cas_application(&organization.id);
        first_input.slug = "cas-lifecycle-first".to_string();
        first_input.name = "CAS Lifecycle First".to_string();
        let first = state.db.insert_application(first_input).await.unwrap();
        let mut second_input = cas_application(&organization.id);
        second_input.slug = "cas-lifecycle-second".to_string();
        second_input.name = "CAS Lifecycle Second".to_string();
        let second = state.db.insert_application(second_input).await.unwrap();

        let first_service = "https://first.example.test/cas";
        let second_service = "https://second.example.test/cas";
        let first_callback = "https://first.example.test/pgt";
        let second_callback = "https://second.example.test/pgt";
        let replacement_callback = "https://replacement.example.test/pgt";
        enable_cas(&state, &first.id, first_service, &[first_callback], true).await;
        enable_cas(&state, &second.id, second_service, &[second_callback], true).await;

        let user = state
            .db
            .insert_user(crate::db::NewUser {
                email: "cas-lifecycle@example.test".to_string(),
                username: "cas-lifecycle".to_string(),
                display_name: Some("CAS Lifecycle".to_string()),
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

        let pgt = "PGT-cas-lifecycle";
        state
            .db
            .insert_application_cas_ticket(NewApplicationCasTicket {
                ticket_hash: util::token_hash(pgt),
                application_id: first.id.clone(),
                ticket_type: CAS_PROXY_GRANTING_TICKET.to_string(),
                service: first_callback.to_string(),
                user_id: user.id.clone(),
                parent_ticket_hash: None,
                pgt_iou: Some("PGTIOU-cas-lifecycle".to_string()),
                expires_at: util::now_ts() + 300,
            })
            .await
            .unwrap();

        let app = routes().with_state(state.clone());
        let cross_application = cas_request(
            &app,
            &format!(
                "/cas/{}/proxy?pgt={}&targetService={}",
                second.slug,
                urlencoding(pgt),
                urlencoding(second_service)
            ),
        )
        .await;
        assert!(
            body_text(cross_application)
                .await
                .contains("INVALID_TICKET")
        );

        let first_proxy = cas_request(
            &app,
            &format!(
                "/cas/{}/proxy?pgt={}&targetService={}",
                first.slug,
                urlencoding(pgt),
                urlencoding(first_service)
            ),
        )
        .await;
        assert!(body_text(first_proxy).await.contains("<cas:proxySuccess>"));

        // A PGT is reusable by design, but revocation must invalidate all
        // subsequent proxy-ticket minting immediately.
        state
            .db
            .revoke_application_cas_ticket(&util::token_hash(pgt))
            .await
            .unwrap();
        let revoked = cas_request(
            &app,
            &format!(
                "/cas/{}/proxy?pgt={}&targetService={}",
                first.slug,
                urlencoding(pgt),
                urlencoding(first_service)
            ),
        )
        .await;
        assert!(body_text(revoked).await.contains("INVALID_TICKET"));

        let expired = "PGT-cas-expired";
        state
            .db
            .insert_application_cas_ticket(NewApplicationCasTicket {
                ticket_hash: util::token_hash(expired),
                application_id: first.id.clone(),
                ticket_type: CAS_PROXY_GRANTING_TICKET.to_string(),
                service: first_callback.to_string(),
                user_id: user.id.clone(),
                parent_ticket_hash: None,
                pgt_iou: Some("PGTIOU-cas-expired".to_string()),
                expires_at: util::now_ts() - 1,
            })
            .await
            .unwrap();
        let expired_response = cas_request(
            &app,
            &format!(
                "/cas/{}/proxy?pgt={}&targetService={}",
                first.slug,
                urlencoding(expired),
                urlencoding(first_service)
            ),
        )
        .await;
        assert!(body_text(expired_response).await.contains("INVALID_TICKET"));

        // Existing PGTs are also checked against the current callback
        // registry, so deleting a callback does not leave a stale integration
        // boundary alive.
        let old_callback_pgt = "PGT-cas-old-callback";
        state
            .db
            .insert_application_cas_ticket(NewApplicationCasTicket {
                ticket_hash: util::token_hash(old_callback_pgt),
                application_id: first.id.clone(),
                ticket_type: CAS_PROXY_GRANTING_TICKET.to_string(),
                service: first_callback.to_string(),
                user_id: user.id.clone(),
                parent_ticket_hash: None,
                pgt_iou: Some("PGTIOU-cas-old-callback".to_string()),
                expires_at: util::now_ts() + 300,
            })
            .await
            .unwrap();
        enable_cas(
            &state,
            &first.id,
            first_service,
            &[replacement_callback],
            true,
        )
        .await;
        let removed_callback = cas_request(
            &app,
            &format!(
                "/cas/{}/proxy?pgt={}&targetService={}",
                first.slug,
                urlencoding(old_callback_pgt),
                urlencoding(first_service)
            ),
        )
        .await;
        assert!(body_text(removed_callback).await.contains("INVALID_TICKET"));

        // The active lookup includes the tenant, not only the application
        // row, so disabling either side cuts off old tickets at the route.
        let inactive_app = state
            .db
            .update_application(
                &first.id,
                crate::db::NewApplication {
                    organization_id: first.organization_id.clone(),
                    slug: first.slug.clone(),
                    name: first.name.clone(),
                    description: first.description.clone(),
                    access_mode: first.access_mode.clone(),
                    registration_mode: first.registration_mode.clone(),
                    account_selection_mode: first.account_selection_mode.clone(),
                    unique_identity_factors: first.unique_identity_factors().unwrap(),
                    is_active: false,
                },
            )
            .await
            .unwrap();
        assert_eq!(inactive_app.is_active, 0);
        let inactive_response = cas_request(
            &app,
            &format!(
                "/cas/{}/proxy?pgt={}&targetService={}",
                first.slug,
                urlencoding(old_callback_pgt),
                urlencoding(first_service)
            ),
        )
        .await;
        assert_eq!(inactive_response.status(), StatusCode::NOT_FOUND);

        let inactive_org = state
            .db
            .update_organization(
                &organization.id,
                crate::db::NewOrganization {
                    slug: "cas-lifecycle-org".to_string(),
                    name: "CAS Lifecycle Org".to_string(),
                    kind: crate::organizations::ORGANIZATION_KIND_TENANT.to_string(),
                    description: None,
                    allowed_email_domains: Vec::new(),
                    is_active: false,
                },
            )
            .await
            .unwrap();
        assert_eq!(inactive_org.is_active, 0);
        let inactive_org_response = cas_request(
            &app,
            &format!(
                "/cas/{}/proxy?pgt={}&targetService={}",
                second.slug,
                urlencoding(pgt),
                urlencoding(second_service)
            ),
        )
        .await;
        assert_eq!(inactive_org_response.status(), StatusCode::NOT_FOUND);

        drop(state);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn cas_proxy_callback_failure_revokes_pgt_and_does_not_follow_redirects() {
        let (state, path) = http_test_state().await;
        let organization = state
            .db
            .insert_organization(crate::db::NewOrganization {
                slug: "cas-callback-org".to_string(),
                name: "CAS Callback Org".to_string(),
                kind: crate::organizations::ORGANIZATION_KIND_TENANT.to_string(),
                description: None,
                allowed_email_domains: Vec::new(),
                is_active: true,
            })
            .await
            .unwrap();
        let mut application_input = cas_application(&organization.id);
        application_input.slug = "cas-callback-app".to_string();
        application_input.name = "CAS Callback App".to_string();
        let application = state
            .db
            .insert_application(application_input)
            .await
            .unwrap();
        let user = state
            .db
            .insert_user(crate::db::NewUser {
                email: "cas-callback@example.test".to_string(),
                username: "cas-callback".to_string(),
                display_name: Some("CAS Callback".to_string()),
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

        let captured_pgt = Arc::new(Mutex::new(None::<String>));
        let target_hit = Arc::new(AtomicBool::new(false));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let callback_url = format!("http://127.0.0.1:{port}/pgt");
        let target_url = format!("http://127.0.0.1:{port}/target");
        enable_cas(
            &state,
            &application.id,
            "https://callback.example.test/cas",
            &[callback_url.as_str()],
            true,
        )
        .await;

        let captured_for_handler = captured_pgt.clone();
        let redirect_target = target_url.clone();
        let target_for_handler = target_hit.clone();
        let callback_app = Router::new()
            .route(
                "/pgt",
                get(move |Query(query): Query<BTreeMap<String, String>>| {
                    let captured = captured_for_handler.clone();
                    let target = redirect_target.clone();
                    async move {
                        if let Some(value) = query.get("pgtId") {
                            *captured.lock().unwrap() = Some(value.clone());
                        }
                        Redirect::temporary(&target)
                    }
                }),
            )
            .route(
                "/target",
                get(move || {
                    let target_hit = target_for_handler.clone();
                    async move {
                        target_hit.store(true, Ordering::SeqCst);
                        StatusCode::OK
                    }
                }),
            );
        let server = tokio::spawn(async move {
            axum::serve(listener, callback_app).await.unwrap();
        });

        let (application, config) = load_application(&state, &application.slug).await.unwrap();
        let result = issue_proxy_grant(&state, &application, &config, &user, &callback_url)
            .await
            .unwrap();
        assert!(result.is_err());

        for _ in 0..100 {
            if captured_pgt.lock().unwrap().is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(!target_hit.load(Ordering::SeqCst));
        let raw_pgt = captured_pgt.lock().unwrap().clone().unwrap();
        assert!(
            state
                .db
                .find_application_cas_ticket(
                    &util::token_hash(&raw_pgt),
                    &application.id,
                    CAS_PROXY_GRANTING_TICKET,
                )
                .await
                .unwrap()
                .is_none()
        );

        server.abort();
        drop(state);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    fn urlencoding(value: &str) -> String {
        url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
    }
}
