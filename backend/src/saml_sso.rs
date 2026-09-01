//! Application-scoped SAML 2.0 Identity Provider.
//!
//! A website application owns the SP metadata and ACS policy. Signet owns the
//! IdP signing material and the account/entitlement decision. The raw SAML
//! protocol work is delegated to `saml-rs`; this module is responsible for the
//! application boundary, one-time browser handoff, and claim mapping.

use crate::{
    AppState, applications, auth,
    auth::AccountCapabilities,
    authorization,
    db::{ApplicationRecord, NewApplicationSamlInteraction, NewApplicationSamlSession},
    error::{AppError, AppResult},
    html::escape as html_escape,
    http_urls::validate_safe_http_endpoint,
    redirects, util,
};
use axum::{
    Form, Router,
    extract::{Path, State},
    http::{HeaderMap, Uri, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
};
use saml_rs::{
    AuthnRequest, BrowserInput, EntityId, EntitySetting, FormField, IdentityProvider, Outbound,
    ServiceProvider, SsoResponse,
    constants::Binding,
    idp::LoginResponseOptions,
    metadata::{Endpoint, IdpMetadataConfig, SpMetadataConfig, generate_sp_metadata},
    raw::{HttpRequest, User},
    template::{LoginResponseAttribute, LoginResponseTemplate},
};
use saml_rs::{LogoutRequest, LogoutResponse};
use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::HashMap;

const SAML_INTERACTION_TTL_SECONDS: i64 = 300;
const SAML_REPLAY_TTL_SECONDS: i64 = 600;
const SAML_SESSION_FALLBACK_TTL_SECONDS: i64 = 86_400;
const SAML_CLOCK_SKEW_MILLIS: i64 = 30_000;
const MAX_SAML_REQUEST_BYTES: usize = 512 * 1024;
const NAME_ID_FORMAT_EMAIL: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
const NAME_ID_FORMAT_PERSISTENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
const ATTRIBUTE_NAME_FORMAT_BASIC: &str = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic";

type SamlAttributeOutput = (Vec<LoginResponseAttribute>, Vec<(String, String)>);
type SamlResponseAttributes<'a> = Option<(&'a [LoginResponseAttribute], &'a [(String, String)])>;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/saml/{app}/metadata", get(metadata))
        .route("/saml/{app}/sso", get(sso_redirect).post(sso_post))
        .route("/saml/{app}/sso/continue", get(continue_sso))
        .route("/saml/{app}/slo", get(slo_get).post(slo_post))
}

#[derive(Debug, Clone)]
struct SamlApplicationConfig {
    application_slug: String,
    idp_entity_id: String,
    sp_entity_id: String,
    acs_url: String,
    slo_url: Option<String>,
    acs_index: u16,
    require_signed_requests: bool,
    want_assertions_signed: bool,
    require_signed_logout: bool,
    want_logout_responses_signed: bool,
    name_id_claim: String,
    name_id_format: String,
    sp_metadata_xml: Option<String>,
    sp_signing_certificate: Option<String>,
    attributes: Vec<SamlAttributeConfig>,
}

#[derive(Debug, Clone)]
struct SamlAttributeConfig {
    name: String,
    claim: String,
    name_format: String,
    value_type: String,
}

#[derive(Debug, Clone)]
struct ParsedSamlRequest {
    request_id: String,
    sp_entity_id: String,
    acs_url: String,
}

#[derive(Debug, Deserialize)]
struct SamlPostInput {
    #[serde(rename = "SAMLRequest")]
    saml_request: String,
    #[serde(rename = "RelayState")]
    relay_state: Option<String>,
    #[serde(rename = "Signature")]
    signature: Option<String>,
    #[serde(rename = "SigAlg")]
    sig_alg: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SamlLogoutPostInput {
    #[serde(rename = "SAMLRequest")]
    saml_request: Option<String>,
    #[serde(rename = "SAMLResponse")]
    saml_response: Option<String>,
    #[serde(rename = "RelayState")]
    relay_state: Option<String>,
    #[serde(rename = "Signature")]
    signature: Option<String>,
    #[serde(rename = "SigAlg")]
    sig_alg: Option<String>,
}

async fn metadata(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(app_slug): Path<String>,
) -> AppResult<Response> {
    let (application, config) = load_application(&state, &app_slug).await?;
    let base_url = state.effective_public_base_url(&headers).await?;
    let idp = build_idp(&state, &config, &base_url, None).await?;
    let mut response = idp.metadata_xml().to_string().into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        "application/samlmetadata+xml".parse().unwrap(),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        "public, max-age=300".parse().unwrap(),
    );
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        format!("inline; filename=\"{}.xml\"", application.slug)
            .parse()
            .map_err(|_| AppError::Internal("invalid SAML metadata filename".to_string()))?,
    );
    Ok(response)
}

async fn sso_redirect(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: axum_extra::extract::cookie::CookieJar,
    Path(app_slug): Path<String>,
    uri: Uri,
) -> AppResult<Response> {
    let raw_query = uri.query().unwrap_or_default();
    if raw_query.len() > MAX_SAML_REQUEST_BYTES {
        return Err(AppError::BadRequest(
            "SAML request is too large".to_string(),
        ));
    }
    if contains_query_key(raw_query, "SAMLRequest") {
        reject_duplicate_query_keys(
            raw_query,
            &["SAMLRequest", "RelayState", "SigAlg", "Signature"],
        )?;
        if contains_query_key(raw_query, "SAMLResponse") {
            return Err(AppError::BadRequest(
                "SAMLRequest and SAMLResponse cannot be combined".to_string(),
            ));
        }
        let relay_state = validated_relay_state(query_value(raw_query, "RelayState"))?;
        return process_sso_request(
            &state,
            &headers,
            &jar,
            &app_slug,
            BrowserInput::<AuthnRequest>::redirect(raw_query.to_string()),
            Binding::Redirect,
            relay_state,
        )
        .await;
    }
    if contains_query_key(raw_query, "SAMLResponse") {
        return Err(AppError::BadRequest(
            "SAMLResponse is not accepted at the SAML request endpoint".to_string(),
        ));
    }

    let (application, config) = load_application(&state, &app_slug).await?;
    let base_url = state.effective_public_base_url(&headers).await?;
    let sp_entity_id = query_value(raw_query, "sp_entity_id")
        .or_else(|| query_value(raw_query, "entityID"))
        .unwrap_or_else(|| config.sp_entity_id.clone());
    if sp_entity_id != config.sp_entity_id {
        return Err(AppError::BadRequest(
            "unknown SAML service provider".to_string(),
        ));
    }
    let relay_state = validated_relay_state(query_value(raw_query, "RelayState"))?;
    begin_saml_flow(SamlFlowRequest {
        state: &state,
        jar: &jar,
        application: &application,
        config: &config,
        base_url: &base_url,
        request_id: None,
        relay_state,
        acs_url: config.acs_url.clone(),
    })
    .await
}

async fn sso_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: axum_extra::extract::cookie::CookieJar,
    Path(app_slug): Path<String>,
    Form(input): Form<SamlPostInput>,
) -> AppResult<Response> {
    if input.saml_request.len() > MAX_SAML_REQUEST_BYTES {
        return Err(AppError::BadRequest(
            "SAML request is too large".to_string(),
        ));
    }
    if input.signature.is_some() || input.sig_alg.is_some() {
        return Err(AppError::BadRequest(
            "HTTP-POST-SimpleSign is not enabled for this application; use signed XML POST"
                .to_string(),
        ));
    }
    let relay_state = validated_relay_state(input.relay_state)?;
    let mut fields = vec![FormField::new("SAMLRequest", input.saml_request)];
    if let Some(relay_state) = relay_state.as_deref() {
        fields.push(FormField::new("RelayState", relay_state));
    }
    process_sso_request(
        &state,
        &headers,
        &jar,
        &app_slug,
        BrowserInput::<AuthnRequest>::post(fields),
        Binding::Post,
        relay_state,
    )
    .await
}

async fn slo_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: axum_extra::extract::cookie::CookieJar,
    Path(app_slug): Path<String>,
    uri: Uri,
) -> AppResult<Response> {
    let raw_query = uri.query().unwrap_or_default();
    if raw_query.len() > MAX_SAML_REQUEST_BYTES {
        return Err(AppError::BadRequest(
            "SAML logout request is too large".to_string(),
        ));
    }
    if !contains_query_key(raw_query, "SAMLRequest") {
        return Err(AppError::BadRequest(
            "SAML logout endpoint requires SAMLRequest".to_string(),
        ));
    }
    reject_duplicate_query_keys(
        raw_query,
        &[
            "SAMLRequest",
            "RelayState",
            "SigAlg",
            "Signature",
            "SAMLResponse",
        ],
    )?;
    if contains_query_key(raw_query, "SAMLResponse") {
        return Err(AppError::BadRequest(
            "SAML LogoutResponse is not accepted without a pending request".to_string(),
        ));
    }
    let relay_state = validated_relay_state(query_value(raw_query, "RelayState"))?;
    process_slo_request(
        &state,
        &headers,
        &jar,
        &app_slug,
        BrowserInput::<LogoutRequest>::redirect(raw_query.to_string()),
        Binding::Redirect,
        relay_state,
    )
    .await
}

async fn slo_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: axum_extra::extract::cookie::CookieJar,
    Path(app_slug): Path<String>,
    Form(input): Form<SamlLogoutPostInput>,
) -> AppResult<Response> {
    if input.saml_response.is_some() {
        return Err(AppError::BadRequest(
            "SAML LogoutResponse is not accepted without a pending request".to_string(),
        ));
    }
    let saml_request = input.saml_request.ok_or_else(|| {
        AppError::BadRequest("SAML logout endpoint requires SAMLRequest".to_string())
    })?;
    if saml_request.len() > MAX_SAML_REQUEST_BYTES {
        return Err(AppError::BadRequest(
            "SAML logout request is too large".to_string(),
        ));
    }
    if input.signature.is_some() || input.sig_alg.is_some() {
        return Err(AppError::BadRequest(
            "HTTP-POST-SimpleSign is not enabled for SAML logout; use signed XML POST".to_string(),
        ));
    }
    let relay_state = validated_relay_state(input.relay_state)?;
    let mut fields = vec![FormField::new("SAMLRequest", saml_request)];
    if let Some(relay_state) = relay_state.as_deref() {
        fields.push(FormField::new("RelayState", relay_state));
    }
    process_slo_request(
        &state,
        &headers,
        &jar,
        &app_slug,
        BrowserInput::<LogoutRequest>::post(fields),
        Binding::Post,
        relay_state,
    )
    .await
}

async fn process_slo_request(
    state: &AppState,
    headers: &HeaderMap,
    jar: &axum_extra::extract::cookie::CookieJar,
    app_slug: &str,
    input: BrowserInput<LogoutRequest>,
    binding: Binding,
    relay_state: Option<String>,
) -> AppResult<Response> {
    let (application, config) = load_application(state, app_slug).await?;
    if config.slo_url.is_none() {
        return Err(AppError::NotFound);
    }
    let base_url = state.effective_public_base_url(headers).await?;
    let idp = build_idp(state, &config, &base_url, None).await?;
    let sp = build_sp(&config)?;
    let request = HttpRequest::try_from(input).map_err(inbound_saml_error)?;
    let flow = saml_rs::logout::parse_logout_request(&idp.setting, &sp.metadata, binding, &request)
        .map_err(inbound_saml_error)?;
    let logout = LogoutRequest::try_from(flow).map_err(inbound_saml_error)?;
    let expected_destination =
        idp.metadata
            .get_single_logout_service(binding)
            .ok_or_else(|| {
                AppError::Configuration("SAML IdP SLO metadata is incomplete".to_string())
            })?;
    if logout
        .destination()
        .is_some_and(|destination| destination.as_str() != expected_destination)
    {
        return Err(AppError::BadRequest(
            "SAML LogoutRequest destination does not match Signet".to_string(),
        ));
    }
    if logout.issuer().as_str() != config.sp_entity_id {
        return Err(AppError::BadRequest(
            "unknown SAML logout service provider".to_string(),
        ));
    }
    let replay_key = util::token_hash(&format!(
        "signet:saml:logout-request:v1:{}:{}",
        application.id,
        logout.id().as_str()
    ));
    if !state
        .db
        .claim_application_saml_replay(
            &replay_key,
            &application.id,
            util::now_ts() + SAML_REPLAY_TTL_SECONDS,
        )
        .await?
    {
        return Err(AppError::Unauthorized);
    }

    let requested_name_id = logout.name_id().map(|name_id| name_id.value().to_string());
    let mut sessions = Vec::new();
    if let Some(name_id) = requested_name_id.as_deref() {
        let session_index_hashes = logout
            .session_indexes()
            .iter()
            .map(|session_index| saml_session_index_hash(&application.id, session_index.as_str()))
            .collect::<Vec<_>>();
        let sessions_by_index = state
            .db
            .list_application_saml_sessions_by_indexes(&session_index_hashes, &application.id)
            .await?
            .into_iter()
            .map(|record| (record.session_index_hash.clone(), record))
            .collect::<HashMap<_, _>>();
        for session_index in logout.session_indexes() {
            if let Some(record) = sessions_by_index.get(&saml_session_index_hash(
                &application.id,
                session_index.as_str(),
            )) && record.name_id_hash == saml_name_id_hash(&application.id, name_id)
                && !sessions
                    .iter()
                    .any(|item: &crate::db::ApplicationSamlSessionRecord| {
                        item.session_index_hash == record.session_index_hash
                    })
            {
                sessions.push(record.clone());
            }
        }
        if logout.session_indexes().is_empty() {
            sessions = state
                .db
                .list_application_saml_sessions_by_name_id(
                    &saml_name_id_hash(&application.id, name_id),
                    &application.id,
                )
                .await?;
        }
    }

    for session in sessions {
        state.db.delete_session(&session.signet_session_id).await?;
        state
            .db
            .delete_application_saml_session(&session.session_index_hash, &application.id)
            .await?;
    }

    // A deployment may have issued an assertion before the SessionIndex
    // binding table was introduced. A browser cookie is a safe compatibility
    // fallback only when its user produces exactly the requested NameID.
    if requested_name_id.is_some()
        && logout.session_indexes().is_empty()
        && let Some(current) = auth::current_user_from_cookie(state, jar).await?
        && current.can_authorize_oauth_client()
        && saml_name_id(&config, &current.user) == requested_name_id.as_deref().unwrap_or_default()
    {
        state.db.delete_session(&current.session_id).await?;
    }

    let context = saml_rs::logout::create_logout_response(
        &idp.setting,
        &idp.metadata,
        &sp.metadata,
        Binding::Post,
        Some(logout.id().as_str()),
        relay_state.as_deref(),
        config.want_logout_responses_signed,
    )
    .map_err(|err| {
        AppError::Configuration(format!("failed to issue SAML LogoutResponse: {err}"))
    })?;
    let outbound = Outbound::<LogoutResponse>::try_from(context).map_err(|err| {
        AppError::Configuration(format!("failed to build SAML LogoutResponse form: {err}"))
    })?;
    render_saml_post_form(outbound.post_form().map_err(|err| {
        AppError::Configuration(format!("failed to build SAML LogoutResponse form: {err}"))
    })?)
}

fn render_saml_post_form(form: &saml_rs::PostForm) -> AppResult<Response> {
    let action = form.action().as_str().to_string();
    let fields = form
        .fields()
        .iter()
        .map(|field| (field.name().to_string(), field.value().to_string()))
        .collect::<Vec<_>>();
    render_saml_post_form_values(&action, &fields)
}

fn render_saml_post_form_values(action: &str, fields: &[(String, String)]) -> AppResult<Response> {
    let mut html = String::from(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Signet SAML</title></head><body><form method=\"post\" action=\"",
    );
    html.push_str(&html_escape(action));
    html.push_str("\" id=\"saml\">");
    for (name, value) in fields {
        html.push_str("<input type=\"hidden\" name=\"");
        html.push_str(&html_escape(name));
        html.push_str("\" value=\"");
        html.push_str(&html_escape(value));
        html.push_str("\">");
    }
    html.push_str(
        "<noscript><button type=\"submit\">Continue</button></noscript></form><script>document.forms[0].submit()</script></body></html>",
    );
    Ok(Html(html).into_response())
}

fn saml_name_id(config: &SamlApplicationConfig, user: &crate::db::UserRecord) -> String {
    match config.name_id_claim.as_str() {
        "sub" => user.id.clone(),
        "username" => user.username.clone(),
        _ => user.email.clone(),
    }
}

fn saml_session_index_hash(application_id: &str, session_index: &str) -> String {
    util::token_hash(&format!(
        "signet:saml:session-index:v1:{application_id}:{session_index}"
    ))
}

fn saml_name_id_hash(application_id: &str, name_id: &str) -> String {
    util::token_hash(&format!(
        "signet:saml:name-id:v1:{application_id}:{name_id}"
    ))
}

async fn process_sso_request(
    state: &AppState,
    headers: &HeaderMap,
    jar: &axum_extra::extract::cookie::CookieJar,
    app_slug: &str,
    input: BrowserInput<AuthnRequest>,
    binding: Binding,
    relay_state: Option<String>,
) -> AppResult<Response> {
    let (application, config) = load_application(state, app_slug).await?;
    let base_url = state.effective_public_base_url(headers).await?;
    let parsed = parse_saml_request(state, &config, &base_url, input, binding).await?;
    if parsed.sp_entity_id != config.sp_entity_id {
        return Err(AppError::BadRequest(
            "unknown SAML service provider".to_string(),
        ));
    }
    let replay_key = util::token_hash(&format!(
        "signet:saml:authn-request:v1:{}:{}",
        application.id, parsed.request_id
    ));
    if !state
        .db
        .claim_application_saml_replay(
            &replay_key,
            &application.id,
            util::now_ts() + SAML_REPLAY_TTL_SECONDS,
        )
        .await?
    {
        return Err(AppError::Unauthorized);
    }
    begin_saml_flow(SamlFlowRequest {
        state,
        jar,
        application: &application,
        config: &config,
        base_url: &base_url,
        request_id: Some(parsed.request_id),
        relay_state,
        acs_url: parsed.acs_url,
    })
    .await
}

async fn continue_sso(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: axum_extra::extract::cookie::CookieJar,
    Path(app_slug): Path<String>,
    axum::extract::Query(query): axum::extract::Query<ContinueQuery>,
) -> AppResult<Response> {
    let current = auth::require_current_user(&state, &jar).await?;
    ensure_saml_account_capability(&current)?;
    let (application, config) = load_application(&state, &app_slug).await?;
    let base_url = state.effective_public_base_url(&headers).await?;
    let interaction = state
        .db
        .consume_application_saml_interaction(
            &util::token_hash(query.handle.trim()),
            &application.id,
        )
        .await?;
    if interaction.sp_entity_id != config.sp_entity_id
        || interaction.acs_url != config.acs_url
        || interaction.response_binding != "post"
    {
        return Err(AppError::Unauthorized);
    }
    issue_saml_response(SamlResponseRequest {
        state: &state,
        application: &application,
        config: &config,
        base_url: &base_url,
        user: &current.user,
        signet_session_id: &current.session_id,
        request_id: (!interaction.request_id.is_empty()).then_some(interaction.request_id.as_str()),
        relay_state: interaction.relay_state.as_deref(),
    })
    .await
}

#[derive(Debug, Deserialize)]
struct ContinueQuery {
    handle: String,
}

struct SamlFlowRequest<'a> {
    state: &'a AppState,
    jar: &'a axum_extra::extract::cookie::CookieJar,
    application: &'a ApplicationRecord,
    config: &'a SamlApplicationConfig,
    base_url: &'a str,
    request_id: Option<String>,
    relay_state: Option<String>,
    acs_url: String,
}

struct SamlResponseRequest<'a> {
    state: &'a AppState,
    application: &'a ApplicationRecord,
    config: &'a SamlApplicationConfig,
    base_url: &'a str,
    user: &'a crate::db::UserRecord,
    signet_session_id: &'a str,
    request_id: Option<&'a str>,
    relay_state: Option<&'a str>,
}

async fn begin_saml_flow(request: SamlFlowRequest<'_>) -> AppResult<Response> {
    let SamlFlowRequest {
        state,
        jar,
        application,
        config,
        base_url,
        request_id,
        relay_state,
        acs_url,
    } = request;
    let current = auth::current_user_from_cookie(state, jar).await?;
    if let Some(current) = current {
        ensure_saml_account_capability(&current)?;
        return issue_saml_response(SamlResponseRequest {
            state,
            application,
            config,
            base_url,
            user: &current.user,
            signet_session_id: &current.session_id,
            request_id: request_id.as_deref(),
            relay_state: relay_state.as_deref(),
        })
        .await;
    }

    let handle = util::random_token(32);
    state
        .db
        .insert_application_saml_interaction(NewApplicationSamlInteraction {
            handle_hash: util::token_hash(&handle),
            application_id: application.id.clone(),
            request_id: request_id.unwrap_or_default(),
            sp_entity_id: config.sp_entity_id.clone(),
            acs_url,
            relay_state,
            response_binding: "post".to_string(),
            expires_at: util::now_ts() + SAML_INTERACTION_TTL_SECONDS,
        })
        .await?;
    let return_to = format!(
        "/saml/{}/sso/continue?{}",
        application.slug,
        serde_urlencoded::to_string([("handle", handle.as_str())]).map_err(|err| {
            AppError::Internal(format!("failed to encode SAML continuation: {err}"))
        })?
    );
    Ok(Redirect::to(&redirects::frontend_login_url(&return_to, None, true)).into_response())
}

async fn parse_saml_request(
    state: &AppState,
    config: &SamlApplicationConfig,
    base_url: &str,
    input: BrowserInput<AuthnRequest>,
    binding: Binding,
) -> AppResult<ParsedSamlRequest> {
    let idp = build_idp(state, config, base_url, None).await?;
    let sp = build_sp(config)?;
    let request = HttpRequest::try_from(input).map_err(inbound_saml_error)?;
    let flow = idp
        .parse_login_request(&sp, binding, &request)
        .map_err(inbound_saml_error)?;
    let authn = AuthnRequest::try_from(flow).map_err(inbound_saml_error)?;
    let expected_destination = idp
        .metadata
        .get_single_sign_on_service(binding)
        .ok_or_else(|| {
            AppError::Configuration("SAML IdP SSO metadata is incomplete".to_string())
        })?;
    if authn
        .destination()
        .is_none_or(|destination| destination.as_str() != expected_destination)
    {
        return Err(AppError::BadRequest(
            "SAML AuthnRequest destination does not match Signet".to_string(),
        ));
    }
    if authn
        .acs_url()
        .is_some_and(|acs| acs.as_str() != config.acs_url)
    {
        return Err(AppError::BadRequest(
            "SAML AssertionConsumerServiceURL is not registered".to_string(),
        ));
    }
    if authn
        .acs_index()
        .is_some_and(|index| index != config.acs_index)
    {
        return Err(AppError::BadRequest(
            "SAML AssertionConsumerServiceIndex is not registered".to_string(),
        ));
    }
    if authn
        .protocol_binding()
        .is_some_and(|binding| binding != saml_rs::SsoResponseBinding::Post)
    {
        return Err(AppError::BadRequest(
            "SAML response binding must be HTTP-POST".to_string(),
        ));
    }
    Ok(ParsedSamlRequest {
        request_id: authn.id().as_str().to_string(),
        sp_entity_id: authn.issuer().as_str().to_string(),
        acs_url: config.acs_url.clone(),
    })
}

async fn issue_saml_response(request: SamlResponseRequest<'_>) -> AppResult<Response> {
    let SamlResponseRequest {
        state,
        application,
        config,
        base_url,
        user,
        signet_session_id,
        request_id,
        relay_state,
    } = request;
    let entitlements = authorization::resolve_entitlements(state, application, user).await?;
    let claims = saml_claims(application, user, &entitlements);
    let (attributes, user_attributes) = saml_attributes(config, &claims)?;
    let idp = build_idp(
        state,
        config,
        base_url,
        Some((&attributes, &user_attributes)),
    )
    .await?;
    let sp = build_sp(config)?;
    let name_id = saml_name_id(config, user);
    let session_index = format!("{}_{}", application.id, util::random_token(16));
    let saml_user = User {
        name_id: name_id.clone(),
        attributes: user_attributes,
        session_index: Some(session_index.clone()),
    };
    let context = idp
        .create_login_response(
            &sp,
            Binding::Post,
            &saml_user,
            &LoginResponseOptions {
                in_response_to: request_id,
                relay_state,
                ..Default::default()
            },
        )
        .map_err(|err| AppError::Configuration(format!("failed to issue SAML response: {err}")))?;
    let outbound = Outbound::<SsoResponse>::try_from(context)
        .map_err(|err| AppError::Configuration(format!("failed to build SAML POST: {err}")))?;
    let form = outbound
        .post_form()
        .map_err(|err| AppError::Configuration(format!("failed to build SAML form: {err}")))?;
    let action = form.action().as_str().to_string();
    let fields = form
        .fields()
        .iter()
        .map(|field| (field.name().to_string(), field.value().to_string()))
        .collect::<Vec<_>>();
    let session_expires_at = state
        .db
        .find_session(signet_session_id)
        .await?
        .map(|session| session.expires_at)
        .unwrap_or_else(|| util::now_ts() + SAML_SESSION_FALLBACK_TTL_SECONDS);
    state
        .db
        .insert_application_saml_session(NewApplicationSamlSession {
            session_index_hash: saml_session_index_hash(&application.id, &session_index),
            application_id: application.id.clone(),
            user_id: user.id.clone(),
            signet_session_id: signet_session_id.to_string(),
            name_id_hash: saml_name_id_hash(&application.id, &name_id),
            expires_at: session_expires_at,
        })
        .await?;
    render_saml_post_form_values(&action, &fields)
}

fn saml_claims(
    application: &ApplicationRecord,
    user: &crate::db::UserRecord,
    entitlements: &authorization::ApplicationEntitlements,
) -> Map<String, Value> {
    let mut claims = entitlements.claims.clone();
    claims.insert("sub".to_string(), Value::String(user.id.clone()));
    claims.insert("email".to_string(), Value::String(user.email.clone()));
    claims.insert(
        "preferred_username".to_string(),
        Value::String(user.username.clone()),
    );
    claims.insert(
        "name".to_string(),
        Value::String(
            user.display_name
                .clone()
                .unwrap_or_else(|| user.username.clone()),
        ),
    );
    claims.insert(
        "application_id".to_string(),
        Value::String(application.id.clone()),
    );
    claims
}

fn saml_attributes(
    config: &SamlApplicationConfig,
    claims: &Map<String, Value>,
) -> AppResult<SamlAttributeOutput> {
    let configured = if config.attributes.is_empty() {
        vec![
            SamlAttributeConfig::basic("email", "email"),
            SamlAttributeConfig::basic("preferred_username", "preferred_username"),
            SamlAttributeConfig::basic("name", "name"),
            SamlAttributeConfig::basic("roles", "roles"),
            SamlAttributeConfig::basic("permissions", "permissions"),
            SamlAttributeConfig::basic("groups", "groups"),
            SamlAttributeConfig::basic("organization_role", "organization_role"),
        ]
    } else {
        config.attributes.clone()
    };
    let mut attributes = Vec::new();
    let mut values = Vec::new();
    for (attribute_index, config) in configured.iter().enumerate() {
        let Some(value) = claims.get(&config.claim) else {
            continue;
        };
        let candidates = match value {
            Value::Array(items) => items
                .iter()
                .filter_map(value_to_string)
                .enumerate()
                .collect::<Vec<_>>(),
            other => value_to_string(other)
                .map(|value| vec![(0, value)])
                .unwrap_or_default(),
        };
        for (value_index, value) in candidates {
            let value_tag = format!("signet_{attribute_index}_{value_index}");
            attributes.push(LoginResponseAttribute {
                name: config.name.clone(),
                name_format: config.name_format.clone(),
                value_xsi_type: config.value_type.clone(),
                value_tag: value_tag.clone(),
                value_xmlns_xs: None,
                value_xmlns_xsi: None,
            });
            values.push((value_tag, value));
        }
    }
    Ok((attributes, values))
}

fn value_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

impl SamlAttributeConfig {
    fn basic(name: &str, claim: &str) -> Self {
        Self {
            name: name.to_string(),
            claim: claim.to_string(),
            name_format: ATTRIBUTE_NAME_FORMAT_BASIC.to_string(),
            value_type: "xs:string".to_string(),
        }
    }
}

async fn load_application(
    state: &AppState,
    app_slug: &str,
) -> AppResult<(ApplicationRecord, SamlApplicationConfig)> {
    let (application, protocol) =
        applications::load_active_application_protocol_config(state, app_slug, "saml2").await?;
    let runtime = state.runtime_settings().await?;
    let config = parse_saml_config(&application.slug, &runtime.issuer, &protocol)?;
    Ok((application, config))
}

fn parse_saml_config(
    application_slug: &str,
    issuer: &str,
    config: &Map<String, Value>,
) -> AppResult<SamlApplicationConfig> {
    let sp_entity_id = config
        .get("sp_entity_id")
        .or_else(|| config.get("entity_id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::BadRequest("SAML SP entity_id is required".to_string()))?
        .to_string();
    let acs_url = config
        .get("acs_url")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::BadRequest("SAML ACS URL is required".to_string()))?
        .to_string();
    validate_web_endpoint(&acs_url, "SAML ACS URL")?;
    let slo_url = config
        .get("slo_url")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    if let Some(slo_url) = slo_url.as_deref() {
        validate_web_endpoint(slo_url, "SAML SLO URL")?;
    }
    let idp_entity_id = config
        .get("idp_entity_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| {
            format!(
                "{}/saml/{}/idp",
                issuer.trim_end_matches('/'),
                application_slug
            )
        });
    EntityId::try_new(idp_entity_id.clone())
        .map_err(|err| AppError::BadRequest(format!("SAML IdP entity_id is invalid: {err}")))?;
    EntityId::try_new(sp_entity_id.clone())
        .map_err(|err| AppError::BadRequest(format!("SAML SP entity_id is invalid: {err}")))?;
    let name_id_claim = config
        .get("name_id_claim")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("email")
        .to_string();
    if !matches!(name_id_claim.as_str(), "sub" | "email" | "username") {
        return Err(AppError::BadRequest(
            "SAML name_id_claim must be sub, email, or username".to_string(),
        ));
    }
    let name_id_format = config
        .get("name_id_format")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(if name_id_claim == "sub" {
            NAME_ID_FORMAT_PERSISTENT
        } else {
            NAME_ID_FORMAT_EMAIL
        })
        .to_string();
    if config
        .get("response_binding")
        .and_then(Value::as_str)
        .is_some_and(|binding| !binding.trim().eq_ignore_ascii_case("post"))
    {
        return Err(AppError::BadRequest(
            "SAML response_binding must be post".to_string(),
        ));
    }
    let sp_metadata_xml = config
        .get("sp_metadata_xml")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let sp_signing_certificate = config
        .get("sp_signing_certificate")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let require_signed_requests = config
        .get("require_signed_requests")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if require_signed_requests && sp_metadata_xml.is_none() && sp_signing_certificate.is_none() {
        return Err(AppError::BadRequest(
            "signed SAML requests require SP metadata or a signing certificate".to_string(),
        ));
    }
    let want_assertions_signed = config
        .get("want_assertions_signed")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let require_signed_logout = config
        .get("require_signed_logout")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let want_logout_responses_signed = config
        .get("want_logout_responses_signed")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let acs_index = match config.get("acs_index") {
        None => 0,
        Some(value) => value.as_u64().ok_or_else(|| {
            AppError::BadRequest("SAML acs_index must be an unsigned integer".to_string())
        })?,
    };
    if acs_index > u16::MAX as u64 {
        return Err(AppError::BadRequest(
            "SAML acs_index is out of range".to_string(),
        ));
    }
    let attributes = parse_attributes(config)?;
    Ok(SamlApplicationConfig {
        application_slug: application_slug.to_string(),
        idp_entity_id,
        sp_entity_id,
        acs_url,
        slo_url,
        acs_index: acs_index as u16,
        require_signed_requests,
        want_assertions_signed,
        require_signed_logout,
        want_logout_responses_signed,
        name_id_claim,
        name_id_format,
        sp_metadata_xml,
        sp_signing_certificate,
        attributes,
    })
}

fn parse_attributes(config: &Map<String, Value>) -> AppResult<Vec<SamlAttributeConfig>> {
    let Some(values) = config.get("attributes") else {
        return Ok(Vec::new());
    };
    values
        .as_array()
        .ok_or_else(|| AppError::BadRequest("SAML attributes must be a list".to_string()))?
        .iter()
        .map(|value| {
            let object = value.as_object().ok_or_else(|| {
                AppError::BadRequest("SAML attribute must be an object".to_string())
            })?;
            let name = required_string(object, "name")?;
            let claim = required_string(object, "claim")?;
            let name_format = object
                .get("name_format")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or(ATTRIBUTE_NAME_FORMAT_BASIC)
                .to_string();
            let value_type = object
                .get("value_type")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or("xs:string")
                .to_string();
            Ok(SamlAttributeConfig {
                name,
                claim,
                name_format,
                value_type,
            })
        })
        .collect()
}

fn required_string(object: &Map<String, Value>, field: &str) -> AppResult<String> {
    object
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| AppError::BadRequest(format!("SAML attribute {field} is required")))
}

fn validate_web_endpoint(value: &str, label: &str) -> AppResult<()> {
    validate_safe_http_endpoint(value, label)
}

async fn build_idp(
    state: &AppState,
    config: &SamlApplicationConfig,
    base_url: &str,
    response_attributes: SamlResponseAttributes<'_>,
) -> AppResult<IdentityProvider> {
    let private_key = if !state
        .settings
        .security
        .saml_private_key_pem
        .trim()
        .is_empty()
    {
        state.settings.security.saml_private_key_pem.clone()
    } else {
        state
            .db
            .list_signing_keys()
            .await?
            .into_iter()
            .find(|key| key.is_active == 1)
            .map(|key| key.private_key_pem)
            .ok_or_else(|| {
                AppError::Configuration("no active signing key is available for SAML".to_string())
            })?
    };
    let certificate = state.settings.security.saml_signing_certificate_pem.trim();
    if certificate.is_empty() {
        return Err(AppError::Configuration(
            "SAML requires security.saml_signing_certificate_pem".to_string(),
        ));
    }
    let sso_url = format!(
        "{}/saml/{}/sso",
        base_url.trim_end_matches('/'),
        config.application_slug
    );
    let slo_endpoint_url = format!(
        "{}/saml/{}/slo",
        base_url.trim_end_matches('/'),
        config.application_slug
    );
    let single_logout_service = if config.slo_url.is_some() {
        vec![
            Endpoint::new(Binding::Redirect, &slo_endpoint_url),
            Endpoint::new(Binding::Post, &slo_endpoint_url),
        ]
    } else {
        Vec::new()
    };
    let metadata = IdpMetadataConfig {
        entity_id: config.idp_entity_id.clone(),
        signing_certs: vec![certificate.to_string()],
        encrypt_certs: Vec::new(),
        want_authn_requests_signed: config.require_signed_requests,
        name_id_format: vec![config.name_id_format.clone()],
        single_sign_on_service: vec![
            Endpoint::new(Binding::Redirect, &sso_url),
            Endpoint::new(Binding::Post, &sso_url),
        ],
        // `slo_url` belongs to the website's SP metadata.  The IdP metadata
        // advertises Signet's own endpoint; the response is sent back to the
        // website's configured SLO endpoint after the request is validated.
        single_logout_service,
        elements_order: None,
    };
    let mut setting = EntitySetting::default();
    setting.entity_id = Some(config.idp_entity_id.clone());
    setting.private_key = Some(private_key);
    setting.signing_cert = Some(certificate.to_string());
    setting.name_id_format = vec![config.name_id_format.clone()];
    setting.want_authn_requests_signed = config.require_signed_requests;
    setting.want_logout_request_signed = config.require_signed_logout;
    setting.want_logout_response_signed = config.want_logout_responses_signed;
    setting.clock_drifts = (SAML_CLOCK_SKEW_MILLIS, SAML_CLOCK_SKEW_MILLIS);
    if let Some((attributes, _values)) = response_attributes {
        setting.login_response_template = Some(LoginResponseTemplate {
            context: None,
            attributes: attributes.to_vec(),
        });
    }
    IdentityProvider::from_config(&metadata, setting)
        .map_err(|err| AppError::Configuration(format!("invalid SAML IdP configuration: {err}")))
}

fn build_sp(config: &SamlApplicationConfig) -> AppResult<ServiceProvider> {
    let metadata_xml = if let Some(metadata) = config.sp_metadata_xml.as_deref() {
        metadata.to_string()
    } else {
        let mut acs = Endpoint::new(Binding::Post, &config.acs_url);
        acs.index = Some(config.acs_index);
        acs.is_default = true;
        let slo = config
            .slo_url
            .as_deref()
            .map(|url| vec![Endpoint::new(Binding::Post, url)])
            .unwrap_or_default();
        generate_sp_metadata(&SpMetadataConfig {
            entity_id: config.sp_entity_id.clone(),
            signing_certs: config
                .sp_signing_certificate
                .as_deref()
                .map(|value| vec![value.to_string()])
                .unwrap_or_default(),
            encrypt_certs: Vec::new(),
            authn_requests_signed: config.require_signed_requests,
            want_assertions_signed: config.want_assertions_signed,
            name_id_format: vec![config.name_id_format.clone()],
            single_logout_service: slo,
            assertion_consumer_service: vec![acs],
            elements_order: None,
        })
    };
    let mut setting = EntitySetting::default();
    setting.entity_id = Some(config.sp_entity_id.clone());
    setting.clock_drifts = (SAML_CLOCK_SKEW_MILLIS, SAML_CLOCK_SKEW_MILLIS);
    let sp = ServiceProvider::from_metadata(&metadata_xml, setting)
        .map_err(|err| AppError::Configuration(format!("invalid SAML SP metadata: {err}")))?;
    if sp.metadata.get_entity_id() != Some(config.sp_entity_id.as_str())
        || sp
            .metadata
            .get_assertion_consumer_service(Binding::Post)
            .as_deref()
            != Some(config.acs_url.as_str())
    {
        return Err(AppError::Configuration(
            "SAML SP metadata does not match the configured entity_id or ACS".to_string(),
        ));
    }
    if config.require_signed_requests
        && sp
            .metadata
            .x509_certificates(saml_rs::constants::CertUse::Signing)
            .is_empty()
    {
        return Err(AppError::Configuration(
            "signed SAML requests require a signing certificate in SP metadata".to_string(),
        ));
    }
    if let Some(slo_url) = config.slo_url.as_deref()
        && sp
            .metadata
            .get_single_logout_service(Binding::Post)
            .as_deref()
            != Some(slo_url)
    {
        return Err(AppError::Configuration(
            "SAML SP metadata does not match the configured SLO URL".to_string(),
        ));
    }
    Ok(sp)
}

fn ensure_saml_account_capability(current: &auth::CurrentUser) -> AppResult<()> {
    if !current.can_authorize_oauth_client() {
        return Err(AppError::Forbidden);
    }
    Ok(())
}

fn validated_relay_state(value: Option<String>) -> AppResult<Option<String>> {
    saml_rs::RelayStateParam::try_from_option(value)
        .map(|state| state.as_deref().map(ToOwned::to_owned))
        .map_err(inbound_saml_error)
}

fn query_value(raw_query: &str, key: &str) -> Option<String> {
    url::form_urlencoded::parse(raw_query.as_bytes())
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.into_owned())
}

fn contains_query_key(raw_query: &str, key: &str) -> bool {
    url::form_urlencoded::parse(raw_query.as_bytes()).any(|(name, _)| name == key)
}

fn reject_duplicate_query_keys(raw_query: &str, keys: &[&str]) -> AppResult<()> {
    for key in keys {
        let count = url::form_urlencoded::parse(raw_query.as_bytes())
            .filter(|(name, _)| name == key)
            .count();
        if count > 1 {
            return Err(AppError::BadRequest(format!(
                "SAML query parameter {key} must appear once"
            )));
        }
    }
    Ok(())
}

fn inbound_saml_error(error: impl std::fmt::Display) -> AppError {
    tracing::debug!(error = %error, "SAML request validation failed");
    AppError::BadRequest("invalid SAML request".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
        response::Response,
    };
    use tower::ServiceExt;

    #[test]
    fn relay_state_is_limited_and_query_keys_are_decoded() {
        assert!(validated_relay_state(Some("ok".to_string())).is_ok());
        assert!(validated_relay_state(Some("x".repeat(81))).is_err());
        assert_eq!(
            query_value("RelayState=a+b&SAMLRequest=abc", "RelayState"),
            Some("a b".to_string())
        );
        assert!(contains_query_key("foo=1&SAMLRequest=abc", "SAMLRequest"));
        assert!(!contains_query_key("foo=1", "SAMLRequest"));
        assert!(
            reject_duplicate_query_keys(
                "SAMLRequest=one&RelayState=state",
                &["SAMLRequest", "RelayState"]
            )
            .is_ok()
        );
        assert!(
            reject_duplicate_query_keys("SAMLRequest=one&SAMLRequest=two", &["SAMLRequest"])
                .is_err()
        );
    }

    #[test]
    fn html_escape_does_not_allow_form_markup() {
        assert_eq!(
            html_escape("\"><script>alert(1)</script>"),
            "&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;"
        );
    }

    #[test]
    fn saml_config_defaults_to_post_and_email_name_id() {
        let config = serde_json::json!({
            "sp_entity_id": "https://portal.example.test/metadata",
            "acs_url": "https://portal.example.test/sso/acs"
        });
        let parsed = parse_saml_config(
            "portal",
            "https://signet.example.test",
            config.as_object().unwrap(),
        )
        .unwrap();
        assert_eq!(parsed.name_id_claim, "email");
        assert_eq!(parsed.name_id_format, NAME_ID_FORMAT_EMAIL);
        assert_eq!(parsed.acs_index, 0);
        assert!(!parsed.require_signed_requests);
        assert!(!parsed.want_assertions_signed);
        assert!(parsed.require_signed_logout);
        assert!(parsed.want_logout_responses_signed);
    }

    #[test]
    fn saml_config_rejects_invalid_acs_index_and_signed_request_material() {
        let missing_material = serde_json::json!({
            "sp_entity_id": "https://portal.example.test/metadata",
            "acs_url": "https://portal.example.test/sso/acs",
            "require_signed_requests": true
        });
        assert!(
            parse_saml_config(
                "portal",
                "https://signet.example.test",
                missing_material.as_object().unwrap(),
            )
            .is_err()
        );

        for acs_index in [
            serde_json::json!(-1),
            serde_json::json!(u64::from(u16::MAX) + 1),
        ] {
            let config = serde_json::json!({
                "sp_entity_id": "https://portal.example.test/metadata",
                "acs_url": "https://portal.example.test/sso/acs",
                "acs_index": acs_index
            });
            assert!(
                parse_saml_config(
                    "portal",
                    "https://signet.example.test",
                    config.as_object().unwrap(),
                )
                .is_err()
            );
        }
    }

    #[test]
    fn saml_request_destination_is_required_by_the_runtime_boundary() {
        let config = serde_json::json!({
            "sp_entity_id": "https://portal.example.test/metadata",
            "acs_url": "https://portal.example.test/sso/acs"
        });
        let parsed = parse_saml_config(
            "portal",
            "https://signet.example.test",
            config.as_object().unwrap(),
        )
        .unwrap();
        assert!(parsed.acs_url.starts_with("https://"));
    }

    #[test]
    fn saml_attributes_support_multiple_claim_values_and_custom_mapping() {
        let config = serde_json::json!({
            "sp_entity_id": "https://portal.example.test/metadata",
            "acs_url": "https://portal.example.test/sso/acs",
            "attributes": [{
                "name": "memberOf",
                "claim": "groups",
                "name_format": ATTRIBUTE_NAME_FORMAT_BASIC,
                "value_type": "xs:string"
            }]
        });
        let parsed = parse_saml_config(
            "portal",
            "https://signet.example.test",
            config.as_object().unwrap(),
        )
        .unwrap();
        let claims = Map::from_iter([(
            "groups".to_string(),
            serde_json::json!(["engineering", "support"]),
        )]);
        let (_attributes, values) = saml_attributes(&parsed, &claims).unwrap();
        assert_eq!(
            values
                .into_iter()
                .map(|(_, value)| value)
                .collect::<Vec<_>>(),
            vec!["engineering".to_string(), "support".to_string()]
        );
    }

    #[cfg(feature = "sqlite")]
    async fn http_test_state() -> (AppState, std::path::PathBuf) {
        let mut settings: crate::Settings =
            toml::from_str(include_str!("../../config/default.toml")).unwrap();
        let path = std::env::temp_dir().join(format!(
            "gpt-sso-saml-http-test-{}.sqlite3",
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
    async fn saml_request(app: &Router, uri: &str) -> Response {
        app.clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn saml_http_entry_is_application_bound_and_rejects_response_confusion() {
        let (state, path) = http_test_state().await;
        let organization = state
            .db
            .insert_organization(crate::db::NewOrganization {
                slug: "saml-http-org".to_string(),
                name: "SAML HTTP Org".to_string(),
                kind: crate::organizations::ORGANIZATION_KIND_TENANT.to_string(),
                description: None,
                allowed_email_domains: Vec::new(),
                is_active: true,
            })
            .await
            .unwrap();
        let application = state
            .db
            .insert_application(crate::db::NewApplication {
                organization_id: organization.id.clone(),
                slug: "saml-http-app".to_string(),
                name: "SAML HTTP App".to_string(),
                description: None,
                access_mode: applications::ACCESS_ALL_SIGNET_USERS.to_string(),
                registration_mode: applications::REGISTRATION_DISABLED.to_string(),
                account_selection_mode: applications::ACCOUNT_SELECTION_OPTIONAL.to_string(),
                unique_identity_factors: Vec::new(),
                is_active: true,
            })
            .await
            .unwrap();
        let sp_entity_id = "https://portal.example.test/metadata";
        state
            .db
            .upsert_application_module(
                &application.id,
                "protocols",
                &serde_json::json!({
                    "website_url": "https://portal.example.test",
                    "saml2": {
                        "enabled": true,
                        "sp_entity_id": sp_entity_id,
                        "acs_url": "https://portal.example.test/sso/acs",
                        "response_binding": "post"
                    }
                })
                .to_string(),
                true,
            )
            .await
            .unwrap();

        let app = routes().with_state(state.clone());
        let entry = saml_request(
            &app,
            &format!(
                "/saml/{}/sso?sp_entity_id={}&RelayState=relay-value",
                application.slug,
                url::form_urlencoded::byte_serialize(sp_entity_id.as_bytes()).collect::<String>()
            ),
        )
        .await;
        assert_eq!(entry.status(), StatusCode::SEE_OTHER);
        let location = entry
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(location.starts_with("/?auth=login&"));
        assert!(location.contains("saml-http-app%2Fsso%2Fcontinue"));

        let oversized_relay = saml_request(
            &app,
            &format!(
                "/saml/{}/sso?sp_entity_id={}&RelayState={}",
                application.slug,
                url::form_urlencoded::byte_serialize(sp_entity_id.as_bytes()).collect::<String>(),
                "x".repeat(81)
            ),
        )
        .await;
        assert_eq!(oversized_relay.status(), StatusCode::BAD_REQUEST);

        let response_at_request_endpoint = saml_request(
            &app,
            &format!("/saml/{}/sso?SAMLResponse=not-a-request", application.slug),
        )
        .await;
        assert_eq!(
            response_at_request_endpoint.status(),
            StatusCode::BAD_REQUEST
        );

        drop(state);
        let _ = std::fs::remove_file(path);
    }
}
