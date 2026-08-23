use crate::{
    AppState, applications,
    assurance::{self, AssurancePolicy, SessionAuthenticationAssurance},
    audit::{self, AuditOutcome, AuditSink},
    auth::{self, AccountCapabilities},
    auth_domain::ApplicationAuthContext,
    auth_flow, authorization, authorization_details,
    claim_mapper::{self, ClaimContext, ClaimOutputTarget},
    client_assertion,
    client_policy::{
        AuthorizationRequestSecurityView, AuthorizationRequestSource, ClientSecurityPolicy,
        DefaultClientSecurityPolicy,
    },
    consent::{self, OidcConsentPolicy},
    db::{
        ApplicationRecord, ClientRecord, LoginCodeLevel, NewApplicationAuthContext,
        NewAuthorizationCode, RefreshTokenInput, SessionRecord, UserRecord,
    },
    directory,
    dpop::{self, DpopBinding},
    error::{AppError, AppResult},
    jwt::{TokenClaims, TokenSubject},
    mfa,
    mfa_policy::MfaDecision,
    network_policy::TrustedNetworkPolicy,
    oidc_claims::{
        self, DefaultEmailVerifiedClaimPolicy, EmailVerifiedClaimPolicy, RequestedClaims,
    },
    redirects, security_policy,
    service_accounts::ServiceAccountProfile,
    subject, util,
};
use axum::{
    Form, Json, Router,
    extract::{ConnectInfo, Query, State},
    http::{HeaderMap, Method, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use time::Duration;
use url::Url;

pub(crate) const OIDC_LOGIN_GRANT_TTL_SECONDS: i64 = 180;

fn oidc_login_grant_cookie_name(state: &AppState) -> String {
    format!("{}_oidc_grant", state.settings.security.cookie_name)
}

pub(crate) fn new_oidc_login_grant_credentials() -> (String, String) {
    let cookie_value = format!("og1.{}", util::random_token(32));
    (util::token_hash(&cookie_value), cookie_value)
}

pub(crate) fn oidc_login_grant_cookie(state: &AppState, value: String) -> Cookie<'static> {
    let mut cookie = Cookie::build((oidc_login_grant_cookie_name(state), value))
        .path("/oauth2/authorize")
        .http_only(true)
        .secure(state.settings.security.cookie_secure)
        .same_site(SameSite::Lax)
        .max_age(Duration::seconds(OIDC_LOGIN_GRANT_TTL_SECONDS))
        .build();
    if !state.settings.security.cookie_domain.trim().is_empty() {
        cookie.set_domain(state.settings.security.cookie_domain.clone());
    }
    cookie
}

fn expired_oidc_login_grant_cookie(state: &AppState) -> Cookie<'static> {
    let mut cookie = oidc_login_grant_cookie(state, String::new());
    cookie.set_max_age(Duration::ZERO);
    cookie
}

fn oidc_login_grant_credential_hash(state: &AppState, jar: &CookieJar) -> Option<String> {
    let value = jar.get(&oidc_login_grant_cookie_name(state))?.value();
    value.starts_with("og1.").then(|| util::token_hash(value))
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        // RFC 8414 OAuth clients (including external MCP clients) discover
        // the same authorization server through this standard endpoint. The
        // OIDC document already contains the complete OAuth metadata surface.
        .route("/.well-known/oauth-authorization-server", get(discovery))
        .route("/oauth2/jwks", get(jwks))
        .route("/oauth2/authorize", get(authorize).post(authorize_consent))
        .route("/oauth2/par", post(crate::par::pushed_authorization))
        .route(
            "/oauth2/device_authorization",
            post(crate::device::device_authorization),
        )
        .route(
            "/oauth2/device",
            get(crate::device::device_page).post(crate::device::device_form),
        )
        .route("/oauth2/token", post(token))
        .route("/oauth2/introspect", post(introspect))
        .route("/oauth2/revoke", post(revoke))
        .route("/oauth2/userinfo", get(userinfo).post(userinfo))
        .route("/oauth2/logout", get(logout_get).post(logout_post))
        .route("/connect/register", post(crate::dcr::register_client))
        .route(
            "/connect/register/{client_id}",
            get(crate::dcr::read_client)
                .put(crate::dcr::update_client)
                .delete(crate::dcr::delete_client),
        )
        .route("/login", get(login_page).post(login_form))
}

#[derive(Debug, Serialize)]
struct DiscoveryDocument {
    issuer: String,
    authorization_endpoint: String,
    pushed_authorization_request_endpoint: String,
    require_pushed_authorization_requests: bool,
    device_authorization_endpoint: String,
    token_endpoint: String,
    introspection_endpoint: String,
    revocation_endpoint: String,
    resource_parameter_supported: bool,
    authorization_details_parameter_supported: bool,
    authorization_details_types_supported: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    registration_endpoint: Option<String>,
    userinfo_endpoint: String,
    jwks_uri: String,
    end_session_endpoint: String,
    backchannel_logout_supported: bool,
    backchannel_logout_session_supported: bool,
    frontchannel_logout_supported: bool,
    frontchannel_logout_session_supported: bool,
    response_types_supported: Vec<&'static str>,
    response_modes_supported: Vec<&'static str>,
    grant_types_supported: Vec<&'static str>,
    subject_types_supported: Vec<&'static str>,
    id_token_signing_alg_values_supported: Vec<&'static str>,
    authorization_signing_alg_values_supported: Vec<&'static str>,
    token_endpoint_auth_methods_supported: Vec<&'static str>,
    token_endpoint_auth_signing_alg_values_supported: Vec<&'static str>,
    dpop_signing_alg_values_supported: Vec<&'static str>,
    request_parameter_supported: bool,
    request_uri_parameter_supported: bool,
    request_object_signing_alg_values_supported: Vec<&'static str>,
    claims_parameter_supported: bool,
    acr_values_supported: Vec<&'static str>,
    scopes_supported: Vec<String>,
    claims_supported: Vec<&'static str>,
    code_challenge_methods_supported: Vec<&'static str>,
}

async fn discovery(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<DiscoveryDocument>> {
    let issuer = state.effective_issuer(&headers).await?;
    let authorization_details_types_supported =
        authorization_details::supported_types_from_clients(&state.db.list_clients().await?)?;
    Ok(Json(DiscoveryDocument {
        issuer: issuer.clone(),
        authorization_endpoint: absolute(&issuer, &state.settings.oidc.authorization_endpoint),
        pushed_authorization_request_endpoint: absolute(&issuer, "/oauth2/par"),
        require_pushed_authorization_requests: false,
        device_authorization_endpoint: absolute(&issuer, "/oauth2/device_authorization"),
        token_endpoint: absolute(&issuer, &state.settings.oidc.token_endpoint),
        introspection_endpoint: absolute(&issuer, "/oauth2/introspect"),
        revocation_endpoint: absolute(&issuer, "/oauth2/revoke"),
        resource_parameter_supported: true,
        authorization_details_parameter_supported: true,
        authorization_details_types_supported,
        registration_endpoint: state
            .settings
            .oidc
            .allow_dynamic_client_registration
            .then(|| absolute(&issuer, "/connect/register")),
        userinfo_endpoint: absolute(&issuer, &state.settings.oidc.userinfo_endpoint),
        jwks_uri: absolute(&issuer, &state.settings.oidc.jwks_uri),
        end_session_endpoint: absolute(&issuer, &state.settings.oidc.end_session_endpoint),
        backchannel_logout_supported: true,
        backchannel_logout_session_supported: true,
        frontchannel_logout_supported: true,
        frontchannel_logout_session_supported: true,
        response_types_supported: vec!["code"],
        response_modes_supported: crate::jarm::SUPPORTED_RESPONSE_MODES.to_vec(),
        grant_types_supported: vec![
            "authorization_code",
            "refresh_token",
            "client_credentials",
            crate::device::DEVICE_CODE_GRANT,
            crate::token_exchange::TOKEN_EXCHANGE_GRANT,
        ],
        subject_types_supported: vec![subject::SUBJECT_TYPE_PUBLIC, subject::SUBJECT_TYPE_PAIRWISE],
        id_token_signing_alg_values_supported: vec!["RS256"],
        authorization_signing_alg_values_supported: crate::jarm::SUPPORTED_SIGNING_ALGS.to_vec(),
        token_endpoint_auth_methods_supported: vec![
            "client_secret_basic",
            "client_secret_post",
            client_assertion::CLIENT_SECRET_JWT,
            client_assertion::PRIVATE_KEY_JWT,
            "none",
        ],
        token_endpoint_auth_signing_alg_values_supported:
            client_assertion::TOKEN_ENDPOINT_AUTH_SIGNING_ALGS.to_vec(),
        dpop_signing_alg_values_supported: dpop::SUPPORTED_SIGNING_ALGS.to_vec(),
        request_parameter_supported: true,
        request_uri_parameter_supported: true,
        request_object_signing_alg_values_supported: client_assertion::SUPPORTED_SIGNING_ALGS
            .to_vec(),
        claims_parameter_supported: true,
        acr_values_supported: assurance::SUPPORTED_ACR_VALUES.to_vec(),
        scopes_supported: state.settings.oidc.supported_scopes.clone(),
        claims_supported: oidc_claims::SUPPORTED_CLAIMS.to_vec(),
        code_challenge_methods_supported: vec!["plain", "S256"],
    }))
}

async fn jwks(State(state): State<AppState>) -> Json<crate::jwt::Jwks> {
    Json(state.jwt.jwks())
}

#[derive(Debug, Clone, Deserialize)]
struct AuthorizeRequest {
    interaction_request: Option<String>,
    request: Option<String>,
    request_uri: Option<String>,
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    scope: Option<String>,
    resource: Option<String>,
    authorization_details: Option<String>,
    login_hint: Option<String>,
    prompt: Option<String>,
    max_age: Option<String>,
    acr_values: Option<String>,
    claims: Option<String>,
    state: Option<String>,
    nonce: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    response_mode: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ConsentForm {
    _csrf: Option<String>,
    action: String,
    remember: Option<String>,
    response_type: String,
    client_id: String,
    redirect_uri: String,
    scope: String,
    resource: Option<String>,
    authorization_details: Option<String>,
    login_hint: Option<String>,
    prompt: Option<String>,
    max_age: Option<String>,
    interaction_request: Option<String>,
    request_uri: Option<String>,
    acr_values: Option<String>,
    claims: Option<String>,
    state: Option<String>,
    nonce: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    response_mode: Option<String>,
}

#[derive(Debug, Clone, Copy)]
struct PromptBehavior {
    force_consent: bool,
    force_login: bool,
    select_account: bool,
    none: bool,
}

struct AuthorizationHttpContext<'a> {
    state: &'a AppState,
    headers: &'a HeaderMap,
    remote_addr: Option<SocketAddr>,
}

trait AuthorizationSessionFreshness {
    fn needs_reauthentication(
        &self,
        prompt: PromptBehavior,
        max_age: Option<i64>,
        now: i64,
    ) -> bool;
}

impl AuthorizationSessionFreshness for SessionRecord {
    fn needs_reauthentication(
        &self,
        prompt: PromptBehavior,
        max_age: Option<i64>,
        now: i64,
    ) -> bool {
        prompt.force_login
            || max_age.is_some_and(|max_age| {
                max_age == 0 || now.saturating_sub(self.created_at) > max_age
            })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct ResolvedAuthorizeRequest {
    #[serde(default)]
    pub source: AuthorizationRequestSource,
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub resource: Option<String>,
    pub authorization_details: Option<String>,
    pub login_hint: Option<String>,
    pub prompt: Option<String>,
    pub max_age: Option<i64>,
    pub acr_values: Option<String>,
    pub claims: Option<RequestedClaims>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub response_mode: Option<String>,
    #[serde(default)]
    pub account_selection_prompted: bool,
    #[serde(default)]
    pub account_selection_required: bool,
    #[serde(default)]
    pub reauthentication_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_user_id: Option<String>,
}

impl ResolvedAuthorizeRequest {
    fn from_query(query: AuthorizeRequest) -> AppResult<Self> {
        Ok(Self {
            source: AuthorizationRequestSource::Query,
            response_type: required_query_value(query.response_type, "response_type")?,
            client_id: required_query_value(query.client_id, "client_id")?,
            redirect_uri: required_query_value(query.redirect_uri, "redirect_uri")?,
            scope: query.scope,
            resource: normalize_resource(query.resource.as_deref())?,
            authorization_details: optional_form_value(query.authorization_details),
            login_hint: optional_form_value(query.login_hint),
            prompt: query.prompt,
            max_age: parse_max_age(query.max_age.as_deref())?,
            acr_values: normalize_acr_values_param(query.acr_values.as_deref())?,
            claims: RequestedClaims::from_authorization_parameter(query.claims.as_deref())?,
            state: query.state,
            nonce: query.nonce,
            code_challenge: query.code_challenge,
            code_challenge_method: query.code_challenge_method,
            response_mode: query.response_mode,
            account_selection_prompted: false,
            account_selection_required: false,
            reauthentication_required: false,
            selected_session_id: None,
            selected_user_id: None,
        })
    }

    fn prompt_behavior(&self) -> AppResult<PromptBehavior> {
        prompt_behavior(self.prompt.as_deref())
    }

    fn requested_assurance(&self) -> AppResult<assurance::RequestedAssurance> {
        self.claims
            .as_ref()
            .map(|claims| claims.requested_assurance(self.acr_values.as_deref()))
            .unwrap_or_else(|| {
                assurance::RequestedAssurance::new(
                    self.acr_values.as_deref(),
                    Vec::new(),
                    Vec::new(),
                )
            })
    }
}

impl ConsentForm {
    fn resolved_request(&self) -> AppResult<ResolvedAuthorizeRequest> {
        Ok(ResolvedAuthorizeRequest {
            source: AuthorizationRequestSource::Query,
            response_type: required_query_value(Some(self.response_type.clone()), "response_type")?,
            client_id: required_query_value(Some(self.client_id.clone()), "client_id")?,
            redirect_uri: required_query_value(Some(self.redirect_uri.clone()), "redirect_uri")?,
            scope: Some(self.scope.clone()),
            resource: normalize_resource(self.resource.as_deref())?,
            authorization_details: optional_form_value(self.authorization_details.clone()),
            login_hint: optional_form_value(self.login_hint.clone()),
            prompt: optional_form_value(self.prompt.clone()),
            max_age: parse_max_age(self.max_age.as_deref())?,
            acr_values: normalize_acr_values_param(self.acr_values.as_deref())?,
            claims: RequestedClaims::from_authorization_parameter(self.claims.as_deref())?,
            state: optional_form_value(self.state.clone()),
            nonce: optional_form_value(self.nonce.clone()),
            code_challenge: optional_form_value(self.code_challenge.clone()),
            code_challenge_method: optional_form_value(self.code_challenge_method.clone()),
            response_mode: optional_form_value(self.response_mode.clone()),
            account_selection_prompted: false,
            account_selection_required: false,
            reauthentication_required: false,
            selected_session_id: None,
            selected_user_id: None,
        })
    }
}

async fn resolve_authorize_request(
    state: &AppState,
    headers: &HeaderMap,
    query: AuthorizeRequest,
) -> AppResult<ResolvedAuthorizeRequest> {
    if let Some(interaction_request) = query.interaction_request.as_deref() {
        return crate::par::consume_interaction_request(state, interaction_request).await;
    }
    if let Some(request_uri) = query.request_uri.as_deref() {
        let mut request = crate::par::consume_request_uri(state, request_uri).await?;
        request.source = AuthorizationRequestSource::PushedAuthorizationRequest;
        return Ok(request);
    }
    if let Some(request_object) = query.request.as_deref() {
        let mut request = crate::request_object::resolve_authorization_request_object(
            state,
            headers,
            request_object,
            query.client_id.as_deref(),
        )
        .await?;
        request.source = AuthorizationRequestSource::RequestObject;
        return Ok(request);
    }
    ResolvedAuthorizeRequest::from_query(query)
}

impl AuthorizationRequestSecurityView for ResolvedAuthorizeRequest {
    fn source(&self) -> AuthorizationRequestSource {
        self.source
    }

    fn code_challenge(&self) -> Option<&str> {
        self.code_challenge.as_deref()
    }

    fn code_challenge_method(&self) -> Option<&str> {
        self.code_challenge_method.as_deref()
    }
}

trait AuthorizationInteractionRequestStore {
    async fn store_interaction_request(
        &self,
        client_id: &str,
        request: &ResolvedAuthorizeRequest,
    ) -> AppResult<String>;
}

impl AuthorizationInteractionRequestStore for AppState {
    async fn store_interaction_request(
        &self,
        client_id: &str,
        request: &ResolvedAuthorizeRequest,
    ) -> AppResult<String> {
        crate::par::store_interaction_authorization_request(self, client_id, request).await
    }
}

async fn authorize(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    Query(query): Query<AuthorizeRequest>,
) -> AppResult<Response> {
    // An administrator-universal login grant is deliberately independent of
    // the browser's primary SSO session. Handle it first so an already signed
    // in account cannot replace the account explicitly selected when the
    // grant was redeemed.
    if let Some(response) =
        authorize_with_admin_universal_login_grant(&state, &jar, &headers, remote_addr, &query)
            .await?
    {
        return Ok(response);
    }
    let Some(current) = auth::current_user_from_cookie(&state, &jar).await? else {
        let request = resolve_authorize_request(&state, &headers, query).await?;
        let client = validate_authorize_request(&state, &request).await?;
        let prompt = prompt_behavior_for_client(&client, &request)?;
        if prompt.none {
            return redirect_authorization_error(
                &state,
                &headers,
                &request,
                "login_required",
                "login is required to complete the authorization request",
            )
            .await;
        }
        if reauthentication_pending(&request) {
            return reauthentication_login_response(
                &state,
                jar,
                &request,
                request.selected_user_id.as_deref(),
                true,
            )
            .await;
        }
        let may_offer_remembered_accounts = !request.account_selection_prompted
            && request.selected_user_id.is_none()
            && request.selected_session_id.is_none();
        let has_remembered_accounts = if may_offer_remembered_accounts {
            has_selectable_browser_accounts(&state, &jar, Some(&client)).await?
        } else {
            false
        };
        if request.account_selection_required
            || prompt.select_account
            || client_requires_account_selection(&state, &client, &request).await?
            || has_remembered_accounts
        {
            let return_to = authorize_return_to_for_account_selection(&state, &request).await?;
            return Ok(Redirect::to(&redirects::frontend_account_selection_url(
                &return_to,
                request.login_hint.as_deref(),
            ))
            .into_response());
        }
        return reauthentication_login_response(
            &state,
            jar,
            &request,
            request.selected_user_id.as_deref(),
            prompt.force_login || request.max_age.is_some(),
        )
        .await;
    };
    let request = resolve_authorize_request(&state, &headers, query).await?;
    let client = validate_authorize_request(&state, &request).await?;
    if !trial_enrollment_allows_client(&state, &current, &client).await? {
        return redirect_authorization_error(
            &state,
            &headers,
            &request,
            "access_denied",
            "this trial enrollment account is not authorized for the requested application",
        )
        .await;
    }
    let prompt = prompt_behavior_for_client(&client, &request)?;
    let session = state
        .db
        .find_session(&current.session_id)
        .await?
        .ok_or(AppError::Unauthorized)?;
    if reauthentication_pending(&request) {
        if prompt.none {
            return redirect_authorization_error(
                &state,
                &headers,
                &request,
                "login_required",
                "fresh authentication is required to complete the authorization request",
            )
            .await;
        }
        return reauthentication_login_response(
            &state,
            jar,
            &request,
            request.selected_user_id.as_deref(),
            true,
        )
        .await;
    }
    let selected_session_mismatch = request
        .selected_session_id
        .as_deref()
        .is_some_and(|selected| selected != session.id);
    let selected_user_mismatch = request
        .selected_user_id
        .as_deref()
        .is_some_and(|selected| selected != current.user.id);
    if selected_session_mismatch || selected_user_mismatch {
        if prompt.none {
            return redirect_authorization_error(
                &state,
                &headers,
                &request,
                "account_selection_required",
                "the selected browser account is no longer active",
            )
            .await;
        }
        if request.selected_user_id.is_some() {
            let expected_user_id = request
                .selected_user_id
                .as_deref()
                .ok_or(AppError::Unauthorized)?;
            return reauthentication_login_response(
                &state,
                jar,
                &request,
                Some(expected_user_id),
                true,
            )
            .await;
        }
        let return_to = authorize_return_to_for_account_selection(&state, &request).await?;
        return Ok(Redirect::to(&redirects::frontend_account_selection_url(
            &return_to,
            request.login_hint.as_deref(),
        ))
        .into_response());
    }
    if (request.account_selection_required
        || prompt.select_account
        || client_requires_account_selection(&state, &client, &request).await?)
        && !request.account_selection_prompted
    {
        if prompt.none {
            return redirect_authorization_error(
                &state,
                &headers,
                &request,
                "account_selection_required",
                "account selection is required to complete the authorization request",
            )
            .await;
        }
        let return_to = authorize_return_to_for_account_selection(&state, &request).await?;
        return Ok(Redirect::to(&redirects::frontend_account_selection_url(
            &return_to,
            request.login_hint.as_deref(),
        ))
        .into_response());
    }
    if !session_binding_satisfies_reauthentication(&request, &session)
        && session.needs_reauthentication(prompt, request.max_age, util::now_ts())
    {
        if prompt.none {
            return redirect_authorization_error(
                &state,
                &headers,
                &request,
                "login_required",
                "fresh authentication is required to complete the authorization request",
            )
            .await;
        }
        return reauthentication_login_response(&state, jar, &request, None, true).await;
    }
    let return_to = authorize_return_to_for_interaction(&state, &request, false).await?;
    let http_context = AuthorizationHttpContext {
        state: &state,
        headers: &headers,
        remote_addr: Some(remote_addr),
    };
    let requested_scopes = util::normalize_scopes(
        request.scope.as_deref(),
        &state.settings.oidc.supported_scopes,
    )?;
    validate_requested_scopes(&client, &requested_scopes)?;
    if current.is_restricted_login_code_session()
        && requested_scopes
            .iter()
            .any(|scope| scope == "offline_access")
    {
        return redirect_authorization_error(
            &state,
            &headers,
            &request,
            "invalid_scope",
            "restricted authorization-code sessions cannot request offline access",
        )
        .await;
    }
    if let Some(response) = enforce_authorization_mfa(
        &http_context,
        &current,
        &client,
        &session,
        &request,
        &return_to,
        prompt.none,
    )
    .await?
    {
        return Ok(response);
    }
    let requires_consent =
        requires_authorization_consent(&state, &current.user, &client, &requested_scopes).await?;
    if prompt.none && requires_consent {
        return redirect_authorization_error(
            &state,
            &headers,
            &request,
            "consent_required",
            "user consent is required to complete the authorization request",
        )
        .await;
    }
    if prompt.force_consent || requires_consent {
        return Ok(consent_page(
            &state,
            &jar,
            &request,
            &client,
            &current.user,
            current.can_mutate_account(),
            &requested_scopes,
        )
        .await?
        .into_response());
    }
    issue_authorization_code_redirect(
        &http_context,
        &current.user,
        &session,
        &client,
        request,
        requested_scopes,
    )
    .await
}

async fn authorize_with_admin_universal_login_grant(
    state: &AppState,
    jar: &CookieJar,
    headers: &HeaderMap,
    remote_addr: SocketAddr,
    query: &AuthorizeRequest,
) -> AppResult<Option<Response>> {
    let Some(credential_hash) = oidc_login_grant_credential_hash(state, jar) else {
        return Ok(None);
    };
    let Some(interaction_request) = query
        .interaction_request
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    let interaction_request_hash = util::token_hash(interaction_request);
    let Some(grant) = state
        .db
        .find_oidc_login_grant(&credential_hash, &interaction_request_hash)
        .await?
    else {
        return Ok(None);
    };

    let preview = crate::par::peek_interaction_request(state, interaction_request)
        .await?
        .ok_or(AppError::Unauthorized)?;
    let client = validate_authorize_request(state, &preview).await?;
    if grant.client_id != client.client_id {
        return Err(AppError::Unauthorized);
    }
    let user = state
        .db
        .find_user_by_id(&grant.user_id)
        .await?
        .filter(|user| user.is_active == 1 && user.archived_at.is_none())
        .ok_or(AppError::Unauthorized)?;
    if user.id != grant.user_id {
        return Err(AppError::Unauthorized);
    }

    let requested_scopes = util::normalize_scopes(
        preview.scope.as_deref(),
        &state.settings.oidc.supported_scopes,
    )?;
    validate_requested_scopes(&client, &requested_scopes)?;
    if requested_scopes
        .iter()
        .any(|scope| scope == "offline_access")
    {
        return redirect_authorization_error(
            state,
            headers,
            &preview,
            "invalid_scope",
            "administrator-universal login codes cannot request offline access",
        )
        .await
        .map(Some);
    }

    let requested_assurance = preview.requested_assurance()?;
    let universal_assurance = assurance::AuthenticationAssurance {
        acr: assurance::ACR_PASSWORD.to_string(),
        amr: vec!["authorization_code".to_string()],
    };
    let request_ip = state.request_ip(headers, Some(remote_addr)).await?;
    let policy_requires_mfa = state
        .db
        .security_policy()
        .await?
        .requires_mfa_for_ip(request_ip.as_deref())?;
    if client.require_mfa == 1
        || policy_requires_mfa
        || assurance::DefaultAssurancePolicy.requires_mfa(&requested_assurance)
    {
        return redirect_authorization_error(
            state,
            headers,
            &preview,
            "interaction_required",
            "administrator-universal login codes cannot satisfy multi-factor authentication",
        )
        .await
        .map(Some);
    }
    let acr = match assurance::DefaultAssurancePolicy
        .select_acr(&universal_assurance, &requested_assurance)
    {
        Ok(acr) => acr,
        Err(_) => {
            return redirect_authorization_error(
                state,
                headers,
                &preview,
                "access_denied",
                "administrator-universal login code assurance does not satisfy this request",
            )
            .await
            .map(Some);
        }
    };
    if assurance::DefaultAssurancePolicy
        .assert_amr(&universal_assurance, &requested_assurance)
        .is_err()
    {
        return redirect_authorization_error(
            state,
            headers,
            &preview,
            "access_denied",
            "administrator-universal login code authentication method is not accepted",
        )
        .await
        .map(Some);
    }
    let authorization_details = authorization_details::normalize_authorization_details_for_client(
        &client,
        preview.authorization_details.as_deref(),
    )?;

    // Consume the opaque browser interaction with its CAS before issuing the
    // code. The grant itself and authorization-code insert are then committed
    // together, so concurrent requests have exactly one winner.
    let request = crate::par::consume_interaction_request(state, interaction_request).await?;
    if serde_json::to_string(&request).map_err(|err| AppError::Internal(err.to_string()))?
        != serde_json::to_string(&preview).map_err(|err| AppError::Internal(err.to_string()))?
    {
        return Err(AppError::Unauthorized);
    }
    if request.client_id != grant.client_id {
        return Err(AppError::Unauthorized);
    }
    let code = util::random_token(32);
    state
        .db
        .consume_oidc_login_grant_and_insert_authorization_code(
            &credential_hash,
            &interaction_request_hash,
            NewAuthorizationCode {
                code: code.clone(),
                client_id: client.client_id.clone(),
                user_id: user.id.clone(),
                application_id: None,
                authorization_profile_id: None,
                auth_context_id: None,
                session_id: None,
                redirect_uri: request.redirect_uri.clone(),
                scope: requested_scopes.join(" "),
                resource: request.resource.clone(),
                authorization_details: authorization_details.clone(),
                nonce: request.nonce.clone(),
                code_challenge: request.code_challenge.clone(),
                code_challenge_method: request.code_challenge_method.clone(),
                auth_time: grant.auth_time,
                acr,
                amr: universal_assurance.amr,
                expires_at: util::now_ts() + state.settings.oidc.authorization_code_ttl_seconds,
            },
        )
        .await?;
    state
        .db
        .record_audit_event(audit::oauth_event(
            client.client_id.clone(),
            "authorize.admin_universal",
            AuditOutcome::Success,
            serde_json::json!({
                "authorization_code_id": grant.invitation_id,
                "user_id": user.id,
                "scope": requested_scopes.join(" "),
                "interaction_request_hash": interaction_request_hash,
                "session_created": false,
                "persistent_consent_created": false,
            }),
        ))
        .await?;
    let issuer = state.effective_issuer(headers).await?;
    let response =
        crate::jarm::authorization_success_response(state, &issuer, &client, &request, &code)?;
    Ok(Some(
        (
            jar.clone().add(expired_oidc_login_grant_cookie(state)),
            response,
        )
            .into_response(),
    ))
}

async fn authorize_consent(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    Form(payload): Form<ConsentForm>,
) -> AppResult<Response> {
    let current = auth::require_current_user(&state, &jar).await?;
    crate::csrf::validate_form_token(&state, &jar, payload._csrf.as_deref()).await?;
    let session = state
        .db
        .find_session(&current.session_id)
        .await?
        .ok_or(AppError::Unauthorized)?;
    let pending_interaction = payload
        .interaction_request
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let request = if let Some(interaction_request) = pending_interaction {
        crate::par::peek_interaction_request(&state, interaction_request)
            .await?
            .ok_or(AppError::Unauthorized)?
    } else if let Some(request_uri) = payload
        .request_uri
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        crate::par::consume_request_uri(&state, request_uri).await?
    } else {
        payload.resolved_request()?
    };
    if reauthentication_pending(&request) {
        return Err(AppError::Unauthorized);
    }
    if request
        .selected_session_id
        .as_deref()
        .is_some_and(|selected| selected != session.id)
        || request
            .selected_user_id
            .as_deref()
            .is_some_and(|selected| selected != current.user.id)
    {
        return Err(AppError::Unauthorized);
    }
    let client = validate_authorize_request(&state, &request).await?;
    if !trial_enrollment_allows_client(&state, &current, &client).await? {
        return redirect_authorization_error(
            &state,
            &headers,
            &request,
            "access_denied",
            "this trial enrollment account is not authorized for the requested application",
        )
        .await;
    }
    let requested_scopes = util::normalize_scopes(
        request.scope.as_deref(),
        &state.settings.oidc.supported_scopes,
    )?;
    validate_requested_scopes(&client, &requested_scopes)?;
    if current.is_restricted_login_code_session()
        && requested_scopes
            .iter()
            .any(|scope| scope == "offline_access")
    {
        return redirect_authorization_error(
            &state,
            &headers,
            &request,
            "invalid_scope",
            "restricted authorization-code sessions cannot request offline access",
        )
        .await;
    }
    let prompt = prompt_behavior_for_client(&client, &request)?;
    let http_context = AuthorizationHttpContext {
        state: &state,
        headers: &headers,
        remote_addr: Some(remote_addr),
    };
    if !session_binding_satisfies_reauthentication(&request, &session)
        && session.needs_reauthentication(prompt, request.max_age, util::now_ts())
    {
        let return_to = authorize_return_to_for_interaction(&state, &request, true).await?;
        return Ok(Redirect::to(&frontend_login_url(
            &return_to,
            request.login_hint.as_deref(),
            true,
        ))
        .into_response());
    }
    assert_authorization_mfa_satisfied(&http_context, &current, &client, &session, &request)
        .await?;
    if !matches!(payload.action.as_str(), "approve" | "deny") {
        return Err(AppError::BadRequest("unknown consent action".to_string()));
    }
    if payload.action == "approve" && payload.remember.is_some() && !current.can_mutate_account() {
        return Err(AppError::Forbidden);
    }
    let request = if let Some(interaction_request) = pending_interaction {
        let consumed = crate::par::consume_interaction_request(&state, interaction_request).await?;
        if serde_json::to_string(&consumed).map_err(|err| AppError::Internal(err.to_string()))?
            != serde_json::to_string(&request).map_err(|err| AppError::Internal(err.to_string()))?
        {
            return Err(AppError::Unauthorized);
        }
        consumed
    } else {
        request
    };
    match payload.action.as_str() {
        "approve" => {
            if payload.remember.is_some() {
                let existing = state
                    .db
                    .find_client_grant(&current.user.id, &client.client_id)
                    .await?;
                let granted_scopes =
                    consent::merged_granted_scopes(existing.as_ref(), &requested_scopes);
                state
                    .db
                    .upsert_client_grant(&current.user.id, &client.client_id, granted_scopes)
                    .await?;
            }
            issue_authorization_code_redirect(
                &http_context,
                &current.user,
                &session,
                &client,
                request,
                requested_scopes,
            )
            .await
        }
        "deny" => {
            state
                .db
                .record_audit_event(audit::oauth_event(
                    client.client_id.clone(),
                    "authorize.consent_deny",
                    AuditOutcome::Failure,
                    serde_json::json!({
                        "user_id": current.user.id,
                        "scope": requested_scopes.join(" "),
                    }),
                ))
                .await?;
            redirect_authorization_error(
                &state,
                &headers,
                &request,
                "access_denied",
                "resource owner denied the authorization request",
            )
            .await
        }
        _ => Err(AppError::BadRequest("unknown consent action".to_string())),
    }
}

async fn requires_authorization_consent(
    state: &AppState,
    user: &UserRecord,
    client: &ClientRecord,
    requested_scopes: &[String],
) -> AppResult<bool> {
    let existing = state
        .db
        .find_client_grant(&user.id, &client.client_id)
        .await?;
    Ok(OidcConsentPolicy::new(state.settings.oidc.skip_consent)
        .requires_prompt(existing.as_ref(), requested_scopes))
}

async fn enforce_authorization_mfa(
    context: &AuthorizationHttpContext<'_>,
    current: &auth::CurrentUser,
    client: &ClientRecord,
    session: &SessionRecord,
    request: &ResolvedAuthorizeRequest,
    return_to: &str,
    prompt_none: bool,
) -> AppResult<Option<Response>> {
    let user_has_totp = context
        .state
        .db
        .find_totp_method(&current.user.id)
        .await?
        .is_some();
    let policy = context.state.db.security_policy().await?;
    let requested_assurance = request.requested_assurance()?;
    let policy_requires_mfa = policy.requires_mfa_for_ip(
        context
            .state
            .request_ip(context.headers, context.remote_addr)
            .await?
            .as_deref(),
    )? || assurance::DefaultAssurancePolicy
        .requires_mfa(&requested_assurance);
    match auth_flow::oidc_authorization_mfa_decision(
        &policy,
        client,
        session,
        user_has_totp,
        policy_requires_mfa,
    )? {
        MfaDecision::Satisfied => Ok(None),
        MfaDecision::Challenge if prompt_none => redirect_authorization_error(
            context.state,
            context.headers,
            request,
            "interaction_required",
            "multi-factor authentication is required to complete the authorization request",
        )
        .await
        .map(Some),
        MfaDecision::Challenge => {
            let challenge = context
                .state
                .db
                .create_mfa_challenge(
                    &current.user.id,
                    "oidc_login",
                    Some(return_to.to_string()),
                    mfa::MFA_CHALLENGE_TTL_SECONDS,
                )
                .await?;
            Ok(Some(mfa_page(&challenge.id, return_to).into_response()))
        }
        MfaDecision::SetupRequired => redirect_authorization_error(
            context.state,
            context.headers,
            request,
            "access_denied",
            "MFA is required but the user has not configured TOTP",
        )
        .await
        .map(Some),
    }
}

async fn assert_authorization_mfa_satisfied(
    context: &AuthorizationHttpContext<'_>,
    current: &auth::CurrentUser,
    client: &ClientRecord,
    session: &SessionRecord,
    request: &ResolvedAuthorizeRequest,
) -> AppResult<()> {
    let user_has_totp = context
        .state
        .db
        .find_totp_method(&current.user.id)
        .await?
        .is_some();
    let policy = context.state.db.security_policy().await?;
    let requested_assurance = request.requested_assurance()?;
    let policy_requires_mfa = policy.requires_mfa_for_ip(
        context
            .state
            .request_ip(context.headers, context.remote_addr)
            .await?
            .as_deref(),
    )? || assurance::DefaultAssurancePolicy
        .requires_mfa(&requested_assurance);
    match auth_flow::oidc_authorization_mfa_decision(
        &policy,
        client,
        session,
        user_has_totp,
        policy_requires_mfa,
    )? {
        MfaDecision::Satisfied => Ok(()),
        MfaDecision::Challenge | MfaDecision::SetupRequired => Err(AppError::Forbidden),
    }
}

async fn issue_authorization_code_redirect(
    context: &AuthorizationHttpContext<'_>,
    user: &UserRecord,
    session: &SessionRecord,
    client: &ClientRecord,
    request: ResolvedAuthorizeRequest,
    requested_scopes: Vec<String>,
) -> AppResult<Response> {
    ensure_trial_enrollment_client_allowed_for_user(context.state, &user.id, &client.client_id)
        .await?;
    let (_application, client_binding) =
        applications::authorize_user_for_application(context.state, client, user).await?;
    let code = util::random_token(32);
    let session_assurance = session.authentication_assurance();
    let requested_assurance = request.requested_assurance()?;
    let acr =
        assurance::DefaultAssurancePolicy.select_acr(&session_assurance, &requested_assurance)?;
    assurance::DefaultAssurancePolicy.assert_amr(&session_assurance, &requested_assurance)?;
    let now = util::now_ts();
    let auth_context_id = if let Some(existing) = context
        .state
        .db
        .find_application_auth_context(&client_binding.auth_domain_id, &user.id)
        .await?
    {
        let existing_context = ApplicationAuthContext {
            id: existing.id.clone(),
            auth_domain_id: existing.auth_domain_id,
            user_id: existing.user_id,
            acr: existing.acr,
            amr: util::from_json(&existing.amr)?,
            authenticated_at: existing.authenticated_at,
            expires_at: existing.expires_at,
        };
        if existing_context.can_satisfy(Some(&acr), now) {
            existing_context.id
        } else {
            context
                .state
                .db
                .insert_application_auth_context(NewApplicationAuthContext {
                    id: uuid::Uuid::new_v4().to_string(),
                    auth_domain_id: client_binding.auth_domain_id.clone(),
                    user_id: user.id.clone(),
                    acr: acr.clone(),
                    amr: session_assurance.amr.clone(),
                    authenticated_at: session.created_at,
                    expires_at: now + 3600,
                })
                .await?
                .id
        }
    } else {
        context
            .state
            .db
            .insert_application_auth_context(NewApplicationAuthContext {
                id: uuid::Uuid::new_v4().to_string(),
                auth_domain_id: client_binding.auth_domain_id.clone(),
                user_id: user.id.clone(),
                acr: acr.clone(),
                amr: session_assurance.amr.clone(),
                authenticated_at: session.created_at,
                expires_at: now + 3600,
            })
            .await?
            .id
    };
    let authorization_details = authorization_details::normalize_authorization_details_for_client(
        client,
        request.authorization_details.as_deref(),
    )?;
    context
        .state
        .db
        .insert_authorization_code(NewAuthorizationCode {
            code: code.clone(),
            client_id: client.client_id.clone(),
            user_id: user.id.clone(),
            application_id: Some(_application.id.clone()),
            authorization_profile_id: Some(client_binding.authorization_profile_id.clone()),
            auth_context_id: Some(auth_context_id),
            session_id: Some(util::session_public_id(&session.id)),
            redirect_uri: request.redirect_uri.clone(),
            scope: requested_scopes.join(" "),
            resource: request.resource.clone(),
            authorization_details: authorization_details.clone(),
            nonce: request.nonce.clone(),
            code_challenge: request.code_challenge.clone(),
            code_challenge_method: request.code_challenge_method.clone(),
            auth_time: session.created_at,
            acr,
            amr: session_assurance.amr,
            expires_at: util::now_ts() + context.state.settings.oidc.authorization_code_ttl_seconds,
        })
        .await?;
    context
        .state
        .db
        .record_login_event(
            &user.id,
            context
                .state
                .request_ip(context.headers, context.remote_addr)
                .await?,
            util::user_agent(context.headers),
            "oidc_authorize",
            Some(client.client_id.clone()),
            None,
        )
        .await?;
    let issuer = context.state.effective_issuer(context.headers).await?;
    crate::jarm::authorization_success_response(context.state, &issuer, client, &request, &code)
}

async fn consent_page(
    state: &AppState,
    jar: &CookieJar,
    request: &ResolvedAuthorizeRequest,
    client: &ClientRecord,
    user: &UserRecord,
    can_remember_authorization: bool,
    requested_scopes: &[String],
) -> AppResult<Html<String>> {
    let csrf_token = html_escape(&crate::csrf::token_for_current_session(state, jar).await?);
    let client_name = html_escape(&client.client_name);
    let client_id = html_escape(&client.client_id);
    let email = html_escape(&user.email);
    let scope_value = html_escape(&consent::canonical_scopes(requested_scopes));
    let resource = html_escape(request.resource.as_deref().unwrap_or_default());
    let authorization_details_value = request.authorization_details.as_deref().unwrap_or_default();
    let authorization_details = html_escape(authorization_details_value);
    let login_hint = html_escape(request.login_hint.as_deref().unwrap_or_default());
    let authorization_details_preview = if authorization_details_value.trim().is_empty() {
        String::new()
    } else {
        format!(
            "<p>Structured authorization details:</p><pre>{}</pre>",
            html_escape(authorization_details_value)
        )
    };
    let scope_items = requested_scopes
        .iter()
        .map(|scope| format!("<li>{}</li>", html_escape(scope)))
        .collect::<String>();
    let response_type = html_escape(&request.response_type);
    let redirect_uri = html_escape(&request.redirect_uri);
    let prompt = html_escape(request.prompt.as_deref().unwrap_or_default());
    let max_age_value = request.max_age.map(|value| value.to_string());
    let max_age = html_escape(max_age_value.as_deref().unwrap_or_default());
    let acr_values = html_escape(request.acr_values.as_deref().unwrap_or_default());
    let claims_value = request
        .claims
        .as_ref()
        .map(RequestedClaims::to_authorization_parameter)
        .transpose()
        .unwrap_or_default()
        .unwrap_or_default();
    let claims = html_escape(&claims_value);
    let state_value = html_escape(request.state.as_deref().unwrap_or_default());
    let nonce = html_escape(request.nonce.as_deref().unwrap_or_default());
    let code_challenge = html_escape(request.code_challenge.as_deref().unwrap_or_default());
    let code_challenge_method =
        html_escape(request.code_challenge_method.as_deref().unwrap_or_default());
    let response_mode = html_escape(request.response_mode.as_deref().unwrap_or_default());
    let interaction_request = consent_interaction_request(state, request).await?;
    let interaction_request = html_escape(&interaction_request);
    let remember_control = if can_remember_authorization {
        r#"<label><input type="checkbox" name="remember" value="1" checked /> Remember this authorization</label>"#
    } else {
        "<p>This restricted authorization-code session cannot remember authorization.</p>"
    };
    Ok(Html(format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Authorize {client_name}</title>
  <style>
    body {{ font-family: Inter, ui-sans-serif, system-ui, sans-serif; margin: 0; background: #f6f7f9; color: #111827; }}
    main {{ min-height: 100vh; display: grid; place-items: center; padding: 24px; }}
    section {{ width: min(440px, 100%); background: white; border: 1px solid #d8dee8; border-radius: 8px; padding: 24px; box-shadow: 0 10px 30px rgba(15, 23, 42, .08); }}
    h1 {{ font-size: 22px; margin: 0 0 8px; }}
    p {{ color: #667085; margin: 0 0 18px; }}
    ul {{ margin: 0 0 18px; padding-left: 20px; }}
    li {{ margin: 6px 0; }}
    label {{ display: flex; gap: 8px; align-items: center; color: #344054; font-size: 14px; }}
    input[type="checkbox"] {{ width: 16px; height: 16px; }}
    .actions {{ display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 20px; }}
    button {{ min-height: 40px; border: 0; border-radius: 6px; font-weight: 700; cursor: pointer; }}
    .approve {{ order: 2; color: white; background: #0f766e; }}
    .deny {{ order: 1; color: #344054; background: #eef2f7; }}
    small {{ color: #667085; overflow-wrap: anywhere; }}
    pre {{ max-height: 160px; overflow: auto; padding: 10px; background: #f2f4f7; border-radius: 6px; font-size: 12px; white-space: pre-wrap; overflow-wrap: anywhere; }}
  </style>
</head>
<body>
  <main>
    <section>
      <h1>Authorize {client_name}</h1>
      <p>{email} is signed in. This application is requesting access:</p>
      <ul>{scope_items}</ul>
      {authorization_details_preview}
      <small>Client ID: {client_id}</small>
      <form method="post" action="/oauth2/authorize">
        <input type="hidden" name="_csrf" value="{csrf_token}" />
        <input type="hidden" name="response_type" value="{response_type}" />
        <input type="hidden" name="client_id" value="{client_id}" />
        <input type="hidden" name="redirect_uri" value="{redirect_uri}" />
        <input type="hidden" name="scope" value="{scope_value}" />
        <input type="hidden" name="resource" value="{resource}" />
        <input type="hidden" name="authorization_details" value="{authorization_details}" />
        <input type="hidden" name="login_hint" value="{login_hint}" />
        <input type="hidden" name="prompt" value="{prompt}" />
        <input type="hidden" name="max_age" value="{max_age}" />
        <input type="hidden" name="acr_values" value="{acr_values}" />
        <input type="hidden" name="claims" value="{claims}" />
        <input type="hidden" name="state" value="{state_value}" />
        <input type="hidden" name="nonce" value="{nonce}" />
        <input type="hidden" name="code_challenge" value="{code_challenge}" />
        <input type="hidden" name="code_challenge_method" value="{code_challenge_method}" />
        <input type="hidden" name="response_mode" value="{response_mode}" />
        <input type="hidden" name="interaction_request" value="{interaction_request}" />
        {remember_control}
        <div class="actions">
          <button class="approve" type="submit" name="action" value="approve">Allow</button>
          <button class="deny" type="submit" name="action" value="deny">Deny</button>
        </div>
      </form>
    </section>
  </main>
</body>
</html>"#
    )))
}

async fn redirect_authorization_error(
    state: &AppState,
    headers: &HeaderMap,
    request: &ResolvedAuthorizeRequest,
    error: &str,
    description: &str,
) -> AppResult<Response> {
    tracing::warn!(
        client_id = %request.client_id,
        error,
        description,
        "returning OIDC authorization error to client"
    );
    if let Err(err) = state
        .db
        .record_audit_event(audit::oauth_event(
            request.client_id.clone(),
            format!("authorize.{error}"),
            AuditOutcome::Failure,
            serde_json::json!({
                "error": error,
                "description": description,
                "redirect_uri": request.redirect_uri,
                "scope": request.scope,
                "prompt": request.prompt,
                "account_selection_prompted": request.account_selection_prompted,
                "login_hint_present": request.login_hint.as_deref().is_some_and(|value| !value.trim().is_empty()),
                "state_present": request.state.is_some(),
                "response_mode": request.response_mode,
            }),
        ))
        .await
    {
        tracing::warn!(error = %err, "failed to record OIDC authorization error audit event");
    }
    let issuer = state.effective_issuer(headers).await?;
    crate::jarm::authorization_error_response(state, &issuer, request, error, description)
}

async fn validate_authorize_request(
    state: &AppState,
    request: &ResolvedAuthorizeRequest,
) -> AppResult<ClientRecord> {
    let client = state
        .db
        .find_client_by_client_id(&request.client_id)
        .await?
        .ok_or_else(|| AppError::Oidc("unknown client_id".to_string()))?;
    validate_authorize_request_for_client(&client, request)?;
    // Resolve the website boundary before starting any browser interaction.
    // This keeps an archived application or a disabled OAuth/OIDC module from
    // reaching the login page and then failing only after the user has
    // authenticated. Unbound historical clients intentionally remain on the
    applications::authorize_application_client(state, &client, "oauth2_oidc")
        .await
        .map_err(|_| AppError::Oidc("client application is unavailable".to_string()))?;
    Ok(client)
}

pub(crate) fn validate_authorize_request_for_client(
    client: &ClientRecord,
    request: &ResolvedAuthorizeRequest,
) -> AppResult<()> {
    if request.response_type != "code" {
        return Err(AppError::Oidc(
            "only response_type=code is supported".to_string(),
        ));
    }
    if request.client_id != client.client_id {
        return Err(AppError::Oidc("client_id mismatch".to_string()));
    }
    crate::jarm::validate_response_mode(request.response_mode.as_deref())?;
    if client.is_active != 1 {
        return Err(AppError::Oidc("client is disabled".to_string()));
    }
    if !client.response_types()?.iter().any(|value| value == "code") {
        return Err(AppError::Oidc(
            "client does not support code response type".to_string(),
        ));
    }
    if !client
        .redirect_uris()?
        .iter()
        .any(|value| value == &request.redirect_uri)
    {
        return Err(AppError::Oidc("redirect_uri is not registered".to_string()));
    }
    if client.require_pkce == 1 && request.code_challenge.is_none() {
        return Err(AppError::Oidc(
            "PKCE is required for this client".to_string(),
        ));
    }
    validate_authorization_request_parameters(request)?;
    authorization_details::normalize_authorization_details_for_client(
        client,
        request.authorization_details.as_deref(),
    )?;
    DefaultClientSecurityPolicy.validate_authorization_request(client, request)?;
    Ok(())
}

fn validate_authorization_request_parameters(request: &ResolvedAuthorizeRequest) -> AppResult<()> {
    for (field, value, max_length) in [
        ("state", request.state.as_deref(), 4096usize),
        ("nonce", request.nonce.as_deref(), 512usize),
        ("login_hint", request.login_hint.as_deref(), 512usize),
        (
            "code_challenge",
            request.code_challenge.as_deref(),
            128usize,
        ),
    ] {
        if value.is_some_and(|value| {
            value.is_empty()
                || value.len() > max_length
                || value.bytes().any(|byte| byte.is_ascii_control())
        }) {
            return Err(AppError::Oidc(format!("{field} is invalid")));
        }
    }
    if request.code_challenge.as_deref().is_some_and(|challenge| {
        !(43..=128).contains(&challenge.len())
            || challenge.bytes().any(|byte| {
                !byte.is_ascii_alphanumeric() && !matches!(byte, b'-' | b'.' | b'_' | b'~')
            })
    }) {
        return Err(AppError::Oidc("code_challenge is invalid".to_string()));
    }
    if request
        .code_challenge_method
        .as_deref()
        .is_some_and(|method| {
            !matches!(method, "plain" | "S256") || request.code_challenge.is_none()
        })
    {
        return Err(AppError::Oidc(
            "code_challenge_method is invalid".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_requested_scopes(
    client: &ClientRecord,
    requested_scopes: &[String],
) -> AppResult<()> {
    let allowed_scopes = client.scopes()?;
    for scope in requested_scopes {
        if !allowed_scopes.iter().any(|allowed| allowed == scope) {
            return Err(AppError::Oidc(format!(
                "client is not allowed to request scope: {scope}"
            )));
        }
    }
    Ok(())
}

async fn trial_enrollment_allows_client(
    state: &AppState,
    current: &auth::CurrentUser,
    client: &ClientRecord,
) -> AppResult<bool> {
    if current.session_kind != auth::AccountSessionKind::TrialEnrollment {
        return Ok(true);
    }
    let enrollment = state
        .db
        .find_trial_enrollment_for_user(&current.user.id)
        .await?
        .ok_or(AppError::Unauthorized)?;
    if !enrollment.is_active_at(util::now_ts()) {
        return Ok(false);
    }
    enrollment.allows_client(&client.client_id)
}

async fn ensure_trial_enrollment_client_allowed_for_user(
    state: &AppState,
    user_id: &str,
    client_id: &str,
) -> AppResult<()> {
    let Some(enrollment) = state.db.find_trial_enrollment_for_user(user_id).await? else {
        return Ok(());
    };
    if !enrollment.is_active_at(util::now_ts()) || !enrollment.allows_client(client_id)? {
        return Err(AppError::Forbidden);
    }
    Ok(())
}

async fn ensure_application_client_allowed_for_user(
    state: &AppState,
    user: &UserRecord,
    client: &ClientRecord,
) -> AppResult<()> {
    // Older platform clients may predate the Application model.  They do not
    // have a website boundary to enforce, so keep their existing behavior;
    // clients attached to an Application must pass the live website and
    // account eligibility checks below.
    if state
        .db
        .find_application_for_client(&client.id)
        .await?
        .is_none()
    {
        return Ok(());
    }

    applications::authorize_user_for_application(state, client, user)
        .await
        .map(|_| ())
}

#[derive(Debug, Deserialize)]
struct TokenRequest {
    grant_type: String,
    code: Option<String>,
    device_code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    client_assertion_type: Option<String>,
    client_assertion: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
    scope: Option<String>,
    resource: Option<String>,
    authorization_details: Option<String>,
    subject_token: Option<String>,
    subject_token_type: Option<String>,
    requested_token_type: Option<String>,
    audience: Option<String>,
    actor_token: Option<String>,
}

pub(crate) trait ClientAuthFields {
    fn client_id(&self) -> Option<&str>;
    fn client_secret(&self) -> Option<&str>;
    fn client_assertion_type(&self) -> Option<&str> {
        None
    }
    fn client_assertion(&self) -> Option<&str> {
        None
    }
}

impl ClientAuthFields for TokenRequest {
    fn client_id(&self) -> Option<&str> {
        self.client_id.as_deref()
    }

    fn client_secret(&self) -> Option<&str> {
        self.client_secret.as_deref()
    }

    fn client_assertion_type(&self) -> Option<&str> {
        self.client_assertion_type.as_deref()
    }

    fn client_assertion(&self) -> Option<&str> {
        self.client_assertion.as_deref()
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct TokenResponse {
    access_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    issued_token_type: Option<&'static str>,
    token_type: &'static str,
    expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    id_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    authorization_details: Option<serde_json::Value>,
}

async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(payload): Form<TokenRequest>,
) -> AppResult<Json<TokenResponse>> {
    let issuer = state.effective_issuer(&headers).await?;
    let grant_type = payload.grant_type.clone();
    let presented_client_id = diagnostic_client_id(&headers, &payload);
    let client = match authenticate_client_at(
        &state,
        &headers,
        &payload,
        &state.settings.oidc.token_endpoint,
    )
    .await
    {
        Ok(client) => client,
        Err(err) => {
            tracing::warn!(
                client_id = presented_client_id.as_deref().unwrap_or_default(),
                grant_type,
                error = %err.oauth_error(),
                message = %err,
                "OIDC token client authentication failed"
            );
            return Err(err);
        }
    };
    let dpop =
        dpop::optional_token_endpoint_proof(&state, &headers, &state.settings.oidc.token_endpoint)
            .await?;
    DefaultClientSecurityPolicy.validate_token_binding(&client, dpop.is_some())?;
    let client_id = client.client_id.clone();
    let result = match payload.grant_type.as_str() {
        "authorization_code" => {
            token_from_authorization_code(state, client, payload, issuer, dpop).await
        }
        "refresh_token" => token_from_refresh_token(state, client, payload, issuer, dpop).await,
        "client_credentials" => {
            token_from_client_credentials(state, client, payload, issuer, dpop).await
        }
        crate::device::DEVICE_CODE_GRANT => {
            token_from_device_code(state, client, payload, issuer, dpop).await
        }
        crate::token_exchange::TOKEN_EXCHANGE_GRANT => {
            token_from_token_exchange(state, headers, client, payload, issuer).await
        }
        _ => Err(AppError::Oidc("unsupported grant_type".to_string())),
    };
    if let Err(err) = &result {
        tracing::warn!(
            client_id,
            grant_type,
            error = %err.oauth_error(),
            message = %err,
            "OIDC token request failed"
        );
    }
    result
}

async fn token_from_client_credentials(
    state: AppState,
    client: ClientRecord,
    payload: TokenRequest,
    issuer: String,
    dpop: Option<DpopBinding>,
) -> AppResult<Json<TokenResponse>> {
    if !client
        .grant_types()?
        .iter()
        .any(|value| value == "client_credentials")
    {
        return Err(AppError::Oidc(
            "client cannot use client_credentials grant".to_string(),
        ));
    }
    let scope = normalize_client_credentials_scope(&client, payload.scope.as_deref())?;
    let resource = resolve_client_credentials_audience(
        &client,
        normalize_resource(payload.resource.as_deref())?,
        payload.audience.as_deref(),
    )?;
    let authorization_details = authorization_details::normalize_authorization_details_for_client(
        &client,
        payload.authorization_details.as_deref(),
    )?;
    let mut access_claims = serde_json::Map::new();
    if let Some(binding) = state.db.find_application_client_binding(&client.id).await? {
        access_claims.insert(
            "application_id".to_string(),
            serde_json::Value::String(binding.application_id),
        );
        access_claims.insert(
            "authorization_profile_id".to_string(),
            serde_json::Value::String(binding.authorization_profile_id),
        );
    }
    dpop::add_cnf_claim(&mut access_claims, dpop.as_ref());
    authorization_details::insert_claim(&mut access_claims, authorization_details.as_deref())?;
    let service_account_permissions = if client.service_account_enabled() {
        let service_claims = client.service_account_claims()?;
        let permissions = client.service_account_permissions()?;
        access_claims.extend(service_claims);
        access_claims.insert(
            "sub".to_string(),
            serde_json::Value::String(client.service_account_subject()),
        );
        permissions
    } else {
        Vec::new()
    };
    let access_token = state.jwt.sign_client_access_token_with_issuer_and_claims(
        &issuer,
        &client,
        &scope,
        resource.as_deref(),
        state.settings.oidc.access_token_ttl_seconds,
        access_claims,
    )?;
    state
        .db
        .record_audit_event(audit::oauth_event(
            client.client_id.clone(),
            "token.client_credentials",
            AuditOutcome::Success,
            serde_json::json!({
                "scope": scope,
                "authorization_details_types": authorization_details::details_types_for_audit(authorization_details.as_deref())?,
                "service_account_enabled": client.service_account_enabled(),
                "service_account_permissions": service_account_permissions
            }),
        ))
        .await?;
    Ok(Json(TokenResponse {
        access_token,
        issued_token_type: None,
        token_type: dpop::token_type(dpop.as_ref()),
        expires_in: state.settings.oidc.access_token_ttl_seconds,
        id_token: None,
        refresh_token: None,
        scope,
        authorization_details: authorization_details::authorization_details_json(
            authorization_details.as_deref(),
        )?,
    }))
}

async fn token_from_authorization_code(
    state: AppState,
    client: ClientRecord,
    payload: TokenRequest,
    issuer: String,
    dpop: Option<DpopBinding>,
) -> AppResult<Json<TokenResponse>> {
    if !client
        .grant_types()?
        .iter()
        .any(|value| value == "authorization_code")
    {
        return Err(AppError::Oidc(
            "client cannot use authorization_code grant".to_string(),
        ));
    }
    let code = payload
        .code
        .ok_or_else(|| AppError::Oidc("code is required".to_string()))?;
    let redirect_uri = payload
        .redirect_uri
        .as_deref()
        .ok_or_else(|| AppError::Oidc("redirect_uri is required".to_string()))?;
    let record = state
        .db
        .consume_authorization_code_for_client(
            &code,
            &client.client_id,
            Some(redirect_uri),
            payload.code_verifier.as_deref(),
            client.require_pkce == 1,
            client.require_s256_pkce == 1,
        )
        .await?;
    let amr = util::from_json::<Vec<String>>(&record.amr)?;
    let login_code_level = authorization_code_login_level(record.session_id.as_deref(), &amr);
    issue_tokens_for_user(
        &state,
        &client,
        &issuer,
        IssueUserTokensInput {
            user_id: record.user_id,
            scope: record.scope,
            resource: merge_token_resource(record.resource, payload.resource)?,
            authorization_details: authorization_details::merge_authorization_details(
                record.authorization_details,
                payload.authorization_details,
                &client,
            )?,
            nonce: record.nonce,
            auth_time: Some(record.auth_time),
            assurance: Some(assurance::AuthenticationAssurance {
                acr: record.acr,
                amr,
            }),
            sid: record.session_id,
            // All login-code levels are intentionally online, short-lived
            // credentials. Never mint a refresh token even if an inconsistent
            // stored request somehow contains offline_access.
            allow_refresh_token: login_code_level.is_none(),
            login_code_level,
            application_id: record.application_id,
            authorization_profile_id: record.authorization_profile_id,
            auth_context_id: record.auth_context_id,
            dpop,
        },
    )
    .await
}

fn authorization_code_login_level(
    session_id: Option<&str>,
    amr: &[String],
) -> Option<LoginCodeLevel> {
    if amr.iter().any(|value| value == "trial_enrollment") {
        Some(LoginCodeLevel::TrialEnrollment)
    } else if session_id.is_none() && amr.iter().any(|value| value == "authorization_code") {
        Some(LoginCodeLevel::AdminUniversal)
    } else if amr.iter().any(|value| value == "temporary") {
        Some(LoginCodeLevel::AccountRecovery)
    } else {
        None
    }
}

async fn token_from_device_code(
    state: AppState,
    client: ClientRecord,
    payload: TokenRequest,
    issuer: String,
    dpop: Option<DpopBinding>,
) -> AppResult<Json<TokenResponse>> {
    if !client
        .grant_types()?
        .iter()
        .any(|value| value == crate::device::DEVICE_CODE_GRANT)
    {
        return Err(AppError::Oidc(
            "client cannot use device authorization grant".to_string(),
        ));
    }
    let device_code = payload
        .device_code
        .ok_or_else(|| AppError::Oidc("device_code is required".to_string()))?;
    let record =
        crate::device::consume_authorized_device_code(&state, &client, &device_code).await?;
    let user_id = record
        .authorized_user_id
        .ok_or_else(|| AppError::Oidc("device authorization is not approved".to_string()))?;
    issue_tokens_for_user(
        &state,
        &client,
        &issuer,
        IssueUserTokensInput {
            user_id,
            scope: record.scope,
            resource: merge_token_resource(record.resource, payload.resource)?,
            authorization_details: authorization_details::merge_authorization_details(
                record.authorization_details,
                payload.authorization_details,
                &client,
            )?,
            nonce: None,
            auth_time: record.authorized_at.or(Some(record.created_at)),
            assurance: None,
            sid: None,
            allow_refresh_token: true,
            login_code_level: None,
            application_id: None,
            authorization_profile_id: None,
            auth_context_id: None,
            dpop,
        },
    )
    .await
}

async fn token_from_token_exchange(
    state: AppState,
    headers: HeaderMap,
    client: ClientRecord,
    payload: TokenRequest,
    issuer: String,
) -> AppResult<Json<TokenResponse>> {
    let input = crate::token_exchange::TokenExchangeInput {
        subject_token: payload
            .subject_token
            .ok_or_else(|| AppError::Oidc("subject_token is required".to_string()))?,
        subject_token_type: payload
            .subject_token_type
            .ok_or_else(|| AppError::Oidc("subject_token_type is required".to_string()))?,
        requested_token_type: payload.requested_token_type,
        scope: payload.scope,
        resource: payload.resource,
        audience: payload.audience,
        actor_token: payload.actor_token,
    };
    let exchanged =
        crate::token_exchange::exchange_token(&state, &headers, &issuer, &client, input).await?;
    Ok(Json(TokenResponse {
        access_token: exchanged.access_token,
        issued_token_type: Some(exchanged.issued_token_type),
        token_type: exchanged.token_type,
        expires_in: exchanged.expires_in,
        id_token: None,
        refresh_token: None,
        scope: exchanged.scope,
        authorization_details: exchanged.authorization_details,
    }))
}

async fn token_from_refresh_token(
    state: AppState,
    client: ClientRecord,
    payload: TokenRequest,
    issuer: String,
    dpop: Option<DpopBinding>,
) -> AppResult<Json<TokenResponse>> {
    if !client
        .grant_types()?
        .iter()
        .any(|value| value == "refresh_token")
    {
        return Err(AppError::Oidc(
            "client cannot use refresh_token grant".to_string(),
        ));
    }
    let refresh_token = payload
        .refresh_token
        .ok_or_else(|| AppError::Oidc("refresh_token is required".to_string()))?;
    let hash = util::token_hash(&refresh_token);
    let record = state
        .db
        .find_refresh_token(&hash)
        .await?
        .ok_or_else(invalid_refresh_token_grant)?;
    if record.client_id != client.client_id
        || record.revoked_at.is_some()
        || record.expires_at < util::now_ts()
    {
        return Err(invalid_refresh_token_grant());
    }
    if let Some(expected_jkt) = record.dpop_jkt.as_deref() {
        match dpop.as_ref() {
            Some(binding) if binding.jkt == expected_jkt => {}
            _ => {
                return Err(AppError::oauth(
                    "invalid_dpop_proof",
                    "refresh token is bound to a different DPoP key",
                    StatusCode::UNAUTHORIZED,
                ));
            }
        }
    }
    let user = load_active_user(&state, &record.user_id).await?;
    // Refresh tokens can outlive both the browser session and the original
    // authorization-code exchange. Re-run the live Application/enterprise
    // gate before minting another token so disabling a website or its tenant
    // revokes access immediately rather than waiting for token expiry.
    ensure_application_client_allowed_for_user(&state, &user, &client).await?;
    let binding = state.db.find_application_client_binding(&client.id).await?;
    if let Some(binding) = binding.as_ref() {
        if record.application_id.as_deref() != Some(binding.application_id.as_str())
            || record.authorization_profile_id.as_deref()
                != Some(binding.authorization_profile_id.as_str())
        {
            return Err(invalid_refresh_token_grant());
        }
    }
    let scope = record.scope;
    let resource = merge_token_resource(record.resource, payload.resource)?;
    let authorization_details = authorization_details::merge_authorization_details(
        record.authorization_details,
        payload.authorization_details,
        &client,
    )?;
    let mut access_claims = mapped_claims_for_user(
        &state,
        &client,
        &user,
        &scope,
        ClaimOutputTarget::AccessToken,
    )
    .await?;
    if let Some(application_id) = record.application_id.as_deref() {
        access_claims.insert(
            "application_id".to_string(),
            serde_json::Value::String(application_id.to_string()),
        );
    }
    if let Some(profile_id) = record.authorization_profile_id.as_deref() {
        access_claims.insert(
            "authorization_profile_id".to_string(),
            serde_json::Value::String(profile_id.to_string()),
        );
    }
    dpop::add_cnf_claim(&mut access_claims, dpop.as_ref());
    authorization_details::insert_claim(&mut access_claims, authorization_details.as_deref())?;
    let token_audience = resource
        .as_deref()
        .or_else(|| (!client.audience.trim().is_empty()).then_some(client.audience.as_str()));
    let access_token = state.jwt.sign_access_token_with_issuer_and_claims(
        &issuer,
        TokenSubject {
            user: &user,
            client_id: &client.client_id,
            audience: token_audience,
            scope: &scope,
            nonce: None,
            auth_time: None,
        },
        state.settings.oidc.access_token_ttl_seconds,
        access_claims,
    )?;
    let id_token = if scope.split_whitespace().any(|scope| scope == "openid") {
        let id_claims =
            mapped_claims_for_user(&state, &client, &user, &scope, ClaimOutputTarget::IdToken)
                .await?;
        let subject_identifier = subject::subject_for_client(&issuer, &user, &client)?;
        Some(state.jwt.sign_id_token_with_subject_and_claims(
            &issuer,
            TokenSubject {
                user: &user,
                client_id: &client.client_id,
                audience: None,
                scope: &scope,
                nonce: None,
                auth_time: None,
            },
            &subject_identifier,
            state.settings.oidc.id_token_ttl_seconds,
            id_claims,
        )?)
    } else {
        None
    };
    let response_authorization_details =
        authorization_details::authorization_details_json(authorization_details.as_deref())?;
    let new_refresh_token = util::random_token(48);
    let rotated = state
        .db
        .rotate_refresh_token(
            &hash,
            &client.client_id,
            RefreshTokenInput {
                token_hash: util::token_hash(&new_refresh_token),
                user_id: user.id,
                scope: scope.clone(),
                resource: resource.clone(),
                authorization_details: authorization_details.clone(),
                dpop_jkt: dpop.as_ref().map(|binding| binding.jkt.clone()),
                auth_context_id: record.auth_context_id.clone(),
                expires_at: util::now_ts() + state.settings.oidc.refresh_token_ttl_seconds,
            },
        )
        .await?;
    if !rotated {
        return Err(invalid_refresh_token_grant());
    }
    Ok(Json(TokenResponse {
        access_token,
        issued_token_type: None,
        token_type: dpop::token_type(dpop.as_ref()),
        expires_in: state.settings.oidc.access_token_ttl_seconds,
        id_token,
        refresh_token: Some(new_refresh_token),
        scope,
        authorization_details: response_authorization_details,
    }))
}

fn invalid_refresh_token_grant() -> AppError {
    AppError::oauth(
        "invalid_grant",
        "refresh token is invalid",
        StatusCode::BAD_REQUEST,
    )
}

struct IssueUserTokensInput {
    user_id: String,
    scope: String,
    resource: Option<String>,
    authorization_details: Option<String>,
    nonce: Option<String>,
    auth_time: Option<i64>,
    assurance: Option<assurance::AuthenticationAssurance>,
    sid: Option<String>,
    allow_refresh_token: bool,
    login_code_level: Option<LoginCodeLevel>,
    application_id: Option<String>,
    authorization_profile_id: Option<String>,
    auth_context_id: Option<String>,
    dpop: Option<DpopBinding>,
}

async fn issue_tokens_for_user(
    state: &AppState,
    client: &ClientRecord,
    issuer: &str,
    input: IssueUserTokensInput,
) -> AppResult<Json<TokenResponse>> {
    let IssueUserTokensInput {
        user_id,
        scope,
        resource,
        authorization_details,
        nonce,
        auth_time,
        assurance,
        sid,
        allow_refresh_token,
        login_code_level,
        application_id,
        authorization_profile_id,
        auth_context_id,
        dpop,
    } = input;
    let user = load_oidc_user(state, &user_id).await?;
    // An authorization code can outlive the browser session by a few minutes.
    // Re-check immutable trial provenance here so disabling/expiring an
    // enrollment code also blocks a previously issued OAuth code at token
    // exchange time.
    ensure_trial_enrollment_client_allowed_for_user(state, &user.id, &client.client_id).await?;
    ensure_application_client_allowed_for_user(state, &user, client).await?;
    let binding = state.db.find_application_client_binding(&client.id).await?;
    if let Some(binding) = binding.as_ref() {
        if application_id
            .as_deref()
            .is_some_and(|value| value != binding.application_id)
            || authorization_profile_id
                .as_deref()
                .is_some_and(|value| value != binding.authorization_profile_id)
        {
            return Err(invalid_refresh_token_grant());
        }
    }
    tracing::info!(
        client_id = %client.client_id,
        user_id = %user.id,
        email = %user.email,
        scope,
        issuer,
        "issuing OIDC tokens"
    );
    let mut access_claims =
        mapped_claims_for_user(state, client, &user, &scope, ClaimOutputTarget::AccessToken)
            .await?;
    if let Some(application_id) = application_id.as_deref() {
        access_claims.insert(
            "application_id".to_string(),
            serde_json::Value::String(application_id.to_string()),
        );
    } else if let Some(binding) = binding.as_ref() {
        access_claims.insert(
            "application_id".to_string(),
            serde_json::Value::String(binding.application_id.clone()),
        );
    }
    if let Some(profile_id) = authorization_profile_id.as_deref() {
        access_claims.insert(
            "authorization_profile_id".to_string(),
            serde_json::Value::String(profile_id.to_string()),
        );
    } else if let Some(binding) = binding.as_ref() {
        access_claims.insert(
            "authorization_profile_id".to_string(),
            serde_json::Value::String(binding.authorization_profile_id.clone()),
        );
    }
    dpop::add_cnf_claim(&mut access_claims, dpop.as_ref());
    authorization_details::insert_claim(&mut access_claims, authorization_details.as_deref())?;
    if let Some(level) = login_code_level {
        access_claims.insert(
            "gpt_sso_login_code_level".to_string(),
            serde_json::Value::String(level.as_str().to_string()),
        );
    }
    let token_audience = resource
        .as_deref()
        .or_else(|| (!client.audience.trim().is_empty()).then_some(client.audience.as_str()));
    let access_token = state.jwt.sign_access_token_with_issuer_and_claims(
        issuer,
        TokenSubject {
            user: &user,
            client_id: &client.client_id,
            audience: token_audience,
            scope: &scope,
            nonce: None,
            auth_time,
        },
        state.settings.oidc.access_token_ttl_seconds,
        access_claims,
    )?;
    let mut id_claims =
        mapped_claims_for_user(state, client, &user, &scope, ClaimOutputTarget::IdToken).await?;
    if let Some(binding) = binding.as_ref() {
        id_claims.insert(
            "application_id".to_string(),
            serde_json::Value::String(binding.application_id.clone()),
        );
        id_claims.insert(
            "authorization_profile_id".to_string(),
            serde_json::Value::String(binding.authorization_profile_id.clone()),
        );
    }
    insert_sid_claim(&mut id_claims, sid.as_deref());
    if let Some(level) = login_code_level {
        id_claims.insert(
            "gpt_sso_login_code_level".to_string(),
            serde_json::Value::String(level.as_str().to_string()),
        );
    }
    if let Some(assurance) = assurance.as_ref() {
        assurance::insert_id_token_assurance_claims(
            &mut id_claims,
            assurance,
            &assurance::RequestedAssurance::default(),
        )?;
    }
    let subject_identifier = subject::subject_for_client(issuer, &user, client)?;
    let id_token = state.jwt.sign_id_token_with_subject_and_claims(
        issuer,
        TokenSubject {
            user: &user,
            client_id: &client.client_id,
            audience: None,
            scope: &scope,
            nonce: nonce.as_deref(),
            auth_time,
        },
        &subject_identifier,
        state.settings.oidc.id_token_ttl_seconds,
        id_claims,
    )?;
    let refresh_token = if allow_refresh_token
        && user.archived_at.is_none()
        && scope
            .split_whitespace()
            .any(|scope| scope == "offline_access")
        && client
            .grant_types()?
            .iter()
            .any(|value| value == "refresh_token")
    {
        let refresh_token = util::random_token(48);
        state
            .db
            .insert_refresh_token(
                client.client_id.clone(),
                RefreshTokenInput {
                    token_hash: util::token_hash(&refresh_token),
                    user_id: user.id.clone(),
                    scope: scope.clone(),
                    resource: resource.clone(),
                    authorization_details: authorization_details.clone(),
                    dpop_jkt: dpop.as_ref().map(|binding| binding.jkt.clone()),
                    auth_context_id: auth_context_id.clone(),
                    expires_at: util::now_ts() + state.settings.oidc.refresh_token_ttl_seconds,
                },
            )
            .await?;
        Some(refresh_token)
    } else {
        None
    };
    Ok(Json(TokenResponse {
        access_token,
        issued_token_type: None,
        token_type: dpop::token_type(dpop.as_ref()),
        expires_in: state.settings.oidc.access_token_ttl_seconds,
        id_token: Some(id_token),
        refresh_token,
        scope,
        authorization_details: authorization_details::authorization_details_json(
            authorization_details.as_deref(),
        )?,
    }))
}

async fn mapped_claims_for_user(
    state: &AppState,
    client: &ClientRecord,
    user: &UserRecord,
    scope: &str,
    target: ClaimOutputTarget,
) -> AppResult<serde_json::Map<String, serde_json::Value>> {
    let records = state.db.list_client_claim_mappers(&client.id).await?;
    let mut claims = serde_json::Map::new();
    claims.insert(
        "email_verified".to_string(),
        serde_json::Value::Bool(DefaultEmailVerifiedClaimPolicy.email_verified(user, client)),
    );
    claims.extend(claim_mapper::mapped_claims(
        &records,
        &ClaimContext {
            user,
            client,
            scope,
        },
        target,
    )?);

    // Client claim mappers describe the protocol connection; application
    // entitlements describe the website that owns that connection.  Keep the
    // latter as a separate, live policy layer so role/group changes are
    // visible on the next token or UserInfo request and cannot be hidden by a
    // stale mapper configuration.
    if let Some(application) = state.db.find_application_for_client(&client.id).await? {
        let entitlements =
            authorization::resolve_entitlements_for_client(state, &application, client, user)
                .await?;
        claims.extend(entitlements.claims);
        claims.insert(
            "policy_version".to_string(),
            serde_json::Value::String(entitlements.policy_version),
        );
    }
    Ok(claims)
}

fn insert_sid_claim(claims: &mut serde_json::Map<String, serde_json::Value>, sid: Option<&str>) {
    if let Some(sid) = sid.filter(|value| !value.trim().is_empty()) {
        claims.insert(
            "sid".to_string(),
            serde_json::Value::String(sid.to_string()),
        );
    }
}

async fn userinfo(
    State(state): State<AppState>,
    method: Method,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let (auth_scheme, token) = authorization_token(&headers)?;
    let issuers = state.accepted_issuers(&headers).await?;
    let issuer_refs = issuers.iter().map(String::as_str).collect::<Vec<_>>();
    // The access token identifies the client connection first. UserInfo is a
    // concrete OIDC resource endpoint, so the second verification must bind
    // its audience to that client; a token minted for an RFC 8707 API must
    // not be replayed against UserInfo merely because it carries the same
    // user subject.
    let bootstrap_claims = state
        .jwt
        .verify_access_token_for_generic_bearer(token, &issuer_refs)?;
    let client = state
        .db
        .find_client_by_client_id(&bootstrap_claims.client_id)
        .await?
        .ok_or(AppError::Unauthorized)?;
    if client.is_active != 1 {
        return Err(AppError::Unauthorized);
    }
    let audiences = [client.client_id.clone()];
    let claims = state.jwt.verify_access_token_with_issuers_and_audiences(
        token,
        &issuer_refs,
        &audiences,
    )?;
    if let Some(cnf) = claims.cnf.as_ref() {
        if auth_scheme != dpop::TOKEN_TYPE {
            return Err(AppError::Unauthorized);
        }
        dpop::validate_access_token_proof(
            &state,
            &headers,
            &method,
            &state.settings.oidc.userinfo_endpoint,
            token,
            &cnf.jkt,
        )
        .await?;
    } else if auth_scheme != "Bearer" {
        return Err(AppError::Unauthorized);
    }
    let user = load_oidc_user(&state, &claims.sub).await?;
    ensure_trial_enrollment_client_allowed_for_user(&state, &user.id, &client.client_id).await?;
    ensure_application_client_allowed_for_user(&state, &user, &client).await?;
    tracing::info!(
        client_id = %client.client_id,
        user_id = %user.id,
        email = %user.email,
        "served OIDC userinfo"
    );
    let userinfo_subject = subject::subject_for_client(&claims.iss, &user, &client)?;
    let mut response = serde_json::Map::new();
    response.insert(
        "sub".to_string(),
        serde_json::Value::String(userinfo_subject),
    );
    response.insert(
        "email".to_string(),
        serde_json::Value::String(user.email.clone()),
    );
    response.insert(
        "email_verified".to_string(),
        serde_json::Value::Bool(DefaultEmailVerifiedClaimPolicy.email_verified(&user, &client)),
    );
    response.insert(
        "name".to_string(),
        serde_json::Value::String(
            user.display_name
                .clone()
                .unwrap_or_else(|| user.username.clone()),
        ),
    );
    response.insert(
        "preferred_username".to_string(),
        serde_json::Value::String(user.username.clone()),
    );
    response.extend(
        mapped_claims_for_user(
            &state,
            &client,
            &user,
            &claims.scope,
            ClaimOutputTarget::UserInfo,
        )
        .await?,
    );
    Ok(Json(serde_json::Value::Object(response)))
}

#[derive(Debug, Deserialize)]
struct IntrospectionRequest {
    token: String,
    token_type_hint: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    client_assertion_type: Option<String>,
    client_assertion: Option<String>,
}

impl ClientAuthFields for IntrospectionRequest {
    fn client_id(&self) -> Option<&str> {
        self.client_id.as_deref()
    }

    fn client_secret(&self) -> Option<&str> {
        self.client_secret.as_deref()
    }

    fn client_assertion_type(&self) -> Option<&str> {
        self.client_assertion_type.as_deref()
    }

    fn client_assertion(&self) -> Option<&str> {
        self.client_assertion.as_deref()
    }
}

async fn introspect(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(payload): Form<IntrospectionRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let client = authenticate_client_at(&state, &headers, &payload, "/oauth2/introspect").await?;
    if client.token_endpoint_auth_method == "none" {
        return Err(AppError::Unauthorized);
    }
    let _hint = payload.token_type_hint.as_deref();
    let issuers = state.accepted_issuers(&headers).await?;
    let issuer_refs = issuers.iter().map(String::as_str).collect::<Vec<_>>();
    let expected_audience = introspection_audience(&client);
    if let Ok(claims) = state
        .jwt
        .verify_access_token_for_introspection(&payload.token, &issuer_refs)
    {
        let source_client = state.db.find_client_by_client_id(&claims.client_id).await?;
        let boundary_matches = if let Some(source_client) = source_client.as_ref() {
            match state
                .db
                .find_application_client_binding(&source_client.id)
                .await?
            {
                Some(binding) => {
                    claims.application_id.as_deref() == Some(binding.application_id.as_str())
                        && claims.authorization_profile_id.as_deref()
                            == Some(binding.authorization_profile_id.as_str())
                }
                None => {
                    claims.application_id.is_none() && claims.authorization_profile_id.is_none()
                }
            }
        } else {
            false
        };
        let active = claims.exp > util::now_ts()
            && claims.aud == expected_audience
            && boundary_matches
            && source_client
                .as_ref()
                .is_some_and(|source_client| source_client.is_active == 1)
            && introspected_access_token_is_live(&state, source_client.as_ref(), &claims).await?;
        if active {
            let cnf = claims
                .cnf
                .clone()
                .map(|claim| serde_json::json!({ "jkt": claim.jkt }));
            let subject_type = if claims.sub.starts_with("service-account:") {
                "service".to_string()
            } else {
                source_client
                    .as_ref()
                    .map(|source_client| source_client.subject_type.clone())
                    .unwrap_or_else(|| subject::SUBJECT_TYPE_PUBLIC.to_string())
            };
            return Ok(Json(serde_json::json!({
                "active": true,
                "scope": claims.scope,
                "client_id": claims.client_id,
                "sub": claims.sub,
                "subject_type": subject_type,
                "token_type": "Bearer",
                "exp": claims.exp,
                "iat": claims.iat,
                "iss": claims.iss,
                "aud": claims.aud,
                "jti": claims.jti,
                "act": claims.act,
                "grant_id": claims.grant_id,
                "grant_reference": claims.grant_id,
                "username": claims.preferred_username,
                "cnf": cnf,
                "authorization_details": claims.authorization_details,
            })));
        }
    }
    let hash = util::token_hash(&payload.token);
    if let Some(record) = state.db.find_refresh_token(&hash).await?
        && record.revoked_at.is_none()
        && record.expires_at > util::now_ts()
        && record
            .resource
            .as_deref()
            .unwrap_or(record.client_id.as_str())
            == expected_audience
    {
        let source_client = state.db.find_client_by_client_id(&record.client_id).await?;
        let user = source_client
            .as_ref()
            .filter(|source_client| source_client.is_active == 1)
            .and_then(|_| Some(record.user_id.clone()));
        let user_active = if let Some(user_id) = user {
            load_oidc_user(&state, &user_id).await.is_ok()
        } else {
            false
        };
        let consent_active = if user_active {
            introspected_refresh_grant_is_live(&state, &record.user_id, &record.client_id).await?
        } else {
            false
        };
        if !consent_active {
            return Ok(Json(serde_json::json!({ "active": false })));
        }
        let subject_type = if record.user_id.starts_with("service-account:") {
            "service".to_string()
        } else {
            source_client
                .as_ref()
                .map(|source_client| source_client.subject_type.clone())
                .unwrap_or_else(|| subject::SUBJECT_TYPE_PUBLIC.to_string())
        };
        let audience = record
            .resource
            .clone()
            .unwrap_or_else(|| record.client_id.clone());
        let authorization_details = authorization_details::authorization_details_json(
            record.authorization_details.as_deref(),
        )?;
        return Ok(Json(serde_json::json!({
            "active": true,
            "scope": record.scope,
            "client_id": record.client_id,
            "sub": record.user_id,
            "subject_type": subject_type,
            "token_type": "refresh_token",
            "exp": record.expires_at,
            "iat": record.created_at,
            "aud": audience,
            "jti": serde_json::Value::Null,
            "act": serde_json::Value::Null,
            "grant_id": serde_json::Value::Null,
            "grant_reference": serde_json::Value::Null,
            "authorization_details": authorization_details,
        })));
    }
    Ok(Json(serde_json::json!({ "active": false })))
}

fn introspection_audience(client: &ClientRecord) -> String {
    if client.audience.trim().is_empty() {
        client.client_id.clone()
    } else {
        client.audience.trim().to_string()
    }
}

async fn introspected_access_token_is_live(
    state: &AppState,
    source_client: Option<&ClientRecord>,
    claims: &TokenClaims,
) -> AppResult<bool> {
    if claims.sub == claims.client_id || claims.sub.starts_with("service-account:") {
        return Ok(true);
    }
    let Some(source_client) = source_client else {
        return Ok(false);
    };
    let user = match load_oidc_user(state, &claims.sub).await {
        Ok(user) => user,
        Err(_) => return Ok(false),
    };
    if ensure_application_client_allowed_for_user(state, &user, source_client)
        .await
        .is_err()
    {
        return Ok(false);
    }
    introspected_user_grant_is_live(
        state,
        &user.id,
        &claims.client_id,
        &claims.scope,
        claims.grant_id.as_deref(),
    )
    .await
}

async fn introspected_user_grant_is_live(
    state: &AppState,
    user_id: &str,
    client_id: &str,
    scope: &str,
    grant_id: Option<&str>,
) -> AppResult<bool> {
    if let Some(grant_id) = grant_id
        && let Some(reference) = grant_id.strip_prefix("consent:")
        && let Some((grant_client_id, version)) = reference.rsplit_once(':')
    {
        let Ok(version) = version.parse::<i64>() else {
            return Ok(false);
        };
        let Some(consent) = state.db.find_client_grant(user_id, grant_client_id).await? else {
            return Ok(false);
        };
        return Ok(consent.revoked_at.is_none()
            && consent.updated_at == version
            && grants_all_scopes(&consent.granted_scopes, scope));
    }
    let Some(consent) = state.db.find_client_grant(user_id, client_id).await? else {
        // `skip_consent` creates an implicit authorization grant for ordinary
        // browser flows. Delegated exchanges never take this branch because
        // they always carry a consent:* grant reference.
        return Ok(true);
    };
    Ok(consent.revoked_at.is_none() && grants_all_scopes(&consent.granted_scopes, scope))
}

async fn introspected_refresh_grant_is_live(
    state: &AppState,
    user_id: &str,
    client_id: &str,
) -> AppResult<bool> {
    let Some(consent) = state.db.find_client_grant(user_id, client_id).await? else {
        return Ok(true);
    };
    Ok(consent.revoked_at.is_none())
}

fn grants_all_scopes(granted_scopes: &str, requested_scope: &str) -> bool {
    let granted = granted_scopes
        .split_whitespace()
        .collect::<std::collections::BTreeSet<_>>();
    requested_scope
        .split_whitespace()
        .all(|scope| granted.contains(scope))
}

#[derive(Debug, Deserialize)]
struct RevocationRequest {
    token: String,
    token_type_hint: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    client_assertion_type: Option<String>,
    client_assertion: Option<String>,
}

impl ClientAuthFields for RevocationRequest {
    fn client_id(&self) -> Option<&str> {
        self.client_id.as_deref()
    }

    fn client_secret(&self) -> Option<&str> {
        self.client_secret.as_deref()
    }

    fn client_assertion_type(&self) -> Option<&str> {
        self.client_assertion_type.as_deref()
    }

    fn client_assertion(&self) -> Option<&str> {
        self.client_assertion.as_deref()
    }
}

async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(payload): Form<RevocationRequest>,
) -> AppResult<StatusCode> {
    let client = authenticate_client_at(&state, &headers, &payload, "/oauth2/revoke").await?;
    let hash = util::token_hash(&payload.token);
    if let Some(record) = state.db.find_refresh_token(&hash).await?
        && record.client_id == client.client_id
    {
        state.db.revoke_refresh_token(&hash).await?;
        state
            .db
            .record_audit_event(audit::oauth_event(
                client.client_id,
                "token.revoke",
                AuditOutcome::Success,
                serde_json::json!({ "token_type": payload.token_type_hint.unwrap_or_else(|| "refresh_token".to_string()) }),
            ))
            .await?;
    }
    Ok(StatusCode::OK)
}

#[derive(Debug, Deserialize)]
struct LogoutRequest {
    _csrf: Option<String>,
    id_token_hint: Option<String>,
    logout_hint: Option<String>,
    client_id: Option<String>,
    post_logout_redirect_uri: Option<String>,
    state: Option<String>,
    ui_locales: Option<String>,
}

async fn logout_get(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Query(query): Query<LogoutRequest>,
) -> AppResult<Response> {
    let current = auth::current_user_from_cookie(&state, &jar).await?;
    let redirect =
        validated_post_logout_redirect(&state, &headers, current.as_ref(), &query).await?;
    let Some(current_user) = current.as_ref() else {
        return complete_logout(state, jar, headers, current, redirect).await;
    };
    if logout_hint_authorizes_current_session(&state, &headers, current_user, &query).await? {
        return complete_logout(state, jar, headers, current, redirect).await;
    }

    let csrf_token = crate::csrf::token_for_current_session(&state, &jar).await?;
    let client = logout_request_client(&state, &headers, current.as_ref(), &query).await?;
    Ok(logout_confirmation_page(&query, &csrf_token, client.as_ref()).into_response())
}

async fn logout_post(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Form(payload): Form<LogoutRequest>,
) -> AppResult<Response> {
    let current = auth::current_user_from_cookie(&state, &jar).await?;
    if let Some(current) = current.as_ref()
        && !logout_hint_authorizes_current_session(&state, &headers, current, &payload).await?
    {
        crate::csrf::validate_form_token(&state, &jar, payload._csrf.as_deref()).await?;
    }
    let redirect =
        validated_post_logout_redirect(&state, &headers, current.as_ref(), &payload).await?;
    complete_logout(state, jar, headers, current, redirect).await
}

async fn complete_logout(
    state: AppState,
    jar: CookieJar,
    headers: HeaderMap,
    current: Option<auth::CurrentUser>,
    redirect: Option<Url>,
) -> AppResult<Response> {
    let mut frontchannel_frames = Vec::new();
    if let Some(current) = current.as_ref() {
        let public_session_id = util::session_public_id(&current.session_id);
        frontchannel_frames = match crate::frontchannel_logout::frames_for_user(
            &state,
            &headers,
            &current.user,
            &public_session_id,
        )
        .await
        {
            Ok(frames) => frames,
            Err(err) => {
                tracing::warn!(error = %err, "front-channel logout notification preparation failed");
                Vec::new()
            }
        };
        if let Err(err) = crate::backchannel_logout::notify_user_logout(
            &state,
            &headers,
            &current.user,
            Some(&public_session_id),
        )
        .await
        {
            tracing::warn!(error = %err, "back-channel logout notification failed");
        }
    }
    let mut next_jar = jar.clone();
    if let Some(current) = current.as_ref() {
        state.db.delete_session(&current.session_id).await?;
    }
    if jar.get(&state.settings.security.cookie_name).is_some() {
        next_jar = next_jar.add(auth::expired_session_cookie(&state));
    }
    let redirect_to = redirect
        .as_ref()
        .map(|uri| uri.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let response = if !frontchannel_frames.is_empty() {
        (
            next_jar,
            crate::frontchannel_logout::logout_page(&frontchannel_frames, &redirect_to),
        )
            .into_response()
    } else if let Some(uri) = redirect {
        (next_jar, Redirect::to(uri.as_str())).into_response()
    } else {
        (next_jar, Redirect::to("/")).into_response()
    };
    Ok(response)
}

async fn logout_hint_authorizes_current_session(
    state: &AppState,
    headers: &HeaderMap,
    current: &auth::CurrentUser,
    request: &LogoutRequest,
) -> AppResult<bool> {
    let Some((_client, claims)) =
        validated_logout_hint(state, headers, Some(current), request).await?
    else {
        return Ok(false);
    };
    if let Some(sid) = claims.sid.as_deref() {
        return Ok(sid == util::session_public_id(&current.session_id));
    }
    Ok(true)
}

fn logout_confirmation_page(
    request: &LogoutRequest,
    csrf_token: &str,
    client: Option<&ClientRecord>,
) -> Html<String> {
    let application = client
        .map(|client| format!("<strong>{}</strong>", html_escape(&client.client_name)))
        .unwrap_or_else(|| "the requesting application".to_string());
    let hidden_fields = [
        ("id_token_hint", request.id_token_hint.as_deref()),
        ("logout_hint", request.logout_hint.as_deref()),
        ("client_id", request.client_id.as_deref()),
        (
            "post_logout_redirect_uri",
            request.post_logout_redirect_uri.as_deref(),
        ),
        ("state", request.state.as_deref()),
        ("ui_locales", request.ui_locales.as_deref()),
    ]
    .into_iter()
    .filter_map(|(name, value)| {
        value.map(|value| {
            format!(
                r#"<input type="hidden" name="{}" value="{}" />"#,
                name,
                html_escape(value)
            )
        })
    })
    .collect::<String>();
    Html(format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Confirm sign out</title>
  <style>
    body {{ font-family: Inter, ui-sans-serif, system-ui, sans-serif; margin: 0; background: #f6f7f9; color: #111827; }}
    main {{ min-height: 100vh; display: grid; place-items: center; padding: 24px; }}
    section {{ width: min(420px, 100%); box-sizing: border-box; background: white; border: 1px solid #d8dee8; border-radius: 12px; padding: 28px; box-shadow: 0 18px 45px rgba(15, 23, 42, .10); }}
    h1 {{ font-size: 24px; margin: 0 0 10px; }}
    p {{ color: #667085; line-height: 1.55; margin: 0 0 22px; }}
    .actions {{ display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }}
    button, a {{ min-height: 42px; box-sizing: border-box; border-radius: 8px; font-weight: 700; display: inline-flex; align-items: center; justify-content: center; text-decoration: none; }}
    button {{ border: 0; color: white; background: #b42318; cursor: pointer; }}
    a {{ color: #344054; background: #eef2f7; }}
  </style>
</head>
<body>
  <main>
    <section>
      <h1>Sign out?</h1>
      <p>{application} asked to end your SSO session. Confirm to sign out of this browser.</p>
      <form method="post" action="/oauth2/logout">
        <input type="hidden" name="_csrf" value="{}" />
        {hidden_fields}
        <div class="actions">
          <a href="/">Stay signed in</a>
          <button type="submit">Sign out</button>
        </div>
      </form>
    </section>
  </main>
</body>
</html>"#,
        html_escape(csrf_token)
    ))
}

async fn validated_post_logout_redirect(
    state: &AppState,
    headers: &HeaderMap,
    current: Option<&auth::CurrentUser>,
    request: &LogoutRequest,
) -> AppResult<Option<Url>> {
    let Some(uri) = request.post_logout_redirect_uri.as_deref() else {
        return Ok(None);
    };
    let _ = request.logout_hint.as_deref();
    let _ = request.ui_locales.as_deref();
    let Some(client) = logout_request_client(state, headers, current, request).await? else {
        return Ok(None);
    };
    if !client
        .post_logout_redirect_uris()?
        .iter()
        .any(|registered| registered == uri)
    {
        return Ok(None);
    }
    Ok(post_logout_redirect_url(uri, request.state.as_deref()))
}

async fn logout_request_client(
    state: &AppState,
    headers: &HeaderMap,
    current: Option<&auth::CurrentUser>,
    request: &LogoutRequest,
) -> AppResult<Option<ClientRecord>> {
    if request.id_token_hint.is_some() {
        return Ok(validated_logout_hint(state, headers, current, request)
            .await?
            .map(|(client, _claims)| client));
    }

    let Some(client_id) = request.client_id.as_deref() else {
        return Ok(None);
    };
    state.db.find_client_by_client_id(client_id).await
}

async fn validated_logout_hint(
    state: &AppState,
    headers: &HeaderMap,
    current: Option<&auth::CurrentUser>,
    request: &LogoutRequest,
) -> AppResult<Option<(ClientRecord, crate::jwt::TokenClaims)>> {
    let Some(id_token_hint) = request.id_token_hint.as_deref() else {
        return Ok(None);
    };
    let issuers = state.accepted_issuers(headers).await?;
    let issuer_refs = issuers.iter().map(String::as_str).collect::<Vec<_>>();
    let Ok(bootstrap_claims) = state
        .jwt
        .verify_id_token_hint_for_logout_bootstrap(id_token_hint, &issuer_refs)
    else {
        return Ok(None);
    };
    let Some(client) = state
        .db
        .find_client_by_client_id(&bootstrap_claims.client_id)
        .await?
    else {
        return Ok(None);
    };
    if client.is_active != 1 {
        return Ok(None);
    }
    // ID tokens issued by Signet are always audience-bound to the OIDC
    // client. Do not let a syntactically valid signed token for another
    // audience authorize a logout request for this client.
    let audiences = [client.client_id.clone()];
    let Ok(claims) = state.jwt.verify_id_token_hint_with_issuers_and_audiences(
        id_token_hint,
        &issuer_refs,
        &audiences,
    ) else {
        return Ok(None);
    };
    if let Some(current) = current {
        let expected_subject = subject::subject_for_client(&claims.iss, &current.user, &client)?;
        if expected_subject != claims.sub {
            return Ok(None);
        }
    }
    if let Some(client_id) = request.client_id.as_deref()
        && client_id != claims.client_id
    {
        return Ok(None);
    }
    Ok(Some((client, claims)))
}

fn post_logout_redirect_url(uri: &str, state: Option<&str>) -> Option<Url> {
    let mut redirect = Url::parse(uri).ok()?;
    if let Some(state_value) = state {
        redirect.query_pairs_mut().append_pair("state", state_value);
    }
    Some(redirect)
}

#[derive(Debug, Deserialize)]
struct LoginPageQuery {
    return_to: Option<String>,
    login_hint: Option<String>,
    force_login: Option<String>,
}

async fn login_page(Query(query): Query<LoginPageQuery>) -> Redirect {
    let return_to_value = redirects::local_return_to(query.return_to.as_deref());
    Redirect::to(&redirects::frontend_login_url(
        &return_to_value,
        query.login_hint.as_deref(),
        query.force_login.as_deref() == Some("1"),
    ))
}

fn password_login_page(
    return_to_value: &str,
    email_value: Option<&str>,
    captcha: Option<&crate::captcha::LoginCaptchaPrompt>,
    message: Option<&str>,
) -> Html<String> {
    let return_to = html_escape(return_to_value);
    let email = html_escape(email_value.unwrap_or_default());
    let message_html = message
        .map(|value| format!(r#"<p class="error">{}</p>"#, html_escape(value)))
        .unwrap_or_default();
    let captcha_html = captcha
        .map(|challenge| {
            format!(
                r#"<input type="hidden" name="captcha_challenge_id" value="{}" />
      <label>Security check</label>
      <p class="muted">{}</p>
      <input name="captcha_answer" inputmode="numeric" autocomplete="off" required />"#,
                html_escape(&challenge.challenge_id),
                html_escape(&challenge.prompt)
            )
        })
        .unwrap_or_default();
    Html(format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>SSO Login</title>
  <style>
    body {{ font-family: Inter, ui-sans-serif, system-ui, sans-serif; margin: 0; background: #f6f7f9; color: #111827; }}
    main {{ min-height: 100vh; display: grid; place-items: center; padding: 24px; }}
    form {{ width: min(380px, 100%); background: white; border: 1px solid #d8dee8; border-radius: 8px; padding: 24px; box-shadow: 0 10px 30px rgba(15, 23, 42, .08); }}
    h1 {{ font-size: 22px; margin: 0 0 20px; }}
    p {{ color: #667085; margin: 0 0 12px; }}
    .error {{ color: #b42318; }}
    .muted {{ color: #667085; font-size: 13px; }}
    label {{ display: block; font-weight: 650; font-size: 13px; margin: 14px 0 6px; }}
    input {{ width: 100%; box-sizing: border-box; padding: 11px 12px; border: 1px solid #c9d1dc; border-radius: 6px; font-size: 15px; }}
    button {{ width: 100%; margin-top: 20px; padding: 11px 14px; border: 0; border-radius: 6px; color: white; background: #0f766e; font-weight: 700; cursor: pointer; }}
  </style>
</head>
<body>
  <main>
    <form method="post" action="/login">
      <h1>Sign in</h1>
      {message_html}
      <input type="hidden" name="return_to" value="{return_to}" />
      <label>Email</label>
      <input name="email" type="email" autocomplete="username" value="{email}" required />
      <label>Password</label>
      <input name="password" type="password" autocomplete="current-password" required />
      {captcha_html}
      <button type="submit">Sign in</button>
    </form>
  </main>
</body>
</html>"#
    ))
}

pub(crate) fn mfa_page(challenge_id: &str, return_to: &str) -> Html<String> {
    let challenge_id = html_escape(challenge_id);
    let return_to = html_escape(return_to);
    Html(format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>SSO MFA</title>
  <style>
    body {{ font-family: Inter, ui-sans-serif, system-ui, sans-serif; margin: 0; background: #f6f7f9; color: #111827; }}
    main {{ min-height: 100vh; display: grid; place-items: center; padding: 24px; }}
    form {{ width: min(380px, 100%); background: white; border: 1px solid #d8dee8; border-radius: 8px; padding: 24px; box-shadow: 0 10px 30px rgba(15, 23, 42, .08); }}
    h1 {{ font-size: 22px; margin: 0 0 8px; }}
    p {{ color: #667085; margin: 0 0 20px; }}
    label {{ display: block; font-weight: 650; font-size: 13px; margin: 14px 0 6px; }}
    input {{ width: 100%; box-sizing: border-box; padding: 11px 12px; border: 1px solid #c9d1dc; border-radius: 6px; font-size: 15px; }}
    button {{ width: 100%; margin-top: 20px; padding: 11px 14px; border: 0; border-radius: 6px; color: white; background: #0f766e; font-weight: 700; cursor: pointer; }}
  </style>
</head>
<body>
  <main>
    <form method="post" action="/login">
      <h1>Two-factor authentication</h1>
      <p>Enter a TOTP code or one unused recovery code.</p>
      <input type="hidden" name="mfa_challenge_id" value="{challenge_id}" />
      <input type="hidden" name="return_to" value="{return_to}" />
      <label>Code</label>
      <input name="mfa_code" inputmode="numeric" autocomplete="one-time-code" required />
      <button type="submit">Continue</button>
    </form>
  </main>
</body>
</html>"#
    ))
}

#[derive(Debug, Deserialize)]
struct LoginForm {
    email: Option<String>,
    password: Option<String>,
    return_to: Option<String>,
    mfa_challenge_id: Option<String>,
    mfa_code: Option<String>,
    captcha_challenge_id: Option<String>,
    captcha_answer: Option<String>,
}

async fn login_form(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    Form(payload): Form<LoginForm>,
) -> AppResult<Response> {
    let request_ip = state.request_ip(&headers, Some(remote_addr)).await?;
    if let Some(challenge_id) = payload.mfa_challenge_id.as_deref() {
        let challenge = state
            .db
            .find_mfa_challenge(challenge_id)
            .await?
            .ok_or(AppError::Unauthorized)?;
        if challenge.purpose != "oidc_login" {
            return Err(AppError::Unauthorized);
        }
        let code = payload.mfa_code.as_deref().ok_or(AppError::Unauthorized)?;
        let user_id = challenge.user_id.clone();
        let return_to = redirects::local_return_to(
            challenge
                .return_to
                .as_deref()
                .or(payload.return_to.as_deref()),
        );
        let subject = state
            .db
            .find_user_by_id(&user_id)
            .await?
            .map(|user| security_policy::normalize_login_subject(&user.email))
            .ok_or(AppError::Unauthorized)?;
        auth::assert_login_entry_allowed(&state, &subject, request_ip.as_deref()).await?;
        let completion = match mfa::complete_challenge(&state, challenge, code).await {
            Ok(value) => value,
            Err(err) => {
                auth::record_login_failure(
                    &state,
                    request_ip.clone(),
                    &headers,
                    &subject,
                    "bad_mfa",
                )
                .await?;
                return Err(err);
            }
        };
        let user = state
            .db
            .find_user_by_id(&user_id)
            .await?
            .ok_or(AppError::Unauthorized)?;
        if user.is_active != 1 || user.archived_at.is_some() {
            return Err(AppError::Unauthorized);
        }
        let jar = auth::issue_session(
            &state,
            jar,
            &headers,
            request_ip.clone(),
            &user,
            &format!("oidc_{}", completion.method),
        )
        .await?;
        auth::clear_login_failures(&state, &subject).await?;
        return Ok((jar, Redirect::to(&return_to)).into_response());
    }

    let email = payload.email.as_deref().ok_or(AppError::Unauthorized)?;
    let password = payload.password.as_deref().ok_or(AppError::Unauthorized)?;
    let subject = security_policy::normalize_login_subject(email);
    auth::assert_login_entry_allowed(&state, &subject, request_ip.as_deref()).await?;
    let return_to = redirects::local_return_to(payload.return_to.as_deref());
    let login_context =
        authorization_login_context_from_return_to(&state, &headers, Some(&return_to)).await?;
    let local_password_allowed = match login_context.application.as_ref() {
        Some(application) => {
            applications::application_signet_password_enabled(&state, &application.id).await?
        }
        None => true,
    };
    if let Some(captcha) = auth::login_captcha_prompt_if_required(
        &state,
        &subject,
        request_ip.as_deref(),
        payload.captcha_challenge_id.as_deref(),
        payload.captcha_answer.as_deref(),
    )
    .await?
    {
        let return_to = redirects::local_return_to(payload.return_to.as_deref());
        return Ok(password_login_page(
            &return_to,
            Some(&subject),
            Some(&captcha),
            Some("Complete the security check to continue."),
        )
        .into_response());
    }
    let local_user = state.db.find_user_by_email(&subject).await?;
    let failure_reason = if local_user.is_some() {
        "bad_credentials"
    } else {
        "unknown_user"
    };
    let mut login_method = "oidc_login".to_string();
    let mut external_provider = None;
    let mut user = local_user.filter(|candidate| {
        local_password_allowed
            && candidate.is_active == 1
            && candidate.archived_at.is_none()
            && util::verify_password(&candidate.password_hash, password)
    });
    if user.is_none() {
        let directory_login =
            match directory::authenticate_with_configured_directories_for_application(
                &state,
                &subject,
                password,
                login_context.application.as_ref(),
            )
            .await
            {
                Ok(value) => value,
                Err(AppError::Unauthorized | AppError::Forbidden) => None,
                Err(err) => return Err(err),
            };
        if let Some(login) = directory_login {
            login_method = "oidc_ldap".to_string();
            external_provider = Some(login.provider_key);
            user = Some(login.user);
        }
    }
    let Some(user) = user else {
        auth::record_login_failure(
            &state,
            request_ip.clone(),
            &headers,
            &subject,
            failure_reason,
        )
        .await?;
        return Err(AppError::Unauthorized);
    };
    let user_has_totp = state.db.find_totp_method(&user.id).await?.is_some();
    let policy = state.db.security_policy().await?;
    let policy_requires_mfa =
        policy.requires_mfa_for_ip(request_ip.as_deref())? || login_context.request_requires_mfa;
    match auth_flow::oidc_login_mfa_decision(
        &policy,
        login_context.client.as_ref(),
        user_has_totp,
        policy_requires_mfa,
    )? {
        MfaDecision::Satisfied => {}
        MfaDecision::Challenge => {
            let challenge = state
                .db
                .create_mfa_challenge(
                    &user.id,
                    "oidc_login",
                    Some(return_to.clone()),
                    mfa::MFA_CHALLENGE_TTL_SECONDS,
                )
                .await?;
            return Ok(mfa_page(&challenge.id, &return_to).into_response());
        }
        MfaDecision::SetupRequired => {
            return Err(AppError::BadRequest(
                "MFA is required but the account has no TOTP method".to_string(),
            ));
        }
    }
    let jar = auth::issue_session_with_login_event(
        &state,
        jar,
        &headers,
        request_ip,
        &user,
        &login_method,
        auth::LoginEventContext {
            external_provider,
            ..Default::default()
        },
    )
    .await?;
    auth::clear_login_failures(&state, &subject).await?;
    Ok((jar, Redirect::to(&return_to)).into_response())
}

struct ClientCredentials {
    client_id: String,
    client_secret: Option<String>,
    client_assertion_type: Option<String>,
    client_assertion: Option<String>,
}

pub(crate) struct AuthorizationLoginContext {
    pub(crate) client: Option<ClientRecord>,
    pub(crate) application: Option<ApplicationRecord>,
    pub(crate) request_requires_mfa: bool,
}

pub(crate) async fn authenticate_client_at<T: ClientAuthFields>(
    state: &AppState,
    headers: &HeaderMap,
    payload: &T,
    endpoint_path: &str,
) -> AppResult<ClientRecord> {
    let credentials = client_credentials(headers, payload)?;
    let client = state
        .db
        .find_client_by_client_id(&credentials.client_id)
        .await?
        .ok_or(AppError::Unauthorized)?;
    if client.is_active != 1 {
        return Err(AppError::Unauthorized);
    }
    applications::authorize_application_client(state, &client, "oauth2_oidc")
        .await
        .map_err(|_| AppError::Unauthorized)?;
    if client.require_confidential_client == 1 && client.token_endpoint_auth_method == "none" {
        return Err(AppError::Unauthorized);
    }
    match client.token_endpoint_auth_method.as_str() {
        "none" => Ok(client),
        "client_secret_post" | "client_secret_basic" => {
            let Some(hash) = &client.client_secret_hash else {
                return Err(AppError::Unauthorized);
            };
            let secret = credentials.client_secret.ok_or(AppError::Unauthorized)?;
            if util::verify_password(hash, &secret) {
                Ok(client)
            } else {
                Err(AppError::Unauthorized)
            }
        }
        client_assertion::CLIENT_SECRET_JWT => {
            let audiences = client_auth_audiences(state, headers, endpoint_path).await?;
            client_assertion::authenticate_client_secret_jwt(
                state,
                &client,
                credentials.client_assertion_type.as_deref(),
                credentials.client_assertion.as_deref(),
                &audiences,
            )
            .await?;
            Ok(client)
        }
        client_assertion::PRIVATE_KEY_JWT => {
            let audiences = client_auth_audiences(state, headers, endpoint_path).await?;
            client_assertion::authenticate_private_key_jwt(
                state,
                &client,
                credentials.client_assertion_type.as_deref(),
                credentials.client_assertion.as_deref(),
                &audiences,
            )
            .await?;
            Ok(client)
        }
        _ => Err(AppError::Unauthorized),
    }
}

fn client_credentials<T: ClientAuthFields>(
    headers: &HeaderMap,
    payload: &T,
) -> AppResult<ClientCredentials> {
    if let Some(header) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        && let Some(encoded) = header.strip_prefix("Basic ")
    {
        let decoded = STANDARD
            .decode(encoded)
            .map_err(|_| AppError::Unauthorized)?;
        let decoded = String::from_utf8(decoded).map_err(|_| AppError::Unauthorized)?;
        let (client_id, client_secret) = decoded.split_once(':').ok_or(AppError::Unauthorized)?;
        return Ok(ClientCredentials {
            client_id: url_decode(client_id),
            client_secret: Some(url_decode(client_secret)),
            client_assertion_type: None,
            client_assertion: None,
        });
    }
    if let Some(assertion) = payload.client_assertion() {
        let client_id = payload
            .client_id()
            .map(ToOwned::to_owned)
            .map(Ok)
            .unwrap_or_else(|| client_assertion::client_id_from_assertion(assertion))?;
        return Ok(ClientCredentials {
            client_id,
            client_secret: None,
            client_assertion_type: payload.client_assertion_type().map(ToOwned::to_owned),
            client_assertion: Some(assertion.to_string()),
        });
    }
    Ok(ClientCredentials {
        client_id: payload
            .client_id()
            .map(ToOwned::to_owned)
            .ok_or(AppError::Unauthorized)?,
        client_secret: payload.client_secret().map(ToOwned::to_owned),
        client_assertion_type: None,
        client_assertion: None,
    })
}

fn diagnostic_client_id<T: ClientAuthFields>(headers: &HeaderMap, payload: &T) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Basic "))
        .and_then(|encoded| STANDARD.decode(encoded).ok())
        .and_then(|decoded| String::from_utf8(decoded).ok())
        .and_then(|decoded| {
            decoded
                .split_once(':')
                .map(|(client_id, _)| url_decode(client_id))
        })
        .or_else(|| payload.client_id().map(ToOwned::to_owned))
}

fn authorization_token(headers: &HeaderMap) -> AppResult<(&'static str, &str)> {
    let header = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or(AppError::Unauthorized)?;
    if let Some(token) = header.strip_prefix("Bearer ") {
        return Ok(("Bearer", token));
    }
    if let Some(token) = header.strip_prefix("DPoP ") {
        return Ok((dpop::TOKEN_TYPE, token));
    }
    Err(AppError::Unauthorized)
}

async fn client_auth_audiences(
    state: &AppState,
    headers: &HeaderMap,
    endpoint_path: &str,
) -> AppResult<Vec<String>> {
    let mut audiences = state
        .accepted_issuers(headers)
        .await?
        .into_iter()
        .map(|issuer| absolute(&issuer, endpoint_path))
        .collect::<Vec<_>>();
    audiences.sort();
    audiences.dedup();
    Ok(audiences)
}

fn normalize_client_credentials_scope(
    client: &ClientRecord,
    requested: Option<&str>,
) -> AppResult<String> {
    let Some(requested) = requested.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(String::new());
    };
    let allowed = client.scopes()?;
    let scopes = requested
        .split_whitespace()
        .filter(|scope| !scope.is_empty())
        .collect::<Vec<_>>();
    for scope in &scopes {
        if !allowed.iter().any(|allowed| allowed == scope) {
            return Err(AppError::Oidc(format!(
                "client is not allowed to request scope: {scope}"
            )));
        }
    }
    Ok(scopes.join(" "))
}

pub(crate) fn normalize_resource(resource: Option<&str>) -> AppResult<Option<String>> {
    let Some(resource) = resource.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let parsed = Url::parse(resource)
        .map_err(|err| AppError::Oidc(format!("invalid resource parameter: {err}")))?;
    if parsed.fragment().is_some() {
        return Err(AppError::Oidc(
            "resource parameter must not include a fragment".to_string(),
        ));
    }
    Ok(Some(resource.to_string()))
}

fn resolve_client_credentials_audience(
    client: &ClientRecord,
    requested_resource: Option<String>,
    requested_audience: Option<&str>,
) -> AppResult<Option<String>> {
    let requested_audience = requested_audience
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(normalize_audience)
        .transpose()?;
    if let (Some(resource), Some(audience)) = (&requested_resource, &requested_audience)
        && resource != audience
    {
        return Err(AppError::Oidc(
            "resource and audience identify different targets".to_string(),
        ));
    }
    let configured =
        (!client.audience.trim().is_empty()).then(|| client.audience.trim().to_string());
    let requested = requested_resource.or(requested_audience);
    if let (Some(expected), Some(requested)) = (&configured, &requested)
        && expected != requested
    {
        return Err(AppError::Oidc(
            "resource parameter does not match configured client audience".to_string(),
        ));
    }
    Ok(requested.or(configured))
}

fn normalize_audience(audience: &str) -> AppResult<String> {
    if audience.len() > 2048 || audience.chars().any(char::is_whitespace) {
        return Err(AppError::Oidc("invalid audience parameter".to_string()));
    }
    Ok(audience.to_string())
}

fn merge_token_resource(
    issued: Option<String>,
    requested: Option<String>,
) -> AppResult<Option<String>> {
    let requested = normalize_resource(requested.as_deref())?;
    match (issued, requested) {
        (Some(issued), Some(requested)) if issued != requested => Err(AppError::Oidc(
            "resource parameter does not match authorization request".to_string(),
        )),
        (Some(issued), _) => Ok(Some(issued)),
        (None, requested) => Ok(requested),
    }
}

async fn load_active_user(state: &AppState, user_id: &str) -> AppResult<UserRecord> {
    let user = state
        .db
        .find_user_by_id(user_id)
        .await?
        .ok_or(AppError::Unauthorized)?;
    if user.is_active == 1
        && user.archived_at.is_none()
        && state
            .db
            .find_trial_enrollment_for_user(&user.id)
            .await?
            .is_none_or(|enrollment| enrollment.is_active_at(util::now_ts()))
    {
        Ok(user)
    } else {
        Err(AppError::Unauthorized)
    }
}

async fn load_oidc_user(state: &AppState, user_id: &str) -> AppResult<UserRecord> {
    let user = state
        .db
        .find_user_by_id(user_id)
        .await?
        .ok_or(AppError::Unauthorized)?;
    if user.is_active != 1 {
        return Err(AppError::Unauthorized);
    }
    if state
        .db
        .find_trial_enrollment_for_user(&user.id)
        .await?
        .is_some_and(|enrollment| !enrollment.is_active_at(util::now_ts()))
    {
        return Err(AppError::Unauthorized);
    }
    if user.archived_at.is_none() {
        return Ok(user);
    }
    let looks_temporary = user.email.ends_with("@temporary.local")
        && state.db.user_has_invitation_redemption(&user.id).await?;
    if looks_temporary {
        Ok(user)
    } else {
        Err(AppError::Unauthorized)
    }
}

fn absolute(base_url: &str, path: &str) -> String {
    if path.starts_with("http://") || path.starts_with("https://") {
        path.to_string()
    } else {
        format!(
            "{}{}",
            base_url.trim_end_matches('/'),
            if path.starts_with('/') {
                path.to_string()
            } else {
                format!("/{path}")
            }
        )
    }
}

#[cfg(test)]
fn resolved_query_to_pairs(
    request: &ResolvedAuthorizeRequest,
    strip_login_prompt: bool,
) -> Vec<(&'static str, String)> {
    let mut pairs = Vec::new();
    pairs.push(("response_type", request.response_type.clone()));
    pairs.push(("client_id", request.client_id.clone()));
    pairs.push(("redirect_uri", request.redirect_uri.clone()));
    if let Some(value) = &request.scope {
        pairs.push(("scope", value.clone()));
    }
    if let Some(value) = &request.resource {
        pairs.push(("resource", value.clone()));
    }
    if let Some(value) = &request.authorization_details {
        pairs.push(("authorization_details", value.clone()));
    }
    if let Some(value) = &request.login_hint {
        pairs.push(("login_hint", value.clone()));
    }
    let prompt = if strip_login_prompt {
        prompt_without_login(request.prompt.as_deref())
    } else {
        request.prompt.clone()
    };
    if let Some(value) = prompt {
        pairs.push(("prompt", value));
    }
    if let Some(value) = request.max_age {
        pairs.push(("max_age", value.to_string()));
    }
    if let Some(value) = &request.acr_values {
        pairs.push(("acr_values", value.clone()));
    }
    if let Some(value) = &request.claims
        && let Ok(encoded) = value.to_authorization_parameter()
    {
        pairs.push(("claims", encoded));
    }
    if let Some(value) = &request.state {
        pairs.push(("state", value.clone()));
    }
    if let Some(value) = &request.nonce {
        pairs.push(("nonce", value.clone()));
    }
    if let Some(value) = &request.code_challenge {
        pairs.push(("code_challenge", value.clone()));
    }
    if let Some(value) = &request.code_challenge_method {
        pairs.push(("code_challenge_method", value.clone()));
    }
    if let Some(value) = &request.response_mode {
        pairs.push(("response_mode", value.clone()));
    }
    pairs
}

#[cfg(test)]
fn authorize_return_to_resolved_for_login(
    request: &ResolvedAuthorizeRequest,
    strip_login_prompt: bool,
) -> String {
    format!(
        "/oauth2/authorize?{}",
        serde_urlencode(&resolved_query_to_pairs(request, strip_login_prompt))
    )
}

fn frontend_login_url(return_to: &str, login_hint: Option<&str>, force_login: bool) -> String {
    redirects::frontend_login_url(return_to, login_hint, force_login)
}

async fn reauthentication_login_response(
    state: &AppState,
    jar: CookieJar,
    request: &ResolvedAuthorizeRequest,
    expected_user_id: Option<&str>,
    force_login: bool,
) -> AppResult<Response> {
    let request = reauthentication_request(request);
    let return_to = authorize_return_to_for_interaction(state, &request, false).await?;
    let (jar, context, _current) =
        crate::browser_accounts::ensure_browser_context(state, jar).await?;
    let account_flow = crate::browser_accounts::create_account_login_flow(
        state,
        &context.id,
        &return_to,
        expected_user_id,
    )
    .await?;
    let login_url = format!(
        "{}&account_flow={}",
        frontend_login_url(&return_to, request.login_hint.as_deref(), force_login),
        url_encode(&account_flow)
    );
    Ok((jar, Redirect::to(&login_url)).into_response())
}

async fn authorize_return_to_for_interaction(
    store: &impl AuthorizationInteractionRequestStore,
    request: &ResolvedAuthorizeRequest,
    strip_login_prompt: bool,
) -> AppResult<String> {
    let request = return_to_request(request, strip_login_prompt);
    let request_uri = store
        .store_interaction_request(&request.client_id, &request)
        .await?;
    Ok(format!(
        "/oauth2/authorize?interaction_request={}",
        url_encode(&request_uri)
    ))
}

async fn authorize_return_to_for_account_selection(
    store: &impl AuthorizationInteractionRequestStore,
    request: &ResolvedAuthorizeRequest,
) -> AppResult<String> {
    let request = account_selection_prompted_request(request);
    let request_uri = store
        .store_interaction_request(&request.client_id, &request)
        .await?;
    Ok(format!(
        "/oauth2/authorize?interaction_request={}",
        url_encode(&request_uri)
    ))
}

async fn consent_interaction_request(
    state: &AppState,
    request: &ResolvedAuthorizeRequest,
) -> AppResult<String> {
    crate::par::store_interaction_authorization_request(state, &request.client_id, request).await
}

fn return_to_request(
    request: &ResolvedAuthorizeRequest,
    strip_login_prompt: bool,
) -> ResolvedAuthorizeRequest {
    let mut request = request.clone();
    if strip_login_prompt {
        request.prompt = prompt_without_login(request.prompt.as_deref());
    }
    request
}

fn reauthentication_request(request: &ResolvedAuthorizeRequest) -> ResolvedAuthorizeRequest {
    let mut request = request.clone();
    request.reauthentication_required = true;
    request.selected_session_id = None;
    request
}

fn account_selection_prompted_request(
    request: &ResolvedAuthorizeRequest,
) -> ResolvedAuthorizeRequest {
    let mut request = request.clone();
    // This handle is exposed to the browser before a selection is made. Keep
    // the request incomplete so navigating to it directly cannot bypass the
    // chooser. Only `complete_browser_account_selection` marks it completed.
    request.account_selection_prompted = false;
    request.account_selection_required = true;
    request.reauthentication_required = false;
    request.selected_session_id = None;
    request.selected_user_id = None;
    request
}

async fn client_requires_account_selection(
    state: &AppState,
    client: &ClientRecord,
    request: &ResolvedAuthorizeRequest,
) -> AppResult<bool> {
    if request.account_selection_prompted {
        return Ok(false);
    }
    Ok(client.require_account_selection == 1
        || state
            .db
            .find_application_for_client(&client.id)
            .await?
            .is_some_and(|application| application.requires_account_selection()))
}

fn reauthentication_pending(request: &ResolvedAuthorizeRequest) -> bool {
    request.reauthentication_required && request.selected_session_id.is_none()
}

fn session_binding_satisfies_reauthentication(
    request: &ResolvedAuthorizeRequest,
    session: &SessionRecord,
) -> bool {
    !request.reauthentication_required
        && request.selected_session_id.as_deref() == Some(session.id.as_str())
}

async fn has_selectable_browser_accounts(
    state: &AppState,
    jar: &CookieJar,
    client: Option<&ClientRecord>,
) -> AppResult<bool> {
    let Some(context_id) = auth::browser_context_id_from_jar(state, jar) else {
        return Ok(false);
    };
    if state.db.find_browser_context(&context_id).await?.is_none() {
        return Ok(false);
    }
    for account in state.db.list_browser_context_accounts(&context_id).await? {
        let Some(user) = state.db.find_user_by_id(&account.user_id).await? else {
            continue;
        };
        let Some(session) = state
            .db
            .find_session(&account.session_id)
            .await?
            .filter(|session| session.expires_at >= util::now_ts())
        else {
            continue;
        };
        let trial_enrollment = state.db.find_trial_enrollment_for_user(&user.id).await?;
        if trial_enrollment
            .as_ref()
            .is_some_and(|enrollment| !enrollment.is_active_at(util::now_ts()))
        {
            continue;
        }
        let has_redemption = if user.archived_at.is_some() {
            state.db.user_has_invitation_redemption(&user.id).await?
        } else {
            false
        };
        if auth::AccountSessionKind::for_session_with_trial_enrollment(
            &user,
            &session,
            has_redemption,
            trial_enrollment.is_some(),
        )
        .is_some()
        {
            if let Some(client) = client
                && !applications::user_can_authorize_client(state, client, &user).await?
            {
                continue;
            }
            return Ok(true);
        }
    }
    Ok(false)
}

fn prompt_behavior_for_client(
    _client: &ClientRecord,
    request: &ResolvedAuthorizeRequest,
) -> AppResult<PromptBehavior> {
    request.prompt_behavior()
}

fn authorize_request_from_return_to(return_to: &str) -> AppResult<Option<AuthorizeRequest>> {
    let return_to = decode_authorize_return_to(return_to);
    let Some(query) = return_to.strip_prefix("/oauth2/authorize?") else {
        return Ok(None);
    };
    serde_urlencoded::from_str(query)
        .map(Some)
        .map_err(|err| AppError::BadRequest(format!("invalid OIDC return target: {err}")))
}

fn decode_authorize_return_to(return_to: &str) -> String {
    let return_to = return_to.trim();
    if return_to.starts_with("/oauth2/authorize?") {
        return_to.to_string()
    } else {
        url_decode(return_to)
    }
}

pub(crate) async fn authorization_login_context_from_return_to(
    state: &AppState,
    headers: &HeaderMap,
    return_to: Option<&str>,
) -> AppResult<AuthorizationLoginContext> {
    let Some(return_to) = return_to else {
        return Ok(AuthorizationLoginContext {
            client: None,
            application: None,
            request_requires_mfa: false,
        });
    };
    let Some(query) = authorize_request_from_return_to(return_to)? else {
        return Ok(AuthorizationLoginContext {
            client: None,
            application: None,
            request_requires_mfa: false,
        });
    };
    let request = if let Some(interaction_request) = query.interaction_request.as_deref() {
        let Some(request) =
            crate::par::peek_interaction_request(state, interaction_request).await?
        else {
            return Ok(AuthorizationLoginContext {
                client: None,
                application: None,
                request_requires_mfa: false,
            });
        };
        request
    } else if let Some(request_uri) = query.request_uri.as_deref() {
        let Some(request) = crate::par::peek_request_uri(state, request_uri).await? else {
            return Ok(AuthorizationLoginContext {
                client: None,
                application: None,
                request_requires_mfa: false,
            });
        };
        request
    } else {
        resolve_authorize_request(state, headers, query).await?
    };
    let client = validate_authorize_request(state, &request).await?;
    let application = state.db.find_application_for_client(&client.id).await?;
    if let Some(application) = application.as_ref() {
        applications::ensure_application_runtime_active(state, application).await?;
    }
    let requested_assurance = request.requested_assurance()?;
    Ok(AuthorizationLoginContext {
        client: Some(client),
        application,
        request_requires_mfa: assurance::DefaultAssurancePolicy.requires_mfa(&requested_assurance),
    })
}

#[derive(Debug, Clone)]
pub(crate) struct VerifiedOidcLoginInteraction {
    pub interaction_request_hash: String,
    pub client: ClientRecord,
    pub continue_to: String,
    pub request_requires_mfa: bool,
    pub requests_offline_access: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct BrowserAccountInteractionContext {
    pub client_id: String,
    pub client_name: String,
    pub client_logo_uri: Option<String>,
    pub login_hint: Option<String>,
    pub reauthentication_required: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct BrowserAccountSelectionContinuation {
    pub continue_to: String,
    pub reauthentication_required: bool,
    pub selected_user_id: String,
}

/// Resolve the only OIDC context that may authorize an administrator-universal
/// login code. The application identity comes exclusively from a server-created
/// browser interaction; callers must never accept a client ID from JSON input.
pub(crate) async fn verified_oidc_login_interaction_from_return_to(
    state: &AppState,
    return_to: Option<&str>,
) -> AppResult<VerifiedOidcLoginInteraction> {
    let interaction_request =
        strict_interaction_request_from_return_to(return_to).ok_or(AppError::Unauthorized)?;
    let request = crate::par::peek_interaction_request(state, &interaction_request)
        .await?
        .ok_or(AppError::Unauthorized)?;
    let client = validate_authorize_request(state, &request).await?;
    let requested_scopes = util::normalize_scopes(
        request.scope.as_deref(),
        &state.settings.oidc.supported_scopes,
    )?;
    validate_requested_scopes(&client, &requested_scopes)?;
    let requested_assurance = request.requested_assurance()?;
    let request_requires_mfa = client.require_mfa == 1
        || assurance::DefaultAssurancePolicy.requires_mfa(&requested_assurance);
    let requests_offline_access = requested_scopes
        .iter()
        .any(|scope| scope == "offline_access");
    let continue_to = format!(
        "/oauth2/authorize?interaction_request={}",
        url_encode(&interaction_request)
    );
    Ok(VerifiedOidcLoginInteraction {
        interaction_request_hash: util::token_hash(&interaction_request),
        client,
        continue_to,
        request_requires_mfa,
        requests_offline_access,
    })
}

pub(crate) async fn browser_account_interaction_context(
    state: &AppState,
    return_to: &str,
) -> AppResult<Option<BrowserAccountInteractionContext>> {
    let Some(interaction_request) = strict_interaction_request_from_return_to(Some(return_to))
    else {
        return Ok(None);
    };
    let Some(request) = crate::par::peek_interaction_request(state, &interaction_request).await?
    else {
        return Err(AppError::Unauthorized);
    };
    let client = validate_authorize_request(state, &request).await?;
    let prompt = request.prompt_behavior()?;
    Ok(Some(BrowserAccountInteractionContext {
        client_id: client.client_id,
        client_name: client.client_name,
        client_logo_uri: (!client.logo_uri.trim().is_empty()).then_some(client.logo_uri),
        login_hint: request.login_hint,
        reauthentication_required: prompt.force_login || request.max_age.is_some(),
    }))
}

pub(crate) async fn complete_browser_account_selection(
    state: &AppState,
    return_to: &str,
    selected_session_id: &str,
) -> AppResult<BrowserAccountSelectionContinuation> {
    let interaction_request =
        strict_interaction_request_from_return_to(Some(return_to)).ok_or(AppError::Unauthorized)?;
    let preview = crate::par::peek_interaction_request(state, &interaction_request)
        .await?
        .ok_or(AppError::Unauthorized)?;
    let client = validate_authorize_request(state, &preview).await?;
    if !preview.account_selection_required || preview.account_selection_prompted {
        return Err(AppError::Unauthorized);
    }
    let session = state
        .db
        .find_session(selected_session_id)
        .await?
        .filter(|session| session.expires_at >= util::now_ts())
        .ok_or(AppError::Unauthorized)?;
    let user = state
        .db
        .find_user_by_id(&session.user_id)
        .await?
        .filter(|user| user.is_active == 1)
        .ok_or(AppError::Unauthorized)?;
    ensure_trial_enrollment_client_allowed_for_user(state, &user.id, &client.client_id).await?;
    ensure_application_client_allowed_for_user(state, &user, &client).await?;
    let trial_enrollment = state.db.find_trial_enrollment_for_user(&user.id).await?;
    if trial_enrollment
        .as_ref()
        .is_some_and(|enrollment| !enrollment.is_active_at(util::now_ts()))
    {
        return Err(AppError::Unauthorized);
    }
    let has_redemption = if user.archived_at.is_some() {
        state.db.user_has_invitation_redemption(&user.id).await?
    } else {
        false
    };
    auth::AccountSessionKind::for_session_with_trial_enrollment(
        &user,
        &session,
        has_redemption,
        trial_enrollment.is_some(),
    )
    .ok_or(AppError::Unauthorized)?;
    let request = crate::par::consume_interaction_request(state, &interaction_request).await?;
    if serde_json::to_string(&request).map_err(|err| AppError::Internal(err.to_string()))?
        != serde_json::to_string(&preview).map_err(|err| AppError::Internal(err.to_string()))?
    {
        return Err(AppError::Unauthorized);
    }
    let prompt = prompt_behavior_for_client(&client, &request)?;
    let reauthentication_required =
        session.needs_reauthentication(prompt, request.max_age, util::now_ts());
    let mut continuation = request;
    continuation.account_selection_prompted = true;
    continuation.account_selection_required = false;
    continuation.prompt = prompt_without_select_account(continuation.prompt.as_deref());
    continuation.selected_user_id = Some(user.id.clone());
    if reauthentication_required {
        continuation.reauthentication_required = true;
        continuation.selected_session_id = None;
    } else {
        continuation.reauthentication_required = false;
        continuation.selected_session_id = Some(session.id);
    }
    let next_interaction = crate::par::store_interaction_authorization_request(
        state,
        &continuation.client_id,
        &continuation,
    )
    .await?;
    Ok(BrowserAccountSelectionContinuation {
        continue_to: format!(
            "/oauth2/authorize?interaction_request={}",
            url_encode(&next_interaction)
        ),
        reauthentication_required,
        selected_user_id: user.id,
    })
}

pub(crate) async fn complete_browser_account_reauthentication(
    state: &AppState,
    return_to: &str,
    authenticated_user_id: &str,
    authenticated_session_id: &str,
    flow_created_at: i64,
) -> AppResult<bool> {
    let Some(interaction_request) = strict_interaction_request_from_return_to(Some(return_to))
    else {
        return Ok(false);
    };
    let Some(mut request) =
        crate::par::peek_interaction_request(state, &interaction_request).await?
    else {
        return Ok(false);
    };
    if !reauthentication_pending(&request) {
        return Ok(false);
    }
    validate_authorize_request(state, &request).await?;
    if request
        .selected_user_id
        .as_deref()
        .is_some_and(|selected| selected != authenticated_user_id)
    {
        return Err(AppError::Unauthorized);
    }
    let session = state
        .db
        .find_session(authenticated_session_id)
        .await?
        .filter(|session| {
            session.user_id == authenticated_user_id
                && session.expires_at >= util::now_ts()
                && session.created_at >= flow_created_at
        })
        .ok_or(AppError::Unauthorized)?;
    let expected_request = request.clone();
    request.reauthentication_required = false;
    request.selected_user_id = Some(authenticated_user_id.to_string());
    request.selected_session_id = Some(session.id);
    crate::par::update_interaction_authorization_request(
        state,
        &interaction_request,
        &expected_request,
        &request,
    )
    .await?;
    Ok(true)
}

fn strict_interaction_request_from_return_to(return_to: Option<&str>) -> Option<String> {
    let return_to = decode_authorize_return_to(return_to?.trim());
    if return_to.contains('#') {
        return None;
    }
    let query = return_to.strip_prefix("/oauth2/authorize?")?;
    let pairs = url::form_urlencoded::parse(query.as_bytes()).collect::<Vec<_>>();
    if pairs.len() != 1 || pairs[0].0 != "interaction_request" {
        return None;
    }
    let interaction_request = pairs[0].1.trim();
    (!interaction_request.is_empty()).then(|| interaction_request.to_string())
}

fn required_query_value(value: Option<String>, field: &str) -> AppResult<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::Oidc(format!("{field} is required")))
}

fn optional_form_value(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub(crate) fn parse_max_age(value: Option<&str>) -> AppResult<Option<i64>> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let max_age = value
        .parse::<i64>()
        .map_err(|_| AppError::Oidc("max_age must be a non-negative integer".to_string()))?;
    validate_max_age(max_age).map(Some)
}

pub(crate) fn validate_max_age(max_age: i64) -> AppResult<i64> {
    if max_age < 0 {
        return Err(AppError::Oidc(
            "max_age must be a non-negative integer".to_string(),
        ));
    }
    Ok(max_age)
}

pub(crate) fn normalize_acr_values_param(value: Option<&str>) -> AppResult<Option<String>> {
    let values = assurance::parse_acr_values(value)?;
    Ok((!values.is_empty()).then(|| values.join(" ")))
}

fn prompt_without_login(prompt: Option<&str>) -> Option<String> {
    let prompt = prompt?
        .split_whitespace()
        .filter(|value| *value != "login")
        .collect::<Vec<_>>()
        .join(" ");
    (!prompt.is_empty()).then_some(prompt)
}

fn prompt_without_select_account(prompt: Option<&str>) -> Option<String> {
    let prompt = prompt?
        .split_whitespace()
        .filter(|value| *value != "select_account")
        .collect::<Vec<_>>()
        .join(" ");
    (!prompt.is_empty()).then_some(prompt)
}

fn prompt_behavior(prompt: Option<&str>) -> AppResult<PromptBehavior> {
    let values = prompt
        .unwrap_or_default()
        .split_whitespace()
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    let mut behavior = PromptBehavior {
        force_consent: false,
        force_login: false,
        select_account: false,
        none: false,
    };
    if values.is_empty() {
        return Ok(behavior);
    }
    for value in &values {
        match *value {
            "consent" => behavior.force_consent = true,
            "login" => behavior.force_login = true,
            "select_account" => behavior.select_account = true,
            "none" => behavior.none = true,
            other => return Err(AppError::Oidc(format!("unsupported prompt: {other}"))),
        }
    }
    if behavior.none && values.len() > 1 {
        return Err(AppError::Oidc(
            "prompt=none cannot be combined with other prompt values".to_string(),
        ));
    }
    Ok(behavior)
}

#[cfg(test)]
fn serde_urlencode(pairs: &[(&'static str, String)]) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in pairs {
        serializer.append_pair(key, value);
    }
    serializer.finish()
}

fn url_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn url_decode(value: &str) -> String {
    url::form_urlencoded::parse(value.as_bytes())
        .map(|(key, _)| key.into_owned())
        .next()
        .unwrap_or_else(|| value.to_string())
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[allow(dead_code)]
fn oauth_json_error(error: &str, description: &str, status: StatusCode) -> Response {
    (
        status,
        Json(serde_json::json!({
            "error": error,
            "error_description": description,
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
        response::Response,
    };
    use std::{collections::HashMap, path::PathBuf, sync::Mutex};
    use tower::ServiceExt;

    struct StubInteractionStore {
        request_uri: String,
        stored: Mutex<Vec<ResolvedAuthorizeRequest>>,
    }

    impl StubInteractionStore {
        fn new(request_uri: &str) -> Self {
            Self {
                request_uri: request_uri.to_string(),
                stored: Mutex::new(Vec::new()),
            }
        }
    }

    impl AuthorizationInteractionRequestStore for StubInteractionStore {
        async fn store_interaction_request(
            &self,
            client_id: &str,
            request: &ResolvedAuthorizeRequest,
        ) -> AppResult<String> {
            assert_eq!(client_id, request.client_id);
            self.stored.lock().unwrap().push(request.clone());
            Ok(self.request_uri.clone())
        }
    }

    fn redirect_url(response: &Response) -> Url {
        let location = response
            .headers()
            .get(header::LOCATION)
            .expect("redirect must include Location")
            .to_str()
            .unwrap();
        Url::parse("http://sso.test/")
            .unwrap()
            .join(location)
            .unwrap()
    }

    fn query_value(url: &Url, name: &str) -> String {
        url.query_pairs()
            .find_map(|(key, value)| (key == name).then(|| value.into_owned()))
            .unwrap_or_else(|| panic!("redirect query must include {name}"))
    }

    #[test]
    fn prompt_none_is_exclusive() {
        assert!(prompt_behavior(Some("none")).unwrap().none);
        assert!(prompt_behavior(Some("none consent")).is_err());
        assert!(prompt_behavior(Some("none login")).is_err());
    }

    #[test]
    fn account_selection_client_preserves_non_interactive_prompt_none() {
        let request = test_authorize_request(Some("none"), None);
        let strict_client = test_client();
        assert!(
            prompt_behavior_for_client(&strict_client, &request)
                .unwrap()
                .none
        );

        let mut interactive_client = test_client();
        interactive_client.require_account_selection = 1;
        let behavior = prompt_behavior_for_client(&interactive_client, &request).unwrap();
        assert!(behavior.none);
        assert!(!behavior.force_login);
        assert!(!behavior.force_consent);
    }

    #[test]
    fn authorization_request_parameters_are_bounded_and_pkce_is_well_formed() {
        let mut client = test_client();
        client.require_pkce = 1;
        let mut request = test_authorize_request(None, None);
        request.code_challenge = Some("a".repeat(43));
        request.code_challenge_method = Some("S256".to_string());
        assert!(validate_authorize_request_for_client(&client, &request).is_ok());

        request.state = Some("x".repeat(4097));
        assert!(validate_authorize_request_for_client(&client, &request).is_err());
        request.state = Some("line\nfeed".to_string());
        assert!(validate_authorize_request_for_client(&client, &request).is_err());

        request.state = Some("safe-state".to_string());
        request.code_challenge = Some("a".repeat(42));
        assert!(validate_authorize_request_for_client(&client, &request).is_err());
        request.code_challenge = Some("a".repeat(43));
        request.code_challenge_method = Some("plain-ish".to_string());
        assert!(validate_authorize_request_for_client(&client, &request).is_err());
        request.code_challenge_method = None;
        assert!(validate_authorize_request_for_client(&client, &request).is_ok());
        client.require_s256_pkce = 1;
        assert!(validate_authorize_request_for_client(&client, &request).is_err());
    }

    #[test]
    fn prompt_consent_forces_consent() {
        let behavior = prompt_behavior(Some("consent")).unwrap();
        assert!(behavior.force_consent);
        assert!(!behavior.none);
    }

    #[test]
    fn prompt_login_forces_reauthentication() {
        let behavior = prompt_behavior(Some("login consent")).unwrap();
        assert!(behavior.force_login);
        assert!(behavior.force_consent);
        assert!(!behavior.none);
    }

    #[test]
    fn prompt_select_account_forces_account_selection() {
        let behavior = prompt_behavior(Some("select_account consent")).unwrap();
        assert!(behavior.select_account);
        assert!(!behavior.force_login);
        assert!(behavior.force_consent);
        assert!(!behavior.none);
    }

    #[test]
    fn max_age_parses_non_negative_seconds() {
        assert_eq!(parse_max_age(None).unwrap(), None);
        assert_eq!(parse_max_age(Some("")).unwrap(), None);
        assert_eq!(parse_max_age(Some("0")).unwrap(), Some(0));
        assert_eq!(parse_max_age(Some("300")).unwrap(), Some(300));
        assert!(parse_max_age(Some("-1")).is_err());
        assert!(parse_max_age(Some("soon")).is_err());
    }

    #[test]
    fn session_freshness_respects_prompt_login_and_max_age() {
        let session = test_session(100);
        assert!(session.needs_reauthentication(
            PromptBehavior {
                force_consent: false,
                force_login: false,
                select_account: false,
                none: false,
            },
            Some(0),
            100
        ));
        assert!(session.needs_reauthentication(
            PromptBehavior {
                force_consent: false,
                force_login: true,
                select_account: false,
                none: false,
            },
            None,
            100
        ));
        assert!(!session.needs_reauthentication(
            PromptBehavior {
                force_consent: false,
                force_login: false,
                select_account: false,
                none: false,
            },
            Some(30),
            130
        ));
        assert!(session.needs_reauthentication(
            PromptBehavior {
                force_consent: false,
                force_login: false,
                select_account: false,
                none: false,
            },
            Some(30),
            131
        ));
    }

    #[test]
    fn reauthentication_return_to_removes_login_prompt() {
        let mut request = test_authorize_request(Some("login select_account consent"), Some(300));
        request.acr_values = Some(assurance::ACR_MFA.to_string());
        request.login_hint = Some("alice@example.com".to_string());
        request.claims = RequestedClaims::from_authorization_parameter(Some(
            r#"{"id_token":{"amr":{"essential":true,"values":["otp"]}}}"#,
        ))
        .unwrap();
        let return_to = authorize_return_to_resolved_for_login(&request, true);
        assert!(return_to.starts_with("/oauth2/authorize?"));
        let query = return_to.trim_start_matches("/oauth2/authorize?");
        let parsed = serde_urlencoded::from_str::<HashMap<String, String>>(query).unwrap();
        assert_eq!(
            parsed.get("prompt").map(String::as_str),
            Some("select_account consent")
        );
        assert_eq!(parsed.get("max_age").map(String::as_str), Some("300"));
        assert_eq!(
            parsed.get("acr_values").map(String::as_str),
            Some(assurance::ACR_MFA)
        );
        assert!(
            parsed
                .get("claims")
                .is_some_and(|value| value.contains(r#""amr""#))
        );
        assert_eq!(
            parsed.get("login_hint").map(String::as_str),
            Some("alice@example.com")
        );
    }

    #[test]
    fn frontend_login_url_prefills_hint_and_local_return_target() {
        let url = frontend_login_url(
            "/oauth2/authorize?client_id=client-a&login_hint=alice%40example.com",
            Some("alice@example.com"),
            false,
        );
        let query = url.trim_start_matches("/?");
        let parsed = serde_urlencoded::from_str::<HashMap<String, String>>(query).unwrap();
        assert_eq!(parsed.get("auth").map(String::as_str), Some("login"));
        assert_eq!(
            parsed.get("return_to").map(String::as_str),
            Some("/oauth2/authorize?client_id=client-a&login_hint=alice%40example.com")
        );
        assert_eq!(
            parsed.get("login_hint").map(String::as_str),
            Some("alice@example.com")
        );
    }

    #[test]
    fn frontend_login_url_can_force_interactive_login() {
        let url = frontend_login_url("/oauth2/authorize?client_id=client-a", None, true);
        let query = url.trim_start_matches("/?");
        let parsed = serde_urlencoded::from_str::<HashMap<String, String>>(query).unwrap();
        assert_eq!(parsed.get("force_login").map(String::as_str), Some("1"));
    }

    #[test]
    fn universal_login_context_accepts_only_one_opaque_interaction_handle() {
        assert_eq!(
            strict_interaction_request_from_return_to(Some(
                "/oauth2/authorize?interaction_request=urn%3Agpt-sso%3Abrowser-interaction%3Asecret"
            ))
            .as_deref(),
            Some("urn:gpt-sso:browser-interaction:secret")
        );
        for invalid in [
            "/oauth2/authorize?client_id=client-a&response_type=code",
            "/oauth2/authorize?request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Apar",
            "/oauth2/authorize?interaction_request=one&client_id=client-a",
            "/oauth2/authorize?interaction_request=one&interaction_request=two",
            "/oauth2/authorize?interaction_request=one#fragment",
            "https://evil.example/oauth2/authorize?interaction_request=one",
        ] {
            assert_eq!(
                strict_interaction_request_from_return_to(Some(invalid)),
                None
            );
        }
    }

    #[test]
    fn account_selection_entry_request_cannot_mark_selection_complete() {
        let request = test_authorize_request(Some("login select_account consent"), None);
        let prompted = account_selection_prompted_request(&request);
        assert!(!prompted.account_selection_prompted);
        assert!(prompted.account_selection_required);
        assert!(!prompted.reauthentication_required);
        assert_eq!(
            prompted.prompt.as_deref(),
            Some("login select_account consent")
        );
    }

    #[test]
    fn public_authorize_query_cannot_forge_internal_account_state() {
        let query = serde_urlencoded::from_str::<AuthorizeRequest>(
            "response_type=code&client_id=demo-web&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&account_selection_prompted=true&account_selection_required=true&reauthentication_required=true&selected_session_id=forged-session&selected_user_id=forged-user",
        )
        .unwrap();
        let request = ResolvedAuthorizeRequest::from_query(query).unwrap();

        assert!(!request.account_selection_prompted);
        assert!(!request.account_selection_required);
        assert!(!request.reauthentication_required);
        assert_eq!(request.selected_session_id, None);
        assert_eq!(request.selected_user_id, None);
    }

    #[test]
    fn reauthentication_request_remains_incomplete_until_login_proves_a_session() {
        let mut request = test_authorize_request(Some("login select_account"), Some(0));
        request.selected_user_id = Some("user-id".to_string());
        request.selected_session_id = Some("old-session".to_string());

        let pending = reauthentication_request(&request);

        assert!(pending.reauthentication_required);
        assert_eq!(pending.selected_user_id.as_deref(), Some("user-id"));
        assert_eq!(pending.selected_session_id, None);
        assert!(reauthentication_pending(&pending));
    }

    #[tokio::test]
    async fn interaction_return_to_uses_short_request_uri() {
        let store = StubInteractionStore::new("urn:ietf:params:oauth:request_uri:stored-request");
        let mut request = test_authorize_request(Some("login consent"), None);
        request.state = Some("state-value-that-should-stay-server-side".repeat(8));
        request.nonce = Some("nonce-value-that-should-stay-server-side".repeat(8));

        let return_to = authorize_return_to_for_interaction(&store, &request, true)
            .await
            .unwrap();

        assert!(return_to.starts_with("/oauth2/authorize?"));
        assert!(!return_to.contains("client_id="));
        assert!(!return_to.contains("state-value"));
        assert!(!return_to.contains("nonce-value"));
        let query = return_to.trim_start_matches("/oauth2/authorize?");
        let parsed = serde_urlencoded::from_str::<HashMap<String, String>>(query).unwrap();
        assert_eq!(
            parsed.get("interaction_request").map(String::as_str),
            Some("urn:ietf:params:oauth:request_uri:stored-request")
        );

        let stored = store.stored.lock().unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].prompt.as_deref(), Some("consent"));
        assert_eq!(stored[0].state, request.state);
        assert_eq!(stored[0].nonce, request.nonce);
    }

    #[tokio::test]
    async fn login_context_uses_direct_authorization_return_to() {
        let (state, path) = test_app_state().await;
        let return_to = format!(
            "/oauth2/authorize?{}",
            serde_urlencode(&[
                ("response_type", "code".to_string()),
                ("client_id", "demo-web".to_string()),
                ("redirect_uri", "http://localhost:3000/callback".to_string(),),
                ("scope", "openid profile".to_string()),
                ("acr_values", assurance::ACR_MFA.to_string()),
            ])
        );

        let context =
            authorization_login_context_from_return_to(&state, &HeaderMap::new(), Some(&return_to))
                .await
                .unwrap();

        assert_eq!(
            context
                .client
                .as_ref()
                .map(|client| client.client_id.as_str()),
            Some("demo-web")
        );
        assert!(context.request_requires_mfa);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn login_context_peeks_interaction_request_without_consuming_it() {
        let (state, path) = test_app_state().await;
        let mut request = test_authorize_request(None, None);
        request.client_id = "demo-web".to_string();
        request.redirect_uri = "http://localhost:3000/callback".to_string();
        request.scope = Some("openid profile".to_string());
        request.acr_values = Some(assurance::ACR_MFA.to_string());
        let request_uri = crate::par::store_interaction_authorization_request(
            &state,
            &request.client_id,
            &request,
        )
        .await
        .unwrap();
        let return_to = format!(
            "/oauth2/authorize?interaction_request={}",
            url_encode(&request_uri)
        );

        let context =
            authorization_login_context_from_return_to(&state, &HeaderMap::new(), Some(&return_to))
                .await
                .unwrap();

        assert_eq!(
            context
                .client
                .as_ref()
                .map(|client| client.client_id.as_str()),
            Some("demo-web")
        );
        assert!(context.request_requires_mfa);
        let consumed = crate::par::consume_interaction_request(&state, &request_uri)
            .await
            .unwrap();
        assert_eq!(consumed.client_id, "demo-web");
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn browser_account_context_exposes_the_verified_client_logo_uri() {
        let (state, path) = test_app_state().await;
        let client = insert_test_oidc_client(
            &state,
            "branded-client",
            "http://localhost:4100/callback",
            "https://assets.example.com/branded-client.svg",
        )
        .await;
        let mut request = test_authorize_request(None, None);
        request.client_id = client.client_id;
        request.redirect_uri = "http://localhost:4100/callback".to_string();
        let request_uri = crate::par::store_interaction_authorization_request(
            &state,
            &request.client_id,
            &request,
        )
        .await
        .unwrap();
        let return_to = format!(
            "/oauth2/authorize?interaction_request={}",
            url_encode(&request_uri)
        );

        let context = browser_account_interaction_context(&state, &return_to)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(context.client_name, "branded-client");
        assert_eq!(
            context.client_logo_uri.as_deref(),
            Some("https://assets.example.com/branded-client.svg")
        );

        drop(state);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn authorize_request_derives_assurance_from_acr_and_claims() {
        let mut request = test_authorize_request(None, None);
        request.acr_values = Some(assurance::ACR_PASSWORD.to_string());
        request.claims = RequestedClaims::from_authorization_parameter(Some(&format!(
            r#"{{"id_token":{{"acr":{{"essential":true,"values":["{}"]}},"amr":{{"essential":true,"values":["otp"]}}}}}}"#,
            assurance::ACR_MFA
        )))
        .unwrap();

        let requested = request.requested_assurance().unwrap();
        assert_eq!(
            requested.acr_values,
            vec![assurance::ACR_PASSWORD.to_string()]
        );
        assert_eq!(
            requested.essential_acr_values,
            vec![assurance::ACR_MFA.to_string()]
        );
        assert_eq!(requested.essential_amr_values, vec!["otp".to_string()]);
    }

    #[test]
    fn post_logout_redirect_appends_state() {
        let redirect =
            post_logout_redirect_url("http://localhost:3000/logout?done=1", Some("abc 123"))
                .unwrap();
        assert_eq!(
            redirect.as_str(),
            "http://localhost:3000/logout?done=1&state=abc+123"
        );
        assert!(post_logout_redirect_url("not a url", Some("state")).is_none());
    }

    #[tokio::test]
    async fn invalid_consent_csrf_does_not_consume_interaction_request() {
        let (state, path) = test_app_state().await;
        let user = insert_refresh_test_user(&state, "consent-csrf").await;
        let (session, cookie_value) = state
            .db
            .insert_session(&user.id, 600, crate::db::SessionMetadata::default())
            .await
            .unwrap();
        let jar = CookieJar::new().add(auth::session_cookie(&state, cookie_value, 600));

        let page = consent_page(
            &state,
            &jar,
            &test_authorize_request(None, None),
            &test_client(),
            &user,
            true,
            &["openid".to_string()],
        )
        .await
        .unwrap();
        assert!(
            page.0
                .contains(&format!(r#"name="_csrf" value="{}""#, session.csrf_token))
        );
        let temporary_page = consent_page(
            &state,
            &jar,
            &test_authorize_request(None, None),
            &test_client(),
            &user,
            false,
            &["openid".to_string()],
        )
        .await
        .unwrap();
        assert!(!temporary_page.0.contains("name=\"remember\""));
        assert!(
            temporary_page
                .0
                .contains("restricted authorization-code session cannot remember")
        );

        let mut request = test_authorize_request(None, None);
        request.client_id = "demo-web".to_string();
        request.redirect_uri = "http://localhost:3000/callback".to_string();
        let request_uri = crate::par::store_interaction_authorization_request(
            &state,
            &request.client_id,
            &request,
        )
        .await
        .unwrap();
        let result = authorize_consent(
            State(state.clone()),
            jar,
            HeaderMap::new(),
            ConnectInfo("127.0.0.1:12345".parse().unwrap()),
            Form(ConsentForm {
                _csrf: Some("wrong-token".to_string()),
                action: "approve".to_string(),
                remember: None,
                response_type: "code".to_string(),
                client_id: "demo-web".to_string(),
                redirect_uri: "http://localhost:3000/callback".to_string(),
                scope: "openid".to_string(),
                resource: None,
                authorization_details: None,
                login_hint: None,
                prompt: None,
                max_age: None,
                interaction_request: Some(request_uri.clone()),
                request_uri: None,
                acr_values: None,
                claims: None,
                state: None,
                nonce: None,
                code_challenge: None,
                code_challenge_method: None,
                response_mode: None,
            }),
        )
        .await;
        assert!(matches!(result, Err(AppError::Forbidden)));
        let consumed = crate::par::consume_interaction_request(&state, &request_uri)
            .await
            .unwrap();
        assert_eq!(consumed.client_id, "demo-web");

        drop(state);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn logout_hint_must_match_subject_and_public_session_id() {
        let (state, path) = test_app_state().await;
        let user = insert_refresh_test_user(&state, "logout-hint").await;
        let (session, _cookie_value) = state
            .db
            .insert_session(&user.id, 600, crate::db::SessionMetadata::default())
            .await
            .unwrap();
        let current = auth::CurrentUser {
            user: user.clone(),
            session_id: session.id.clone(),
            session_kind: auth::AccountSessionKind::Standard,
        };
        let client = state
            .db
            .find_client_by_client_id("demo-web")
            .await
            .unwrap()
            .unwrap();
        let headers = HeaderMap::new();
        let issuer = state.effective_issuer(&headers).await.unwrap();
        let subject_identifier = subject::subject_for_client(&issuer, &user, &client).unwrap();
        let sign_hint = |subject_identifier: &str, sid: Option<&str>| {
            let mut extra_claims = serde_json::Map::new();
            if let Some(sid) = sid {
                extra_claims.insert(
                    "sid".to_string(),
                    serde_json::Value::String(sid.to_string()),
                );
            }
            state
                .jwt
                .sign_id_token_with_subject_and_claims(
                    &issuer,
                    TokenSubject {
                        user: &user,
                        client_id: &client.client_id,
                        audience: None,
                        scope: "openid",
                        nonce: None,
                        auth_time: Some(session.created_at),
                    },
                    subject_identifier,
                    600,
                    extra_claims,
                )
                .unwrap()
        };
        let request_for = |id_token_hint: String| LogoutRequest {
            _csrf: None,
            id_token_hint: Some(id_token_hint),
            logout_hint: None,
            client_id: Some(client.client_id.clone()),
            post_logout_redirect_uri: None,
            state: None,
            ui_locales: None,
        };

        let public_sid = util::session_public_id(&session.id);
        assert!(
            logout_hint_authorizes_current_session(
                &state,
                &headers,
                &current,
                &request_for(sign_hint(&subject_identifier, Some(&public_sid))),
            )
            .await
            .unwrap()
        );
        assert!(
            logout_hint_authorizes_current_session(
                &state,
                &headers,
                &current,
                &request_for(sign_hint(&subject_identifier, None)),
            )
            .await
            .unwrap()
        );
        assert!(
            !logout_hint_authorizes_current_session(
                &state,
                &headers,
                &current,
                &request_for(sign_hint(&subject_identifier, Some("sid.wrong"))),
            )
            .await
            .unwrap()
        );
        assert!(
            !logout_hint_authorizes_current_session(
                &state,
                &headers,
                &current,
                &request_for(sign_hint("different-subject", Some(&public_sid))),
            )
            .await
            .unwrap()
        );
        assert!(
            !logout_hint_authorizes_current_session(
                &state,
                &headers,
                &current,
                &request_for("not-a-token".to_string()),
            )
            .await
            .unwrap()
        );

        drop(state);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn untrusted_logout_get_requires_confirmation_without_deleting_session() {
        let (state, path) = test_app_state().await;
        let user = insert_refresh_test_user(&state, "logout-confirmation").await;
        let (session, cookie_value) = state
            .db
            .insert_session(&user.id, 600, crate::db::SessionMetadata::default())
            .await
            .unwrap();
        let jar = CookieJar::new().add(auth::session_cookie(&state, cookie_value, 600));
        let response = logout_get(
            State(state.clone()),
            jar.clone(),
            HeaderMap::new(),
            Query(LogoutRequest {
                _csrf: None,
                id_token_hint: Some("not-a-token".to_string()),
                logout_hint: None,
                client_id: Some("demo-web".to_string()),
                post_logout_redirect_uri: Some("http://localhost:3000/".to_string()),
                state: Some("opaque-state".to_string()),
                ui_locales: None,
            }),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(state.db.find_session(&session.id).await.unwrap().is_some());

        let client_only_response = logout_get(
            State(state.clone()),
            jar.clone(),
            HeaderMap::new(),
            Query(LogoutRequest {
                _csrf: None,
                id_token_hint: None,
                logout_hint: None,
                client_id: Some("demo-web".to_string()),
                post_logout_redirect_uri: Some("http://localhost:3000/".to_string()),
                state: Some("opaque-state".to_string()),
                ui_locales: None,
            }),
        )
        .await
        .unwrap();
        assert_eq!(client_only_response.status(), StatusCode::OK);
        assert!(state.db.find_session(&session.id).await.unwrap().is_some());

        let result = logout_post(
            State(state.clone()),
            jar,
            HeaderMap::new(),
            Form(LogoutRequest {
                _csrf: None,
                id_token_hint: Some("not-a-token".to_string()),
                logout_hint: None,
                client_id: Some("demo-web".to_string()),
                post_logout_redirect_uri: Some("http://localhost:3000/".to_string()),
                state: Some("opaque-state".to_string()),
                ui_locales: None,
            }),
        )
        .await;
        assert!(matches!(result, Err(AppError::Forbidden)));
        assert!(state.db.find_session(&session.id).await.unwrap().is_some());

        drop(state);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn account_switch_authorize_get_preserves_existing_session() {
        let (state, path) = test_app_state().await;
        let user = insert_refresh_test_user(&state, "account-switch").await;
        let (session, cookie_value) = state
            .db
            .insert_session(&user.id, 600, crate::db::SessionMetadata::default())
            .await
            .unwrap();
        let jar = CookieJar::new().add(auth::session_cookie(&state, cookie_value, 600));
        let response = authorize(
            State(state.clone()),
            jar,
            HeaderMap::new(),
            ConnectInfo("127.0.0.1:12345".parse().unwrap()),
            Query(AuthorizeRequest {
                interaction_request: None,
                request: None,
                request_uri: None,
                response_type: Some("code".to_string()),
                client_id: Some("demo-web".to_string()),
                redirect_uri: Some("http://localhost:3000/callback".to_string()),
                scope: Some("openid profile".to_string()),
                resource: None,
                authorization_details: None,
                login_hint: Some("someone-else@example.com".to_string()),
                prompt: None,
                max_age: None,
                acr_values: None,
                claims: None,
                state: Some("opaque-state".to_string()),
                nonce: Some("opaque-nonce".to_string()),
                code_challenge: None,
                code_challenge_method: None,
                response_mode: None,
            }),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert!(state.db.find_session(&session.id).await.unwrap().is_some());

        drop(state);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn remembered_account_without_primary_cookie_opens_incomplete_account_chooser() {
        let (state, path) = test_app_state().await;
        let user = insert_refresh_test_user(&state, "remembered-account").await;
        let full_jar = auth::issue_session(
            &state,
            CookieJar::new(),
            &HeaderMap::new(),
            None,
            &user,
            "password",
        )
        .await
        .unwrap();
        let current = auth::require_current_user(&state, &full_jar).await.unwrap();
        let context_cookie = full_jar
            .get(&auth::browser_context_cookie_name(&state))
            .unwrap()
            .clone();
        let context_only_jar = CookieJar::new().add(context_cookie);

        let response = authorize(
            State(state.clone()),
            context_only_jar.clone(),
            HeaderMap::new(),
            ConnectInfo("127.0.0.1:12345".parse().unwrap()),
            Query(test_authorize_query(None, None)),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = redirect_url(&response);
        assert_eq!(query_value(&location, "auth"), "select_account");
        let return_to = query_value(&location, "return_to");
        let interaction_request =
            strict_interaction_request_from_return_to(Some(&return_to)).unwrap();
        let stored = crate::par::peek_interaction_request(&state, &interaction_request)
            .await
            .unwrap()
            .unwrap();
        assert!(stored.account_selection_required);
        assert!(!stored.account_selection_prompted);
        assert!(!stored.reauthentication_required);
        assert_eq!(stored.selected_session_id, None);
        assert_eq!(stored.selected_user_id, None);
        assert!(
            response
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .all(|value| !value
                    .to_str()
                    .unwrap()
                    .starts_with(&format!("{}=", state.settings.security.cookie_name)))
        );
        assert!(
            state
                .db
                .find_session(&current.session_id)
                .await
                .unwrap()
                .is_some()
        );

        let prompt_none_response = authorize(
            State(state.clone()),
            context_only_jar,
            HeaderMap::new(),
            ConnectInfo("127.0.0.1:12346".parse().unwrap()),
            Query(test_authorize_query(Some("none"), None)),
        )
        .await
        .unwrap();
        let prompt_none_location = redirect_url(&prompt_none_response);
        assert_eq!(
            query_value(&prompt_none_location, "error"),
            "login_required"
        );
        assert!(
            prompt_none_location
                .query_pairs()
                .all(|(key, value)| key != "auth" || value != "select_account")
        );

        let explicit_selection_response = authorize(
            State(state.clone()),
            CookieJar::new(),
            HeaderMap::new(),
            ConnectInfo("127.0.0.1:12347".parse().unwrap()),
            Query(test_authorize_query(Some("select_account"), None)),
        )
        .await
        .unwrap();
        assert_eq!(
            query_value(&redirect_url(&explicit_selection_response), "auth"),
            "select_account"
        );

        drop(state);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn login_prompt_continuation_requires_one_time_session_proof() {
        let (state, path) = test_app_state().await;
        let user = insert_refresh_test_user(&state, "login-proof").await;
        let (_session, cookie_value) = state
            .db
            .insert_session(
                &user.id,
                600,
                crate::db::SessionMetadata {
                    login_method: Some("password".to_string()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        let initial = authorize(
            State(state.clone()),
            CookieJar::new(),
            HeaderMap::new(),
            ConnectInfo("127.0.0.1:12345".parse().unwrap()),
            Query(test_authorize_query(Some("login"), None)),
        )
        .await
        .unwrap();
        let initial_location = redirect_url(&initial);
        assert_eq!(query_value(&initial_location, "auth"), "login");
        assert!(!query_value(&initial_location, "account_flow").is_empty());
        let return_to = query_value(&initial_location, "return_to");
        let interaction_request =
            strict_interaction_request_from_return_to(Some(&return_to)).unwrap();
        let pending = crate::par::peek_interaction_request(&state, &interaction_request)
            .await
            .unwrap()
            .unwrap();
        assert!(pending.reauthentication_required);
        assert_eq!(pending.selected_session_id, None);

        let existing_session_jar = CookieJar::new().add(auth::session_cookie(
            &state,
            cookie_value,
            state.settings.security.session_ttl_seconds,
        ));
        let bypass_attempt = authorize(
            State(state.clone()),
            existing_session_jar,
            HeaderMap::new(),
            ConnectInfo("127.0.0.1:12346".parse().unwrap()),
            Query(interaction_authorize_query(&interaction_request)),
        )
        .await
        .unwrap();
        let bypass_location = redirect_url(&bypass_attempt);
        assert_eq!(query_value(&bypass_location, "auth"), "login");
        assert!(!query_value(&bypass_location, "account_flow").is_empty());
        assert_ne!(bypass_location.host_str(), Some("localhost"));

        drop(state);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn selected_account_reauthentication_binds_new_session_and_satisfies_max_age() {
        let (state, path) = test_app_state().await;
        let user = insert_refresh_test_user(&state, "selected-reauth").await;
        let jar = auth::issue_session(
            &state,
            CookieJar::new(),
            &HeaderMap::new(),
            None,
            &user,
            "password",
        )
        .await
        .unwrap();
        let original = auth::require_current_user(&state, &jar).await.unwrap();
        let context_id = auth::browser_context_id_from_jar(&state, &jar).unwrap();

        let mut request = test_authorize_request(Some("login select_account"), Some(300));
        request.client_id = "demo-web".to_string();
        request.redirect_uri = "http://localhost:3000/callback".to_string();
        let selection_request = account_selection_prompted_request(&request);
        let selection_handle = crate::par::store_interaction_authorization_request(
            &state,
            &selection_request.client_id,
            &selection_request,
        )
        .await
        .unwrap();
        let selection_return_to = format!(
            "/oauth2/authorize?interaction_request={}",
            url_encode(&selection_handle)
        );
        let continuation =
            complete_browser_account_selection(&state, &selection_return_to, &original.session_id)
                .await
                .unwrap();
        assert!(continuation.reauthentication_required);
        let continuation_handle =
            strict_interaction_request_from_return_to(Some(&continuation.continue_to)).unwrap();
        let pending = crate::par::peek_interaction_request(&state, &continuation_handle)
            .await
            .unwrap()
            .unwrap();
        assert!(pending.account_selection_prompted);
        assert!(!pending.account_selection_required);
        assert!(pending.reauthentication_required);
        assert_eq!(pending.selected_user_id.as_deref(), Some(user.id.as_str()));
        assert_eq!(pending.selected_session_id, None);
        assert_eq!(pending.prompt.as_deref(), Some("login"));
        assert_eq!(pending.max_age, Some(300));

        let account_flow = format!("alf1.{}", util::random_token(24));
        state
            .db
            .insert_account_login_flow(
                &util::token_hash(&account_flow),
                &context_id,
                &continuation.continue_to,
                Some(&user.id),
                600,
            )
            .await
            .unwrap();
        let reauthenticated_jar = auth::issue_session_with_login_event(
            &state,
            jar,
            &HeaderMap::new(),
            None,
            &user,
            "password",
            auth::LoginEventContext {
                account_flow: Some(account_flow),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let reauthenticated = auth::require_current_user(&state, &reauthenticated_jar)
            .await
            .unwrap();
        assert_ne!(reauthenticated.session_id, original.session_id);
        assert!(
            state
                .db
                .find_session(&original.session_id)
                .await
                .unwrap()
                .is_none()
        );
        let completed = crate::par::peek_interaction_request(&state, &continuation_handle)
            .await
            .unwrap()
            .unwrap();
        assert!(!completed.reauthentication_required);
        assert_eq!(
            completed.selected_session_id.as_deref(),
            Some(reauthenticated.session_id.as_str())
        );
        assert_eq!(
            completed.selected_user_id.as_deref(),
            Some(user.id.as_str())
        );
        assert_eq!(completed.prompt.as_deref(), Some("login"));
        assert_eq!(completed.max_age, Some(300));
        let session = state
            .db
            .find_session(&reauthenticated.session_id)
            .await
            .unwrap()
            .unwrap();
        assert!(session_binding_satisfies_reauthentication(
            &completed, &session
        ));

        let response = authorize(
            State(state.clone()),
            reauthenticated_jar,
            HeaderMap::new(),
            ConnectInfo("127.0.0.1:12347".parse().unwrap()),
            Query(interaction_authorize_query(&continuation_handle)),
        )
        .await
        .unwrap();
        if response.status() == StatusCode::SEE_OTHER {
            let location = redirect_url(&response);
            assert_ne!(
                location
                    .query_pairs()
                    .find(|(key, _)| key == "auth")
                    .map(|(_, value)| value.into_owned())
                    .as_deref(),
                Some("login")
            );
            assert_ne!(
                location
                    .query_pairs()
                    .find(|(key, _)| key == "auth")
                    .map(|(_, value)| value.into_owned())
                    .as_deref(),
                Some("select_account")
            );
        } else {
            assert_eq!(response.status(), StatusCode::OK);
        }

        drop(state);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn max_age_zero_selected_account_always_requires_bound_reauthentication() {
        let (state, path) = test_app_state().await;
        let user = insert_refresh_test_user(&state, "max-age-zero-selection").await;
        let jar = auth::issue_session(
            &state,
            CookieJar::new(),
            &HeaderMap::new(),
            None,
            &user,
            "password",
        )
        .await
        .unwrap();
        let current = auth::require_current_user(&state, &jar).await.unwrap();
        let mut request = test_authorize_request(Some("select_account"), Some(0));
        request.client_id = "demo-web".to_string();
        request.redirect_uri = "http://localhost:3000/callback".to_string();
        let request = account_selection_prompted_request(&request);
        let selection_handle = crate::par::store_interaction_authorization_request(
            &state,
            &request.client_id,
            &request,
        )
        .await
        .unwrap();
        let selection_return_to = format!(
            "/oauth2/authorize?interaction_request={}",
            url_encode(&selection_handle)
        );

        let continuation =
            complete_browser_account_selection(&state, &selection_return_to, &current.session_id)
                .await
                .unwrap();
        assert!(continuation.reauthentication_required);
        let continuation_handle =
            strict_interaction_request_from_return_to(Some(&continuation.continue_to)).unwrap();
        let pending = crate::par::peek_interaction_request(&state, &continuation_handle)
            .await
            .unwrap()
            .unwrap();
        assert!(pending.reauthentication_required);
        assert_eq!(pending.max_age, Some(0));
        assert_eq!(pending.selected_user_id.as_deref(), Some(user.id.as_str()));
        assert_eq!(pending.selected_session_id, None);

        drop(state);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn expired_selected_session_is_rejected_without_consuming_selection() {
        let (state, path) = test_app_state().await;
        let user = insert_refresh_test_user(&state, "expired-selection").await;
        let (expired_session, _) = state
            .db
            .insert_session(
                &user.id,
                -1,
                crate::db::SessionMetadata {
                    login_method: Some("password".to_string()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let mut request = test_authorize_request(Some("select_account"), None);
        request.client_id = "demo-web".to_string();
        request.redirect_uri = "http://localhost:3000/callback".to_string();
        let request = account_selection_prompted_request(&request);
        let interaction_request = crate::par::store_interaction_authorization_request(
            &state,
            &request.client_id,
            &request,
        )
        .await
        .unwrap();
        let return_to = format!(
            "/oauth2/authorize?interaction_request={}",
            url_encode(&interaction_request)
        );

        assert!(
            complete_browser_account_selection(&state, &return_to, &expired_session.id)
                .await
                .is_err()
        );
        assert!(
            crate::par::peek_interaction_request(&state, &interaction_request)
                .await
                .unwrap()
                .is_some()
        );

        drop(state);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn completed_account_binding_cannot_be_reselected_from_another_context_or_cookie() {
        let (state, path) = test_app_state().await;
        let alice = insert_refresh_test_user(&state, "binding-alice").await;
        let bob = insert_refresh_test_user(&state, "binding-bob").await;
        let alice_jar = auth::issue_session(
            &state,
            CookieJar::new(),
            &HeaderMap::new(),
            None,
            &alice,
            "password",
        )
        .await
        .unwrap();
        let alice_current = auth::require_current_user(&state, &alice_jar)
            .await
            .unwrap();
        let bob_jar = auth::issue_session(
            &state,
            CookieJar::new(),
            &HeaderMap::new(),
            None,
            &bob,
            "password",
        )
        .await
        .unwrap();
        let bob_current = auth::require_current_user(&state, &bob_jar).await.unwrap();
        let bob_context_cookie = bob_jar
            .get(&auth::browser_context_cookie_name(&state))
            .unwrap()
            .clone();

        let wrong_cookie_handle =
            completed_selection_interaction(&state, &alice_current.session_id).await;
        let wrong_cookie_response = authorize(
            State(state.clone()),
            bob_jar.clone(),
            HeaderMap::new(),
            ConnectInfo("127.0.0.1:12345".parse().unwrap()),
            Query(interaction_authorize_query(&wrong_cookie_handle)),
        )
        .await
        .unwrap();
        let wrong_cookie_location = redirect_url(&wrong_cookie_response);
        assert_eq!(query_value(&wrong_cookie_location, "auth"), "login");
        assert!(
            wrong_cookie_location
                .query_pairs()
                .all(|(key, value)| key != "auth" || value != "select_account")
        );
        let account_flow = query_value(&wrong_cookie_location, "account_flow");
        assert!(
            auth::issue_session_with_login_event(
                &state,
                bob_jar,
                &HeaderMap::new(),
                None,
                &bob,
                "password",
                auth::LoginEventContext {
                    account_flow: Some(account_flow),
                    ..Default::default()
                },
            )
            .await
            .is_err()
        );
        assert!(
            state
                .db
                .find_session(&bob_current.session_id)
                .await
                .unwrap()
                .is_some()
        );

        let cross_context_handle =
            completed_selection_interaction(&state, &alice_current.session_id).await;
        let context_only_jar = CookieJar::new().add(bob_context_cookie);
        let cross_context_response = authorize(
            State(state.clone()),
            context_only_jar,
            HeaderMap::new(),
            ConnectInfo("127.0.0.1:12346".parse().unwrap()),
            Query(interaction_authorize_query(&cross_context_handle)),
        )
        .await
        .unwrap();
        let cross_context_location = redirect_url(&cross_context_response);
        assert_eq!(query_value(&cross_context_location, "auth"), "login");
        assert!(
            cross_context_location
                .query_pairs()
                .all(|(key, value)| key != "auth" || value != "select_account")
        );
        let pending_return_to = query_value(&cross_context_location, "return_to");
        let pending_handle =
            strict_interaction_request_from_return_to(Some(&pending_return_to)).unwrap();
        let pending = crate::par::peek_interaction_request(&state, &pending_handle)
            .await
            .unwrap()
            .unwrap();
        assert!(pending.reauthentication_required);
        assert_eq!(pending.selected_user_id.as_deref(), Some(alice.id.as_str()));
        assert_eq!(pending.selected_session_id, None);

        drop(state);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn temporary_authorization_code_session_allows_oidc_but_rejects_offline_access() {
        let (state, path) = test_app_state().await;
        let user = insert_refresh_test_user(&state, "temporary-oidc").await;
        let jar = auth::issue_session_with_login_event(
            &state,
            CookieJar::new(),
            &HeaderMap::new(),
            None,
            &user,
            "authorization_code",
            auth::LoginEventContext {
                session_ttl_seconds: Some(120),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let response = authorize(
            State(state.clone()),
            jar.clone(),
            HeaderMap::new(),
            ConnectInfo("127.0.0.1:12345".parse().unwrap()),
            Query(test_authorize_query(None, None)),
        )
        .await
        .unwrap();
        if response.status() == StatusCode::SEE_OTHER {
            let location = redirect_url(&response);
            assert!(
                location
                    .query_pairs()
                    .all(|(key, value)| { key != "error" || value != "access_denied" })
            );
        } else {
            assert_eq!(response.status(), StatusCode::OK);
        }

        let mut offline_query = test_authorize_query(None, None);
        offline_query.scope = Some("openid offline_access".to_string());
        let offline_response = authorize(
            State(state.clone()),
            jar,
            HeaderMap::new(),
            ConnectInfo("127.0.0.1:12346".parse().unwrap()),
            Query(offline_query),
        )
        .await
        .unwrap();
        assert_eq!(
            query_value(&redirect_url(&offline_response), "error"),
            "invalid_scope"
        );

        drop(state);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn trial_enrollment_session_only_authorizes_its_immutable_client_allowlist() {
        let (state, path) = test_app_state().await;
        let organization = state
            .db
            .insert_organization(crate::db::NewOrganization {
                slug: "trial-oidc".to_string(),
                name: "Trial OIDC".to_string(),
                kind: crate::organizations::ORGANIZATION_KIND_TENANT.to_string(),
                description: None,
                allowed_email_domains: vec!["example.com".to_string()],
                is_active: true,
            })
            .await
            .unwrap();
        let blocked_client = insert_test_oidc_client(
            &state,
            "trial-blocked",
            "http://localhost:4100/callback",
            "",
        )
        .await;
        let (invitation, code) = state
            .db
            .insert_invitation(crate::db::NewInvitation {
                code_type: crate::db::AuthorizationCodeType::Login,
                login_code_level: crate::db::LoginCodeLevel::TrialEnrollment,
                allowed_client_ids: vec!["demo-web".to_string()],
                organization_id: Some(organization.id.clone()),
                organization_role: Some(crate::organizations::ROLE_MEMBER.to_string()),
                description: None,
                authorized_email: None,
                authorized_username: None,
                authorized_user_id: None,
                authorized_display_name: None,
                expires_at: Some(util::now_ts() + 600),
                max_uses: Some(1),
                is_active: true,
                created_by: None,
            })
            .await
            .unwrap();
        let enrollment = state
            .db
            .redeem_trial_enrollment_code_for_new_user(
                &code,
                crate::db::NewTrialEnrollmentUser {
                    email: "trial-oidc@example.com".to_string(),
                    username: "trial-oidc".to_string(),
                    display_name: None,
                    password_hash: "test-hash".to_string(),
                },
            )
            .await
            .unwrap();
        let jar = auth::issue_session_with_login_event(
            &state,
            CookieJar::new(),
            &HeaderMap::new(),
            None,
            &enrollment.user,
            "trial_enrollment",
            auth::LoginEventContext {
                session_ttl_seconds: Some(300),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let allowed_response = authorize(
            State(state.clone()),
            jar.clone(),
            HeaderMap::new(),
            ConnectInfo("127.0.0.1:12345".parse().unwrap()),
            Query(test_authorize_query(None, None)),
        )
        .await
        .unwrap();
        if allowed_response.status().is_redirection() {
            assert!(
                redirect_url(&allowed_response)
                    .query_pairs()
                    .all(|(key, value)| key != "error" || value != "access_denied")
            );
        } else {
            assert_ne!(allowed_response.status(), StatusCode::FORBIDDEN);
        }

        let mut blocked_query = test_authorize_query(None, None);
        blocked_query.client_id = Some(blocked_client.client_id.clone());
        blocked_query.redirect_uri = Some("http://localhost:4100/callback".to_string());
        let blocked_response = authorize(
            State(state.clone()),
            jar.clone(),
            HeaderMap::new(),
            ConnectInfo("127.0.0.1:12346".parse().unwrap()),
            Query(blocked_query),
        )
        .await
        .unwrap();
        assert_eq!(
            query_value(&redirect_url(&blocked_response), "error"),
            "access_denied"
        );

        let mut offline_query = test_authorize_query(None, None);
        offline_query.scope = Some("openid offline_access".to_string());
        let offline_response = authorize(
            State(state.clone()),
            jar.clone(),
            HeaderMap::new(),
            ConnectInfo("127.0.0.1:12347".parse().unwrap()),
            Query(offline_query),
        )
        .await
        .unwrap();
        assert_eq!(
            query_value(&redirect_url(&offline_response), "error"),
            "invalid_scope"
        );

        state
            .db
            .update_invitation(crate::db::InvitationUpdate {
                id: &invitation.id,
                description: None,
                authorized_email: None,
                authorized_username: None,
                authorized_display_name: None,
                expires_at: Some(util::now_ts() + 600),
                max_uses: Some(1),
                is_active: false,
            })
            .await
            .unwrap();
        assert!(
            auth::current_user_from_cookie(&state, &jar)
                .await
                .unwrap()
                .is_none()
        );

        drop(state);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn admin_universal_grant_precedes_primary_session_and_has_one_winner() {
        let (state, path) = test_app_state().await;
        let primary_user = insert_refresh_test_user(&state, "universal-primary").await;
        let target_user = insert_refresh_test_user(&state, "universal-target").await;
        let (primary_session, primary_cookie) = state
            .db
            .insert_session(&primary_user.id, 600, crate::db::SessionMetadata::default())
            .await
            .unwrap();

        let mut request = test_authorize_request(None, None);
        request.client_id = "demo-web".to_string();
        request.redirect_uri = "http://localhost:3000/callback".to_string();
        request.scope = Some("openid profile".to_string());
        let interaction_request = crate::par::store_interaction_authorization_request(
            &state,
            &request.client_id,
            &request,
        )
        .await
        .unwrap();
        let (_invitation, raw_code) = state
            .db
            .insert_invitation(crate::db::NewInvitation {
                code_type: crate::db::AuthorizationCodeType::Login,
                login_code_level: crate::db::LoginCodeLevel::AdminUniversal,
                allowed_client_ids: vec!["demo-web".to_string()],
                organization_id: None,
                organization_role: None,
                description: Some("test universal code".to_string()),
                authorized_email: None,
                authorized_username: None,
                authorized_user_id: None,
                authorized_display_name: None,
                expires_at: Some(util::now_ts() + 600),
                max_uses: Some(1),
                is_active: true,
                created_by: None,
            })
            .await
            .unwrap();
        let (credential_hash, credential_value) = new_oidc_login_grant_credentials();
        let interaction_request_hash = util::token_hash(&interaction_request);
        let redemption = state
            .db
            .redeem_admin_login_code_for_oidc_grant(crate::db::AdminLoginCodeRedemptionInput {
                code: &raw_code,
                user_id: &target_user.id,
                email: &target_user.email,
                trusted_client_id: "demo-web",
                interaction_request_hash: &interaction_request_hash,
                credential_hash: &credential_hash,
                ttl_seconds: OIDC_LOGIN_GRANT_TTL_SECONDS,
            })
            .await
            .unwrap();
        assert_eq!(redemption.user.id, target_user.id);

        let jar = CookieJar::new()
            .add(auth::session_cookie(&state, primary_cookie, 600))
            .add(oidc_login_grant_cookie(&state, credential_value));
        let query = AuthorizeRequest {
            interaction_request: Some(interaction_request),
            request: None,
            request_uri: None,
            response_type: None,
            client_id: None,
            redirect_uri: None,
            scope: None,
            resource: None,
            authorization_details: None,
            login_hint: None,
            prompt: None,
            max_age: None,
            acr_values: None,
            claims: None,
            state: None,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            response_mode: None,
        };
        let first = authorize(
            State(state.clone()),
            jar.clone(),
            HeaderMap::new(),
            ConnectInfo("127.0.0.1:12345".parse().unwrap()),
            Query(query.clone()),
        );
        let second = authorize(
            State(state.clone()),
            jar,
            HeaderMap::new(),
            ConnectInfo("127.0.0.1:12346".parse().unwrap()),
            Query(query),
        );
        let (first, second) = tokio::join!(first, second);

        let mut location = None;
        let mut failures = 0;
        for result in [first, second] {
            match result {
                Ok(response) if response.status() == StatusCode::SEE_OTHER => {
                    assert!(location.is_none(), "only one authorization may succeed");
                    location = Some(
                        response
                            .headers()
                            .get(header::LOCATION)
                            .unwrap()
                            .to_str()
                            .unwrap()
                            .to_string(),
                    );
                }
                Err(_) => failures += 1,
                Ok(response) => panic!("unexpected authorization status: {}", response.status()),
            }
        }
        assert_eq!(failures, 1);
        let location =
            Url::parse(location.as_deref().expect("one redirect should succeed")).unwrap();
        let code = location
            .query_pairs()
            .find_map(|(key, value)| (key == "code").then(|| value.into_owned()))
            .expect("authorization redirect should contain a code");
        let authorization_code = state.db.consume_authorization_code(&code).await.unwrap();
        assert_eq!(authorization_code.user_id, target_user.id);
        assert_eq!(authorization_code.client_id, "demo-web");
        assert_eq!(authorization_code.session_id, None);
        assert_eq!(authorization_code.acr, assurance::ACR_PASSWORD);
        assert_eq!(
            util::from_json::<Vec<String>>(&authorization_code.amr).unwrap(),
            vec!["authorization_code".to_string()]
        );
        assert!(
            state
                .db
                .find_session(&primary_session.id)
                .await
                .unwrap()
                .is_some(),
            "universal login must preserve the primary browser session"
        );

        drop(state);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn resource_parameter_must_be_absolute_without_fragment() {
        assert_eq!(
            normalize_resource(Some("https://api.example/resource")).unwrap(),
            Some("https://api.example/resource".to_string())
        );
        assert!(normalize_resource(Some("/relative")).is_err());
        assert!(normalize_resource(Some("https://api.example/#frag")).is_err());
    }

    #[test]
    fn client_credentials_use_and_enforce_configured_audience() {
        let mut client = test_client();
        client.audience = "https://memory.example/api".to_string();

        assert_eq!(
            resolve_client_credentials_audience(&client, None, None).unwrap(),
            Some("https://memory.example/api".to_string())
        );
        assert_eq!(
            resolve_client_credentials_audience(
                &client,
                Some("https://other.example/api".to_string()),
                None,
            )
            .unwrap_err()
            .to_string(),
            "oidc error: resource parameter does not match configured client audience"
        );
        assert_eq!(
            resolve_client_credentials_audience(
                &client,
                Some("https://memory.example/api".to_string()),
                None,
            )
            .unwrap(),
            Some("https://memory.example/api".to_string())
        );
    }

    #[test]
    fn token_resource_cannot_change_issued_resource() {
        assert_eq!(
            merge_token_resource(
                Some("https://api.example/one".to_string()),
                Some("https://api.example/one".to_string())
            )
            .unwrap(),
            Some("https://api.example/one".to_string())
        );
        assert!(
            merge_token_resource(
                Some("https://api.example/one".to_string()),
                Some("https://api.example/two".to_string())
            )
            .is_err()
        );
    }

    #[test]
    fn authorization_code_tokens_preserve_login_code_provenance() {
        assert_eq!(
            authorization_code_login_level(Some("sid.recovery"), &["temporary".to_string()]),
            Some(LoginCodeLevel::AccountRecovery)
        );
        assert_eq!(
            authorization_code_login_level(None, &["authorization_code".to_string()]),
            Some(LoginCodeLevel::AdminUniversal)
        );
        assert_eq!(
            authorization_code_login_level(Some("sid.trial"), &["trial_enrollment".to_string()]),
            Some(LoginCodeLevel::TrialEnrollment)
        );
        assert_eq!(
            authorization_code_login_level(Some("sid.normal"), &["pwd".to_string()]),
            None
        );
    }

    #[tokio::test]
    async fn login_code_tokens_are_marked_and_never_receive_refresh_tokens() {
        let (state, path) = test_app_state().await;
        let user = insert_refresh_test_user(&state, "login-code-token").await;
        let client = state
            .db
            .find_client_by_client_id("demo-web")
            .await
            .unwrap()
            .unwrap();
        let issuer = state.settings.oidc.issuer.clone();

        for (suffix, session_id, amr, expected_level) in [
            (
                "recovery",
                Some("sid.recovery".to_string()),
                vec!["temporary".to_string()],
                "account_recovery",
            ),
            (
                "universal",
                None,
                vec!["authorization_code".to_string()],
                "admin_universal",
            ),
            (
                "trial",
                Some("sid.trial".to_string()),
                vec!["trial_enrollment".to_string()],
                "trial_enrollment",
            ),
        ] {
            let code = format!("login-code-token-{suffix}");
            state
                .db
                .insert_authorization_code(NewAuthorizationCode {
                    code: code.clone(),
                    client_id: client.client_id.clone(),
                    user_id: user.id.clone(),
                    application_id: None,
                    authorization_profile_id: None,
                    auth_context_id: None,
                    session_id,
                    redirect_uri: "http://localhost:3000/callback".to_string(),
                    // This inconsistent defense-in-depth fixture proves that
                    // login-code provenance suppresses refresh issuance even
                    // if an old/stale authorization record contains offline.
                    scope: "openid offline_access".to_string(),
                    resource: None,
                    authorization_details: None,
                    nonce: Some(format!("nonce-{suffix}")),
                    code_challenge: None,
                    code_challenge_method: None,
                    auth_time: util::now_ts(),
                    acr: assurance::ACR_PASSWORD.to_string(),
                    amr,
                    expires_at: util::now_ts() + 300,
                })
                .await
                .unwrap();

            let Json(response) = token_from_authorization_code(
                state.clone(),
                client.clone(),
                test_authorization_code_token_request(&code),
                issuer.clone(),
                None,
            )
            .await
            .unwrap();
            assert!(response.refresh_token.is_none());
            let access_claims = state
                .jwt
                .verify_access_token_with_issuers(&response.access_token, &[issuer.as_str()])
                .unwrap();
            assert_eq!(
                access_claims.gpt_sso_login_code_level.as_deref(),
                Some(expected_level)
            );
            let id_token = response
                .id_token
                .expect("authorization code returns ID token");
            let id_claims = state
                .jwt
                .verify_id_token_hint_with_issuers(&id_token, &[issuer.as_str()])
                .unwrap();
            assert_eq!(
                id_claims.gpt_sso_login_code_level.as_deref(),
                Some(expected_level)
            );
        }

        drop(state);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn concurrent_refresh_grant_has_one_winner_and_returns_invalid_grant() {
        let (state, path) = test_app_state().await;
        let user = insert_refresh_test_user(&state, "race").await;
        let refresh_token = "concurrent-refresh-token";
        state
            .db
            .insert_refresh_token(
                "client-a".to_string(),
                RefreshTokenInput {
                    token_hash: util::token_hash(refresh_token),
                    user_id: user.id,
                    scope: "profile".to_string(),
                    resource: None,
                    authorization_details: None,
                    dpop_jkt: None,
                    auth_context_id: None,
                    expires_at: util::now_ts() + 600,
                },
            )
            .await
            .unwrap();

        let client = test_refresh_client();
        let issuer = state.settings.oidc.issuer.clone();
        let (first, second) = tokio::join!(
            token_from_refresh_token(
                state.clone(),
                client.clone(),
                test_refresh_request(refresh_token),
                issuer.clone(),
                None,
            ),
            token_from_refresh_token(
                state.clone(),
                client,
                test_refresh_request(refresh_token),
                issuer,
                None,
            )
        );

        let mut replacement_token = None;
        let mut invalid_grants = 0;
        for result in [first, second] {
            match result {
                Ok(Json(response)) => {
                    assert!(replacement_token.is_none());
                    replacement_token = response.refresh_token;
                }
                Err(AppError::OAuth { error, status, .. }) => {
                    assert_eq!(error, "invalid_grant");
                    assert_eq!(status, StatusCode::BAD_REQUEST);
                    invalid_grants += 1;
                }
                Err(other) => panic!("unexpected refresh error: {other:?}"),
            }
        }
        assert_eq!(invalid_grants, 1);
        let replacement_token = replacement_token.expect("one rotation should succeed");
        assert!(
            state
                .db
                .find_refresh_token(&util::token_hash(&replacement_token))
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            state
                .db
                .find_refresh_token(&util::token_hash(refresh_token))
                .await
                .unwrap()
                .unwrap()
                .revoked_at
                .is_some()
        );

        drop(state);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn failed_dpop_and_resource_validation_do_not_consume_refresh_token() {
        let (state, path) = test_app_state().await;
        let user = insert_refresh_test_user(&state, "validation").await;
        let refresh_token = "validation-refresh-token";
        let refresh_hash = util::token_hash(refresh_token);
        state
            .db
            .insert_refresh_token(
                "client-a".to_string(),
                RefreshTokenInput {
                    token_hash: refresh_hash.clone(),
                    user_id: user.id,
                    scope: "profile".to_string(),
                    resource: Some("https://api.example/one".to_string()),
                    authorization_details: None,
                    dpop_jkt: Some("expected-jkt".to_string()),
                    auth_context_id: None,
                    expires_at: util::now_ts() + 600,
                },
            )
            .await
            .unwrap();

        let client = test_refresh_client();
        let issuer = state.settings.oidc.issuer.clone();
        let dpop_error = token_from_refresh_token(
            state.clone(),
            client.clone(),
            test_refresh_request(refresh_token),
            issuer.clone(),
            Some(DpopBinding {
                jkt: "wrong-jkt".to_string(),
            }),
        )
        .await
        .expect_err("mismatched DPoP key should fail");
        assert!(matches!(
            dpop_error,
            AppError::OAuth { error, .. } if error == "invalid_dpop_proof"
        ));
        assert!(
            state
                .db
                .find_refresh_token(&refresh_hash)
                .await
                .unwrap()
                .unwrap()
                .revoked_at
                .is_none()
        );

        let mut invalid_resource_request = test_refresh_request(refresh_token);
        invalid_resource_request.resource = Some("https://api.example/two".to_string());
        assert!(
            token_from_refresh_token(
                state.clone(),
                client.clone(),
                invalid_resource_request,
                issuer.clone(),
                Some(DpopBinding {
                    jkt: "expected-jkt".to_string(),
                }),
            )
            .await
            .is_err()
        );
        assert!(
            state
                .db
                .find_refresh_token(&refresh_hash)
                .await
                .unwrap()
                .unwrap()
                .revoked_at
                .is_none()
        );

        let mut valid_request = test_refresh_request(refresh_token);
        valid_request.resource = Some("https://api.example/one".to_string());
        let response = token_from_refresh_token(
            state.clone(),
            client,
            valid_request,
            issuer,
            Some(DpopBinding {
                jkt: "expected-jkt".to_string(),
            }),
        )
        .await
        .unwrap();
        assert!(response.0.refresh_token.is_some());

        drop(state);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn client_policy_requires_pushed_authorization_requests() {
        let mut client = test_client();
        client.require_pushed_authorization_requests = 1;
        let mut request = test_authorize_request(None, None);

        assert!(validate_authorize_request_for_client(&client, &request).is_err());
        request.source = AuthorizationRequestSource::PushedAuthorizationRequest;
        assert!(validate_authorize_request_for_client(&client, &request).is_ok());
    }

    #[test]
    fn client_policy_requires_s256_pkce() {
        let mut client = test_client();
        client.require_pkce = 1;
        client.require_s256_pkce = 1;
        let mut request = test_authorize_request(None, None);
        request.code_challenge = Some("c".repeat(43));
        request.code_challenge_method = Some("plain".to_string());

        assert!(validate_authorize_request_for_client(&client, &request).is_err());
        request.code_challenge_method = Some("S256".to_string());
        assert!(validate_authorize_request_for_client(&client, &request).is_ok());
    }

    #[test]
    fn authorization_details_require_allowed_client_types() {
        let mut request = test_authorize_request(None, None);
        request.authorization_details =
            Some(r#"[{"type":"resource_access","actions":["read"]}]"#.to_string());
        let mut client = test_client();

        assert!(validate_authorize_request_for_client(&client, &request).is_err());
        client.authorization_details_types = serde_json::json!(["resource_access"]).to_string();
        assert!(validate_authorize_request_for_client(&client, &request).is_ok());
    }

    fn test_session(created_at: i64) -> SessionRecord {
        SessionRecord {
            id: "session-id".to_string(),
            user_id: "user-id".to_string(),
            csrf_token: "csrf".to_string(),
            ip_address: None,
            user_agent: None,
            login_method: Some("password".to_string()),
            expires_at: created_at + 3600,
            created_at,
        }
    }

    fn test_authorize_request(
        prompt: Option<&str>,
        max_age: Option<i64>,
    ) -> ResolvedAuthorizeRequest {
        ResolvedAuthorizeRequest {
            source: AuthorizationRequestSource::Query,
            response_type: "code".to_string(),
            client_id: "client-a".to_string(),
            redirect_uri: "https://app.example/callback".to_string(),
            scope: Some("openid profile".to_string()),
            resource: None,
            authorization_details: None,
            login_hint: None,
            prompt: prompt.map(str::to_string),
            max_age,
            acr_values: None,
            claims: None,
            state: Some("state-a".to_string()),
            nonce: Some("nonce-a".to_string()),
            code_challenge: None,
            code_challenge_method: None,
            response_mode: None,
            account_selection_prompted: false,
            account_selection_required: false,
            reauthentication_required: false,
            selected_session_id: None,
            selected_user_id: None,
        }
    }

    fn test_authorize_query(prompt: Option<&str>, max_age: Option<i64>) -> AuthorizeRequest {
        AuthorizeRequest {
            interaction_request: None,
            request: None,
            request_uri: None,
            response_type: Some("code".to_string()),
            client_id: Some("demo-web".to_string()),
            redirect_uri: Some("http://localhost:3000/callback".to_string()),
            scope: Some("openid profile".to_string()),
            resource: None,
            authorization_details: None,
            login_hint: None,
            prompt: prompt.map(str::to_string),
            max_age: max_age.map(|value| value.to_string()),
            acr_values: None,
            claims: None,
            state: Some("opaque-state".to_string()),
            nonce: Some("opaque-nonce".to_string()),
            code_challenge: None,
            code_challenge_method: None,
            response_mode: None,
        }
    }

    fn interaction_authorize_query(interaction_request: &str) -> AuthorizeRequest {
        let mut query = test_authorize_query(None, None);
        query.interaction_request = Some(interaction_request.to_string());
        query.response_type = None;
        query.client_id = None;
        query.redirect_uri = None;
        query.scope = None;
        query.state = None;
        query.nonce = None;
        query
    }

    async fn completed_selection_interaction(state: &AppState, session_id: &str) -> String {
        let mut request = test_authorize_request(Some("select_account"), None);
        request.client_id = "demo-web".to_string();
        request.redirect_uri = "http://localhost:3000/callback".to_string();
        let request = account_selection_prompted_request(&request);
        let selection_handle = crate::par::store_interaction_authorization_request(
            state,
            &request.client_id,
            &request,
        )
        .await
        .unwrap();
        let selection_return_to = format!(
            "/oauth2/authorize?interaction_request={}",
            url_encode(&selection_handle)
        );
        let continuation =
            complete_browser_account_selection(state, &selection_return_to, session_id)
                .await
                .unwrap();
        strict_interaction_request_from_return_to(Some(&continuation.continue_to)).unwrap()
    }

    fn test_refresh_request(refresh_token: &str) -> TokenRequest {
        TokenRequest {
            grant_type: "refresh_token".to_string(),
            code: None,
            device_code: None,
            redirect_uri: None,
            client_id: Some("client-a".to_string()),
            client_secret: None,
            client_assertion_type: None,
            client_assertion: None,
            code_verifier: None,
            refresh_token: Some(refresh_token.to_string()),
            scope: None,
            resource: None,
            authorization_details: None,
            subject_token: None,
            subject_token_type: None,
            requested_token_type: None,
            audience: None,
            actor_token: None,
        }
    }

    fn test_authorization_code_token_request(code: &str) -> TokenRequest {
        TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: Some(code.to_string()),
            device_code: None,
            redirect_uri: Some("http://localhost:3000/callback".to_string()),
            client_id: Some("demo-web".to_string()),
            client_secret: None,
            client_assertion_type: None,
            client_assertion: None,
            code_verifier: None,
            refresh_token: None,
            scope: None,
            resource: None,
            authorization_details: None,
            subject_token: None,
            subject_token_type: None,
            requested_token_type: None,
            audience: None,
            actor_token: None,
        }
    }

    fn test_refresh_client() -> ClientRecord {
        let mut client = test_client();
        client.grant_types = serde_json::json!(["refresh_token"]).to_string();
        client
    }

    #[cfg(feature = "sqlite")]
    async fn oidc_http_body_json(response: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn oidc_http_flow_exposes_application_entitlements_and_rechecks_access() {
        let (state, path) = test_app_state().await;
        let user = insert_refresh_test_user(&state, "application-http").await;
        let (_session, cookie_value) = state
            .db
            .insert_session(&user.id, 600, crate::db::SessionMetadata::default())
            .await
            .unwrap();
        let cookie = format!("{}={cookie_value}", state.settings.security.cookie_name);
        let app = routes().with_state(state.clone());

        let discovery = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/.well-known/openid-configuration")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(discovery.status(), StatusCode::OK);
        let discovery_body = oidc_http_body_json(discovery).await;
        assert_eq!(
            discovery_body["authorization_endpoint"],
            "http://localhost:8080/oauth2/authorize"
        );
        assert_eq!(
            discovery_body["token_endpoint"],
            "http://localhost:8080/oauth2/token"
        );
        assert_eq!(
            discovery_body["jwks_uri"],
            "http://localhost:8080/oauth2/jwks"
        );

        let mut query = url::form_urlencoded::Serializer::new(String::new());
        query
            .append_pair("response_type", "code")
            .append_pair("client_id", "demo-web")
            .append_pair("redirect_uri", "http://localhost:3000/callback")
            .append_pair("scope", "openid profile email")
            .append_pair("state", "oidc-state")
            .append_pair("nonce", "oidc-nonce");
        let mut authorize_request = Request::builder()
            .uri(format!("/oauth2/authorize?{}", query.finish()))
            .header(header::COOKIE, cookie)
            .body(Body::empty())
            .unwrap();
        authorize_request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 43000))));
        let authorize_response = app.clone().oneshot(authorize_request).await.unwrap();
        assert_eq!(authorize_response.status(), StatusCode::SEE_OTHER);
        let redirect = redirect_url(&authorize_response);
        assert_eq!(redirect.path(), "/callback");
        assert_eq!(query_value(&redirect, "state"), "oidc-state");
        let code = query_value(&redirect, "code");

        let form = serde_urlencoded::to_string([
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", "http://localhost:3000/callback"),
        ])
        .unwrap();
        let basic = STANDARD.encode("demo-web:demo-secret-change-me");
        let wrong_redirect_form = serde_urlencoded::to_string([
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", "http://localhost:3000/wrong-callback"),
        ])
        .unwrap();
        let wrong_redirect = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth2/token")
                    .header(header::AUTHORIZATION, format!("Basic {basic}"))
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(wrong_redirect_form))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(wrong_redirect.status(), StatusCode::BAD_REQUEST);

        let token_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth2/token")
                    .header(header::AUTHORIZATION, format!("Basic {basic}"))
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(form))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(token_response.status(), StatusCode::OK);
        let token_body = oidc_http_body_json(token_response).await;
        let access_token = token_body["access_token"].as_str().unwrap();
        let claims = state.jwt.verify_access_token(access_token).unwrap();
        assert_eq!(claims.sub, user.id);
        assert_eq!(claims.client_id, "demo-web");
        assert_eq!(claims.nonce, None);

        let userinfo = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/oauth2/userinfo")
                    .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(userinfo.status(), StatusCode::OK);
        let userinfo_body = oidc_http_body_json(userinfo).await;
        assert_eq!(userinfo_body["email"], user.email);

        let application = state
            .db
            .find_application_for_client(
                &state
                    .db
                    .find_client_by_client_id("demo-web")
                    .await
                    .unwrap()
                    .unwrap()
                    .id,
            )
            .await
            .unwrap()
            .unwrap();
        state
            .db
            .update_application(
                &application.id,
                crate::db::NewApplication {
                    organization_id: application.organization_id.clone(),
                    slug: application.slug.clone(),
                    name: application.name.clone(),
                    description: application.description.clone(),
                    access_mode: applications::ACCESS_ALL_SIGNET_USERS.to_string(),
                    registration_mode: applications::REGISTRATION_DISABLED.to_string(),
                    account_selection_mode: application.account_selection_mode.clone(),
                    unique_identity_factors: application.unique_identity_factors().unwrap(),
                    is_active: false,
                },
            )
            .await
            .unwrap();
        let revoked = app
            .oneshot(
                Request::builder()
                    .uri("/oauth2/userinfo")
                    .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(revoked.status(), StatusCode::FORBIDDEN);

        let _ = std::fs::remove_file(path);
    }

    async fn insert_refresh_test_user(state: &AppState, suffix: &str) -> UserRecord {
        state
            .db
            .insert_user(crate::db::NewUser {
                email: format!("refresh-{suffix}@example.com"),
                username: format!("refresh-{suffix}"),
                display_name: None,
                phone: None,
                password_hash: "test-hash".to_string(),
                email_verified_at: Some(util::now_ts()),
                phone_verified_at: None,
                is_admin: false,
                is_active: true,
                archived_at: None,
            })
            .await
            .unwrap()
    }

    async fn insert_test_oidc_client(
        state: &AppState,
        client_id: &str,
        redirect_uri: &str,
        logo_uri: &str,
    ) -> ClientRecord {
        state
            .db
            .insert_client(crate::db::NewClient {
                client_id: client_id.to_string(),
                client_secret_hash: None,
                client_name: client_id.to_string(),
                logo_uri: logo_uri.to_string(),
                organization_id: None,
                redirect_uris: vec![redirect_uri.to_string()],
                post_logout_redirect_uris: Vec::new(),
                scopes: vec![
                    "openid".to_string(),
                    "profile".to_string(),
                    "offline_access".to_string(),
                ],
                audience: String::new(),
                grant_types: vec!["authorization_code".to_string()],
                response_types: vec!["code".to_string()],
                token_endpoint_auth_method: "none".to_string(),
                require_pkce: false,
                require_mfa: false,
                require_pushed_authorization_requests: false,
                require_s256_pkce: false,
                require_confidential_client: false,
                require_dpop: false,
                require_account_selection: false,
                trust_email_verified: false,
                authorization_details_types: Vec::new(),
                subject_type: subject::SUBJECT_TYPE_PUBLIC.to_string(),
                sector_identifier_uri: String::new(),
                jwks_uri: String::new(),
                jwks: String::new(),
                backchannel_logout_uri: String::new(),
                backchannel_logout_session_required: false,
                frontchannel_logout_uri: String::new(),
                frontchannel_logout_session_required: false,
                service_account_enabled: false,
                service_account_permissions: Vec::new(),
                is_active: true,
            })
            .await
            .unwrap()
    }

    async fn test_app_state() -> (AppState, PathBuf) {
        let config_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../config/default.toml");
        let raw = std::fs::read_to_string(config_path).unwrap();
        let mut settings: crate::Settings = toml::from_str(&raw).unwrap();
        // The production profile now requires explicit consent before a
        // delegated scope is granted. These fixture-based HTTP tests exercise
        // the post-login protocol path and historically assume the browser
        // consent page is skipped; consent-specific behavior is covered by
        // dedicated tests below.
        settings.oidc.skip_consent = true;
        let path = std::env::temp_dir().join(format!(
            "gpt-sso-oidc-test-{}.sqlite3",
            uuid::Uuid::new_v4()
        ));
        settings.database.kind = crate::config::DatabaseKind::Sqlite;
        settings.database.url = path.to_string_lossy().to_string();
        settings.database.run_migrations = true;
        settings.bootstrap.admin.create_on_startup = false;
        // Keep the production profile free of authentication clients while
        // preserving the historical OIDC HTTP fixture used by this module.
        // This client exists only in the per-test database and is still
        // reconciled through the normal bootstrap path, including its
        // application boundary.
        settings
            .bootstrap
            .clients
            .push(crate::config::BootstrapClient {
                client_id: "demo-web".to_string(),
                client_name: "Demo Web App".to_string(),
                logo_uri: String::new(),
                client_secret: "demo-secret-change-me".to_string(),
                client_secret_env: None,
                redirect_uris: vec![
                    "http://localhost:3000/callback".to_string(),
                    "http://localhost:5173/callback".to_string(),
                ],
                post_logout_redirect_uris: vec!["http://localhost:3000/".to_string()],
                scopes: vec![
                    "openid".to_string(),
                    "profile".to_string(),
                    "email".to_string(),
                    "offline_access".to_string(),
                ],
                grant_types: vec![
                    "authorization_code".to_string(),
                    "refresh_token".to_string(),
                    "urn:ietf:params:oauth:grant-type:device_code".to_string(),
                    "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
                ],
                response_types: vec!["code".to_string()],
                token_endpoint_auth_method: "client_secret_basic".to_string(),
                require_pkce: false,
                require_confidential_client: false,
                service_account_enabled: false,
                service_account_permissions: Vec::new(),
                audience: None,
                rotate_secret: false,
            });
        let db = crate::db::Db::connect(&settings).unwrap();
        db.migrate().await.unwrap();
        db.seed(&settings).await.unwrap();
        let jwt = crate::jwt::JwtManager::new(&settings).unwrap();
        (AppState { settings, db, jwt }, path)
    }

    fn test_client() -> ClientRecord {
        ClientRecord {
            id: "client-db-id".to_string(),
            client_id: "client-a".to_string(),
            client_secret_hash: None,
            client_name: "Client A".to_string(),
            logo_uri: String::new(),
            organization_id: None,
            redirect_uris: serde_json::json!(["https://app.example/callback"]).to_string(),
            post_logout_redirect_uris: "[]".to_string(),
            scopes: serde_json::json!(["openid", "profile"]).to_string(),
            audience: String::new(),
            grant_types: serde_json::json!(["authorization_code"]).to_string(),
            response_types: serde_json::json!(["code"]).to_string(),
            token_endpoint_auth_method: "none".to_string(),
            require_pkce: 0,
            require_mfa: 0,
            require_pushed_authorization_requests: 0,
            require_s256_pkce: 0,
            require_confidential_client: 0,
            require_dpop: 0,
            require_account_selection: 0,
            trust_email_verified: 0,
            authorization_details_types: "[]".to_string(),
            subject_type: subject::SUBJECT_TYPE_PUBLIC.to_string(),
            sector_identifier_uri: String::new(),
            jwks_uri: String::new(),
            jwks: String::new(),
            backchannel_logout_uri: String::new(),
            backchannel_logout_session_required: 0,
            frontchannel_logout_uri: String::new(),
            frontchannel_logout_session_required: 0,
            service_account_enabled: 0,
            service_account_permissions: "[]".to_string(),
            is_active: 1,
            created_at: 1,
            updated_at: 1,
        }
    }
}
