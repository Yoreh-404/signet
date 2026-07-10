use crate::{
    AppState,
    assurance::{self, AssurancePolicy, SessionAuthenticationAssurance},
    audit::{self, AuditOutcome, AuditSink},
    auth::{self, AccountCapabilities},
    auth_flow, authorization_details,
    claim_mapper::{self, ClaimContext, ClaimOutputTarget},
    client_assertion,
    client_policy::{
        AuthorizationRequestSecurityView, AuthorizationRequestSource, ClientSecurityPolicy,
        DefaultClientSecurityPolicy,
    },
    consent::{self, OidcConsentPolicy},
    db::{ClientRecord, NewAuthorizationCode, SessionRecord, UserRecord},
    directory,
    dpop::{self, DpopBinding},
    error::{AppError, AppResult},
    jwt::TokenSubject,
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
use axum_extra::extract::cookie::CookieJar;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use url::Url;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
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
    none: bool,
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
            || max_age.is_some_and(|max_age| now.saturating_sub(self.created_at) > max_age)
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
        })
    }
}

async fn resolve_authorize_request(
    state: &AppState,
    headers: &HeaderMap,
    query: AuthorizeRequest,
) -> AppResult<ResolvedAuthorizeRequest> {
    if let Some(interaction_request) = query.interaction_request.as_deref() {
        return crate::par::consume_request_uri(state, interaction_request).await;
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
        let force_login = client_requires_account_selection(&client, &request);
        let return_to = if force_login {
            authorize_return_to_for_account_selection(&state, &request).await?
        } else {
            authorize_return_to_for_interaction(&state, &request, prompt.force_login).await?
        };
        return Ok(Redirect::to(&frontend_login_url(
            &return_to,
            request.login_hint.as_deref(),
            force_login || prompt.force_login,
        ))
        .into_response());
    };
    if !current.can_authorize_oauth_client() {
        let request = resolve_authorize_request(&state, &headers, query).await?;
        let client = validate_authorize_request(&state, &request).await?;
        let prompt = prompt_behavior_for_client(&client, &request)?;
        if prompt.none {
            return redirect_authorization_error(
                &state,
                &headers,
                &request,
                "login_required",
                "archived accounts cannot authorize OIDC clients",
            )
            .await;
        }
        let force_login = client_requires_account_selection(&client, &request);
        let return_to = if force_login {
            authorize_return_to_for_account_selection(&state, &request).await?
        } else {
            authorize_return_to_for_interaction(&state, &request, false).await?
        };
        state.db.delete_session(&current.session_id).await?;
        return Ok((
            jar.add(auth::expired_session_cookie(&state)),
            Redirect::to(&frontend_login_url(
                &return_to,
                request.login_hint.as_deref(),
                true,
            )),
        )
            .into_response());
    }
    let request = resolve_authorize_request(&state, &headers, query).await?;
    let client = validate_authorize_request(&state, &request).await?;
    let prompt = prompt_behavior_for_client(&client, &request)?;
    if login_hint_requires_account_switch(&request, &current.user) {
        tracing::info!(
            client_id = %request.client_id,
            user_id = %current.user.id,
            login_hint = request.login_hint.as_deref().unwrap_or_default(),
            "OIDC login_hint does not match the active browser session; requiring account switch"
        );
        if prompt.none {
            return redirect_authorization_error(
                &state,
                &headers,
                &request,
                "account_selection_required",
                "the active session does not match the requested login_hint",
            )
            .await;
        }
        let return_to = authorize_return_to_for_interaction(&state, &request, true).await?;
        state.db.delete_session(&current.session_id).await?;
        return Ok((
            jar.add(auth::expired_session_cookie(&state)),
            Redirect::to(&frontend_login_url(
                &return_to,
                request.login_hint.as_deref(),
                true,
            )),
        )
            .into_response());
    }
    let session = state
        .db
        .find_session(&current.session_id)
        .await?
        .ok_or(AppError::Unauthorized)?;
    if client_requires_account_selection(&client, &request) {
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
        state.db.delete_session(&current.session_id).await?;
        return Ok((
            jar.add(auth::expired_session_cookie(&state)),
            Redirect::to(&frontend_login_url(
                &return_to,
                request.login_hint.as_deref(),
                true,
            )),
        )
            .into_response());
    }
    if session.needs_reauthentication(prompt, request.max_age, util::now_ts()) {
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
        let return_to = authorize_return_to_for_interaction(&state, &request, true).await?;
        return Ok(Redirect::to(&frontend_login_url(
            &return_to,
            request.login_hint.as_deref(),
            true,
        ))
        .into_response());
    }
    let return_to = authorize_return_to_for_interaction(&state, &request, false).await?;
    let requested_scopes = util::normalize_scopes(
        request.scope.as_deref(),
        &state.settings.oidc.supported_scopes,
    )?;
    validate_requested_scopes(&client, &requested_scopes)?;
    if let Some(response) = enforce_authorization_mfa(
        &state,
        &headers,
        Some(remote_addr),
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
        return Ok(
            consent_page(&state, &request, &client, &current.user, &requested_scopes)
                .await?
                .into_response(),
        );
    }
    issue_authorization_code_redirect(
        &state,
        &headers,
        Some(remote_addr),
        &current.user,
        &session,
        &client,
        request,
        requested_scopes,
    )
    .await
}

async fn authorize_consent(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    Form(payload): Form<ConsentForm>,
) -> AppResult<Response> {
    let current = auth::require_current_user(&state, &jar).await?;
    auth::ensure_account_mutable(&current.user)?;
    let request = if let Some(request_uri) = payload
        .request_uri
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        crate::par::consume_request_uri(&state, request_uri).await?
    } else {
        payload.resolved_request()?
    };
    let client = validate_authorize_request(&state, &request).await?;
    if login_hint_requires_account_switch(&request, &current.user) {
        tracing::info!(
            client_id = %request.client_id,
            user_id = %current.user.id,
            login_hint = request.login_hint.as_deref().unwrap_or_default(),
            "OIDC consent was submitted under a session that no longer matches login_hint"
        );
        let return_to = authorize_return_to_for_interaction(&state, &request, true).await?;
        state.db.delete_session(&current.session_id).await?;
        return Ok((
            jar.add(auth::expired_session_cookie(&state)),
            Redirect::to(&frontend_login_url(
                &return_to,
                request.login_hint.as_deref(),
                true,
            )),
        )
            .into_response());
    }
    let requested_scopes = util::normalize_scopes(
        request.scope.as_deref(),
        &state.settings.oidc.supported_scopes,
    )?;
    validate_requested_scopes(&client, &requested_scopes)?;
    let prompt = prompt_behavior_for_client(&client, &request)?;
    let session = state
        .db
        .find_session(&current.session_id)
        .await?
        .ok_or(AppError::Unauthorized)?;
    if session.needs_reauthentication(prompt, request.max_age, util::now_ts()) {
        let return_to = authorize_return_to_for_interaction(&state, &request, true).await?;
        return Ok(Redirect::to(&frontend_login_url(
            &return_to,
            request.login_hint.as_deref(),
            true,
        ))
        .into_response());
    }
    assert_authorization_mfa_satisfied(
        &state,
        &headers,
        Some(remote_addr),
        &current,
        &client,
        &session,
        &request,
    )
    .await?;
    match payload.action.as_str() {
        "approve" => {
            if payload.remember.is_some() {
                let existing = state
                    .db
                    .find_user_consent(&current.user.id, &client.client_id)
                    .await?;
                let granted_scopes =
                    consent::merged_granted_scopes(existing.as_ref(), &requested_scopes);
                state
                    .db
                    .upsert_user_consent(&current.user.id, &client.client_id, granted_scopes)
                    .await?;
            }
            issue_authorization_code_redirect(
                &state,
                &headers,
                Some(remote_addr),
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
        .find_user_consent(&user.id, &client.client_id)
        .await?;
    Ok(OidcConsentPolicy::new(state.settings.oidc.skip_consent)
        .requires_prompt(existing.as_ref(), requested_scopes))
}

async fn enforce_authorization_mfa(
    state: &AppState,
    headers: &HeaderMap,
    remote_addr: Option<SocketAddr>,
    current: &auth::CurrentUser,
    client: &ClientRecord,
    session: &SessionRecord,
    request: &ResolvedAuthorizeRequest,
    return_to: &str,
    prompt_none: bool,
) -> AppResult<Option<Response>> {
    let user_has_totp = state.db.find_totp_method(&current.user.id).await?.is_some();
    let policy = state.db.security_policy().await?;
    let requested_assurance = request.requested_assurance()?;
    let policy_requires_mfa = policy
        .requires_mfa_for_ip(state.request_ip(headers, remote_addr).await?.as_deref())?
        || assurance::DefaultAssurancePolicy.requires_mfa(&requested_assurance);
    match auth_flow::oidc_authorization_mfa_decision(
        &policy,
        client,
        session,
        user_has_totp,
        policy_requires_mfa,
    )? {
        MfaDecision::Satisfied => Ok(None),
        MfaDecision::Challenge if prompt_none => redirect_authorization_error(
            state,
            headers,
            request,
            "interaction_required",
            "multi-factor authentication is required to complete the authorization request",
        )
        .await
        .map(Some),
        MfaDecision::Challenge => {
            let challenge = state
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
            state,
            headers,
            request,
            "access_denied",
            "MFA is required but the user has not configured TOTP",
        )
        .await
        .map(Some),
    }
}

async fn assert_authorization_mfa_satisfied(
    state: &AppState,
    headers: &HeaderMap,
    remote_addr: Option<SocketAddr>,
    current: &auth::CurrentUser,
    client: &ClientRecord,
    session: &SessionRecord,
    request: &ResolvedAuthorizeRequest,
) -> AppResult<()> {
    let user_has_totp = state.db.find_totp_method(&current.user.id).await?.is_some();
    let policy = state.db.security_policy().await?;
    let requested_assurance = request.requested_assurance()?;
    let policy_requires_mfa = policy
        .requires_mfa_for_ip(state.request_ip(headers, remote_addr).await?.as_deref())?
        || assurance::DefaultAssurancePolicy.requires_mfa(&requested_assurance);
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
    state: &AppState,
    headers: &HeaderMap,
    remote_addr: Option<SocketAddr>,
    user: &UserRecord,
    session: &SessionRecord,
    client: &ClientRecord,
    request: ResolvedAuthorizeRequest,
    requested_scopes: Vec<String>,
) -> AppResult<Response> {
    let code = util::random_token(32);
    let session_assurance = session.authentication_assurance();
    let requested_assurance = request.requested_assurance()?;
    let acr =
        assurance::DefaultAssurancePolicy.select_acr(&session_assurance, &requested_assurance)?;
    assurance::DefaultAssurancePolicy.assert_amr(&session_assurance, &requested_assurance)?;
    let authorization_details = authorization_details::normalize_authorization_details_for_client(
        client,
        request.authorization_details.as_deref(),
    )?;
    state
        .db
        .insert_authorization_code(NewAuthorizationCode {
            code: code.clone(),
            client_id: client.client_id.clone(),
            user_id: user.id.clone(),
            session_id: Some(session.id.clone()),
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
            expires_at: util::now_ts() + state.settings.oidc.authorization_code_ttl_seconds,
        })
        .await?;
    state
        .db
        .record_login_event(
            &user.id,
            state.request_ip(headers, remote_addr).await?,
            util::user_agent(headers),
            "oidc_authorize",
            Some(client.client_id.clone()),
            None,
        )
        .await?;
    let issuer = state.effective_issuer(headers).await?;
    crate::jarm::authorization_success_response(state, &issuer, client, &request, &code)
}

async fn consent_page(
    state: &AppState,
    request: &ResolvedAuthorizeRequest,
    client: &ClientRecord,
    user: &UserRecord,
    requested_scopes: &[String],
) -> AppResult<Html<String>> {
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
    let request_uri = consent_request_uri(state, request).await?;
    let request_uri = html_escape(request_uri.as_deref().unwrap_or_default());
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
        <input type="hidden" name="request_uri" value="{request_uri}" />
        <label><input type="checkbox" name="remember" value="1" checked /> Remember this authorization</label>
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
    authorization_details::normalize_authorization_details_for_client(
        client,
        request.authorization_details.as_deref(),
    )?;
    DefaultClientSecurityPolicy.validate_authorization_request(client, request)?;
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
    let resource = normalize_resource(payload.resource.as_deref())?;
    let authorization_details = authorization_details::normalize_authorization_details_for_client(
        &client,
        payload.authorization_details.as_deref(),
    )?;
    let mut access_claims = serde_json::Map::new();
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
    let record = state.db.consume_authorization_code(&code).await?;
    if record.client_id != client.client_id {
        return Err(AppError::Oidc(
            "authorization code was issued to a different client".to_string(),
        ));
    }
    if let Some(redirect_uri) = payload.redirect_uri {
        if redirect_uri != record.redirect_uri {
            return Err(AppError::Oidc("redirect_uri mismatch".to_string()));
        }
    }
    util::check_pkce(
        record.code_challenge.as_deref(),
        record.code_challenge_method.as_deref(),
        payload.code_verifier.as_deref(),
        client.require_pkce == 1,
    )?;
    issue_tokens_for_user(
        &state,
        &client,
        &record.user_id,
        record.scope,
        merge_token_resource(record.resource, payload.resource)?,
        authorization_details::merge_authorization_details(
            record.authorization_details,
            payload.authorization_details,
            &client,
        )?,
        record.nonce,
        Some(record.auth_time),
        Some(assurance::AuthenticationAssurance {
            acr: record.acr,
            amr: util::from_json(&record.amr)?,
        }),
        record.session_id,
        true,
        &issuer,
        dpop,
    )
    .await
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
        &user_id,
        record.scope,
        merge_token_resource(record.resource, payload.resource)?,
        authorization_details::merge_authorization_details(
            record.authorization_details,
            payload.authorization_details,
            &client,
        )?,
        None,
        record.authorized_at.or(Some(record.created_at)),
        None,
        None,
        true,
        &issuer,
        dpop,
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
        authorization_details: None,
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
        .ok_or_else(|| AppError::Oidc("invalid refresh token".to_string()))?;
    if record.client_id != client.client_id
        || record.revoked_at.is_some()
        || record.expires_at < util::now_ts()
    {
        return Err(AppError::Oidc("invalid refresh token".to_string()));
    }
    state.db.revoke_refresh_token(&hash).await?;
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
    dpop::add_cnf_claim(&mut access_claims, dpop.as_ref());
    authorization_details::insert_claim(&mut access_claims, authorization_details.as_deref())?;
    let access_token = state.jwt.sign_access_token_with_issuer_and_claims(
        &issuer,
        TokenSubject {
            user: &user,
            client_id: &client.client_id,
            audience: resource.as_deref(),
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
    let new_refresh_token = util::random_token(48);
    state
        .db
        .insert_refresh_token(
            util::token_hash(&new_refresh_token),
            client.client_id,
            user.id,
            scope.clone(),
            resource.clone(),
            authorization_details.clone(),
            dpop.as_ref().map(|binding| binding.jkt.clone()),
            util::now_ts() + state.settings.oidc.refresh_token_ttl_seconds,
        )
        .await?;
    Ok(Json(TokenResponse {
        access_token,
        issued_token_type: None,
        token_type: dpop::token_type(dpop.as_ref()),
        expires_in: state.settings.oidc.access_token_ttl_seconds,
        id_token,
        refresh_token: Some(new_refresh_token),
        scope,
        authorization_details: authorization_details::authorization_details_json(
            authorization_details.as_deref(),
        )?,
    }))
}

async fn issue_tokens_for_user(
    state: &AppState,
    client: &ClientRecord,
    user_id: &str,
    scope: String,
    resource: Option<String>,
    authorization_details: Option<String>,
    nonce: Option<String>,
    auth_time: Option<i64>,
    assurance: Option<assurance::AuthenticationAssurance>,
    sid: Option<String>,
    allow_refresh_token: bool,
    issuer: &str,
    dpop: Option<DpopBinding>,
) -> AppResult<Json<TokenResponse>> {
    let user = load_active_user(state, user_id).await?;
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
    dpop::add_cnf_claim(&mut access_claims, dpop.as_ref());
    authorization_details::insert_claim(&mut access_claims, authorization_details.as_deref())?;
    let access_token = state.jwt.sign_access_token_with_issuer_and_claims(
        issuer,
        TokenSubject {
            user: &user,
            client_id: &client.client_id,
            audience: resource.as_deref(),
            scope: &scope,
            nonce: None,
            auth_time,
        },
        state.settings.oidc.access_token_ttl_seconds,
        access_claims,
    )?;
    let mut id_claims =
        mapped_claims_for_user(state, client, &user, &scope, ClaimOutputTarget::IdToken).await?;
    insert_sid_claim(&mut id_claims, sid.as_deref());
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
                util::token_hash(&refresh_token),
                client.client_id.clone(),
                user.id.clone(),
                scope.clone(),
                resource.clone(),
                authorization_details.clone(),
                dpop.as_ref().map(|binding| binding.jkt.clone()),
                util::now_ts() + state.settings.oidc.refresh_token_ttl_seconds,
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
    let claims = state
        .jwt
        .verify_access_token_with_issuers(token, &issuer_refs)?;
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
    let user = load_active_user(&state, &claims.sub).await?;
    let client = state
        .db
        .find_client_by_client_id(&claims.client_id)
        .await?
        .ok_or(AppError::Unauthorized)?;
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
    let _hint = payload.token_type_hint.as_deref();
    let issuers = state.accepted_issuers(&headers).await?;
    let issuer_refs = issuers.iter().map(String::as_str).collect::<Vec<_>>();
    if let Ok(claims) = state
        .jwt
        .verify_access_token_with_issuers(&payload.token, &issuer_refs)
    {
        let mut active = claims.exp > util::now_ts() && claims.client_id == client.client_id;
        if active && claims.sub != claims.client_id {
            active = load_active_user(&state, &claims.sub).await.is_ok();
        }
        if active {
            let cnf = claims
                .cnf
                .map(|claim| serde_json::json!({ "jkt": claim.jkt }));
            return Ok(Json(serde_json::json!({
                "active": true,
                "scope": claims.scope,
                "client_id": claims.client_id,
                "sub": claims.sub,
                "token_type": "Bearer",
                "exp": claims.exp,
                "iat": claims.iat,
                "iss": claims.iss,
                "aud": claims.aud,
                "username": claims.preferred_username,
                "cnf": cnf,
                "authorization_details": claims.authorization_details,
            })));
        }
    }
    let hash = util::token_hash(&payload.token);
    if let Some(record) = state.db.find_refresh_token(&hash).await? {
        if record.client_id == client.client_id
            && record.revoked_at.is_none()
            && record.expires_at > util::now_ts()
        {
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
                "token_type": "refresh_token",
                "exp": record.expires_at,
                "iat": record.created_at,
                "aud": audience,
                "authorization_details": authorization_details,
            })));
        }
    }
    Ok(Json(serde_json::json!({ "active": false })))
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
    if let Some(record) = state.db.find_refresh_token(&hash).await? {
        if record.client_id == client.client_id {
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
    }
    Ok(StatusCode::OK)
}

#[derive(Debug, Deserialize)]
struct LogoutRequest {
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
    logout_with_request(state, jar, headers, query).await
}

async fn logout_post(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Form(payload): Form<LogoutRequest>,
) -> AppResult<Response> {
    logout_with_request(state, jar, headers, payload).await
}

async fn logout_with_request(
    state: AppState,
    jar: CookieJar,
    headers: HeaderMap,
    request: LogoutRequest,
) -> AppResult<Response> {
    let current = auth::current_user_from_cookie(&state, &jar).await?;
    let redirect =
        validated_post_logout_redirect(&state, &headers, current.as_ref(), &request).await?;
    let mut frontchannel_frames = Vec::new();
    if let Some(current) = current.as_ref() {
        frontchannel_frames = match crate::frontchannel_logout::frames_for_user(
            &state,
            &headers,
            &current.user,
            current.session_id.as_str(),
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
            Some(current.session_id.as_str()),
        )
        .await
        {
            tracing::warn!(error = %err, "back-channel logout notification failed");
        }
    }
    let mut next_jar = jar.clone();
    if let Some(cookie) = jar.get(&state.settings.security.cookie_name) {
        state.db.delete_session(cookie.value()).await?;
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
    if let Some(id_token_hint) = request.id_token_hint.as_deref() {
        let issuers = state.accepted_issuers(headers).await?;
        let issuer_refs = issuers.iter().map(String::as_str).collect::<Vec<_>>();
        let Ok(claims) = state
            .jwt
            .verify_id_token_hint_with_issuers(id_token_hint, &issuer_refs)
        else {
            return Ok(None);
        };
        let Some(client) = state.db.find_client_by_client_id(&claims.client_id).await? else {
            return Ok(None);
        };
        if let Some(current) = current {
            let expected_subject =
                subject::subject_for_client(&claims.iss, &current.user, &client)?;
            if expected_subject != claims.sub {
                return Ok(None);
            }
        }
        if let Some(client_id) = request.client_id.as_deref() {
            if client_id != claims.client_id && client_id != claims.aud {
                return Ok(None);
            }
        }
        return Ok(Some(client));
    }

    let Some(client_id) = request.client_id.as_deref() else {
        return Ok(None);
    };
    state.db.find_client_by_client_id(client_id).await
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
        let jar = auth::issue_session_with_login_event(
            &state,
            jar,
            &headers,
            request_ip.clone(),
            &user,
            &format!("oidc_{}", completion.method),
            None,
            None,
        )
        .await?;
        auth::clear_login_failures(&state, &subject).await?;
        return Ok((jar, Redirect::to(&return_to)).into_response());
    }

    let email = payload.email.as_deref().ok_or(AppError::Unauthorized)?;
    let password = payload.password.as_deref().ok_or(AppError::Unauthorized)?;
    let subject = security_policy::normalize_login_subject(email);
    auth::assert_login_entry_allowed(&state, &subject, request_ip.as_deref()).await?;
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
        candidate.is_active == 1
            && candidate.archived_at.is_none()
            && util::verify_password(&candidate.password_hash, password)
    });
    if user.is_none() {
        let directory_login =
            match directory::authenticate_with_configured_directories(&state, &subject, password)
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
    let return_to = redirects::local_return_to(payload.return_to.as_deref());
    let login_context =
        authorization_login_context_from_return_to(&state, &headers, Some(&return_to)).await?;
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
        None,
        external_provider,
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
    {
        if let Some(encoded) = header.strip_prefix("Basic ") {
            let decoded = STANDARD
                .decode(encoded)
                .map_err(|_| AppError::Unauthorized)?;
            let decoded = String::from_utf8(decoded).map_err(|_| AppError::Unauthorized)?;
            let (client_id, client_secret) =
                decoded.split_once(':').ok_or(AppError::Unauthorized)?;
            return Ok(ClientCredentials {
                client_id: url_decode(client_id),
                client_secret: Some(url_decode(client_secret)),
                client_assertion_type: None,
                client_assertion: None,
            });
        }
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
    if user.is_active == 1 && user.archived_at.is_none() {
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
    if let Some(value) = &request.claims {
        if let Ok(encoded) = value.to_authorization_parameter() {
            pairs.push(("claims", encoded));
        }
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

async fn consent_request_uri(
    state: &AppState,
    request: &ResolvedAuthorizeRequest,
) -> AppResult<Option<String>> {
    if request.source == AuthorizationRequestSource::PushedAuthorizationRequest {
        crate::par::store_authorization_request(state, &request.client_id, request)
            .await
            .map(Some)
    } else {
        Ok(None)
    }
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

fn account_selection_prompted_request(
    request: &ResolvedAuthorizeRequest,
) -> ResolvedAuthorizeRequest {
    let mut request = return_to_request(request, true);
    request.account_selection_prompted = true;
    request
}

fn client_requires_account_selection(
    client: &ClientRecord,
    request: &ResolvedAuthorizeRequest,
) -> bool {
    client.require_account_selection == 1 && !request.account_selection_prompted
}

fn prompt_behavior_for_client(
    client: &ClientRecord,
    request: &ResolvedAuthorizeRequest,
) -> AppResult<PromptBehavior> {
    let mut behavior = request.prompt_behavior()?;
    if behavior.none && client_allows_interactive_prompt_none(client) {
        tracing::info!(
            client_id = %client.client_id,
            "treating prompt=none as interactive because the client requires account selection"
        );
        behavior.none = false;
    }
    Ok(behavior)
}

fn client_allows_interactive_prompt_none(client: &ClientRecord) -> bool {
    client.require_account_selection == 1
}

fn login_hint_requires_account_switch(
    request: &ResolvedAuthorizeRequest,
    user: &UserRecord,
) -> bool {
    let Some(hint) = normalized_login_hint_email(request.login_hint.as_deref()) else {
        return false;
    };
    hint != security_policy::normalize_login_subject(&user.email)
}

fn normalized_login_hint_email(login_hint: Option<&str>) -> Option<String> {
    let value = login_hint?.trim();
    if !value.contains('@') {
        return None;
    }
    Some(security_policy::normalize_login_subject(value))
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
            request_requires_mfa: false,
        });
    };
    let Some(query) = authorize_request_from_return_to(return_to)? else {
        return Ok(AuthorizationLoginContext {
            client: None,
            request_requires_mfa: false,
        });
    };
    let request = if let Some(interaction_request) = query.interaction_request.as_deref() {
        let Some(request) = crate::par::peek_request_uri(state, interaction_request).await? else {
            return Ok(AuthorizationLoginContext {
                client: None,
                request_requires_mfa: false,
            });
        };
        request
    } else if let Some(request_uri) = query.request_uri.as_deref() {
        let Some(request) = crate::par::peek_request_uri(state, request_uri).await? else {
            return Ok(AuthorizationLoginContext {
                client: None,
                request_requires_mfa: false,
            });
        };
        request
    } else {
        resolve_authorize_request(state, headers, query).await?
    };
    let client = validate_authorize_request(state, &request).await?;
    let requested_assurance = request.requested_assurance()?;
    Ok(AuthorizationLoginContext {
        client: Some(client),
        request_requires_mfa: assurance::DefaultAssurancePolicy.requires_mfa(&requested_assurance),
    })
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
        .filter(|value| !matches!(*value, "login" | "select_account"))
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
        none: false,
    };
    if values.is_empty() {
        return Ok(behavior);
    }
    for value in &values {
        match *value {
            "consent" => behavior.force_consent = true,
            "login" => behavior.force_login = true,
            "select_account" => behavior.force_login = true,
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
    use std::{collections::HashMap, path::PathBuf, sync::Mutex};

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

    #[test]
    fn prompt_none_is_exclusive() {
        assert!(prompt_behavior(Some("none")).unwrap().none);
        assert!(prompt_behavior(Some("none consent")).is_err());
        assert!(prompt_behavior(Some("none login")).is_err());
    }

    #[test]
    fn account_selection_client_allows_interactive_prompt_none() {
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
        assert!(!behavior.none);
        assert!(!behavior.force_login);
        assert!(!behavior.force_consent);
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
        assert!(behavior.force_login);
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
                force_login: true,
                none: false,
            },
            None,
            100
        ));
        assert!(!session.needs_reauthentication(
            PromptBehavior {
                force_consent: false,
                force_login: false,
                none: false,
            },
            Some(30),
            130
        ));
        assert!(session.needs_reauthentication(
            PromptBehavior {
                force_consent: false,
                force_login: false,
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
        assert_eq!(parsed.get("prompt").map(String::as_str), Some("consent"));
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
    fn account_selection_prompted_request_strips_login_prompt() {
        let request = test_authorize_request(Some("login select_account consent"), None);
        let prompted = account_selection_prompted_request(&request);
        assert!(prompted.account_selection_prompted);
        assert_eq!(prompted.prompt.as_deref(), Some("consent"));
    }

    #[test]
    fn login_hint_account_switch_uses_requested_email() {
        let mut request = test_authorize_request(None, None);
        request.login_hint = Some(" Alice@Example.COM ".to_string());
        assert!(!login_hint_requires_account_switch(
            &request,
            &test_user("alice@example.com")
        ));

        request.login_hint = Some("bob@example.com".to_string());
        assert!(login_hint_requires_account_switch(
            &request,
            &test_user("alice@example.com")
        ));

        request.login_hint = Some("opaque-subject".to_string());
        assert!(!login_hint_requires_account_switch(
            &request,
            &test_user("alice@example.com")
        ));
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
        let consumed = crate::par::consume_request_uri(&state, &request_uri)
            .await
            .unwrap();
        assert_eq!(consumed.client_id, "demo-web");
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
        request.code_challenge = Some("challenge".to_string());
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

    fn test_user(email: &str) -> UserRecord {
        UserRecord {
            id: "user-id".to_string(),
            email: email.to_string(),
            username: "alice".to_string(),
            display_name: None,
            phone: None,
            password_hash: "hash".to_string(),
            email_verified_at: Some(1),
            phone_verified_at: None,
            is_admin: 0,
            is_active: 1,
            archived_at: None,
            last_login_at: None,
            last_login_ip: None,
            last_oidc_client_id: None,
            last_login_method: None,
            created_at: 1,
            updated_at: 1,
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
        }
    }

    async fn test_app_state() -> (AppState, PathBuf) {
        let config_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../config/default.toml");
        let raw = std::fs::read_to_string(config_path).unwrap();
        let mut settings: crate::Settings = toml::from_str(&raw).unwrap();
        let path = std::env::temp_dir().join(format!(
            "gpt-sso-oidc-test-{}.sqlite3",
            uuid::Uuid::new_v4()
        ));
        settings.database.kind = crate::config::DatabaseKind::Sqlite;
        settings.database.url = path.to_string_lossy().to_string();
        settings.database.run_migrations = true;
        settings.bootstrap.admin.create_on_startup = false;
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
            organization_id: None,
            redirect_uris: serde_json::json!(["https://app.example/callback"]).to_string(),
            post_logout_redirect_uris: "[]".to_string(),
            scopes: serde_json::json!(["openid", "profile"]).to_string(),
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
