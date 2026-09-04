use crate::{
    AppState, applications,
    assurance::{self, AssurancePolicy, SessionAuthenticationAssurance},
    audit::{self, AuditOutcome, AuditSink},
    auth::{self, AccountCapabilities},
    auth_flow, authorization_details,
    client_policy::{
        AuthorizationRequestSecurityView, AuthorizationRequestSource, ClientSecurityPolicy,
        DefaultClientSecurityPolicy,
    },
    consent,
    db::{ApplicationRecord, ClientRecord, NewAuthorizationCode, SessionRecord, UserRecord},
    directory,
    error::{AppError, AppResult},
    html::escape as html_escape,
    mfa,
    mfa_policy::MfaDecision,
    network_policy::TrustedNetworkPolicy,
    oidc_authorization::AuthorizationSnapshot,
    oidc_client_auth::ClientAuthFields,
    redirects, security_policy,
    util::{self, url_encode},
};
#[cfg(test)]
use axum::Json;
use axum::{
    Form, Router,
    extract::{ConnectInfo, Query, State},
    http::HeaderMap,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
#[cfg(test)]
use base64::{Engine as _, engine::general_purpose::STANDARD};
#[path = "oidc_authorization_flow.rs"]
mod oidc_authorization_flow;
#[path = "oidc_browser_interaction.rs"]
mod oidc_browser_interaction;
#[path = "oidc_metadata.rs"]
mod oidc_metadata;
#[path = "oidc_request.rs"]
mod oidc_request;
#[path = "oidc_request_validation.rs"]
mod oidc_request_validation;
#[path = "oidc_resource.rs"]
mod oidc_resource;
#[path = "oidc_return_target.rs"]
mod oidc_return_target;
#[path = "oidc_token.rs"]
mod oidc_token;
#[path = "oidc_token_liveness.rs"]
mod oidc_token_liveness;
#[path = "oidc_user.rs"]
mod oidc_user;
#[path = "oidc_values.rs"]
mod oidc_values;
use oidc_authorization_flow::{
    AuthorizationHttpContext, AuthorizationSessionFreshness, authorization_mfa_decision,
    find_or_create_application_auth_context, requires_authorization_consent,
};
#[cfg(test)]
use oidc_browser_interaction::{
    AuthorizationInteractionRequestStore, account_selection_prompted_request,
};
use oidc_browser_interaction::{
    authorize_return_to_for_account_selection, authorize_return_to_for_interaction, consent_page,
    prompt_without_select_account, reauthentication_request,
};
use oidc_user::{load_active_user, load_oidc_user};
pub(crate) use oidc_values::normalize_resource;
use oidc_values::{merge_token_resource, resolve_client_credentials_audience};
use serde::Deserialize;
use std::{collections::HashSet, net::SocketAddr};
use time::Duration;
#[cfg(test)]
use url::Url;

#[cfg(test)]
use crate::{
    db::{LoginCodeLevel, RefreshTokenInput},
    dpop::DpopBinding,
    jwt::TokenSubject,
    oidc_claims::RequestedClaims,
    oidc_client_auth::ClientAuthForm,
    subject,
};
use oidc_metadata::{discovery, jwks};
pub(crate) use oidc_request::ResolvedAuthorizeRequest;
use oidc_request::{
    AuthorizeRequest, ConsentForm, PromptBehavior, optional_form_value, prompt_behavior,
    required_query_value,
};
pub(crate) use oidc_request::{normalize_acr_values_param, parse_max_age, validate_max_age};
use oidc_resource::{introspect, revoke, userinfo};
pub(crate) use oidc_return_target::{absolute, frontend_login_url};
pub(crate) use oidc_return_target::{
    authorize_request_from_return_to, strict_interaction_request_from_return_to,
};
#[cfg(test)]
use oidc_return_target::{authorize_return_to_resolved_for_login, serde_urlencode};
use oidc_token::token;
#[cfg(test)]
use oidc_token::{
    TokenRequest, authorization_code_login_level, token_from_authorization_code,
    token_from_refresh_token,
};
#[cfg(test)]
use oidc_token_liveness::{is_machine_token_claims, service_account_claim_is_live};

#[cfg(test)]
pub(crate) use crate::oidc_logout::{
    LogoutRequest, logout_hint_authorizes_current_session, post_logout_redirect_url,
};
pub(crate) use crate::oidc_logout::{logout_get, logout_post};

#[cfg(test)]
pub(crate) use crate::oidc_client_auth::service_client_endpoint_request;

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
        let runtime = AuthorizationSnapshot::load_runtime(&state, &client).await?;
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
            has_selectable_browser_accounts(&state, &jar, Some(&runtime)).await?
        } else {
            false
        };
        if request.account_selection_required
            || prompt.select_account
            || client_requires_account_selection(&client, Some(&runtime.application), &request)
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
    let authorization_snapshot =
        AuthorizationSnapshot::load(&state, &client, &current.user).await?;
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
        || client_requires_account_selection(
            &client,
            authorization_snapshot.application.as_ref(),
            &request,
        ))
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
    let requested_scopes = normalize_and_validate_requested_scopes(
        &client,
        request.scope.as_deref(),
        &state.settings.oidc.supported_scopes,
    )?;
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
        &authorization_snapshot,
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
    let (client, _runtime) = validate_authorize_request_with_runtime(state, &preview).await?;
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

    let requested_scopes = normalize_and_validate_requested_scopes(
        &client,
        preview.scope.as_deref(),
        &state.settings.oidc.supported_scopes,
    )?;
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
    ensure_interaction_request_matches_preview(&request, &preview)?;
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
    let authorization_snapshot =
        AuthorizationSnapshot::load(&state, &client, &current.user).await?;
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
    let requested_scopes = normalize_and_validate_requested_scopes(
        &client,
        request.scope.as_deref(),
        &state.settings.oidc.supported_scopes,
    )?;
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
                &authorization_snapshot,
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

async fn enforce_authorization_mfa(
    context: &AuthorizationHttpContext<'_>,
    current: &auth::CurrentUser,
    client: &ClientRecord,
    session: &SessionRecord,
    request: &ResolvedAuthorizeRequest,
    return_to: &str,
    prompt_none: bool,
) -> AppResult<Option<Response>> {
    match authorization_mfa_decision(context, current, client, session, request).await? {
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
    match authorization_mfa_decision(context, current, client, session, request).await? {
        MfaDecision::Satisfied => Ok(()),
        MfaDecision::Challenge | MfaDecision::SetupRequired => Err(AppError::Forbidden),
    }
}

async fn issue_authorization_code_redirect(
    context: &AuthorizationHttpContext<'_>,
    user: &UserRecord,
    session: &SessionRecord,
    client: &ClientRecord,
    authorization_snapshot: &AuthorizationSnapshot,
    request: ResolvedAuthorizeRequest,
    requested_scopes: Vec<String>,
) -> AppResult<Response> {
    ensure_trial_enrollment_client_allowed_for_user(context.state, &user.id, &client.client_id)
        .await?;
    if !authorization_snapshot.policy.is_authorizable
        || authorization_snapshot.policy.user_id != user.id
        || authorization_snapshot.policy.client_id.as_deref() != Some(client.id.as_str())
    {
        return Err(AppError::Forbidden);
    }
    let application = authorization_snapshot
        .application
        .as_ref()
        .ok_or(AppError::Forbidden)?;
    let client_binding = authorization_snapshot
        .binding
        .as_ref()
        .ok_or(AppError::Forbidden)?;
    let code = util::random_token(32);
    let session_assurance = session.authentication_assurance();
    let requested_assurance = request.requested_assurance()?;
    let acr =
        assurance::DefaultAssurancePolicy.select_acr(&session_assurance, &requested_assurance)?;
    assurance::DefaultAssurancePolicy.assert_amr(&session_assurance, &requested_assurance)?;
    let now = util::now_ts();
    let auth_context_id = find_or_create_application_auth_context(
        context.state,
        &client_binding.auth_domain_id,
        &user.id,
        &acr,
        &session_assurance.amr,
        session.created_at,
        now,
    )
    .await?;
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
            application_id: Some(application.id.clone()),
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
    state.db.ensure_application_for_client(&client).await?;
    validate_authorize_request_for_client(&client, request)?;
    Ok(client)
}

async fn validate_authorize_request_with_runtime(
    state: &AppState,
    request: &ResolvedAuthorizeRequest,
) -> AppResult<(ClientRecord, applications::ApplicationRuntimeSnapshot)> {
    let client = validate_authorize_request(state, request).await?;
    let runtime = AuthorizationSnapshot::load_runtime(state, &client)
        .await
        .map_err(|_| AppError::Oidc("client application is unavailable".to_string()))?;
    Ok((client, runtime))
}

fn ensure_interaction_request_matches_preview(
    request: &ResolvedAuthorizeRequest,
    preview: &ResolvedAuthorizeRequest,
) -> AppResult<()> {
    let request_json =
        serde_json::to_string(request).map_err(|err| AppError::Internal(err.to_string()))?;
    let preview_json =
        serde_json::to_string(preview).map_err(|err| AppError::Internal(err.to_string()))?;
    if request_json != preview_json {
        return Err(AppError::Unauthorized);
    }
    Ok(())
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
    oidc_request_validation::validate_authorization_request_parameters(request)?;
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
    let allowed_scope_set = allowed_scopes
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    for scope in requested_scopes {
        if !allowed_scope_set.contains(scope.as_str()) {
            return Err(AppError::Oidc(format!(
                "client is not allowed to request scope: {scope}"
            )));
        }
    }
    Ok(())
}

fn normalize_and_validate_requested_scopes(
    client: &ClientRecord,
    requested_scope: Option<&str>,
    supported_scopes: &[String],
) -> AppResult<Vec<String>> {
    let requested_scopes = util::normalize_scopes(requested_scope, supported_scopes)?;
    validate_requested_scopes(client, &requested_scopes)?;
    Ok(requested_scopes)
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
    crate::oidc_client_auth::authenticate_client_at(state, headers, payload, endpoint_path).await
}

fn normalize_client_credentials_scope(
    client: &ClientRecord,
    requested: Option<&str>,
) -> AppResult<String> {
    let Some(requested) = requested.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(String::new());
    };
    let scopes = requested
        .split_whitespace()
        .filter(|scope| !scope.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    validate_requested_scopes(client, &scopes)?;
    Ok(scopes.join(" "))
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

fn client_requires_account_selection(
    client: &ClientRecord,
    application: Option<&ApplicationRecord>,
    request: &ResolvedAuthorizeRequest,
) -> bool {
    if request.account_selection_prompted {
        return false;
    }
    client.require_account_selection == 1
        || application.is_some_and(ApplicationRecord::requires_account_selection)
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
    runtime: Option<&applications::ApplicationRuntimeSnapshot>,
) -> AppResult<bool> {
    let Some(context_id) = auth::browser_context_id_from_jar(state, jar) else {
        return Ok(false);
    };
    for option in state
        .db
        .list_browser_context_account_options(&context_id)
        .await?
    {
        let user = option.user;
        let session = option.session;
        let trial_enrollment = option.trial_enrollment;
        if trial_enrollment
            .as_ref()
            .is_some_and(|enrollment| !enrollment.is_active_at(util::now_ts()))
        {
            continue;
        }
        let has_redemption = user.archived_at.is_some() && option.has_authorization_code_redemption;
        if auth::AccountSessionKind::for_session_with_trial_enrollment(
            &user,
            &session,
            has_redemption,
            trial_enrollment.is_some(),
        )
        .is_some()
        {
            if runtime.is_some() {
                if runtime
                    .is_none_or(|runtime| !runtime.policy.is_interactive_client_runtime_active())
                {
                    continue;
                }
                // The application runtime snapshot already proves the
                // application/organization/client boundary.  Account
                // selection only needs the account/session boundary here;
                // the selected user receives the full AuthorizationSnapshot
                // before a code is issued.
                if user.is_active != 1 || user.archived_at.is_some() {
                    continue;
                }
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

async fn authorization_request_from_return_to(
    state: &AppState,
    headers: &HeaderMap,
    query: AuthorizeRequest,
) -> AppResult<Option<ResolvedAuthorizeRequest>> {
    if let Some(interaction_request) = query.interaction_request.as_deref() {
        return crate::par::peek_interaction_request(state, interaction_request).await;
    }
    if let Some(request_uri) = query.request_uri.as_deref() {
        return crate::par::peek_request_uri(state, request_uri).await;
    }
    resolve_authorize_request(state, headers, query)
        .await
        .map(Some)
}

fn empty_authorization_login_context() -> AuthorizationLoginContext {
    AuthorizationLoginContext {
        client: None,
        application: None,
        request_requires_mfa: false,
    }
}

pub(crate) async fn authorization_login_context_from_return_to(
    state: &AppState,
    headers: &HeaderMap,
    return_to: Option<&str>,
) -> AppResult<AuthorizationLoginContext> {
    let Some(return_to) = return_to else {
        return Ok(empty_authorization_login_context());
    };
    let Some(query) = authorize_request_from_return_to(return_to)? else {
        return Ok(empty_authorization_login_context());
    };
    let Some(request) = authorization_request_from_return_to(state, headers, query).await? else {
        return Ok(empty_authorization_login_context());
    };
    let (client, runtime) = validate_authorize_request_with_runtime(state, &request).await?;
    let application = Some(runtime.application.clone());
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
    let (client, _runtime) = validate_authorize_request_with_runtime(state, &request).await?;
    let requested_scopes = normalize_and_validate_requested_scopes(
        &client,
        request.scope.as_deref(),
        &state.settings.oidc.supported_scopes,
    )?;
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
    let (client, _runtime) = validate_authorize_request_with_runtime(state, &request).await?;
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
    AuthorizationSnapshot::load(state, &client, &user).await?;
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
    ensure_interaction_request_matches_preview(&request, &preview)?;
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
    let _ = validate_authorize_request_with_runtime(state, &request).await?;
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

#[cfg(test)]
#[path = "oidc_tests.rs"]
mod tests;
