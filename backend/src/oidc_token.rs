use super::oidc_token_liveness::introspected_refresh_grant_is_live;
use super::{
    authenticate_client_at, ensure_trial_enrollment_client_allowed_for_user, load_active_user,
    load_oidc_user, merge_token_resource, normalize_client_credentials_scope, normalize_resource,
    resolve_client_credentials_audience,
};
use crate::{
    AppState, applications, assurance,
    audit::{self, AuditOutcome, AuditSink},
    authorization_details,
    claim_mapper::ClaimOutputTarget,
    client_policy::{ClientSecurityPolicy, DefaultClientSecurityPolicy},
    db::{ClientRecord, LoginCodeLevel, RefreshTokenInput},
    dpop::{self, DpopBinding},
    error::{AppError, AppResult},
    jwt::TokenSubject,
    oidc_authorization::{AuthorizationSnapshot, ClientClaimsSnapshot},
    oidc_client_auth::{ClientAuthFields, ClientAuthForm, diagnostic_client_id},
    service_accounts::ServiceAccountProfile,
    subject, util,
};
use axum::{
    Form, Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use serde::{Deserialize, Serialize};
#[derive(Debug, Deserialize)]
pub(super) struct TokenRequest {
    pub(super) grant_type: String,
    pub(super) code: Option<String>,
    pub(super) device_code: Option<String>,
    pub(super) redirect_uri: Option<String>,
    #[serde(flatten)]
    pub(super) client_auth: ClientAuthForm,
    pub(super) code_verifier: Option<String>,
    pub(super) refresh_token: Option<String>,
    pub(super) scope: Option<String>,
    pub(super) resource: Option<String>,
    pub(super) authorization_details: Option<String>,
    pub(super) subject_token: Option<String>,
    pub(super) subject_token_type: Option<String>,
    pub(super) requested_token_type: Option<String>,
    pub(super) audience: Option<String>,
    pub(super) actor_token: Option<String>,
}

impl ClientAuthFields for TokenRequest {
    fn client_auth(&self) -> &ClientAuthForm {
        &self.client_auth
    }

    fn defers_application_runtime_gate(&self) -> bool {
        matches!(
            self.grant_type.as_str(),
            "authorization_code"
                | "refresh_token"
                | "client_credentials"
                | crate::device::DEVICE_CODE_GRANT
                | crate::token_exchange::TOKEN_EXCHANGE_GRANT
        )
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct TokenResponse {
    pub(super) access_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) issued_token_type: Option<&'static str>,
    pub(super) token_type: &'static str,
    pub(super) expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) id_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) refresh_token: Option<String>,
    pub(super) scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) authorization_details: Option<serde_json::Value>,
}

pub(super) async fn token(
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
            token_from_token_exchange(state, headers, client, payload, issuer, dpop).await
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

pub(super) async fn token_from_client_credentials(
    state: AppState,
    client: ClientRecord,
    payload: TokenRequest,
    issuer: String,
    dpop: Option<DpopBinding>,
) -> AppResult<Json<TokenResponse>> {
    // Client credentials are machine authorization. Load the application,
    // client binding, organization, and discovery boundary once here and use
    // that same value for both the gate and access-token claims. This path is
    // intentionally separate from the user authorization snapshot.
    if client.service_account_enabled != 1
        || !client
            .grant_types()
            .map_err(|_| AppError::Unauthorized)?
            .iter()
            .any(|value| value == "client_credentials")
    {
        return Err(AppError::Unauthorized);
    }
    let runtime = applications::ApplicationRuntimeSnapshot::load_service(&state, &client)
        .await
        .map_err(|_| AppError::Unauthorized)?;
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
    access_claims.insert(
        "application_id".to_string(),
        serde_json::Value::String(runtime.application.id.clone()),
    );
    access_claims.insert(
        "authorization_profile_id".to_string(),
        serde_json::Value::String(runtime.binding.authorization_profile_id.clone()),
    );
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

pub(super) async fn token_from_authorization_code(
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

pub(super) fn authorization_code_login_level(
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

pub(super) async fn token_from_device_code(
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

pub(super) async fn token_from_token_exchange(
    state: AppState,
    headers: HeaderMap,
    client: ClientRecord,
    payload: TokenRequest,
    issuer: String,
    dpop: Option<DpopBinding>,
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
        dpop,
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

pub(super) async fn token_from_refresh_token(
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
    if !introspected_refresh_grant_is_live(&state, &user.id, &client.client_id).await? {
        return Err(invalid_refresh_token_grant());
    }
    // The single AuthorizationSnapshot below is the live application/client /
    // user gate for refresh issuance. Do not run an independent application
    // lookup before it: that would let the claim projection and the gate see
    // different policy revisions.
    let authorization_snapshot = AuthorizationSnapshot::load(&state, &client, &user).await?;
    let binding = authorization_snapshot.binding.clone();
    if let Some(binding) = binding.as_ref()
        && (record.application_id.as_deref() != Some(binding.application_id.as_str())
            || record.authorization_profile_id.as_deref()
                != Some(binding.authorization_profile_id.as_str()))
    {
        return Err(invalid_refresh_token_grant());
    }
    let scope = record.scope;
    let resource = merge_token_resource(record.resource, payload.resource)?;
    let authorization_details = authorization_details::merge_authorization_details(
        record.authorization_details,
        payload.authorization_details,
        &client,
    )?;
    let mut access_claims = authorization_snapshot.claims_for_user(
        &client,
        &user,
        &scope,
        ClaimOutputTarget::AccessToken,
    )?;
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
        let id_claims = authorization_snapshot.claims_for_user(
            &client,
            &user,
            &scope,
            ClaimOutputTarget::IdToken,
        )?;
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

pub(super) struct IssueUserTokensInput {
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

pub(super) async fn issue_tokens_for_user(
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
    let authorization_snapshot = if login_code_level.is_none() {
        Some(AuthorizationSnapshot::load(state, client, &user).await?)
    } else {
        if application_id.is_some() || authorization_profile_id.is_some() {
            return Err(invalid_refresh_token_grant());
        }
        None
    };
    let client_claims_snapshot = if authorization_snapshot.is_none() {
        Some(ClientClaimsSnapshot::load(state, client).await?)
    } else {
        None
    };
    let binding = authorization_snapshot
        .as_ref()
        .and_then(|snapshot| snapshot.binding.as_ref());
    if let Some(binding) = binding
        && (application_id
            .as_deref()
            .is_some_and(|value| value != binding.application_id)
            || authorization_profile_id
                .as_deref()
                .is_some_and(|value| value != binding.authorization_profile_id))
    {
        return Err(invalid_refresh_token_grant());
    }
    tracing::info!(
        client_id = %client.client_id,
        user_id = %user.id,
        email = %user.email,
        scope,
        issuer,
        "issuing OIDC tokens"
    );
    let mut access_claims = if let Some(snapshot) = authorization_snapshot.as_ref() {
        snapshot.claims_for_user(client, &user, &scope, ClaimOutputTarget::AccessToken)?
    } else {
        client_claims_snapshot
            .as_ref()
            .ok_or(AppError::Forbidden)?
            .claims_for_user(client, &user, &scope, ClaimOutputTarget::AccessToken)?
    };
    if let Some(application_id) = application_id.as_deref() {
        access_claims.insert(
            "application_id".to_string(),
            serde_json::Value::String(application_id.to_string()),
        );
    } else if let Some(binding) = binding {
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
    } else if let Some(binding) = binding {
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
    let mut id_claims = if let Some(snapshot) = authorization_snapshot.as_ref() {
        snapshot.claims_for_user(client, &user, &scope, ClaimOutputTarget::IdToken)?
    } else {
        client_claims_snapshot
            .as_ref()
            .ok_or(AppError::Forbidden)?
            .claims_for_user(client, &user, &scope, ClaimOutputTarget::IdToken)?
    };
    if let Some(binding) = binding {
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

pub(super) fn insert_sid_claim(
    claims: &mut serde_json::Map<String, serde_json::Value>,
    sid: Option<&str>,
) {
    if let Some(sid) = sid.filter(|value| !value.trim().is_empty()) {
        claims.insert(
            "sid".to_string(),
            serde_json::Value::String(sid.to_string()),
        );
    }
}
