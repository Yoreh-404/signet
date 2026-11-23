use super::oidc_token_liveness::{
    introspected_access_token_is_live, introspected_refresh_grant_is_live,
    introspected_user_grant_is_live,
};
use super::{
    authenticate_client_at, ensure_trial_enrollment_client_allowed_for_user, load_oidc_user,
};
use crate::{
    AppState,
    audit::{self, AuditOutcome, AuditSink},
    authorization_details,
    claim_mapper::ClaimOutputTarget,
    db::ClientRecord,
    dpop,
    error::{AppError, AppResult},
    oidc_authorization::{AuthorizationSnapshot, ClientClaimsSnapshot},
    oidc_claims::{DefaultEmailVerifiedClaimPolicy, EmailVerifiedClaimPolicy},
    oidc_client_auth::{ClientAuthFields, ClientAuthForm},
    subject, util,
};
use axum::{
    Form, Json,
    extract::State,
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

pub(super) fn authorization_token(headers: &HeaderMap) -> AppResult<(&'static str, &str)> {
    let header = headers
        .get(axum::http::header::AUTHORIZATION)
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

pub(super) async fn userinfo(
    State(state): State<AppState>,
    method: Method,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let (auth_scheme, token) = authorization_token(&headers)?;
    let issuers = state.accepted_issuers(&headers).await?;
    if token.starts_with(super::website_token::PREFIX) {
        return super::website_token::userinfo(
            &state,
            &method,
            &headers,
            auth_scheme,
            token,
            &issuers,
        )
        .await;
    }
    let issuer_refs = issuers.iter().map(String::as_str).collect::<Vec<_>>();
    // The access token identifies the client connection first. UserInfo is a
    // concrete OIDC resource endpoint, so the second verification must bind
    // its audience to that client; a token minted for an RFC 8707 API must
    // not be replayed against UserInfo merely because it carries the same
    // user subject.
    let bootstrap_claims = state
        .jwt
        .verify_access_token_for_generic_bearer(token, &issuer_refs)?;
    if crate::dcr::is_website_client_id(&bootstrap_claims.client_id) {
        // Website access tokens use the dedicated opaque-token path above.
        return Err(AppError::Unauthorized);
    }
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
    if !introspected_user_grant_is_live(
        &state,
        &user.id,
        &claims.client_id,
        &claims.scope,
        claims.grant_id.as_deref(),
    )
    .await?
    {
        return Err(AppError::Unauthorized);
    }
    let authorization_snapshot = if claims.gpt_sso_login_code_level.is_none() {
        Some(AuthorizationSnapshot::load(&state, &client, &user).await?)
    } else {
        None
    };
    let client_claims_snapshot = if authorization_snapshot.is_none() {
        Some(ClientClaimsSnapshot::load(&state, &client).await?)
    } else {
        None
    };
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
    let mapped_claims = if let Some(snapshot) = authorization_snapshot.as_ref() {
        snapshot.claims_for_user(&client, &user, &claims.scope, ClaimOutputTarget::UserInfo)?
    } else {
        client_claims_snapshot
            .as_ref()
            .ok_or(AppError::Unauthorized)?
            .claims_for_user(&client, &user, &claims.scope, ClaimOutputTarget::UserInfo)?
    };
    response.extend(mapped_claims);
    Ok(Json(serde_json::Value::Object(response)))
}

#[derive(Debug, Deserialize)]
pub(super) struct IntrospectionRequest {
    token: String,
    token_type_hint: Option<String>,
    #[serde(flatten)]
    client_auth: ClientAuthForm,
}

impl ClientAuthFields for IntrospectionRequest {
    fn client_auth(&self) -> &ClientAuthForm {
        &self.client_auth
    }
}

pub(super) async fn introspect(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(payload): Form<IntrospectionRequest>,
) -> AppResult<Response> {
    let v3 = payload.token_type_hint.as_deref() == Some(AXON_ADMIN_V3_HINT);
    let mut response = introspect_value(state, headers, payload).await?.into_response();
    if v3 {
        response.headers_mut().insert(axum::http::header::CACHE_CONTROL, "no-store".parse().unwrap());
    }
    Ok(response)
}

const AXON_ADMIN_V3_HINT: &str = "axon_admin_authority_v3";

async fn introspect_value(
    state: AppState, headers: HeaderMap, payload: IntrospectionRequest,
) -> AppResult<Json<serde_json::Value>> {
    let client = authenticate_client_at(&state, &headers, &payload, "/oauth2/introspect").await?;
    if client.token_endpoint_auth_method == "none" {
        return Err(AppError::Unauthorized);
    }
    if payload.token_type_hint.as_deref() == Some(AXON_ADMIN_V3_HINT) {
        return introspect_durable_axon_admin(&state, &client, &headers, &payload.token).await;
    }
    if payload.token_type_hint.as_deref() == Some(crate::claim_mapper::AXON_ADMIN_AUTHORITY_CLAIM) {
        return introspect_axon_admin_authority(&state, &client, &headers, &payload.token).await;
    }
    let issuers = state.accepted_issuers(&headers).await?;
    let issuer_refs = issuers.iter().map(String::as_str).collect::<Vec<_>>();
    let expected_audience = introspection_audience(&client);
    if let Ok(claims) = state
        .jwt
        .verify_access_token_for_introspection(&payload.token, &issuer_refs)
    {
        let source_client = state.db.find_client_by_client_id(&claims.client_id).await?;
        let active = claims.exp > util::now_ts()
            && claims.aud == expected_audience
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
        let user = if source_client
            .as_ref()
            .is_some_and(|source_client| source_client.is_active == 1)
        {
            load_oidc_user(&state, &record.user_id).await.ok()
        } else {
            None
        };
        let runtime_active = if let (Some(source_client), Some(user)) =
            (source_client.as_ref(), user.as_ref())
        {
            match state
                .db
                .load_client_policy_snapshot_for_protocol(
                    &source_client.id,
                    &user.id,
                    "oauth2_oidc",
                )
                .await
            {
                Ok(policy) => match policy.binding.as_ref() {
                    Some(binding) => {
                        policy.is_authorizable
                            && policy.is_interactive_client_runtime_active()
                            && policy.client_id.as_deref() == Some(source_client.id.as_str())
                            && policy.user_id == user.id
                            && record.application_id.as_deref()
                                == Some(binding.application_id.as_str())
                            && record.authorization_profile_id.as_deref()
                                == Some(binding.authorization_profile_id.as_str())
                    }
                    None => {
                        // Legacy refresh tokens have no application boundary;
                        // a token carrying one cannot survive an unbind.
                        record.application_id.is_none() && record.authorization_profile_id.is_none()
                    }
                },
                Err(_) => false,
            }
        } else {
            false
        };
        let consent_active = if runtime_active {
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

async fn introspect_durable_axon_admin(
    state: &AppState, verifier: &ClientRecord, headers: &HeaderMap, token: &str,
) -> AppResult<Json<serde_json::Value>> {
    use serde_json::json;
    let inactive = || Ok(Json(json!({"active":false})));
    let Some(enrolled) = state.settings.discovery.axon_admin_v3.as_ref() else { return inactive(); };
    if verifier.client_id != enrolled.introspection_client_id
        || verifier.client_id == enrolled.client_id || verifier.is_active != 1
        || verifier.organization_id.as_deref() != Some(enrolled.organization_id.as_str())
        || verifier.audience != enrolled.audience || token.len() > 32_768
        || !state.accepted_issuers(headers).await?.contains(&enrolled.issuer)
    { return inactive(); }
    let Ok(claims) = state.jwt.verify_access_token_for_introspection(token, &[&enrolled.issuer])
        else { return inactive(); };
    let now = util::now_ts();
    if claims.iat <= 0 || claims.iat > now || claims.exp <= now || claims.scope != "openid"
        || claims.client_id != enrolled.client_id || claims.aud != enrolled.audience
        || claims.act.is_some() || claims.gpt_sso_login_code_level.is_some()
        || super::oidc_token_liveness::is_machine_token_claims(&claims)
    { return inactive(); }
    let Some(sid) = claims.sid.as_deref() else { return inactive(); };
    let Some(source) = state.db.find_client_by_client_id(&enrolled.client_id).await? else { return inactive(); };
    if !introspected_access_token_is_live(state, Some(&source), &claims).await?
        || !state.db.list_user_sessions(&claims.sub).await?.iter().any(|session|
            session.expires_at > util::now_ts() && crate::util::session_public_id(&session.id) == sid)
    { return inactive(); }
    let interlock = crate::application_discovery::axon_v3_restore::RestoreInterlock::new(
        enrolled.restore_marker_path.clone(), enrolled.restore_marker_owner_uid,
    );
    let Some(live) = state.db.read_active_axon_v3_policy(crate::db::AxonV3CheckedScope {
        organization_id: enrolled.organization_id.clone(), enrollment_id: enrolled.enrollment_id.clone(),
        application_id: enrolled.application_id.clone(), issuer: claims.iss.clone(),
        client_id: claims.client_id.clone(), verifier_client_id: verifier.client_id.clone(),
        audience: claims.aud.clone(), origin: enrolled.origin.clone(), subject: claims.sub.clone(),
    }, &interlock).await? else { return inactive(); };
    Ok(Json(json!({
        "active":true, "iss":claims.iss, "sub":claims.sub, "client_id":claims.client_id,
        "aud":claims.aud, "iat":claims.iat, "exp":claims.exp, (AXON_ADMIN_V3_HINT):live,
    })))
}

async fn introspect_axon_admin_authority(
    state: &AppState,
    verifier: &ClientRecord,
    headers: &HeaderMap,
    token: &str,
) -> AppResult<Json<serde_json::Value>> {
    use serde_json::{Value, json};
    let inactive = || Ok(Json(json!({"active": false})));
    let (Some(policy), Some(trust)) = (
        state.settings.discovery.axon_admin_v2.as_ref(), state.settings.discovery.axon_admin_trust.as_ref(),
    ) else {
        return inactive();
    };
    if verifier.client_id != policy.introspection_client_id
        || verifier.client_id == trust.client_id || verifier.is_active != 1
        || crate::dcr::is_website_client_id(&verifier.client_id)
        || verifier.organization_id.as_deref() != Some(trust.organization_id.as_str())
        || introspection_audience(verifier) != trust.audience
        || token.len() > 32_768
    {
        return inactive();
    }
    let issuers = state.accepted_issuers(headers).await?;
    if !issuers.contains(&policy.issuer) {
        return inactive();
    }
    let Ok(claims) = state.jwt.verify_access_token_for_introspection(token, &[&policy.issuer]) else {
        return inactive();
    };
    if claims.iat < policy.activation_epoch || claims.iat > util::now_ts()
        || claims.exp <= util::now_ts() || claims.aud != trust.audience
        || claims.client_id != trust.client_id || claims.scope != "openid"
        || claims.act.is_some() || claims.gpt_sso_login_code_level.is_some()
    {
        return inactive();
    }
    let Some(sid) = claims.sid.as_deref() else { return inactive(); };
    let Some(source) = state.db.find_client_by_client_id(&claims.client_id).await? else { return inactive(); };
    if !introspected_access_token_is_live(state, Some(&source), &claims).await? {
        return inactive();
    }
    let Ok(user) = load_oidc_user(state, &claims.sub).await else { return inactive(); };
    let Ok(snapshot) = AuthorizationSnapshot::load(state, &source, &user).await else { return inactive(); };
    let Some(live) = crate::oidc_authorization::project_axon_admin_v2(
        state, &snapshot, &source, &user, Some(&claims.aud), sid, &claims.scope, &claims.iss,
    ).await? else { return inactive(); };
    // Re-read the exact payload only after verifying this same access token.
    let signed = token.split('.').nth(1).and_then(|raw| URL_SAFE_NO_PAD.decode(raw).ok())
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
    if signed.as_ref().and_then(|v| v.get(crate::claim_mapper::AXON_ADMIN_AUTHORITY_CLAIM)) != Some(&live) {
        return inactive();
    }
    Ok(Json(json!({"active": true, "axon_admin_authority": live})))
}

fn introspection_audience(client: &ClientRecord) -> String {
    if client.audience.trim().is_empty() {
        client.client_id.clone()
    } else {
        client.audience.trim().to_string()
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct RevocationRequest {
    token: String,
    token_type_hint: Option<String>,
    #[serde(flatten)]
    client_auth: ClientAuthForm,
}

impl ClientAuthFields for RevocationRequest {
    fn client_auth(&self) -> &ClientAuthForm {
        &self.client_auth
    }
}

pub(super) async fn revoke(
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
