use crate::{
    AppState,
    access::{Authorizer, Permission, PermissionInfo, permission_catalog},
    archived_accounts,
    audit::{self, AuditSink},
    auth, auth_flow, backchannel_logout, claim_mapper, client_assertion, client_policy,
    db::{
        AuditEventRecord, GroupRecord, LinkedIdentityRecord, LoginEventRecord, NewClient,
        NewClientClaimMapper, NewExternalOidcProvider, NewGroup, NewIapApplication, NewInvitation,
        NewLdapProvider, NewLoginSettings, NewOrganization, NewRegistrationSettings, NewRole,
        NewRuntimeSettings, NewSecurityPolicy, NewUser, OrganizationMemberInput,
        OrganizationMemberWithUserRecord, OrganizationRecord, PublicAuditWebhook, PublicClient,
        PublicClientClaimMapper, PublicExternalOidcProvider, PublicIapApplication,
        PublicInvitation, PublicLdapProvider, PublicLoginSettings, PublicRegistrationSettings,
        PublicSecurityPolicy, PublicUser, QuickLink, RoleRecord, SecurityPolicyRecord,
        SessionRecord, SigningKeyRecord, UserConsentWithClientRecord, UserListScope,
        UserOrganizationRecord,
    },
    directory,
    error::{AppError, AppResult},
    frontchannel_logout, iap,
    identity_sources::{self, OidcDiscoveryResult, OidcProviderTemplate},
    mfa::{self, RecoveryCodeIssuer},
    mfa_policy::MfaDecision,
    network_policy::{self, TrustedNetworkPolicy},
    organizations,
    security_policy::{self, PasswordPolicy, PasswordSubject},
    service_accounts, subject, util, webhooks,
};
use axum::{
    Json, Router,
    extract::{ConnectInfo, Path, Query, State},
    http::HeaderMap,
    routing::{delete, get, post, put},
};
use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
};
use url::Url;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/health", get(health))
        .route("/api/login", post(login))
        .route("/api/logout", post(logout))
        .route("/api/me", get(me))
        .route("/api/me/sessions", get(list_my_sessions))
        .route("/api/me/sessions/{session_id}", delete(revoke_my_session))
        .route("/api/me/consents", get(list_my_consents))
        .route(
            "/api/me/consents/{client_id}",
            get(get_my_consent).delete(revoke_my_consent),
        )
        .route("/api/mfa/status", get(mfa_status))
        .route("/api/mfa/totp", post(start_totp_setup).delete(disable_mfa))
        .route("/api/mfa/totp/confirm", post(confirm_totp_setup))
        .route(
            "/api/mfa/recovery-codes/rotate",
            post(rotate_recovery_codes),
        )
        .route("/api/admin/overview", get(overview))
        .route("/api/admin/settings", get(settings_summary))
        .route(
            "/api/admin/registration-settings",
            get(get_registration_settings).put(update_registration_settings),
        )
        .route(
            "/api/admin/runtime-settings",
            get(get_runtime_settings).put(update_runtime_settings),
        )
        .route(
            "/api/admin/login-settings",
            get(get_login_settings).put(update_login_settings),
        )
        .route(
            "/api/admin/security-policy",
            get(get_security_policy).put(update_security_policy),
        )
        .route(
            "/api/admin/signing-keys",
            get(list_signing_keys).post(rotate_signing_key),
        )
        .route("/api/admin/users", get(list_users).post(create_user))
        .route(
            "/api/admin/users/{id}",
            get(user_detail).put(update_user).delete(delete_user),
        )
        .route("/api/admin/users/{id}/enable", post(enable_user))
        .route("/api/admin/users/{id}/password", post(set_user_password))
        .route("/api/admin/users/{id}/mfa/reset", post(reset_user_mfa))
        .route("/api/admin/users/{id}/login-events", get(user_login_events))
        .route("/api/admin/users/{id}/permissions", get(user_permissions))
        .route("/api/admin/clients", get(list_clients).post(create_client))
        .route("/api/admin/clients/{id}", put(update_client))
        .route(
            "/api/admin/iap-applications",
            get(list_iap_applications).post(create_iap_application),
        )
        .route(
            "/api/admin/iap-applications/{id}",
            put(update_iap_application).delete(delete_iap_application),
        )
        .route("/api/admin/audit-events", get(list_audit_events))
        .route(
            "/api/admin/audit-webhooks",
            get(list_audit_webhooks).post(create_audit_webhook),
        )
        .route(
            "/api/admin/audit-webhooks/{id}",
            put(update_audit_webhook).delete(delete_audit_webhook),
        )
        .route("/api/admin/access/permissions", get(list_permissions))
        .route("/api/admin/access/roles", get(list_roles).post(create_role))
        .route(
            "/api/admin/access/roles/{id}",
            put(update_role).delete(delete_role),
        )
        .route(
            "/api/admin/access/groups",
            get(list_groups).post(create_group),
        )
        .route(
            "/api/admin/access/groups/{id}",
            put(update_group).delete(delete_group),
        )
        .route(
            "/api/admin/access/groups/{id}/roles",
            put(update_group_roles),
        )
        .route(
            "/api/admin/access/groups/{id}/members",
            put(update_group_members),
        )
        .route(
            "/api/admin/organizations",
            get(list_organizations).post(create_organization),
        )
        .route(
            "/api/admin/organizations/{id}",
            put(update_organization).delete(delete_organization),
        )
        .route(
            "/api/admin/organizations/{id}/members",
            put(update_organization_members),
        )
        .route("/api/admin/users/{id}/access", get(user_access))
        .route("/api/admin/users/{id}/roles", put(update_user_roles))
        .route(
            "/api/admin/authorization-codes",
            get(list_invitations).post(create_invitation),
        )
        .route(
            "/api/admin/authorization-codes/{id}",
            put(update_invitation).delete(delete_invitation),
        )
        .route(
            "/api/admin/invitations",
            get(list_invitations).post(create_invitation),
        )
        .route(
            "/api/admin/invitations/{id}",
            put(update_invitation).delete(delete_invitation),
        )
        .route(
            "/api/admin/external-oidc-providers",
            get(list_external_oidc_providers).post(create_external_oidc_provider),
        )
        .route(
            "/api/admin/external-oidc-provider-templates",
            get(list_external_oidc_provider_templates),
        )
        .route(
            "/api/admin/external-oidc-provider-discovery",
            post(discover_external_oidc_provider),
        )
        .route(
            "/api/admin/external-oidc-providers/{id}",
            put(update_external_oidc_provider).delete(delete_external_oidc_provider),
        )
        .route(
            "/api/admin/ldap-providers",
            get(list_ldap_providers).post(create_ldap_provider),
        )
        .route(
            "/api/admin/ldap-providers/{id}",
            put(update_ldap_provider).delete(delete_ldap_provider),
        )
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    ok: bool,
    service: &'static str,
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        ok: true,
        service: "gpt-sso",
    })
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
    mfa_challenge_id: Option<String>,
    mfa_code: Option<String>,
    captcha_challenge_id: Option<String>,
    captcha_answer: Option<String>,
    return_to: Option<String>,
}

#[derive(Debug, Serialize)]
struct LoginResponse {
    user: Option<auth::CurrentUserResponse>,
    mfa_required: bool,
    mfa_challenge_id: Option<String>,
    recovery_available: bool,
    captcha_required: bool,
    captcha_challenge_id: Option<String>,
    captcha_prompt: Option<String>,
    captcha_expires_at: Option<i64>,
}

async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<LoginRequest>,
) -> AppResult<(CookieJar, Json<LoginResponse>)> {
    let subject = security_policy::normalize_login_subject(&payload.email);
    let request_ip = state.request_ip(&headers, Some(remote_addr)).await?;
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
        return Ok((
            jar,
            Json(LoginResponse {
                user: None,
                mfa_required: false,
                mfa_challenge_id: None,
                recovery_available: false,
                captcha_required: true,
                captcha_challenge_id: Some(captcha.challenge_id),
                captcha_prompt: Some(captcha.prompt),
                captcha_expires_at: Some(captcha.expires_at),
            }),
        ));
    }
    let local_user = state.db.find_user_by_email(&subject).await?;
    let failure_reason = if local_user.is_some() {
        "bad_credentials"
    } else {
        "unknown_user"
    };
    let mut login_method = "password".to_string();
    let mut external_provider = None;
    let mut user = local_user.filter(|candidate| {
        candidate.is_active == 1
            && candidate.archived_at.is_none()
            && util::verify_password(&candidate.password_hash, &payload.password)
    });
    if user.is_none() {
        let directory_login = match directory::authenticate_with_configured_directories(
            &state,
            &subject,
            &payload.password,
        )
        .await
        {
            Ok(value) => value,
            Err(AppError::Unauthorized | AppError::Forbidden) => None,
            Err(err) => return Err(err),
        };
        if let Some(login) = directory_login {
            login_method = "ldap".to_string();
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
    let login_context = crate::oidc::authorization_login_context_from_return_to(
        &state,
        &headers,
        payload.return_to.as_deref(),
    )
    .await?;
    let has_totp = state.db.find_totp_method(&user.id).await?.is_some();
    let policy = state.db.security_policy().await?;
    let policy_requires_mfa =
        policy.requires_mfa_for_ip(request_ip.as_deref())? || login_context.request_requires_mfa;
    match auth_flow::oidc_login_mfa_decision(
        &policy,
        login_context.client.as_ref(),
        has_totp,
        policy_requires_mfa,
    )? {
        MfaDecision::SetupRequired => {
            auth::record_login_failure(
                &state,
                request_ip.clone(),
                &headers,
                &subject,
                "mfa_required_no_totp",
            )
            .await?;
            return Err(AppError::BadRequest(
                "MFA is required for this login but this account has no TOTP method".to_string(),
            ));
        }
        MfaDecision::Challenge => {
            let recovery_codes = state.db.list_unused_recovery_codes(&user.id).await?;
            let Some(challenge_id) = payload.mfa_challenge_id.as_deref() else {
                let challenge = state
                    .db
                    .create_mfa_challenge(
                        &user.id,
                        "api_login",
                        None,
                        mfa::MFA_CHALLENGE_TTL_SECONDS,
                    )
                    .await?;
                return Ok((
                    jar,
                    Json(LoginResponse {
                        user: None,
                        mfa_required: true,
                        mfa_challenge_id: Some(challenge.id),
                        recovery_available: !recovery_codes.is_empty(),
                        captcha_required: false,
                        captcha_challenge_id: None,
                        captcha_prompt: None,
                        captcha_expires_at: None,
                    }),
                ));
            };
            let code = payload.mfa_code.as_deref().ok_or(AppError::Unauthorized)?;
            let completion = match mfa::complete_challenge_by_id(
                &state,
                challenge_id,
                &user.id,
                "api_login",
                code,
            )
            .await
            {
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
            let completed_method = if login_method == "ldap" {
                format!("ldap_{}", completion.method)
            } else {
                completion.method
            };
            let jar = issue_password_session(
                &state,
                jar,
                &headers,
                request_ip.clone(),
                &user,
                &completed_method,
                external_provider.clone(),
            )
            .await?;
            auth::clear_login_failures(&state, &subject).await?;
            return Ok((
                jar,
                Json(LoginResponse {
                    user: Some(auth::current_user_response(&state, user.clone()).await?),
                    mfa_required: false,
                    mfa_challenge_id: None,
                    recovery_available: false,
                    captcha_required: false,
                    captcha_challenge_id: None,
                    captcha_prompt: None,
                    captcha_expires_at: None,
                }),
            ));
        }
        MfaDecision::Satisfied => {}
    }

    let jar = issue_password_session(
        &state,
        jar,
        &headers,
        request_ip,
        &user,
        &login_method,
        external_provider,
    )
    .await?;
    auth::clear_login_failures(&state, &subject).await?;
    Ok((
        jar,
        Json(LoginResponse {
            user: Some(auth::current_user_response(&state, user.clone()).await?),
            mfa_required: false,
            mfa_challenge_id: None,
            recovery_available: false,
            captcha_required: false,
            captcha_challenge_id: None,
            captcha_prompt: None,
            captcha_expires_at: None,
        }),
    ))
}

async fn issue_password_session(
    state: &AppState,
    jar: CookieJar,
    headers: &HeaderMap,
    request_ip: Option<String>,
    user: &crate::db::UserRecord,
    method: &str,
    external_provider: Option<String>,
) -> AppResult<CookieJar> {
    auth::issue_session_with_login_event(
        state,
        jar,
        headers,
        request_ip,
        user,
        method,
        None,
        external_provider,
    )
    .await
}

async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> AppResult<(CookieJar, Json<serde_json::Value>)> {
    let current = auth::current_user_from_cookie(&state, &jar).await?;
    let mut frontchannel_frames = Vec::new();
    if let Some(current) = current.as_ref() {
        frontchannel_frames = match frontchannel_logout::frames_for_user(
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
        if let Err(err) = backchannel_logout::notify_user_logout(
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
    if let Some(cookie) = jar.get(&state.settings.security.cookie_name) {
        state.db.delete_session(cookie.value()).await?;
    }
    Ok((
        jar.add(auth::expired_session_cookie(&state)),
        Json(serde_json::json!({
            "ok": true,
            "frontchannel_logout_frames": frontchannel_frames,
        })),
    ))
}

#[derive(Debug, Serialize)]
struct MfaStatusResponse {
    enabled: bool,
    totp_enabled: bool,
    recovery_codes_remaining: usize,
    recovery_codes_total: usize,
}

#[derive(Debug, Serialize)]
struct TotpSetupResponse {
    setup_id: String,
    secret: String,
    otpauth_uri: String,
    expires_at: i64,
}

#[derive(Debug, Deserialize)]
struct ConfirmTotpInput {
    setup_id: String,
    code: String,
}

#[derive(Debug, Serialize)]
struct ConfirmTotpResponse {
    status: MfaStatusResponse,
    recovery_codes: Vec<String>,
}

async fn mfa_status(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<MfaStatusResponse>> {
    let current = auth::require_current_user(&state, &jar).await?;
    Ok(Json(mfa_status_for_user(&state, &current.user.id).await?))
}

async fn start_totp_setup(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> AppResult<Json<TotpSetupResponse>> {
    let current = auth::require_current_user(&state, &jar).await?;
    auth::ensure_account_mutable(&current.user)?;
    let secret = mfa::generate_totp_secret();
    let setup = state
        .db
        .create_mfa_totp_setup(&current.user.id, secret.clone(), mfa::MFA_SETUP_TTL_SECONDS)
        .await?;
    let issuer = state.effective_issuer(&headers).await?;
    let otpauth_uri = mfa::otpauth_uri(&issuer, &current.user.email, &secret)?;
    Ok(Json(TotpSetupResponse {
        setup_id: setup.id,
        secret,
        otpauth_uri,
        expires_at: setup.expires_at,
    }))
}

async fn confirm_totp_setup(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<ConfirmTotpInput>,
) -> AppResult<Json<ConfirmTotpResponse>> {
    let current = auth::require_current_user(&state, &jar).await?;
    auth::ensure_account_mutable(&current.user)?;
    let setup = state
        .db
        .find_mfa_totp_setup(&payload.setup_id)
        .await?
        .ok_or(AppError::NotFound)?;
    if setup.user_id != current.user.id || setup.expires_at < util::now_ts() {
        return Err(AppError::Unauthorized);
    }
    if !mfa::verify_setup_code(&setup.secret, &payload.code)? {
        return Err(AppError::Unauthorized);
    }
    state
        .db
        .upsert_totp_method(&current.user.id, setup.secret)
        .await?;
    state.db.delete_mfa_totp_setup(&payload.setup_id).await?;
    let codes = mfa::StandardRecoveryCodeIssuer.issue_recovery_codes(mfa::RECOVERY_CODE_COUNT)?;
    state
        .db
        .replace_recovery_codes(&current.user.id, mfa::code_hashes(&codes))
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id.clone(),
            "mfa.totp.enable",
            "user",
            Some(current.user.id.clone()),
            serde_json::json!({ "method": "totp" }),
        ))
        .await?;
    Ok(Json(ConfirmTotpResponse {
        status: mfa_status_for_user(&state, &current.user.id).await?,
        recovery_codes: mfa::plaintext_codes(&codes),
    }))
}

async fn rotate_recovery_codes(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<ConfirmTotpResponse>> {
    let current = auth::require_current_user(&state, &jar).await?;
    auth::ensure_account_mutable(&current.user)?;
    if state.db.find_totp_method(&current.user.id).await?.is_none() {
        return Err(AppError::BadRequest("MFA is not enabled".to_string()));
    }
    let codes = mfa::StandardRecoveryCodeIssuer.issue_recovery_codes(mfa::RECOVERY_CODE_COUNT)?;
    state
        .db
        .replace_recovery_codes(&current.user.id, mfa::code_hashes(&codes))
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id.clone(),
            "mfa.recovery_codes.rotate",
            "user",
            Some(current.user.id.clone()),
            serde_json::json!({ "count": codes.len() }),
        ))
        .await?;
    Ok(Json(ConfirmTotpResponse {
        status: mfa_status_for_user(&state, &current.user.id).await?,
        recovery_codes: mfa::plaintext_codes(&codes),
    }))
}

async fn disable_mfa(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<MfaStatusResponse>> {
    let current = auth::require_current_user(&state, &jar).await?;
    auth::ensure_account_mutable(&current.user)?;
    state.db.delete_mfa_for_user(&current.user.id).await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id.clone(),
            "mfa.disable",
            "user",
            Some(current.user.id.clone()),
            serde_json::json!({}),
        ))
        .await?;
    Ok(Json(mfa_status_for_user(&state, &current.user.id).await?))
}

async fn mfa_status_for_user(state: &AppState, user_id: &str) -> AppResult<MfaStatusResponse> {
    let method = state.db.find_totp_method(user_id).await?;
    let recovery_codes = state.db.list_recovery_codes(user_id).await?;
    Ok(MfaStatusResponse {
        enabled: mfa::method_enabled(method.as_ref()),
        totp_enabled: method.is_some(),
        recovery_codes_remaining: mfa::recovery_codes_remaining(&recovery_codes),
        recovery_codes_total: recovery_codes.len(),
    })
}

async fn me(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<Option<auth::CurrentUserResponse>>> {
    let current = auth::current_user_from_cookie(&state, &jar).await?;
    let Some(current) = current else {
        return Ok(Json(None));
    };
    Ok(Json(Some(
        auth::current_user_response(&state, current.user).await?,
    )))
}

#[derive(Debug, Serialize)]
struct MySessionResponse {
    id: String,
    current: bool,
    ip_address: Option<String>,
    user_agent: Option<String>,
    login_method: Option<String>,
    expires_at: i64,
    created_at: i64,
}

impl MySessionResponse {
    fn from_record(record: SessionRecord, current_session_id: &str) -> Self {
        Self {
            current: record.id == current_session_id,
            id: record.id,
            ip_address: record.ip_address,
            user_agent: record.user_agent,
            login_method: record.login_method,
            expires_at: record.expires_at,
            created_at: record.created_at,
        }
    }
}

async fn list_my_sessions(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<Vec<MySessionResponse>>> {
    let current = auth::require_current_user(&state, &jar).await?;
    let sessions = state
        .db
        .list_user_sessions(&current.user.id)
        .await?
        .into_iter()
        .map(|record| MySessionResponse::from_record(record, &current.session_id))
        .collect();
    Ok(Json(sessions))
}

async fn revoke_my_session(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(session_id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let current = auth::require_current_user(&state, &jar).await?;
    auth::ensure_account_mutable(&current.user)?;
    if session_id == current.session_id {
        return Err(AppError::BadRequest(
            "current session must be ended with logout".to_string(),
        ));
    }
    let revoked = state
        .db
        .delete_user_session(&current.user.id, &session_id)
        .await?;
    if !revoked {
        return Err(AppError::NotFound);
    }
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "session.revoke",
            "session",
            Some(session_id),
            serde_json::json!({}),
        ))
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

#[derive(Debug, Serialize)]
struct MyConsentResponse {
    client_id: String,
    client_name: Option<String>,
    granted_scopes: Vec<String>,
    granted_at: i64,
    updated_at: i64,
}

impl From<UserConsentWithClientRecord> for MyConsentResponse {
    fn from(record: UserConsentWithClientRecord) -> Self {
        Self {
            client_id: record.client_id,
            client_name: record.client_name,
            granted_scopes: record
                .granted_scopes
                .split_whitespace()
                .filter(|scope| !scope.is_empty())
                .map(ToOwned::to_owned)
                .collect(),
            granted_at: record.granted_at,
            updated_at: record.updated_at,
        }
    }
}

async fn list_my_consents(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<Vec<MyConsentResponse>>> {
    let current = auth::require_current_user(&state, &jar).await?;
    let consents = state
        .db
        .list_active_user_consents(&current.user.id)
        .await?
        .into_iter()
        .map(MyConsentResponse::from)
        .collect();
    Ok(Json(consents))
}

async fn get_my_consent(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(client_id): Path<String>,
) -> AppResult<Json<MyConsentResponse>> {
    let current = auth::require_current_user(&state, &jar).await?;
    let consent = state
        .db
        .list_active_user_consents(&current.user.id)
        .await?
        .into_iter()
        .find(|record| record.client_id == client_id)
        .ok_or(AppError::NotFound)?;
    Ok(Json(MyConsentResponse::from(consent)))
}

async fn revoke_my_consent(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(client_id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let current = auth::require_current_user(&state, &jar).await?;
    auth::ensure_account_mutable(&current.user)?;
    let revoked = state
        .db
        .revoke_user_consent(&current.user.id, &client_id)
        .await?;
    if !revoked {
        return Err(AppError::NotFound);
    }
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "consent.revoke",
            "client_consent",
            Some(client_id),
            serde_json::json!({}),
        ))
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

#[derive(Debug, Serialize)]
struct OverviewResponse {
    users: usize,
    active_users: usize,
    clients: usize,
    active_clients: usize,
    issuer: String,
    database_kind: String,
}

async fn overview(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> AppResult<Json<OverviewResponse>> {
    require_admin_reader(&state, &jar).await?;
    let users = state.db.count_users(UserListScope::All).await?;
    let active_users = state.db.count_users(UserListScope::Active).await?;
    let clients = state.db.list_clients().await?;
    Ok(Json(OverviewResponse {
        active_users: active_users as usize,
        users: users as usize,
        active_clients: clients
            .iter()
            .filter(|client| client.is_active == 1)
            .count(),
        clients: clients.len(),
        issuer: state.effective_issuer(&headers).await?,
        database_kind: format!("{:?}", state.settings.database.kind).to_ascii_lowercase(),
    }))
}

#[derive(Debug, Serialize)]
struct SettingsSummary {
    config_server_public_base_url: String,
    config_issuer: String,
    runtime_public_base_url: String,
    runtime_issuer: String,
    runtime_trust_proxy_headers: bool,
    effective_public_base_url: String,
    effective_issuer: String,
    database_kind: String,
    database_pool_size: u32,
    run_migrations: bool,
    supported_scopes: Vec<String>,
    access_token_ttl_seconds: i64,
    id_token_ttl_seconds: i64,
    refresh_token_ttl_seconds: i64,
    cookie_secure: bool,
    cookie_same_site: String,
    cors_allowed_origins: Vec<String>,
}

async fn settings_summary(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> AppResult<Json<SettingsSummary>> {
    require_admin_reader(&state, &jar).await?;
    let runtime = state.runtime_settings().await?;
    Ok(Json(SettingsSummary {
        config_server_public_base_url: state.settings.server.public_base_url.clone(),
        config_issuer: state.settings.oidc.issuer.clone(),
        runtime_public_base_url: runtime.public_base_url.clone(),
        runtime_issuer: runtime.issuer.clone(),
        runtime_trust_proxy_headers: runtime.trust_proxy_headers == 1,
        effective_public_base_url: state.effective_public_base_url(&headers).await?,
        effective_issuer: state.effective_issuer(&headers).await?,
        database_kind: format!("{:?}", state.settings.database.kind).to_ascii_lowercase(),
        database_pool_size: state.settings.database.pool_size,
        run_migrations: state.settings.database.run_migrations,
        supported_scopes: state.settings.oidc.supported_scopes.clone(),
        access_token_ttl_seconds: state.settings.oidc.access_token_ttl_seconds,
        id_token_ttl_seconds: state.settings.oidc.id_token_ttl_seconds,
        refresh_token_ttl_seconds: state.settings.oidc.refresh_token_ttl_seconds,
        cookie_secure: state.settings.security.cookie_secure,
        cookie_same_site: format!("{:?}", state.settings.security.cookie_same_site),
        cors_allowed_origins: state.settings.cors.allowed_origins.clone(),
    }))
}

async fn get_registration_settings(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<PublicRegistrationSettings>> {
    require_settings_manager(&state, &jar).await?;
    Ok(Json(state.db.registration_settings().await?.public()))
}

#[derive(Debug, Deserialize)]
struct RegistrationSettingsInput {
    allow_password_registration: bool,
    require_email_verification: bool,
    require_phone_verification: bool,
    allow_external_oidc_registration: bool,
    require_invitation: bool,
    first_user_direct_admin: bool,
    default_user_active: bool,
}

async fn update_registration_settings(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<RegistrationSettingsInput>,
) -> AppResult<Json<PublicRegistrationSettings>> {
    let current = require_settings_manager(&state, &jar).await?;
    let settings = state
        .db
        .upsert_registration_settings(NewRegistrationSettings {
            allow_password_registration: payload.allow_password_registration,
            require_email_verification: payload.require_email_verification,
            require_phone_verification: payload.require_phone_verification,
            allow_external_oidc_registration: payload.allow_external_oidc_registration,
            require_invitation: payload.require_invitation,
            first_user_direct_admin: payload.first_user_direct_admin
                || crate::db::FIRST_REGISTERED_USER_IS_ADMIN,
            default_user_active: payload.default_user_active,
        })
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "registration_settings.update",
            "registration_settings",
            Some("default".to_string()),
            serde_json::json!({ "require_invitation": payload.require_invitation }),
        ))
        .await?;
    Ok(Json(settings.public()))
}

#[derive(Debug, Deserialize)]
struct SecurityPolicyInput {
    password_min_length: i32,
    password_require_uppercase: bool,
    password_require_lowercase: bool,
    password_require_digit: bool,
    password_require_symbol: bool,
    password_reject_user_info: bool,
    login_lockout_enabled: bool,
    max_failed_login_attempts: i32,
    failure_window_seconds: i64,
    lockout_seconds: i64,
    #[serde(default)]
    trusted_ip_cidrs: Vec<String>,
    #[serde(default)]
    require_mfa_outside_trusted_networks: bool,
    #[serde(default)]
    allowed_ip_cidrs: Vec<String>,
    #[serde(default)]
    blocked_ip_cidrs: Vec<String>,
    #[serde(default)]
    allowed_email_domains: Vec<String>,
    #[serde(default)]
    blocked_email_domains: Vec<String>,
    #[serde(default)]
    captcha_enabled: bool,
    #[serde(default = "default_captcha_after_failed_attempts")]
    captcha_after_failed_attempts: i32,
    #[serde(default = "default_captcha_ttl_seconds")]
    captcha_ttl_seconds: i64,
}

fn default_captcha_after_failed_attempts() -> i32 {
    3
}

fn default_captcha_ttl_seconds() -> i64 {
    300
}

fn policy_from_input(payload: SecurityPolicyInput) -> AppResult<NewSecurityPolicy> {
    Ok(NewSecurityPolicy {
        password_min_length: payload.password_min_length,
        password_require_uppercase: payload.password_require_uppercase,
        password_require_lowercase: payload.password_require_lowercase,
        password_require_digit: payload.password_require_digit,
        password_require_symbol: payload.password_require_symbol,
        password_reject_user_info: payload.password_reject_user_info,
        login_lockout_enabled: payload.login_lockout_enabled,
        max_failed_login_attempts: payload.max_failed_login_attempts,
        failure_window_seconds: payload.failure_window_seconds,
        lockout_seconds: payload.lockout_seconds,
        trusted_ip_cidrs: network_policy::normalize_trusted_networks(payload.trusted_ip_cidrs)?,
        require_mfa_outside_trusted_networks: payload.require_mfa_outside_trusted_networks,
        allowed_ip_cidrs: network_policy::normalize_networks(
            payload.allowed_ip_cidrs,
            "allowed IP network",
        )?,
        blocked_ip_cidrs: network_policy::normalize_networks(
            payload.blocked_ip_cidrs,
            "blocked IP network",
        )?,
        allowed_email_domains: security_policy::normalize_email_domain_rules(
            payload.allowed_email_domains,
        )?,
        blocked_email_domains: security_policy::normalize_email_domain_rules(
            payload.blocked_email_domains,
        )?,
        captcha_enabled: payload.captcha_enabled,
        captcha_after_failed_attempts: payload.captcha_after_failed_attempts,
        captcha_ttl_seconds: payload.captcha_ttl_seconds,
    })
}

fn policy_record_for_validation(settings: &NewSecurityPolicy) -> AppResult<SecurityPolicyRecord> {
    Ok(SecurityPolicyRecord {
        id: "default".to_string(),
        password_min_length: settings.password_min_length,
        password_require_uppercase: i32::from(settings.password_require_uppercase),
        password_require_lowercase: i32::from(settings.password_require_lowercase),
        password_require_digit: i32::from(settings.password_require_digit),
        password_require_symbol: i32::from(settings.password_require_symbol),
        password_reject_user_info: i32::from(settings.password_reject_user_info),
        login_lockout_enabled: i32::from(settings.login_lockout_enabled),
        max_failed_login_attempts: settings.max_failed_login_attempts,
        failure_window_seconds: settings.failure_window_seconds,
        lockout_seconds: settings.lockout_seconds,
        trusted_ip_cidrs: util::to_json(&settings.trusted_ip_cidrs)?,
        require_mfa_outside_trusted_networks: i32::from(
            settings.require_mfa_outside_trusted_networks,
        ),
        allowed_ip_cidrs: util::to_json(&settings.allowed_ip_cidrs)?,
        blocked_ip_cidrs: util::to_json(&settings.blocked_ip_cidrs)?,
        allowed_email_domains: util::to_json(&settings.allowed_email_domains)?,
        blocked_email_domains: util::to_json(&settings.blocked_email_domains)?,
        captcha_enabled: i32::from(settings.captcha_enabled),
        captcha_after_failed_attempts: settings.captcha_after_failed_attempts,
        captcha_ttl_seconds: settings.captcha_ttl_seconds,
        updated_at: util::now_ts(),
    })
}

async fn get_security_policy(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<PublicSecurityPolicy>> {
    let current = auth::require_current_user(&state, &jar).await?;
    state
        .db
        .require_permission(&current.user, Permission::SecurityManage)
        .await?;
    state.db.security_policy().await?.public().map(Json)
}

async fn update_security_policy(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<SecurityPolicyInput>,
) -> AppResult<Json<PublicSecurityPolicy>> {
    let current = auth::require_current_user(&state, &jar).await?;
    state
        .db
        .require_permission(&current.user, Permission::SecurityManage)
        .await?;
    let next = policy_from_input(payload)?;
    let record = policy_record_for_validation(&next)?;
    security_policy::validate_policy_input(&record)?;
    let settings = state.db.upsert_security_policy(next).await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "security_policy.update",
            "security_policy",
            Some("default".to_string()),
            serde_json::json!({
                "trusted_ip_cidrs": settings.public()?.trusted_ip_cidrs,
                "require_mfa_outside_trusted_networks": settings.require_mfa_outside_trusted_networks == 1,
                "allowed_ip_cidrs": settings.public()?.allowed_ip_cidrs,
                "blocked_ip_cidrs": settings.public()?.blocked_ip_cidrs,
                "allowed_email_domains": settings.public()?.allowed_email_domains,
                "blocked_email_domains": settings.public()?.blocked_email_domains,
                "captcha_enabled": settings.captcha_enabled == 1,
                "captcha_after_failed_attempts": settings.captcha_after_failed_attempts,
                "captcha_ttl_seconds": settings.captcha_ttl_seconds
            }),
        ))
        .await?;
    settings.public().map(Json)
}

#[derive(Debug, Serialize)]
struct SigningKeyResponse {
    id: String,
    kid: String,
    is_active: bool,
    created_at: i64,
    activated_at: Option<i64>,
    retired_at: Option<i64>,
}

impl From<SigningKeyRecord> for SigningKeyResponse {
    fn from(record: SigningKeyRecord) -> Self {
        Self {
            id: record.id,
            kid: record.kid,
            is_active: record.is_active == 1,
            created_at: record.created_at,
            activated_at: record.activated_at,
            retired_at: record.retired_at,
        }
    }
}

#[derive(Debug, Deserialize)]
struct RotateSigningKeyInput {
    kid: Option<String>,
}

async fn list_signing_keys(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<Vec<SigningKeyResponse>>> {
    require_security_manager(&state, &jar).await?;
    let keys = state
        .db
        .list_signing_keys()
        .await?
        .into_iter()
        .map(SigningKeyResponse::from)
        .collect();
    Ok(Json(keys))
}

async fn rotate_signing_key(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<RotateSigningKeyInput>,
) -> AppResult<Json<SigningKeyResponse>> {
    let current = require_security_manager(&state, &jar).await?;
    let key = state.db.rotate_signing_key(payload.kid).await?;
    let keys = state.db.list_signing_keys().await?;
    state.jwt.reload(keys)?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "signing_key.rotate",
            "signing_key",
            Some(key.id.clone()),
            serde_json::json!({ "kid": key.kid.clone() }),
        ))
        .await?;
    Ok(Json(SigningKeyResponse::from(key)))
}

#[derive(Debug, Serialize)]
struct RuntimeSettingsResponse {
    public_base_url: String,
    issuer: String,
    trust_proxy_headers: bool,
    effective_public_base_url: String,
    effective_issuer: String,
    updated_at: i64,
}

#[derive(Debug, Deserialize)]
struct RuntimeSettingsInput {
    public_base_url: String,
    issuer: Option<String>,
    trust_proxy_headers: bool,
}

async fn get_runtime_settings(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> AppResult<Json<RuntimeSettingsResponse>> {
    require_settings_manager(&state, &jar).await?;
    runtime_settings_response(&state, &headers).await.map(Json)
}

async fn update_runtime_settings(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(payload): Json<RuntimeSettingsInput>,
) -> AppResult<Json<RuntimeSettingsResponse>> {
    let current = require_settings_manager(&state, &jar).await?;
    let public_base_url = normalize_base_url(&payload.public_base_url, "public_base_url")?;
    let issuer = match payload
        .issuer
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(value) => normalize_base_url(value, "issuer")?,
        None => public_base_url.clone(),
    };
    state
        .db
        .upsert_runtime_settings(NewRuntimeSettings {
            public_base_url: public_base_url.clone(),
            issuer: issuer.clone(),
            trust_proxy_headers: payload.trust_proxy_headers,
        })
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "runtime_settings.update",
            "runtime_settings",
            Some("default".to_string()),
            serde_json::json!({ "public_base_url": public_base_url, "issuer": issuer }),
        ))
        .await?;
    runtime_settings_response(&state, &headers).await.map(Json)
}

async fn runtime_settings_response(
    state: &AppState,
    headers: &HeaderMap,
) -> AppResult<RuntimeSettingsResponse> {
    let runtime = state.runtime_settings().await?;
    Ok(RuntimeSettingsResponse {
        public_base_url: runtime.public_base_url,
        issuer: runtime.issuer,
        trust_proxy_headers: runtime.trust_proxy_headers == 1,
        effective_public_base_url: state.effective_public_base_url(headers).await?,
        effective_issuer: state.effective_issuer(headers).await?,
        updated_at: runtime.updated_at,
    })
}

#[derive(Debug, Deserialize)]
struct LoginSettingsInput {
    email_domains: Vec<String>,
    quick_links: Vec<QuickLink>,
}

async fn get_login_settings(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<PublicLoginSettings>> {
    require_settings_manager(&state, &jar).await?;
    state.db.login_settings().await?.public().map(Json)
}

async fn update_login_settings(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<LoginSettingsInput>,
) -> AppResult<Json<PublicLoginSettings>> {
    let current = require_settings_manager(&state, &jar).await?;
    let quick_link_count = payload.quick_links.len();
    let settings = state
        .db
        .upsert_login_settings(NewLoginSettings {
            email_domains: normalize_email_domains(payload.email_domains)?,
            quick_links: normalize_quick_links(payload.quick_links)?,
        })
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "login_settings.update",
            "login_settings",
            Some("default".to_string()),
            serde_json::json!({ "quick_links": quick_link_count }),
        ))
        .await?;
    settings.public().map(Json)
}

fn normalize_base_url(value: &str, field: &str) -> AppResult<String> {
    let value = value.trim().trim_end_matches('/').to_string();
    let url = Url::parse(&value)
        .map_err(|err| AppError::BadRequest(format!("{field} is invalid: {err}")))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(AppError::BadRequest(format!(
            "{field} must be an absolute http(s) URL"
        )));
    }
    Ok(value)
}

fn normalize_email_domains(values: Vec<String>) -> AppResult<Vec<String>> {
    security_policy::normalize_email_domain_rules(values)
}

fn normalize_quick_links(values: Vec<QuickLink>) -> AppResult<Vec<QuickLink>> {
    let mut links = Vec::new();
    let mut ids = BTreeSet::new();
    for value in values {
        let label = value.label.trim();
        let url = value.url.trim();
        if label.is_empty() && url.is_empty() {
            continue;
        }
        if label.is_empty() {
            return Err(AppError::BadRequest(
                "quick link label is required".to_string(),
            ));
        }
        let parsed = Url::parse(url)
            .map_err(|err| AppError::BadRequest(format!("quick link url is invalid: {err}")))?;
        if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
            return Err(AppError::BadRequest(
                "quick link url must be an absolute http(s) URL".to_string(),
            ));
        }
        let id = value
            .id
            .trim()
            .chars()
            .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '-' || *ch == '_')
            .collect::<String>();
        let id = if id.is_empty() {
            uuid::Uuid::new_v4().to_string()
        } else {
            id
        };
        if !ids.insert(id.clone()) {
            return Err(AppError::BadRequest(
                "quick link id must be unique".to_string(),
            ));
        }
        let icon = value
            .icon
            .trim()
            .chars()
            .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '-' || *ch == '_')
            .collect::<String>();
        links.push(QuickLink {
            id,
            label: label.chars().take(48).collect(),
            url: url.to_string(),
            icon: if icon.is_empty() {
                "link".to_string()
            } else {
                icon
            },
            is_active: value.is_active,
        });
    }
    Ok(links)
}

fn normalize_optional_text(value: Option<String>) -> Option<String> {
    value
        .map(|item| item.trim().to_string())
        .filter(|item| !item.is_empty())
}

fn normalize_optional_email(value: Option<String>) -> AppResult<Option<String>> {
    let Some(value) = normalize_optional_text(value) else {
        return Ok(None);
    };
    let email = value.to_ascii_lowercase();
    if !email.contains('@') || email.ends_with('@') {
        return Err(AppError::BadRequest("email is invalid".to_string()));
    }
    Ok(Some(email))
}

#[derive(Debug, Deserialize)]
struct UserListQuery {
    status: Option<String>,
}

async fn list_users(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<UserListQuery>,
) -> AppResult<Json<Vec<PublicUser>>> {
    require_user_reader(&state, &jar).await?;
    let scope = user_list_scope(query.status.as_deref())?;
    let users = state
        .db
        .list_users(scope)
        .await?
        .into_iter()
        .map(|user| user.public())
        .collect();
    Ok(Json(users))
}

fn user_list_scope(status: Option<&str>) -> AppResult<UserListScope> {
    match status.unwrap_or("live") {
        "live" => Ok(UserListScope::Live),
        "active" => Ok(UserListScope::Active),
        "disabled" => Ok(UserListScope::Disabled),
        "archived" => Ok(UserListScope::Archived),
        "all" => Ok(UserListScope::All),
        other => Err(AppError::BadRequest(format!(
            "unsupported user status filter: {other}"
        ))),
    }
}

#[derive(Debug, Serialize)]
struct UserDetailResponse {
    user: PublicUser,
    login_events: Vec<LoginEventRecord>,
    linked_identities: Vec<LinkedIdentityRecord>,
    organizations: Vec<UserOrganizationRecord>,
}

async fn user_detail(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<UserDetailResponse>> {
    require_user_reader(&state, &jar).await?;
    let user = state
        .db
        .find_user_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    let login_events = state.db.list_login_events(&id, 20).await?;
    let linked_identities = state.db.list_linked_identities(&id).await?;
    let organizations = state.db.list_user_organizations(&id).await?;
    Ok(Json(UserDetailResponse {
        user: user.public(),
        login_events,
        linked_identities,
        organizations,
    }))
}

async fn user_login_events(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<Vec<LoginEventRecord>>> {
    require_user_reader(&state, &jar).await?;
    Ok(Json(state.db.list_login_events(&id, 100).await?))
}

async fn user_permissions(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<Vec<String>>> {
    require_user_reader(&state, &jar).await?;
    state
        .db
        .find_user_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(state.db.list_effective_permissions(&id).await?))
}

async fn list_audit_events(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<Vec<AuditEventRecord>>> {
    let current = auth::require_current_user(&state, &jar).await?;
    state
        .db
        .require_permission(&current.user, Permission::AuditRead)
        .await?;
    Ok(Json(state.db.list_audit_events(200).await?))
}

async fn list_audit_webhooks(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<Vec<PublicAuditWebhook>>> {
    let current = auth::require_current_user(&state, &jar).await?;
    state
        .db
        .require_any_permission(
            &current.user,
            &[Permission::AuditRead, Permission::SecurityManage],
        )
        .await?;
    let webhooks = state
        .db
        .list_audit_webhooks()
        .await?
        .into_iter()
        .map(|record| record.public())
        .collect::<AppResult<Vec<_>>>()?;
    Ok(Json(webhooks))
}

async fn create_audit_webhook(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<webhooks::AuditWebhookInput>,
) -> AppResult<Json<PublicAuditWebhook>> {
    let current = auth::require_current_user(&state, &jar).await?;
    state
        .db
        .require_permission(&current.user, Permission::SecurityManage)
        .await?;
    let webhook = state
        .db
        .insert_audit_webhook(webhooks::new_webhook(payload)?)
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "audit_webhook.create",
            "audit_webhook",
            Some(webhook.id.clone()),
            serde_json::json!({ "name": webhook.name.clone(), "url": webhook.url.clone() }),
        ))
        .await?;
    Ok(Json(webhook.public()?))
}

async fn update_audit_webhook(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<webhooks::AuditWebhookInput>,
) -> AppResult<Json<PublicAuditWebhook>> {
    let current = auth::require_current_user(&state, &jar).await?;
    state
        .db
        .require_permission(&current.user, Permission::SecurityManage)
        .await?;
    let webhook = state
        .db
        .update_audit_webhook(&id, webhooks::update_webhook(payload)?)
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "audit_webhook.update",
            "audit_webhook",
            Some(webhook.id.clone()),
            serde_json::json!({ "name": webhook.name.clone(), "url": webhook.url.clone() }),
        ))
        .await?;
    Ok(Json(webhook.public()?))
}

async fn delete_audit_webhook(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let current = auth::require_current_user(&state, &jar).await?;
    state
        .db
        .require_permission(&current.user, Permission::SecurityManage)
        .await?;
    let webhook = state
        .db
        .find_audit_webhook(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    state.db.delete_audit_webhook(&id).await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "audit_webhook.delete",
            "audit_webhook",
            Some(id),
            serde_json::json!({ "name": webhook.name, "url": webhook.url }),
        ))
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

#[derive(Debug, Serialize)]
struct RoleAccessResponse {
    id: String,
    name: String,
    description: Option<String>,
    is_system: i32,
    permissions: Vec<String>,
    created_at: i64,
    updated_at: i64,
}

#[derive(Debug, Serialize)]
struct GroupAccessResponse {
    id: String,
    name: String,
    description: Option<String>,
    roles: Vec<RoleRecord>,
    members: Vec<PublicUser>,
    created_at: i64,
    updated_at: i64,
}

#[derive(Debug, Serialize)]
struct OrganizationResponse {
    id: String,
    slug: String,
    name: String,
    description: Option<String>,
    allowed_email_domains: Vec<String>,
    is_active: bool,
    members: Vec<OrganizationMemberResponse>,
    created_at: i64,
    updated_at: i64,
}

#[derive(Debug, Serialize)]
struct OrganizationMemberResponse {
    organization_id: String,
    user_id: String,
    role: String,
    email: String,
    username: String,
    display_name: Option<String>,
    is_active: bool,
    archived_at: Option<i64>,
    created_at: i64,
    updated_at: i64,
}

#[derive(Debug, Serialize)]
struct UserAccessResponse {
    direct_roles: Vec<RoleRecord>,
    groups: Vec<GroupRecord>,
    effective_permissions: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RoleInput {
    name: String,
    description: Option<String>,
    permissions: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct GroupInput {
    name: String,
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OrganizationInput {
    slug: String,
    name: String,
    description: Option<String>,
    #[serde(default)]
    allowed_email_domains: Vec<String>,
    is_active: bool,
}

#[derive(Debug, Deserialize)]
struct OrganizationMemberPayload {
    user_id: String,
    role: String,
}

#[derive(Debug, Deserialize)]
struct OrganizationMembersInput {
    members: Vec<OrganizationMemberPayload>,
}

#[derive(Debug, Deserialize)]
struct RoleIdsInput {
    role_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct UserIdsInput {
    user_ids: Vec<String>,
}

const ADMIN_READ_PERMISSIONS: &[Permission] = &[
    Permission::AdminRead,
    Permission::SettingsManage,
    Permission::UsersRead,
    Permission::UsersManage,
    Permission::ClientsRead,
    Permission::ClientsManage,
    Permission::IapRead,
    Permission::IapManage,
    Permission::OrganizationsRead,
    Permission::OrganizationsManage,
    Permission::AuthorizationCodesManage,
    Permission::ProvidersManage,
    Permission::AuditRead,
    Permission::SecurityManage,
];

const USER_READ_PERMISSIONS: &[Permission] = &[
    Permission::UsersRead,
    Permission::UsersManage,
    Permission::OrganizationsManage,
    Permission::SecurityManage,
];
const CLIENT_READ_PERMISSIONS: &[Permission] =
    &[Permission::ClientsRead, Permission::ClientsManage];
const IAP_READ_PERMISSIONS: &[Permission] = &[Permission::IapRead, Permission::IapManage];
const ORGANIZATION_READ_PERMISSIONS: &[Permission] = &[
    Permission::OrganizationsRead,
    Permission::OrganizationsManage,
    Permission::ClientsManage,
    Permission::ProvidersManage,
];

async fn require_admin_reader(state: &AppState, jar: &CookieJar) -> AppResult<auth::CurrentUser> {
    require_any_permission(state, jar, ADMIN_READ_PERMISSIONS).await
}

async fn require_settings_manager(
    state: &AppState,
    jar: &CookieJar,
) -> AppResult<auth::CurrentUser> {
    require_permission(state, jar, Permission::SettingsManage).await
}

async fn require_user_reader(state: &AppState, jar: &CookieJar) -> AppResult<auth::CurrentUser> {
    require_any_permission(state, jar, USER_READ_PERMISSIONS).await
}

async fn require_user_manager(state: &AppState, jar: &CookieJar) -> AppResult<auth::CurrentUser> {
    require_permission(state, jar, Permission::UsersManage).await
}

async fn require_client_reader(state: &AppState, jar: &CookieJar) -> AppResult<auth::CurrentUser> {
    require_any_permission(state, jar, CLIENT_READ_PERMISSIONS).await
}

async fn require_client_manager(state: &AppState, jar: &CookieJar) -> AppResult<auth::CurrentUser> {
    require_permission(state, jar, Permission::ClientsManage).await
}

async fn require_iap_reader(state: &AppState, jar: &CookieJar) -> AppResult<auth::CurrentUser> {
    require_any_permission(state, jar, IAP_READ_PERMISSIONS).await
}

async fn require_iap_manager(state: &AppState, jar: &CookieJar) -> AppResult<auth::CurrentUser> {
    require_permission(state, jar, Permission::IapManage).await
}

async fn require_authorization_code_manager(
    state: &AppState,
    jar: &CookieJar,
) -> AppResult<auth::CurrentUser> {
    require_permission(state, jar, Permission::AuthorizationCodesManage).await
}

async fn require_provider_manager(
    state: &AppState,
    jar: &CookieJar,
) -> AppResult<auth::CurrentUser> {
    require_permission(state, jar, Permission::ProvidersManage).await
}

async fn require_security_manager(
    state: &AppState,
    jar: &CookieJar,
) -> AppResult<auth::CurrentUser> {
    require_permission(state, jar, Permission::SecurityManage).await
}

async fn require_organization_reader(
    state: &AppState,
    jar: &CookieJar,
) -> AppResult<auth::CurrentUser> {
    require_any_permission(state, jar, ORGANIZATION_READ_PERMISSIONS).await
}

async fn require_organization_manager(
    state: &AppState,
    jar: &CookieJar,
) -> AppResult<auth::CurrentUser> {
    require_permission(state, jar, Permission::OrganizationsManage).await
}

async fn require_permission(
    state: &AppState,
    jar: &CookieJar,
    permission: Permission,
) -> AppResult<auth::CurrentUser> {
    let current = auth::require_current_user(state, jar).await?;
    state
        .db
        .require_permission(&current.user, permission)
        .await?;
    Ok(current)
}

async fn require_any_permission(
    state: &AppState,
    jar: &CookieJar,
    permissions: &[Permission],
) -> AppResult<auth::CurrentUser> {
    let current = auth::require_current_user(state, jar).await?;
    state
        .db
        .require_any_permission(&current.user, permissions)
        .await?;
    Ok(current)
}

async fn role_response(state: &AppState, role: RoleRecord) -> AppResult<RoleAccessResponse> {
    let permissions = state.db.list_role_permissions(&role.id).await?;
    Ok(RoleAccessResponse {
        id: role.id,
        name: role.name,
        description: role.description,
        is_system: role.is_system,
        permissions,
        created_at: role.created_at,
        updated_at: role.updated_at,
    })
}

async fn group_response(state: &AppState, group: GroupRecord) -> AppResult<GroupAccessResponse> {
    let roles = state.db.list_group_roles(&group.id).await?;
    let members = state
        .db
        .list_group_members(&group.id)
        .await?
        .into_iter()
        .map(|user| user.public())
        .collect();
    Ok(GroupAccessResponse {
        id: group.id,
        name: group.name,
        description: group.description,
        roles,
        members,
        created_at: group.created_at,
        updated_at: group.updated_at,
    })
}

async fn organization_response(
    state: &AppState,
    organization: OrganizationRecord,
) -> AppResult<OrganizationResponse> {
    let members = state
        .db
        .list_organization_members(&organization.id)
        .await?
        .into_iter()
        .map(organization_member_response)
        .collect();
    Ok(OrganizationResponse {
        id: organization.id,
        slug: organization.slug,
        name: organization.name,
        description: organization.description,
        allowed_email_domains: security_policy::normalize_email_domain_rules(util::from_json::<
            Vec<String>,
        >(
            &organization.allowed_email_domains,
        )?)?,
        is_active: organization.is_active == 1,
        members,
        created_at: organization.created_at,
        updated_at: organization.updated_at,
    })
}

fn organization_member_response(
    member: OrganizationMemberWithUserRecord,
) -> OrganizationMemberResponse {
    OrganizationMemberResponse {
        organization_id: member.organization_id,
        user_id: member.user_id,
        role: member.role,
        email: member.email,
        username: member.username,
        display_name: member.display_name,
        is_active: member.is_active == 1,
        archived_at: member.archived_at,
        created_at: member.membership_created_at,
        updated_at: member.membership_updated_at,
    }
}

fn organization_input_to_new(input: OrganizationInput) -> AppResult<NewOrganization> {
    Ok(NewOrganization {
        slug: organizations::normalize_slug(&input.slug)?,
        name: organizations::normalize_name(&input.name)?,
        description: normalize_optional_text(input.description),
        allowed_email_domains: security_policy::normalize_email_domain_rules(
            input.allowed_email_domains,
        )?,
        is_active: input.is_active,
    })
}

fn organization_members_input(
    input: OrganizationMembersInput,
) -> AppResult<Vec<OrganizationMemberInput>> {
    input
        .members
        .into_iter()
        .map(|member| {
            Ok(OrganizationMemberInput {
                user_id: member.user_id,
                role: organizations::normalize_role(&member.role)?,
            })
        })
        .collect()
}

async fn list_permissions(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<Vec<PermissionInfo>>> {
    require_security_manager(&state, &jar).await?;
    Ok(Json(permission_catalog()))
}

async fn list_roles(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<Vec<RoleAccessResponse>>> {
    require_security_manager(&state, &jar).await?;
    let roles = state.db.list_roles().await?;
    let mut response = Vec::with_capacity(roles.len());
    for role in roles {
        response.push(role_response(&state, role).await?);
    }
    Ok(Json(response))
}

async fn create_role(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<RoleInput>,
) -> AppResult<Json<RoleAccessResponse>> {
    let current = require_security_manager(&state, &jar).await?;
    let role = state
        .db
        .insert_role(NewRole {
            name: payload.name,
            description: payload.description,
            is_system: false,
            permissions: payload.permissions,
        })
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "role.create",
            "role",
            Some(role.id.clone()),
            serde_json::json!({ "name": role.name.clone() }),
        ))
        .await?;
    Ok(Json(role_response(&state, role).await?))
}

async fn update_role(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<RoleInput>,
) -> AppResult<Json<RoleAccessResponse>> {
    let current = require_security_manager(&state, &jar).await?;
    let role = state
        .db
        .update_role(
            &id,
            NewRole {
                name: payload.name,
                description: payload.description,
                is_system: false,
                permissions: payload.permissions,
            },
        )
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "role.update",
            "role",
            Some(role.id.clone()),
            serde_json::json!({ "name": role.name.clone() }),
        ))
        .await?;
    Ok(Json(role_response(&state, role).await?))
}

async fn delete_role(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let current = require_security_manager(&state, &jar).await?;
    let role = state
        .db
        .find_role_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    state.db.delete_role(&id).await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "role.delete",
            "role",
            Some(id),
            serde_json::json!({ "name": role.name }),
        ))
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn list_groups(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<Vec<GroupAccessResponse>>> {
    require_security_manager(&state, &jar).await?;
    let groups = state.db.list_groups().await?;
    let mut response = Vec::with_capacity(groups.len());
    for group in groups {
        response.push(group_response(&state, group).await?);
    }
    Ok(Json(response))
}

async fn create_group(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<GroupInput>,
) -> AppResult<Json<GroupAccessResponse>> {
    let current = require_security_manager(&state, &jar).await?;
    let group = state
        .db
        .insert_group(NewGroup {
            name: payload.name,
            description: payload.description,
        })
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "group.create",
            "group",
            Some(group.id.clone()),
            serde_json::json!({ "name": group.name.clone() }),
        ))
        .await?;
    Ok(Json(group_response(&state, group).await?))
}

async fn update_group(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<GroupInput>,
) -> AppResult<Json<GroupAccessResponse>> {
    let current = require_security_manager(&state, &jar).await?;
    let group = state
        .db
        .update_group(
            &id,
            NewGroup {
                name: payload.name,
                description: payload.description,
            },
        )
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "group.update",
            "group",
            Some(group.id.clone()),
            serde_json::json!({ "name": group.name.clone() }),
        ))
        .await?;
    Ok(Json(group_response(&state, group).await?))
}

async fn delete_group(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let current = require_security_manager(&state, &jar).await?;
    let group = state
        .db
        .find_group_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    state.db.delete_group(&id).await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "group.delete",
            "group",
            Some(id),
            serde_json::json!({ "name": group.name }),
        ))
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn update_group_roles(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<RoleIdsInput>,
) -> AppResult<Json<GroupAccessResponse>> {
    let current = require_security_manager(&state, &jar).await?;
    state
        .db
        .replace_group_roles(&id, payload.role_ids.clone())
        .await?;
    let group = state
        .db
        .find_group_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "group.roles.update",
            "group",
            Some(id),
            serde_json::json!({ "role_ids": payload.role_ids }),
        ))
        .await?;
    Ok(Json(group_response(&state, group).await?))
}

async fn update_group_members(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<UserIdsInput>,
) -> AppResult<Json<GroupAccessResponse>> {
    let current = require_security_manager(&state, &jar).await?;
    state
        .db
        .find_group_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    ensure_group_members_editable(&state, &id, &payload.user_ids).await?;
    state
        .db
        .replace_group_members(&id, payload.user_ids.clone())
        .await?;
    let group = state
        .db
        .find_group_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "group.members.update",
            "group",
            Some(id),
            serde_json::json!({ "user_ids": payload.user_ids }),
        ))
        .await?;
    Ok(Json(group_response(&state, group).await?))
}

async fn list_organizations(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<Vec<OrganizationResponse>>> {
    require_organization_reader(&state, &jar).await?;
    let mut response = Vec::new();
    for organization in state.db.list_organizations().await? {
        response.push(organization_response(&state, organization).await?);
    }
    Ok(Json(response))
}

async fn create_organization(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<OrganizationInput>,
) -> AppResult<Json<OrganizationResponse>> {
    let current = require_organization_manager(&state, &jar).await?;
    let organization = state
        .db
        .insert_organization(organization_input_to_new(payload)?)
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "organization.create",
            "organization",
            Some(organization.id.clone()),
            serde_json::json!({ "slug": organization.slug.clone(), "name": organization.name.clone() }),
        ))
        .await?;
    Ok(Json(organization_response(&state, organization).await?))
}

async fn update_organization(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<OrganizationInput>,
) -> AppResult<Json<OrganizationResponse>> {
    let current = require_organization_manager(&state, &jar).await?;
    let organization = state
        .db
        .update_organization(&id, organization_input_to_new(payload)?)
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "organization.update",
            "organization",
            Some(organization.id.clone()),
            serde_json::json!({ "slug": organization.slug.clone(), "name": organization.name.clone() }),
        ))
        .await?;
    Ok(Json(organization_response(&state, organization).await?))
}

async fn delete_organization(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let current = require_organization_manager(&state, &jar).await?;
    let organization = state
        .db
        .find_organization_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    state.db.delete_organization(&id).await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "organization.delete",
            "organization",
            Some(id),
            serde_json::json!({ "slug": organization.slug, "name": organization.name }),
        ))
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn update_organization_members(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<OrganizationMembersInput>,
) -> AppResult<Json<OrganizationResponse>> {
    let current = require_organization_manager(&state, &jar).await?;
    let members = organization_members_input(payload)?;
    state
        .db
        .find_organization_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    ensure_organization_members_editable(&state, &id, &members).await?;
    state
        .db
        .replace_organization_members(&id, members.clone())
        .await?;
    let organization = state
        .db
        .find_organization_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "organization.members.update",
            "organization",
            Some(id),
            serde_json::json!({ "members": members.into_iter().map(|member| serde_json::json!({ "user_id": member.user_id, "role": member.role })).collect::<Vec<_>>() }),
        ))
        .await?;
    Ok(Json(organization_response(&state, organization).await?))
}

async fn user_access(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<UserAccessResponse>> {
    require_security_manager(&state, &jar).await?;
    state
        .db
        .find_user_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(UserAccessResponse {
        direct_roles: state.db.list_user_roles(&id).await?,
        groups: state.db.list_user_groups(&id).await?,
        effective_permissions: state.db.list_effective_permissions(&id).await?,
    }))
}

async fn update_user_roles(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<RoleIdsInput>,
) -> AppResult<Json<UserAccessResponse>> {
    let current = require_security_manager(&state, &jar).await?;
    ensure_user_editable(&state, &id).await?;
    state
        .db
        .replace_user_roles(&id, payload.role_ids.clone())
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "user.roles.update",
            "user",
            Some(id.clone()),
            serde_json::json!({ "role_ids": payload.role_ids }),
        ))
        .await?;
    Ok(Json(UserAccessResponse {
        direct_roles: state.db.list_user_roles(&id).await?,
        groups: state.db.list_user_groups(&id).await?,
        effective_permissions: state.db.list_effective_permissions(&id).await?,
    }))
}

#[derive(Debug, Deserialize)]
struct UserInput {
    email: String,
    username: String,
    display_name: Option<String>,
    phone: Option<String>,
    password: Option<String>,
    is_admin: bool,
    is_active: bool,
}

#[derive(Debug)]
struct NormalizedUserInput {
    email: String,
    username: String,
    display_name: Option<String>,
    phone: Option<String>,
    password: Option<String>,
    is_admin: bool,
    is_active: bool,
}

fn normalize_user_input(input: UserInput) -> AppResult<NormalizedUserInput> {
    Ok(NormalizedUserInput {
        email: normalize_required_email(input.email)?,
        username: normalize_required_text(input.username, "username")?,
        display_name: normalize_optional_text(input.display_name),
        phone: normalize_optional_text(input.phone),
        password: normalize_optional_text(input.password),
        is_admin: input.is_admin,
        is_active: input.is_active,
    })
}

fn normalize_required_email(value: String) -> AppResult<String> {
    let email = value.trim().to_ascii_lowercase();
    if !email.contains('@') || email.ends_with('@') {
        return Err(AppError::BadRequest("email is invalid".to_string()));
    }
    Ok(email)
}

fn normalize_required_text(value: String, field: &str) -> AppResult<String> {
    let value = value.trim().to_string();
    if value.is_empty() {
        Err(AppError::BadRequest(format!("{field} is required")))
    } else {
        Ok(value)
    }
}

async fn validate_password_for_subject(
    state: &AppState,
    password: &str,
    email: &str,
    username: &str,
) -> AppResult<()> {
    state
        .db
        .security_policy()
        .await?
        .validate_password(password, PasswordSubject { email, username })
}

async fn create_user(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<UserInput>,
) -> AppResult<Json<PublicUser>> {
    let current = require_user_manager(&state, &jar).await?;
    let payload = normalize_user_input(payload)?;
    let password = payload
        .password
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("password is required".to_string()))?;
    validate_password_for_subject(&state, password, &payload.email, &payload.username).await?;
    let user = state
        .db
        .insert_user(NewUser {
            email: payload.email,
            username: payload.username,
            display_name: payload.display_name,
            phone: payload.phone,
            password_hash: util::hash_password(password)?,
            email_verified_at: Some(util::now_ts()),
            phone_verified_at: None,
            is_admin: payload.is_admin,
            is_active: payload.is_active,
            archived_at: None,
        })
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "user.create",
            "user",
            Some(user.id.clone()),
            serde_json::json!({ "email": user.email.clone() }),
        ))
        .await?;
    Ok(Json(user.public()))
}

async fn update_user(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<UserInput>,
) -> AppResult<Json<PublicUser>> {
    let current = require_user_manager(&state, &jar).await?;
    let target = ensure_user_editable(&state, &id).await?;
    let payload = normalize_user_input(payload)?;
    ensure_account_metadata_update_allowed(
        &current.user,
        &target,
        payload.is_admin,
        payload.is_active,
    )?;
    if let Some(password) = payload.password.as_deref() {
        validate_password_for_subject(&state, password, &payload.email, &payload.username).await?;
    }
    let user = state
        .db
        .update_user(
            &id,
            payload.email,
            payload.username,
            payload.display_name,
            payload.phone,
            payload.is_admin,
            payload.is_active,
        )
        .await?;
    if let Some(password) = payload.password {
        state
            .db
            .set_user_password(&id, util::hash_password(&password)?)
            .await?;
    }
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "user.update",
            "user",
            Some(id),
            serde_json::json!({ "email": user.email.clone() }),
        ))
        .await?;
    Ok(Json(user.public()))
}

async fn delete_user(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let current = require_user_manager(&state, &jar).await?;
    if current.user.id == id {
        return Err(AppError::BadRequest(
            "administrator cannot change their own account lifecycle".to_string(),
        ));
    }
    let target = state
        .db
        .find_user_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    let action = if target.archived_at.is_some() {
        state.db.permanently_delete_user(&id).await?;
        "deleted"
    } else if target.is_active == 1 {
        state.db.disable_user(&id).await?;
        "disabled"
    } else {
        state.db.archive_user(&id).await?;
        "archived"
    };
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            format!("user.{action}"),
            "user",
            Some(id),
            serde_json::json!({ "email": target.email }),
        ))
        .await?;
    Ok(Json(serde_json::json!({ "ok": true, "action": action })))
}

async fn enable_user(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<PublicUser>> {
    let current = require_user_manager(&state, &jar).await?;
    state
        .db
        .find_user_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    state.db.enable_user(&id).await?;
    let user = state
        .db
        .find_user_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "user.enable",
            "user",
            Some(id),
            serde_json::json!({ "email": user.email.clone() }),
        ))
        .await?;
    Ok(Json(user.public()))
}

#[derive(Debug, Deserialize)]
struct PasswordInput {
    password: String,
}

async fn set_user_password(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<PasswordInput>,
) -> AppResult<Json<serde_json::Value>> {
    let current = require_user_manager(&state, &jar).await?;
    ensure_user_editable(&state, &id).await?;
    let user = state
        .db
        .find_user_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    validate_password_for_subject(&state, &payload.password, &user.email, &user.username).await?;
    state
        .db
        .set_user_password(&id, util::hash_password(&payload.password)?)
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "user.password.set",
            "user",
            Some(id),
            serde_json::json!({}),
        ))
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn reset_user_mfa(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<MfaStatusResponse>> {
    let current = require_user_manager(&state, &jar).await?;
    ensure_user_editable(&state, &id).await?;
    state
        .db
        .find_user_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    state.db.delete_mfa_for_user(&id).await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "mfa.admin_reset",
            "user",
            Some(id.clone()),
            serde_json::json!({}),
        ))
        .await?;
    Ok(Json(mfa_status_for_user(&state, &id).await?))
}

async fn ensure_user_editable(state: &AppState, id: &str) -> AppResult<crate::db::UserRecord> {
    let user = state
        .db
        .find_user_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;
    archived_accounts::ensure_user_record_editable(&user)?;
    Ok(user)
}

fn ensure_account_metadata_update_allowed(
    current: &crate::db::UserRecord,
    target: &crate::db::UserRecord,
    next_is_admin: bool,
    next_is_active: bool,
) -> AppResult<()> {
    if target.is_active != i32::from(next_is_active) {
        return Err(AppError::BadRequest(
            "use lifecycle actions to change account status".to_string(),
        ));
    }
    if current.id == target.id && target.is_admin != i32::from(next_is_admin) {
        return Err(AppError::BadRequest(
            "administrator cannot change their own administrator role".to_string(),
        ));
    }
    Ok(())
}

async fn ensure_group_members_editable(
    state: &AppState,
    group_id: &str,
    requested_user_ids: &[String],
) -> AppResult<()> {
    let existing_members = state.db.list_group_members(group_id).await?;
    let requested_user_ids = archived_accounts::normalize_user_ids(requested_user_ids);
    let allowed_archived_user_ids = archived_accounts::ensure_archived_group_members_preserved(
        &existing_members,
        &requested_user_ids,
    )?;
    ensure_assignable_user_ids(
        state,
        &requested_user_ids,
        &allowed_archived_user_ids,
        "groups",
    )
    .await
}

async fn ensure_organization_members_editable(
    state: &AppState,
    organization_id: &str,
    requested_members: &[OrganizationMemberInput],
) -> AppResult<()> {
    let existing_members = state.db.list_organization_members(organization_id).await?;
    let requested_roles = archived_accounts::normalize_organization_member_roles(requested_members);
    let allowed_archived_user_ids =
        archived_accounts::ensure_archived_organization_members_preserved(
            &existing_members,
            &requested_roles,
        )?;
    let requested_user_ids = requested_roles.into_keys().collect::<BTreeSet<_>>();
    ensure_assignable_user_ids(
        state,
        &requested_user_ids,
        &allowed_archived_user_ids,
        "organizations",
    )
    .await
}

async fn ensure_assignable_user_ids(
    state: &AppState,
    requested_user_ids: &BTreeSet<String>,
    allowed_archived_user_ids: &BTreeSet<String>,
    target: &str,
) -> AppResult<()> {
    for user_id in requested_user_ids {
        let user = state
            .db
            .find_user_by_id(user_id)
            .await?
            .ok_or_else(|| AppError::BadRequest(format!("unknown user: {user_id}")))?;
        archived_accounts::ensure_assignable_user_record(&user, allowed_archived_user_ids, target)?;
    }
    Ok(())
}

async fn list_clients(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<Vec<PublicClient>>> {
    require_client_reader(&state, &jar).await?;
    let mut clients = Vec::new();
    for client in state.db.list_clients().await? {
        clients.push(public_client_with_claim_mappers(&state, client).await?);
    }
    Ok(Json(clients))
}

#[derive(Debug, Deserialize)]
struct ClientInput {
    client_id: String,
    client_name: String,
    #[serde(default)]
    organization_id: Option<String>,
    client_secret: Option<String>,
    redirect_uris: Vec<String>,
    post_logout_redirect_uris: Vec<String>,
    scopes: Vec<String>,
    grant_types: Vec<String>,
    response_types: Vec<String>,
    token_endpoint_auth_method: String,
    require_pkce: bool,
    #[serde(default)]
    require_mfa: bool,
    #[serde(default)]
    require_pushed_authorization_requests: bool,
    #[serde(default)]
    require_s256_pkce: bool,
    #[serde(default)]
    require_confidential_client: bool,
    #[serde(default)]
    require_dpop: bool,
    #[serde(default)]
    require_account_selection: bool,
    #[serde(default)]
    trust_email_verified: bool,
    #[serde(default)]
    authorization_details_types: Vec<String>,
    subject_type: String,
    sector_identifier_uri: String,
    #[serde(default)]
    jwks_uri: String,
    #[serde(default)]
    jwks: String,
    #[serde(default)]
    backchannel_logout_uri: String,
    #[serde(default)]
    backchannel_logout_session_required: bool,
    #[serde(default)]
    frontchannel_logout_uri: String,
    #[serde(default)]
    frontchannel_logout_session_required: bool,
    #[serde(default)]
    service_account_enabled: bool,
    #[serde(default)]
    service_account_permissions: Vec<String>,
    is_active: bool,
    #[serde(default)]
    claim_mappers: Vec<ClientClaimMapperInput>,
}

#[derive(Debug, Deserialize)]
struct ClientClaimMapperInput {
    claim_name: String,
    source: String,
    source_value: String,
    value_type: String,
    include_in_id_token: bool,
    include_in_access_token: bool,
    include_in_userinfo: bool,
    is_active: bool,
    #[serde(default)]
    sort_order: i32,
}

async fn create_client(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<ClientInput>,
) -> AppResult<Json<PublicClient>> {
    let current = require_client_manager(&state, &jar).await?;
    validate_client_input(&payload)?;
    let organization_id =
        normalize_client_organization_id(&state, payload.organization_id.clone()).await?;
    let claim_mappers = client_input_to_claim_mappers(&payload)?;
    let client = state
        .db
        .insert_client(client_input_to_new(payload, None, organization_id.clone())?)
        .await?;
    state
        .db
        .replace_client_claim_mappers(&client.id, claim_mappers)
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "client.create",
            "client",
            Some(client.id.clone()),
            serde_json::json!({
                "client_id": client.client_id.clone(),
                "organization_id": organization_id,
                "require_mfa": client.require_mfa == 1,
                "require_pushed_authorization_requests": client.require_pushed_authorization_requests == 1,
                "require_s256_pkce": client.require_s256_pkce == 1,
                "require_confidential_client": client.require_confidential_client == 1,
                "require_dpop": client.require_dpop == 1,
                "require_account_selection": client.require_account_selection == 1,
                "trust_email_verified": client.trust_email_verified == 1,
                "authorization_details_types": client.authorization_details_types()?,
                "service_account_enabled": client.service_account_enabled == 1
            }),
        ))
        .await?;
    Ok(Json(
        public_client_with_claim_mappers(&state, client).await?,
    ))
}

async fn update_client(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<ClientInput>,
) -> AppResult<Json<PublicClient>> {
    let current = require_client_manager(&state, &jar).await?;
    validate_client_input(&payload)?;
    let organization_id =
        normalize_client_organization_id(&state, payload.organization_id.clone()).await?;
    let claim_mappers = client_input_to_claim_mappers(&payload)?;
    let existing = state
        .db
        .find_client_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    let client = state
        .db
        .update_client(
            &id,
            client_input_to_new(
                payload,
                existing.client_secret_hash,
                organization_id.clone(),
            )?,
        )
        .await?;
    state
        .db
        .replace_client_claim_mappers(&client.id, claim_mappers)
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "client.update",
            "client",
            Some(id),
            serde_json::json!({
                "client_id": client.client_id.clone(),
                "organization_id": organization_id,
                "require_mfa": client.require_mfa == 1,
                "require_pushed_authorization_requests": client.require_pushed_authorization_requests == 1,
                "require_s256_pkce": client.require_s256_pkce == 1,
                "require_confidential_client": client.require_confidential_client == 1,
                "require_dpop": client.require_dpop == 1,
                "require_account_selection": client.require_account_selection == 1,
                "trust_email_verified": client.trust_email_verified == 1,
                "authorization_details_types": client.authorization_details_types()?,
                "service_account_enabled": client.service_account_enabled == 1
            }),
        ))
        .await?;
    Ok(Json(
        public_client_with_claim_mappers(&state, client).await?,
    ))
}

#[derive(Debug, Deserialize)]
struct IapApplicationInput {
    slug: String,
    name: String,
    description: Option<String>,
    external_host: String,
    path_prefix: String,
    #[serde(default)]
    required_organization_id: Option<String>,
    #[serde(default)]
    required_organization_roles: Vec<String>,
    #[serde(default)]
    required_permissions: Vec<String>,
    is_active: bool,
}

async fn list_iap_applications(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<Vec<PublicIapApplication>>> {
    require_iap_reader(&state, &jar).await?;
    Ok(Json(
        state
            .db
            .list_iap_applications()
            .await?
            .into_iter()
            .map(|app| app.public())
            .collect::<AppResult<Vec<_>>>()?,
    ))
}

async fn create_iap_application(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<IapApplicationInput>,
) -> AppResult<Json<PublicIapApplication>> {
    let current = require_iap_manager(&state, &jar).await?;
    let app = iap_application_input_to_new(&state, payload).await?;
    let created = state.db.insert_iap_application(app).await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "iap_application.create",
            "iap_application",
            Some(created.id.clone()),
            serde_json::json!({
                "slug": created.slug.clone(),
                "external_host": created.external_host.clone(),
                "path_prefix": created.path_prefix.clone()
            }),
        ))
        .await?;
    Ok(Json(created.public()?))
}

async fn update_iap_application(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<IapApplicationInput>,
) -> AppResult<Json<PublicIapApplication>> {
    let current = require_iap_manager(&state, &jar).await?;
    let app = iap_application_input_to_new(&state, payload).await?;
    let updated = state.db.update_iap_application(&id, app).await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "iap_application.update",
            "iap_application",
            Some(id),
            serde_json::json!({
                "slug": updated.slug.clone(),
                "external_host": updated.external_host.clone(),
                "path_prefix": updated.path_prefix.clone(),
                "is_active": updated.is_active == 1
            }),
        ))
        .await?;
    Ok(Json(updated.public()?))
}

async fn delete_iap_application(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let current = require_iap_manager(&state, &jar).await?;
    let existing = state
        .db
        .find_iap_application_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    state.db.delete_iap_application(&id).await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "iap_application.delete",
            "iap_application",
            Some(id),
            serde_json::json!({ "slug": existing.slug }),
        ))
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn list_invitations(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<Vec<PublicInvitation>>> {
    require_authorization_code_manager(&state, &jar).await?;
    let mut redemptions = BTreeMap::<String, Vec<_>>::new();
    for redemption in state.db.list_invitation_redemptions().await? {
        redemptions
            .entry(redemption.invitation_id.clone())
            .or_default()
            .push(redemption.public());
    }
    Ok(Json(
        state
            .db
            .list_invitations()
            .await?
            .into_iter()
            .map(|invitation| {
                let id = invitation.id.clone();
                invitation.public_with_redemptions(redemptions.remove(&id).unwrap_or_default())
            })
            .collect(),
    ))
}

#[derive(Debug, Deserialize)]
struct InvitationInput {
    description: Option<String>,
    authorized_email: Option<String>,
    authorized_username: Option<String>,
    authorized_display_name: Option<String>,
    expires_at: Option<i64>,
    max_uses: Option<i32>,
    is_active: bool,
}

#[derive(Debug, Serialize)]
struct InvitationCreateResponse {
    invitation: PublicInvitation,
    code: String,
}

async fn create_invitation(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<InvitationInput>,
) -> AppResult<Json<InvitationCreateResponse>> {
    let current = require_authorization_code_manager(&state, &jar).await?;
    if matches!(payload.max_uses, Some(value) if value <= 0) {
        return Err(AppError::BadRequest(
            "max_uses must be positive when provided".to_string(),
        ));
    }
    let (invitation, code) = state
        .db
        .insert_invitation(NewInvitation {
            description: payload.description,
            authorized_email: normalize_optional_email(payload.authorized_email)?,
            authorized_username: normalize_optional_text(payload.authorized_username),
            authorized_display_name: normalize_optional_text(payload.authorized_display_name),
            expires_at: payload.expires_at,
            max_uses: payload.max_uses,
            is_active: payload.is_active,
            created_by: Some(current.user.id.clone()),
        })
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "authorization_code.create",
            "authorization_code",
            Some(invitation.id.clone()),
            serde_json::json!({ "max_uses": invitation.max_uses }),
        ))
        .await?;
    Ok(Json(InvitationCreateResponse {
        invitation: invitation.public(),
        code,
    }))
}

async fn update_invitation(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<InvitationInput>,
) -> AppResult<Json<PublicInvitation>> {
    let current = require_authorization_code_manager(&state, &jar).await?;
    if matches!(payload.max_uses, Some(value) if value <= 0) {
        return Err(AppError::BadRequest(
            "max_uses must be positive when provided".to_string(),
        ));
    }
    let invitation = state
        .db
        .update_invitation(
            &id,
            payload.description,
            normalize_optional_email(payload.authorized_email)?,
            normalize_optional_text(payload.authorized_username),
            normalize_optional_text(payload.authorized_display_name),
            payload.expires_at,
            payload.max_uses,
            payload.is_active,
        )
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "authorization_code.update",
            "authorization_code",
            Some(id),
            serde_json::json!({ "is_active": invitation.is_active == 1 }),
        ))
        .await?;
    Ok(Json(invitation.public()))
}

async fn delete_invitation(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let current = require_authorization_code_manager(&state, &jar).await?;
    state.db.delete_invitation(&id).await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "authorization_code.delete",
            "authorization_code",
            Some(id),
            serde_json::json!({}),
        ))
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn list_external_oidc_providers(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<Vec<PublicExternalOidcProvider>>> {
    require_provider_manager(&state, &jar).await?;
    let mut providers = Vec::new();
    for provider in state.db.list_external_oidc_providers().await? {
        providers.push(provider.public()?);
    }
    Ok(Json(providers))
}

async fn list_external_oidc_provider_templates(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<Vec<OidcProviderTemplate>>> {
    require_provider_manager(&state, &jar).await?;
    Ok(Json(identity_sources::oidc_provider_templates()))
}

#[derive(Debug, Deserialize)]
struct OidcDiscoveryInput {
    issuer: String,
}

async fn discover_external_oidc_provider(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<OidcDiscoveryInput>,
) -> AppResult<Json<OidcDiscoveryResult>> {
    require_provider_manager(&state, &jar).await?;
    identity_sources::discover_oidc_provider(&payload.issuer)
        .await
        .map(Json)
}

#[derive(Debug, Deserialize)]
struct ExternalOidcProviderInput {
    slug: String,
    display_name: String,
    #[serde(default)]
    organization_id: Option<String>,
    issuer: String,
    client_id: String,
    client_secret: String,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    redirect_path: String,
    scopes: Vec<String>,
    email_domains: Vec<String>,
    is_active: bool,
    #[serde(default = "default_true")]
    allow_login: bool,
    allow_registration: bool,
}

fn default_true() -> bool {
    true
}

async fn create_external_oidc_provider(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<ExternalOidcProviderInput>,
) -> AppResult<Json<PublicExternalOidcProvider>> {
    let current = require_provider_manager(&state, &jar).await?;
    let organization_id =
        normalize_client_organization_id(&state, payload.organization_id.clone()).await?;
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

async fn update_external_oidc_provider(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<ExternalOidcProviderInput>,
) -> AppResult<Json<PublicExternalOidcProvider>> {
    let current = require_provider_manager(&state, &jar).await?;
    let organization_id =
        normalize_client_organization_id(&state, payload.organization_id.clone()).await?;
    let provider_input = normalize_external_provider_input(payload, organization_id.clone())?;
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

async fn delete_external_oidc_provider(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let current = require_provider_manager(&state, &jar).await?;
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

async fn list_ldap_providers(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<Vec<PublicLdapProvider>>> {
    require_provider_manager(&state, &jar).await?;
    let providers = state
        .db
        .list_ldap_providers()
        .await?
        .into_iter()
        .map(|provider| provider.public())
        .collect();
    Ok(Json(providers))
}

#[derive(Debug, Deserialize)]
struct LdapProviderInput {
    slug: String,
    display_name: String,
    url: String,
    starttls: bool,
    bind_dn: String,
    #[serde(default)]
    bind_password: Option<String>,
    #[serde(default)]
    clear_bind_password: bool,
    base_dn: String,
    user_filter: String,
    user_id_attribute: String,
    email_attribute: String,
    username_attribute: String,
    display_name_attribute: String,
    phone_attribute: String,
    is_active: bool,
    allow_login: bool,
    allow_registration: bool,
}

async fn create_ldap_provider(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<LdapProviderInput>,
) -> AppResult<Json<PublicLdapProvider>> {
    let current = require_provider_manager(&state, &jar).await?;
    let provider_input = normalize_ldap_provider_input(payload)?;
    let provider = state.db.insert_ldap_provider(provider_input).await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "ldap_provider.create",
            "ldap_provider",
            Some(provider.id.clone()),
            serde_json::json!({ "slug": provider.slug.clone() }),
        ))
        .await?;
    Ok(Json(provider.public()))
}

async fn update_ldap_provider(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<LdapProviderInput>,
) -> AppResult<Json<PublicLdapProvider>> {
    let current = require_provider_manager(&state, &jar).await?;
    let provider_input = normalize_ldap_provider_input(payload)?;
    let provider = state.db.update_ldap_provider(&id, provider_input).await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "ldap_provider.update",
            "ldap_provider",
            Some(id),
            serde_json::json!({ "slug": provider.slug.clone() }),
        ))
        .await?;
    Ok(Json(provider.public()))
}

async fn delete_ldap_provider(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let current = require_provider_manager(&state, &jar).await?;
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

fn normalize_external_provider_input(
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

fn normalize_ldap_provider_input(payload: LdapProviderInput) -> AppResult<NewLdapProvider> {
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
        normalize_optional_text(payload.bind_password)
    };
    Ok(NewLdapProvider {
        slug,
        display_name,
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

fn normalize_ldap_url(value: String) -> AppResult<String> {
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

fn normalize_ldap_user_filter(value: String) -> String {
    let value = value.trim();
    if value.is_empty() {
        "(&(|(mail={login})(uid={login})(sAMAccountName={login}))(objectClass=person))".to_string()
    } else {
        value.to_string()
    }
}

fn normalize_ldap_attribute(value: String, field: &str, allow_empty: bool) -> AppResult<String> {
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

fn normalize_provider_slug(value: String) -> AppResult<String> {
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

fn normalize_optional_http_url(
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

fn normalize_external_redirect_path(value: String, slug: &str) -> AppResult<String> {
    let path = value.trim().to_string();
    let expected = format!("/api/register/oidc/{slug}/callback");
    if path != expected {
        return Err(AppError::BadRequest(format!(
            "redirect_path must be {expected}"
        )));
    }
    Ok(path)
}

fn normalize_scope_list(values: Vec<String>) -> AppResult<Vec<String>> {
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

fn validate_client_input(payload: &ClientInput) -> AppResult<()> {
    if payload.client_id.trim().is_empty() {
        return Err(AppError::BadRequest("client_id is required".to_string()));
    }
    let redirect_uris = normalize_redirect_uri_list(&payload.redirect_uris, "redirect_uri")?;
    let post_logout_redirect_uris = normalize_redirect_uri_list(
        &payload.post_logout_redirect_uris,
        "post_logout_redirect_uri",
    )?;
    let uses_authorization_code = payload
        .grant_types
        .iter()
        .any(|value| value == "authorization_code");
    if uses_authorization_code && redirect_uris.is_empty() {
        return Err(AppError::BadRequest(
            "at least one redirect_uri is required".to_string(),
        ));
    }
    if !payload.scopes.iter().any(|scope| scope == "openid") {
        return Err(AppError::BadRequest(
            "scopes must include openid".to_string(),
        ));
    }
    if uses_authorization_code && !payload.response_types.iter().any(|value| value == "code") {
        return Err(AppError::BadRequest(
            "response_types must include code".to_string(),
        ));
    }
    if payload.service_account_enabled
        && !payload
            .grant_types
            .iter()
            .any(|value| value == "client_credentials")
    {
        return Err(AppError::BadRequest(
            "service accounts require client_credentials grant".to_string(),
        ));
    }
    service_accounts::normalize_permissions(payload.service_account_permissions.clone())?;
    crate::authorization_details::normalize_public_types(
        payload.authorization_details_types.clone(),
    )?;
    if !matches!(
        payload.token_endpoint_auth_method.as_str(),
        "client_secret_basic"
            | "client_secret_post"
            | client_assertion::CLIENT_SECRET_JWT
            | client_assertion::PRIVATE_KEY_JWT
            | "none"
    ) {
        return Err(AppError::BadRequest(
            "unsupported token_endpoint_auth_method".to_string(),
        ));
    }
    client_assertion::validate_key_source(
        &payload.token_endpoint_auth_method,
        &payload.jwks_uri,
        &payload.jwks,
    )?;
    client_policy::validate_client_security_configuration(client_policy::ClientSecurityConfig {
        token_endpoint_auth_method: &payload.token_endpoint_auth_method,
        require_pkce: payload.require_pkce,
        require_s256_pkce: payload.require_s256_pkce,
        require_confidential_client: payload.require_confidential_client,
        require_pushed_authorization_requests: payload.require_pushed_authorization_requests,
        require_dpop: payload.require_dpop,
    })?;
    backchannel_logout::validate_backchannel_logout_config(
        &payload.backchannel_logout_uri,
        payload.backchannel_logout_session_required,
    )?;
    frontchannel_logout::validate_frontchannel_logout_config(
        &payload.frontchannel_logout_uri,
        payload.frontchannel_logout_session_required,
        &redirect_uris,
    )?;
    for uri in post_logout_redirect_uris {
        validate_absolute_http_url(&uri, "post_logout_redirect_uri")?;
    }
    subject::validate_subject_config(&payload.subject_type, &payload.sector_identifier_uri)?;
    Ok(())
}

fn normalize_redirect_uri_list(values: &[String], field: &str) -> AppResult<Vec<String>> {
    let mut seen = BTreeSet::new();
    let mut normalized = Vec::new();
    for value in values {
        let value = value.trim().to_string();
        if value.is_empty() {
            continue;
        }
        validate_absolute_http_url(&value, field)?;
        if seen.insert(value.clone()) {
            normalized.push(value);
        }
    }
    Ok(normalized)
}

fn validate_absolute_http_url(value: &str, field: &str) -> AppResult<()> {
    let parsed = Url::parse(value)
        .map_err(|err| AppError::BadRequest(format!("{field} is invalid: {err}")))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err(AppError::BadRequest(format!(
            "{field} must be an absolute http(s) URL"
        )));
    }
    if parsed.fragment().is_some() {
        return Err(AppError::BadRequest(format!(
            "{field} cannot contain a fragment"
        )));
    }
    Ok(())
}

async fn public_client_with_claim_mappers(
    state: &AppState,
    client: crate::db::ClientRecord,
) -> AppResult<PublicClient> {
    let mappers = state
        .db
        .list_client_claim_mappers(&client.id)
        .await?
        .into_iter()
        .map(|mapper| mapper.public())
        .collect::<Vec<PublicClientClaimMapper>>();
    let mut public = client.public()?;
    if let Some(organization_id) = public.organization_id.as_deref() {
        if let Some(organization) = state.db.find_organization_by_id(organization_id).await? {
            public.organization_slug = Some(organization.slug);
            public.organization_name = Some(organization.name);
        }
    }
    public.claim_mappers = mappers;
    Ok(public)
}

async fn normalize_client_organization_id(
    state: &AppState,
    organization_id: Option<String>,
) -> AppResult<Option<String>> {
    let Some(organization_id) = organization_id.map(|value| value.trim().to_string()) else {
        return Ok(None);
    };
    if organization_id.is_empty() {
        return Ok(None);
    }
    if state
        .db
        .find_organization_by_id(&organization_id)
        .await?
        .is_none()
    {
        return Err(AppError::BadRequest(
            "organization_id does not reference an existing organization".to_string(),
        ));
    }
    Ok(Some(organization_id))
}

async fn iap_application_input_to_new(
    state: &AppState,
    payload: IapApplicationInput,
) -> AppResult<NewIapApplication> {
    let required_organization_id =
        normalize_client_organization_id(state, payload.required_organization_id).await?;
    iap::normalize_iap_application(NewIapApplication {
        slug: payload.slug,
        name: payload.name,
        description: payload.description,
        external_host: payload.external_host,
        path_prefix: payload.path_prefix,
        required_organization_id,
        required_organization_roles: payload.required_organization_roles,
        required_permissions: payload.required_permissions,
        is_active: payload.is_active,
    })
}

fn client_input_to_claim_mappers(payload: &ClientInput) -> AppResult<Vec<NewClientClaimMapper>> {
    payload
        .claim_mappers
        .iter()
        .enumerate()
        .map(|(index, mapper)| {
            let sort_order = if mapper.sort_order == 0 {
                index as i32
            } else {
                mapper.sort_order
            };
            let record = crate::db::ClientClaimMapperRecord {
                id: String::new(),
                client_db_id: String::new(),
                claim_name: mapper.claim_name.trim().to_string(),
                source: mapper.source.trim().to_string(),
                source_value: mapper.source_value.trim().to_string(),
                value_type: mapper.value_type.trim().to_string(),
                include_in_id_token: i32::from(mapper.include_in_id_token),
                include_in_access_token: i32::from(mapper.include_in_access_token),
                include_in_userinfo: i32::from(mapper.include_in_userinfo),
                is_active: i32::from(mapper.is_active),
                sort_order,
                created_at: 0,
                updated_at: 0,
            };
            claim_mapper::validate_mapper_record(&record)?;
            Ok(NewClientClaimMapper {
                claim_name: record.claim_name,
                source: record.source,
                source_value: record.source_value,
                value_type: record.value_type,
                include_in_id_token: mapper.include_in_id_token,
                include_in_access_token: mapper.include_in_access_token,
                include_in_userinfo: mapper.include_in_userinfo,
                is_active: mapper.is_active,
                sort_order,
            })
        })
        .collect()
}

fn client_input_to_new(
    payload: ClientInput,
    existing_hash: Option<String>,
    organization_id: Option<String>,
) -> AppResult<NewClient> {
    let secret = payload.client_secret.unwrap_or_default();
    let token_auth = payload.token_endpoint_auth_method.as_str();
    let can_reuse_secret =
        client_assertion::stored_secret_supports_method(token_auth, existing_hash.as_deref());
    let client_secret_hash = match token_auth {
        "none" | client_assertion::PRIVATE_KEY_JWT => None,
        _ if !secret.is_empty() => client_assertion::store_client_secret(token_auth, &secret)?,
        _ if can_reuse_secret => existing_hash,
        _ => {
            return Err(AppError::BadRequest(
                "client_secret is required for secret-based client authentication".to_string(),
            ));
        }
    };
    let jwks_uri = client_assertion::validate_jwks_uri(&payload.jwks_uri)?;
    let jwks = client_assertion::normalize_jwks_json(&payload.jwks)?;
    let service_account_permissions =
        service_accounts::normalize_permissions(payload.service_account_permissions)?;
    let backchannel_logout_uri = backchannel_logout::validate_backchannel_logout_config(
        &payload.backchannel_logout_uri,
        payload.backchannel_logout_session_required,
    )?;
    let redirect_uris = normalize_redirect_uri_list(&payload.redirect_uris, "redirect_uri")?;
    let post_logout_redirect_uris = normalize_redirect_uri_list(
        &payload.post_logout_redirect_uris,
        "post_logout_redirect_uri",
    )?;
    let frontchannel_logout_uri = frontchannel_logout::validate_frontchannel_logout_config(
        &payload.frontchannel_logout_uri,
        payload.frontchannel_logout_session_required,
        &redirect_uris,
    )?;
    Ok(NewClient {
        client_id: payload.client_id,
        client_secret_hash,
        client_name: payload.client_name,
        organization_id,
        redirect_uris,
        post_logout_redirect_uris,
        scopes: payload.scopes,
        grant_types: payload.grant_types,
        response_types: payload.response_types,
        token_endpoint_auth_method: payload.token_endpoint_auth_method,
        require_pkce: payload.require_pkce,
        require_mfa: payload.require_mfa,
        require_pushed_authorization_requests: payload.require_pushed_authorization_requests,
        require_s256_pkce: payload.require_s256_pkce,
        require_confidential_client: payload.require_confidential_client,
        require_dpop: payload.require_dpop,
        require_account_selection: payload.require_account_selection,
        trust_email_verified: payload.trust_email_verified,
        authorization_details_types: crate::authorization_details::normalize_public_types(
            payload.authorization_details_types,
        )?,
        subject_type: payload.subject_type,
        sector_identifier_uri: payload.sector_identifier_uri,
        jwks_uri,
        jwks,
        backchannel_logout_uri,
        backchannel_logout_session_required: payload.backchannel_logout_session_required,
        frontchannel_logout_uri,
        frontchannel_logout_session_required: payload.frontchannel_logout_session_required,
        service_account_enabled: payload.service_account_enabled,
        service_account_permissions,
        is_active: payload.is_active,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(archived_at: Option<i64>) -> crate::db::UserRecord {
        crate::db::UserRecord {
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
            archived_at,
            last_login_at: None,
            last_login_ip: None,
            last_oidc_client_id: None,
            last_login_method: None,
            created_at: 1,
            updated_at: 1,
        }
    }

    #[test]
    fn archived_users_are_not_editable() {
        assert!(archived_accounts::ensure_user_record_editable(&user(None)).is_ok());
        assert!(matches!(
            archived_accounts::ensure_user_record_editable(&user(Some(100))),
            Err(AppError::BadRequest(_))
        ));
    }

    #[test]
    fn profile_updates_cannot_bypass_lifecycle_or_self_role_guards() {
        let mut current = user(None);
        current.is_admin = 1;
        let target = current.clone();

        assert!(ensure_account_metadata_update_allowed(&current, &target, true, true).is_ok());
        assert!(matches!(
            ensure_account_metadata_update_allowed(&current, &target, false, true),
            Err(AppError::BadRequest(_))
        ));
        assert!(matches!(
            ensure_account_metadata_update_allowed(&current, &target, true, false),
            Err(AppError::BadRequest(_))
        ));

        let mut other = target.clone();
        other.id = "other-user-id".to_string();
        assert!(ensure_account_metadata_update_allowed(&current, &other, false, true).is_ok());
        assert!(matches!(
            ensure_account_metadata_update_allowed(&current, &other, false, false),
            Err(AppError::BadRequest(_))
        ));
    }

    #[test]
    fn user_input_is_normalized_before_admin_writes() {
        let input = normalize_user_input(UserInput {
            email: " User@Example.COM ".to_string(),
            username: " alice ".to_string(),
            display_name: Some(" Alice ".to_string()),
            phone: Some("  ".to_string()),
            password: Some("  ".to_string()),
            is_admin: false,
            is_active: true,
        })
        .unwrap();

        assert_eq!(input.email, "user@example.com");
        assert_eq!(input.username, "alice");
        assert_eq!(input.display_name.as_deref(), Some("Alice"));
        assert_eq!(input.phone, None);
        assert_eq!(input.password, None);
    }

    fn external_provider_input() -> ExternalOidcProviderInput {
        ExternalOidcProviderInput {
            slug: "Corp_OIDC".to_string(),
            display_name: " Corp OIDC ".to_string(),
            organization_id: None,
            issuer: "https://idp.example.com/".to_string(),
            client_id: " client ".to_string(),
            client_secret: " secret ".to_string(),
            authorization_endpoint: "https://idp.example.com/oauth2/authorize/".to_string(),
            token_endpoint: "https://idp.example.com/oauth2/token/".to_string(),
            userinfo_endpoint: "https://idp.example.com/oauth2/userinfo/".to_string(),
            redirect_path: "/api/register/oidc/corp_oidc/callback".to_string(),
            scopes: vec![
                " openid ".to_string(),
                "email".to_string(),
                "openid".to_string(),
            ],
            email_domains: vec![
                " @Example.COM. ".to_string(),
                "team.example.com".to_string(),
                "example.com".to_string(),
            ],
            is_active: true,
            allow_login: true,
            allow_registration: true,
        }
    }

    fn ldap_provider_input() -> LdapProviderInput {
        LdapProviderInput {
            slug: "Corp_LDAP".to_string(),
            display_name: " Corp LDAP ".to_string(),
            url: "ldap://ldap.example.com/".to_string(),
            starttls: true,
            bind_dn: " cn=reader,dc=example,dc=com ".to_string(),
            bind_password: Some(" secret ".to_string()),
            clear_bind_password: false,
            base_dn: " dc=example,dc=com ".to_string(),
            user_filter: " (&(objectClass=person)(|(mail={login})(uid={login}))) ".to_string(),
            user_id_attribute: " DN ".to_string(),
            email_attribute: " mail ".to_string(),
            username_attribute: " uid ".to_string(),
            display_name_attribute: " cn ".to_string(),
            phone_attribute: " telephoneNumber ".to_string(),
            is_active: true,
            allow_login: true,
            allow_registration: true,
        }
    }

    #[test]
    fn external_provider_input_is_normalized_and_path_bound_to_slug() {
        let provider = normalize_external_provider_input(external_provider_input(), None).unwrap();

        assert_eq!(provider.slug, "corp_oidc");
        assert_eq!(provider.display_name, "Corp OIDC");
        assert_eq!(provider.issuer, "https://idp.example.com");
        assert_eq!(
            provider.authorization_endpoint,
            "https://idp.example.com/oauth2/authorize/"
        );
        assert_eq!(
            provider.redirect_path,
            "/api/register/oidc/corp_oidc/callback"
        );
        assert_eq!(
            provider.scopes,
            vec!["email".to_string(), "openid".to_string()]
        );
        assert_eq!(
            provider.email_domains,
            vec!["example.com".to_string(), "team.example.com".to_string()]
        );
        assert!(provider.allow_login);
    }

    #[test]
    fn external_provider_input_rejects_unsafe_urls_and_paths() {
        let mut provider = external_provider_input();
        provider.authorization_endpoint = "javascript:alert(1)".to_string();
        assert!(matches!(
            normalize_external_provider_input(provider, None),
            Err(AppError::BadRequest(_))
        ));

        let mut provider = external_provider_input();
        provider.redirect_path = "/api/register/oidc/other/callback".to_string();
        assert!(matches!(
            normalize_external_provider_input(provider, None),
            Err(AppError::BadRequest(_))
        ));
    }

    #[test]
    fn active_external_provider_requires_runtime_fields() {
        let mut provider = external_provider_input();
        provider.client_id = " ".to_string();
        assert!(matches!(
            normalize_external_provider_input(provider, None),
            Err(AppError::BadRequest(_))
        ));

        let mut provider = external_provider_input();
        provider.is_active = false;
        provider.client_id = " ".to_string();
        assert!(normalize_external_provider_input(provider, None).is_ok());
    }

    #[test]
    fn ldap_provider_input_is_normalized() {
        let provider = normalize_ldap_provider_input(ldap_provider_input()).unwrap();

        assert_eq!(provider.slug, "corp_ldap");
        assert_eq!(provider.display_name, "Corp LDAP");
        assert_eq!(provider.url, "ldap://ldap.example.com");
        assert_eq!(provider.bind_dn, "cn=reader,dc=example,dc=com");
        assert_eq!(provider.bind_password.as_deref(), Some("secret"));
        assert_eq!(provider.base_dn, "dc=example,dc=com");
        assert_eq!(provider.user_id_attribute, "dn");
        assert_eq!(provider.email_attribute, "mail");
        assert_eq!(provider.username_attribute, "uid");
    }

    #[test]
    fn ldap_provider_input_rejects_unsafe_runtime_values() {
        let mut provider = ldap_provider_input();
        provider.url = "http://ldap.example.com".to_string();
        assert!(matches!(
            normalize_ldap_provider_input(provider),
            Err(AppError::BadRequest(_))
        ));

        let mut provider = ldap_provider_input();
        provider.user_filter = "(objectClass=person)".to_string();
        assert!(matches!(
            normalize_ldap_provider_input(provider),
            Err(AppError::BadRequest(_))
        ));

        let mut provider = ldap_provider_input();
        provider.email_attribute = "mail)(uid=*".to_string();
        assert!(matches!(
            normalize_ldap_provider_input(provider),
            Err(AppError::BadRequest(_))
        ));
    }

    #[test]
    fn inactive_ldap_provider_can_be_saved_incomplete() {
        let mut provider = ldap_provider_input();
        provider.is_active = false;
        provider.url = String::new();
        provider.base_dn = String::new();
        provider.user_filter = String::new();

        let provider = normalize_ldap_provider_input(provider).unwrap();
        assert_eq!(provider.url, "");
        assert!(provider.user_filter.contains("{login}"));
    }

    fn client_input() -> ClientInput {
        ClientInput {
            client_id: "demo-web".to_string(),
            client_name: "Demo Web".to_string(),
            organization_id: None,
            client_secret: None,
            redirect_uris: vec![
                " https://app.example.com/callback ".to_string(),
                "https://app.example.com/callback".to_string(),
                "https://app.example.com/alt".to_string(),
                " ".to_string(),
            ],
            post_logout_redirect_uris: vec![" https://app.example.com/logout ".to_string()],
            scopes: vec!["openid".to_string(), "profile".to_string()],
            grant_types: vec!["authorization_code".to_string()],
            response_types: vec!["code".to_string()],
            token_endpoint_auth_method: "none".to_string(),
            require_pkce: true,
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
            frontchannel_logout_uri: " https://app.example.com/front-logout ".to_string(),
            frontchannel_logout_session_required: false,
            service_account_enabled: false,
            service_account_permissions: Vec::new(),
            is_active: true,
            claim_mappers: Vec::new(),
        }
    }

    #[test]
    fn client_redirect_uris_are_validated_and_normalized() {
        let input = client_input();
        validate_client_input(&input).unwrap();

        let client = client_input_to_new(input, None, None).unwrap();
        assert_eq!(
            client.redirect_uris,
            vec![
                "https://app.example.com/callback".to_string(),
                "https://app.example.com/alt".to_string()
            ]
        );
        assert_eq!(
            client.post_logout_redirect_uris,
            vec!["https://app.example.com/logout".to_string()]
        );
        assert_eq!(
            client.frontchannel_logout_uri,
            "https://app.example.com/front-logout"
        );
    }

    #[test]
    fn client_redirect_uris_reject_fragments_and_non_http_schemes() {
        let mut input = client_input();
        input.redirect_uris = vec!["https://app.example.com/callback#fragment".to_string()];
        assert!(matches!(
            validate_client_input(&input),
            Err(AppError::BadRequest(_))
        ));

        let mut input = client_input();
        input.post_logout_redirect_uris = vec!["javascript:alert(1)".to_string()];
        assert!(matches!(
            validate_client_input(&input),
            Err(AppError::BadRequest(_))
        ));
    }

    #[test]
    fn client_security_policy_rejects_incoherent_settings() {
        let mut input = client_input();
        input.require_s256_pkce = true;
        input.require_pkce = false;
        assert!(matches!(
            validate_client_input(&input),
            Err(AppError::BadRequest(_))
        ));

        let mut input = client_input();
        input.require_confidential_client = true;
        input.token_endpoint_auth_method = "none".to_string();
        assert!(matches!(
            validate_client_input(&input),
            Err(AppError::BadRequest(_))
        ));
    }

    #[test]
    fn email_domains_are_normalized_and_deduplicated() {
        assert_eq!(
            normalize_email_domains(vec![
                "@Example.COM.".to_string(),
                "example.com".to_string(),
                "corp".to_string(),
                " ".to_string()
            ])
            .unwrap(),
            vec!["example.com".to_string(), "corp".to_string()]
        );
    }

    #[test]
    fn invalid_email_domains_are_rejected() {
        assert!(matches!(
            normalize_email_domains(vec!["bad/domain".to_string()]),
            Err(AppError::BadRequest(_))
        ));
        assert!(matches!(
            normalize_email_domains(vec!["bad domain".to_string()]),
            Err(AppError::BadRequest(_))
        ));
        assert!(matches!(
            normalize_email_domains(vec!["bad\\domain".to_string()]),
            Err(AppError::BadRequest(_))
        ));
        assert!(matches!(
            normalize_email_domains(vec!["bad..domain".to_string()]),
            Err(AppError::BadRequest(_))
        ));
    }

    #[test]
    fn quick_links_are_normalized_for_login_entry_configuration() {
        let links = normalize_quick_links(vec![
            QuickLink {
                id: " OpenAI Link! ".to_string(),
                label: " OpenAI ".to_string(),
                url: " https://chatgpt.com/auth/login?sso=true&connection=conn_01KTR8HRA3ZQR9S3EGT32TY3WT ".to_string(),
                icon: " openai! ".to_string(),
                is_active: true,
            },
            QuickLink {
                id: "".to_string(),
                label: "".to_string(),
                url: "".to_string(),
                icon: "".to_string(),
                is_active: false,
            },
        ])
        .unwrap();

        assert_eq!(links.len(), 1);
        assert_eq!(links[0].id, "OpenAILink");
        assert_eq!(links[0].label, "OpenAI");
        assert_eq!(
            links[0].url,
            "https://chatgpt.com/auth/login?sso=true&connection=conn_01KTR8HRA3ZQR9S3EGT32TY3WT"
        );
        assert_eq!(links[0].icon, "openai");
        assert!(links[0].is_active);
    }

    #[test]
    fn invalid_or_duplicate_quick_links_are_rejected() {
        assert!(matches!(
            normalize_quick_links(vec![QuickLink {
                id: "bad".to_string(),
                label: "Bad".to_string(),
                url: "javascript:alert(1)".to_string(),
                icon: "link".to_string(),
                is_active: true,
            }]),
            Err(AppError::BadRequest(_))
        ));

        assert!(matches!(
            normalize_quick_links(vec![
                QuickLink {
                    id: "open-ai".to_string(),
                    label: "OpenAI".to_string(),
                    url: "https://chatgpt.com".to_string(),
                    icon: "openai".to_string(),
                    is_active: true,
                },
                QuickLink {
                    id: "open-ai".to_string(),
                    label: "OpenAI duplicate".to_string(),
                    url: "https://chatgpt.com/auth/login".to_string(),
                    icon: "openai".to_string(),
                    is_active: true,
                },
            ]),
            Err(AppError::BadRequest(message)) if message == "quick link id must be unique"
        ));
    }
}
