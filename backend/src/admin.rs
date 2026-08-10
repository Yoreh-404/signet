use crate::{
    AppState,
    access::{Authorizer, Permission, PermissionInfo, permission_catalog},
    applications, archived_accounts,
    audit::{self, AuditSink},
    auth::{self, AccountCapabilities},
    auth_flow, authorization, authorization_manifest, backchannel_logout, claim_mapper,
    client_assertion, client_policy,
    csrf,
    db::{
        ApplicationAuthorizationProfileRecord, ApplicationJwtClientRecord,
        ApplicationModuleRecord, ApplicationPermissionDefinitionRecord,
        ApplicationProfileRoleRecord, ApplicationRecord, ApplicationRoleRecord,
        ApplicationScimTokenRecord, AuditEventRecord, AuthorizationCodeType,
        GroupRecord, InvitationRecord, InvitationUpdate, LinkedIdentityRecord, LoginCodeLevel,
        LoginEventRecord, NewApplication, NewApplicationAuthorizationProfile,
        NewApplicationJwtClient,
        NewApplicationProfileRole, NewApplicationRole, NewApplicationScimToken,
        NewBulkProvisionedUser, NewClient, NewClientClaimMapper,
        NewExternalOidcProvider, NewGroup, NewIapApplication, NewInvitation, NewLdapProvider,
        NewLoginSettings, NewOrganization, NewRegistrationSettings, NewRole, NewRuntimeSettings,
        NewSecurityPolicy, NewUser, OrganizationMemberInput, OrganizationMemberWithUserRecord,
        OrganizationRecord, PublicAuditWebhook, PublicClient, PublicClientClaimMapper,
        PublicExternalOidcProvider, PublicIapApplication, PublicInvitation,
        PublicInvitationRedemption, PublicLdapProvider, PublicLoginSettings,
        PublicRegistrationSettings, PublicSecurityPolicy, PublicUser, QuickLink, RoleRecord,
        SecurityPolicyRecord, SessionRecord, SigningKeyRecord, UserConsentWithClientRecord,
        UserListScope, UserOrganizationRecord, UserUpdate,
    },
    directory, directory_sync,
    error::{AppError, AppResult},
    frontchannel_logout, iap,
    identity_sources::{self, OidcDiscoveryResult, OidcProviderTemplate},
    mfa::{self, RecoveryCodeIssuer},
    mfa_policy::MfaDecision,
    network_policy::{self, TrustedNetworkPolicy},
    organizations::{self, OrganizationEmailPolicy},
    security_policy::{self, PasswordPolicy, PasswordSubject},
    service_accounts, subject, util, webhooks,
};
use axum::{
    Json, Router,
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
};
use axum_extra::extract::cookie::CookieJar;
use csv::ReaderBuilder;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
};
use url::Url;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/login", post(login))
        .route("/api/logout", post(logout))
        .route("/api/me", get(me))
        .route(
            "/api/me/organizations",
            get(my_organizations).post(create_my_organization),
        )
        .route(
            "/api/me/organization-context",
            get(my_organization_context).put(set_my_organization_context),
        )
        .route("/api/csrf", get(csrf_token))
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
        .route("/api/admin/users/import-csv", post(import_users_csv))
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
        .route(
            "/api/admin/clients/{id}",
            put(update_client).delete(delete_client),
        )
        .route(
            "/api/admin/applications",
            get(list_applications).post(create_application),
        )
        .route(
            "/api/admin/applications/{id}",
            put(update_application).delete(delete_application),
        )
        .route(
            "/api/admin/applications/{id}/oidc-clients",
            get(list_application_oidc_clients).put(replace_application_oidc_clients),
        )
        .route(
            "/api/admin/applications/{id}/modules",
            get(list_application_modules),
        )
        .route(
            "/api/admin/applications/{id}/modules/{module_key}",
            put(update_application_module).delete(delete_application_module),
        )
        .route(
            "/api/admin/applications/{id}/directory-sync/runs",
            get(list_application_directory_sync_runs),
        )
        .route(
            "/api/admin/applications/{id}/directory-sync/{provider_id}/run",
            post(run_application_directory_sync),
        )
        .route(
            "/api/admin/applications/{id}/jwt-client",
            get(get_application_jwt_client).put(update_application_jwt_client),
        )
        .route(
            "/api/admin/applications/{id}/jwt-client/secret",
            post(rotate_application_jwt_secret),
        )
        .route(
            "/api/admin/applications/{id}/jwt-client/secrets",
            delete(revoke_application_jwt_secrets),
        )
        .route(
            "/api/admin/applications/{id}/scim-tokens",
            get(list_application_scim_tokens).post(create_application_scim_token),
        )
        .route(
            "/api/admin/applications/{id}/scim-tokens/{token_id}",
            delete(revoke_application_scim_token),
        )
        .route(
            "/api/admin/applications/{id}/roles",
            get(list_application_roles).post(create_application_role),
        )
        .route(
            "/api/admin/applications/{id}/authorization/catalog",
            get(application_permission_catalog),
        )
        .route(
            "/api/admin/applications/{id}/authorization/profiles",
            get(list_application_authorization_profiles),
        )
        .route(
            "/api/admin/applications/{id}/authorization/profiles/{profile_id}",
            get(get_application_authorization_profile)
                .put(update_application_authorization_profile),
        )
        .route(
            "/api/admin/applications/{id}/authorization/profiles/{profile_id}/refresh",
            post(refresh_application_authorization_profile),
        )
        .route(
            "/api/admin/applications/{id}/authorization/profiles/{profile_id}/catalog",
            get(application_profile_permission_catalog),
        )
        .route(
            "/api/admin/applications/{id}/authorization/profiles/{profile_id}/roles",
            get(list_application_profile_roles).post(create_application_profile_role),
        )
        .route(
            "/api/admin/applications/{id}/authorization/profiles/{profile_id}/roles/{role_id}",
            put(update_application_profile_role).delete(delete_application_profile_role),
        )
        .route(
            "/api/admin/applications/{id}/authorization/profiles/{profile_id}/users/{user_id}/roles",
            get(list_application_profile_user_roles).put(update_application_profile_user_roles),
        )
        .route(
            "/api/admin/applications/{id}/authorization/profiles/{profile_id}/groups/{group_id}/roles",
            get(list_application_profile_group_roles).put(update_application_profile_group_roles),
        )
        .route(
            "/api/admin/applications/{id}/authorization/profiles/{profile_id}/organization-roles/{organization_role}/roles",
            get(list_application_profile_organization_role_roles)
                .put(update_application_profile_organization_role_roles),
        )
        .route(
            "/api/admin/applications/{id}/authorization/profiles/{profile_id}/users/{user_id}/permission-overrides",
            get(list_application_profile_user_permission_overrides)
                .put(update_application_profile_user_permission_overrides),
        )
        .route(
            "/api/admin/applications/{id}/authorization/profiles/{profile_id}/{user_id}",
            get(application_profile_authorization_preview),
        )
        .route(
            "/api/admin/applications/{id}/authorization/subjects",
            get(application_authorization_subjects),
        )
        .route(
            "/api/admin/applications/{id}/roles/{role_id}",
            put(update_application_role).delete(delete_application_role),
        )
        .route(
            "/api/admin/applications/{id}/users/{user_id}/roles",
            get(list_application_user_roles).put(update_application_user_roles),
        )
        .route(
            "/api/admin/applications/{id}/groups/{group_id}/roles",
            get(list_application_group_roles).put(update_application_group_roles),
        )
        .route(
            "/api/admin/applications/{id}/organization-roles/{organization_role}/roles",
            get(list_application_organization_role_roles)
                .put(update_application_organization_role_roles),
        )
        .route(
            "/api/admin/applications/{id}/users/{user_id}/permission-overrides",
            get(list_application_user_permission_overrides)
                .put(update_application_user_permission_overrides),
        )
        .route(
            "/api/admin/applications/{id}/authorization/{user_id}",
            get(application_authorization_preview),
        )
        .route(
            "/api/admin/applications/{id}/enrollment-codes",
            get(list_application_enrollment_codes).post(create_application_enrollment_code),
        )
        .route(
            "/api/admin/applications/{id}/enrollment-codes/{code_id}",
            delete(delete_application_enrollment_code),
        )
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
            "/api/admin/organization-options",
            get(list_organization_options),
        )
        .route(
            "/api/admin/organizations/{id}",
            put(update_organization).delete(delete_organization),
        )
        .route(
            "/api/admin/organizations/{id}/members",
            get(list_organization_members)
                .post(upsert_organization_member)
                .put(update_organization_members),
        )
        .route(
            "/api/admin/organizations/{id}/member-invitations",
            get(list_organization_member_invitations).post(create_organization_member_invitation),
        )
        .route(
            "/api/admin/organizations/{id}/member-invitations/{invitation_id}",
            delete(delete_organization_member_invitation),
        )
        .route("/api/admin/users/{id}/access", get(user_access))
        .route("/api/admin/users/{id}/roles", put(update_user_roles))
        .route(
            "/api/admin/authorization-codes",
            get(list_invitations).post(create_invitation),
        )
        .route(
            "/api/admin/authorization-codes/{id}/reveal",
            post(reveal_invitation_code),
        )
        .route(
            "/api/admin/authorization-codes/{id}/redemptions",
            get(list_invitation_redemptions),
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
            "/api/admin/invitations/{id}/reveal",
            post(reveal_invitation_code),
        )
        .route(
            "/api/admin/invitations/{id}/redemptions",
            get(list_invitation_redemptions),
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

#[derive(Debug, Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
    mfa_challenge_id: Option<String>,
    mfa_code: Option<String>,
    captcha_challenge_id: Option<String>,
    captcha_answer: Option<String>,
    return_to: Option<String>,
    account_flow: Option<String>,
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
            let jar = auth::issue_session_with_login_event(
                &state,
                jar,
                &headers,
                request_ip.clone(),
                &user,
                &completed_method,
                auth::LoginEventContext {
                    external_provider: external_provider.clone(),
                    account_flow: payload.account_flow.clone(),
                    ..Default::default()
                },
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

    let jar = auth::issue_session_with_login_event(
        &state,
        jar,
        &headers,
        request_ip,
        &user,
        &login_method,
        auth::LoginEventContext {
            external_provider,
            account_flow: payload.account_flow,
            ..Default::default()
        },
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

async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> AppResult<(CookieJar, Json<serde_json::Value>)> {
    let current = auth::current_user_from_cookie(&state, &jar).await?;
    let mut frontchannel_frames = Vec::new();
    if let Some(current) = current.as_ref() {
        let public_session_id = util::session_public_id(&current.session_id);
        frontchannel_frames = match frontchannel_logout::frames_for_user(
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
        if let Err(err) = backchannel_logout::notify_user_logout(
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
    if let Some(current) = current.as_ref() {
        state.db.delete_session(&current.session_id).await?;
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
    auth::ensure_current_account_mutable(&current)?;
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
    auth::ensure_current_account_mutable(&current)?;
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
    auth::ensure_current_account_mutable(&current)?;
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
    auth::ensure_current_account_mutable(&current)?;
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
        auth::current_user_response_for_session(&state, current).await?,
    )))
}

#[derive(Debug, Deserialize)]
struct OrganizationContextInput {
    organization_id: String,
}

#[derive(Debug, Serialize)]
struct OrganizationContextResponse {
    organization: Option<UserOrganizationRecord>,
}

/// The tenant creation endpoint is intentionally self-service.  It creates a
/// regular tenant only (never the protected Signet system tenant), makes the
/// caller its owner, and selects it for the console.  Global platform roles
/// are therefore not a prerequisite for a customer to start using Signet.
#[derive(Debug, Deserialize)]
struct MyOrganizationInput {
    slug: String,
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    allowed_email_domains: Vec<String>,
}

async fn my_organizations(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<Vec<UserOrganizationRecord>>> {
    let current = auth::require_current_user(&state, &jar).await?;
    Ok(Json(
        state.db.list_user_organizations(&current.user.id).await?,
    ))
}

async fn create_my_organization(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<MyOrganizationInput>,
) -> AppResult<Json<OrganizationResponse>> {
    let current = auth::require_current_user(&state, &jar).await?;
    auth::ensure_current_account_mutable(&current)?;
    let organization = state
        .db
        .insert_organization(NewOrganization {
            slug: organizations::normalize_slug(&payload.slug)?,
            name: organizations::normalize_name(&payload.name)?,
            kind: organizations::ORGANIZATION_KIND_TENANT.to_string(),
            description: normalize_optional_text(payload.description),
            allowed_email_domains: security_policy::normalize_email_domain_rules(
                payload.allowed_email_domains,
            )?,
            is_active: true,
        })
        .await?;
    state
        .db
        .upsert_organization_member(
            &organization.id,
            &current.user.id,
            organizations::ROLE_OWNER,
        )
        .await?;
    state
        .db
        .set_active_user_organization(&current.user.id, &organization.id)
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "organization.self_service_create",
            "organization",
            Some(organization.id.clone()),
            serde_json::json!({ "slug": organization.slug, "name": organization.name }),
        ))
        .await?;
    Ok(Json(organization_response(&state, organization).await?))
}

async fn my_organization_context(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<OrganizationContextResponse>> {
    let current = auth::require_current_user(&state, &jar).await?;
    Ok(Json(OrganizationContextResponse {
        organization: state.db.active_user_organization(&current.user.id).await?,
    }))
}

async fn set_my_organization_context(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<OrganizationContextInput>,
) -> AppResult<Json<OrganizationContextResponse>> {
    let current = auth::require_current_user(&state, &jar).await?;
    auth::ensure_current_account_mutable(&current)?;
    let organization = state
        .db
        .set_active_user_organization(&current.user.id, payload.organization_id.trim())
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "organization.context.select",
            "organization",
            Some(organization.id.clone()),
            serde_json::json!({ "slug": organization.slug }),
        ))
        .await?;
    Ok(Json(OrganizationContextResponse {
        organization: Some(organization),
    }))
}

#[derive(Debug, Serialize)]
struct CsrfTokenResponse {
    csrf_token: String,
}

async fn csrf_token(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<CsrfTokenResponse>> {
    Ok(Json(CsrfTokenResponse {
        csrf_token: csrf::token_for_current_session(&state, &jar).await?,
    }))
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
            id: util::session_public_id(&record.id),
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
    Path(session_handle): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let current = auth::require_current_user(&state, &jar).await?;
    auth::ensure_current_account_mutable(&current)?;
    let target = state
        .db
        .list_user_sessions(&current.user.id)
        .await?
        .into_iter()
        .find(|record| util::session_public_id(&record.id) == session_handle)
        .ok_or(AppError::NotFound)?;
    if target.id == current.session_id {
        return Err(AppError::BadRequest(
            "current session must be ended with logout".to_string(),
        ));
    }
    let revoked = state
        .db
        .delete_user_session(&current.user.id, &target.id)
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
            Some(session_handle),
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
    auth::ensure_current_account_mutable(&current)?;
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
    brand_logo_url: Option<String>,
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
    let LoginSettingsInput {
        brand_logo_url,
        email_domains,
        quick_links,
    } = payload;
    let quick_link_count = quick_links.len();
    let brand_logo_url = match brand_logo_url {
        Some(value) => normalize_brand_logo_url(value)?,
        None => state.db.login_settings().await?.brand_logo_url,
    };
    let settings = state
        .db
        .upsert_login_settings(NewLoginSettings {
            brand_logo_url,
            email_domains: normalize_email_domains(email_domains)?,
            quick_links: normalize_quick_links(quick_links)?,
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

fn normalize_brand_logo_url(value: String) -> AppResult<String> {
    let value = normalize_optional_http_url(value, "brand_logo_url", false)?;
    if value.len() > 2048 {
        return Err(AppError::BadRequest(
            "brand_logo_url exceeds 2048 characters".to_string(),
        ));
    }
    Ok(value)
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
        links.push(QuickLink {
            id,
            label: label.chars().take(48).collect(),
            url: url.to_string(),
            // Preserve the serialized field for compatibility with existing
            // data, but do not carry forward a preconfigured icon mapping.
            icon: String::new(),
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
    organization_id: Option<String>,
    linked_identity: Option<String>,
}

async fn list_users(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<UserListQuery>,
) -> AppResult<Json<Vec<PublicUser>>> {
    require_user_reader(&state, &jar).await?;
    let scope = user_list_scope(query.status.as_deref())?;
    let mut users = state.db.list_users(scope).await?;
    if let Some(organization_id) = query
        .organization_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let member_ids = state
            .db
            .list_organization_members(organization_id)
            .await?
            .into_iter()
            .map(|member| member.user_id)
            .collect::<BTreeSet<_>>();
        users.retain(|user| member_ids.contains(&user.id));
    }
    let linked_identity_filter = query
        .linked_identity
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("all");
    match linked_identity_filter {
        "all" => {}
        "linked" | "unlinked" => {
            let linked_user_ids = state
                .db
                .list_user_ids_with_linked_identities()
                .await?
                .into_iter()
                .collect::<BTreeSet<_>>();
            let has_linked_identity = linked_identity_filter == "linked";
            users.retain(|user| linked_user_ids.contains(&user.id) == has_linked_identity);
        }
        other => {
            return Err(AppError::BadRequest(format!(
                "unsupported linked identity filter: {other}"
            )));
        }
    }
    Ok(Json(users.into_iter().map(|user| user.public()).collect()))
}

fn user_list_scope(status: Option<&str>) -> AppResult<UserListScope> {
    match status.unwrap_or("live") {
        "live" => Ok(UserListScope::Live),
        "active" => Ok(UserListScope::Active),
        "disabled" => Ok(UserListScope::Disabled),
        "archived" => Ok(UserListScope::Archived),
        "authorization_code" => Ok(UserListScope::AuthorizationCode),
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
    kind: String,
    description: Option<String>,
    allowed_email_domains: Vec<String>,
    is_active: bool,
    member_count: i64,
    created_at: i64,
    updated_at: i64,
}

#[derive(Debug, Serialize)]
struct OrganizationOptionResponse {
    id: String,
    slug: String,
    name: String,
    kind: String,
    is_active: bool,
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
    #[serde(default)]
    user_id: Option<String>,
    #[serde(default)]
    email: Option<String>,
    role: String,
}

#[derive(Debug, Deserialize)]
struct OrganizationMembersInput {
    members: Vec<OrganizationMemberPayload>,
}

#[derive(Debug, Deserialize)]
struct OrganizationMemberInvitationInput {
    email: String,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    expires_at: i64,
    #[serde(default = "default_organization_role")]
    organization_role: String,
    #[serde(default = "default_true")]
    is_active: bool,
}

#[derive(Debug, Serialize)]
struct OrganizationMemberInvitationCreateResponse {
    invitation: PublicInvitation,
    code: String,
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
const IAP_READ_PERMISSIONS: &[Permission] = &[Permission::IapRead, Permission::IapManage];
const ORGANIZATION_READ_PERMISSIONS: &[Permission] = &[
    Permission::OrganizationsRead,
    Permission::OrganizationsManage,
];
const ORGANIZATION_OPTION_PERMISSIONS: &[Permission] = &[
    Permission::OrganizationsRead,
    Permission::OrganizationsManage,
    // User-directory readers need organization names to narrow the account
    // list, without receiving the organization member roster.
    Permission::UsersRead,
    Permission::UsersManage,
    // Authorization-code managers need non-sensitive organization metadata to
    // bind an enrollment code, without gaining access to organization members
    // or full organization administration.
    Permission::AuthorizationCodesManage,
    Permission::ClientsManage,
    Permission::IapRead,
    Permission::IapManage,
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

async fn require_organization_option_reader(
    state: &AppState,
    jar: &CookieJar,
) -> AppResult<auth::CurrentUser> {
    require_any_permission(state, jar, ORGANIZATION_OPTION_PERMISSIONS).await
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
    if !current.can_mutate_account() {
        return Err(AppError::Forbidden);
    }
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
    if !current.can_mutate_account() {
        return Err(AppError::Forbidden);
    }
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
    let member_count = state
        .db
        .count_organization_members(&organization.id)
        .await?;
    organization_response_with_member_count(organization, member_count)
}

fn organization_response_with_member_count(
    organization: OrganizationRecord,
    member_count: i64,
) -> AppResult<OrganizationResponse> {
    Ok(OrganizationResponse {
        id: organization.id,
        slug: organization.slug,
        name: organization.name,
        kind: organization.kind,
        description: organization.description,
        allowed_email_domains: security_policy::normalize_email_domain_rules(util::from_json::<
            Vec<String>,
        >(
            &organization.allowed_email_domains,
        )?)?,
        is_active: organization.is_active == 1,
        member_count,
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
        kind: organizations::ORGANIZATION_KIND_TENANT.to_string(),
        description: normalize_optional_text(input.description),
        allowed_email_domains: security_policy::normalize_email_domain_rules(
            input.allowed_email_domains,
        )?,
        is_active: input.is_active,
    })
}

async fn organization_members_input(
    state: &AppState,
    input: OrganizationMembersInput,
) -> AppResult<Vec<OrganizationMemberInput>> {
    let mut members = Vec::with_capacity(input.members.len());
    for member in input.members {
        let user_id = member.user_id.unwrap_or_default().trim().to_string();
        let email = member.email.unwrap_or_default().trim().to_string();
        let user_id = match (user_id.is_empty(), email.is_empty()) {
            (false, true) => user_id,
            (true, false) => {
                state
                    .db
                    .find_user_by_email(&email)
                    .await?
                    .ok_or_else(|| {
                        AppError::BadRequest("no account found for member email".to_string())
                    })?
                    .id
            }
            _ => {
                return Err(AppError::BadRequest(
                    "organization member must provide exactly one of user_id or email".to_string(),
                ));
            }
        };
        members.push(OrganizationMemberInput {
            user_id,
            role: organizations::normalize_role(&member.role)?,
        });
    }
    Ok(members)
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
    let member_counts = state.db.list_organization_member_counts().await?;
    let mut response = Vec::new();
    for organization in state.db.list_organizations().await? {
        let member_count = member_counts
            .get(&organization.id)
            .copied()
            .unwrap_or_default();
        response.push(organization_response_with_member_count(
            organization,
            member_count,
        )?);
    }
    Ok(Json(response))
}

async fn list_organization_options(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<Vec<OrganizationOptionResponse>>> {
    require_organization_option_reader(&state, &jar).await?;
    Ok(Json(
        state
            .db
            .list_organizations()
            .await?
            .into_iter()
            .map(|organization| OrganizationOptionResponse {
                id: organization.id,
                slug: organization.slug,
                name: organization.name,
                kind: organization.kind,
                is_active: organization.is_active == 1,
            })
            .collect(),
    ))
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

async fn list_organization_members(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<Vec<OrganizationMemberResponse>>> {
    let current = auth::require_current_user(&state, &jar).await?;
    auth::ensure_current_account_mutable(&current)?;
    let organization = state
        .db
        .find_organization_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    require_organization_manager_for(&state, &current, &organization.id).await?;
    Ok(Json(
        state
            .db
            .list_organization_members(&id)
            .await?
            .into_iter()
            .map(organization_member_response)
            .collect(),
    ))
}

/// Adds a known Signet account to one enterprise without exposing the global
/// user directory. Tenant administrators may use an email address; platform
/// administrators can retain the stable-ID workflow used by the old console.
async fn upsert_organization_member(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<OrganizationMemberPayload>,
) -> AppResult<Json<serde_json::Value>> {
    let current = auth::require_current_user(&state, &jar).await?;
    auth::ensure_current_account_mutable(&current)?;
    let organization = state
        .db
        .find_organization_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    require_organization_manager_for(&state, &current, &organization.id).await?;
    if organization.kind == organizations::ORGANIZATION_KIND_SYSTEM
        && !state
            .db
            .has_permission(&current.user, Permission::OrganizationsManage)
            .await?
    {
        return Err(AppError::Forbidden);
    }
    let member = organization_members_input(
        &state,
        OrganizationMembersInput {
            members: vec![payload],
        },
    )
    .await?
    .pop()
    .ok_or_else(|| AppError::BadRequest("organization member is required".to_string()))?;
    ensure_assignable_user_ids(
        &state,
        &BTreeSet::from([member.user_id.clone()]),
        &BTreeSet::new(),
        "organizations",
    )
    .await?;
    state
        .db
        .upsert_organization_member(&id, &member.user_id, &member.role)
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "organization.member.upsert",
            "organization",
            Some(id),
            serde_json::json!({ "user_id": member.user_id, "role": member.role }),
        ))
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// Creates a one-time registration capability for a specific email address.
/// Unlike application trial enrollment, this produces a normal Signet account
/// and grants it membership in the enterprise on successful registration.
/// Existing accounts continue to be added through the member-by-email action.
async fn list_organization_member_invitations(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<Vec<PublicInvitation>>> {
    let current = auth::require_current_user(&state, &jar).await?;
    let organization = state
        .db
        .find_organization_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    require_organization_manager_for(&state, &current, &organization.id).await?;
    if organization.kind == organizations::ORGANIZATION_KIND_SYSTEM
        && !state
            .db
            .has_permission(&current.user, Permission::OrganizationsManage)
            .await?
    {
        return Err(AppError::Forbidden);
    }
    Ok(Json(
        state
            .db
            .list_organization_registration_invitations(&organization.id)
            .await?
            .into_iter()
            .map(InvitationRecord::public)
            .collect::<AppResult<Vec<_>>>()?,
    ))
}

async fn create_organization_member_invitation(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<OrganizationMemberInvitationInput>,
) -> AppResult<Json<OrganizationMemberInvitationCreateResponse>> {
    let current = auth::require_current_user(&state, &jar).await?;
    let organization = state
        .db
        .find_organization_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    require_organization_manager_for(&state, &current, &organization.id).await?;
    if organization.kind == organizations::ORGANIZATION_KIND_SYSTEM
        && !state
            .db
            .has_permission(&current.user, Permission::OrganizationsManage)
            .await?
    {
        return Err(AppError::Forbidden);
    }
    if organization.is_active != 1 {
        return Err(AppError::BadRequest(
            "cannot invite members to a disabled organization".to_string(),
        ));
    }
    if payload.expires_at <= util::now_ts() {
        return Err(AppError::BadRequest(
            "organization member invitations require a future expiry".to_string(),
        ));
    }
    let email = normalize_optional_email(Some(payload.email))?.ok_or_else(|| {
        AppError::BadRequest("organization member invitation email is required".to_string())
    })?;
    if !organization.allows_email(&email)? {
        return Err(AppError::BadRequest(
            "email is not allowed by the organization policy".to_string(),
        ));
    }
    let organization_role = organizations::normalize_role(&payload.organization_role)?;
    let code = format!("ORG-{}", util::random_token(18));
    let signing_key = state
        .db
        .list_signing_keys()
        .await?
        .into_iter()
        .find(|key| key.is_active == 1)
        .ok_or_else(|| {
            AppError::Configuration(
                "an active signing key is required to create a revealable organization invitation"
                    .to_string(),
            )
        })?;
    let ciphertext =
        util::encrypt_authorization_code_for_reveal(&signing_key.private_key_pem, &code)?;
    let (invitation, code) = state
        .db
        .insert_invitation_with_reveal_secret(
            NewInvitation {
                code_type: AuthorizationCodeType::Registration,
                login_code_level: LoginCodeLevel::AccountRecovery,
                allowed_client_ids: Vec::new(),
                organization_id: Some(organization.id.clone()),
                organization_role: Some(organization_role.clone()),
                description: normalize_optional_text(payload.description),
                authorized_email: Some(email.clone()),
                authorized_username: None,
                authorized_user_id: None,
                authorized_display_name: normalize_optional_text(payload.display_name),
                expires_at: Some(payload.expires_at),
                max_uses: Some(1),
                is_active: payload.is_active,
                created_by: Some(current.user.id.clone()),
            },
            code,
            signing_key.kid,
            ciphertext,
        )
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "organization.member_invitation.create",
            "organization",
            Some(organization.id.clone()),
            serde_json::json!({
                "invitation_id": invitation.id,
                "email": email,
                "organization_role": organization_role,
            }),
        ))
        .await?;
    Ok(Json(OrganizationMemberInvitationCreateResponse {
        invitation: invitation.public()?,
        code,
    }))
}

async fn delete_organization_member_invitation(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, invitation_id)): Path<(String, String)>,
) -> AppResult<Json<serde_json::Value>> {
    let current = auth::require_current_user(&state, &jar).await?;
    let organization = state
        .db
        .find_organization_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    require_organization_manager_for(&state, &current, &organization.id).await?;
    if organization.kind == organizations::ORGANIZATION_KIND_SYSTEM
        && !state
            .db
            .has_permission(&current.user, Permission::OrganizationsManage)
            .await?
    {
        return Err(AppError::Forbidden);
    }
    if !state
        .db
        .organization_registration_invitation_belongs_to(&organization.id, &invitation_id)
        .await?
    {
        return Err(AppError::NotFound);
    }
    state.db.delete_invitation(&invitation_id).await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "organization.member_invitation.delete",
            "organization",
            Some(organization.id),
            serde_json::json!({ "invitation_id": invitation_id }),
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
    let current = auth::require_current_user(&state, &jar).await?;
    auth::ensure_current_account_mutable(&current)?;
    let members = organization_members_input(&state, payload).await?;
    let organization = state
        .db
        .find_organization_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    require_organization_manager_for(&state, &current, &organization.id).await?;
    // Signet is the platform-control tenant. Its roster may be managed only
    // by a global organization administrator, never merely by a membership
    // role within the system tenant.
    if organization.kind == organizations::ORGANIZATION_KIND_SYSTEM
        && !state
            .db
            .has_permission(&current.user, Permission::OrganizationsManage)
            .await?
    {
        return Err(AppError::Forbidden);
    }
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

const BULK_IMPORT_MAX_BYTES: usize = 1_048_576;
const BULK_IMPORT_MAX_ROWS: usize = 1_000;
const BULK_IMPORT_HEADERS: [&str; 6] = [
    "email",
    "username",
    "display_name",
    "organization_slug",
    "organization_role",
    "is_active",
];

#[derive(Debug, Deserialize, Default)]
struct BulkImportQuery {
    #[serde(default)]
    dry_run: bool,
}

#[derive(Debug, Serialize)]
struct BulkImportResponse {
    dry_run: bool,
    atomic: bool,
    committed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    batch_error: Option<String>,
    summary: BulkImportSummary,
    rows: Vec<BulkImportRowResponse>,
}

#[derive(Debug, Serialize)]
struct BulkImportSummary {
    total: usize,
    created: usize,
    would_create: usize,
    invalid: usize,
    not_committed: usize,
}

#[derive(Debug, Serialize)]
struct BulkImportRowResponse {
    /// The physical CSV line, where the header is line 1.
    row: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    /// `created`, `would_create`, `invalid`, or `not_committed`.
    outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Clone)]
struct BulkImportCandidate {
    result_index: usize,
    email: String,
    username: String,
    display_name: Option<String>,
    organization_slug: Option<String>,
    organization_role: Option<String>,
    organization_id: Option<String>,
    is_active: bool,
}

#[derive(Debug)]
struct ParsedBulkImport {
    rows: Vec<BulkImportRowResponse>,
    candidates: Vec<BulkImportCandidate>,
    has_organization_assignments: bool,
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

/// Import new enterprise accounts from a CSV document.
///
/// The endpoint is intentionally insert-only.  A dry run performs the same
/// validation and collision checks as a commit, while a commit creates all
/// users and organization memberships in one database transaction.
async fn import_users_csv(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<BulkImportQuery>,
    csv_document: String,
) -> AppResult<Response> {
    let current = require_user_manager(&state, &jar).await?;
    if csv_document.len() > BULK_IMPORT_MAX_BYTES {
        return Err(AppError::BadRequest(format!(
            "CSV import exceeds the {} byte limit",
            BULK_IMPORT_MAX_BYTES
        )));
    }

    let mut batch = match parse_bulk_import_csv(&csv_document) {
        Ok(batch) => batch,
        Err(message) => {
            record_bulk_import_audit(
                &state,
                &current.user.id,
                query.dry_run,
                false,
                &[],
                Some(&message),
            )
            .await?;
            return Err(AppError::BadRequest(message));
        }
    };

    // A user manager may create unassigned accounts, but assigning an
    // organization owner/admin/member is organization administration too.
    if batch.has_organization_assignments {
        state
            .db
            .require_permission(&current.user, Permission::OrganizationsManage)
            .await?;
    }

    validate_bulk_import_duplicates(&mut batch);
    validate_bulk_import_existing_identities(&state, &mut batch).await?;
    validate_bulk_import_organizations(&state, &mut batch).await?;

    if bulk_import_has_invalid_rows(&batch.rows) {
        mark_bulk_import_not_committed(&mut batch.rows);
        let batch_error = "the CSV contains invalid rows; no accounts were imported";
        record_bulk_import_audit(
            &state,
            &current.user.id,
            query.dry_run,
            false,
            &batch.rows,
            Some(batch_error),
        )
        .await?;
        return Ok((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(bulk_import_response(
                query.dry_run,
                false,
                Some(batch_error.to_string()),
                batch.rows,
            )),
        )
            .into_response());
    }

    if query.dry_run {
        record_bulk_import_audit(&state, &current.user.id, true, false, &batch.rows, None).await?;
        return Ok(Json(bulk_import_response(true, false, None, batch.rows)).into_response());
    }

    // Imported accounts have a cryptographically random, undisclosed initial
    // password.  The same per-batch hash is safe because its plaintext is not
    // returned, logged, or retained; it also avoids an expensive Argon2 run
    // for every CSV row.  Administrators can subsequently use the ordinary
    // password-reset/activation path for each account.
    let initial_password_hash =
        util::hash_password(&format!("BulkProvisioned-{}9!", util::random_token(48)))?;
    let users = batch
        .candidates
        .iter()
        .filter(|candidate| batch.rows[candidate.result_index].outcome == "would_create")
        .map(|candidate| NewBulkProvisionedUser {
            user: NewUser {
                email: candidate.email.clone(),
                username: candidate.username.clone(),
                display_name: candidate.display_name.clone(),
                phone: None,
                password_hash: initial_password_hash.clone(),
                email_verified_at: Some(util::now_ts()),
                phone_verified_at: None,
                is_admin: false,
                is_active: candidate.is_active,
                archived_at: None,
            },
            organization_id: candidate.organization_id.clone(),
            organization_role: candidate.organization_role.clone(),
        })
        .collect::<Vec<_>>();

    let created = match state.db.insert_bulk_provisioned_users(users).await {
        Ok(users) => users,
        Err(error)
            if matches!(
                &error,
                AppError::BadRequest(_) | AppError::Forbidden | AppError::NotFound
            ) =>
        {
            // The preflight passed, so a validation failure here means the
            // database changed between preflight and the transaction.  The DB
            // method rolls the entire transaction back.
            mark_bulk_import_not_committed(&mut batch.rows);
            let batch_error =
                "the directory changed while this batch was committing; no accounts were imported";
            record_bulk_import_audit(
                &state,
                &current.user.id,
                false,
                false,
                &batch.rows,
                Some(batch_error),
            )
            .await?;
            return Ok((
                StatusCode::CONFLICT,
                Json(bulk_import_response(
                    false,
                    false,
                    Some(batch_error.to_string()),
                    batch.rows,
                )),
            )
                .into_response());
        }
        Err(error) => return Err(error),
    };

    for (candidate, user) in batch.candidates.iter().zip(created) {
        let row = &mut batch.rows[candidate.result_index];
        row.outcome = "created".to_string();
        row.user_id = Some(user.id);
    }
    record_bulk_import_audit(&state, &current.user.id, false, true, &batch.rows, None).await?;
    Ok(Json(bulk_import_response(false, true, None, batch.rows)).into_response())
}

fn parse_bulk_import_csv(csv_document: &str) -> Result<ParsedBulkImport, String> {
    let mut reader = ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .trim(csv::Trim::All)
        .from_reader(csv_document.as_bytes());
    let header_positions = bulk_import_header_positions(
        &reader
            .headers()
            .map_err(|error| format!("CSV header is invalid: {error}"))?
            .clone(),
    )?;

    let mut rows = Vec::new();
    let mut candidates = Vec::new();
    let mut has_organization_assignments = false;
    for (index, record) in reader.records().enumerate() {
        if index >= BULK_IMPORT_MAX_ROWS {
            return Err(format!(
                "CSV import exceeds the {BULK_IMPORT_MAX_ROWS} row limit"
            ));
        }
        let record = record.map_err(|error| format!("CSV row is invalid: {error}"))?;
        let row = record
            .position()
            .map(|position| position.line() as usize)
            .unwrap_or(index + 2);
        let result_index = rows.len();
        let email_raw = bulk_import_csv_value(&record, &header_positions, "email");
        let username_raw = bulk_import_csv_value(&record, &header_positions, "username");
        rows.push(BulkImportRowResponse {
            row,
            email: (!email_raw.is_empty()).then(|| email_raw.to_string()),
            username: (!username_raw.is_empty()).then(|| username_raw.to_string()),
            outcome: "would_create".to_string(),
            user_id: None,
            error: None,
        });

        if record.len() != BULK_IMPORT_HEADERS.len() {
            mark_bulk_import_row_invalid(
                &mut rows,
                result_index,
                format!(
                    "expected {} columns but found {}",
                    BULK_IMPORT_HEADERS.len(),
                    record.len()
                ),
            );
            continue;
        }

        let email = match normalize_required_email(email_raw.to_string()) {
            Ok(value) => {
                rows[result_index].email = Some(value.clone());
                Some(value)
            }
            Err(error) => {
                mark_bulk_import_row_invalid(&mut rows, result_index, error.to_string());
                None
            }
        };
        let username = match normalize_required_text(username_raw.to_string(), "username") {
            Ok(value) => {
                rows[result_index].username = Some(value.clone());
                Some(value)
            }
            Err(error) => {
                mark_bulk_import_row_invalid(&mut rows, result_index, error.to_string());
                None
            }
        };
        let display_name = normalize_optional_text(
            (!bulk_import_csv_value(&record, &header_positions, "display_name").is_empty()).then(
                || bulk_import_csv_value(&record, &header_positions, "display_name").to_string(),
            ),
        );
        let organization_slug_raw =
            bulk_import_csv_value(&record, &header_positions, "organization_slug");
        let organization_role_raw =
            bulk_import_csv_value(&record, &header_positions, "organization_role");
        if !organization_slug_raw.is_empty() {
            has_organization_assignments = true;
        }
        let organization_slug = if organization_slug_raw.is_empty() {
            None
        } else {
            match organizations::normalize_slug(organization_slug_raw) {
                Ok(value) => Some(value),
                Err(error) => {
                    mark_bulk_import_row_invalid(&mut rows, result_index, error.to_string());
                    None
                }
            }
        };
        let organization_role = if organization_role_raw.is_empty() {
            None
        } else {
            match organizations::normalize_role(organization_role_raw) {
                Ok(value) => Some(value),
                Err(error) => {
                    mark_bulk_import_row_invalid(&mut rows, result_index, error.to_string());
                    None
                }
            }
        };
        match (&organization_slug, &organization_role) {
            (Some(_), None) => mark_bulk_import_row_invalid(
                &mut rows,
                result_index,
                "organization_role is required when organization_slug is set",
            ),
            (None, Some(_)) => mark_bulk_import_row_invalid(
                &mut rows,
                result_index,
                "organization_role must be empty when organization_slug is empty",
            ),
            _ => {}
        }
        let is_active = match parse_bulk_import_is_active(bulk_import_csv_value(
            &record,
            &header_positions,
            "is_active",
        )) {
            Ok(value) => Some(value),
            Err(message) => {
                mark_bulk_import_row_invalid(&mut rows, result_index, message);
                None
            }
        };

        if let (Some(email), Some(username), Some(is_active)) = (email, username, is_active)
            && rows[result_index].outcome != "invalid"
        {
            candidates.push(BulkImportCandidate {
                result_index,
                email,
                username,
                display_name,
                organization_slug,
                organization_role,
                organization_id: None,
                is_active,
            });
        }
    }

    if rows.is_empty() {
        return Err("CSV import must contain at least one data row".to_string());
    }
    Ok(ParsedBulkImport {
        rows,
        candidates,
        has_organization_assignments,
    })
}

fn bulk_import_header_positions(
    headers: &csv::StringRecord,
) -> Result<BTreeMap<String, usize>, String> {
    let mut positions = BTreeMap::new();
    for (index, value) in headers.iter().enumerate() {
        let value = if index == 0 {
            value.strip_prefix('\u{feff}').unwrap_or(value)
        } else {
            value
        };
        let value = value.trim().to_ascii_lowercase();
        if !BULK_IMPORT_HEADERS.contains(&value.as_str()) {
            return Err(format!("unexpected CSV column: {value}"));
        }
        if positions.insert(value.clone(), index).is_some() {
            return Err(format!("CSV column appears more than once: {value}"));
        }
    }
    for required in BULK_IMPORT_HEADERS {
        if !positions.contains_key(required) {
            return Err(format!("CSV column is required: {required}"));
        }
    }
    if headers.len() != BULK_IMPORT_HEADERS.len() {
        return Err("CSV header must contain exactly the supported columns".to_string());
    }
    Ok(positions)
}

fn bulk_import_csv_value<'a>(
    record: &'a csv::StringRecord,
    header_positions: &BTreeMap<String, usize>,
    field: &str,
) -> &'a str {
    record
        .get(*header_positions.get(field).expect("validated CSV header"))
        .unwrap_or_default()
        .trim()
}

fn parse_bulk_import_is_active(value: &str) -> Result<bool, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => Err("is_active must be true or false".to_string()),
    }
}

fn mark_bulk_import_row_invalid(
    rows: &mut [BulkImportRowResponse],
    index: usize,
    message: impl Into<String>,
) {
    let row = &mut rows[index];
    let message = message.into();
    row.outcome = "invalid".to_string();
    match &mut row.error {
        Some(existing) if !existing.contains(&message) => {
            existing.push_str("; ");
            existing.push_str(&message);
        }
        Some(_) => {}
        None => row.error = Some(message),
    }
}

fn validate_bulk_import_duplicates(batch: &mut ParsedBulkImport) {
    let mut email_rows = BTreeMap::<String, usize>::new();
    let mut username_rows = BTreeMap::<String, usize>::new();
    for candidate in batch.candidates.clone() {
        if let Some(first_index) =
            email_rows.insert(candidate.email.clone(), candidate.result_index)
            && first_index != candidate.result_index
        {
            let first_row = batch.rows[first_index].row;
            let duplicate_row = batch.rows[candidate.result_index].row;
            mark_bulk_import_row_invalid(
                &mut batch.rows,
                first_index,
                format!("email duplicates CSV row {duplicate_row}"),
            );
            mark_bulk_import_row_invalid(
                &mut batch.rows,
                candidate.result_index,
                format!("email duplicates CSV row {first_row}"),
            );
        }
        if let Some(first_index) =
            username_rows.insert(candidate.username.clone(), candidate.result_index)
            && first_index != candidate.result_index
        {
            let first_row = batch.rows[first_index].row;
            let duplicate_row = batch.rows[candidate.result_index].row;
            mark_bulk_import_row_invalid(
                &mut batch.rows,
                first_index,
                format!("username duplicates CSV row {duplicate_row}"),
            );
            mark_bulk_import_row_invalid(
                &mut batch.rows,
                candidate.result_index,
                format!("username duplicates CSV row {first_row}"),
            );
        }
    }
}

async fn validate_bulk_import_existing_identities(
    state: &AppState,
    batch: &mut ParsedBulkImport,
) -> AppResult<()> {
    for candidate in batch.candidates.clone() {
        if batch.rows[candidate.result_index].outcome == "invalid" {
            continue;
        }
        if state
            .db
            .find_user_by_email(&candidate.email)
            .await?
            .is_some()
        {
            mark_bulk_import_row_invalid(
                &mut batch.rows,
                candidate.result_index,
                "email already belongs to an existing account",
            );
        }
        if state
            .db
            .find_user_by_username(&candidate.username)
            .await?
            .is_some()
        {
            mark_bulk_import_row_invalid(
                &mut batch.rows,
                candidate.result_index,
                "username already belongs to an existing account",
            );
        }
    }
    Ok(())
}

async fn validate_bulk_import_organizations(
    state: &AppState,
    batch: &mut ParsedBulkImport,
) -> AppResult<()> {
    let organizations_by_slug = state
        .db
        .list_organizations()
        .await?
        .into_iter()
        .map(|organization| (organization.slug.clone(), organization))
        .collect::<BTreeMap<_, _>>();
    for (candidate_index, candidate) in batch.candidates.clone().into_iter().enumerate() {
        if batch.rows[candidate.result_index].outcome == "invalid" {
            continue;
        }
        let Some(slug) = candidate.organization_slug.as_deref() else {
            continue;
        };
        let Some(organization) = organizations_by_slug.get(slug) else {
            mark_bulk_import_row_invalid(
                &mut batch.rows,
                candidate.result_index,
                "organization_slug does not reference an existing organization",
            );
            continue;
        };
        if organization.is_active != 1 {
            mark_bulk_import_row_invalid(
                &mut batch.rows,
                candidate.result_index,
                "organization is inactive",
            );
            continue;
        }
        if !organization.allows_email(&candidate.email)? {
            mark_bulk_import_row_invalid(
                &mut batch.rows,
                candidate.result_index,
                "email is not allowed by the organization policy",
            );
            continue;
        }
        batch.candidates[candidate_index].organization_id = Some(organization.id.clone());
    }
    Ok(())
}

fn bulk_import_has_invalid_rows(rows: &[BulkImportRowResponse]) -> bool {
    rows.iter().any(|row| row.outcome == "invalid")
}

fn mark_bulk_import_not_committed(rows: &mut [BulkImportRowResponse]) {
    for row in rows {
        if row.outcome == "would_create" {
            row.outcome = "not_committed".to_string();
        }
    }
}

fn bulk_import_summary(rows: &[BulkImportRowResponse]) -> BulkImportSummary {
    let mut summary = BulkImportSummary {
        total: rows.len(),
        created: 0,
        would_create: 0,
        invalid: 0,
        not_committed: 0,
    };
    for row in rows {
        match row.outcome.as_str() {
            "created" => summary.created += 1,
            "would_create" => summary.would_create += 1,
            "invalid" => summary.invalid += 1,
            "not_committed" => summary.not_committed += 1,
            _ => {}
        }
    }
    summary
}

fn bulk_import_response(
    dry_run: bool,
    committed: bool,
    batch_error: Option<String>,
    rows: Vec<BulkImportRowResponse>,
) -> BulkImportResponse {
    BulkImportResponse {
        dry_run,
        atomic: true,
        committed,
        batch_error,
        summary: bulk_import_summary(&rows),
        rows,
    }
}

async fn record_bulk_import_audit(
    state: &AppState,
    actor_user_id: &str,
    dry_run: bool,
    committed: bool,
    rows: &[BulkImportRowResponse],
    batch_error: Option<&str>,
) -> AppResult<()> {
    let summary = bulk_import_summary(rows);
    let outcome = if committed || (dry_run && batch_error.is_none()) {
        audit::AuditOutcome::Success
    } else {
        audit::AuditOutcome::Failure
    };
    let action = if dry_run && batch_error.is_none() {
        "user.bulk_import.dry_run"
    } else if committed {
        "user.bulk_import"
    } else {
        "user.bulk_import.rejected"
    };
    state
        .db
        .record_audit_event(audit::AuditEvent {
            actor_user_id: Some(actor_user_id.to_string()),
            actor_client_id: None,
            action: action.to_string(),
            target_kind: "user_bulk_import".to_string(),
            target_id: None,
            outcome,
            ip_address: None,
            user_agent: None,
            details: serde_json::json!({
                "dry_run": dry_run,
                "committed": committed,
                "total": summary.total,
                "created": summary.created,
                "would_create": summary.would_create,
                "invalid": summary.invalid,
                "not_committed": summary.not_committed,
                "error": batch_error,
            }),
        })
        .await
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
        .update_user(UserUpdate {
            id: &id,
            email: payload.email,
            username: payload.username,
            display_name: payload.display_name,
            phone: payload.phone,
            is_admin: payload.is_admin,
            is_active: payload.is_active,
        })
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
    let (_, organization) = current_organization_client_manager(&state, &jar, false).await?;
    let mut clients = Vec::new();
    for client in state
        .db
        .list_clients_for_organization(&organization.id)
        .await?
    {
        clients.push(public_client_with_claim_mappers(&state, client).await?);
    }
    Ok(Json(clients))
}

/// OIDC connections are enterprise-owned. A global client permission remains
/// a platform escape hatch, while an owner/admin of the selected enterprise
/// can manage its own connections without receiving visibility into others.
async fn current_organization_client_manager(
    state: &AppState,
    jar: &CookieJar,
    manage: bool,
) -> AppResult<(auth::CurrentUser, UserOrganizationRecord)> {
    let (current, organization) = current_organization_context(state, jar).await?;
    let global_permission = if manage {
        Permission::ClientsManage
    } else {
        Permission::ClientsRead
    };
    if state
        .db
        .has_permission(&current.user, global_permission)
        .await?
        || (!manage
            && state
                .db
                .has_permission(&current.user, Permission::ClientsManage)
                .await?)
    {
        return Ok((current, organization));
    }
    require_organization_manager_for(state, &current, &organization.id).await?;
    Ok((current, organization))
}

fn client_organization_from_context(
    submitted_organization_id: Option<String>,
    organization: &UserOrganizationRecord,
) -> AppResult<Option<String>> {
    if let Some(submitted) = submitted_organization_id {
        let submitted = submitted.trim();
        if !submitted.is_empty() && submitted != organization.id {
            return Err(AppError::Forbidden);
        }
    }
    Ok(Some(organization.id.clone()))
}

#[derive(Debug, Deserialize)]
struct ClientInput {
    client_id: String,
    client_name: String,
    #[serde(default)]
    logo_uri: String,
    #[serde(default)]
    organization_id: Option<String>,
    client_secret: Option<String>,
    redirect_uris: Vec<String>,
    post_logout_redirect_uris: Vec<String>,
    scopes: Vec<String>,
    #[serde(default)]
    audience: Option<String>,
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
    let (current, organization) = current_organization_client_manager(&state, &jar, true).await?;
    validate_client_input(&payload)?;
    let organization_id =
        client_organization_from_context(payload.organization_id.clone(), &organization)?;
    let claim_mappers = client_input_to_claim_mappers(&payload)?;
    let client = state
        .db
        .insert_client(client_input_to_new(
            payload,
            None,
            organization_id.clone(),
            None,
        )?)
        .await?;
    let application = state.db.harden_new_client_application(&client.id).await?;
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
                "application_id": application.id,
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
    let (current, organization) = current_organization_client_manager(&state, &jar, true).await?;
    validate_client_input(&payload)?;
    let existing = state
        .db
        .find_client_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    if existing.organization_id.as_deref() != Some(organization.id.as_str()) {
        return Err(AppError::NotFound);
    }
    let organization_id =
        client_organization_from_context(payload.organization_id.clone(), &organization)?;
    let claim_mappers = client_input_to_claim_mappers(&payload)?;
    let client = state
        .db
        .update_client(
            &id,
            client_input_to_new(
                payload,
                existing.client_secret_hash.clone(),
                organization_id.clone(),
                Some(existing.audience.clone()),
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

async fn delete_client(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let (current, organization) = current_organization_client_manager(&state, &jar, true).await?;
    let client = state
        .db
        .find_client_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    if client.organization_id.as_deref() != Some(organization.id.as_str()) {
        return Err(AppError::NotFound);
    }
    state.db.delete_client(&id).await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "client.delete",
            "client",
            Some(id),
            serde_json::json!({
                "client_id": client.client_id,
                "organization_id": client.organization_id
            }),
        ))
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

#[derive(Debug, Deserialize)]
struct ApplicationInput {
    slug: String,
    name: String,
    #[serde(default)]
    description: Option<String>,
    account_selection_mode: String,
    #[serde(default)]
    unique_identity_factors: Vec<String>,
    is_active: bool,
}

#[derive(Debug, Deserialize)]
struct ApplicationOidcClientsInput {
    client_ids: Vec<String>,
}

const APPLICATION_MODULE_KEYS: &[&str] = &[
    "protocols",
    "login_adapters",
    "directory_sync",
    "authorization",
];

#[derive(Debug, Serialize)]
struct ApplicationModuleResponse {
    module_key: String,
    config: serde_json::Value,
    is_enabled: bool,
    created_at: i64,
    updated_at: i64,
}

#[derive(Debug, Serialize)]
struct ApplicationAuthorizationProfileResponse {
    id: String,
    profile_key: String,
    connection_kind: String,
    connection_id: Option<String>,
    source_mode: String,
    manifest_url: String,
    signer_client_id: Option<String>,
    remote_version: Option<String>,
    remote_digest: Option<String>,
    sync_status: String,
    last_synced_at: Option<i64>,
    last_error: Option<String>,
    permission_count: usize,
    role_count: usize,
    created_at: i64,
    updated_at: i64,
}

#[derive(Debug, Deserialize)]
struct ApplicationAuthorizationProfileInput {
    #[serde(default)]
    manifest_url: Option<String>,
    #[serde(default)]
    signer_client_id: Option<String>,
    #[serde(default = "default_true")]
    signed_manifest_enabled: bool,
}

#[derive(Debug, Deserialize)]
struct ApplicationModuleInput {
    #[serde(default)]
    config: serde_json::Value,
    #[serde(default = "default_true")]
    is_enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
struct ApplicationJwtClientResponse {
    client_id: String,
    client_type: String,
    is_active: bool,
    secret_count: usize,
    active_secret_count: usize,
    latest_secret_created_at: Option<i64>,
    latest_secret_expires_at: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct ApplicationJwtClientInput {
    client_id: String,
    #[serde(default = "default_application_jwt_client_type")]
    client_type: String,
    #[serde(default = "default_true")]
    is_active: bool,
}

#[derive(Debug, Deserialize)]
struct ApplicationJwtSecretRotationInput {
    #[serde(default = "default_jwt_secret_grace_seconds")]
    grace_seconds: i64,
}

#[derive(Debug, Serialize)]
struct ApplicationJwtSecretRotationResponse {
    client_id: String,
    secret: String,
    created_at: i64,
    grace_seconds: i64,
}

#[derive(Debug, Clone, Serialize)]
struct ApplicationScimTokenResponse {
    id: String,
    application_id: String,
    token_prefix: String,
    scopes: Vec<String>,
    expires_at: Option<i64>,
    revoked_at: Option<i64>,
    last_used_at: Option<i64>,
    created_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ApplicationScimTokenInput {
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    expires_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
struct ApplicationRoleResponse {
    id: String,
    application_id: String,
    name: String,
    description: Option<String>,
    permissions: Vec<String>,
    is_default: bool,
    is_active: bool,
    created_at: i64,
    updated_at: i64,
}

#[derive(Debug, Clone, Serialize)]
struct ApplicationProfileRoleResponse {
    id: String,
    profile_id: String,
    role_key: String,
    name: String,
    description: Option<String>,
    permissions: Vec<String>,
    source: String,
    is_default: bool,
    is_active: bool,
    created_at: i64,
    updated_at: i64,
}

#[derive(Debug, Deserialize)]
struct ApplicationProfileRoleInput {
    role_key: String,
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    permissions: Vec<String>,
    #[serde(default = "default_true")]
    is_active: bool,
    #[serde(default)]
    is_default: bool,
}

#[derive(Debug, Deserialize)]
struct ApplicationRoleInput {
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    permissions: Vec<String>,
    #[serde(default)]
    is_default: bool,
    #[serde(default = "default_true")]
    is_active: bool,
}

#[derive(Debug, Deserialize)]
struct ApplicationRoleIdsInput {
    role_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ApplicationPermissionOverrideResponse {
    permission: String,
    effect: String,
}

#[derive(Debug, Deserialize)]
struct ApplicationPermissionOverridesInput {
    overrides: Vec<ApplicationPermissionOverrideInput>,
}

#[derive(Debug, Deserialize)]
struct ApplicationPermissionOverrideInput {
    permission: String,
    effect: String,
}

#[derive(Debug, Clone, Serialize)]
struct ApplicationPermissionDefinitionResponse {
    key: String,
    label: String,
    description: Option<String>,
    source: String,
    is_active: bool,
}

#[derive(Debug, Serialize)]
struct ApplicationAuthorizationGroupResponse {
    id: String,
    name: String,
    description: Option<String>,
    created_at: i64,
    updated_at: i64,
}

#[derive(Debug, Serialize)]
struct ApplicationAuthorizationSubjectsResponse {
    users: Vec<OrganizationMemberResponse>,
    groups: Vec<ApplicationAuthorizationGroupResponse>,
    organization_roles: Vec<String>,
}

fn application_profile_role_response(
    role: ApplicationProfileRoleRecord,
) -> AppResult<ApplicationProfileRoleResponse> {
    let permissions = role.permission_keys()?;
    Ok(ApplicationProfileRoleResponse {
        id: role.id,
        profile_id: role.profile_id,
        role_key: role.role_key,
        name: role.name,
        description: role.description,
        permissions,
        source: role.source,
        is_default: role.is_default == 1,
        is_active: role.is_active == 1,
        created_at: role.created_at,
        updated_at: role.updated_at,
    })
}

fn application_permission_definition_response(
    definition: ApplicationPermissionDefinitionRecord,
) -> ApplicationPermissionDefinitionResponse {
    ApplicationPermissionDefinitionResponse {
        key: definition.permission_key,
        label: definition.label,
        description: definition.description,
        source: definition.source,
        is_active: definition.is_active == 1,
    }
}

fn application_role_response(role: ApplicationRoleRecord) -> AppResult<ApplicationRoleResponse> {
    let permissions = role.permission_keys()?;
    Ok(ApplicationRoleResponse {
        id: role.id,
        application_id: role.application_id,
        name: role.name,
        description: role.description,
        permissions,
        is_default: role.is_default == 1,
        is_active: role.is_active == 1,
        created_at: role.created_at,
        updated_at: role.updated_at,
    })
}

fn application_module_response(
    module: ApplicationModuleRecord,
) -> AppResult<ApplicationModuleResponse> {
    let config = serde_json::from_str(&module.config_json).map_err(|err| {
        AppError::Internal(format!("application module config is invalid: {err}"))
    })?;
    Ok(ApplicationModuleResponse {
        module_key: module.module_key,
        config,
        is_enabled: module.is_enabled == 1,
        created_at: module.created_at,
        updated_at: module.updated_at,
    })
}

async fn application_jwt_client_response(
    state: &AppState,
    client: ApplicationJwtClientRecord,
) -> AppResult<ApplicationJwtClientResponse> {
    let secrets = state
        .db
        .list_application_jwt_secrets(&client.application_id, &client.client_id)
        .await?;
    let now = util::now_ts();
    let active_secret_count = secrets
        .iter()
        .filter(|secret| {
            secret.revoked_at.is_none()
                && secret.expires_at.is_none_or(|expires_at| expires_at >= now)
        })
        .count();
    let latest_secret = secrets.first();
    Ok(ApplicationJwtClientResponse {
        client_id: client.client_id,
        client_type: client.client_type,
        is_active: client.is_active == 1,
        secret_count: secrets.len(),
        active_secret_count,
        latest_secret_created_at: latest_secret.map(|secret| secret.created_at),
        latest_secret_expires_at: latest_secret.and_then(|secret| secret.expires_at),
    })
}

fn normalize_application_module_key(value: &str) -> AppResult<String> {
    let key = value.trim();
    if APPLICATION_MODULE_KEYS.contains(&key) {
        return Ok(key.to_string());
    }
    Err(AppError::BadRequest(format!(
        "unsupported application module: {key}"
    )))
}

#[derive(Debug, Serialize)]
struct ApplicationResponse {
    id: String,
    organization_id: String,
    slug: String,
    name: String,
    description: Option<String>,
    account_selection_mode: String,
    unique_identity_factors: Vec<String>,
    is_active: bool,
    oidc_clients: Vec<PublicClient>,
    modules: Vec<ApplicationModuleResponse>,
    authorization_profiles: Vec<ApplicationAuthorizationProfileResponse>,
    created_at: i64,
    updated_at: i64,
}

fn default_organization_role() -> String {
    "member".to_string()
}

fn default_application_jwt_client_type() -> String {
    "public".to_string()
}

fn default_jwt_secret_grace_seconds() -> i64 {
    300
}

fn application_input_to_new(
    organization_id: String,
    input: ApplicationInput,
    _allow_legacy: bool,
) -> AppResult<NewApplication> {
    Ok(NewApplication {
        organization_id,
        slug: applications::normalize_application_slug(&input.slug)?,
        name: applications::normalize_application_name(&input.name)?,
        description: normalize_optional_text(input.description),
        // Applications are website containers. Login eligibility is the
        // active Signet account, never an application member roster.
        access_mode: applications::ACCESS_ALL_SIGNET_USERS.to_string(),
        registration_mode: applications::REGISTRATION_DISABLED.to_string(),
        account_selection_mode: applications::normalize_account_selection_mode(
            &input.account_selection_mode,
        )?,
        unique_identity_factors: applications::normalize_unique_identity_factors(
            input.unique_identity_factors,
        )?,
        is_active: input.is_active,
    })
}

async fn ensure_application_authorization_profiles(
    state: &AppState,
    application: &ApplicationRecord,
) -> AppResult<Vec<ApplicationAuthorizationProfileRecord>> {
    let website_url = applications::application_website_url(state, &application.id)
        .await?
        .unwrap_or_default();
    let manifest_url = if website_url.trim().is_empty() {
        String::new()
    } else {
        authorization_manifest::default_manifest_url(&website_url)?
    };
    let mut profiles = Vec::new();
    for client_id in state.db.list_application_oidc_client_ids(&application.id).await? {
        let client = state
            .db
            .find_client_by_id(&client_id)
            .await?
            .ok_or(AppError::NotFound)?;
        let existing = state
            .db
            .find_application_authorization_profile(&application.id, &client.client_id)
            .await?;
        let profile = if let Some(existing) = existing {
            if existing.manifest_url.is_empty() && !manifest_url.is_empty() {
                state
                    .db
                    .upsert_application_authorization_profile(
                        NewApplicationAuthorizationProfile {
                            id: existing.id.clone(),
                            application_id: application.id.clone(),
                            profile_key: existing.profile_key.clone(),
                            connection_kind: existing.connection_kind.clone(),
                            connection_id: existing.connection_id.clone(),
                            source_mode: existing.source_mode.clone(),
                            manifest_url: manifest_url.clone(),
                            signer_client_id: existing.signer_client_id.clone(),
                            remote_version: existing.remote_version.clone(),
                            remote_digest: existing.remote_digest.clone(),
                            sync_status: existing.sync_status.clone(),
                            last_synced_at: existing.last_synced_at,
                            last_error: existing.last_error.clone(),
                        },
                    )
                    .await?
            } else {
                existing
            }
        } else {
            let manifest_capable = !manifest_url.is_empty()
                && (!client.jwks.trim().is_empty() || !client.jwks_uri.trim().is_empty());
            state
                .db
                .upsert_application_authorization_profile(
                    NewApplicationAuthorizationProfile {
                        id: uuid::Uuid::new_v4().to_string(),
                        application_id: application.id.clone(),
                        profile_key: client.client_id.clone(),
                        connection_kind: "oidc".to_string(),
                        connection_id: Some(client.id.clone()),
                        source_mode: if manifest_capable {
                            authorization_manifest::SOURCE_MODE_SIGNED.to_string()
                        } else {
                            authorization_manifest::SOURCE_MODE_MANUAL.to_string()
                        },
                        manifest_url: manifest_url.clone(),
                        signer_client_id: (!client.jwks.trim().is_empty()
                            || !client.jwks_uri.trim().is_empty())
                            .then(|| client.client_id.clone()),
                        remote_version: None,
                        remote_digest: None,
                        sync_status: authorization_manifest::SYNC_STATUS_MANUAL.to_string(),
                        last_synced_at: None,
                        last_error: None,
                    },
                )
                .await?
        };
        profiles.push(profile);
    }
    Ok(profiles)
}

async fn application_response(
    state: &AppState,
    application: ApplicationRecord,
) -> AppResult<ApplicationResponse> {
    let mut oidc_clients = Vec::new();
    for client_db_id in state
        .db
        .list_application_oidc_client_ids(&application.id)
        .await?
    {
        if let Some(client) = state.db.find_client_by_id(&client_db_id).await? {
            oidc_clients.push(public_client_with_claim_mappers(state, client).await?);
        }
    }
    let unique_identity_factors = application.unique_identity_factors()?;
    let modules = state
        .db
        .list_application_modules(&application.id)
        .await?
        .into_iter()
        .map(application_module_response)
        .collect::<AppResult<Vec<_>>>()?;
    let profiles = ensure_application_authorization_profiles(&state, &application).await?;
    let mut authorization_profiles = Vec::with_capacity(profiles.len());
    for profile in profiles {
        let definitions = state
            .db
            .list_application_permission_definitions(&profile.id)
            .await?;
        let roles = state.db.list_application_profile_roles(&profile.id).await?;
        authorization_profiles.push(ApplicationAuthorizationProfileResponse {
                id: profile.id.clone(),
                profile_key: profile.profile_key.clone(),
                connection_kind: profile.connection_kind.clone(),
                connection_id: profile.connection_id.clone(),
                source_mode: profile.source_mode.clone(),
                manifest_url: profile.manifest_url.clone(),
                signer_client_id: profile.signer_client_id.clone(),
                remote_version: profile.remote_version.clone(),
                remote_digest: profile.remote_digest.clone(),
                sync_status: profile.sync_status.clone(),
                last_synced_at: profile.last_synced_at,
                last_error: profile.last_error.clone(),
                permission_count: definitions.iter().filter(|item| item.is_active == 1).count(),
                role_count: roles.iter().filter(|item| item.is_active == 1).count(),
                created_at: profile.created_at,
                updated_at: profile.updated_at,
        });
    }
    Ok(ApplicationResponse {
        id: application.id,
        organization_id: application.organization_id,
        slug: application.slug,
        name: application.name,
        description: application.description,
        account_selection_mode: application.account_selection_mode,
        unique_identity_factors,
        is_active: application.is_active == 1,
        oidc_clients,
        modules,
        authorization_profiles,
        created_at: application.created_at,
        updated_at: application.updated_at,
    })
}

async fn current_organization_context(
    state: &AppState,
    jar: &CookieJar,
) -> AppResult<(auth::CurrentUser, UserOrganizationRecord)> {
    let current = auth::require_current_user(state, jar).await?;
    if !current.can_mutate_account() {
        return Err(AppError::Forbidden);
    }
    let organization = state
        .db
        .active_user_organization(&current.user.id)
        .await?
        .ok_or_else(|| {
            AppError::BadRequest(
                "join or create an organization before using the management console".to_string(),
            )
        })?;
    Ok((current, organization))
}

async fn require_organization_manager_for(
    state: &AppState,
    current: &auth::CurrentUser,
    organization_id: &str,
) -> AppResult<()> {
    auth::ensure_current_account_mutable(current)?;
    let organization = state
        .db
        .find_organization_by_id(organization_id)
        .await?
        .ok_or(AppError::NotFound)?;
    // Signet is the platform-control tenant. Its membership roster is useful
    // for console context, but it must never turn an ordinary tenant role
    // into platform administration.
    if organization.kind == organizations::ORGANIZATION_KIND_SYSTEM {
        state
            .db
            .require_permission(&current.user, Permission::OrganizationsManage)
            .await?;
        return Ok(());
    }
    if state
        .db
        .has_permission(&current.user, Permission::OrganizationsManage)
        .await?
    {
        return Ok(());
    }
    let membership = state
        .db
        .list_user_organizations(&current.user.id)
        .await?
        .into_iter()
        .find(|organization| organization.id == organization_id && organization.is_active == 1);
    match membership
        .as_ref()
        .map(|membership| membership.role.as_str())
    {
        Some(organizations::ROLE_OWNER | organizations::ROLE_ADMIN) => Ok(()),
        _ => Err(AppError::Forbidden),
    }
}

/// External OIDC sources follow the same enterprise boundary as applications
/// and OIDC clients. Platform provider managers retain cross-tenant access;
/// an enterprise owner/admin can operate only sources owned by the selected
/// enterprise.
async fn current_organization_provider_manager(
    state: &AppState,
    jar: &CookieJar,
) -> AppResult<(auth::CurrentUser, UserOrganizationRecord, bool)> {
    let (current, organization) = current_organization_context(state, jar).await?;
    let platform_manager = state
        .db
        .has_permission(&current.user, Permission::ProvidersManage)
        .await?;
    if !platform_manager {
        require_organization_manager_for(state, &current, &organization.id).await?;
    }
    Ok((current, organization, platform_manager))
}

async fn list_applications(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<Vec<ApplicationResponse>>> {
    let (current, organization) = current_organization_context(&state, &jar).await?;
    require_organization_manager_for(&state, &current, &organization.id).await?;
    let mut result = Vec::new();
    for application in state.db.list_applications(Some(&organization.id)).await? {
        result.push(application_response(&state, application).await?);
    }
    Ok(Json(result))
}

async fn list_application_modules(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<Vec<ApplicationModuleResponse>>> {
    let current = auth::require_current_user(&state, &jar).await?;
    let application = state
        .db
        .find_application_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    require_organization_manager_for(&state, &current, &application.organization_id).await?;
    let modules = state
        .db
        .list_application_modules(&id)
        .await?
        .into_iter()
        .map(application_module_response)
        .collect::<AppResult<Vec<_>>>()?;
    Ok(Json(modules))
}

async fn list_application_directory_sync_runs(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<Vec<crate::db::DirectorySyncRunRecord>>> {
    let (_current, application) = managed_application(&state, &jar, &id).await?;
    Ok(Json(
        directory_sync::list_application_ldap_sync_runs(&state, &application.id).await?,
    ))
}

async fn run_application_directory_sync(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, provider_id)): Path<(String, String)>,
) -> AppResult<Json<crate::db::DirectorySyncRunRecord>> {
    let (current, application) = managed_application(&state, &jar, &id).await?;
    let result =
        directory_sync::run_application_ldap_sync(&state, &application.id, &provider_id).await;
    match result {
        Ok(run) => {
            state
                .db
                .record_audit_event(audit::management_event(
                    current.user.id,
                    "application.directory_sync.run",
                    "application",
                    Some(application.id),
                    serde_json::json!({
                        "organization_id": application.organization_id,
                        "provider_id": provider_id,
                        "status": run.status,
                        "run_id": run.id,
                    }),
                ))
                .await?;
            Ok(Json(run))
        }
        Err(error) => {
            // The sync coordinator records a failed run when it has started
            // one. Keep the management audit deliberately metadata-only so
            // LDAP bind credentials and provider response details cannot leak.
            let _ = state
                .db
                .record_audit_event(audit::management_event(
                    current.user.id,
                    "application.directory_sync.run",
                    "application",
                    Some(application.id),
                    serde_json::json!({
                        "organization_id": application.organization_id,
                        "provider_id": provider_id,
                        "status": "failed",
                    }),
                ))
                .await;
            Err(error)
        }
    }
}

async fn update_application_module(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, module_key)): Path<(String, String)>,
    Json(payload): Json<ApplicationModuleInput>,
) -> AppResult<Json<ApplicationModuleResponse>> {
    let current = auth::require_current_user(&state, &jar).await?;
    let application = state
        .db
        .find_application_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    require_organization_manager_for(&state, &current, &application.organization_id).await?;
    let module_key = normalize_application_module_key(&module_key)?;
    let config = applications::normalize_module_config(&module_key, payload.config)?;
    applications::validate_module_bindings(
        &state,
        &application,
        &module_key,
        config.as_object().ok_or_else(|| {
            AppError::BadRequest("application module config must be an object".to_string())
        })?,
    )
    .await?;
    let config_json = serde_json::to_string(&config).map_err(|err| {
        AppError::BadRequest(format!("application module config is invalid: {err}"))
    })?;
    if config_json.len() > 512 * 1024 {
        return Err(AppError::BadRequest(
            "application module config is too large".to_string(),
        ));
    }
    let module = state
        .db
        .upsert_application_module(&id, &module_key, &config_json, payload.is_enabled)
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.module.update",
            "application",
            Some(id),
            serde_json::json!({
                "organization_id": application.organization_id,
                "module": module_key,
                "is_enabled": payload.is_enabled,
            }),
        ))
        .await?;
    Ok(Json(application_module_response(module)?))
}

async fn get_application_jwt_client(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<Option<ApplicationJwtClientResponse>>> {
    let current = auth::require_current_user(&state, &jar).await?;
    let application = state
        .db
        .find_application_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    require_organization_manager_for(&state, &current, &application.organization_id).await?;
    let Some(module) = applications::enabled_protocol_config(&state, &id, "jwt").await? else {
        return Ok(Json(None));
    };
    let client_id = module
        .get("client_id")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(application.slug.as_str());
    let client = state.db.find_application_jwt_client(&id, client_id).await?;
    match client {
        Some(client) => Ok(Json(Some(
            application_jwt_client_response(&state, client).await?,
        ))),
        None => Ok(Json(None)),
    }
}

async fn update_application_jwt_client(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<ApplicationJwtClientInput>,
) -> AppResult<Json<ApplicationJwtClientResponse>> {
    let current = auth::require_current_user(&state, &jar).await?;
    let application = state
        .db
        .find_application_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    require_organization_manager_for(&state, &current, &application.organization_id).await?;
    let client_type = payload.client_type.trim().to_ascii_lowercase();
    if !matches!(client_type.as_str(), "public" | "confidential") {
        return Err(AppError::BadRequest(
            "application JWT client_type must be public or confidential".to_string(),
        ));
    }
    let client = state
        .db
        .upsert_application_jwt_client(
            &id,
            NewApplicationJwtClient {
                client_id: payload.client_id,
                client_type,
                is_active: payload.is_active,
            },
        )
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.jwt_client.update",
            "application",
            Some(id),
            serde_json::json!({
                "organization_id": application.organization_id,
                "client_id": client.client_id,
                "client_type": client.client_type,
                "is_active": client.is_active == 1,
            }),
        ))
        .await?;
    Ok(Json(application_jwt_client_response(&state, client).await?))
}

async fn rotate_application_jwt_secret(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<ApplicationJwtSecretRotationInput>,
) -> AppResult<Json<ApplicationJwtSecretRotationResponse>> {
    let current = auth::require_current_user(&state, &jar).await?;
    let application = state
        .db
        .find_application_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    require_organization_manager_for(&state, &current, &application.organization_id).await?;
    if !(0..=86_400).contains(&payload.grace_seconds) {
        return Err(AppError::BadRequest(
            "JWT secret grace_seconds must be between 0 and 86400".to_string(),
        ));
    }
    let module = applications::enabled_protocol_config(&state, &id, "jwt")
        .await?
        .ok_or_else(|| AppError::BadRequest("JWT protocol is not enabled".to_string()))?;
    let client_id = module
        .get("client_id")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(application.slug.as_str())
        .to_string();
    let client = state
        .db
        .find_application_jwt_client(&id, &client_id)
        .await?
        .ok_or_else(|| {
            AppError::BadRequest("configure the JWT client before rotating its secret".to_string())
        })?;
    if client.client_type != "confidential" || client.is_active != 1 {
        return Err(AppError::BadRequest(
            "JWT secret rotation requires an active confidential client".to_string(),
        ));
    }
    let secret = format!("jwt_{}", util::random_token(32));
    let secret_hash = client_assertion::store_client_secret("client_secret_post", &secret)?
        .ok_or_else(|| AppError::Internal("failed to hash JWT client secret".to_string()))?;
    let record = state
        .db
        .rotate_application_jwt_secret(&id, &client_id, &secret_hash, payload.grace_seconds)
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.jwt_client.secret.rotate",
            "application",
            Some(id),
            serde_json::json!({
                "organization_id": application.organization_id,
                "client_id": client_id,
                "grace_seconds": payload.grace_seconds,
                "secret_id": record.id,
            }),
        ))
        .await?;
    Ok(Json(ApplicationJwtSecretRotationResponse {
        client_id,
        secret,
        created_at: record.created_at,
        grace_seconds: payload.grace_seconds,
    }))
}

async fn revoke_application_jwt_secrets(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let current = auth::require_current_user(&state, &jar).await?;
    let application = state
        .db
        .find_application_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    require_organization_manager_for(&state, &current, &application.organization_id).await?;
    let module = applications::enabled_protocol_config(&state, &id, "jwt")
        .await?
        .ok_or_else(|| AppError::BadRequest("JWT protocol is not enabled".to_string()))?;
    let client_id = module
        .get("client_id")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(application.slug.as_str())
        .to_string();
    state
        .db
        .revoke_application_jwt_secrets(&id, &client_id)
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.jwt_client.secret.revoke",
            "application",
            Some(id),
            serde_json::json!({
                "organization_id": application.organization_id,
                "client_id": client_id,
            }),
        ))
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

fn application_scim_token_response(
    token: ApplicationScimTokenRecord,
    raw_token: Option<String>,
) -> AppResult<ApplicationScimTokenResponse> {
    Ok(ApplicationScimTokenResponse {
        id: token.id,
        application_id: token.application_id,
        token_prefix: token.token_prefix,
        scopes: util::from_json(&token.scopes)?,
        expires_at: token.expires_at,
        revoked_at: token.revoked_at,
        last_used_at: token.last_used_at,
        created_at: token.created_at,
        token: raw_token,
    })
}

fn normalize_application_scim_token_scopes(values: Vec<String>) -> AppResult<Vec<String>> {
    let values = if values.is_empty() {
        vec!["scim.read".to_string(), "scim.write".to_string()]
    } else {
        values
    };
    let mut scopes = BTreeSet::new();
    for value in values {
        match value.trim() {
            "scim.read" | "scim.write" => {
                scopes.insert(value.trim().to_string());
            }
            other => {
                return Err(AppError::BadRequest(format!(
                    "unsupported application SCIM token scope: {other}"
                )));
            }
        }
    }
    Ok(scopes.into_iter().collect())
}

async fn list_application_scim_tokens(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<Vec<ApplicationScimTokenResponse>>> {
    let (current, application) = managed_application(&state, &jar, &id).await?;
    let tokens = state
        .db
        .list_application_scim_tokens(&application.id)
        .await?
        .into_iter()
        .map(|token| application_scim_token_response(token, None))
        .collect::<AppResult<Vec<_>>>()?;
    let _ = current;
    Ok(Json(tokens))
}

async fn create_application_scim_token(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<ApplicationScimTokenInput>,
) -> AppResult<Json<ApplicationScimTokenResponse>> {
    let (current, application) = managed_application(&state, &jar, &id).await?;
    let module = applications::enabled_module_config(&state, &id, "directory_sync")
        .await?
        .ok_or_else(|| {
            AppError::BadRequest("enable directory sync before creating a SCIM token".to_string())
        })?;
    if module
        .get("scim_enabled")
        .and_then(serde_json::Value::as_bool)
        != Some(true)
    {
        return Err(AppError::BadRequest(
            "enable application SCIM before creating a token".to_string(),
        ));
    }
    let scopes = normalize_application_scim_token_scopes(payload.scopes)?;
    if payload
        .expires_at
        .is_some_and(|expires_at| expires_at <= util::now_ts())
    {
        return Err(AppError::BadRequest(
            "application SCIM token expiry must be in the future".to_string(),
        ));
    }
    let raw_token = format!("scim_v1_{}", util::random_token(32));
    let record = state
        .db
        .insert_application_scim_token(NewApplicationScimToken {
            id: uuid::Uuid::new_v4().to_string(),
            application_id: application.id.clone(),
            token_prefix: raw_token.chars().take(16).collect(),
            token_hash: util::token_hash(&raw_token),
            scopes,
            expires_at: payload.expires_at,
        })
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.scim_token.create",
            "application",
            Some(application.id),
            serde_json::json!({ "token_id": record.id, "token_prefix": record.token_prefix }),
        ))
        .await?;
    Ok(Json(application_scim_token_response(
        record,
        Some(raw_token),
    )?))
}

async fn revoke_application_scim_token(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, token_id)): Path<(String, String)>,
) -> AppResult<Json<serde_json::Value>> {
    let (current, application) = managed_application(&state, &jar, &id).await?;
    state
        .db
        .revoke_application_scim_token(&application.id, &token_id)
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.scim_token.revoke",
            "application",
            Some(application.id),
            serde_json::json!({ "token_id": token_id }),
        ))
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn delete_application_module(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, module_key)): Path<(String, String)>,
) -> AppResult<Json<serde_json::Value>> {
    let current = auth::require_current_user(&state, &jar).await?;
    let application = state
        .db
        .find_application_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    require_organization_manager_for(&state, &current, &application.organization_id).await?;
    let module_key = normalize_application_module_key(&module_key)?;
    state.db.delete_application_module(&id, &module_key).await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.module.delete",
            "application",
            Some(id),
            serde_json::json!({
                "organization_id": application.organization_id,
                "module": module_key,
            }),
        ))
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn managed_application(
    state: &AppState,
    jar: &CookieJar,
    id: &str,
) -> AppResult<(auth::CurrentUser, ApplicationRecord)> {
    let current = auth::require_current_user(state, jar).await?;
    let application = state
        .db
        .find_application_by_id(id)
        .await?
        .ok_or(AppError::NotFound)?;
    require_organization_manager_for(state, &current, &application.organization_id).await?;
    Ok((current, application))
}

async fn list_application_roles(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<Vec<ApplicationRoleResponse>>> {
    let (_current, _application) = managed_application(&state, &jar, &id).await?;
    let roles = state
        .db
        .list_application_roles(&id)
        .await?
        .into_iter()
        .map(application_role_response)
        .collect::<AppResult<Vec<_>>>()?;
    Ok(Json(roles))
}

async fn application_permission_catalog(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<Vec<PermissionInfo>>> {
    // Application managers need the same stable standard-permission catalog
    // used by the role validator. Requiring the global security-manager
    // permission here would make an enterprise owner unable to configure the
    // website they own, while returning the catalog does not grant any
    // permission by itself.
    let (_current, _application) = managed_application(&state, &jar, &id).await?;
    Ok(Json(permission_catalog()))
}

async fn application_authorization_subjects(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<ApplicationAuthorizationSubjectsResponse>> {
    let (_current, application) = managed_application(&state, &jar, &id).await?;
    let organization_members = state
        .db
        .list_organization_members(&application.organization_id)
        .await?;
    let organization_user_ids = organization_members
        .iter()
        .filter(|member| member.is_active == 1 && member.archived_at.is_none())
        .map(|member| member.user_id.clone())
        .collect::<BTreeSet<_>>();
    let users = organization_members
        .into_iter()
        .filter(|member| member.is_active == 1 && member.archived_at.is_none())
        .map(|member| OrganizationMemberResponse {
            organization_id: member.organization_id,
            user_id: member.user_id,
            role: member.role,
            email: member.email,
            username: member.username,
            display_name: member.display_name,
            is_active: true,
            archived_at: None,
            created_at: member.membership_created_at,
            updated_at: member.membership_updated_at,
        })
        .collect();
    let mut groups = Vec::new();
    for group in state.db.list_groups().await? {
        let has_organization_member = state
            .db
            .list_group_members(&group.id)
            .await?
            .iter()
            .any(|member| organization_user_ids.contains(&member.id));
        if has_organization_member {
            groups.push(ApplicationAuthorizationGroupResponse {
                id: group.id,
                name: group.name,
                description: group.description,
                created_at: group.created_at,
                updated_at: group.updated_at,
            });
        }
    }
    Ok(Json(ApplicationAuthorizationSubjectsResponse {
        users,
        groups,
        organization_roles: vec![
            organizations::ROLE_OWNER.to_string(),
            organizations::ROLE_ADMIN.to_string(),
            organizations::ROLE_MEMBER.to_string(),
        ],
    }))
}

async fn create_application_role(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<ApplicationRoleInput>,
) -> AppResult<Json<ApplicationRoleResponse>> {
    let (current, application) = managed_application(&state, &jar, &id).await?;
    let role = state
        .db
        .upsert_application_role(
            &id,
            NewApplicationRole {
                name: payload.name,
                description: payload.description,
                permissions: payload.permissions,
                is_default: payload.is_default,
                is_active: payload.is_active,
            },
        )
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.role.create",
            "application_role",
            Some(role.id.clone()),
            serde_json::json!({
                "application_id": application.id,
                "organization_id": application.organization_id,
                "role": role.name,
            }),
        ))
        .await?;
    Ok(Json(application_role_response(role)?))
}

async fn update_application_role(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, role_id)): Path<(String, String)>,
    Json(payload): Json<ApplicationRoleInput>,
) -> AppResult<Json<ApplicationRoleResponse>> {
    let (current, application) = managed_application(&state, &jar, &id).await?;
    state
        .db
        .find_application_role_by_id(&id, &role_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let role = state
        .db
        .update_application_role(
            &id,
            &role_id,
            NewApplicationRole {
                name: payload.name,
                description: payload.description,
                permissions: payload.permissions,
                is_default: payload.is_default,
                is_active: payload.is_active,
            },
        )
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.role.update",
            "application_role",
            Some(role.id.clone()),
            serde_json::json!({
                "application_id": application.id,
                "organization_id": application.organization_id,
            }),
        ))
        .await?;
    Ok(Json(application_role_response(role)?))
}

async fn delete_application_role(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, role_id)): Path<(String, String)>,
) -> AppResult<Json<serde_json::Value>> {
    let (current, application) = managed_application(&state, &jar, &id).await?;
    state.db.delete_application_role(&id, &role_id).await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.role.delete",
            "application_role",
            Some(role_id),
            serde_json::json!({
                "application_id": application.id,
                "organization_id": application.organization_id,
            }),
        ))
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn managed_authorization_profile(
    state: &AppState,
    jar: &CookieJar,
    application_id: &str,
    profile_id: &str,
) -> AppResult<(
    auth::CurrentUser,
    ApplicationRecord,
    ApplicationAuthorizationProfileRecord,
)> {
    let current = auth::require_current_user(state, jar).await?;
    let application = state
        .db
        .find_application_by_id(application_id)
        .await?
        .ok_or(AppError::NotFound)?;
    require_organization_manager_for(state, &current, &application.organization_id).await?;
    let profile = state
        .db
        .find_application_authorization_profile_by_id(profile_id)
        .await?
        .ok_or(AppError::NotFound)?;
    if profile.application_id != application.id {
        return Err(AppError::NotFound);
    }
    Ok((current, application, profile))
}

async fn application_authorization_user(
    state: &AppState,
    application: &ApplicationRecord,
    user_id: &str,
) -> AppResult<crate::db::UserRecord> {
    let user = state
        .db
        .find_user_by_id(user_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let belongs_to_application = state
        .db
        .list_organization_members(&application.organization_id)
        .await?
        .into_iter()
        .any(|member| member.user_id == user.id && member.is_active == 1 && member.archived_at.is_none());
    if !belongs_to_application {
        return Err(AppError::NotFound);
    }
    Ok(user)
}

async fn application_authorization_group(
    state: &AppState,
    application: &ApplicationRecord,
    group_id: &str,
) -> AppResult<GroupRecord> {
    let group = state
        .db
        .find_group_by_id(group_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let organization_user_ids = state
        .db
        .list_organization_members(&application.organization_id)
        .await?
        .into_iter()
        .filter(|member| member.is_active == 1 && member.archived_at.is_none())
        .map(|member| member.user_id)
        .collect::<BTreeSet<_>>();
    let belongs_to_application = state
        .db
        .list_group_members(&group.id)
        .await?
        .into_iter()
        .any(|member| organization_user_ids.contains(&member.id));
    if !belongs_to_application {
        return Err(AppError::NotFound);
    }
    Ok(group)
}

async fn authorization_profile_response(
    state: &AppState,
    profile: ApplicationAuthorizationProfileRecord,
) -> AppResult<ApplicationAuthorizationProfileResponse> {
    let definitions = state
        .db
        .list_application_permission_definitions(&profile.id)
        .await?;
    let roles = state.db.list_application_profile_roles(&profile.id).await?;
    Ok(ApplicationAuthorizationProfileResponse {
        id: profile.id,
        profile_key: profile.profile_key,
        connection_kind: profile.connection_kind,
        connection_id: profile.connection_id,
        source_mode: profile.source_mode,
        manifest_url: profile.manifest_url,
        signer_client_id: profile.signer_client_id,
        remote_version: profile.remote_version,
        remote_digest: profile.remote_digest,
        sync_status: profile.sync_status,
        last_synced_at: profile.last_synced_at,
        last_error: profile.last_error,
        permission_count: definitions.iter().filter(|item| item.is_active == 1).count(),
        role_count: roles.iter().filter(|item| item.is_active == 1).count(),
        created_at: profile.created_at,
        updated_at: profile.updated_at,
    })
}

async fn list_application_authorization_profiles(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<Vec<ApplicationAuthorizationProfileResponse>>> {
    let (_current, application) = managed_application(&state, &jar, &id).await?;
    auto_refresh_application_authorization_profiles(&state, &application).await?;
    let profiles = ensure_application_authorization_profiles(&state, &application).await?;
    let mut response = Vec::with_capacity(profiles.len());
    for profile in profiles {
        response.push(authorization_profile_response(&state, profile).await?);
    }
    Ok(Json(response))
}

async fn get_application_authorization_profile(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, profile_id)): Path<(String, String)>,
) -> AppResult<Json<ApplicationAuthorizationProfileResponse>> {
    let (_current, _application, profile) =
        managed_authorization_profile(&state, &jar, &id, &profile_id).await?;
    Ok(Json(authorization_profile_response(&state, profile).await?))
}

async fn update_application_authorization_profile(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, profile_id)): Path<(String, String)>,
    Json(payload): Json<ApplicationAuthorizationProfileInput>,
) -> AppResult<Json<ApplicationAuthorizationProfileResponse>> {
    let (current, application, profile) =
        managed_authorization_profile(&state, &jar, &id, &profile_id).await?;
    let manifest_url = payload
        .manifest_url
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| profile.manifest_url.clone());
    let signer_client_id = payload
        .signer_client_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .or(profile.signer_client_id.clone());
    let source_mode = if payload.signed_manifest_enabled {
        if manifest_url.is_empty() || signer_client_id.is_none() {
            return Err(AppError::BadRequest(
                "signed authorization profiles require a manifest URL and signer client"
                    .to_string(),
            ));
        }
        authorization_manifest::SOURCE_MODE_SIGNED.to_string()
    } else {
        authorization_manifest::SOURCE_MODE_MANUAL.to_string()
    };
    if let Some(signer_client_id) = signer_client_id.as_deref() {
        let signer = state
            .db
            .find_client_by_client_id(signer_client_id)
            .await?
            .ok_or_else(|| AppError::BadRequest("manifest signer client does not exist".to_string()))?;
        if signer.organization_id.as_deref() != Some(application.organization_id.as_str())
            || !state
                .db
                .list_application_oidc_client_ids(&application.id)
                .await?
                .contains(&signer.id)
        {
            return Err(AppError::Forbidden);
        }
        if signer.jwks.trim().is_empty() && signer.jwks_uri.trim().is_empty() {
            return Err(AppError::BadRequest(
                "manifest signer client must have a public JWKS".to_string(),
            ));
        }
    }
    let updated = state
        .db
        .upsert_application_authorization_profile(NewApplicationAuthorizationProfile {
            id: profile.id.clone(),
            application_id: application.id.clone(),
            profile_key: profile.profile_key.clone(),
            connection_kind: profile.connection_kind.clone(),
            connection_id: profile.connection_id.clone(),
            source_mode,
            manifest_url,
            signer_client_id,
            remote_version: profile.remote_version.clone(),
            remote_digest: profile.remote_digest.clone(),
            sync_status: if payload.signed_manifest_enabled {
                profile.sync_status.clone()
            } else {
                authorization_manifest::SYNC_STATUS_MANUAL.to_string()
            },
            last_synced_at: profile.last_synced_at,
            last_error: None,
        })
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.authorization_profile.update",
            "application_authorization_profile",
            Some(updated.id.clone()),
            serde_json::json!({
                "application_id": application.id,
                "profile_key": updated.profile_key,
                "source_mode": updated.source_mode,
            }),
        ))
        .await?;
    Ok(Json(authorization_profile_response(&state, updated).await?))
}

async fn synchronize_authorization_profile(
    state: &AppState,
    application: &ApplicationRecord,
    profile: &ApplicationAuthorizationProfileRecord,
) -> AppResult<ApplicationAuthorizationProfileRecord> {
    if profile.source_mode != authorization_manifest::SOURCE_MODE_SIGNED {
        return Err(AppError::BadRequest(
            "enable signed manifest mode before refreshing this profile".to_string(),
        ));
    }
    let website_url = applications::application_website_url(state, &application.id)
        .await?
        .ok_or_else(|| AppError::BadRequest("website URL is required for manifest discovery".to_string()))?;
    let signer_client_id = profile
        .signer_client_id
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("manifest signer client is not configured".to_string()))?;
    let signer = state
        .db
        .find_client_by_client_id(signer_client_id)
        .await?
        .ok_or_else(|| AppError::BadRequest("manifest signer client does not exist".to_string()))?;
    let result = authorization_manifest::discover_profile(
        state,
        &signer,
        &profile.manifest_url,
        &website_url,
        &application.id,
        &profile.profile_key,
        &profile.id,
    )
    .await;
    let verified = match result {
        Ok(value) => value,
        Err(error) => {
            state
                .db
                .upsert_application_authorization_profile(NewApplicationAuthorizationProfile {
                    id: profile.id.clone(),
                    application_id: profile.application_id.clone(),
                    profile_key: profile.profile_key.clone(),
                    connection_kind: profile.connection_kind.clone(),
                    connection_id: profile.connection_id.clone(),
                    source_mode: profile.source_mode.clone(),
                    manifest_url: profile.manifest_url.clone(),
                    signer_client_id: profile.signer_client_id.clone(),
                    remote_version: profile.remote_version.clone(),
                    remote_digest: profile.remote_digest.clone(),
                    sync_status: authorization_manifest::SYNC_STATUS_ERROR.to_string(),
                    last_synced_at: profile.last_synced_at,
                    last_error: Some(error.to_string().chars().take(512).collect()),
                })
                .await?;
            return Err(error);
        }
    };
    let Some(verified) = verified else {
        let no_profile = state
            .db
            .upsert_application_authorization_profile(NewApplicationAuthorizationProfile {
                id: profile.id.clone(),
                application_id: profile.application_id.clone(),
                profile_key: profile.profile_key.clone(),
                connection_kind: profile.connection_kind.clone(),
                connection_id: profile.connection_id.clone(),
                source_mode: authorization_manifest::SOURCE_MODE_MANUAL.to_string(),
                manifest_url: profile.manifest_url.clone(),
                signer_client_id: profile.signer_client_id.clone(),
                remote_version: profile.remote_version.clone(),
                remote_digest: profile.remote_digest.clone(),
                sync_status: authorization_manifest::SYNC_STATUS_NO_PROFILE.to_string(),
                last_synced_at: profile.last_synced_at,
                last_error: None,
            })
            .await?;
        return Ok(no_profile);
    };

    state
        .db
        .replace_application_permission_definitions(&profile.id, verified.permissions)
        .await?;
    let existing_roles = state.db.list_application_profile_roles(&profile.id).await?;
    let incoming_keys = verified
        .roles
        .iter()
        .map(|role| role.role_key.as_str())
        .collect::<BTreeSet<_>>();
    for role in existing_roles
        .into_iter()
        .filter(|role| role.source == authorization_manifest::SOURCE_MANIFEST)
        .filter(|role| !incoming_keys.contains(role.role_key.as_str()))
    {
        let permissions = role.permission_keys()?;
        state
            .db
            .upsert_application_profile_role(NewApplicationProfileRole {
                id: Some(role.id),
                profile_id: profile.id.clone(),
                role_key: role.role_key,
                name: role.name,
                description: role.description,
                permissions,
                source: authorization_manifest::SOURCE_MANIFEST.to_string(),
                is_default: false,
                is_active: false,
            })
            .await?;
    }
    for role in verified.roles {
        state.db.upsert_application_profile_role(role).await?;
    }
    let synced = state
        .db
        .upsert_application_authorization_profile(NewApplicationAuthorizationProfile {
            id: profile.id.clone(),
            application_id: profile.application_id.clone(),
            profile_key: profile.profile_key.clone(),
            connection_kind: profile.connection_kind.clone(),
            connection_id: profile.connection_id.clone(),
            source_mode: authorization_manifest::SOURCE_MODE_SIGNED.to_string(),
            manifest_url: profile.manifest_url.clone(),
            signer_client_id: profile.signer_client_id.clone(),
            remote_version: Some(verified.version),
            remote_digest: Some(verified.digest),
            sync_status: authorization_manifest::SYNC_STATUS_SYNCED.to_string(),
            last_synced_at: Some(util::now_ts()),
            last_error: None,
        })
        .await?;
    Ok(synced)
}

async fn auto_refresh_application_authorization_profiles(
    state: &AppState,
    application: &ApplicationRecord,
) -> AppResult<()> {
    let profiles = ensure_application_authorization_profiles(state, application).await?;
    for profile in profiles.into_iter().filter(|profile| {
        profile.source_mode == authorization_manifest::SOURCE_MODE_SIGNED
            && profile.remote_digest.is_none()
            && profile.sync_status == authorization_manifest::SYNC_STATUS_MANUAL
    }) {
        if let Err(error) = synchronize_authorization_profile(state, application, &profile).await {
            tracing::warn!(
                application_id = %application.id,
                profile_id = %profile.id,
                error = %error,
                "initial authorization manifest refresh failed"
            );
        }
    }
    Ok(())
}

async fn refresh_application_authorization_profile(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, profile_id)): Path<(String, String)>,
) -> AppResult<Json<ApplicationAuthorizationProfileResponse>> {
    let (current, application, profile) =
        managed_authorization_profile(&state, &jar, &id, &profile_id).await?;
    let synced = synchronize_authorization_profile(&state, &application, &profile).await;
    match synced {
        Ok(synced) => {
            state
                .db
                .record_audit_event(audit::management_event(
                    current.user.id,
                    "application.authorization_profile.refresh",
                    "application_authorization_profile",
                    Some(profile.id.clone()),
                    serde_json::json!({ "status": "synced", "profile_key": profile.profile_key }),
                ))
                .await?;
            Ok(Json(authorization_profile_response(&state, synced).await?))
        }
        Err(error) => {
            let _ = state
                .db
                .record_audit_event(audit::management_event(
                    current.user.id,
                    "application.authorization_profile.refresh",
                    "application_authorization_profile",
                    Some(profile.id),
                    serde_json::json!({ "status": "error" }),
                ))
                .await;
            Err(error)
        }
    }
}

async fn application_profile_permission_catalog(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, profile_id)): Path<(String, String)>,
) -> AppResult<Json<Vec<ApplicationPermissionDefinitionResponse>>> {
    let (_current, _application, profile) =
        managed_authorization_profile(&state, &jar, &id, &profile_id).await?;
    let mut definitions = Vec::new();
    if profile.source_mode == authorization_manifest::SOURCE_MODE_MANUAL {
        definitions.extend(permission_catalog().into_iter().map(|item| {
            ApplicationPermissionDefinitionResponse {
                key: item.key.to_string(),
                label: item.label.to_string(),
                description: Some(item.category.to_string()),
                source: "signet_compat".to_string(),
                is_active: true,
            }
        }));
    }
    definitions.extend(
        state
            .db
            .list_application_permission_definitions(&profile.id)
            .await?
            .into_iter()
            .map(application_permission_definition_response),
    );
    definitions.sort_by(|left, right| left.key.cmp(&right.key));
    definitions.dedup_by(|left, right| left.key == right.key);
    Ok(Json(definitions))
}

async fn list_application_profile_roles(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, profile_id)): Path<(String, String)>,
) -> AppResult<Json<Vec<ApplicationProfileRoleResponse>>> {
    let (_current, _application, _profile) =
        managed_authorization_profile(&state, &jar, &id, &profile_id).await?;
    Ok(Json(
        state
            .db
            .list_application_profile_roles(&profile_id)
            .await?
            .into_iter()
            .map(application_profile_role_response)
            .collect::<AppResult<Vec<_>>>()?,
    ))
}

async fn create_application_profile_role(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, profile_id)): Path<(String, String)>,
    Json(payload): Json<ApplicationProfileRoleInput>,
) -> AppResult<Json<ApplicationProfileRoleResponse>> {
    let (current, application, _profile) =
        managed_authorization_profile(&state, &jar, &id, &profile_id).await?;
    let role = state
        .db
        .upsert_application_profile_role(NewApplicationProfileRole {
            id: None,
            profile_id: profile_id.clone(),
            role_key: payload.role_key,
            name: payload.name,
            description: payload.description,
            permissions: payload.permissions,
            source: authorization_manifest::SOURCE_MANUAL.to_string(),
            is_default: payload.is_default,
            is_active: payload.is_active,
        })
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.authorization_profile_role.create",
            "application_profile_role",
            Some(role.id.clone()),
            serde_json::json!({ "application_id": application.id, "profile_id": profile_id }),
        ))
        .await?;
    Ok(Json(application_profile_role_response(role)?))
}

async fn update_application_profile_role(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, profile_id, role_id)): Path<(String, String, String)>,
    Json(payload): Json<ApplicationProfileRoleInput>,
) -> AppResult<Json<ApplicationProfileRoleResponse>> {
    let (current, application, _profile) =
        managed_authorization_profile(&state, &jar, &id, &profile_id).await?;
    let current_role = state
        .db
        .list_application_profile_roles(&profile_id)
        .await?
        .into_iter()
        .find(|role| role.id == role_id)
        .ok_or(AppError::NotFound)?;
    if current_role.source == authorization_manifest::SOURCE_MANIFEST
        && payload.role_key != current_role.role_key
    {
        return Err(AppError::BadRequest(
            "manifest role keys cannot be renamed locally".to_string(),
        ));
    }
    let role = state
        .db
        .upsert_application_profile_role(NewApplicationProfileRole {
            id: Some(role_id),
            profile_id: profile_id.clone(),
            role_key: current_role.role_key,
            name: payload.name,
            description: payload.description,
            permissions: payload.permissions,
            source: current_role.source,
            is_default: payload.is_default,
            is_active: payload.is_active,
        })
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.authorization_profile_role.update",
            "application_profile_role",
            Some(role.id.clone()),
            serde_json::json!({ "application_id": application.id, "profile_id": profile_id }),
        ))
        .await?;
    Ok(Json(application_profile_role_response(role)?))
}

async fn delete_application_profile_role(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, profile_id, role_id)): Path<(String, String, String)>,
) -> AppResult<Json<serde_json::Value>> {
    let (current, application, _profile) =
        managed_authorization_profile(&state, &jar, &id, &profile_id).await?;
    state
        .db
        .delete_application_profile_role(&profile_id, &role_id)
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.authorization_profile_role.delete",
            "application_profile_role",
            Some(role_id.clone()),
            serde_json::json!({ "application_id": application.id, "profile_id": profile_id }),
        ))
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn list_application_profile_user_roles(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, profile_id, user_id)): Path<(String, String, String)>,
) -> AppResult<Json<Vec<String>>> {
    let (_current, application, _profile) =
        managed_authorization_profile(&state, &jar, &id, &profile_id).await?;
    application_authorization_user(&state, &application, &user_id).await?;
    Ok(Json(
        state
            .db
            .list_application_profile_user_role_ids(&profile_id, &user_id)
            .await?,
    ))
}

async fn update_application_profile_user_roles(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, profile_id, user_id)): Path<(String, String, String)>,
    Json(payload): Json<ApplicationRoleIdsInput>,
) -> AppResult<Json<Vec<String>>> {
    let (current, application, _profile) =
        managed_authorization_profile(&state, &jar, &id, &profile_id).await?;
    let user = application_authorization_user(&state, &application, &user_id).await?;
    state
        .db
        .replace_application_profile_user_role_ids(&profile_id, &user.id, payload.role_ids)
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.authorization_profile.user_roles.update",
            "application_authorization_profile",
            Some(profile_id.clone()),
            serde_json::json!({ "application_id": application.id, "user_id": user.id }),
        ))
        .await?;
    Ok(Json(
        state
            .db
            .list_application_profile_user_role_ids(&profile_id, &user_id)
            .await?,
    ))
}

async fn list_application_profile_group_roles(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, profile_id, group_id)): Path<(String, String, String)>,
) -> AppResult<Json<Vec<String>>> {
    let (_current, application, _profile) =
        managed_authorization_profile(&state, &jar, &id, &profile_id).await?;
    application_authorization_group(&state, &application, &group_id).await?;
    Ok(Json(
        state
            .db
            .list_application_profile_group_role_ids(&profile_id, &group_id)
            .await?,
    ))
}

async fn update_application_profile_group_roles(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, profile_id, group_id)): Path<(String, String, String)>,
    Json(payload): Json<ApplicationRoleIdsInput>,
) -> AppResult<Json<Vec<String>>> {
    let (current, application, _profile) =
        managed_authorization_profile(&state, &jar, &id, &profile_id).await?;
    application_authorization_group(&state, &application, &group_id).await?;
    state
        .db
        .replace_application_profile_group_role_ids(&profile_id, &group_id, payload.role_ids)
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.authorization_profile.group_roles.update",
            "application_authorization_profile",
            Some(profile_id.clone()),
            serde_json::json!({ "application_id": application.id, "group_id": group_id }),
        ))
        .await?;
    Ok(Json(
        state
            .db
            .list_application_profile_group_role_ids(&profile_id, &group_id)
            .await?,
    ))
}

async fn list_application_profile_organization_role_roles(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, profile_id, organization_role)): Path<(String, String, String)>,
) -> AppResult<Json<Vec<String>>> {
    let (_current, _application, _profile) =
        managed_authorization_profile(&state, &jar, &id, &profile_id).await?;
    let organization_role = organizations::normalize_role(&organization_role)?;
    Ok(Json(
        state
            .db
            .list_application_profile_organization_role_ids(&profile_id, &organization_role)
            .await?,
    ))
}

async fn update_application_profile_organization_role_roles(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, profile_id, organization_role)): Path<(String, String, String)>,
    Json(payload): Json<ApplicationRoleIdsInput>,
) -> AppResult<Json<Vec<String>>> {
    let (current, application, _profile) =
        managed_authorization_profile(&state, &jar, &id, &profile_id).await?;
    let organization_role = organizations::normalize_role(&organization_role)?;
    state
        .db
        .replace_application_profile_organization_role_ids(
            &profile_id,
            &organization_role,
            payload.role_ids,
        )
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.authorization_profile.organization_roles.update",
            "application_authorization_profile",
            Some(profile_id.clone()),
            serde_json::json!({
                "application_id": application.id,
                "organization_role": organization_role,
            }),
        ))
        .await?;
    Ok(Json(
        state
            .db
            .list_application_profile_organization_role_ids(
                &profile_id,
                &organization_role,
            )
            .await?,
    ))
}

async fn list_application_profile_user_permission_overrides(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, profile_id, user_id)): Path<(String, String, String)>,
) -> AppResult<Json<Vec<ApplicationPermissionOverrideResponse>>> {
    let (_current, application, _profile) =
        managed_authorization_profile(&state, &jar, &id, &profile_id).await?;
    application_authorization_user(&state, &application, &user_id).await?;
    Ok(Json(
        state
            .db
            .list_application_profile_user_permission_overrides(&profile_id, &user_id)
            .await?
            .into_iter()
            .map(|value| ApplicationPermissionOverrideResponse {
                permission: value.permission,
                effect: value.effect,
            })
            .collect(),
    ))
}

async fn update_application_profile_user_permission_overrides(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, profile_id, user_id)): Path<(String, String, String)>,
    Json(payload): Json<ApplicationPermissionOverridesInput>,
) -> AppResult<Json<Vec<ApplicationPermissionOverrideResponse>>> {
    let (current, application, _profile) =
        managed_authorization_profile(&state, &jar, &id, &profile_id).await?;
    application_authorization_user(&state, &application, &user_id).await?;
    state
        .db
        .replace_application_profile_user_permission_overrides(
            &profile_id,
            &user_id,
            payload
                .overrides
                .into_iter()
                .map(|item| (item.permission, item.effect))
                .collect(),
        )
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.authorization_profile.user_permission_overrides.update",
            "application_authorization_profile",
            Some(profile_id.clone()),
            serde_json::json!({ "application_id": application.id, "user_id": user_id }),
        ))
        .await?;
    Ok(Json(
        state
            .db
            .list_application_profile_user_permission_overrides(&profile_id, &user_id)
            .await?
            .into_iter()
            .map(|value| ApplicationPermissionOverrideResponse {
                permission: value.permission,
                effect: value.effect,
            })
            .collect(),
    ))
}

async fn application_profile_authorization_preview(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, profile_id, user_id)): Path<(String, String, String)>,
) -> AppResult<Json<serde_json::Value>> {
    let (_current, application, profile) =
        managed_authorization_profile(&state, &jar, &id, &profile_id).await?;
    let user = application_authorization_user(&state, &application, &user_id).await?;
    let decision = authorization::check_login_access(&state, &application, &user.id).await?;
    let entitlements = if decision.allowed {
        Some(
            authorization::resolve_entitlements_for_profile(&state, &application, &profile, &user)
                .await?,
        )
    } else {
        None
    };
    Ok(Json(serde_json::json!({
        "decision": decision,
        "entitlements": entitlements,
    })))
}

async fn list_application_user_roles(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, user_id)): Path<(String, String)>,
) -> AppResult<Json<Vec<String>>> {
    let (_current, _application) = managed_application(&state, &jar, &id).await?;
    Ok(Json(
        state
            .db
            .list_application_user_role_ids(&id, &user_id)
            .await?,
    ))
}

async fn update_application_user_roles(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, user_id)): Path<(String, String)>,
    Json(payload): Json<ApplicationRoleIdsInput>,
) -> AppResult<Json<Vec<String>>> {
    let (current, application) = managed_application(&state, &jar, &id).await?;
    let user = state
        .db
        .find_user_by_id(&user_id)
        .await?
        .ok_or(AppError::NotFound)?;
    state
        .db
        .replace_application_user_role_ids(&id, &user.id, payload.role_ids)
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.user_roles.update",
            "application",
            Some(id.clone()),
            serde_json::json!({
                "organization_id": application.organization_id,
                "user_id": user.id,
            }),
        ))
        .await?;
    Ok(Json(
        state
            .db
            .list_application_user_role_ids(&id, &user_id)
            .await?,
    ))
}

async fn list_application_group_roles(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, group_id)): Path<(String, String)>,
) -> AppResult<Json<Vec<String>>> {
    let (_current, _application) = managed_application(&state, &jar, &id).await?;
    state
        .db
        .find_group_by_id(&group_id)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(
        state
            .db
            .list_application_group_role_ids(&id, &group_id)
            .await?,
    ))
}

async fn update_application_group_roles(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, group_id)): Path<(String, String)>,
    Json(payload): Json<ApplicationRoleIdsInput>,
) -> AppResult<Json<Vec<String>>> {
    let (current, application) = managed_application(&state, &jar, &id).await?;
    state
        .db
        .find_group_by_id(&group_id)
        .await?
        .ok_or(AppError::NotFound)?;
    state
        .db
        .replace_application_group_role_ids(&id, &group_id, payload.role_ids)
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.group_roles.update",
            "application",
            Some(id.clone()),
            serde_json::json!({
                "organization_id": application.organization_id,
                "group_id": group_id,
            }),
        ))
        .await?;
    Ok(Json(
        state
            .db
            .list_application_group_role_ids(&id, &group_id)
            .await?,
    ))
}

async fn list_application_organization_role_roles(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, organization_role)): Path<(String, String)>,
) -> AppResult<Json<Vec<String>>> {
    let (_current, _application) = managed_application(&state, &jar, &id).await?;
    let organization_role = organizations::normalize_role(&organization_role)?;
    Ok(Json(
        state
            .db
            .list_application_organization_role_ids(&id, &organization_role)
            .await?,
    ))
}

async fn update_application_organization_role_roles(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, organization_role)): Path<(String, String)>,
    Json(payload): Json<ApplicationRoleIdsInput>,
) -> AppResult<Json<Vec<String>>> {
    let (current, application) = managed_application(&state, &jar, &id).await?;
    let organization_role = organizations::normalize_role(&organization_role)?;
    state
        .db
        .replace_application_organization_role_ids(&id, &organization_role, payload.role_ids)
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.organization_role_mapping.update",
            "application",
            Some(id.clone()),
            serde_json::json!({
                "organization_id": application.organization_id,
                "organization_role": organization_role,
            }),
        ))
        .await?;
    Ok(Json(
        state
            .db
            .list_application_organization_role_ids(&id, &organization_role)
            .await?,
    ))
}

async fn list_application_user_permission_overrides(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, user_id)): Path<(String, String)>,
) -> AppResult<Json<Vec<ApplicationPermissionOverrideResponse>>> {
    let (_current, _application) = managed_application(&state, &jar, &id).await?;
    let values = state
        .db
        .list_application_user_permission_overrides(&id, &user_id)
        .await?
        .into_iter()
        .map(|value| ApplicationPermissionOverrideResponse {
            permission: value.permission,
            effect: value.effect,
        })
        .collect();
    Ok(Json(values))
}

async fn update_application_user_permission_overrides(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, user_id)): Path<(String, String)>,
    Json(payload): Json<ApplicationPermissionOverridesInput>,
) -> AppResult<Json<Vec<ApplicationPermissionOverrideResponse>>> {
    let (current, application) = managed_application(&state, &jar, &id).await?;
    state
        .db
        .find_user_by_id(&user_id)
        .await?
        .ok_or(AppError::NotFound)?;
    state
        .db
        .replace_application_user_permission_overrides(
            &id,
            &user_id,
            payload
                .overrides
                .into_iter()
                .map(|item| (item.permission, item.effect))
                .collect(),
        )
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.user_permission_overrides.update",
            "application",
            Some(id.clone()),
            serde_json::json!({
                "organization_id": application.organization_id,
                "user_id": user_id,
            }),
        ))
        .await?;
    let values = state
        .db
        .list_application_user_permission_overrides(&id, &user_id)
        .await?
        .into_iter()
        .map(|value| ApplicationPermissionOverrideResponse {
            permission: value.permission,
            effect: value.effect,
        })
        .collect();
    Ok(Json(values))
}

async fn application_authorization_preview(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, user_id)): Path<(String, String)>,
) -> AppResult<Json<serde_json::Value>> {
    let (_current, application) = managed_application(&state, &jar, &id).await?;
    let user = state
        .db
        .find_user_by_id(&user_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let decision = authorization::check_login_access(&state, &application, &user.id).await?;
    let entitlements = if decision.allowed {
        Some(authorization::resolve_entitlements(&state, &application, &user).await?)
    } else {
        None
    };
    Ok(Json(serde_json::json!({
        "decision": decision,
        "entitlements": entitlements,
    })))
}

async fn create_application(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<ApplicationInput>,
) -> AppResult<Json<ApplicationResponse>> {
    let (current, organization) = current_organization_context(&state, &jar).await?;
    require_organization_manager_for(&state, &current, &organization.id).await?;
    let application = state
        .db
        .insert_application(application_input_to_new(
            organization.id.clone(),
            payload,
            false,
        )?)
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.create",
            "application",
            Some(application.id.clone()),
            serde_json::json!({
                "organization_id": application.organization_id,
                "slug": application.slug,
            }),
        ))
        .await?;
    Ok(Json(application_response(&state, application).await?))
}

async fn update_application(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<ApplicationInput>,
) -> AppResult<Json<ApplicationResponse>> {
    let current = auth::require_current_user(&state, &jar).await?;
    let existing = state
        .db
        .find_application_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    require_organization_manager_for(&state, &current, &existing.organization_id).await?;
    let application = state
        .db
        .update_application(
            &id,
            application_input_to_new(existing.organization_id.clone(), payload, false)?,
        )
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.update",
            "application",
            Some(application.id.clone()),
            serde_json::json!({ "organization_id": application.organization_id }),
        ))
        .await?;
    Ok(Json(application_response(&state, application).await?))
}

async fn delete_application(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let current = auth::require_current_user(&state, &jar).await?;
    let existing = state
        .db
        .find_application_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    require_organization_manager_for(&state, &current, &existing.organization_id).await?;
    // An enrollment capability must never outlive the application that owns
    // it. Deleting it also revokes the restricted sessions it created.
    for invitation in state.db.list_application_enrollment_codes(&id).await? {
        state.db.delete_invitation(&invitation.id).await?;
    }
    state.db.delete_application(&id).await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.delete",
            "application",
            Some(id),
            serde_json::json!({ "organization_id": existing.organization_id }),
        ))
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn list_application_oidc_clients(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<Vec<PublicClient>>> {
    let current = auth::require_current_user(&state, &jar).await?;
    let application = state
        .db
        .find_application_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    require_organization_manager_for(&state, &current, &application.organization_id).await?;
    let mut clients = Vec::new();
    for client_id in state.db.list_application_oidc_client_ids(&id).await? {
        let client = state
            .db
            .find_client_by_id(&client_id)
            .await?
            .ok_or(AppError::NotFound)?;
        clients.push(public_client_with_claim_mappers(&state, client).await?);
    }
    Ok(Json(clients))
}

async fn replace_application_oidc_clients(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<ApplicationOidcClientsInput>,
) -> AppResult<Json<Vec<PublicClient>>> {
    let current = auth::require_current_user(&state, &jar).await?;
    let application = state
        .db
        .find_application_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    require_organization_manager_for(&state, &current, &application.organization_id).await?;
    let requested_ids = payload
        .client_ids
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>();
    for client_id in &requested_ids {
        let client = state
            .db
            .find_client_by_id(client_id)
            .await?
            .ok_or_else(|| AppError::BadRequest("OIDC client does not exist".to_string()))?;
        if client.organization_id.as_deref() != Some(application.organization_id.as_str()) {
            return Err(AppError::Forbidden);
        }
    }
    for existing_client_id in state.db.list_application_oidc_client_ids(&id).await? {
        if !requested_ids.contains(&existing_client_id) {
            // Removing a connection leaves its compatibility application in
            // place only when explicitly linked elsewhere. The mapping table
            // is the sole authority, so deletion is safe here.
            state
                .db
                .unlink_oidc_client_from_application(&existing_client_id)
                .await?;
        }
    }
    for client_id in &requested_ids {
        state
            .db
            .link_oidc_client_to_application(&id, client_id)
            .await?;
    }
    auto_refresh_application_authorization_profiles(&state, &application).await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.oidc_clients.update",
            "application",
            Some(id.clone()),
            serde_json::json!({ "client_ids": requested_ids }),
        ))
        .await?;
    list_application_oidc_clients(State(state), jar, Path(id)).await
}

#[derive(Debug, Deserialize)]
struct ApplicationEnrollmentCodeInput {
    #[serde(default)]
    description: Option<String>,
    /// Normal enrollment creates a reusable multi-enterprise Signet account.
    /// Restricted trial is retained for short-lived, application-only trials.
    #[serde(default = "default_application_enrollment_account_kind")]
    account_kind: String,
    expires_at: i64,
    max_uses: i32,
    #[serde(default = "default_organization_role")]
    organization_role: String,
    #[serde(default = "default_true")]
    is_active: bool,
}

#[derive(Debug, Clone, Copy)]
enum ApplicationEnrollmentAccountKind {
    Normal,
    RestrictedTrial,
}

impl ApplicationEnrollmentAccountKind {
    fn parse(value: &str) -> AppResult<Self> {
        match value.trim() {
            "normal" => Ok(Self::Normal),
            "restricted_trial" => Ok(Self::RestrictedTrial),
            other => Err(AppError::BadRequest(format!(
                "unsupported application enrollment account kind: {other}"
            ))),
        }
    }

    const fn audit_value(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::RestrictedTrial => "restricted_trial",
        }
    }
}

// Keep the previous API behavior for callers that have not yet sent the new
// field. The management UI deliberately sends `normal` as its product
// default, because it is the right choice for a regular enterprise member.
fn default_application_enrollment_account_kind() -> String {
    "restricted_trial".to_string()
}

#[derive(Debug, Serialize)]
struct ApplicationEnrollmentCodeCreateResponse {
    invitation: PublicInvitation,
    code: String,
}

async fn active_application_client_ids(
    state: &AppState,
    application: &ApplicationRecord,
) -> AppResult<Vec<String>> {
    let mut client_ids = Vec::new();
    for client_db_id in state
        .db
        .list_application_oidc_client_ids(&application.id)
        .await?
    {
        let client = state
            .db
            .find_client_by_id(&client_db_id)
            .await?
            .ok_or(AppError::NotFound)?;
        if client.organization_id.as_deref() != Some(application.organization_id.as_str()) {
            return Err(AppError::Internal(
                "application has an OIDC connection from a different organization".to_string(),
            ));
        }
        if client.is_active == 1 {
            client_ids.push(client.client_id);
        }
    }
    Ok(client_ids)
}

async fn list_application_enrollment_codes(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<Vec<PublicInvitation>>> {
    let current = auth::require_current_user(&state, &jar).await?;
    let application = state
        .db
        .find_application_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    require_organization_manager_for(&state, &current, &application.organization_id).await?;
    Ok(Json(
        state
            .db
            .list_application_enrollment_codes(&id)
            .await?
            .into_iter()
            .map(|invitation| invitation.public())
            .collect::<AppResult<Vec<_>>>()?,
    ))
}

async fn create_application_enrollment_code(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<ApplicationEnrollmentCodeInput>,
) -> AppResult<Json<ApplicationEnrollmentCodeCreateResponse>> {
    let current = auth::require_current_user(&state, &jar).await?;
    let application = state
        .db
        .find_application_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    require_organization_manager_for(&state, &current, &application.organization_id).await?;
    if application.is_active != 1 {
        return Err(AppError::BadRequest(
            "application enrollment is unavailable while the application is disabled".to_string(),
        ));
    }
    if application.registration_mode != applications::REGISTRATION_INVITATION {
        return Err(AppError::BadRequest(
            "set this application's registration policy to invitation before creating enrollment codes"
                .to_string(),
        ));
    }
    if payload.expires_at <= util::now_ts() {
        return Err(AppError::BadRequest(
            "application enrollment codes require a future expiry".to_string(),
        ));
    }
    if payload.max_uses <= 0 {
        return Err(AppError::BadRequest(
            "application enrollment codes require a positive maximum use count".to_string(),
        ));
    }
    let account_kind = ApplicationEnrollmentAccountKind::parse(&payload.account_kind)?;
    let organization_role = organizations::normalize_role(&payload.organization_role)?;
    let allowed_client_ids = active_application_client_ids(&state, &application).await?;
    if allowed_client_ids.is_empty() {
        return Err(AppError::BadRequest(
            "attach at least one active OIDC connection before creating an enrollment code"
                .to_string(),
        ));
    }
    let code = format!("APP-{}", util::random_token(18));
    let signing_key = state
        .db
        .list_signing_keys()
        .await?
        .into_iter()
        .find(|key| key.is_active == 1)
        .ok_or_else(|| {
            AppError::Configuration(
                "an active signing key is required to create a revealable enrollment code"
                    .to_string(),
            )
        })?;
    let ciphertext =
        util::encrypt_authorization_code_for_reveal(&signing_key.private_key_pem, &code)?;
    let (invitation, code) = state
        .db
        .insert_invitation_with_reveal_secret(
            NewInvitation {
                code_type: match account_kind {
                    ApplicationEnrollmentAccountKind::Normal => AuthorizationCodeType::Registration,
                    ApplicationEnrollmentAccountKind::RestrictedTrial => {
                        AuthorizationCodeType::Login
                    }
                },
                login_code_level: match account_kind {
                    ApplicationEnrollmentAccountKind::Normal => LoginCodeLevel::AccountRecovery,
                    ApplicationEnrollmentAccountKind::RestrictedTrial => {
                        LoginCodeLevel::TrialEnrollment
                    }
                },
                allowed_client_ids: allowed_client_ids.clone(),
                organization_id: Some(application.organization_id.clone()),
                organization_role: Some(organization_role.clone()),
                description: normalize_optional_text(payload.description),
                authorized_email: None,
                authorized_username: None,
                authorized_user_id: None,
                authorized_display_name: None,
                expires_at: Some(payload.expires_at),
                max_uses: Some(payload.max_uses),
                is_active: payload.is_active,
                created_by: Some(current.user.id.clone()),
            },
            code,
            signing_key.kid,
            ciphertext,
        )
        .await?;
    state
        .db
        .link_application_enrollment_code(&application.id, &invitation.id)
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.enrollment_code.create",
            "application",
            Some(application.id),
            serde_json::json!({
                "invitation_id": invitation.id,
                "organization_id": application.organization_id,
                "allowed_client_ids": allowed_client_ids,
                "organization_role": organization_role,
                "max_uses": payload.max_uses,
                "account_kind": account_kind.audit_value(),
            }),
        ))
        .await?;
    Ok(Json(ApplicationEnrollmentCodeCreateResponse {
        invitation: invitation.public()?,
        code,
    }))
}

async fn delete_application_enrollment_code(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, code_id)): Path<(String, String)>,
) -> AppResult<Json<serde_json::Value>> {
    let current = auth::require_current_user(&state, &jar).await?;
    let application = state
        .db
        .find_application_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    require_organization_manager_for(&state, &current, &application.organization_id).await?;
    if !state
        .db
        .application_enrollment_code_belongs_to(&id, &code_id)
        .await?
    {
        return Err(AppError::NotFound);
    }
    state.db.delete_invitation(&code_id).await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.enrollment_code.delete",
            "application",
            Some(id),
            serde_json::json!({ "invitation_id": code_id }),
        ))
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
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
    Ok(Json(
        state
            .db
            .list_invitations()
            .await?
            .into_iter()
            .map(crate::db::InvitationRecord::public)
            .collect::<AppResult<Vec<_>>>()?,
    ))
}

#[derive(Debug, Serialize)]
struct InvitationRevealResponse {
    code: String,
}

/// Deliberately uses POST: revealing a credential is sensitive, should not be
/// link-prefetched, and receives the same CSRF protection as other management
/// operations.  List responses never include the ciphertext or plaintext.
async fn reveal_invitation_code(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<InvitationRevealResponse>> {
    let current = require_authorization_code_manager(&state, &jar).await?;
    let invitation = state
        .db
        .find_invitation_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    let key_id = invitation.code_reveal_key_id.clone().ok_or_else(|| {
        AppError::BadRequest(
            "this authorization code was created before secure reveal was available".to_string(),
        )
    })?;
    let ciphertext = invitation.code_reveal_ciphertext.clone().ok_or_else(|| {
        AppError::BadRequest(
            "this authorization code was created before secure reveal was available".to_string(),
        )
    })?;
    let signing_key = state
        .db
        .list_signing_keys()
        .await?
        .into_iter()
        .find(|key| key.kid == key_id)
        .ok_or_else(|| {
            AppError::Configuration(
                "authorization code reveal key is unavailable; retain retired signing keys while revealable codes exist"
                    .to_string(),
            )
        })?;
    let code =
        util::decrypt_authorization_code_for_reveal(&signing_key.private_key_pem, &ciphertext)?;
    if util::token_hash(&code) != invitation.code_hash {
        return Err(AppError::Internal(
            "decrypted authorization code does not match its stored verifier".to_string(),
        ));
    }
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "authorization_code.reveal",
            "authorization_code",
            Some(invitation.id),
            serde_json::json!({
                "code_type": invitation.code_type,
                "login_code_level": invitation.login_code_level,
            }),
        ))
        .await?;
    Ok(Json(InvitationRevealResponse { code }))
}

const INVITATION_REDEMPTIONS_DEFAULT_PAGE_SIZE: usize = 50;
const INVITATION_REDEMPTIONS_MAX_PAGE_SIZE: usize = 100;

#[derive(Debug, Deserialize)]
struct InvitationRedemptionsQuery {
    cursor: Option<String>,
    limit: Option<usize>,
}

#[derive(Debug, Serialize)]
struct InvitationRedemptionsResponse {
    redemptions: Vec<PublicInvitationRedemption>,
    next_cursor: Option<String>,
}

fn parse_invitation_redemptions_cursor(value: Option<&str>) -> AppResult<Option<(i64, String)>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let (redeemed_at, id) = value.rsplit_once(':').ok_or_else(|| {
        AppError::BadRequest("invalid authorization-code redemption cursor".to_string())
    })?;
    let redeemed_at = redeemed_at.parse::<i64>().map_err(|_| {
        AppError::BadRequest("invalid authorization-code redemption cursor".to_string())
    })?;
    if id.is_empty() || id.len() > 128 {
        return Err(AppError::BadRequest(
            "invalid authorization-code redemption cursor".to_string(),
        ));
    }
    Ok(Some((redeemed_at, id.to_string())))
}

async fn list_invitation_redemptions(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Query(query): Query<InvitationRedemptionsQuery>,
) -> AppResult<Json<InvitationRedemptionsResponse>> {
    require_authorization_code_manager(&state, &jar).await?;
    state
        .db
        .find_invitation_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    let limit = query
        .limit
        .unwrap_or(INVITATION_REDEMPTIONS_DEFAULT_PAGE_SIZE);
    if !(1..=INVITATION_REDEMPTIONS_MAX_PAGE_SIZE).contains(&limit) {
        return Err(AppError::BadRequest(format!(
            "authorization-code redemption limit must be between 1 and {INVITATION_REDEMPTIONS_MAX_PAGE_SIZE}"
        )));
    }
    let cursor = parse_invitation_redemptions_cursor(query.cursor.as_deref())?;
    let mut records = state
        .db
        .list_invitation_redemptions_for_invitation(&id, cursor, (limit + 1) as i32)
        .await?;
    let has_more = records.len() > limit;
    records.truncate(limit);
    let next_cursor = has_more
        .then(|| {
            records
                .last()
                .map(|record| format!("{}:{}", record.redeemed_at, record.id))
        })
        .flatten();
    Ok(Json(InvitationRedemptionsResponse {
        redemptions: records
            .into_iter()
            .map(crate::db::InvitationRedemptionRecord::public)
            .collect(),
        next_cursor,
    }))
}

#[derive(Debug, Deserialize)]
struct InvitationInput {
    code_type: Option<AuthorizationCodeType>,
    login_code_level: Option<LoginCodeLevel>,
    allowed_client_ids: Option<Vec<String>>,
    organization_id: Option<String>,
    organization_role: Option<String>,
    description: Option<String>,
    authorized_email: Option<String>,
    authorized_username: Option<String>,
    authorized_display_name: Option<String>,
    expires_at: Option<i64>,
    max_uses: Option<i32>,
    is_active: bool,
}

fn normalized_client_ids(values: Option<Vec<String>>) -> Vec<String> {
    values
        .unwrap_or_default()
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn immutable_allowed_client_ids(
    existing: Vec<String>,
    requested: Option<Vec<String>>,
) -> AppResult<Vec<String>> {
    let existing = normalized_client_ids(Some(existing));
    let Some(requested) = requested else {
        return Ok(existing);
    };
    if normalized_client_ids(Some(requested)) != existing {
        return Err(AppError::BadRequest(
            "allowed_client_ids cannot be changed after creation".to_string(),
        ));
    }
    Ok(existing)
}

fn immutable_optional_text(
    field: &str,
    existing: Option<&str>,
    requested: Option<String>,
) -> AppResult<Option<String>> {
    let existing = existing
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let Some(requested) = requested else {
        return Ok(existing);
    };
    let requested = normalize_optional_text(Some(requested));
    if requested != existing {
        return Err(AppError::BadRequest(format!(
            "{field} cannot be changed after trial enrollment code creation"
        )));
    }
    Ok(existing)
}

fn immutable_recovery_username(
    existing: Option<&str>,
    requested: Option<String>,
) -> AppResult<Option<String>> {
    let existing = existing
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            AppError::Configuration(
                "account recovery authorization code is missing its bound username".to_string(),
            )
        })?
        .to_string();
    let Some(requested) = requested else {
        return Ok(Some(existing));
    };
    let requested = normalize_optional_text(Some(requested)).ok_or_else(|| {
        AppError::BadRequest(
            "authorized_username cannot be cleared after account recovery code creation"
                .to_string(),
        )
    })?;
    if requested != existing {
        return Err(AppError::BadRequest(
            "authorized_username cannot be changed after account recovery code creation"
                .to_string(),
        ));
    }
    Ok(Some(existing))
}

fn ensure_admin_universal_manager(
    user: &crate::db::UserRecord,
    code_type: AuthorizationCodeType,
    login_code_level: LoginCodeLevel,
) -> AppResult<()> {
    if code_type == AuthorizationCodeType::Login
        && login_code_level == LoginCodeLevel::AdminUniversal
        && user.is_admin != 1
    {
        return Err(AppError::Forbidden);
    }
    Ok(())
}

async fn ensure_trial_enrollment_role_manager(
    state: &AppState,
    user: &crate::db::UserRecord,
    code_type: AuthorizationCodeType,
    login_code_level: LoginCodeLevel,
    _organization_role: Option<&str>,
) -> AppResult<()> {
    if code_type == AuthorizationCodeType::Login
        && login_code_level == LoginCodeLevel::TrialEnrollment
    {
        // An enrollment code grants organization membership, even for the
        // default member role. Keep that authority with organization managers
        // rather than broad authorization-code operators.
        state
            .db
            .require_permission(user, Permission::OrganizationsManage)
            .await?;
    }
    Ok(())
}

fn recovery_target_user_id(
    username: &str,
    user: Option<crate::db::UserRecord>,
) -> AppResult<String> {
    let user = user.ok_or_else(|| {
        AppError::BadRequest(
            "account recovery authorization codes require an existing account".to_string(),
        )
    })?;
    if user.username != username {
        return Err(AppError::BadRequest(
            "authorized_username must exactly match the existing account username".to_string(),
        ));
    }
    if user.is_active != 1 || user.archived_at.is_some() {
        return Err(AppError::BadRequest(
            "account recovery authorization codes require an active account".to_string(),
        ));
    }
    Ok(user.id)
}

fn validate_login_code_binding_metadata(
    login_code_level: LoginCodeLevel,
    authorized_email: Option<&str>,
    authorized_username: Option<&str>,
    authorized_display_name: Option<&str>,
) -> AppResult<()> {
    if authorized_email.is_some() || authorized_display_name.is_some() {
        return Err(AppError::BadRequest(
            "login authorization codes cannot set email or display-name metadata".to_string(),
        ));
    }
    if matches!(
        login_code_level,
        LoginCodeLevel::AdminUniversal | LoginCodeLevel::TrialEnrollment
    ) && authorized_username.is_some()
    {
        return Err(AppError::BadRequest(
            "this login authorization code cannot set account binding metadata".to_string(),
        ));
    }
    Ok(())
}

struct AuthorizationCodeValidationInput<'a> {
    code_type: AuthorizationCodeType,
    login_code_level: LoginCodeLevel,
    authorized_email: Option<&'a str>,
    authorized_username: Option<&'a str>,
    authorized_display_name: Option<&'a str>,
    allowed_client_ids: &'a [String],
    organization_id: Option<&'a str>,
    organization_role: Option<&'a str>,
}

async fn validate_authorization_code_input(
    state: &AppState,
    input: AuthorizationCodeValidationInput<'_>,
) -> AppResult<()> {
    let AuthorizationCodeValidationInput {
        code_type,
        login_code_level,
        authorized_email,
        authorized_username,
        authorized_display_name,
        allowed_client_ids,
        organization_id,
        organization_role,
    } = input;
    match code_type {
        AuthorizationCodeType::Registration => {
            if login_code_level != LoginCodeLevel::AccountRecovery {
                return Err(AppError::BadRequest(
                    "registration authorization codes cannot set a login code level".to_string(),
                ));
            }
            if !allowed_client_ids.is_empty() {
                return Err(AppError::BadRequest(
                    "registration authorization codes cannot allow OIDC clients".to_string(),
                ));
            }
            if organization_id.is_some() || organization_role.is_some() {
                return Err(AppError::BadRequest(
                    "registration authorization codes cannot bind an organization".to_string(),
                ));
            }
        }
        AuthorizationCodeType::Login => {
            validate_login_code_binding_metadata(
                login_code_level,
                authorized_email,
                authorized_username,
                authorized_display_name,
            )?;
            match login_code_level {
                LoginCodeLevel::AccountRecovery => {
                    if authorized_username.is_none_or(|value| value.trim().is_empty()) {
                        return Err(AppError::BadRequest(
                            "account recovery authorization codes require authorized_username"
                                .to_string(),
                        ));
                    }
                    if !allowed_client_ids.is_empty() {
                        return Err(AppError::BadRequest(
                            "account recovery authorization codes cannot allow OIDC clients"
                                .to_string(),
                        ));
                    }
                    if organization_id.is_some() || organization_role.is_some() {
                        return Err(AppError::BadRequest(
                            "account recovery authorization codes cannot bind an organization"
                                .to_string(),
                        ));
                    }
                }
                LoginCodeLevel::AdminUniversal => {
                    if allowed_client_ids.is_empty() {
                        return Err(AppError::BadRequest(
                        "admin universal authorization codes require at least one allowed OIDC client"
                            .to_string(),
                    ));
                    }
                    if organization_id.is_some() || organization_role.is_some() {
                        return Err(AppError::BadRequest(
                            "admin universal authorization codes cannot bind an organization"
                                .to_string(),
                        ));
                    }
                    for client_id in allowed_client_ids {
                        let client = state
                            .db
                            .find_client_by_client_id(client_id)
                            .await?
                            .ok_or_else(|| {
                                AppError::BadRequest(format!(
                                    "allowed OIDC client does not exist: {client_id}"
                                ))
                            })?;
                        if client.is_active != 1 {
                            return Err(AppError::BadRequest(format!(
                                "allowed OIDC client is disabled: {client_id}"
                            )));
                        }
                    }
                }
                LoginCodeLevel::TrialEnrollment => {
                    let organization_id = organization_id
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .ok_or_else(|| {
                            AppError::BadRequest(
                                "trial enrollment authorization codes require organization_id"
                                    .to_string(),
                            )
                        })?;
                    let role = organization_role
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .ok_or_else(|| {
                            AppError::BadRequest(
                                "trial enrollment authorization codes require organization_role"
                                    .to_string(),
                            )
                        })?;
                    organizations::normalize_role(role)?;
                    if allowed_client_ids.is_empty() {
                        return Err(AppError::BadRequest(
                            "trial enrollment authorization codes require at least one allowed OIDC client"
                                .to_string(),
                        ));
                    }
                    let organization = state
                        .db
                        .find_organization_by_id(organization_id)
                        .await?
                        .ok_or_else(|| {
                            AppError::BadRequest(
                                "trial enrollment organization does not exist".to_string(),
                            )
                        })?;
                    if organization.is_active != 1 {
                        return Err(AppError::BadRequest(
                            "trial enrollment organization is disabled".to_string(),
                        ));
                    }
                    for client_id in allowed_client_ids {
                        let client = state
                            .db
                            .find_client_by_client_id(client_id)
                            .await?
                            .ok_or_else(|| {
                                AppError::BadRequest(format!(
                                    "allowed OIDC client does not exist: {client_id}"
                                ))
                            })?;
                        if client.is_active != 1 {
                            return Err(AppError::BadRequest(format!(
                                "allowed OIDC client is disabled: {client_id}"
                            )));
                        }
                    }
                }
            }
        }
    }
    Ok(())
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
    let code_type = payload.code_type.unwrap_or(AuthorizationCodeType::Login);
    let login_code_level = payload
        .login_code_level
        .unwrap_or(LoginCodeLevel::AccountRecovery);
    ensure_admin_universal_manager(&current.user, code_type, login_code_level)?;
    let allowed_client_ids = normalized_client_ids(payload.allowed_client_ids);
    let organization_id = normalize_optional_text(payload.organization_id);
    let organization_role = normalize_optional_text(payload.organization_role)
        .map(|value| organizations::normalize_role(&value))
        .transpose()?;
    let authorized_email = normalize_optional_email(payload.authorized_email)?;
    let authorized_username = normalize_optional_text(payload.authorized_username);
    let authorized_display_name = normalize_optional_text(payload.authorized_display_name);
    validate_authorization_code_input(
        &state,
        AuthorizationCodeValidationInput {
            code_type,
            login_code_level,
            authorized_email: authorized_email.as_deref(),
            authorized_username: authorized_username.as_deref(),
            authorized_display_name: authorized_display_name.as_deref(),
            allowed_client_ids: &allowed_client_ids,
            organization_id: organization_id.as_deref(),
            organization_role: organization_role.as_deref(),
        },
    )
    .await?;
    ensure_trial_enrollment_role_manager(
        &state,
        &current.user,
        code_type,
        login_code_level,
        organization_role.as_deref(),
    )
    .await?;
    if login_code_level == LoginCodeLevel::TrialEnrollment {
        if payload
            .expires_at
            .is_none_or(|expires_at| expires_at <= util::now_ts())
        {
            return Err(AppError::BadRequest(
                "trial enrollment authorization codes require a future expires_at".to_string(),
            ));
        }
        if payload.max_uses.is_none() {
            return Err(AppError::BadRequest(
                "trial enrollment authorization codes require max_uses".to_string(),
            ));
        }
    }
    let authorized_user_id = if code_type == AuthorizationCodeType::Login
        && login_code_level == LoginCodeLevel::AccountRecovery
    {
        let username = authorized_username
            .as_deref()
            .ok_or_else(|| AppError::BadRequest("authorized_username is required".to_string()))?;
        Some(recovery_target_user_id(
            username,
            state.db.find_user_by_username(username).await?,
        )?)
    } else {
        None
    };
    // Store a separate, OAEP-encrypted display copy before hashing the code
    // for normal redemption.  The public list still receives only the prefix;
    // full-code access is an explicit, audited POST to the reveal endpoint.
    let code = format!(
        "{}-{}",
        match code_type {
            AuthorizationCodeType::Registration => "REG",
            AuthorizationCodeType::Login => "LOGIN",
        },
        util::random_token(18)
    );
    let signing_key = state
        .db
        .list_signing_keys()
        .await?
        .into_iter()
        .find(|key| key.is_active == 1)
        .ok_or_else(|| {
            AppError::Configuration(
                "an active signing key is required to create a revealable authorization code"
                    .to_string(),
            )
        })?;
    let code_reveal_ciphertext =
        util::encrypt_authorization_code_for_reveal(&signing_key.private_key_pem, &code)?;
    let (invitation, code) = state
        .db
        .insert_invitation_with_reveal_secret(
            NewInvitation {
                code_type,
                login_code_level,
                allowed_client_ids: allowed_client_ids.clone(),
                organization_id: organization_id.clone(),
                organization_role: organization_role.clone(),
                description: payload.description,
                authorized_email,
                authorized_username,
                authorized_user_id,
                authorized_display_name,
                expires_at: payload.expires_at,
                max_uses: payload.max_uses,
                is_active: payload.is_active,
                created_by: Some(current.user.id.clone()),
            },
            code,
            signing_key.kid,
            code_reveal_ciphertext,
        )
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "authorization_code.create",
            "authorization_code",
            Some(invitation.id.clone()),
            serde_json::json!({
                "code_type": code_type,
                "login_code_level": login_code_level,
                "allowed_client_ids": allowed_client_ids,
                "organization_id": invitation.organization_id.clone(),
                "organization_role": invitation.organization_role.clone(),
                "max_uses": invitation.max_uses
            }),
        ))
        .await?;
    Ok(Json(InvitationCreateResponse {
        invitation: invitation.public()?,
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
    let existing = state
        .db
        .find_invitation_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    let code_type = existing.authorization_code_type()?;
    let login_code_level = existing.login_code_level()?;
    ensure_admin_universal_manager(&current.user, code_type, login_code_level)?;
    if payload.code_type.is_some_and(|value| value != code_type)
        || payload
            .login_code_level
            .is_some_and(|value| value != login_code_level)
    {
        return Err(AppError::BadRequest(
            "authorization code type cannot be changed after creation".to_string(),
        ));
    }
    let allowed_client_ids =
        immutable_allowed_client_ids(existing.allowed_client_ids()?, payload.allowed_client_ids)?;
    let requested_organization_role = normalize_optional_text(payload.organization_role)
        .map(|value| organizations::normalize_role(&value))
        .transpose()?;
    let organization_id = if login_code_level == LoginCodeLevel::TrialEnrollment {
        immutable_optional_text(
            "organization_id",
            existing.organization_id.as_deref(),
            payload.organization_id,
        )?
    } else {
        normalize_optional_text(payload.organization_id)
    };
    let organization_role = if login_code_level == LoginCodeLevel::TrialEnrollment {
        immutable_optional_text(
            "organization_role",
            existing.organization_role.as_deref(),
            requested_organization_role,
        )?
    } else {
        requested_organization_role
    };
    let authorized_email = normalize_optional_email(payload.authorized_email)?;
    let authorized_username = if code_type == AuthorizationCodeType::Login
        && login_code_level == LoginCodeLevel::AccountRecovery
    {
        immutable_recovery_username(
            existing.authorized_username.as_deref(),
            payload.authorized_username,
        )?
    } else {
        normalize_optional_text(payload.authorized_username)
    };
    let authorized_display_name = normalize_optional_text(payload.authorized_display_name);
    validate_authorization_code_input(
        &state,
        AuthorizationCodeValidationInput {
            code_type,
            login_code_level,
            authorized_email: authorized_email.as_deref(),
            authorized_username: authorized_username.as_deref(),
            authorized_display_name: authorized_display_name.as_deref(),
            allowed_client_ids: &allowed_client_ids,
            organization_id: organization_id.as_deref(),
            organization_role: organization_role.as_deref(),
        },
    )
    .await?;
    ensure_trial_enrollment_role_manager(
        &state,
        &current.user,
        code_type,
        login_code_level,
        organization_role.as_deref(),
    )
    .await?;
    if login_code_level == LoginCodeLevel::TrialEnrollment {
        if payload
            .expires_at
            .is_none_or(|expires_at| expires_at <= util::now_ts())
        {
            return Err(AppError::BadRequest(
                "trial enrollment authorization codes require a future expires_at".to_string(),
            ));
        }
        if payload.max_uses.is_none() {
            return Err(AppError::BadRequest(
                "trial enrollment authorization codes require max_uses".to_string(),
            ));
        }
    }
    let invitation = state
        .db
        .update_invitation(InvitationUpdate {
            id: &id,
            description: payload.description,
            authorized_email,
            authorized_username,
            authorized_display_name,
            expires_at: payload.expires_at,
            max_uses: payload.max_uses,
            is_active: payload.is_active,
        })
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "authorization_code.update",
            "authorization_code",
            Some(id),
            serde_json::json!({
                "code_type": code_type,
                "login_code_level": login_code_level,
                "allowed_client_ids": allowed_client_ids,
                "organization_id": organization_id,
                "organization_role": organization_role,
                "is_active": invitation.is_active == 1
            }),
        ))
        .await?;
    Ok(Json(invitation.public()?))
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
    let (_, organization, platform_manager) =
        current_organization_provider_manager(&state, &jar).await?;
    let mut providers = Vec::new();
    for provider in state.db.list_external_oidc_providers().await? {
        if !platform_manager
            && provider.organization_id.as_deref() != Some(organization.id.as_str())
        {
            continue;
        }
        providers.push(provider.public()?);
    }
    Ok(Json(providers))
}

async fn list_external_oidc_provider_templates(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<Vec<OidcProviderTemplate>>> {
    current_organization_provider_manager(&state, &jar).await?;
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
    current_organization_provider_manager(&state, &jar).await?;
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
    #[serde(default)]
    clear_client_secret: bool,
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
    let (current, organization, platform_manager) =
        current_organization_provider_manager(&state, &jar).await?;
    let organization_id = if platform_manager {
        normalize_client_organization_id(&state, payload.organization_id.clone()).await?
    } else {
        client_organization_from_context(payload.organization_id.clone(), &organization)?
    };
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
    let (current, organization, platform_manager) =
        current_organization_provider_manager(&state, &jar).await?;
    let existing = state
        .db
        .find_external_oidc_provider_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    if !platform_manager && existing.organization_id.as_deref() != Some(organization.id.as_str()) {
        return Err(AppError::NotFound);
    }
    let organization_id = if platform_manager {
        normalize_client_organization_id(&state, payload.organization_id.clone()).await?
    } else {
        client_organization_from_context(payload.organization_id.clone(), &organization)?
    };
    let clear_client_secret = payload.clear_client_secret;
    let mut provider_input = normalize_external_provider_input(payload, organization_id.clone())?;
    apply_external_provider_secret_update(
        &mut provider_input,
        &existing.client_secret,
        clear_client_secret,
    );
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
    let (current, organization, platform_manager) =
        current_organization_provider_manager(&state, &jar).await?;
    let existing = state
        .db
        .find_external_oidc_provider_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    if !platform_manager && existing.organization_id.as_deref() != Some(organization.id.as_str()) {
        return Err(AppError::NotFound);
    }
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
    let (_, organization, platform_manager) =
        current_organization_provider_manager(&state, &jar).await?;
    let providers = state
        .db
        .list_ldap_providers()
        .await?
        .into_iter()
        .filter(|provider| {
            platform_manager
                || provider.organization_id.as_deref() == Some(organization.id.as_str())
        })
        .map(|provider| provider.public())
        .collect();
    Ok(Json(providers))
}

#[derive(Debug, Deserialize)]
struct LdapProviderInput {
    slug: String,
    display_name: String,
    #[serde(default)]
    organization_id: Option<String>,
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
    let (current, organization, platform_manager) =
        current_organization_provider_manager(&state, &jar).await?;
    let organization_id = if platform_manager {
        normalize_client_organization_id(&state, payload.organization_id.clone()).await?
    } else {
        client_organization_from_context(payload.organization_id.clone(), &organization)?
    };
    let provider_input = normalize_ldap_provider_input(payload, organization_id.clone())?;
    let provider = state.db.insert_ldap_provider(provider_input).await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "ldap_provider.create",
            "ldap_provider",
            Some(provider.id.clone()),
            serde_json::json!({
                "slug": provider.slug.clone(),
                "organization_id": organization_id,
            }),
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
    let (current, organization, platform_manager) =
        current_organization_provider_manager(&state, &jar).await?;
    let existing = state
        .db
        .find_ldap_provider_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    if !platform_manager && existing.organization_id.as_deref() != Some(organization.id.as_str()) {
        return Err(AppError::NotFound);
    }
    let organization_id = if platform_manager {
        normalize_client_organization_id(&state, payload.organization_id.clone()).await?
    } else {
        client_organization_from_context(payload.organization_id.clone(), &organization)?
    };
    if organization_id != existing.organization_id {
        return Err(AppError::BadRequest(
            "LDAP provider organization cannot be changed after creation".to_string(),
        ));
    }
    let provider_input = normalize_ldap_provider_input(payload, organization_id.clone())?;
    let provider = state.db.update_ldap_provider(&id, provider_input).await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "ldap_provider.update",
            "ldap_provider",
            Some(id),
            serde_json::json!({
                "slug": provider.slug.clone(),
                "organization_id": organization_id,
            }),
        ))
        .await?;
    Ok(Json(provider.public()))
}

async fn delete_ldap_provider(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let (current, organization, platform_manager) =
        current_organization_provider_manager(&state, &jar).await?;
    let existing = state
        .db
        .find_ldap_provider_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    if !platform_manager && existing.organization_id.as_deref() != Some(organization.id.as_str()) {
        return Err(AppError::NotFound);
    }
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

fn apply_external_provider_secret_update(
    provider: &mut NewExternalOidcProvider,
    existing_secret: &str,
    clear_secret: bool,
) {
    if clear_secret {
        provider.client_secret.clear();
    } else if provider.client_secret.is_empty() {
        provider.client_secret = existing_secret.to_string();
    }
}

fn normalize_ldap_provider_input(
    payload: LdapProviderInput,
    organization_id: Option<String>,
) -> AppResult<NewLdapProvider> {
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
        organization_id,
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
    normalize_client_logo_uri(&payload.logo_uri)?;
    let redirect_uris = normalize_redirect_uri_list(&payload.redirect_uris, "redirect_uri")?;
    let post_logout_redirect_uris = normalize_redirect_uri_list(
        &payload.post_logout_redirect_uris,
        "post_logout_redirect_uri",
    )?;
    if let Some(audience) = payload.audience.as_deref()
        && !audience.trim().is_empty()
        && audience.len() > 2048
    {
        return Err(AppError::BadRequest(
            "audience must be between 1 and 2048 characters".to_string(),
        ));
    }
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

fn normalize_client_logo_uri(value: &str) -> AppResult<String> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(String::new());
    }
    if value.len() > 2048 {
        return Err(AppError::BadRequest(
            "logo_uri must not exceed 2048 characters".to_string(),
        ));
    }
    validate_absolute_http_url(value, "logo_uri")?;
    let parsed = Url::parse(value)
        .map_err(|err| AppError::BadRequest(format!("logo_uri is invalid: {err}")))?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(AppError::BadRequest(
            "logo_uri cannot include user info".to_string(),
        ));
    }
    Ok(value.to_string())
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
    if let Some(organization_id) = public.organization_id.as_deref()
        && let Some(organization) = state.db.find_organization_by_id(organization_id).await?
    {
        public.organization_slug = Some(organization.slug);
        public.organization_name = Some(organization.name);
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
    existing_audience: Option<String>,
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
    let logo_uri = normalize_client_logo_uri(&payload.logo_uri)?;
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
        logo_uri,
        organization_id,
        redirect_uris,
        post_logout_redirect_uris,
        scopes: payload.scopes,
        audience: payload
            .audience
            .or(existing_audience)
            .unwrap_or_default()
            .trim()
            .to_string(),
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

    #[test]
    fn user_list_scope_accepts_authorization_code_accounts() {
        assert!(matches!(
            user_list_scope(Some("authorization_code")),
            Ok(UserListScope::AuthorizationCode)
        ));
    }

    #[test]
    fn bulk_csv_parser_normalizes_fields_and_rejects_duplicate_identities() {
        let batch = parse_bulk_import_csv(
            "email,username,display_name,organization_slug,organization_role,is_active\n\
             Alice@Example.com,alice,\"Alice, Example\",Corp,ADMIN,true\n\
             bob@example.com,bob,,,,0\n",
        )
        .unwrap();

        assert_eq!(batch.rows.len(), 2);
        assert_eq!(batch.rows[0].email.as_deref(), Some("alice@example.com"));
        assert_eq!(
            batch.candidates[0].organization_slug.as_deref(),
            Some("corp")
        );
        assert_eq!(
            batch.candidates[0].organization_role.as_deref(),
            Some("admin")
        );
        assert!(!batch.candidates[1].is_active);

        let mut duplicate_batch = parse_bulk_import_csv(
            "email,username,display_name,organization_slug,organization_role,is_active\n\
             first@example.com,duplicate,,,,true\n\
             second@example.com,duplicate,,,,false\n",
        )
        .unwrap();
        validate_bulk_import_duplicates(&mut duplicate_batch);
        assert_eq!(duplicate_batch.rows[0].outcome, "invalid");
        assert_eq!(duplicate_batch.rows[1].outcome, "invalid");
        assert!(
            duplicate_batch.rows[0]
                .error
                .as_deref()
                .is_some_and(|message| message.contains("username duplicates CSV row"))
        );
    }

    #[test]
    fn bulk_csv_parser_requires_exact_headers_and_boolean_status() {
        assert!(
            parse_bulk_import_csv(
                "email,username,display_name,organization_slug,organization_role\n\
             alice@example.com,alice,,,,true\n"
            )
            .is_err()
        );

        let batch = parse_bulk_import_csv(
            "\u{feff}email,username,display_name,organization_slug,organization_role,is_active\n\
             alice@example.com,alice,,,,sometimes\n",
        )
        .unwrap();
        assert_eq!(batch.rows[0].outcome, "invalid");
        assert_eq!(
            batch.rows[0].error.as_deref(),
            Some("is_active must be true or false")
        );
    }

    #[cfg(feature = "sqlite")]
    async fn bulk_import_test_state(
        permissions: &[Permission],
    ) -> (AppState, std::path::PathBuf, CookieJar) {
        let mut settings: crate::Settings =
            toml::from_str(include_str!("../../config/default.toml")).unwrap();
        let path = std::env::temp_dir().join(format!(
            "gpt-sso-admin-bulk-import-test-{}.sqlite3",
            uuid::Uuid::new_v4()
        ));
        settings.database.kind = crate::config::DatabaseKind::Sqlite;
        settings.database.url = path.to_string_lossy().into_owned();
        settings.database.run_migrations = true;
        settings.bootstrap.admin.create_on_startup = false;
        settings.bootstrap.clients.clear();
        let db = crate::db::Db::connect(&settings).unwrap();
        db.migrate().await.unwrap();
        db.seed(&settings).await.unwrap();
        let jwt = crate::jwt::JwtManager::new(&settings).unwrap();
        let state = AppState { settings, db, jwt };
        let user = state
            .db
            .insert_user(NewUser {
                email: "bulk-manager@example.com".to_string(),
                username: "bulk-manager".to_string(),
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
            .unwrap();
        if !permissions.is_empty() {
            let role = state
                .db
                .insert_role(NewRole {
                    name: format!("bulk-import-manager-{}", uuid::Uuid::new_v4()),
                    description: None,
                    is_system: false,
                    permissions: permissions
                        .iter()
                        .map(|permission| permission.as_str().to_string())
                        .collect(),
                })
                .await
                .unwrap();
            state
                .db
                .replace_user_roles(&user.id, vec![role.id])
                .await
                .unwrap();
        }
        let (_session, cookie_value) = state
            .db
            .insert_session(
                &user.id,
                state.settings.security.session_ttl_seconds,
                crate::db::SessionMetadata::default(),
            )
            .await
            .unwrap();
        let jar = CookieJar::new().add(axum_extra::extract::cookie::Cookie::new(
            state.settings.security.cookie_name.clone(),
            cookie_value,
        ));
        (state, path, jar)
    }

    #[cfg(feature = "sqlite")]
    async fn bulk_import_body(response: Response) -> serde_json::Value {
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn bulk_import_dry_run_is_insert_only_and_records_row_results() {
        let (state, path, jar) =
            bulk_import_test_state(&[Permission::UsersManage, Permission::OrganizationsManage])
                .await;
        let organization = state
            .db
            .insert_organization(NewOrganization {
                slug: "corp".to_string(),
                name: "Corp".to_string(),
                kind: crate::organizations::ORGANIZATION_KIND_TENANT.to_string(),
                description: None,
                allowed_email_domains: vec!["example.com".to_string()],
                is_active: true,
            })
            .await
            .unwrap();

        let response = import_users_csv(
            State(state.clone()),
            jar,
            Query(BulkImportQuery { dry_run: true }),
            "email,username,display_name,organization_slug,organization_role,is_active\n\
             alice@example.com,alice,Alice,corp,member,true\n"
                .to_string(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = bulk_import_body(response).await;
        assert_eq!(body["dry_run"], true);
        assert_eq!(body["committed"], false);
        assert_eq!(body["summary"]["would_create"], 1);
        assert_eq!(body["rows"][0]["outcome"], "would_create");
        assert!(
            state
                .db
                .find_user_by_email("alice@example.com")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            state
                .db
                .list_organization_members(&organization.id)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            state
                .db
                .list_audit_events(10)
                .await
                .unwrap()
                .iter()
                .any(|event| event.action == "user.bulk_import.dry_run")
        );

        drop(state);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn bulk_import_requires_organization_manage_for_organization_roles() {
        let (state, path, jar) = bulk_import_test_state(&[Permission::UsersManage]).await;
        let result = import_users_csv(
            State(state.clone()),
            jar,
            Query(BulkImportQuery { dry_run: true }),
            "email,username,display_name,organization_slug,organization_role,is_active\n\
             alice@example.com,alice,Alice,corp,owner,true\n"
                .to_string(),
        )
        .await;
        assert!(matches!(result, Err(AppError::Forbidden)));
        assert!(
            state
                .db
                .find_user_by_email("alice@example.com")
                .await
                .unwrap()
                .is_none()
        );

        drop(state);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn enterprise_resource_inputs_cannot_override_selected_context() {
        let organization = UserOrganizationRecord {
            id: "selected-organization".to_string(),
            slug: "selected".to_string(),
            name: "Selected".to_string(),
            kind: organizations::ORGANIZATION_KIND_TENANT.to_string(),
            description: None,
            is_active: 1,
            role: organizations::ROLE_ADMIN.to_string(),
            membership_created_at: 1,
            membership_updated_at: 1,
        };

        assert_eq!(
            client_organization_from_context(None, &organization).unwrap(),
            Some(organization.id.clone())
        );
        assert_eq!(
            client_organization_from_context(Some(organization.id.clone()), &organization).unwrap(),
            Some(organization.id.clone())
        );
        assert!(matches!(
            client_organization_from_context(Some("other-organization".to_string()), &organization,),
            Err(AppError::Forbidden)
        ));
        assert!(matches!(
            client_organization_from_context(
                Some("  other-organization  ".to_string()),
                &organization,
            ),
            Err(AppError::Forbidden)
        ));
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn bulk_import_commits_roles_atomically_and_rejects_existing_identities() {
        let (state, path, jar) =
            bulk_import_test_state(&[Permission::UsersManage, Permission::OrganizationsManage])
                .await;
        let organization = state
            .db
            .insert_organization(NewOrganization {
                slug: "corp".to_string(),
                name: "Corp".to_string(),
                kind: crate::organizations::ORGANIZATION_KIND_TENANT.to_string(),
                description: None,
                allowed_email_domains: Vec::new(),
                is_active: true,
            })
            .await
            .unwrap();
        let existing = state
            .db
            .insert_user(NewUser {
                email: "existing@example.com".to_string(),
                username: "existing".to_string(),
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
            .unwrap();
        let invalid_response = import_users_csv(
            State(state.clone()),
            jar.clone(),
            Query(BulkImportQuery { dry_run: false }),
            "email,username,display_name,organization_slug,organization_role,is_active\n\
             new@example.com,new,New,corp,member,true\n\
             existing@example.com,different,Existing,corp,admin,true\n"
                .to_string(),
        )
        .await
        .unwrap();
        assert_eq!(invalid_response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let invalid_body = bulk_import_body(invalid_response).await;
        assert_eq!(invalid_body["summary"]["invalid"], 1);
        assert_eq!(invalid_body["summary"]["not_committed"], 1);
        assert!(
            state
                .db
                .find_user_by_email("new@example.com")
                .await
                .unwrap()
                .is_none()
        );

        let success_response = import_users_csv(
            State(state.clone()),
            jar,
            Query(BulkImportQuery { dry_run: false }),
            "email,username,display_name,organization_slug,organization_role,is_active\n\
             owner@example.com,owner,Owner,corp,owner,true\n\
             member@example.com,member,Member,corp,member,false\n"
                .to_string(),
        )
        .await
        .unwrap();
        assert_eq!(success_response.status(), StatusCode::OK);
        let success_body = bulk_import_body(success_response).await;
        assert_eq!(success_body["committed"], true);
        assert_eq!(success_body["summary"]["created"], 2);
        let memberships = state
            .db
            .list_organization_members(&organization.id)
            .await
            .unwrap();
        assert!(memberships.iter().any(|membership| {
            membership.email == "owner@example.com" && membership.role == organizations::ROLE_OWNER
        }));
        assert!(memberships.iter().any(|membership| {
            membership.email == "member@example.com"
                && membership.role == organizations::ROLE_MEMBER
                && membership.is_active == 0
        }));
        let existing_after = state
            .db
            .find_user_by_email("existing@example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(existing_after.id, existing.id);

        drop(state);
        let _ = std::fs::remove_file(path);
    }

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
            registration_source: "local".to_string(),
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

    #[test]
    fn admin_universal_code_creation_and_updates_require_a_true_administrator() {
        let delegated_manager = user(None);
        assert!(matches!(
            ensure_admin_universal_manager(
                &delegated_manager,
                AuthorizationCodeType::Login,
                LoginCodeLevel::AdminUniversal,
            ),
            Err(AppError::Forbidden)
        ));
        assert!(
            ensure_admin_universal_manager(
                &delegated_manager,
                AuthorizationCodeType::Login,
                LoginCodeLevel::AccountRecovery,
            )
            .is_ok()
        );

        let mut administrator = delegated_manager;
        administrator.is_admin = 1;
        assert!(
            ensure_admin_universal_manager(
                &administrator,
                AuthorizationCodeType::Login,
                LoginCodeLevel::AdminUniversal,
            )
            .is_ok()
        );
    }

    #[test]
    fn account_recovery_target_must_be_an_exact_active_existing_user() {
        assert!(matches!(
            recovery_target_user_id("user", None),
            Err(AppError::BadRequest(message))
                if message.contains("existing account")
        ));

        let mut case_mismatch = user(None);
        case_mismatch.username = "User".to_string();
        assert!(matches!(
            recovery_target_user_id("user", Some(case_mismatch)),
            Err(AppError::BadRequest(message))
                if message.contains("exactly match")
        ));

        let mut disabled = user(None);
        disabled.is_active = 0;
        assert!(matches!(
            recovery_target_user_id("user", Some(disabled)),
            Err(AppError::BadRequest(message))
                if message.contains("active account")
        ));
        assert!(matches!(
            recovery_target_user_id("user", Some(user(Some(1)))),
            Err(AppError::BadRequest(message))
                if message.contains("active account")
        ));
        assert_eq!(
            recovery_target_user_id("user", Some(user(None))).unwrap(),
            "user-id"
        );
    }

    #[test]
    fn admin_universal_codes_reject_account_binding_metadata() {
        assert!(matches!(
            validate_login_code_binding_metadata(
                LoginCodeLevel::AdminUniversal,
                None,
                Some("user"),
                None,
            ),
            Err(AppError::BadRequest(message))
                if message.contains("cannot set account binding metadata")
        ));
        assert!(
            validate_login_code_binding_metadata(LoginCodeLevel::AdminUniversal, None, None, None,)
                .is_ok()
        );
    }

    #[test]
    fn all_login_codes_reject_unused_email_and_display_name_metadata() {
        for level in [
            LoginCodeLevel::AccountRecovery,
            LoginCodeLevel::AdminUniversal,
            LoginCodeLevel::TrialEnrollment,
        ] {
            for (email, display_name) in [(Some("user@example.com"), None), (None, Some("User"))] {
                assert!(matches!(
                    validate_login_code_binding_metadata(
                        level,
                        email,
                        (level == LoginCodeLevel::AccountRecovery).then_some("user"),
                        display_name,
                    ),
                    Err(AppError::BadRequest(message))
                        if message.contains("cannot set email or display-name metadata")
                ));
            }
        }
        assert!(
            validate_login_code_binding_metadata(
                LoginCodeLevel::AccountRecovery,
                None,
                Some("user"),
                None,
            )
            .is_ok()
        );
        assert!(matches!(
            validate_login_code_binding_metadata(
                LoginCodeLevel::TrialEnrollment,
                None,
                Some("user"),
                None,
            ),
            Err(AppError::BadRequest(message)) if message.contains("cannot set account binding metadata")
        ));
    }

    #[test]
    fn authorization_code_client_allowlist_is_immutable() {
        let existing = vec!["client-b".to_string(), "client-a".to_string()];
        assert_eq!(
            immutable_allowed_client_ids(existing.clone(), None).unwrap(),
            vec!["client-a".to_string(), "client-b".to_string()]
        );
        assert!(
            immutable_allowed_client_ids(
                existing.clone(),
                Some(vec![
                    " client-a ".to_string(),
                    "client-b".to_string(),
                    "client-a".to_string(),
                ]),
            )
            .is_ok()
        );
        assert!(matches!(
            immutable_allowed_client_ids(existing, Some(vec!["client-c".to_string()])),
            Err(AppError::BadRequest(message))
                if message == "allowed_client_ids cannot be changed after creation"
        ));
    }

    #[test]
    fn account_recovery_username_is_immutable_and_missing_put_field_is_preserved() {
        assert_eq!(
            immutable_recovery_username(Some("recovery-user"), None).unwrap(),
            Some("recovery-user".to_string())
        );
        assert_eq!(
            immutable_recovery_username(
                Some("recovery-user"),
                Some(" recovery-user ".to_string()),
            )
            .unwrap(),
            Some("recovery-user".to_string())
        );
        assert!(matches!(
            immutable_recovery_username(
                Some("recovery-user"),
                Some("different-user".to_string()),
            ),
            Err(AppError::BadRequest(message)) if message.contains("cannot be changed")
        ));
        assert!(matches!(
            immutable_recovery_username(Some("recovery-user"), Some(" ".to_string())),
            Err(AppError::BadRequest(message)) if message.contains("cannot be cleared")
        ));
    }

    fn external_provider_input() -> ExternalOidcProviderInput {
        ExternalOidcProviderInput {
            slug: "Corp_OIDC".to_string(),
            display_name: " Corp OIDC ".to_string(),
            organization_id: None,
            issuer: "https://idp.example.com/".to_string(),
            client_id: " client ".to_string(),
            client_secret: " secret ".to_string(),
            clear_client_secret: false,
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
            organization_id: None,
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
    fn external_provider_update_preserves_or_explicitly_clears_secret() {
        let mut payload = external_provider_input();
        payload.client_secret = " ".to_string();
        let mut provider = normalize_external_provider_input(payload, None).unwrap();
        apply_external_provider_secret_update(&mut provider, "stored-secret", false);
        assert_eq!(provider.client_secret, "stored-secret");

        apply_external_provider_secret_update(&mut provider, "stored-secret", true);
        assert!(provider.client_secret.is_empty());

        let mut provider =
            normalize_external_provider_input(external_provider_input(), None).unwrap();
        apply_external_provider_secret_update(&mut provider, "stored-secret", false);
        assert_eq!(provider.client_secret, "secret");
    }

    #[test]
    fn organization_options_do_not_grant_full_member_read_access() {
        for permission in [
            Permission::ClientsManage,
            Permission::IapRead,
            Permission::IapManage,
            Permission::ProvidersManage,
        ] {
            assert!(ORGANIZATION_OPTION_PERMISSIONS.contains(&permission));
            assert!(!ORGANIZATION_READ_PERMISSIONS.contains(&permission));
        }
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
        let provider = normalize_ldap_provider_input(ldap_provider_input(), None).unwrap();

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
            normalize_ldap_provider_input(provider, None),
            Err(AppError::BadRequest(_))
        ));

        let mut provider = ldap_provider_input();
        provider.user_filter = "(objectClass=person)".to_string();
        assert!(matches!(
            normalize_ldap_provider_input(provider, None),
            Err(AppError::BadRequest(_))
        ));

        let mut provider = ldap_provider_input();
        provider.email_attribute = "mail)(uid=*".to_string();
        assert!(matches!(
            normalize_ldap_provider_input(provider, None),
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

        let provider = normalize_ldap_provider_input(provider, None).unwrap();
        assert_eq!(provider.url, "");
        assert!(provider.user_filter.contains("{login}"));
    }

    fn client_input() -> ClientInput {
        ClientInput {
            client_id: "demo-web".to_string(),
            client_name: "Demo Web".to_string(),
            logo_uri: String::new(),
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
            audience: None,
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

        let client = client_input_to_new(input, None, None, None).unwrap();
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
    fn client_logo_uri_is_normalized_and_rejects_unsafe_urls() {
        let mut input = client_input();
        input.logo_uri = " https://assets.example.com/signet.svg ".to_string();
        validate_client_input(&input).unwrap();
        let client = client_input_to_new(input, None, None, None).unwrap();
        assert_eq!(client.logo_uri, "https://assets.example.com/signet.svg");

        for logo_uri in [
            "javascript:alert(1)",
            "https://user:secret@assets.example.com/logo.svg",
            "https://assets.example.com/logo.svg#fragment",
        ] {
            let mut input = client_input();
            input.logo_uri = logo_uri.to_string();
            assert!(matches!(
                validate_client_input(&input),
                Err(AppError::BadRequest(_))
            ));
        }
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
        assert!(links[0].icon.is_empty());
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

    #[test]
    fn brand_logo_url_allows_blank_and_rejects_unsafe_urls() {
        assert_eq!(normalize_brand_logo_url("  ".to_string()).unwrap(), "");
        assert_eq!(
            normalize_brand_logo_url(" https://cdn.example.com/signet.svg ".to_string()).unwrap(),
            "https://cdn.example.com/signet.svg"
        );
        assert!(matches!(
            normalize_brand_logo_url("javascript:alert(1)".to_string()),
            Err(AppError::BadRequest(_))
        ));
        assert!(matches!(
            normalize_brand_logo_url("/signet.svg".to_string()),
            Err(AppError::BadRequest(_))
        ));
        assert!(matches!(
            normalize_brand_logo_url(format!("https://cdn.example.com/{}", "a".repeat(2048))),
            Err(AppError::BadRequest(_))
        ));
    }

    #[test]
    fn login_settings_input_preserves_compatibility_with_clients_without_brand_logo_url() {
        let input: LoginSettingsInput = serde_json::from_value(serde_json::json!({
            "email_domains": [],
            "quick_links": []
        }))
        .unwrap();

        assert!(input.brand_logo_url.is_none());
    }
}
