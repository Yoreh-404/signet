use crate::{
    AppState,
    access::{Authorizer, Permission, PermissionInfo, permission_catalog},
    application_discovery, applications, archived_accounts,
    audit::{self, AuditSink},
    auth, auth_flow, authorization, backchannel_logout, billing, client_assertion, csrf,
    db::{
        ApplicationAuthorizationProfileRecord, ApplicationDiscoveryRecord,
        ApplicationJwtClientRecord, ApplicationModuleRecord, ApplicationPermissionDefinitionRecord,
        ApplicationProfileRoleRecord, ApplicationRecord, ApplicationScimTokenRecord,
        AuditEventRecord, AuthorizationBindingPermissionOverride, AuthorizationBindingsSnapshot,
        AuthorizationBindingsUpdate, AuthorizationCodeType, ClientGrantWithClientRecord,
        GroupRecord, InvitationRecord, InvitationUpdate, LoginCodeLevel, NewApplication,
        NewApplicationBillingSettings, NewApplicationDiscovery, NewApplicationJwtClient,
        NewApplicationProfileRole, NewApplicationScimToken, NewGroup, NewIapApplication,
        NewInvitation, NewOrganization, NewRole, NewUser, OrganizationMemberInput,
        OrganizationMemberWithUserRecord, OrganizationRecord, PublicAuditWebhook, PublicClient,
        PublicClientClaimMapper, PublicIapApplication, PublicInvitation,
        PublicInvitationRedemption, PublicUser, RoleRecord, SessionRecord, UserListScope,
        UserOrganizationRecord, UserUpdate,
    },
    directory, directory_sync,
    error::{AppError, AppResult},
    frontchannel_logout, iap,
    mfa::{self, RecoveryCodeIssuer},
    mfa_policy::MfaDecision,
    mutations,
    network_policy::TrustedNetworkPolicy,
    organizations::{self, OrganizationEmailPolicy},
    security_policy, util, webhooks,
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

#[path = "admin_settings.rs"]
mod admin_settings;
use admin_settings::{normalize_optional_email, normalize_optional_text};
#[path = "admin_user_import.rs"]
mod admin_user_import;
use admin_user_import::normalize_user_input;
#[path = "admin_client_policy.rs"]
mod admin_client_policy;
#[path = "admin_guards.rs"]
mod admin_guards;
#[path = "admin_providers.rs"]
mod admin_providers;
use admin_client_policy::{
    client_input_to_claim_mappers, client_input_to_new, validate_client_input,
};
use admin_guards::{require_any_permission, require_permission};
#[path = "admin_organization_scope.rs"]
mod admin_organization_scope;
use admin_organization_scope::{client_organization_from_context, current_organization_context};
#[path = "admin_authorization_code_policy.rs"]
mod admin_authorization_code_policy;
use admin_authorization_code_policy::{
    AuthorizationCodeValidationInput, ensure_admin_universal_manager, immutable_allowed_client_ids,
    immutable_optional_text, immutable_recovery_username, normalized_client_ids,
    recovery_target_user_id, validate_active_allowed_clients, validate_login_code_binding_metadata,
};
#[path = "admin_user_directory.rs"]
mod admin_user_directory;
#[path = "admin_user_query.rs"]
mod admin_user_query;
#[cfg(test)]
use crate::db::{UserListLinkedIdentityFilter, UserListRoleFilter};
#[cfg(test)]
use admin_user_query::USER_DIRECTORY_DEFAULT_PAGE_SIZE;
#[cfg(test)]
use admin_user_query::{UserListQuery, parse_user_list_query, user_list_scope};

fn default_true() -> bool {
    true
}

#[cfg(test)]
use crate::db::QuickLink;
#[cfg(test)]
use crate::subject;
#[cfg(test)]
use admin_providers::{
    ExternalOidcProviderInput, LdapProviderInput, apply_external_provider_secret_update,
    normalize_external_provider_input, normalize_ldap_provider_input,
};
#[cfg(test)]
use admin_settings::{normalize_brand_logo_url, normalize_email_domains, normalize_quick_links};
#[cfg(test)]
use admin_user_import::{BulkImportQuery, parse_bulk_import_csv};
#[cfg(test)]
use axum::{http::StatusCode, response::Response};

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
        .route("/api/admin/settings", get(admin_settings::settings_summary))
        .route(
            "/api/admin/registration-settings",
            get(admin_settings::get_registration_settings)
                .put(admin_settings::update_registration_settings),
        )
        .route(
            "/api/admin/runtime-settings",
            get(admin_settings::get_runtime_settings).put(admin_settings::update_runtime_settings),
        )
        .route(
            "/api/admin/login-settings",
            get(admin_settings::get_login_settings).put(admin_settings::update_login_settings),
        )
        .route(
            "/api/admin/security-policy",
            get(admin_settings::get_security_policy).put(admin_settings::update_security_policy),
        )
        .route(
            "/api/admin/signing-keys",
            get(admin_settings::list_signing_keys).post(admin_settings::rotate_signing_key),
        )
        .route(
            "/api/admin/users",
            get(admin_user_directory::list_users).post(create_user),
        )
        .route(
            "/api/admin/users/page",
            get(admin_user_directory::list_users),
        )
        .route(
            "/api/admin/users/cursor",
            get(admin_user_directory::list_users_cursor),
        )
        .route(
            "/api/admin/user-options",
            get(admin_user_directory::list_user_options),
        )
        .route(
            "/api/admin/users/import-csv",
            post(admin_user_import::import_users_csv),
        )
        .route("/api/admin/users/bulk-lifecycle", post(bulk_user_lifecycle))
        .route(
            "/api/admin/users/{id}",
            get(admin_user_directory::user_detail)
                .put(update_user)
                .delete(delete_user),
        )
        .route("/api/admin/users/{id}/enable", post(enable_user))
        .route("/api/admin/users/{id}/password", post(set_user_password))
        .route("/api/admin/users/{id}/mfa/reset", post(reset_user_mfa))
        .route(
            "/api/admin/users/{id}/login-events",
            get(admin_user_directory::user_login_events),
        )
        .route(
            "/api/admin/users/{id}/permissions",
            get(admin_user_directory::user_permissions),
        )
        .route("/api/admin/clients", get(list_clients))
        .route(
            "/api/admin/applications",
            get(list_applications).post(create_application),
        )
        .route(
            "/api/admin/applications/{id}",
            put(update_application).delete(delete_application),
        )
        .route(
            "/api/admin/applications/{id}/discovery",
            get(get_application_discovery).put(update_application_discovery),
        )
        .route(
            "/api/admin/applications/{id}/discovery/sync",
            post(sync_application_discovery),
        )
        .route(
            "/api/admin/applications/{id}/client-bindings",
            get(list_application_client_bindings),
        )
        .route(
            "/api/admin/application-discovery/discover",
            post(discover_application),
        )
        .route(
            "/api/admin/applications/{id}/oidc-clients",
            get(list_application_oidc_clients).post(create_application_oidc_client),
        )
        .route(
            "/api/admin/applications/{id}/oidc-clients/{client_id}",
            put(update_application_oidc_client).delete(delete_application_oidc_client),
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
            "/api/admin/applications/{id}/billing-settings",
            get(get_application_billing_settings).put(update_application_billing_settings),
        )
        .route(
            "/api/admin/applications/{id}/iap-rules",
            get(list_application_iap_rules).post(create_application_iap_rule),
        )
        .route(
            "/api/admin/applications/{id}/iap-rules/{rule_id}",
            put(update_application_iap_rule).delete(delete_application_iap_rule),
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
            "/api/admin/applications/{id}/authorization/catalog",
            get(application_permission_catalog),
        )
        .route(
            "/api/admin/applications/{id}/authorization/profiles",
            get(list_application_authorization_profiles),
        )
        .route(
            "/api/admin/applications/{id}/authorization/profiles/{profile_id}",
            get(get_application_authorization_profile),
        )
        .route(
            "/api/admin/applications/{id}/authorization/profiles/{profile_id}/catalog",
            get(application_profile_permission_catalog),
        )
        .route(
            "/api/admin/applications/{id}/authorization/profiles/{profile_id}/bindings",
            get(get_application_authorization_bindings)
                .put(update_application_authorization_bindings),
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
            "/api/admin/applications/{id}/authorization/profiles/{profile_id}/{user_id}",
            get(application_profile_authorization_preview),
        )
        .route(
            "/api/admin/applications/{id}/authorization/subjects",
            get(application_authorization_subjects),
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
        .route("/api/admin/iap-applications", get(list_iap_applications))
        .route("/api/admin/audit-events", get(list_audit_events))
        .route("/api/admin/mutations/{id}", get(get_mutation_receipt))
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
            get(admin_providers::list_external_oidc_providers)
                .post(admin_providers::create_external_oidc_provider),
        )
        .route(
            "/api/admin/external-oidc-provider-templates",
            get(admin_providers::list_external_oidc_provider_templates),
        )
        .route(
            "/api/admin/external-oidc-provider-discovery",
            post(admin_providers::discover_external_oidc_provider),
        )
        .route(
            "/api/admin/external-oidc-providers/{id}",
            put(admin_providers::update_external_oidc_provider)
                .delete(admin_providers::delete_external_oidc_provider),
        )
        .route(
            "/api/admin/ldap-providers",
            get(admin_providers::list_ldap_providers).post(admin_providers::create_ldap_provider),
        )
        .route(
            "/api/admin/ldap-providers/{id}",
            put(admin_providers::update_ldap_provider)
                .delete(admin_providers::delete_ldap_provider),
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
    let login_context = crate::oidc::authorization_login_context_from_return_to(
        &state,
        &headers,
        payload.return_to.as_deref(),
    )
    .await?;
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
        local_password_allowed
            && candidate.is_active == 1
            && candidate.archived_at.is_none()
            && util::verify_password(&candidate.password_hash, &payload.password)
    });
    if user.is_none() {
        let directory_login =
            match directory::authenticate_with_configured_directories_for_application(
                &state,
                &subject,
                &payload.password,
                login_context.application.as_ref(),
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
    let encrypted_secret = mfa::protect_totp_secret(&state, &secret)?;
    let setup = state
        .db
        .create_mfa_totp_setup(
            &current.user.id,
            encrypted_secret,
            mfa::MFA_SETUP_TTL_SECONDS,
        )
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
    let secret = mfa::reveal_totp_secret(&state, &setup.secret)?;
    if !mfa::verify_setup_code(&secret, &payload.code)? {
        return Err(AppError::Unauthorized);
    }
    let codes = mfa::StandardRecoveryCodeIssuer.issue_recovery_codes(mfa::RECOVERY_CODE_COUNT)?;
    state
        .db
        .confirm_totp_setup_with_audit(
            &current.user.id,
            &payload.setup_id,
            mfa::code_hashes(&codes),
            audit::management_event(
                current.user.id.clone(),
                "mfa.totp.enable",
                "user",
                Some(current.user.id.clone()),
                serde_json::json!({ "method": "totp" }),
            ),
        )
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
    let codes = mfa::StandardRecoveryCodeIssuer.issue_recovery_codes(mfa::RECOVERY_CODE_COUNT)?;
    state
        .db
        .replace_recovery_codes_with_audit(
            &current.user.id,
            mfa::code_hashes(&codes),
            audit::management_event(
                current.user.id.clone(),
                "mfa.recovery_codes.rotate",
                "user",
                Some(current.user.id.clone()),
                serde_json::json!({ "count": codes.len() }),
            ),
        )
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
    state
        .db
        .delete_mfa_for_user_with_audit(
            &current.user.id,
            audit::management_event(
                current.user.id.clone(),
                "mfa.disable",
                "user",
                Some(current.user.id.clone()),
                serde_json::json!({}),
            ),
        )
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
    let organization_input = NewOrganization {
        slug: organizations::normalize_slug(&payload.slug)?,
        name: organizations::normalize_name(&payload.name)?,
        kind: organizations::ORGANIZATION_KIND_TENANT.to_string(),
        description: normalize_optional_text(payload.description),
        allowed_email_domains: security_policy::normalize_email_domain_rules(
            payload.allowed_email_domains,
        )?,
        is_active: true,
    };
    let organization = state
        .db
        .create_organization_with_owner_and_audit(
            organization_input.clone(),
            &current.user.id,
            audit::management_event(
                current.user.id.clone(),
                "organization.self_service_create",
                "organization",
                None,
                serde_json::json!({ "slug": organization_input.slug, "name": organization_input.name }),
            ),
        )
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

impl From<ClientGrantWithClientRecord> for MyConsentResponse {
    fn from(record: ClientGrantWithClientRecord) -> Self {
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
        .list_active_client_grants(&current.user.id)
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
        .list_active_client_grants(&current.user.id)
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
        .revoke_client_grant(&current.user.id, &client_id)
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
    let (users, active_users, clients, active_clients) = tokio::try_join!(
        state.db.count_users(UserListScope::All),
        state.db.count_users(UserListScope::Active),
        state.db.count_clients(false),
        state.db.count_clients(true),
    )?;
    Ok(Json(OverviewResponse {
        active_users: active_users as usize,
        users: users as usize,
        active_clients: active_clients as usize,
        clients: clients as usize,
        issuer: state.effective_issuer(&headers).await?,
        database_kind: format!("{:?}", state.settings.database.kind).to_ascii_lowercase(),
    }))
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

async fn get_mutation_receipt(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Json<mutations::PublicMutationReceipt>> {
    auth::require_current_user(&state, &jar).await?;
    let scope_key = mutations::scope_key(&headers, &state.settings.security.cookie_name);
    let receipt = state
        .db
        .find_mutation_receipt(&id, &scope_key)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(receipt.into()))
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

#[derive(Debug, Deserialize)]
struct UserLifecycleBatchInput {
    action: String,
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
    Permission::SecurityManage,
];
const CLIENT_READ_PERMISSIONS: &[Permission] =
    &[Permission::ClientsRead, Permission::ClientsManage];
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

/// Global user reads require an explicit user-directory permission. An
/// organization owner/admin may use the directory only with an organization
/// boundary; `organizations.manage` is never treated as global `users.read`.
async fn require_user_list_reader(
    state: &AppState,
    jar: &CookieJar,
    organization_id: Option<&str>,
) -> AppResult<auth::CurrentUser> {
    let current = auth::require_current_user(state, jar).await?;
    auth::ensure_current_account_mutable(&current)?;
    if state
        .db
        .has_any_permission(&current.user, USER_READ_PERMISSIONS)
        .await?
    {
        return Ok(current);
    }
    let Some(organization_id) = organization_id else {
        return Err(AppError::Forbidden);
    };
    require_organization_manager_for(state, &current, organization_id).await?;
    Ok(current)
}

async fn require_user_manager(state: &AppState, jar: &CookieJar) -> AppResult<auth::CurrentUser> {
    require_permission(state, jar, Permission::UsersManage).await
}

async fn require_iap_reader(state: &AppState, jar: &CookieJar) -> AppResult<auth::CurrentUser> {
    require_any_permission(state, jar, IAP_READ_PERMISSIONS).await
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
    let mut email_selectors = Vec::new();
    for member in &input.members {
        if member
            .user_id
            .as_deref()
            .unwrap_or_default()
            .trim()
            .is_empty()
            && let Some(email) = member
                .email
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
        {
            email_selectors.push(email.to_string());
        }
    }
    let user_ids_by_email = state.db.find_user_ids_by_emails(&email_selectors).await?;
    let mut members = Vec::with_capacity(input.members.len());
    for member in input.members {
        let user_id = member.user_id.unwrap_or_default().trim().to_string();
        let email = member.email.unwrap_or_default().trim().to_string();
        let user_id = match (user_id.is_empty(), email.is_empty()) {
            (false, true) => user_id,
            (true, false) => user_ids_by_email.get(&email).cloned().ok_or_else(|| {
                AppError::BadRequest("no account found for member email".to_string())
            })?,
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
    let (roles, permissions_by_role) = tokio::try_join!(
        state.db.list_roles(),
        state.db.list_role_permissions_by_role(),
    )?;
    let mut response = Vec::with_capacity(roles.len());
    for role in roles {
        response.push(RoleAccessResponse {
            permissions: permissions_by_role
                .get(&role.id)
                .cloned()
                .unwrap_or_default(),
            id: role.id,
            name: role.name,
            description: role.description,
            is_system: role.is_system,
            created_at: role.created_at,
            updated_at: role.updated_at,
        });
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
    let (groups, roles_by_group, members_by_group) = tokio::try_join!(
        state.db.list_groups(),
        state.db.list_group_roles_by_group(),
        state.db.list_group_members_public_by_group(),
    )?;
    let mut response = Vec::with_capacity(groups.len());
    for group in groups {
        response.push(GroupAccessResponse {
            roles: roles_by_group.get(&group.id).cloned().unwrap_or_default(),
            members: members_by_group.get(&group.id).cloned().unwrap_or_default(),
            id: group.id,
            name: group.name,
            description: group.description,
            created_at: group.created_at,
            updated_at: group.updated_at,
        });
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
        .insert_group_with_audit(
            NewGroup {
                name: payload.name,
                description: payload.description,
            },
            audit::management_event(
                current.user.id,
                "group.create",
                "group",
                None,
                serde_json::json!({}),
            ),
        )
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
        .update_group_with_audit(
            &id,
            NewGroup {
                name: payload.name,
                description: payload.description,
            },
            audit::management_event(
                current.user.id,
                "group.update",
                "group",
                Some(id.clone()),
                serde_json::json!({}),
            ),
        )
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
    state
        .db
        .delete_group_with_audit(
            &id,
            audit::management_event(
                current.user.id,
                "group.delete",
                "group",
                Some(id.clone()),
                serde_json::json!({ "name": group.name }),
            ),
        )
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
        .replace_group_roles_with_audit(
            &id,
            payload.role_ids.clone(),
            audit::management_event(
                current.user.id,
                "group.roles.update",
                "group",
                Some(id.clone()),
                serde_json::json!({ "role_ids": payload.role_ids }),
            ),
        )
        .await?;
    let group = state
        .db
        .find_group_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
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
        .replace_group_members_with_audit(
            &id,
            payload.user_ids.clone(),
            audit::management_event(
                current.user.id,
                "group.members.update",
                "group",
                Some(id.clone()),
                serde_json::json!({ "user_ids": payload.user_ids }),
            ),
        )
        .await?;
    let group = state
        .db
        .find_group_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(group_response(&state, group).await?))
}

async fn list_organizations(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<Vec<OrganizationResponse>>> {
    require_organization_reader(&state, &jar).await?;
    let (member_counts, organizations) = tokio::try_join!(
        state.db.list_organization_member_counts(),
        state.db.list_organizations(),
    )?;
    let mut response = Vec::new();
    for organization in organizations {
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
    let organization_input = organization_input_to_new(payload)?;
    let organization = state
        .db
        .insert_organization_with_audit(
            organization_input.clone(),
            audit::management_event(
                current.user.id,
                "organization.create",
                "organization",
                None,
                serde_json::json!({
                    "slug": organization_input.slug,
                    "name": organization_input.name
                }),
            ),
        )
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
    let organization_input = organization_input_to_new(payload)?;
    let organization = state
        .db
        .update_organization_with_audit(
            &id,
            organization_input.clone(),
            audit::management_event(
                current.user.id,
                "organization.update",
                "organization",
                Some(id.clone()),
                serde_json::json!({
                    "slug": organization_input.slug,
                    "name": organization_input.name
                }),
            ),
        )
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
    state
        .db
        .delete_organization_with_audit(
            &id,
            audit::management_event(
                current.user.id,
                "organization.delete",
                "organization",
                Some(id.clone()),
                serde_json::json!({ "slug": organization.slug, "name": organization.name }),
            ),
        )
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
    // Resolve email selectors only after the organization boundary and
    // manager permission have been established. This prevents an unauthorized
    // caller from using "unknown member email" as an account-existence oracle.
    let members = organization_members_input(&state, payload).await?;
    ensure_organization_members_editable(&state, &id, &members).await?;
    state
        .db
        .replace_organization_members_with_audit(
            &id,
            members.clone(),
            audit::management_event(
                current.user.id,
                "organization.members.update",
                "organization",
                Some(id.clone()),
                serde_json::json!({
                    "members": members
                        .iter()
                        .map(|member| serde_json::json!({
                            "user_id": member.user_id,
                            "role": member.role
                        }))
                        .collect::<Vec<_>>()
                }),
            ),
        )
        .await?;
    let organization = state
        .db
        .find_organization_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
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
    Ok(Json(load_user_access_response(&state, &id).await?))
}

async fn load_user_access_response(
    state: &AppState,
    user_id: &str,
) -> AppResult<UserAccessResponse> {
    let (direct_roles, groups, effective_permissions) = tokio::try_join!(
        state.db.list_user_roles(user_id),
        state.db.list_user_groups(user_id),
        state.db.list_effective_permissions(user_id),
    )?;
    Ok(UserAccessResponse {
        direct_roles,
        groups,
        effective_permissions,
    })
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
    Ok(Json(load_user_access_response(&state, &id).await?))
}

#[derive(Debug, Deserialize)]
pub(super) struct UserInput {
    email: String,
    username: String,
    display_name: Option<String>,
    phone: Option<String>,
    password: Option<String>,
    is_admin: bool,
    is_active: bool,
}

pub(super) fn normalize_required_text(value: String, field: &str) -> AppResult<String> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(AppError::BadRequest(format!("{field} cannot be empty")));
    }
    Ok(value)
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
    security_policy::validate_password_for_subject(
        &state,
        password,
        &payload.email,
        &payload.username,
    )
    .await?;
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
        security_policy::validate_password_for_subject(
            &state,
            password,
            &payload.email,
            &payload.username,
        )
        .await?;
    }
    let password_hash = payload
        .password
        .as_deref()
        .map(util::hash_password)
        .transpose()?;
    let user_update = UserUpdate {
        id: &id,
        email: payload.email,
        username: payload.username,
        display_name: payload.display_name,
        phone: payload.phone,
        is_admin: payload.is_admin,
        is_active: payload.is_active,
    };
    let updated_email = user_update.email.clone();
    let user = if let Some(password_hash) = password_hash {
        state
            .db
            .update_user_with_password_and_audit(
                user_update,
                password_hash,
                audit::management_event(
                    current.user.id.clone(),
                    "user.update",
                    "user",
                    Some(id.clone()),
                    serde_json::json!({ "email": updated_email }),
                ),
            )
            .await?
    } else {
        let user = state.db.update_user(user_update).await?;
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
        user
    };
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

async fn bulk_user_lifecycle(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<UserLifecycleBatchInput>,
) -> AppResult<Json<serde_json::Value>> {
    let current = require_user_manager(&state, &jar).await?;
    let action = crate::db::UserLifecycleBatchAction::parse(&payload.action)?;
    let count = state
        .db
        .apply_user_lifecycle_batch(&current.user.id, payload.user_ids, action)
        .await?;
    Ok(Json(serde_json::json!({
        "ok": true,
        "action": action.as_str(),
        "count": count,
    })))
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
    security_policy::validate_password_for_subject(
        &state,
        &payload.password,
        &user.email,
        &user.username,
    )
    .await?;
    state
        .db
        .replace_user_password_with_audit(
            &id,
            util::hash_password(&payload.password)?,
            audit::management_event(
                current.user.id,
                "user.password.set",
                "user",
                Some(id.clone()),
                serde_json::json!({}),
            ),
        )
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
    state
        .db
        .delete_mfa_for_user_with_audit(
            &id,
            audit::management_event(
                current.user.id,
                "mfa.admin_reset",
                "user",
                Some(id.clone()),
                serde_json::json!({}),
            ),
        )
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
    let requested = requested_user_ids.iter().cloned().collect::<Vec<_>>();
    let states = state.db.find_user_assignment_states(&requested).await?;
    let states = states
        .into_iter()
        .map(|state| (state.id, state.archived_at))
        .collect::<BTreeMap<_, _>>();
    for user_id in requested_user_ids {
        let archived_at = states
            .get(user_id)
            .copied()
            .ok_or_else(|| AppError::BadRequest(format!("unknown user: {user_id}")))?;
        archived_accounts::ensure_assignable_user_state(
            user_id,
            archived_at,
            allowed_archived_user_ids,
            target,
        )?;
    }
    Ok(())
}

async fn list_clients(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<Vec<PublicClient>>> {
    let (_, organization) = current_organization_client_manager(&state, &jar, false).await?;
    let clients = state
        .db
        .list_clients_for_organization(&organization.id)
        .await?;
    let client_ids = clients
        .iter()
        .map(|client| client.id.clone())
        .collect::<Vec<_>>();
    let mut mappers_by_client = state
        .db
        .list_client_claim_mappers_by_client_ids(&client_ids)
        .await?;
    let clients = clients
        .into_iter()
        .map(|client| {
            let mut public = client.public()?;
            public.organization_slug = Some(organization.slug.clone());
            public.organization_name = Some(organization.name.clone());
            public.claim_mappers = mappers_by_client
                .remove(&public.id)
                .unwrap_or_default()
                .into_iter()
                .map(|mapper| mapper.public())
                .collect();
            Ok(public)
        })
        .collect::<AppResult<Vec<_>>>()?;
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
    let has_global_permission = if manage {
        state
            .db
            .has_permission(&current.user, global_permission)
            .await?
    } else {
        state
            .db
            .has_any_permission(&current.user, CLIENT_READ_PERMISSIONS)
            .await?
    };
    if has_global_permission {
        return Ok((current, organization));
    }
    require_organization_manager_for(state, &current, &organization.id).await?;
    Ok((current, organization))
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
    #[serde(default)]
    website_url: Option<String>,
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
struct ApplicationAuthorizationBindingsInput {
    #[serde(default)]
    user_id: Option<String>,
    #[serde(default)]
    group_id: Option<String>,
    #[serde(default)]
    user_role_ids: Vec<String>,
    #[serde(default)]
    user_permission_overrides: Vec<ApplicationPermissionOverrideInput>,
    #[serde(default)]
    group_role_ids: Vec<String>,
    #[serde(default)]
    organization_role_bindings: BTreeMap<String, Vec<String>>,
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
    client_bindings: Vec<ApplicationClientBindingResponse>,
    modules: Vec<ApplicationModuleResponse>,
    authorization_profiles: Vec<ApplicationAuthorizationProfileResponse>,
    created_at: i64,
    updated_at: i64,
}

#[derive(Debug, Serialize)]
struct ApplicationClientBindingResponse {
    #[serde(flatten)]
    client: PublicClient,
    protocol: String,
    authorization_profile_id: String,
    auth_domain_id: String,
}

#[derive(Debug, Clone, Copy)]
enum MissingApplicationClientPolicy {
    Skip,
    NotFound,
}

/// Assemble application client bindings from the aggregate read projection.
///
/// The graph is loaded by `Db::read_application_graph` with bounded queries
/// for every relation. Keeping this assembler synchronous makes the read
/// model boundary explicit: once the graph is available, a binding list must
/// never open a connection for a client, mapper, or organization.
fn application_client_binding_responses_from_graph(
    graph: &crate::db::ApplicationGraphRecordSet,
    protocol: Option<&str>,
    missing_client_policy: MissingApplicationClientPolicy,
) -> AppResult<Vec<ApplicationClientBindingResponse>> {
    let clients_by_id = graph
        .clients
        .iter()
        .map(|client| (client.id.as_str(), client))
        .collect::<BTreeMap<_, _>>();
    let mut mappers_by_client = BTreeMap::<String, Vec<PublicClientClaimMapper>>::new();
    for mapper in &graph.claim_mappers {
        mappers_by_client
            .entry(mapper.client_db_id.clone())
            .or_default()
            .push(mapper.clone().public());
    }
    for mappers in mappers_by_client.values_mut() {
        // Match list_client_claim_mappers' ORDER BY. The graph query groups
        // by client first, so restore the per-client created_at tie-breaker
        // before exposing the public projection.
        mappers.sort_by_key(|mapper| (mapper.sort_order, mapper.created_at));
    }
    let organizations_by_id = graph
        .organizations
        .iter()
        .map(|organization| (organization.id.as_str(), organization))
        .collect::<BTreeMap<_, _>>();

    let mut response = Vec::with_capacity(graph.bindings.len());
    for binding in &graph.bindings {
        if protocol.is_some_and(|expected| binding.protocol != expected) {
            continue;
        }
        let Some(client) = clients_by_id.get(binding.client_db_id.as_str()) else {
            if matches!(
                missing_client_policy,
                MissingApplicationClientPolicy::NotFound
            ) {
                return Err(AppError::NotFound);
            }
            continue;
        };

        let mut public = (*client).clone().public()?;
        if let Some(organization_id) = public.organization_id.as_deref()
            && let Some(organization) = organizations_by_id.get(organization_id)
        {
            public.organization_slug = Some(organization.slug.clone());
            public.organization_name = Some(organization.name.clone());
        }
        public.claim_mappers = mappers_by_client
            .get(&binding.client_db_id)
            .cloned()
            .unwrap_or_default();
        response.push(ApplicationClientBindingResponse {
            client: public,
            protocol: binding.protocol.clone(),
            authorization_profile_id: binding.authorization_profile_id.clone(),
            auth_domain_id: binding.auth_domain_id.clone(),
        });
    }
    Ok(response)
}

#[derive(Debug, Clone, Serialize)]
struct ApplicationDiscoveryResponse {
    application_id: String,
    management_mode: String,
    website_url: String,
    discovery_url: Option<String>,
    fetch_secret_configured: bool,
    signing_key_configured: bool,
    last_verified_revision: Option<i64>,
    last_verified_version: Option<String>,
    last_verified_digest: Option<String>,
    last_verified_expires_at: Option<i64>,
    sync_status: String,
    last_fetched_at: Option<i64>,
    last_success_at: Option<i64>,
    last_error: Option<String>,
    snapshot_available: bool,
    operator_disabled: bool,
    created_at: i64,
    updated_at: i64,
}

#[derive(Debug, Deserialize)]
struct ApplicationDiscoveryInput {
    #[serde(default)]
    management_mode: Option<String>,
    #[serde(default)]
    website_url: Option<String>,
    /// A new fetch secret is accepted only over the authenticated admin API;
    /// the response never returns it, and the database stores only ciphertext.
    #[serde(default)]
    fetch_secret: Option<String>,
    #[serde(default)]
    signing_public_jwks: Option<String>,
    #[serde(default)]
    operator_disabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct ApplicationDiscoveryDiscoverInput {
    website_url: String,
    #[serde(default)]
    idempotency_key: Option<String>,
}

fn application_discovery_response(
    record: ApplicationDiscoveryRecord,
) -> ApplicationDiscoveryResponse {
    let discovery_url = if record.website_url.trim().is_empty() {
        None
    } else {
        application_discovery::default_discovery_url(&record.website_url).ok()
    };
    ApplicationDiscoveryResponse {
        application_id: record.application_id,
        management_mode: record.management_mode,
        website_url: record.website_url,
        discovery_url,
        fetch_secret_configured: !record.fetch_secret_ciphertext.trim().is_empty(),
        signing_key_configured: !record.signing_public_jwks.trim().is_empty(),
        last_verified_revision: record.last_verified_revision,
        last_verified_version: record.last_verified_version,
        last_verified_digest: record.last_verified_digest,
        last_verified_expires_at: record.last_verified_expires_at,
        sync_status: record.sync_status,
        last_fetched_at: record.last_fetched_at,
        last_success_at: record.last_success_at,
        last_error: record.last_error,
        snapshot_available: record.snapshot_json.is_some(),
        operator_disabled: record.operator_disabled != 0,
        created_at: record.created_at,
        updated_at: record.updated_at,
    }
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

async fn application_response(
    state: &AppState,
    application: ApplicationRecord,
) -> AppResult<ApplicationResponse> {
    let graph = state.db.read_application_graph(&application.id).await?;
    application_response_from_graph(application, graph)
}

fn application_response_from_graph(
    application: ApplicationRecord,
    graph: crate::db::ApplicationGraphRecordSet,
) -> AppResult<ApplicationResponse> {
    let client_bindings = application_client_binding_responses_from_graph(
        &graph,
        None,
        MissingApplicationClientPolicy::Skip,
    )?;
    let crate::db::ApplicationGraphRecordSet {
        modules,
        profiles,
        permission_definitions,
        profile_roles,
        ..
    } = graph;
    let unique_identity_factors = application.unique_identity_factors()?;
    let modules = modules
        .into_iter()
        .map(application_module_response)
        .collect::<AppResult<Vec<_>>>()?;
    // A representation read must not repair or mutate the aggregate.  Profile
    // creation belongs to the explicit client/application write transaction;
    // otherwise a harmless GET can leave a partial profile graph behind when
    // a later query or response conversion fails.
    let mut permission_counts = BTreeMap::<String, usize>::new();
    for definition in permission_definitions {
        if definition.is_active == 1 {
            *permission_counts.entry(definition.profile_id).or_default() += 1;
        }
    }
    let mut role_counts = BTreeMap::<String, usize>::new();
    for role in profile_roles {
        if role.is_active == 1 {
            *role_counts.entry(role.profile_id).or_default() += 1;
        }
    }
    let mut authorization_profiles = Vec::with_capacity(profiles.len());
    for profile in profiles {
        authorization_profiles.push(ApplicationAuthorizationProfileResponse {
            id: profile.id.clone(),
            profile_key: profile.profile_key.clone(),
            connection_kind: profile.connection_kind.clone(),
            connection_id: profile.connection_id.clone(),
            source_mode: profile.source_mode.clone(),
            remote_version: profile.remote_version.clone(),
            remote_digest: profile.remote_digest.clone(),
            sync_status: profile.sync_status.clone(),
            last_synced_at: profile.last_synced_at,
            last_error: profile.last_error.clone(),
            permission_count: permission_counts.get(&profile.id).copied().unwrap_or(0),
            role_count: role_counts.get(&profile.id).copied().unwrap_or(0),
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
        client_bindings,
        modules,
        authorization_profiles,
        created_at: application.created_at,
        updated_at: application.updated_at,
    })
}

pub(crate) async fn require_organization_manager_for(
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
    let (platform_manager, memberships) = tokio::try_join!(
        state
            .db
            .has_permission(&current.user, Permission::OrganizationsManage),
        state.db.list_user_organizations(&current.user.id),
    )?;
    if platform_manager {
        return Ok(());
    }
    let membership = memberships
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
    let applications = state.db.list_applications(Some(&organization.id)).await?;
    let application_ids = applications
        .iter()
        .map(|application| application.id.clone())
        .collect::<Vec<_>>();
    let graphs = state
        .db
        .read_application_graph_batch(&application_ids)
        .await?;
    let result = applications
        .into_iter()
        .map(|application| {
            let graph = graphs.get(&application.id).cloned().ok_or_else(|| {
                AppError::Internal(format!(
                    "application graph is missing for {}",
                    application.id
                ))
            })?;
            application_response_from_graph(application, graph)
        })
        .collect::<AppResult<Vec<_>>>()?;
    Ok(Json(result))
}

async fn list_application_modules(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<Vec<ApplicationModuleResponse>>> {
    let (_current, _application) = managed_application(&state, &jar, &id).await?;
    let modules = state
        .db
        .list_application_modules(&id)
        .await?
        .into_iter()
        .map(application_module_response)
        .collect::<AppResult<Vec<_>>>()?;
    Ok(Json(modules))
}

async fn get_application_billing_settings(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<billing::ApplicationBillingSettingsResponse>> {
    let (_current, _application) = managed_application(&state, &jar, &id).await?;
    let settings = state.db.ensure_application_billing_settings(&id).await?;
    Ok(Json(billing::application_billing_settings_response(
        settings,
    )?))
}

async fn update_application_billing_settings(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<billing::ApplicationBillingSettingsInput>,
) -> AppResult<Json<billing::ApplicationBillingSettingsResponse>> {
    let (current, application) = managed_application(&state, &jar, &id).await?;
    let (accept_signet_balance, wallet_mode, supported_currencies) =
        billing::normalize_application_billing_input(&state.settings, payload)?;
    let settings = state
        .db
        .upsert_application_billing_settings(NewApplicationBillingSettings {
            application_id: id.clone(),
            accept_signet_balance,
            wallet_mode,
            supported_currencies,
        })
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.billing_settings.update",
            "application",
            Some(id),
            serde_json::json!({
                "organization_id": application.organization_id,
                "accept_signet_balance": settings.accept_signet_balance == 1,
                "wallet_mode": settings.wallet_mode,
                "supported_currencies": util::from_json::<Vec<String>>(&settings.supported_currencies)?,
            }),
        ))
        .await?;
    Ok(Json(billing::application_billing_settings_response(
        settings,
    )?))
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
    let (current, application) = managed_application(&state, &jar, &id).await?;
    ensure_website_application_modules_editable(&state, &application).await?;
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
        .upsert_application_module_with_audit(
            &id,
            &module_key,
            &config_json,
            payload.is_enabled,
            audit::management_event(
                current.user.id.clone(),
                "application.module.update",
                "application",
                Some(id.clone()),
                serde_json::json!({
                    "organization_id": application.organization_id,
                    "module": module_key.clone(),
                    "is_enabled": payload.is_enabled,
                }),
            ),
        )
        .await?;
    Ok(Json(application_module_response(module)?))
}

async fn get_application_jwt_client(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<Option<ApplicationJwtClientResponse>>> {
    let (_current, application) = managed_application(&state, &jar, &id).await?;
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
    let (current, application) = managed_application(&state, &jar, &id).await?;
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
    let (current, application) = managed_application(&state, &jar, &id).await?;
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
        .rotate_application_jwt_secret_with_audit(
            &id,
            &client_id,
            &secret_hash,
            payload.grace_seconds,
            audit::management_event(
                current.user.id.clone(),
                "application.jwt_client.secret.rotate",
                "application",
                Some(id.clone()),
                serde_json::json!({
                    "organization_id": application.organization_id,
                    "client_id": client_id.clone(),
                    "grace_seconds": payload.grace_seconds,
                }),
            ),
        )
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
    let (current, application) = managed_application(&state, &jar, &id).await?;
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
    let token_id = uuid::Uuid::new_v4().to_string();
    let token_prefix = raw_token.chars().take(16).collect::<String>();
    let token_scopes = scopes.clone();
    let record = state
        .db
        .insert_application_scim_token_with_audit(
            NewApplicationScimToken {
                id: token_id.clone(),
                application_id: application.id.clone(),
                token_prefix,
                token_hash: util::token_hash(&raw_token),
                scopes: token_scopes,
                expires_at: payload.expires_at,
            },
            audit::management_event(
                current.user.id.clone(),
                "application.scim_token.create",
                "application",
                Some(application.id.clone()),
                serde_json::json!({
                    "token_id": token_id,
                    "token_prefix": raw_token.chars().take(16).collect::<String>(),
                }),
            ),
        )
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
    let (current, application) = managed_application(&state, &jar, &id).await?;
    ensure_website_application_modules_editable(&state, &application).await?;
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

async fn ensure_website_application_modules_editable(
    state: &AppState,
    application: &ApplicationRecord,
) -> AppResult<()> {
    if application_is_website_managed(state, application).await? {
        return Err(AppError::BadRequest(
            "website-managed application modules are read-only; update the website manifest"
                .to_string(),
        ));
    }
    Ok(())
}

async fn application_is_website_managed(
    state: &AppState,
    application: &ApplicationRecord,
) -> AppResult<bool> {
    Ok(state
        .db
        .find_application_discovery(&application.id)
        .await?
        .is_some_and(|record| {
            record.management_mode == application_discovery::MANAGEMENT_MODE_WEBSITE
        }))
}

async fn get_application_discovery(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<ApplicationDiscoveryResponse>> {
    let (_current, application) = managed_application(&state, &jar, &id).await?;
    let record = state
        .db
        .find_application_discovery(&application.id)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(application_discovery_response(record)))
}

async fn update_application_discovery(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<ApplicationDiscoveryInput>,
) -> AppResult<Json<ApplicationDiscoveryResponse>> {
    let (current, application) = managed_application(&state, &jar, &id).await?;
    let existing = state.db.find_application_discovery(&id).await?;
    let current_mode = existing
        .as_ref()
        .map(|record| record.management_mode.as_str())
        .unwrap_or(application_discovery::MANAGEMENT_MODE_SIGNET);
    let management_mode = payload
        .management_mode
        .as_deref()
        .unwrap_or(current_mode)
        .trim()
        .to_string();
    if !matches!(
        management_mode.as_str(),
        application_discovery::MANAGEMENT_MODE_SIGNET
            | application_discovery::MANAGEMENT_MODE_WEBSITE
    ) {
        return Err(AppError::BadRequest(
            "unsupported application discovery management mode".to_string(),
        ));
    }

    let current_website_url = existing
        .as_ref()
        .map(|record| record.website_url.clone())
        .filter(|value| !value.trim().is_empty())
        .or(applications::application_website_url(&state, &id).await?);
    let website_url = payload
        .website_url
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .or(current_website_url)
        .unwrap_or_default();
    let website_url = if website_url.is_empty() {
        if management_mode == application_discovery::MANAGEMENT_MODE_WEBSITE {
            return Err(AppError::BadRequest(
                "website-managed applications require website_url".to_string(),
            ));
        }
        String::new()
    } else {
        application_discovery::website_origin(&website_url)?
    };

    let fetch_secret_ciphertext = match payload.fetch_secret {
        None => existing
            .as_ref()
            .map(|record| record.fetch_secret_ciphertext.clone())
            .unwrap_or_default(),
        Some(secret) if secret.trim().is_empty() => String::new(),
        Some(secret) => {
            if state.settings.discovery.encryption_key.trim().is_empty() {
                return Err(AppError::Configuration(
                    "discovery encryption key is not configured".to_string(),
                ));
            }
            util::encrypt_discovery_secret(&state.settings.discovery.encryption_key, secret.trim())?
        }
    };
    let signing_public_jwks = match payload.signing_public_jwks {
        None => existing
            .as_ref()
            .map(|record| record.signing_public_jwks.clone())
            .unwrap_or_default(),
        Some(value) => {
            let value = value.trim().to_string();
            if value.len() > 128 * 1024 {
                return Err(AppError::BadRequest(
                    "signing public JWKS is too large".to_string(),
                ));
            }
            value
        }
    };
    let operator_disabled = payload
        .operator_disabled
        .or_else(|| {
            existing
                .as_ref()
                .map(|record| record.operator_disabled != 0)
        })
        .unwrap_or(false);
    let trust_changed = existing.as_ref().is_some_and(|record| {
        record.website_url != website_url
            || record.fetch_secret_ciphertext != fetch_secret_ciphertext
            || record.signing_public_jwks != signing_public_jwks
    });
    // Challenge-mode website applications intentionally have no persisted
    // fetch secret.  The pinned signing key is sufficient because each sync
    // carries a fresh HTTPS challenge and a signed registration proof.
    let has_trust = !signing_public_jwks.is_empty();
    let sync_status = if management_mode == application_discovery::MANAGEMENT_MODE_SIGNET {
        application_discovery::SYNC_DISABLED.to_string()
    } else if !has_trust {
        application_discovery::SYNC_UNCONFIGURED.to_string()
    } else if trust_changed
        || existing
            .as_ref()
            .and_then(|record| record.last_verified_revision)
            .is_none()
    {
        application_discovery::SYNC_PENDING.to_string()
    } else {
        existing
            .as_ref()
            .map(|record| record.sync_status.clone())
            .unwrap_or_else(|| application_discovery::SYNC_PENDING.to_string())
    };
    let reset_snapshot = trust_changed
        || management_mode != current_mode
        || existing
            .as_ref()
            .is_none_or(|record| record.management_mode != management_mode);
    let record = state
        .db
        .upsert_application_discovery(NewApplicationDiscovery {
            application_id: id.clone(),
            management_mode: management_mode.clone(),
            website_url,
            fetch_secret_ciphertext,
            signing_public_jwks,
            last_verified_revision: (!reset_snapshot)
                .then(|| {
                    existing
                        .as_ref()
                        .and_then(|record| record.last_verified_revision)
                })
                .flatten(),
            last_verified_version: (!reset_snapshot)
                .then(|| {
                    existing
                        .as_ref()
                        .and_then(|record| record.last_verified_version.clone())
                })
                .flatten(),
            last_verified_digest: (!reset_snapshot)
                .then(|| {
                    existing
                        .as_ref()
                        .and_then(|record| record.last_verified_digest.clone())
                })
                .flatten(),
            last_verified_expires_at: (!reset_snapshot)
                .then(|| {
                    existing
                        .as_ref()
                        .and_then(|record| record.last_verified_expires_at)
                })
                .flatten(),
            sync_status,
            last_fetched_at: (!reset_snapshot)
                .then(|| existing.as_ref().and_then(|record| record.last_fetched_at))
                .flatten(),
            last_success_at: (!reset_snapshot)
                .then(|| existing.as_ref().and_then(|record| record.last_success_at))
                .flatten(),
            last_error: (!reset_snapshot)
                .then(|| {
                    existing
                        .as_ref()
                        .and_then(|record| record.last_error.clone())
                })
                .flatten(),
            snapshot_json: (!reset_snapshot)
                .then(|| {
                    existing
                        .as_ref()
                        .and_then(|record| record.snapshot_json.clone())
                })
                .flatten(),
            operator_disabled,
        })
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.discovery.update",
            "application_discovery",
            Some(id),
            serde_json::json!({
                "application_id": application.id,
                "management_mode": management_mode,
                "trust_changed": trust_changed,
            }),
        ))
        .await?;
    Ok(Json(application_discovery_response(record)))
}

async fn sync_application_discovery(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<ApplicationDiscoveryResponse>> {
    let (current, application) = managed_application(&state, &jar, &id).await?;
    let record = application_discovery::sync_application(&state, &id).await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.discovery.sync",
            "application_discovery",
            Some(id),
            serde_json::json!({
                "application_id": application.id,
                "revision": record.last_verified_revision,
            }),
        ))
        .await?;
    Ok(Json(application_discovery_response(record)))
}

async fn discover_application(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<ApplicationDiscoveryDiscoverInput>,
) -> AppResult<Json<ApplicationDiscoveryResponse>> {
    let current = auth::require_current_user(&state, &jar).await?;
    let origin = application_discovery::website_origin(&payload.website_url)?;
    let entry = state
        .settings
        .discovery
        .auto_registration
        .allowlist
        .iter()
        .find(|entry| {
            entry
                .origin
                .trim()
                .trim_end_matches('/')
                .eq_ignore_ascii_case(&origin)
        })
        .ok_or(AppError::Forbidden)?;
    let idempotency_key = payload
        .idempotency_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if idempotency_key.is_some_and(|value| value.len() > 128 || value.chars().any(char::is_control))
    {
        return Err(AppError::BadRequest(
            "idempotency_key is invalid".to_string(),
        ));
    }
    require_organization_manager_for(&state, &current, &entry.organization_id).await?;
    let record = if let Some(idempotency_key) = idempotency_key {
        let request_hash = util::sha256_base64url(&format!(
            "signet:application-discovery:auto-register:v1:{origin}"
        ));
        match state
            .db
            .claim_application_discovery_idempotency(
                &entry.organization_id,
                idempotency_key,
                &request_hash,
                &origin,
            )
            .await?
        {
            crate::db::ApplicationDiscoveryIdempotencyClaim::Completed { application_id } => {
                let application = state
                    .db
                    .find_application_by_id(&application_id)
                    .await?
                    .ok_or(AppError::NotFound)?;
                if application.organization_id != entry.organization_id {
                    return Err(AppError::Forbidden);
                }
                state
                    .db
                    .find_application_discovery(&application_id)
                    .await?
                    .ok_or(AppError::NotFound)?
            }
            crate::db::ApplicationDiscoveryIdempotencyClaim::InProgress => {
                return Err(AppError::BadRequest(
                    "idempotency_key is already being processed".to_string(),
                ));
            }
            crate::db::ApplicationDiscoveryIdempotencyClaim::Claimed { claim_token } => {
                let result =
                    application_discovery::auto_register_application(&state, &origin).await;
                match result {
                    Ok(record) => {
                        state
                            .db
                            .complete_application_discovery_idempotency(
                                &entry.organization_id,
                                idempotency_key,
                                &claim_token,
                                &record.application_id,
                            )
                            .await?;
                        record
                    }
                    Err(error) => {
                        state
                            .db
                            .fail_application_discovery_idempotency(
                                &entry.organization_id,
                                idempotency_key,
                                &claim_token,
                            )
                            .await?;
                        return Err(error);
                    }
                }
            }
        }
    } else {
        application_discovery::auto_register_application(&state, &origin).await?
    };
    let sync_status = record.sync_status.clone();
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.discovery.auto_register",
            "application_discovery",
            Some(record.application_id.clone()),
            serde_json::json!({
                "origin": origin,
                "idempotency_key": idempotency_key,
                "sync_status": sync_status,
            }),
        ))
        .await?;
    Ok(Json(application_discovery_response(record)))
}

async fn list_application_oidc_clients(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<Vec<PublicClient>>> {
    let (_current, _application) = managed_application(&state, &jar, &id).await?;
    let graph = state.db.read_application_graph(&id).await?;
    let clients = application_client_binding_responses_from_graph(
        &graph,
        Some("oidc"),
        MissingApplicationClientPolicy::NotFound,
    )?
    .into_iter()
    .map(|binding| binding.client)
    .collect();
    Ok(Json(clients))
}

async fn create_application_oidc_client(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<ClientInput>,
) -> AppResult<Json<PublicClient>> {
    let (current, application) = managed_application(&state, &jar, &id).await?;
    ensure_website_application_modules_editable(&state, &application).await?;
    validate_client_input(&payload)?;
    if payload
        .organization_id
        .as_deref()
        .map(str::trim)
        .is_some_and(|organization_id| {
            !organization_id.is_empty() && organization_id != application.organization_id
        })
    {
        return Err(AppError::Forbidden);
    }
    let claim_mappers = client_input_to_claim_mappers(&payload)?;
    let client = state
        .db
        .create_application_oidc_client_graph(
            &application.id,
            client_input_to_new(
                payload,
                None,
                Some(application.organization_id.clone()),
                None,
            )?,
            claim_mappers,
        )
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.oidc_client.create",
            "application",
            Some(application.id),
            serde_json::json!({ "client_id": client.client_id }),
        ))
        .await?;
    Ok(Json(
        public_client_with_claim_mappers(&state, client).await?,
    ))
}

async fn update_application_oidc_client(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, client_db_id)): Path<(String, String)>,
    Json(payload): Json<ClientInput>,
) -> AppResult<Json<PublicClient>> {
    let (current, application) = managed_application(&state, &jar, &id).await?;
    ensure_website_application_modules_editable(&state, &application).await?;
    validate_client_input(&payload)?;
    if payload
        .organization_id
        .as_deref()
        .map(str::trim)
        .is_some_and(|organization_id| {
            !organization_id.is_empty() && organization_id != application.organization_id
        })
    {
        return Err(AppError::Forbidden);
    }
    let binding = state
        .db
        .find_application_client_binding(&client_db_id)
        .await?
        .filter(|binding| binding.application_id == application.id && binding.protocol == "oidc")
        .ok_or(AppError::NotFound)?;
    let existing = state
        .db
        .find_client_by_id(&binding.client_db_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let claim_mappers = client_input_to_claim_mappers(&payload)?;
    let client = state
        .db
        .update_application_oidc_client_graph(
            &application.id,
            &existing.id,
            client_input_to_new(
                payload,
                existing.client_secret_hash.clone(),
                Some(application.organization_id.clone()),
                Some(existing.audience.clone()),
            )?,
            claim_mappers,
        )
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.oidc_client.update",
            "application",
            Some(application.id),
            serde_json::json!({ "client_id": client.client_id }),
        ))
        .await?;
    Ok(Json(
        public_client_with_claim_mappers(&state, client).await?,
    ))
}

async fn delete_application_oidc_client(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, client_db_id)): Path<(String, String)>,
) -> AppResult<Json<serde_json::Value>> {
    let (current, application) = managed_application(&state, &jar, &id).await?;
    ensure_website_application_modules_editable(&state, &application).await?;
    let binding = state
        .db
        .find_application_client_binding(&client_db_id)
        .await?
        .filter(|binding| binding.application_id == application.id && binding.protocol == "oidc")
        .ok_or(AppError::NotFound)?;
    let client = state
        .db
        .find_client_by_id(&binding.client_db_id)
        .await?
        .ok_or(AppError::NotFound)?;
    state
        .db
        .delete_application_oidc_client_graph(&application.id, &client.id)
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.oidc_client.delete",
            "application",
            Some(application.id),
            serde_json::json!({ "client_id": client.client_id }),
        ))
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
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
    let groups = state
        .db
        .list_application_authorization_groups(&application.organization_id)
        .await?
        .into_iter()
        .map(|group| ApplicationAuthorizationGroupResponse {
            id: group.id,
            name: group.name,
            description: group.description,
            created_at: group.created_at,
            updated_at: group.updated_at,
        })
        .collect();
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
    let (current, application) = managed_application(state, jar, application_id).await?;
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

async fn ensure_local_profile_catalog_editable(
    state: &AppState,
    application: &ApplicationRecord,
    _profile: &ApplicationAuthorizationProfileRecord,
) -> AppResult<()> {
    if application_is_website_managed(state, application).await? {
        return Err(AppError::BadRequest(
            "website-managed role catalogs are read-only; update the website manifest".to_string(),
        ));
    }
    Ok(())
}

async fn application_authorization_user(
    state: &AppState,
    application: &ApplicationRecord,
    user_id: &str,
) -> AppResult<crate::db::UserRecord> {
    let user = state
        .db
        .find_application_authorization_user(&application.id, user_id)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(user)
}

async fn authorization_profile_response(
    state: &AppState,
    profile: ApplicationAuthorizationProfileRecord,
) -> AppResult<ApplicationAuthorizationProfileResponse> {
    let counts = state
        .db
        .list_application_authorization_profile_counts(std::slice::from_ref(&profile.id))
        .await?;
    let (permission_count, role_count) = counts.get(&profile.id).copied().unwrap_or((0, 0));
    Ok(authorization_profile_response_with_counts(
        profile,
        permission_count.max(0) as usize,
        role_count.max(0) as usize,
    ))
}

fn authorization_profile_response_with_counts(
    profile: ApplicationAuthorizationProfileRecord,
    permission_count: usize,
    role_count: usize,
) -> ApplicationAuthorizationProfileResponse {
    ApplicationAuthorizationProfileResponse {
        id: profile.id,
        profile_key: profile.profile_key,
        connection_kind: profile.connection_kind,
        connection_id: profile.connection_id,
        source_mode: profile.source_mode,
        remote_version: profile.remote_version,
        remote_digest: profile.remote_digest,
        sync_status: profile.sync_status,
        last_synced_at: profile.last_synced_at,
        last_error: profile.last_error,
        permission_count,
        role_count,
        created_at: profile.created_at,
        updated_at: profile.updated_at,
    }
}

async fn list_application_authorization_profiles(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<Vec<ApplicationAuthorizationProfileResponse>>> {
    let (_current, application) = managed_application(&state, &jar, &id).await?;
    let profiles = state
        .db
        .list_application_authorization_profiles(&application.id)
        .await?;
    let profile_ids = profiles
        .iter()
        .map(|profile| profile.id.clone())
        .collect::<Vec<_>>();
    let counts = state
        .db
        .list_application_authorization_profile_counts(&profile_ids)
        .await?;
    let response = profiles
        .into_iter()
        .map(|profile| {
            let (permission_count, role_count) = counts.get(&profile.id).copied().unwrap_or((0, 0));
            authorization_profile_response_with_counts(
                profile,
                permission_count.max(0) as usize,
                role_count.max(0) as usize,
            )
        })
        .collect();
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

async fn application_profile_permission_catalog(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, profile_id)): Path<(String, String)>,
) -> AppResult<Json<Vec<ApplicationPermissionDefinitionResponse>>> {
    let (_current, _application, profile) =
        managed_authorization_profile(&state, &jar, &id, &profile_id).await?;
    let mut definitions = Vec::new();
    if profile.source_mode == application_discovery::SOURCE_MODE_MANUAL {
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

async fn get_application_authorization_bindings(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, profile_id)): Path<(String, String)>,
) -> AppResult<Json<AuthorizationBindingsSnapshot>> {
    let (_current, application, profile) =
        managed_authorization_profile(&state, &jar, &id, &profile_id).await?;
    Ok(Json(
        state
            .db
            .read_application_authorization_bindings(&application.id, &profile.id)
            .await?,
    ))
}

async fn update_application_authorization_bindings(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, profile_id)): Path<(String, String)>,
    Json(payload): Json<ApplicationAuthorizationBindingsInput>,
) -> AppResult<Json<AuthorizationBindingsSnapshot>> {
    let (current, application, profile) =
        managed_authorization_profile(&state, &jar, &id, &profile_id).await?;
    let user_id = payload.user_id.clone();
    let group_id = payload.group_id.clone();
    let user_role_ids = payload.user_role_ids.clone();
    let group_role_ids = payload.group_role_ids.clone();
    let organization_role_bindings = payload.organization_role_bindings.clone();
    let snapshot = state
        .db
        .replace_application_authorization_bindings_with_audit(
            &application.id,
            &profile.id,
            AuthorizationBindingsUpdate {
                user_id: payload.user_id,
                group_id: payload.group_id,
                user_role_ids: payload.user_role_ids,
                user_permission_overrides: payload
                    .user_permission_overrides
                    .into_iter()
                    .map(|value| AuthorizationBindingPermissionOverride {
                        permission: value.permission,
                        effect: value.effect,
                    })
                    .collect(),
                group_role_ids: payload.group_role_ids,
                organization_role_bindings: payload.organization_role_bindings,
            },
            audit::management_event(
                current.user.id,
                "application.authorization_profile.bindings.update",
                "application_authorization_profile",
                Some(profile.id.clone()),
                serde_json::json!({
                    "application_id": application.id,
                    "profile_id": profile.id,
                    "user_id": user_id,
                    "group_id": group_id,
                    "user_role_ids": user_role_ids,
                    "group_role_ids": group_role_ids,
                    "organization_role_bindings": organization_role_bindings,
                }),
            ),
        )
        .await?;
    Ok(Json(snapshot))
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
    let (current, application, profile) =
        managed_authorization_profile(&state, &jar, &id, &profile_id).await?;
    ensure_local_profile_catalog_editable(&state, &application, &profile).await?;
    let role = state
        .db
        .upsert_application_profile_role(NewApplicationProfileRole {
            id: None,
            profile_id: profile_id.clone(),
            role_key: payload.role_key,
            name: payload.name,
            description: payload.description,
            permissions: payload.permissions,
            source: application_discovery::SOURCE_MANUAL.to_string(),
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
    let (current, application, profile) =
        managed_authorization_profile(&state, &jar, &id, &profile_id).await?;
    ensure_local_profile_catalog_editable(&state, &application, &profile).await?;
    let current_role = state
        .db
        .list_application_profile_roles(&profile_id)
        .await?
        .into_iter()
        .find(|role| role.id == role_id)
        .ok_or(AppError::NotFound)?;
    if current_role.source == application_discovery::SOURCE_WEBSITE
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
    let (current, application, profile) =
        managed_authorization_profile(&state, &jar, &id, &profile_id).await?;
    ensure_local_profile_catalog_editable(&state, &application, &profile).await?;
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

/// The entitlement resolver keeps its protocol claims in a dedicated map so
/// OIDC, JWT, SAML, and CAS adapters can share one source of truth.  The
/// administrative preview is a diagnostic representation, however, and its
/// callers expect those claims alongside the typed summary fields.  Merge the
/// claims here at the transport boundary instead of coupling the domain model
/// to one management response shape.
fn authorization_preview_entitlements(
    entitlements: authorization::ApplicationEntitlements,
) -> AppResult<serde_json::Value> {
    let claims = entitlements.claims.clone();
    let mut value = serde_json::to_value(entitlements).map_err(|error| {
        AppError::Internal(format!("failed to serialize entitlements: {error}"))
    })?;
    if let serde_json::Value::Object(object) = &mut value {
        for (key, claim) in claims {
            object.entry(key).or_insert(claim);
        }
    }
    Ok(value)
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
        Some(authorization_preview_entitlements(
            authorization::resolve_entitlements_for_profile(&state, &application, &profile, &user)
                .await?,
        )?)
    } else {
        None
    };
    Ok(Json(serde_json::json!({
        "decision": decision,
        "entitlements": entitlements,
    })))
}

async fn application_authorization_preview(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, user_id)): Path<(String, String)>,
) -> AppResult<Json<serde_json::Value>> {
    let (_current, application) = managed_application(&state, &jar, &id).await?;
    let user = application_authorization_user(&state, &application, &user_id).await?;
    let decision = authorization::check_login_access(&state, &application, &user.id).await?;
    let entitlements = if decision.allowed {
        Some(authorization_preview_entitlements(
            authorization::resolve_entitlements(&state, &application, &user).await?,
        )?)
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
    let website_url = payload.website_url.clone().unwrap_or_default();
    let protocols_config = applications::normalize_module_config(
        "protocols",
        serde_json::json!({ "website_url": website_url }),
    )?;
    let protocols_config = util::to_json(&protocols_config)?;
    let application_input = application_input_to_new(organization.id.clone(), payload, false)?;
    let slug = application_input.slug.clone();
    let application = state
        .db
        .insert_application_with_module_with_audit(
            application_input,
            "protocols",
            &protocols_config,
            false,
            audit::management_event(
                current.user.id.clone(),
                "application.create",
                "application",
                None,
                serde_json::json!({
                    "organization_id": organization.id,
                    "slug": slug,
                }),
            ),
        )
        .await?;
    Ok(Json(application_response(&state, application).await?))
}

async fn update_application(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<ApplicationInput>,
) -> AppResult<Json<ApplicationResponse>> {
    let (current, existing) = managed_application(&state, &jar, &id).await?;
    let organization_id = existing.organization_id.clone();
    let application = state
        .db
        .update_application_with_audit(
            &id,
            application_input_to_new(existing.organization_id.clone(), payload, false)?,
            audit::management_event(
                current.user.id.clone(),
                "application.update",
                "application",
                Some(id.clone()),
                serde_json::json!({ "organization_id": organization_id }),
            ),
        )
        .await?;
    Ok(Json(application_response(&state, application).await?))
}

async fn delete_application(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let (current, existing) = managed_application(&state, &jar, &id).await?;
    state
        .db
        .delete_application_with_expected_organization_and_audit(
            &id,
            &existing.organization_id,
            audit::management_event(
                current.user.id,
                "application.delete",
                "application",
                Some(id.clone()),
                serde_json::json!({ "organization_id": existing.organization_id }),
            ),
        )
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn list_application_client_bindings(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<Vec<ApplicationClientBindingResponse>>> {
    let (_current, _application) = managed_application(&state, &jar, &id).await?;
    let graph = state.db.read_application_graph(&id).await?;
    Ok(Json(application_client_binding_responses_from_graph(
        &graph,
        None,
        MissingApplicationClientPolicy::Skip,
    )?))
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
    for client in state.db.list_application_clients(&application.id).await? {
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
    let (_current, _application) = managed_application(&state, &jar, &id).await?;
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
    let (current, application) = managed_application(&state, &jar, &id).await?;
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
    let (current, _application) = managed_application(&state, &jar, &id).await?;
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

async fn list_application_iap_rules(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<Vec<PublicIapApplication>>> {
    let (_current, _application) = managed_application(&state, &jar, &id).await?;
    Ok(Json(
        state
            .db
            .list_iap_applications_for_application(&id)
            .await?
            .into_iter()
            .map(|rule| rule.public())
            .collect::<AppResult<Vec<_>>>()?,
    ))
}

async fn create_application_iap_rule(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<IapApplicationInput>,
) -> AppResult<Json<PublicIapApplication>> {
    let (current, application) = managed_application(&state, &jar, &id).await?;
    ensure_website_application_modules_editable(&state, &application).await?;
    let rule = state
        .db
        .insert_iap_application(iap_application_input_to_new(&state, &id, payload).await?)
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.iap_rule.create",
            "application",
            Some(id),
            serde_json::json!({
                "rule_id": rule.id,
                "slug": rule.slug,
                "external_host": rule.external_host,
                "path_prefix": rule.path_prefix,
            }),
        ))
        .await?;
    Ok(Json(rule.public()?))
}

async fn update_application_iap_rule(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, rule_id)): Path<(String, String)>,
    Json(payload): Json<IapApplicationInput>,
) -> AppResult<Json<PublicIapApplication>> {
    let (current, application) = managed_application(&state, &jar, &id).await?;
    ensure_website_application_modules_editable(&state, &application).await?;
    let existing = state
        .db
        .find_iap_application_by_id(&rule_id)
        .await?
        .filter(|rule| rule.application_id.as_deref() == Some(id.as_str()))
        .ok_or(AppError::NotFound)?;
    let rule = state
        .db
        .update_iap_application(
            &existing.id,
            iap_application_input_to_new(&state, &id, payload).await?,
        )
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.iap_rule.update",
            "application",
            Some(id),
            serde_json::json!({
                "rule_id": rule.id,
                "slug": rule.slug,
                "is_active": rule.is_active == 1,
            }),
        ))
        .await?;
    Ok(Json(rule.public()?))
}

async fn delete_application_iap_rule(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, rule_id)): Path<(String, String)>,
) -> AppResult<Json<serde_json::Value>> {
    let (current, _application) = managed_application(&state, &jar, &id).await?;
    let existing = state
        .db
        .find_iap_application_by_id(&rule_id)
        .await?
        .filter(|rule| rule.application_id.as_deref() == Some(id.as_str()))
        .ok_or(AppError::NotFound)?;
    state.db.delete_iap_application(&existing.id).await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.iap_rule.delete",
            "application",
            Some(id),
            serde_json::json!({ "rule_id": existing.id, "slug": existing.slug }),
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
                    validate_active_allowed_clients(state, allowed_client_ids).await?;
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
                    validate_active_allowed_clients(state, allowed_client_ids).await?;
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
    application_id: &str,
    payload: IapApplicationInput,
) -> AppResult<NewIapApplication> {
    let required_organization_id =
        normalize_client_organization_id(state, payload.required_organization_id).await?;
    let application = state
        .db
        .find_application_by_id(application_id)
        .await?
        .ok_or(AppError::NotFound)?;
    if required_organization_id
        .as_deref()
        .is_some_and(|organization_id| organization_id != application.organization_id)
    {
        return Err(AppError::Forbidden);
    }
    iap::normalize_iap_application(NewIapApplication {
        application_id: application_id.to_string(),
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

#[cfg(test)]
mod tests {
    use super::admin_settings::LoginSettingsInput;
    use super::admin_user_import::{import_users_csv, validate_bulk_import_duplicates};
    use super::*;

    #[test]
    fn user_list_scope_accepts_authorization_code_accounts() {
        assert!(matches!(
            user_list_scope(Some("authorization_code")),
            Ok(UserListScope::AuthorizationCode)
        ));
    }

    #[test]
    fn user_list_query_defaults_to_a_bounded_first_page() {
        let parsed = parse_user_list_query(UserListQuery::default()).unwrap();
        assert_eq!(parsed.page, 1);
        assert_eq!(parsed.page_size, USER_DIRECTORY_DEFAULT_PAGE_SIZE);
        assert_eq!(parsed.offset, 0);
        assert!(parsed.filters.organization_id.is_none());
    }

    #[test]
    fn user_list_query_accepts_zero_offset_and_normalizes_day_end() {
        let parsed = parse_user_list_query(UserListQuery {
            offset: Some("0".to_string()),
            limit: Some("50".to_string()),
            created_from: Some("2026-01-01".to_string()),
            created_to: Some("2026-01-31".to_string()),
            linked_identity: Some("linked".to_string()),
            role: Some("admin".to_string()),
            ..UserListQuery::default()
        })
        .unwrap();
        assert_eq!(parsed.page, 1);
        assert_eq!(parsed.page_size, 50);
        assert_eq!(parsed.offset, 0);
        assert_eq!(
            parsed.filters.linked_identity,
            UserListLinkedIdentityFilter::Linked
        );
        assert_eq!(parsed.filters.role, UserListRoleFilter::Admin);
        assert_eq!(parsed.filters.created_from, Some(1_767_225_600));
        assert_eq!(parsed.filters.created_to, Some(1_769_904_000));
    }

    #[test]
    fn client_read_permissions_include_read_and_manage_access() {
        assert_eq!(
            CLIENT_READ_PERMISSIONS,
            &[Permission::ClientsRead, Permission::ClientsManage]
        );
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
