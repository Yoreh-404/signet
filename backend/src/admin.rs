use crate::{
    AppState,
    access::{Authorizer, Permission, PermissionInfo, permission_catalog},
    applications, archived_accounts,
    audit::{self, AuditSink},
    auth, auth_flow, backchannel_logout, billing, csrf,
    db::{
        ApplicationAuthorizationProfileRecord, ApplicationModuleRecord, ApplicationRecord,
        AuditEventRecord, AuthorizationCodeType, ClientGrantWithClientRecord, GroupRecord,
        InvitationRecord, InvitationUpdate, LoginCodeLevel, NewApplication,
        NewApplicationBillingSettings, NewGroup, NewIapApplication, NewInvitation, NewOrganization,
        NewRole, NewUser, OrganizationMemberInput, OrganizationMemberWithUserRecord,
        OrganizationRecord, PublicAuditWebhook, PublicClient, PublicClientClaimMapper,
        PublicIapApplication, PublicInvitation, PublicInvitationRedemption, PublicUser, RoleRecord,
        SessionRecord, UserListScope, UserOrganizationRecord, UserUpdate,
    },
    directory,
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
    collections::{BTreeMap, BTreeSet, HashMap},
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
#[path = "admin_application_authorization_preview.rs"]
mod admin_application_authorization_preview;
#[path = "admin_application_authorization_read.rs"]
mod admin_application_authorization_read;
#[path = "admin_application_authorization_write.rs"]
mod admin_application_authorization_write;
#[path = "admin_application_auto_discovery.rs"]
mod admin_application_auto_discovery;
#[path = "admin_application_directory_sync.rs"]
mod admin_application_directory_sync;
#[path = "admin_application_discovery.rs"]
mod admin_application_discovery;
#[path = "admin_application_enrollment.rs"]
mod admin_application_enrollment;
#[path = "admin_application_iap.rs"]
mod admin_application_iap;
#[path = "admin_application_scope.rs"]
mod admin_application_scope;
use admin_application_iap::IapApplicationInput;
use admin_application_scope::{
    application_is_website_managed, ensure_website_application_modules_editable,
    managed_application, require_organization_manager_for,
};
#[path = "admin_application_modules.rs"]
mod admin_application_modules;
#[path = "admin_application_oidc.rs"]
mod admin_application_oidc;
#[path = "admin_invitation_management.rs"]
mod admin_invitation_management;
use admin_application_authorization_read::ApplicationAuthorizationProfileResponse;
#[path = "admin_application_jwt.rs"]
mod admin_application_jwt;
#[path = "admin_application_scim.rs"]
mod admin_application_scim;
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

#[path = "admin_access.rs"]
mod admin_access;
#[path = "admin_account_context.rs"]
mod admin_account_context;
#[path = "admin_account_security.rs"]
mod admin_account_security;
#[path = "admin_account_sessions.rs"]
mod admin_account_sessions;
#[path = "admin_organizations.rs"]
mod admin_organizations;
#[path = "admin_routes.rs"]
mod admin_routes;

pub fn routes() -> Router<AppState> {
    admin_routes::routes()
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
    Ok(Json(
        admin_organizations::organization_response(&state, organization).await?,
    ))
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
) -> AppResult<Json<admin_account_security::MfaStatusResponse>> {
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
    Ok(Json(
        admin_account_security::mfa_status_for_user(&state, &id).await?,
    ))
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

#[derive(Debug, Deserialize)]
struct ApplicationModuleInput {
    #[serde(default)]
    config: serde_json::Value,
    #[serde(default = "default_true")]
    is_enabled: bool,
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
        .collect::<HashMap<_, _>>();
    let mut mappers_by_client = HashMap::<String, Vec<PublicClientClaimMapper>>::new();
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
        .collect::<HashMap<_, _>>();

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
