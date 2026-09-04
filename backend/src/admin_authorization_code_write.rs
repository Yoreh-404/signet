use super::{
    admin_authorization_code_policy::{
        AuthorizationCodeValidationInput, ensure_admin_universal_manager,
        immutable_allowed_client_ids, immutable_optional_text, immutable_recovery_username,
        normalized_client_ids, recovery_target_user_id, validate_active_allowed_clients,
        validate_login_code_binding_metadata,
    },
    admin_guards::require_authorization_code_manager,
    admin_settings::{normalize_optional_email, normalize_optional_text},
};
use crate::{
    AppState,
    access::{Authorizer, Permission},
    audit::{self, AuditSink},
    db::{
        AuthorizationCodeType, InvitationUpdate, LoginCodeLevel, NewInvitation, PublicInvitation,
    },
    error::{AppError, AppResult},
    organizations, util,
};
use axum::{
    Json,
    extract::{Path, State},
};
use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub(super) struct InvitationInput {
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
pub(super) struct InvitationCreateResponse {
    invitation: PublicInvitation,
    code: String,
}

pub(super) async fn create_invitation(
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
    let signing_key = state.db.find_active_signing_key().await?.ok_or_else(|| {
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

pub(super) async fn update_invitation(
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

pub(super) async fn delete_invitation(
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
